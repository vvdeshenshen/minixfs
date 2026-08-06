"""内核门面: 进程、文件描述符、系统调用实现、调度.

与 CPU 层的契约:
    cpu.run(max_steps)      执行至多 N 条指令
    cpu.regs[0..7]          eax ecx edx ebx esp ebp esi edi
    on_int(cpu, vec)        int 0x80 陷出到这里
    on_fault(cpu, exc)      除零/越界 -> 转信号
系统调用返回值写回 eax; 除 eax 外寄存器全部保留(内核 system_call.s
会 push/pop 恢复 ebx/ecx/edx)。
"""

from __future__ import annotations

import time
from typing import Dict, List, Optional

import ksyscall
import kvfs
from cpu86 import CPU, DivideError
from kexec import ExecError, load_aout, resolve_exec, setup_stack
from ksyscall import (SEEK_CUR, SEEK_END, SEEK_SET, UTSNAME_FIELDS, Blocked,
                      SyscallTable, pack_stat)
from kvfs import (EACCES, EBADF, EEXIST, EINVAL, EISDIR, ENOENT, ENOSYS,
                  ENOTDIR, ENOTTY, EPERM, ESPIPE, FsError, O_ACCMODE,
                  O_APPEND, O_CREAT, O_EXCL, O_TRUNC, O_WRONLY, OverlayFS,
                  Pipe, VInode)
from x86mem import AddressSpace, SegFault

NR_OPEN = 20              # 内核 include/linux/fs.h: 每进程最多 20 个 fd
HZ = 100
TIMESLICE = 100_000       # 一个时间片的指令数, 约折算 10ms

# 进程状态
RUNNING, SLEEPING, ZOMBIE, STOPPED = range(4)


class OpenFile:
    """POSIX 的 open file description: fork/dup 共享它, 故共享读写位置."""

    __slots__ = ("obj", "flags", "pos", "refs")

    def __init__(self, obj, flags: int, pos: int = 0):
        self.obj = obj
        self.flags = flags
        self.pos = pos
        self.refs = 1

    @property
    def writable(self) -> bool:
        return (self.flags & O_ACCMODE) in (1, 2)

    @property
    def readable(self) -> bool:
        return (self.flags & O_ACCMODE) in (0, 2)


class Process:
    """字段照内核 task_struct."""

    def __init__(self, pid: int, mem: AddressSpace):
        self.pid = pid
        self.ppid = 0
        self.pgrp = pid
        self.session = pid
        self.leader = False
        self.state = RUNNING
        self.mem = mem
        self.cpu: Optional[CPU] = None
        self.fds: List[Optional[OpenFile]] = [None] * NR_OPEN
        self.close_on_exec = 0
        self.cwd: Optional[VInode] = None
        self.root: Optional[VInode] = None
        self.cwd_path = "/"
        self.umask = 0o022
        self.uid = self.euid = self.suid = 0
        self.gid = self.egid = self.sgid = 0
        self.signal = 0
        self.blocked = 0
        self.sigactions = [(0, 0, 0, 0)] * 33
        self.exit_code = 0
        self.wait_channel = None
        self.tty = None
        self.alarm_at = 0
        self.utime = self.stime = 0
        self.cutime = self.cstime = 0
        self.name = ""

    def alloc_fd(self, start: int = 0) -> int:
        for i in range(start, NR_OPEN):
            if self.fds[i] is None:
                return i
        raise FsError(kvfs.EMFILE, "fd 表已满")

    def get_file(self, fd: int) -> OpenFile:
        if not 0 <= fd < NR_OPEN or self.fds[fd] is None:
            raise FsError(EBADF, f"无效 fd: {fd}")
        return self.fds[fd]


class Exited(Exception):
    """进程调用 exit, 用异常穿透 cpu.run()."""

    def __init__(self, code: int):
        super().__init__(f"exit({code})")
        self.code = code


class Kernel:
    """仿真内核."""

    def __init__(self, fs: OverlayFS, terminal=None, verbose: bool = False):
        self.fs = fs
        self.terminal = terminal
        self.verbose = verbose
        self.procs: Dict[int, Process] = {}
        self.next_pid = 1
        self.jiffies = 0
        self.time_offset = 0
        self.hostname = b"(none)"
        self.syscalls = SyscallTable(self)
        self.current: Optional[Process] = None
        self.exit_status = 0
        self.trace: List[str] = []

    # ---- 进程创建 -----------------------------------------------------

    def _new_process(self) -> Process:
        pid = self.next_pid
        self.next_pid += 1
        p = Process(pid, AddressSpace())
        p.cwd = self.fs.root
        p.root = self.fs.root
        self.procs[pid] = p
        return p

    def boot(self, path: str = "/bin/init", argv: Optional[List[bytes]] = None,
             envp: Optional[List[bytes]] = None) -> Process:
        """装入第一个进程."""
        argv = argv or [path.encode()]
        envp = envp or [b"HOME=/root", b"PATH=/bin:/usr/bin", b"TERM=console"]
        p = self._new_process()
        p.ppid = 0
        v, argv = resolve_exec(self.fs, path, argv, p.cwd, p.root)
        entry, _ = load_aout(p.mem, self.fs, v)
        esp = setup_stack(p.mem, argv, envp)
        p.cpu = CPU(p.mem, on_int=self._on_int, on_fault=self._on_fault)
        p.cpu.eip = entry
        p.cpu.regs[4] = esp                      # ESP
        p.name = path
        self._setup_std_fds(p)
        self.current = p
        return p

    def _setup_std_fds(self, p: Process) -> None:
        """给 fd 0/1/2 接上终端.

        镜像里没有 /dev/console —— init 打开它会 ENOENT, 真机上靠继承内核
        给的 fd 0/1/2 工作, 我们照此直接把终端塞进这三个 fd。
        """
        if self.terminal is None:
            return
        f_in = OpenFile(self.terminal, 0)
        f_out = OpenFile(self.terminal, 1)
        f_out.refs = 2
        p.fds[0] = f_in
        p.fds[1] = f_out
        p.fds[2] = f_out

    # ---- CPU 回调 -----------------------------------------------------

    def _on_int(self, cpu: CPU, vec: int) -> None:
        if vec != 0x80:
            return
        p = self.current
        regs = cpu.regs
        nr, a, b, c = regs[0], regs[3], regs[1], regs[2]   # eax, ebx, ecx, edx
        try:
            ret = self.syscalls.dispatch(p, nr, a, b, c)
        except FsError as e:
            ret = -e.errno
        except ExecError as e:
            ret = -e.errno
        except SegFault:
            ret = -kvfs.EFAULT
        if self.verbose:
            self.trace.append(f"sys {nr}({a:#x},{b:#x},{c:#x}) = {ret}")
        regs[0] = ret & 0xFFFFFFFF

    def _on_fault(self, cpu: CPU, exc: BaseException) -> None:
        kind = "除零" if isinstance(exc, DivideError) else "段错误"
        raise Exited(0x8B if kind == "段错误" else 0x88)

    # ---- 内存辅助 -----------------------------------------------------

    def _cstr(self, p: Process, addr: int) -> str:
        return p.mem.read_cstr(addr).decode("latin-1")

    def _read_ptr_array(self, p: Process, addr: int) -> List[bytes]:
        """读 char*[] 直到 NULL."""
        out = []
        if addr == 0:
            return out
        while len(out) < 512:
            ptr = p.mem.read_u32(addr)
            if ptr == 0:
                break
            out.append(p.mem.read_cstr(ptr))
            addr += 4
        return out

    # ---- 进程与终止 ---------------------------------------------------

    def sys_setup(self, p, a, b, c):
        return 0                    # 根已就绪, 无需挂载

    def sys_exit(self, p, code, b, c):
        raise Exited((code & 0xFF) << 8)

    def sys_getpid(self, p, a, b, c):
        return p.pid

    def sys_getppid(self, p, a, b, c):
        return p.ppid

    def sys_getpgrp(self, p, a, b, c):
        return p.pgrp

    def sys_getuid(self, p, a, b, c):
        return p.uid

    def sys_geteuid(self, p, a, b, c):
        return p.euid

    def sys_getgid(self, p, a, b, c):
        return p.gid

    def sys_getegid(self, p, a, b, c):
        return p.egid

    def sys_setuid(self, p, uid, b, c):
        if p.euid != 0 and uid not in (p.uid, p.suid):
            return -EPERM
        if p.euid == 0:
            p.uid = p.suid = uid
        p.euid = uid
        return 0

    def sys_setgid(self, p, gid, b, c):
        if p.egid != 0 and gid not in (p.gid, p.sgid):
            return -EPERM
        if p.egid == 0:
            p.gid = p.sgid = gid
        p.egid = gid
        return 0

    def sys_umask(self, p, mask, b, c):
        old = p.umask
        p.umask = mask & 0o777
        return old

    def sys_nice(self, p, inc, b, c):
        return 0

    def sys_getgroups(self, p, size, listp, c):
        return 0

    # ---- 时间 ---------------------------------------------------------

    def _now(self) -> int:
        return int(time.time()) + self.time_offset

    def sys_time(self, p, tloc, b, c):
        t = self._now()
        if tloc:
            p.mem.write_u32(tloc, t)
        return t

    def sys_stime(self, p, tptr, b, c):
        if p.euid != 0:
            return -EPERM
        self.time_offset = p.mem.read_u32(tptr) - int(time.time())
        return 0

    def sys_gettimeofday(self, p, tv, tz, c):
        if tv:
            now = time.time() + self.time_offset
            p.mem.write_u32(tv, int(now))
            p.mem.write_u32(tv + 4, int((now % 1) * 1_000_000))
        if tz:
            p.mem.write_u32(tz, 0)
            p.mem.write_u32(tz + 4, 0)
        return 0

    def sys_times(self, p, buf, b, c):
        if buf:
            for i, v in enumerate((p.utime, p.stime, p.cutime, p.cstime)):
                p.mem.write_u32(buf + 4 * i, v)
        return self.jiffies

    def sys_uname(self, p, buf, b, c):
        if not buf:
            return -EINVAL
        for i, field in enumerate(UTSNAME_FIELDS):
            p.mem.write(buf + i * 9, field.encode().ljust(9, b"\x00")[:9])
        return 0

    def sys_sethostname(self, p, name, length, c):
        if p.euid != 0:
            return -EPERM
        self.hostname = p.mem.read(name, length)
        return 0

    def sys_sync(self, p, a, b, c):
        return 0

    def sys_mount(self, p, dev, dirname, rw):
        return -EPERM       # rc 脚本只是写 /etc/mtab 文件, 不真挂载

    def sys_umount(self, p, dev, b, c):
        return -EPERM

    def sys_ulimit(self, p, cmd, limit, c):
        return -ENOSYS

    def sys_getrlimit(self, p, res, rlim, c):
        if rlim:
            p.mem.write_u32(rlim, 0x7FFFFFFF)
            p.mem.write_u32(rlim + 4, 0x7FFFFFFF)
        return 0

    def sys_setrlimit(self, p, res, rlim, c):
        return 0

    # ---- brk ----------------------------------------------------------

    def sys_brk(self, p, addr, b, c):
        """语义照 kernel/sys.c: 恒返回当前 brk, 不返回 -errno."""
        return p.mem.set_brk(addr)

    # ---- 路径与元数据 -------------------------------------------------

    def _walk(self, p: Process, path: str) -> VInode:
        return self.fs.walk(path, p.cwd, p.root)

    def sys_chdir(self, p, path, b, c):
        name = self._cstr(p, path)
        v = self._walk(p, name)
        if not v.is_dir:
            return -ENOTDIR
        p.cwd = v
        return 0

    def sys_chroot(self, p, path, b, c):
        if p.euid != 0:
            return -EPERM
        v = self._walk(p, self._cstr(p, path))
        if not v.is_dir:
            return -ENOTDIR
        p.root = v
        p.cwd = v
        return 0

    def sys_access(self, p, path, mode, c):
        self._walk(p, self._cstr(p, path))
        return 0

    def sys_chmod(self, p, path, mode, c):
        self.fs.chmod(self._walk(p, self._cstr(p, path)), mode)
        return 0

    def sys_chown(self, p, path, uid, gid):
        self.fs.chown(self._walk(p, self._cstr(p, path)), uid, gid)
        return 0

    def sys_utime(self, p, path, times, c):
        v = self._walk(p, self._cstr(p, path))
        mtime = p.mem.read_u32(times + 4) if times else self._now()
        self.fs.utime(v, mtime)
        return 0

    def _write_stat(self, p: Process, buf: int, v: VInode) -> int:
        p.mem.write(buf, pack_stat(self.fs.stat_tuple(v)))
        return 0

    def sys_stat(self, p, path, buf, c):
        return self._write_stat(p, buf, self._walk(p, self._cstr(p, path)))

    def sys_fstat(self, p, fd, buf, c):
        f = p.get_file(fd)
        if isinstance(f.obj, VInode):
            return self._write_stat(p, buf, f.obj)
        # 管道与终端: 造一个足够 stdio 判断的假 stat
        mode = 0o020600 if f.obj is self.terminal else 0o010600
        p.mem.write(buf, pack_stat((kvfs.ROOT_DEV, 0, mode, 1, 0, 0,
                                    0, 0, 0, 0, 0)))
        return 0

    def sys_readlink(self, p, path, buf, size):
        return -EINVAL           # minix v1 无符号链接

    def sys_symlink(self, p, old, new, c):
        return -EPERM

    # ---- 目录项 -------------------------------------------------------

    def sys_link(self, p, old, new, c):
        self.fs.link(self._cstr(p, old), self._cstr(p, new), p.cwd, p.root)
        return 0

    def sys_unlink(self, p, path, b, c):
        self.fs.unlink(self._cstr(p, path), p.cwd, p.root)
        return 0

    def sys_rename(self, p, old, new, c):
        self.fs.rename(self._cstr(p, old), self._cstr(p, new), p.cwd, p.root)
        return 0

    def sys_mkdir(self, p, path, mode, c):
        self.fs.mkdir(self._cstr(p, path), mode & ~p.umask, p.cwd, p.root,
                      p.euid, p.egid)
        return 0

    def sys_rmdir(self, p, path, b, c):
        self.fs.rmdir(self._cstr(p, path), p.cwd, p.root)
        return 0

    def sys_mknod(self, p, path, mode, dev):
        if p.euid != 0:
            return -EPERM
        self.fs.mknod(self._cstr(p, path), mode, dev, p.cwd, p.root,
                      p.euid, p.egid)
        return 0

    # ---- 打开与关闭 ---------------------------------------------------

    def sys_open(self, p, path, flags, mode):
        name = self._cstr(p, path)
        try:
            v = self._walk(p, name)
            if flags & O_EXCL and flags & O_CREAT:
                return -EEXIST
        except FsError as e:
            if e.errno != ENOENT or not (flags & O_CREAT):
                raise
            v = self.fs.create(name, mode & ~p.umask, p.cwd, p.root,
                               p.euid, p.egid)
        if v.is_dir and (flags & O_ACCMODE) != 0:
            return -EISDIR
        obj = v
        if v.is_device:
            obj = self._open_device(v)
        elif flags & O_TRUNC and v.is_regular:
            self.fs.truncate(v, 0)
        fd = p.alloc_fd()
        f = OpenFile(obj, flags)
        if isinstance(obj, VInode):
            obj.open_refs += 1
            if flags & O_APPEND:
                f.pos = obj.size
        p.fds[fd] = f
        return fd

    def _open_device(self, v: VInode):
        """按 (major, minor) 分派设备.

        不检查字符/块类型 —— 镜像里 /dev/null 被误建成了块设备。
        """
        major, minor = v.devno
        if major in (4, 5):
            if self.terminal is None:
                return v
            return self.terminal
        if major == 1 and minor == 3:
            return NullDevice()
        if major == 3:
            raise FsError(EPERM, "不允许直接访问硬盘设备")
        raise FsError(kvfs.ENXIO, f"未知设备 ({major},{minor})")

    def sys_creat(self, p, path, mode, c):
        return self.sys_open(p, path, O_CREAT | O_TRUNC | O_WRONLY, mode)

    def sys_close(self, p, fd, b, c):
        f = p.get_file(fd)
        p.fds[fd] = None
        f.refs -= 1
        if f.refs <= 0 and isinstance(f.obj, VInode):
            f.obj.open_refs = max(f.obj.open_refs - 1, 0)
        return 0

    def sys_dup(self, p, fd, b, c):
        f = p.get_file(fd)
        new = p.alloc_fd()
        f.refs += 1
        p.fds[new] = f
        return new

    def sys_dup2(self, p, oldfd, newfd, c):
        f = p.get_file(oldfd)
        if not 0 <= newfd < NR_OPEN:
            return -EBADF
        if oldfd == newfd:
            return newfd
        if p.fds[newfd] is not None:
            self.sys_close(p, newfd, 0, 0)
        f.refs += 1
        p.fds[newfd] = f
        p.close_on_exec &= ~(1 << newfd)
        return newfd

    def sys_fcntl(self, p, fd, cmd, arg):
        f = p.get_file(fd)
        if cmd == 0:                                    # F_DUPFD
            new = p.alloc_fd(arg)
            f.refs += 1
            p.fds[new] = f
            return new
        if cmd == 1:                                    # F_GETFD
            return 1 if p.close_on_exec & (1 << fd) else 0
        if cmd == 2:                                    # F_SETFD
            if arg & 1:
                p.close_on_exec |= 1 << fd
            else:
                p.close_on_exec &= ~(1 << fd)
            return 0
        if cmd == 3:                                    # F_GETFL
            return f.flags
        if cmd == 4:                                    # F_SETFL
            f.flags = (f.flags & ~(O_APPEND | kvfs.O_NONBLOCK)) | \
                      (arg & (O_APPEND | kvfs.O_NONBLOCK))
            return 0
        return -EINVAL

    # ---- 读写 ---------------------------------------------------------

    def sys_read(self, p, fd, buf, count):
        f = p.get_file(fd)
        if count == 0:
            return 0
        obj = f.obj
        if isinstance(obj, VInode):
            data = self.fs.read(obj, f.pos, count)
            f.pos += len(data)
            p.mem.write(buf, data)
            return len(data)
        if isinstance(obj, Pipe):
            data = obj.read(count)
            if data is None:
                raise Blocked(obj)
            p.mem.write(buf, data)
            return len(data)
        if isinstance(obj, NullDevice):
            return 0
        data = obj.read(count)                         # 终端
        if data is None:
            raise Blocked(obj)
        p.mem.write(buf, data)
        return len(data)

    def sys_write(self, p, fd, buf, count):
        f = p.get_file(fd)
        if count == 0:
            return 0
        data = p.mem.read(buf, count)
        obj = f.obj
        if isinstance(obj, VInode):
            if f.flags & O_APPEND:
                f.pos = obj.size
            n = self.fs.write(obj, f.pos, data)
            f.pos += n
            return n
        if isinstance(obj, Pipe):
            n = obj.write(data)
            if n is None:
                raise Blocked(obj)
            return n
        if isinstance(obj, NullDevice):
            return count
        return obj.write(data)                         # 终端

    def sys_lseek(self, p, fd, offset, whence):
        f = p.get_file(fd)
        if not isinstance(f.obj, VInode):
            return -ESPIPE
        if offset >= 0x80000000:
            offset -= 0x100000000
        if whence == SEEK_SET:
            pos = offset
        elif whence == SEEK_CUR:
            pos = f.pos + offset
        elif whence == SEEK_END:
            pos = f.obj.size + offset
        else:
            return -EINVAL
        if pos < 0:
            return -EINVAL
        f.pos = pos
        return pos

    # ---- ioctl --------------------------------------------------------

    def sys_ioctl(self, p, fd, cmd, arg):
        f = p.get_file(fd)
        obj = f.obj
        if self.terminal is not None and obj is self.terminal:
            return self.terminal.ioctl(p, cmd, arg)
        return -ENOTTY          # isatty() 靠这个判断是否终端

    # ---- 执行 ---------------------------------------------------------

    def sys_execve(self, p, path, argvp, envpp):
        name = self._cstr(p, path)
        argv = self._read_ptr_array(p, argvp) or [name.encode()]
        envp = self._read_ptr_array(p, envpp)
        v, argv = resolve_exec(self.fs, name, argv, p.cwd, p.root)
        mem = AddressSpace()
        entry, _ = load_aout(mem, self.fs, v)
        esp = setup_stack(mem, argv, envp)
        p.mem = mem
        p.cpu = CPU(mem, on_int=self._on_int, on_fault=self._on_fault)
        p.cpu.eip = entry
        p.cpu.regs[4] = esp
        p.name = name
        for i in range(NR_OPEN):
            if p.close_on_exec & (1 << i) and p.fds[i] is not None:
                self.sys_close(p, i, 0, 0)
        p.close_on_exec = 0
        # 信号处置复位为 SIG_DFL, 但 SIG_IGN 保留
        p.sigactions = [(0, 0, 0, 0) if h != 1 else (1, 0, 0, 0)
                        for (h, m, fl, r) in p.sigactions]
        return 0

    # ---- 运行 ---------------------------------------------------------

    def run(self, max_instructions: int = 500_000_000) -> int:
        """跑当前进程直到退出, 返回退出码."""
        p = self.current
        total = 0
        while total < max_instructions:
            try:
                n = p.cpu.run(TIMESLICE)
            except Exited as e:
                self.exit_status = e.code
                return e.code
            except Blocked:
                return -1
            total += n
            self.jiffies += max(n // (TIMESLICE // HZ), 1)
            if p.cpu.halted:
                break
        return self.exit_status


class NullDevice:
    """/dev/null."""

    def read(self, n: int) -> bytes:
        return b""

    def write(self, data: bytes) -> int:
        return len(data)
