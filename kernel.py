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
from collections import Counter, deque
from typing import Dict, List, Optional

import kvfs
from cpu86 import CPU, DivideError, MagicJump, Profiler
from kexec import ExecError, load_aout, resolve_exec, setup_stack
from ksyscall import (SEEK_CUR, SEEK_END, SEEK_SET, UTSNAME_FIELDS, Blocked,
                      SyscallTable, pack_stat)
from kvfs import (EBADF, EEXIST, EINVAL, EISDIR, ENOENT, ENOSYS, ENOTDIR,
                  ENOTTY, EPERM, ESPIPE, FsError, O_ACCMODE, O_APPEND,
                  O_CREAT, O_EXCL, O_TRUNC, O_WRONLY, OverlayFS, Pipe, VInode)
from x86mem import AddressSpace, SegFault

TRACE_DEFAULT = 200       # 轨迹环形缓冲默认容量
TRACE_VERBOSE = 5000      # trace on / --trace 时的容量
PERF_HISTORY = 200        # 已死进程性能记录的保留条数

NR_OPEN = 20              # 内核 include/linux/fs.h: 每进程最多 20 个 fd
HZ = 100
TIMESLICE = 100_000       # 一个时间片的指令数, 约折算 10ms

# 进程状态
RUNNING, SLEEPING, ZOMBIE, STOPPED = range(4)

# 信号(镜像 /usr/include/signal.h)
SIGHUP, SIGINT, SIGQUIT, SIGILL, SIGTRAP, SIGABRT, SIGUNUSED, SIGFPE = range(1, 9)
SIGKILL, SIGUSR1, SIGSEGV, SIGUSR2, SIGPIPE, SIGALRM, SIGTERM = range(9, 16)
SIGSTKFLT, SIGCHLD, SIGCONT, SIGSTOP, SIGTSTP, SIGTTIN, SIGTTOU = range(16, 23)

SA_NOMASK = 0x40000000
SA_ONESHOT = 0x80000000

IGNORED_BY_DEFAULT = frozenset((SIGCHLD, SIGCONT))
STOP_SIGNALS = frozenset((SIGSTOP, SIGTSTP, SIGTTIN, SIGTTOU))

# restorer 为 0 时的兜底: 跳到这个魔数地址即表示信号返回, 由内核手动弹帧
MAGIC_SIGRETURN = 0xFFFF0000


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
        self.umask = 0o022
        self.uid = self.euid = self.suid = 0
        self.gid = self.egid = self.sgid = 0
        self.signal = 0
        self.blocked = 0
        self.sigactions = [(0, 0, 0, 0)] * 33
        self.exit_code = 0
        self.wait_channel = None
        self.alarm_at = 0
        self.utime = self.stime = 0
        self.cutime = self.cstime = 0
        self.name = ""
        self.restart_syscall = False
        self.sigframes = []      # 每层信号帧是否含 blocked 字段
        self.kernel_task = False  # True = 内核任务(init), 无用户态 CPU
        # ---- 性能统计(按进程, 死后进历史) ----
        self.wall = 0.0                    # 宿主墙钟秒数: 仿真该进程实际耗时
        self.syscall_counts = Counter()    # 本进程各系统调用次数
        self.prof = None                   # 本进程指令剖析器(profiling 开时挂上)

    @property
    def syscall_total(self) -> int:
        return sum(self.syscall_counts.values())

    def alloc_fd(self, start: int = 0) -> int:
        for i in range(start, NR_OPEN):
            if self.fds[i] is None:
                return i
        raise FsError(kvfs.EMFILE, "fd 表已满")

    def get_file(self, fd: int) -> OpenFile:
        if not 0 <= fd < NR_OPEN or self.fds[fd] is None:
            raise FsError(EBADF, f"无效 fd: {fd}")
        return self.fds[fd]


class ProcPerf:
    """已死进程的性能快照: 进程被回收(reap)时从 Process 拷一份留存,
    好在 monitor 里回看'镜像里哪个二进制跑了多少、什么指令分布'。"""

    __slots__ = ("pid", "ppid", "name", "icount", "wall",
                 "syscalls", "prof", "exit_code")

    def __init__(self, p: "Process"):
        self.pid = p.pid
        self.ppid = p.ppid
        self.name = p.name
        self.icount = p.utime               # 累计用户态指令数(跨 execve 累加)
        self.wall = p.wall
        self.syscalls = Counter(p.syscall_counts)
        self.prof = p.prof                  # 指令剖析器(可能为 None)
        self.exit_code = p.exit_code

    @property
    def syscall_total(self) -> int:
        return sum(self.syscalls.values())


class Exited(Exception):
    """进程调用 exit, 用异常穿透 cpu.run()."""

    def __init__(self, code: int):
        super().__init__(f"exit({code})")
        self.code = code


class Replaced(Exception):
    """execve 换掉了地址空间与 CPU, 必须打断当前(已失效的)cpu.run() 循环."""


class Kernel:
    """仿真内核."""

    def __init__(self, fs: OverlayFS, terminal=None):
        self.fs = fs
        self.terminal = terminal
        self.procs: Dict[int, Process] = {}
        self.next_pid = 1
        self.jiffies = 0
        self.time_offset = 0
        self.hostname = b"(none)"
        self.syscalls = SyscallTable(self)
        self.current: Optional[Process] = None
        self.exit_status = 0
        self.runq: List[int] = []
        self.init_proc: Optional[Process] = None
        self._init_state = "done"
        self._init_child = 0
        # monitor 与统计
        self.quit_requested = False
        self.monitor_pending = False
        self.monitor = None
        self.syscall_counts = Counter()
        # 系统调用轨迹: 唯一的一份记录, 常开, 环形缓冲(容量可用 trace 命令调)。
        # 早先还并存一个无上限的 self.trace 列表, 但它不含 pid 且没人读, 已删。
        self.trace_capacity = TRACE_DEFAULT
        self.recent_syscalls = deque(maxlen=TRACE_DEFAULT)
        # CPU 性能剖析: 指令混合默认关(纯 Python 解释器, 逐指令插桩有成本), 由
        # monitor 的 `prof on` 或 --profile 打开, 每进程各一个 Profiler。而按进程
        # 的指令数/仿真时间/系统调用统计是常开的(开销可忽略), 死后进 proc_history。
        self.profiling = False
        self.proc_history: deque = deque(maxlen=PERF_HISTORY)
        # 单步调试(gdb 风格): 默认全空, 调度器快路径不受影响。
        self.breakpoints: set = set()            # 永久断点 eip 集合
        self.temp_breakpoints: set = set()       # until 的一次性断点
        self.step_request = 0                    # 还要单步几条(0=不在单步)
        self.debug_stop = None                   # 停因元组, 供 monitor 进入时展示
        self.debug_target_pid = None             # --debug 的目标进程(锁定单步对象)

    # ---- 进程创建 -----------------------------------------------------

    def _new_process(self) -> Process:
        pid = self.next_pid
        self.next_pid += 1
        p = Process(pid, AddressSpace())
        p.cwd = self.fs.root
        p.root = self.fs.root
        self.procs[pid] = p
        return p

    def boot(self, path: str, argv: Optional[List[bytes]] = None,
             envp: Optional[List[bytes]] = None) -> Process:
        """装入并运行单个程序(完整引导用 boot_init)."""
        argv = argv or [path.encode()]
        envp = envp or [b"HOME=/root", b"PATH=/bin:/usr/bin", b"TERM=console"]
        p = self._new_process()
        p.ppid = 0
        v, argv = resolve_exec(self.fs, path, argv, p.cwd, p.root)
        entry, _ = load_aout(p.mem, self.fs, v)
        esp = setup_stack(p.mem, argv, envp)
        p.cpu = self._make_cpu(p.mem, p)
        p.cpu.eip = entry
        p.cpu.regs[4] = esp                      # ESP
        p.name = path
        self._setup_std_fds(p)
        self.current = p
        return p

    def _setup_std_fds(self, p: Process) -> None:
        """给 fd 0/1/2 接上终端.

        等价于内核 init() 里的 open("/dev/tty0") + dup(0) + dup(0),
        只是不走路径查找, 直接把终端对象塞进这三个 fd。
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
        self._on_int_stats(p, nr, a, b, c, ret)
        regs[0] = ret & 0xFFFFFFFF

    def _on_int_stats(self, p, nr: int, a: int, b: int, c: int,
                      ret: int) -> None:
        """记一次系统调用, 供 monitor 的 `info syscalls` 用.

        系统调用相对指令数极稀疏(几千 vs 几百万), 一次 dict 自增可忽略,
        所以统计常开而不必等 --trace。
        """
        self.syscall_counts[nr] += 1
        self.recent_syscalls.append((p.pid, nr, a, b, c, ret))
        p.syscall_counts[nr] += 1              # 按进程一份, 死后随 ProcPerf 留存

    def set_trace_capacity(self, n: int) -> None:
        """调整轨迹环形缓冲容量, 保留已有记录的尾部."""
        n = max(int(n), 1)
        self.trace_capacity = n
        self.recent_syscalls = deque(self.recent_syscalls, maxlen=n)

    def _make_cpu(self, mem, proc: "Process") -> CPU:
        """统一的 CPU 工厂: 挂内核回调, 剖析开启时给该进程挂上自己的剖析器。

        剖析器挂在 Process 上而非 CPU 上, 这样 execve 换掉 CPU 后仍能续着记
        (同一个二进制程序), 而 fork 出的子进程是新 Process, 自然是全新的一份。
        """
        cpu = CPU(mem, on_int=self._on_int, on_fault=self._on_fault)
        if self.profiling:
            if proc.prof is None:
                proc.prof = Profiler()
            cpu.prof = proc.prof
        return cpu

    def set_profiling(self, on: bool) -> None:
        """开关 CPU 指令混合剖析, 给所有现存进程的 CPU 挂/撤各自的剖析器。

        (按进程的指令数/仿真时间/系统调用统计始终常开, 不受此开关影响。)
        """
        self.profiling = bool(on)
        for p in self.procs.values():
            if p.cpu is None:
                continue
            if self.profiling:
                if p.prof is None:
                    p.prof = Profiler()
                p.cpu.prof = p.prof
            else:
                p.cpu.prof = None          # 停止采集, 但保留已采到的数据

    def reset_profiling(self) -> None:
        """清零现存进程的指令混合计数(不动历史与常开统计)."""
        for p in self.procs.values():
            if p.prof is not None:
                p.prof.reset()

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

    def sys_setreuid(self, p, ruid, euid, c):
        if ruid != 0xFFFFFFFF:
            r = self.sys_setuid(p, ruid, 0, 0)
            if r < 0:
                return r
        if euid != 0xFFFFFFFF:
            p.euid = euid
        return 0

    def sys_setregid(self, p, rgid, egid, c):
        if rgid != 0xFFFFFFFF:
            r = self.sys_setgid(p, rgid, 0, 0)
            if r < 0:
                return r
        if egid != 0xFFFFFFFF:
            p.egid = egid
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
        self._release_file(f)
        return 0

    def sys_dup(self, p, fd, b, c):
        f = p.get_file(fd)
        new = p.alloc_fd()
        self._acquire_fd(f)
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
        self._acquire_fd(f)
        p.fds[newfd] = f
        p.close_on_exec &= ~(1 << newfd)
        return newfd

    def sys_fcntl(self, p, fd, cmd, arg):
        f = p.get_file(fd)
        if cmd == 0:                                    # F_DUPFD
            new = p.alloc_fd(arg)
            self._acquire_fd(f)
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
                raise Blocked(("piperead", obj))
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
                raise Blocked(("pipewrite", obj))
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
        p.cpu = self._make_cpu(mem, p)
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
        p.sigframes.clear()
        # 旧 CPU 的 run() 循环还在栈上, 且它持有已失效的内存, 必须打断
        raise Replaced()

    # ---- fork / execve / waitpid --------------------------------------

    def sys_fork(self, p, a, b, c):
        child = Process(self.next_pid, p.mem.clone())
        self.next_pid += 1
        child.ppid = p.pid
        child.pgrp = p.pgrp
        child.session = p.session
        child.cwd = p.cwd
        child.root = p.root
        child.umask = p.umask
        child.uid, child.euid, child.suid = p.uid, p.euid, p.suid
        child.gid, child.egid, child.sgid = p.gid, p.egid, p.sgid
        child.blocked = p.blocked
        child.sigactions = list(p.sigactions)
        child.close_on_exec = p.close_on_exec
        child.name = p.name
        # fd 表逐项复制但指向同一 OpenFile —— fork 后共享文件位置,
        # 这是 `sh > file` 重定向语义的根基
        for i, f in enumerate(p.fds):
            if f is not None:
                self._acquire_fd(f)
                child.fds[i] = f
        child.cpu = self._make_cpu(child.mem, child)
        child.cpu.restore(p.cpu.snapshot())
        child.cpu.regs[0] = 0                 # 子进程 fork 返回 0
        self.procs[child.pid] = child
        self.runq.append(child.pid)
        return child.pid

    def sys_waitpid(self, p, pid, statp, options):
        pid = pid if pid < 0x80000000 else pid - 0x100000000
        kids = [q for q in self.procs.values() if q.ppid == p.pid]
        if not kids:
            return -kvfs.ECHILD

        def wanted(q):
            if pid > 0:
                return q.pid == pid
            if pid == 0:
                return q.pgrp == p.pgrp
            if pid == -1:
                return True
            return q.pgrp == -pid

        cands = [q for q in kids if wanted(q)]
        if not cands:
            return -kvfs.ECHILD
        for q in cands:
            if q.state == ZOMBIE:
                if statp:
                    p.mem.write_u32(statp, q.exit_code & 0xFFFFFFFF)
                p.cutime += q.utime
                p.cstime += q.stime
                self._reap(q)
                return q.pid
        if options & 1:                       # WNOHANG
            return 0
        raise Blocked(("wait", p.pid))

    def _reap(self, q: Process) -> None:
        """回收一个僵尸: 先把它的性能快照存进历史, 再从进程表移除。"""
        self.proc_history.append(ProcPerf(q))
        del self.procs[q.pid]

    def _exit_process(self, p: Process, code: int) -> None:
        p.state = ZOMBIE
        p.exit_code = code
        for i, f in enumerate(p.fds):
            if f is not None:
                self._release_file(f)
                p.fds[i] = None
        p.mem = AddressSpace()               # 释放地址空间
        for q in self.procs.values():        # 孤儿过继给 init
            if q.ppid == p.pid:
                q.ppid = 1
        if p.pid in self.runq:
            self.runq.remove(p.pid)
        parent = self.procs.get(p.ppid)
        if parent is not None:
            self.post_signal(parent, SIGCHLD)
            if parent.state == SLEEPING and \
                    isinstance(parent.wait_channel, tuple) and \
                    parent.wait_channel[0] == "wait":
                self._wake(parent)
        if p.ppid == 0:                      # init 退出 -> 整机结束
            self.exit_status = code

    def _acquire_fd(self, f: OpenFile) -> None:
        """多出一个指向该 OpenFile 的描述符(fork/dup/dup2)."""
        f.refs += 1
        if isinstance(f.obj, Pipe):
            # 管道按**描述符**计数: 只有指向写端的描述符全部关闭, 读端才见 EOF
            if f.readable:
                f.obj.readers += 1
            if f.writable:
                f.obj.writers += 1

    def _release_file(self, f: OpenFile) -> None:
        f.refs -= 1
        obj = f.obj
        if isinstance(obj, Pipe):
            # 每关一个描述符就减一次, 不能等 refs 归零 —— fork 出来的描述符
            # 共享同一个 OpenFile, 否则写端永远关不掉, 读端永远等不到 EOF
            if f.readable:
                obj.readers = max(obj.readers - 1, 0)
            if f.writable:
                obj.writers = max(obj.writers - 1, 0)
        elif isinstance(obj, VInode) and f.refs <= 0:
            obj.open_refs = max(obj.open_refs - 1, 0)

    # ---- 管道 ---------------------------------------------------------

    def sys_pipe(self, p, fds, b, c):
        pipe = Pipe()
        rfd = p.alloc_fd()
        rf = OpenFile(pipe, 0)
        p.fds[rfd] = rf
        try:
            wfd = p.alloc_fd()
        except FsError:
            p.fds[rfd] = None
            raise
        wf = OpenFile(pipe, O_WRONLY)
        p.fds[wfd] = wf
        pipe.readers = 1
        pipe.writers = 1
        p.mem.write_u32(fds, rfd)
        p.mem.write_u32(fds + 4, wfd)
        return 0

    # ---- 信号(基础部分, 帧构造在 K5) -----------------------------------

    def post_signal(self, p: Process, sig: int) -> None:
        if sig <= 0 or sig > 32:
            return
        p.signal |= 1 << (sig - 1)
        if p.state != SLEEPING or (p.blocked & (1 << (sig - 1))):
            return
        # 只有真会被递达的信号才打断睡眠。默认动作是"忽略"的信号(SIGCHLD/
        # SIGCONT)不能让 waitpid 拿到 EINTR —— 否则 bash 会把 -EINTR 当成
        # 调用号重新执行 int 0x80。
        handler = p.sigactions[sig][0] if sig < len(p.sigactions) else 0
        if handler == 1:
            return
        if handler == 0 and sig in IGNORED_BY_DEFAULT:
            return
        self._wake(p, interrupted=True)

    def _wake(self, p: Process, interrupted: bool = False) -> None:
        """唤醒睡眠进程.

        阻塞时 eip 已被回卷 2 字节以便重做 int 0x80。被信号打断的情形要把
        eip 推回去(系统调用不重做), 并让 eax 带上 -EINTR。
        """
        if p.state != SLEEPING:
            return
        p.state = RUNNING
        p.wait_channel = None
        if interrupted and p.restart_syscall:
            p.cpu.eip = (p.cpu.eip + 2) & 0xFFFFFFFF
            p.cpu.regs[0] = (-kvfs.EINTR) & 0xFFFFFFFF
            p.restart_syscall = False
        if p.pid not in self.runq:
            self.runq.append(p.pid)

    def sys_kill(self, p, pid, sig, c):
        pid = pid if pid < 0x80000000 else pid - 0x100000000
        targets = []
        for q in self.procs.values():
            if pid > 0 and q.pid == pid:
                targets.append(q)
            elif pid == 0 and q.pgrp == p.pgrp:
                targets.append(q)
            elif pid == -1 and q.pid > 1:
                targets.append(q)
            elif pid < -1 and q.pgrp == -pid:
                targets.append(q)
        if not targets:
            return -kvfs.ESRCH
        if sig == 0:
            return 0
        for q in targets:
            self.post_signal(q, sig)
        return 0

    def sys_sgetmask(self, p, a, b, c):
        return p.blocked

    def sys_ssetmask(self, p, mask, b, c):
        old = p.blocked
        p.blocked = mask & ~(1 << (SIGKILL - 1))
        return old

    def sys_pause(self, p, a, b, c):
        raise Blocked(("pause", p.pid))

    def sys_setsid(self, p, a, b, c):
        if p.leader:
            return -EPERM
        p.leader = True
        p.session = p.pid
        p.pgrp = p.pid
        return p.pgrp

    def sys_setpgid(self, p, pid, pgid, c):
        target = p if pid == 0 else self.procs.get(pid)
        if target is None:
            return -kvfs.ESRCH
        target.pgrp = pgid or target.pid
        return 0

    def sys_alarm(self, p, secs, b, c):
        remain = max((p.alarm_at - self.jiffies) // HZ, 0) if p.alarm_at else 0
        p.alarm_at = self.jiffies + secs * HZ if secs else 0
        return remain

    # ---- 内建 init(内核 init/main.c 的 init() 函数) ---------------------

    def boot_init(self) -> Process:
        """按内核 init/main.c 的 init() 建立 task 1.

        Linux 0.11 的 init **不是磁盘上的程序**, 而是内核里的 init() 函数在用户态
        执行(镜像里的 /bin/init 是后来某个软件包的东西, 不在 0.11 引导链上)。原文:

            setup(...); open("/dev/tty0",O_RDWR,0); dup(0); dup(0);
            if (!(pid=fork())) {                     // 跑 /etc/rc
                close(0); if (open("/etc/rc",O_RDONLY,0)) _exit(1);
                execve("/bin/sh", argv_rc, envp_rc); _exit(2);
            }
            if (pid>0) while (pid != wait(&i));
            while (1) {                              // 反复起登录 shell
                if (!(pid=fork())) {
                    close(0);close(1);close(2); setsid();
                    open("/dev/tty0",O_RDWR,0); dup(0); dup(0);
                    _exit(execve("/bin/sh", argv, envp));
                }
                while (1) if (pid == wait(&i)) break;
                printf("child %d died with code %04x", pid, i); sync();
            }
        其中 argv_rc = {"/bin/sh"}, envp_rc = {"HOME=/"};
        argv = {"-/bin/sh"}(前导 '-' 使其成为 login shell), envp = {"HOME=/usr/root"}。

        这里把 init 实现成 Python 层的内核任务: 不占用户态 CPU, 由调度器在
        _init_step 里按状态机推进。
        """
        p = self._new_process()          # pid 1
        p.ppid = 0
        p.name = "init"
        p.cpu = None                     # 内核任务, 没有用户态 CPU
        p.kernel_task = True
        self.init_proc = p
        self._init_state = "rc"
        self._init_child = 0
        self._setup_std_fds(p)           # 等价于 open("/dev/tty0"); dup(0); dup(0)
        self.current = p
        return p

    def _spawn(self, path: str, argv: List[bytes], envp: List[bytes],
               stdin_from: Optional[str] = None,
               new_session: bool = False) -> int:
        """替 init 起一个子进程(相当于 fork + 重定向 + execve)."""
        child = self._new_process()
        child.ppid = self.init_proc.pid
        child.name = path
        v, argv = resolve_exec(self.fs, path, argv, child.cwd, child.root)
        entry, _ = load_aout(child.mem, self.fs, v)
        esp = setup_stack(child.mem, argv, envp)
        child.cpu = self._make_cpu(child.mem, child)
        child.cpu.eip = entry
        child.cpu.regs[4] = esp
        if new_session:
            child.leader = True
            child.session = child.pid
            child.pgrp = child.pid
        self._setup_std_fds(child)
        if stdin_from is not None:
            # init 跑 rc 时是 close(0) 后 open("/etc/rc") —— 让 sh 从脚本读命令
            if child.fds[0] is not None:
                self._release_file(child.fds[0])
            script = self.fs.walk(stdin_from, child.cwd, child.root)
            script.open_refs += 1
            child.fds[0] = OpenFile(script, 0)
        if self.terminal is not None and new_session:
            self.terminal.session = child.session
            self.terminal.pgrp = child.pgrp
        if child.pid not in self.runq:
            self.runq.append(child.pid)
        return child.pid

    def _init_step(self) -> None:
        """推进内建 init 的状态机(替代 init 的用户态执行)."""
        if self._init_state == "rc":
            try:
                self._init_child = self._spawn(
                    "/bin/sh", [b"/bin/sh"], [b"HOME=/"], stdin_from="/etc/rc")
                self._init_state = "wait_rc"
            except (FsError, ExecError):
                self._init_state = "shell"       # 没有 /etc/rc 就直接起 shell
            return
        if self._init_state in ("wait_rc", "wait_shell"):
            child = self.procs.get(self._init_child)
            if child is None or child.state == ZOMBIE:
                was_shell = self._init_state == "wait_shell"
                if child is not None:
                    code = child.exit_code
                    self._reap(child)
                    if was_shell:
                        self._write_console(
                            f"\nchild {child.pid} died with code {code:04x}\n")
                # 真机上控制台不会 EOF, 所以 init 无限重启 shell 是对的; 但输入是
                # 管道/脚本时耗尽后再重启只会空转, 此时就地收场。
                self._init_state = "shell" if (not was_shell or
                                               self._console_alive()) else "done"
            return
        if self._init_state == "shell":
            # argv[0] 的前导 '-' 让 bash 以 login shell 启动(会读 /etc/profile)
            try:
                self._init_child = self._spawn(
                    "/bin/sh", [b"-/bin/sh"], [b"HOME=/usr/root"],
                    new_session=True)
                self._init_state = "wait_shell"
            except (FsError, ExecError) as e:
                self._write_console(f"init: 无法启动 /bin/sh: {e}\r\n")
                self._init_state = "done"
            return

    def _console_alive(self) -> bool:
        """控制台还能再提供输入吗?

        交互终端永远算活着(真机上控制台不会 EOF); 管道/脚本输入耗尽后算死。
        """
        if self.terminal is None:
            return False
        term = self.terminal.term
        if term.is_tty():
            return True
        if getattr(term, "at_eof", False):
            return False
        return bool(getattr(term, "pending", None)) or bool(self.terminal.ready)

    def on_escape(self, ch: bytes) -> None:
        """处理转义键(默认 Ctrl-A)之后的命令字符, 仿 qemu 的 Ctrl-A 前缀."""
        import kmonitor

        low = ch.lower()
        if low == b"x":
            self.quit_requested = True
            self._write_console("\n仿真器退出。\n")
        elif low == b"c":
            self.monitor_pending = True
        elif low in (b"?", b"h"):
            self._write_console("\n" + kmonitor.ESCAPE_HELP)

    def _write_console(self, text: str) -> None:
        """向控制台写内核自己的消息.

        用 UTF-8 而不是 latin-1: 这些消息含中文, latin-1 编不出来。UTF-8 的
        续字节都 >= 0x80, 不会和 ONLCR 的换行处理撞车。
        """
        if self.terminal is not None:
            self.terminal.write(text.encode("utf-8", "replace"))

    # ---- 调度 ---------------------------------------------------------

    def _pump_tty(self) -> None:
        if self.terminal is not None:
            self.terminal.pump()

    def _check_alarms(self) -> None:
        for q in list(self.procs.values()):
            if q.alarm_at and self.jiffies >= q.alarm_at:
                q.alarm_at = 0
                self.post_signal(q, SIGALRM)

    def _pick(self) -> Optional[Process]:
        """轮转挑一个可运行进程."""
        n = len(self.runq)
        for _ in range(n):
            pid = self.runq.pop(0)
            q = self.procs.get(pid)
            if q is None or q.state == ZOMBIE:
                continue
            self.runq.append(pid)
            if q.state == RUNNING and not q.kernel_task:
                return q
        return None

    def run(self, max_instructions: int = 2_000_000_000) -> int:
        """调度循环: 协作式 + 指令预算."""
        if self.current is not None and self.current.pid not in self.runq:
            self.runq.append(self.current.pid)
        total = 0
        idle = 0
        while total < max_instructions:
            if self.quit_requested:
                return self.exit_status
            if self.monitor_pending:
                self.monitor_pending = False
                if self.monitor is not None:
                    self.monitor.interact()
                if self.quit_requested:
                    return self.exit_status
            self._pump_tty()
            self._check_alarms()
            self._wake_waiters()             # 每轮都查等待条件, 否则两端互等会卡死
            self._deliver_pending()
            if self._init_state != "done":
                self._init_step()            # 内建 init 的状态机
            p = self._pick()
            if p is None:
                alive = any(q.state != ZOMBIE and not q.kernel_task
                            for q in self.procs.values())
                if not alive and self._init_state == "done":
                    break
                if self.terminal is not None:
                    self.terminal.pump(0.02)      # 阻塞等输入并喂给行规程
                self.jiffies += 2
                idle += 1
                if idle > 20000:            # 全员永久睡眠, 无输入可来
                    break
                continue
            idle = 0
            self.current = p
            cpu = p.cpu
            before = cpu.icount
            t0 = time.perf_counter()
            try:
                if self.breakpoints or self.step_request:
                    self._run_debug_slice(p, cpu)   # 逐指令, 查断点/步数
                else:
                    cpu.run(TIMESLICE)              # 快路径: 一字节不改
                if cpu.halted:
                    self._exit_process(p, 0)
                    if self._debug_active():
                        self._debug_break(("halted", p.pid))
            except Exited as e:
                if self._debug_active():
                    self._debug_break(("exited", p.pid, e.code))
                self._exit_process(p, e.code)
                if p.ppid == 0:
                    return e.code
            except Replaced:
                if self._debug_active():
                    self._debug_break(("execve", p.pid))
                # execve 已换好新 CPU, 下轮继续跑它
            except MagicJump:
                self._sigreturn(p)
                if self._debug_active():
                    self._debug_break(("sigreturn", p.pid))
            except Blocked as e:
                p.state = SLEEPING
                p.wait_channel = e.channel
                p.restart_syscall = True
                cpu.eip -= 2                 # int 0x80 是 CD 80 两字节, 回卷重做
                if p.pid in self.runq:
                    self.runq.remove(p.pid)
                if self._debug_active():
                    self._debug_break(("blocked", p.pid, e.channel))
            finally:
                # 用 icount 差值记账 —— 阻塞/退出都是异常路径, 靠 run() 的
                # 返回值会漏记, 导致 max_instructions 永远到不了。
                n = max(cpu.icount - before, 1)
                total += n
                p.utime += n
                p.wall += time.perf_counter() - t0    # 按进程累计宿主墙钟耗时
                self.jiffies += max(n * HZ // TIMESLICE, 1)
        return self.exit_status

    # ---- 单步调试 -----------------------------------------------------

    def _debug_active(self) -> bool:
        """是否正处于调试(有断点、正在单步, 或 --debug 锁定了目标)."""
        return bool(self.breakpoints or self.step_request
                    or self.debug_target_pid is not None)

    def _debug_break(self, reason: tuple) -> None:
        """记下停因并请求进入 monitor; 顺带清空残留步数以免串到别的进程."""
        self.step_request = 0
        self.debug_stop = reason
        self.monitor_pending = True

    def _run_debug_slice(self, p: Process, cpu) -> None:
        """调试激活时的逐指令时间片: 每执行一条就查断点/步数, 命中即进 monitor。

        断点**执行后**检查: 停时 eip==X 且 X 尚未执行(gdb 语义); 从断点 cont 时先
        执行 X 再检查, 天然不会立刻重命中同一断点。异常(Exited/Blocked/...)由
        cpu.run(1) 抛出, 一路穿回 run() 的异常臂处理。
        """
        budget = 1 if self.step_request else TIMESLICE
        pinned = self.debug_target_pid in (None, p.pid)
        ran = 0
        while ran < budget and not cpu.halted:
            cpu.run(1)                      # 执行 eip 处一条; 递增 icount
            ran += 1
            if self.step_request and pinned:
                self.step_request -= 1
                if self.step_request == 0:
                    self._debug_break(("step", p.pid))
                    return
            if cpu.eip in self.breakpoints or cpu.eip in self.temp_breakpoints:
                self.temp_breakpoints.discard(cpu.eip)
                self._debug_break(("break", p.pid, cpu.eip))
                return

    def _sigreturn(self, p: Process) -> None:
        """兜底的信号返回: 弹出 _build_signal_frame 压下的帧.

        正常情况下 libc 的 sa_restorer 会在用户态自己弹栈; 只有 restorer 为 0
        时才走到这里(我们把 MAGIC_SIGRETURN 当作 restorer 压了进去)。
        栈上此刻是: [signr] [blocked?] [eax] [ecx] [edx] [eflags] [old_eip]
        (restorer 已被 handler 的 ret 弹掉)。
        """
        cpu = p.cpu
        cpu.pop32()                            # signr
        # 帧里有没有 blocked 取决于当初 sigaction 的 SA_NOMASK, 无法从栈上看出,
        # 所以在压帧时记在进程上
        if p.sigframes:
            if p.sigframes.pop():
                p.blocked = cpu.pop32()
        cpu.regs[0] = cpu.pop32()
        cpu.regs[1] = cpu.pop32()
        cpu.regs[2] = cpu.pop32()
        cpu.eflags = cpu.pop32()
        cpu.eip = cpu.pop32()

    def _wake_waiters(self) -> None:
        """检查睡眠进程的等待条件是否已满足."""
        for q in list(self.procs.values()):
            if q.state != SLEEPING:
                continue
            ch = q.wait_channel
            if isinstance(ch, tuple) and ch[0] == "piperead":
                # 读端: 有数据可读, 或写端全关(EOF)才唤醒
                if ch[1].buf or ch[1].writers == 0:
                    self._wake(q)
            elif isinstance(ch, tuple) and ch[0] == "pipewrite":
                # 写端: 有空位, 或读端全关(该收 EPIPE)才唤醒
                if ch[1].space > 0 or ch[1].readers == 0:
                    self._wake(q)
            elif isinstance(ch, tuple) and ch[0] == "wait":
                if any(r.ppid == q.pid and r.state == ZOMBIE
                       for r in self.procs.values()):
                    self._wake(q)
            elif ch is self.terminal:
                if self.terminal is not None and \
                        (self.terminal.ready or self.terminal.eof_pending):
                    self._wake(q)

    def _deliver_pending(self) -> None:
        """在指令边界投递信号(与内核 ret_from_sys_call 处的时机等价)."""
        for q in list(self.procs.values()):
            if q.state == ZOMBIE:
                continue
            pend = q.signal & ~q.blocked
            if not pend:
                continue
            sig = (pend & -pend).bit_length()          # 最低位优先, 同 bsfl
            q.signal &= ~(1 << (sig - 1))
            self._take_signal(q, sig)

    def _take_signal(self, q: Process, sig: int) -> None:
        handler = q.sigactions[sig][0] if sig < len(q.sigactions) else 0
        if handler == 1:                              # SIG_IGN
            return
        if handler == 0:                              # SIG_DFL
            if sig in IGNORED_BY_DEFAULT:
                return
            if sig in STOP_SIGNALS:
                q.state = STOPPED
                if q.pid in self.runq:
                    self.runq.remove(q.pid)
                return
            if q.state == SLEEPING:
                q.state = RUNNING
            self._exit_process(q, sig)
            if q.ppid == 0:
                self.exit_status = sig
            return
        self._build_signal_frame(q, sig)

    def _build_signal_frame(self, q: Process, sig: int) -> None:
        """在用户栈上构造信号帧.

        布局照内核 kernel/signal.c 的 do_signal: 压 7 或 8 个长字
        (SA_NOMASK 时 7 个), 顺序为
        sa_restorer, signr, [blocked,] eax, ecx, edx, eflags, old_eip;
        然后把 eip 改成 handler。0.11 没有 sigreturn 系统调用 —— 返回靠
        libc 提供的 sa_restorer 在用户态弹栈恢复。
        """
        handler, mask, flags, restorer = q.sigactions[sig]
        cpu = q.cpu
        if q.state == SLEEPING:
            q.state = RUNNING
            q.wait_channel = None
            if q.pid not in self.runq:
                self.runq.append(q.pid)
        old_eip = cpu.eip
        eax, ecx, edx = cpu.regs[0], cpu.regs[1], cpu.regs[2]
        eflags = cpu.eflags
        nomask = bool(flags & SA_NOMASK)
        cpu.push32(old_eip)
        cpu.push32(eflags)
        cpu.push32(edx)
        cpu.push32(ecx)
        cpu.push32(eax)
        if not nomask:
            cpu.push32(q.blocked)
        q.sigframes.append(not nomask)
        cpu.push32(sig)
        cpu.push32(restorer or MAGIC_SIGRETURN)
        cpu.eip = handler
        q.blocked |= mask
        if flags & SA_ONESHOT:
            q.sigactions[sig] = (0, mask, flags, restorer)

    def sys_signal(self, p, sig, handler, restorer):
        """0.11 的 signal 是三参: ebx=signum, ecx=handler, edx=restorer."""
        if not 1 <= sig <= 32 or sig == SIGKILL:
            return -EINVAL
        old = p.sigactions[sig][0]
        p.sigactions[sig] = (handler, 0, SA_ONESHOT | SA_NOMASK, restorer)
        return old

    def sys_sigaction(self, p, sig, newp, oldp):
        if not 1 <= sig <= 32 or sig == SIGKILL:
            return -EINVAL
        cur = p.sigactions[sig]
        if oldp:
            for i, v in enumerate(cur):
                p.mem.write_u32(oldp + 4 * i, v)
        if newp:
            vals = tuple(p.mem.read_u32(newp + 4 * i) for i in range(4))
            p.sigactions[sig] = vals
        return 0


class NullDevice:
    """/dev/null."""

    def read(self, n: int) -> bytes:
        return b""

    def write(self, data: bytes) -> int:
        return len(data)
