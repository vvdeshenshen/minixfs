"""kexec 加载器与系统调用层测试.

系统调用测试用 FakeCPU(一个只有 regs 与 mem 的壳), 不需要任何 x86 解码;
端到端合同测试则在迷你镜像里塞一个手写的 a.out, 真正走完
CPU -> int 0x80 -> 内核 -> 终端 这条链, 且不依赖真实镜像。
"""

import io
import struct
import unittest

import cpu86
import kernel as kmod
import kexec
import ksyscall
import ktty
import kvfs
from kernel import Kernel, NR_OPEN, Exited, OpenFile, Process
from kexec import AoutHeader, ExecError, load_aout, parse_shebang, setup_stack
from ksyscall import STAT_FMT, Blocked, pack_stat
from kvfs import EBADF, EINVAL, EISDIR, ENOENT, ENOTTY, FsError, OverlayFS
from minixfs import MinixFS
from test_minixfs import build_image
from x86mem import ARG_AREA, TASK_SIZE, AddressSpace

ZMAGIC = 0o413


# ---------------------------------------------------------------------------
# 手写 a.out: 用于端到端合同测试
# ---------------------------------------------------------------------------

def make_aout(code: bytes, data: bytes = b"", bss: int = 0,
              entry: int = 0) -> bytes:
    """构造一个最小的 ZMAGIC a.out.

    头 32 字节 + 填充到 1024(N_TXTOFF) + text + data。
    """
    text = len(code)
    hdr = struct.pack("<8I", ZMAGIC, text, len(data), bss, 0, entry, 0, 0)
    return hdr + bytes(kexec.N_TXTOFF - len(hdr)) + code + data


def hello_program(msg: bytes = b"hello\n", exit_code: int = 0) -> bytes:
    """write(1, msg, len(msg)); exit(code) 的机器码.

    字符串放在 text 段尾部, 地址 = 代码长度(text 从虚址 0 装载)。
    """
    body_len = 5 + 5 + 5 + 5 + 2 + 5 + 5 + 2      # 下面各指令长度之和
    msg_addr = body_len
    code = (
        b"\xb8" + struct.pack("<I", 4) +           # mov eax, 4 (write)
        b"\xbb" + struct.pack("<I", 1) +           # mov ebx, 1 (fd)
        b"\xb9" + struct.pack("<I", msg_addr) +    # mov ecx, msg
        b"\xba" + struct.pack("<I", len(msg)) +    # mov edx, len
        b"\xcd\x80" +                              # int 0x80
        b"\xb8" + struct.pack("<I", 1) +           # mov eax, 1 (exit)
        b"\xbb" + struct.pack("<I", exit_code) +   # mov ebx, code
        b"\xcd\x80"                                # int 0x80
    )
    assert len(code) == body_len, (len(code), body_len)
    return code + msg


class FakeCPU:
    """系统调用测试用的 CPU 壳: 只有寄存器与内存(不含任何 x86 解码)."""

    def __init__(self, mem):
        self.mem = mem
        self.regs = [0] * 8
        self.eip = 0
        self.eflags = 0x0202       # 与真 CPU 一样有 eflags(monitor 会读它)
        self.icount = 0
        self.halted = False


def make_kernel(inputs=None, image=None):
    """搭 迷你镜像 -> 覆盖层 -> 脚本化终端 -> 内核."""
    raw = image if image is not None else build_image()
    fs = OverlayFS(MinixFS(io.BytesIO(raw), offset=0))
    term = ktty.ScriptedTerminal(inputs=inputs or [])
    tty = ktty.TTY(term)
    k = Kernel(fs, terminal=tty)
    return k, term, fs


def make_proc(k, fs):
    """造一个可做系统调用的进程(不需要真实程序)."""
    p = k._new_process()
    p.mem = AddressSpace()
    p.mem.load_program(b"\x90" * 64, b"", 0x4000)
    p.cpu = FakeCPU(p.mem)
    k._setup_std_fds(p)
    k.current = p
    return p


def put_str(p, addr, s: bytes) -> int:
    p.mem.write(addr, s + b"\x00")
    return addr


class SyscallTestCase(unittest.TestCase):
    def setUp(self):
        self.k, self.term, self.fs = make_kernel()
        self.p = make_proc(self.k, self.fs)
        self.scratch = 0x2000

    def call(self, nr, a=0, b=0, c=0):
        """直接调分派表, 返回 eax(负值即 -errno)."""
        try:
            return self.k.syscalls.dispatch(self.p, nr, a, b, c)
        except FsError as e:
            return -e.errno

    def path(self, s: str, at=0x2800) -> int:
        return put_str(self.p, at, s.encode())


# ---------------------------------------------------------------------------
# a.out 头与加载
# ---------------------------------------------------------------------------

class TestAoutHeader(unittest.TestCase):
    def test_parse_fields(self):
        raw = struct.pack("<8I", ZMAGIC, 100, 200, 300, 0, 0, 0, 0)
        h = AoutHeader(raw)
        self.assertEqual((h.magic, h.text, h.data, h.bss), (ZMAGIC, 100, 200, 300))

    def test_reject_wrong_magic(self):
        h = AoutHeader(struct.pack("<8I", 0o407, 10, 0, 0, 0, 0, 0, 0))
        with self.assertRaises(ExecError) as ctx:
            h.validate(2000)
        self.assertEqual(ctx.exception.errno, kvfs.ENOEXEC)

    def test_reject_relocation_info(self):
        h = AoutHeader(struct.pack("<8I", ZMAGIC, 10, 0, 0, 0, 0, 4, 0))
        with self.assertRaises(ExecError):
            h.validate(2000)

    def test_reject_oversize(self):
        h = AoutHeader(struct.pack("<8I", ZMAGIC, 0x3000000, 0, 0x1000,
                                   0, 0, 0, 0))
        with self.assertRaises(ExecError):
            h.validate(0x4000000)

    def test_reject_truncated_file(self):
        h = AoutHeader(struct.pack("<8I", ZMAGIC, 5000, 0, 0, 0, 0, 0, 0))
        with self.assertRaises(ExecError):
            h.validate(100)

    def test_short_header_raises(self):
        with self.assertRaises(ExecError):
            AoutHeader(b"\x00" * 8)


class TestLoadAout(unittest.TestCase):
    def setUp(self):
        self.k, self.term, self.fs = make_kernel()

    def _make_file(self, blob: bytes, mode=0o755):
        v = self.fs.create("/prog", mode)
        self.fs.write(v, 0, blob)
        return v

    def test_load_layout(self):
        v = self._make_file(make_aout(b"\x90" * 16, b"DATA", bss=32))
        mem = AddressSpace()
        entry, brk = load_aout(mem, self.fs, v)
        self.assertEqual(entry, 0)
        self.assertEqual(mem.read(0, 16), b"\x90" * 16)
        self.assertEqual(mem.read(16, 4), b"DATA")
        self.assertEqual(mem.read(20, 32), bytes(32))    # bss 清零
        self.assertEqual(brk, 16 + 4 + 32)
        self.assertEqual(mem.text_end, 16)

    def test_load_without_exec_bit_fails(self):
        v = self._make_file(make_aout(b"\x90"), mode=0o644)
        with self.assertRaises(ExecError) as ctx:
            load_aout(AddressSpace(), self.fs, v)
        self.assertEqual(ctx.exception.errno, kvfs.EACCES)

    def test_code_read_from_offset_1024(self):
        marker = b"\xde\xad\xbe\xef"
        v = self._make_file(make_aout(marker))
        mem = AddressSpace()
        load_aout(mem, self.fs, v)
        self.assertEqual(mem.read(0, 4), marker)


# ---------------------------------------------------------------------------
# 初始栈布局(内核 create_tables)
# ---------------------------------------------------------------------------

class TestSetupStack(unittest.TestCase):
    def setUp(self):
        self.mem = AddressSpace()
        self.mem.load_program(b"\x90" * 16, b"", 0)

    def test_argc_argv_envp_at_esp(self):
        argv = [b"prog", b"-x", b"file"]
        envp = [b"A=1", b"HOME=/root"]
        esp = setup_stack(self.mem, argv, envp)
        self.assertEqual(self.mem.read_u32(esp), 3)          # argc
        argv_ptr = self.mem.read_u32(esp + 4)
        envp_ptr = self.mem.read_u32(esp + 8)
        got_argv = [self.mem.read_cstr(self.mem.read_u32(argv_ptr + 4 * i))
                    for i in range(3)]
        self.assertEqual(got_argv, argv)
        self.assertEqual(self.mem.read_u32(argv_ptr + 12), 0)    # argv 以 NULL 结尾
        got_envp = [self.mem.read_cstr(self.mem.read_u32(envp_ptr + 4 * i))
                    for i in range(2)]
        self.assertEqual(got_envp, envp)
        self.assertEqual(self.mem.read_u32(envp_ptr + 8), 0)

    def test_empty_argv_and_envp(self):
        esp = setup_stack(self.mem, [], [])
        self.assertEqual(self.mem.read_u32(esp), 0)
        argv_ptr = self.mem.read_u32(esp + 4)
        self.assertEqual(self.mem.read_u32(argv_ptr), 0)

    def test_esp_is_four_byte_aligned(self):
        esp = setup_stack(self.mem, [b"a"], [b"b"])
        self.assertEqual(esp % 4, 0)

    def test_strings_within_arg_area(self):
        esp = setup_stack(self.mem, [b"x" * 100], [b"y" * 100])
        argv_ptr = self.mem.read_u32(esp + 4)
        s = self.mem.read_u32(argv_ptr)
        self.assertGreaterEqual(s, TASK_SIZE - ARG_AREA)
        self.assertLess(s, TASK_SIZE)

    def test_too_big_raises_e2big(self):
        with self.assertRaises(ExecError) as ctx:
            setup_stack(self.mem, [b"x" * (ARG_AREA + 10)], [])
        self.assertEqual(ctx.exception.errno, kvfs.E2BIG)

    def test_start_stack_recorded(self):
        esp = setup_stack(self.mem, [b"a"], [])
        self.assertEqual(self.mem.start_stack, esp & 0xFFFFF000)


# ---------------------------------------------------------------------------
# shebang
# ---------------------------------------------------------------------------

class TestShebang(unittest.TestCase):
    def test_plain_interpreter(self):
        self.assertEqual(parse_shebang(b"#!/bin/sh\nexit 0\n"), ("/bin/sh", None))

    def test_interpreter_with_arg(self):
        self.assertEqual(parse_shebang(b"#!/bin/awk -f\n"), ("/bin/awk", "-f"))

    def test_not_a_script(self):
        self.assertIsNone(parse_shebang(b"\x0b\x01\x00\x00"))
        self.assertIsNone(parse_shebang(b"#!\n"))

    def test_resolve_exec_rewrites_argv(self):
        k, term, fs = make_kernel()
        real = fs.create("/interp", 0o755)
        fs.write(real, 0, make_aout(b"\x90"))
        script = fs.create("/script", 0o755)
        fs.write(script, 0, b"#!/interp\necho hi\n")
        v, argv = kexec.resolve_exec(fs, "/script", [b"/script", b"arg1"])
        self.assertIs(v, real)
        self.assertEqual(argv, [b"/interp", b"/script", b"arg1"])

    def test_resolve_exec_with_interpreter_arg(self):
        k, term, fs = make_kernel()
        real = fs.create("/interp", 0o755)
        fs.write(real, 0, make_aout(b"\x90"))
        script = fs.create("/s", 0o755)
        fs.write(script, 0, b"#!/interp -f\n")
        v, argv = kexec.resolve_exec(fs, "/s", [b"/s"])
        self.assertEqual(argv, [b"/interp", b"-f", b"/s"])


# ---------------------------------------------------------------------------
# 系统调用: 进程信息与时间
# ---------------------------------------------------------------------------

class TestProcessSyscalls(SyscallTestCase):
    def test_getpid_family(self):
        self.assertEqual(self.call(ksyscall.NR_GETPID), self.p.pid)
        self.assertEqual(self.call(ksyscall.NR_GETPPID), self.p.ppid)
        self.assertEqual(self.call(ksyscall.NR_GETUID), 0)
        self.assertEqual(self.call(ksyscall.NR_GETEUID), 0)
        self.assertEqual(self.call(ksyscall.NR_GETGID), 0)
        self.assertEqual(self.call(ksyscall.NR_GETPGRP), self.p.pgrp)

    def test_umask_returns_old(self):
        self.assertEqual(self.call(ksyscall.NR_UMASK, 0o077), 0o022)
        self.assertEqual(self.p.umask, 0o077)
        self.assertEqual(self.call(ksyscall.NR_UMASK, 0o022), 0o077)

    def test_setuid_as_root_then_drop(self):
        self.assertEqual(self.call(ksyscall.NR_SETUID, 100), 0)
        self.assertEqual((self.p.uid, self.p.euid), (100, 100))
        # 降权后不能再随意提权
        self.assertEqual(self.call(ksyscall.NR_SETUID, 200), -kvfs.EPERM)

    def test_time_writes_optional_pointer(self):
        t = self.call(ksyscall.NR_TIME, self.scratch)
        self.assertGreater(t, 1_000_000_000)
        self.assertEqual(self.p.mem.read_u32(self.scratch), t)

    def test_uname_fields(self):
        self.assertEqual(self.call(ksyscall.NR_UNAME, self.scratch), 0)
        raw = self.p.mem.read(self.scratch, 45)
        fields = [raw[i * 9:(i + 1) * 9].split(b"\x00")[0].decode()
                  for i in range(5)]
        self.assertEqual(fields[0], "Linux")
        self.assertEqual(fields[2], "0.11")

    def test_times_writes_four_longs(self):
        self.assertGreaterEqual(self.call(ksyscall.NR_TIMES, self.scratch), 0)
        for i in range(4):
            self.assertEqual(self.p.mem.read_u32(self.scratch + 4 * i), 0)

    def test_brk_semantics(self):
        """恒返回当前 brk, 不返回 -errno(照 kernel/sys.c)."""
        old = self.p.mem.brk
        new = self.call(ksyscall.NR_BRK, old + 8192)
        self.assertEqual(new, old + 8192)
        # 非法值: 返回旧 brk 而不是负数
        self.assertEqual(self.call(ksyscall.NR_BRK, 0), old + 8192)
        self.assertEqual(self.call(ksyscall.NR_BRK, TASK_SIZE - 4), old + 8192)

    def test_exit_raises_exited_with_shifted_code(self):
        with self.assertRaises(Exited) as ctx:
            self.call(ksyscall.NR_EXIT, 3)
        self.assertEqual(ctx.exception.code, 3 << 8)

    def test_unknown_syscall_returns_enosys(self):
        self.assertEqual(self.call(200), -kvfs.ENOSYS)
        self.assertEqual(self.call(ksyscall.NR_PTRACE), -kvfs.ENOSYS)

    def test_sync_and_nice_are_noops(self):
        self.assertEqual(self.call(ksyscall.NR_SYNC), 0)
        self.assertEqual(self.call(ksyscall.NR_NICE, 5), 0)

    def test_mount_denied(self):
        self.assertEqual(self.call(ksyscall.NR_MOUNT), -kvfs.EPERM)

    def test_ulimit_returns_enosys(self):
        """0.11 里 ulimit 就是个 stub。这条以前没测, 掩盖了 kernel.py 漏导入
        ENOSYS 的 bug —— 真被调到会抛 NameError 而不是返回 -ENOSYS。"""
        self.assertEqual(self.call(ksyscall.NR_ULIMIT, 3, 0, 0), -kvfs.ENOSYS)


# ---------------------------------------------------------------------------
# 系统调用: 文件
# ---------------------------------------------------------------------------

class TestFileSyscalls(SyscallTestCase):
    def test_open_read_close(self):
        fd = self.call(ksyscall.NR_OPEN, self.path("/hello.txt"), 0, 0)
        self.assertGreaterEqual(fd, 3)
        n = self.call(ksyscall.NR_READ, fd, self.scratch, 100)
        self.assertEqual(n, 14)
        self.assertEqual(self.p.mem.read(self.scratch, n), b"Hello, Minix!\n")
        self.assertEqual(self.call(ksyscall.NR_CLOSE, fd), 0)
        self.assertEqual(self.call(ksyscall.NR_READ, fd, self.scratch, 1), -EBADF)

    def test_open_missing_returns_enoent(self):
        self.assertEqual(self.call(ksyscall.NR_OPEN, self.path("/nope"), 0, 0),
                         -ENOENT)

    def test_open_creat_makes_file(self):
        fd = self.call(ksyscall.NR_OPEN, self.path("/new"),
                       kvfs.O_CREAT | kvfs.O_WRONLY, 0o644)
        self.assertGreaterEqual(fd, 3)
        self.p.mem.write(self.scratch, b"written")
        self.assertEqual(self.call(ksyscall.NR_WRITE, fd, self.scratch, 7), 7)
        self.call(ksyscall.NR_CLOSE, fd)
        self.assertEqual(self.fs.read(self.fs.walk("/new"), 0, 99), b"written")

    def test_open_excl_on_existing_fails(self):
        r = self.call(ksyscall.NR_OPEN, self.path("/hello.txt"),
                      kvfs.O_CREAT | kvfs.O_EXCL, 0o644)
        self.assertEqual(r, -kvfs.EEXIST)

    def test_open_trunc_empties_file(self):
        fd = self.call(ksyscall.NR_OPEN, self.path("/hello.txt"),
                       kvfs.O_TRUNC | kvfs.O_WRONLY, 0)
        self.call(ksyscall.NR_CLOSE, fd)
        self.assertEqual(self.fs.walk("/hello.txt").size, 0)

    def test_open_append_positions_at_end(self):
        fd = self.call(ksyscall.NR_OPEN, self.path("/hello.txt"),
                       kvfs.O_APPEND | kvfs.O_WRONLY, 0)
        self.p.mem.write(self.scratch, b"XY")
        self.call(ksyscall.NR_WRITE, fd, self.scratch, 2)
        self.assertEqual(self.fs.read(self.fs.walk("/hello.txt"), 0, 99),
                         b"Hello, Minix!\nXY")

    def test_open_dir_for_write_fails(self):
        self.assertEqual(self.call(ksyscall.NR_OPEN, self.path("/sub"),
                                   kvfs.O_WRONLY, 0), -EISDIR)

    def test_read_directory_gives_raw_dirents(self):
        """0.11 的 opendir 就是直接 read 目录 fd."""
        fd = self.call(ksyscall.NR_OPEN, self.path("/sub"), 0, 0)
        n = self.call(ksyscall.NR_READ, fd, self.scratch, 256)
        self.assertEqual(n % 16, 0)
        raw = self.p.mem.read(self.scratch, n)
        names = []
        for off in range(0, n, 16):
            ino = struct.unpack_from("<H", raw, off)[0]
            if ino:
                names.append(raw[off + 2:off + 16].split(b"\x00")[0].decode())
        self.assertIn("note.txt", names)

    def test_lseek_all_whences(self):
        fd = self.call(ksyscall.NR_OPEN, self.path("/hello.txt"), 0, 0)
        self.assertEqual(self.call(ksyscall.NR_LSEEK, fd, 7, 0), 7)
        n = self.call(ksyscall.NR_READ, fd, self.scratch, 5)
        self.assertEqual(self.p.mem.read(self.scratch, n), b"Minix")
        self.assertEqual(self.call(ksyscall.NR_LSEEK, fd, 0, 2), 14)   # SEEK_END
        self.assertEqual(self.call(ksyscall.NR_LSEEK, fd, -4, 1), 10)  # SEEK_CUR
        self.assertEqual(self.call(ksyscall.NR_LSEEK, fd, 0, 9), -EINVAL)

    def test_lseek_negative_result_invalid(self):
        fd = self.call(ksyscall.NR_OPEN, self.path("/hello.txt"), 0, 0)
        self.assertEqual(self.call(ksyscall.NR_LSEEK, fd, -1, 0), -EINVAL)

    def test_lseek_on_tty_is_espipe(self):
        self.assertEqual(self.call(ksyscall.NR_LSEEK, 1, 0, 0), -kvfs.ESPIPE)

    def test_stat_struct_bytes(self):
        self.assertEqual(self.call(ksyscall.NR_STAT, self.path("/hello.txt"),
                                   self.scratch), 0)
        raw = self.p.mem.read(self.scratch, STAT_FMT.size)
        self.assertEqual(STAT_FMT.size, 32)
        expect = pack_stat(self.fs.stat_tuple(self.fs.walk("/hello.txt")))
        self.assertEqual(raw, expect)
        # 逐字段核对
        dev, ino, mode, nlink, uid, gid, rdev, size, at, mt, ct = \
            STAT_FMT.unpack(raw)
        self.assertEqual(ino, 2)
        self.assertEqual(size, 14)
        self.assertEqual(uid, 10)
        self.assertEqual(gid, 20)
        self.assertEqual((at, mt, ct), (mt, mt, mt))   # 三时间戳同值

    def test_stat_out_of_range_mtime_packs_unsigned(self):
        """镜像里有 mtime 超出有符号 i32 的文件, 必须原样按 32 位拷."""
        v = self.fs.walk("/hello.txt")
        v.mtime = 2729881325
        raw = pack_stat(self.fs.stat_tuple(v))
        self.assertEqual(STAT_FMT.unpack(raw)[9], 2729881325)

    def test_fstat_on_open_file(self):
        fd = self.call(ksyscall.NR_OPEN, self.path("/hello.txt"), 0, 0)
        self.assertEqual(self.call(ksyscall.NR_FSTAT, fd, self.scratch), 0)
        self.assertEqual(STAT_FMT.unpack(
            self.p.mem.read(self.scratch, 32))[7], 14)

    def test_dup_and_dup2_share_position(self):
        fd = self.call(ksyscall.NR_OPEN, self.path("/hello.txt"), 0, 0)
        self.call(ksyscall.NR_READ, fd, self.scratch, 7)
        dup = self.call(ksyscall.NR_DUP, fd)
        n = self.call(ksyscall.NR_READ, dup, self.scratch, 5)
        self.assertEqual(self.p.mem.read(self.scratch, n), b"Minix")
        self.assertEqual(self.call(ksyscall.NR_DUP2, fd, 9), 9)
        self.assertIs(self.p.fds[9], self.p.fds[fd])

    def test_dup2_closes_target_first(self):
        a = self.call(ksyscall.NR_OPEN, self.path("/hello.txt"), 0, 0)
        b = self.call(ksyscall.NR_OPEN, self.path("/sub/note.txt"), 0, 0)
        self.assertEqual(self.call(ksyscall.NR_DUP2, a, b), b)
        self.assertIs(self.p.fds[b], self.p.fds[a])

    def test_fcntl_getfd_setfd(self):
        fd = self.call(ksyscall.NR_OPEN, self.path("/hello.txt"), 0, 0)
        self.assertEqual(self.call(ksyscall.NR_FCNTL, fd, 1, 0), 0)
        self.assertEqual(self.call(ksyscall.NR_FCNTL, fd, 2, 1), 0)
        self.assertEqual(self.call(ksyscall.NR_FCNTL, fd, 1, 0), 1)
        self.assertEqual(self.call(ksyscall.NR_FCNTL, fd, 3, 0) & 3, 0)

    def test_fcntl_dupfd_from_index(self):
        fd = self.call(ksyscall.NR_OPEN, self.path("/hello.txt"), 0, 0)
        new = self.call(ksyscall.NR_FCNTL, fd, 0, 10)
        self.assertGreaterEqual(new, 10)

    def test_mkdir_rmdir_unlink_rename(self):
        self.assertEqual(self.call(ksyscall.NR_MKDIR, self.path("/d"), 0o755), 0)
        self.assertTrue(self.fs.walk("/d").is_dir)
        self.assertEqual(self.call(ksyscall.NR_RMDIR, self.path("/d")), 0)
        self.assertEqual(self.call(ksyscall.NR_CREAT, self.path("/f"), 0o644) >= 3,
                         True)
        p2 = put_str(self.p, 0x2900, b"/f2")
        self.assertEqual(self.call(ksyscall.NR_RENAME, self.path("/f"), p2), 0)
        self.assertEqual(self.call(ksyscall.NR_UNLINK, p2), 0)
        self.assertEqual(self.call(ksyscall.NR_UNLINK, p2), -ENOENT)

    def test_link_creates_hardlink(self):
        p2 = put_str(self.p, 0x2900, b"/hard")
        self.assertEqual(self.call(ksyscall.NR_LINK,
                                   self.path("/hello.txt"), p2), 0)
        self.assertIs(self.fs.walk("/hard"), self.fs.walk("/hello.txt"))

    def test_chdir_changes_relative_resolution(self):
        self.assertEqual(self.call(ksyscall.NR_CHDIR, self.path("/sub")), 0)
        fd = self.call(ksyscall.NR_OPEN, self.path("note.txt"), 0, 0)
        self.assertGreaterEqual(fd, 3)

    def test_chdir_to_file_fails(self):
        self.assertEqual(self.call(ksyscall.NR_CHDIR,
                                   self.path("/hello.txt")), -kvfs.ENOTDIR)

    def test_chmod_and_chown(self):
        self.assertEqual(self.call(ksyscall.NR_CHMOD,
                                   self.path("/hello.txt"), 0o600), 0)
        self.assertEqual(self.fs.walk("/hello.txt").mode & 0o777, 0o600)
        self.assertEqual(self.call(ksyscall.NR_CHOWN,
                                   self.path("/hello.txt"), 7, 8), 0)
        self.assertEqual(self.fs.walk("/hello.txt").uid, 7)

    def test_access_existing_and_missing(self):
        self.assertEqual(self.call(ksyscall.NR_ACCESS,
                                   self.path("/hello.txt"), 0), 0)
        self.assertEqual(self.call(ksyscall.NR_ACCESS, self.path("/nope"), 0),
                         -ENOENT)

    def test_chroot_confines_paths(self):
        self.assertEqual(self.call(ksyscall.NR_CHROOT, self.path("/sub")), 0)
        self.assertGreaterEqual(self.call(ksyscall.NR_OPEN,
                                          self.path("/note.txt"), 0, 0), 3)
        self.assertEqual(self.call(ksyscall.NR_OPEN,
                                   self.path("/hello.txt"), 0, 0), -ENOENT)

    def test_readlink_symlink_unsupported(self):
        self.assertEqual(self.call(ksyscall.NR_READLINK,
                                   self.path("/hello.txt"), self.scratch, 10),
                         -EINVAL)
        self.assertEqual(self.call(ksyscall.NR_SYMLINK,
                                   self.path("/a"), self.path("/b")),
                         -kvfs.EPERM)

    def test_lstat_equals_stat(self):
        self.call(ksyscall.NR_STAT, self.path("/hello.txt"), self.scratch)
        a = self.p.mem.read(self.scratch, 32)
        self.call(ksyscall.NR_LSTAT, self.path("/hello.txt"), self.scratch + 64)
        self.assertEqual(a, self.p.mem.read(self.scratch + 64, 32))

    def test_getrlimit_returns_large_limits(self):
        self.assertEqual(self.call(ksyscall.NR_GETRLIMIT, 0, self.scratch), 0)
        self.assertEqual(self.p.mem.read_u32(self.scratch), 0x7FFFFFFF)

    def test_fd_table_exhaustion(self):
        for _ in range(NR_OPEN):
            r = self.call(ksyscall.NR_OPEN, self.path("/hello.txt"), 0, 0)
            if r < 0:
                self.assertEqual(r, -kvfs.EMFILE)
                return
        self.fail("fd 表应该用尽并返回 EMFILE")


# ---------------------------------------------------------------------------
# 系统调用: 终端
# ---------------------------------------------------------------------------

class TestTtySyscalls(SyscallTestCase):
    def test_write_to_stdout_reaches_terminal(self):
        self.p.mem.write(self.scratch, b"out!\n")
        self.assertEqual(self.call(ksyscall.NR_WRITE, 1, self.scratch, 5), 5)
        self.assertIn("out!", self.term.text)

    def test_read_from_tty(self):
        self.term.pending.append(b"typed\n")
        n = self.call(ksyscall.NR_READ, 0, self.scratch, 100)
        self.assertEqual(self.p.mem.read(self.scratch, n), b"typed\n")

    def test_ioctl_on_file_is_enotty(self):
        """isatty() 靠这个返回值判断是否终端."""
        fd = self.call(ksyscall.NR_OPEN, self.path("/hello.txt"), 0, 0)
        self.assertEqual(self.call(ksyscall.NR_IOCTL, fd, ktty.TCGETS,
                                   self.scratch), -ENOTTY)

    def test_ioctl_tcgets_on_tty(self):
        self.assertEqual(self.call(ksyscall.NR_IOCTL, 1, ktty.TCGETS,
                                   self.scratch), 0)
        raw = self.p.mem.read(self.scratch, ktty.TERMIOS_FMT.size)
        iflag, oflag, cflag, lflag, line, cc = ktty.TERMIOS_FMT.unpack(raw)
        self.assertTrue(lflag & ktty.ICANON)
        self.assertEqual(cc[ktty.VINTR], 3)      # ^C
        self.assertEqual(cc[ktty.VERASE], 127)   # DEL

    def test_ioctl_winsize(self):
        self.assertEqual(self.call(ksyscall.NR_IOCTL, 1, ktty.TIOCGWINSZ,
                                   self.scratch), 0)
        rows, cols, _, _ = ktty.WINSIZE_FMT.unpack(
            self.p.mem.read(self.scratch, 8))
        self.assertEqual((rows, cols), (24, 80))

    def test_ioctl_unknown_is_einval(self):
        self.assertEqual(self.call(ksyscall.NR_IOCTL, 1, 0x9999,
                                   self.scratch), -EINVAL)


# ---------------------------------------------------------------------------
# 端到端合同测试: 手写 a.out 走完整条链
# ---------------------------------------------------------------------------

class TestEndToEnd(unittest.TestCase):
    """CPU 层与内核层的合同测试, 不依赖真实镜像."""

    def _run(self, code: bytes, argv=None, envp=None, inputs=None):
        k, term, fs = make_kernel(inputs=inputs)
        v = fs.create("/prog", 0o755)
        fs.write(v, 0, make_aout(code))
        k.boot("/prog", argv or [b"/prog"], envp)
        rc = k.run(2_000_000)
        return k, term, rc

    def test_hello_world(self):
        k, term, rc = self._run(hello_program(b"hello\n"))
        # tty 上 ONLCR 把 \n 展开为 \r\n, 这是正确行为
        self.assertEqual(term.text, "hello\r\n")
        self.assertEqual(rc, 0)

    def test_exit_code_propagates(self):
        k, term, rc = self._run(hello_program(b"x", exit_code=7))
        self.assertEqual(rc, 7 << 8)

    def test_program_sees_argv(self):
        """读 [esp+4] 拿 argv, 打印 argv[1]."""
        code = (
            b"\x8b\x6c\x24\x04" +                  # mov ebp, [esp+4]  (argv)
            b"\x8b\x4d\x04" +                      # mov ecx, [ebp+4]  (argv[1])
            b"\xb8" + struct.pack("<I", 4) +       # mov eax, 4 (write)
            b"\xbb" + struct.pack("<I", 1) +       # mov ebx, 1
            b"\xba" + struct.pack("<I", 3) +       # mov edx, 3
            b"\xcd\x80" +
            b"\xb8" + struct.pack("<I", 1) +
            b"\x31\xdb" +                          # xor ebx, ebx
            b"\xcd\x80")
        k, term, rc = self._run(code, argv=[b"/prog", b"ABC"])
        self.assertEqual(term.text, "ABC")

    def test_program_sees_envp(self):
        """读 [esp+8] 拿 envp(与 /bin/date 入口同一套路)."""
        code = (
            b"\x8b\x6c\x24\x08" +                  # mov ebp, [esp+8]  (envp)
            b"\x8b\x4d\x00" +                      # mov ecx, [ebp]    (envp[0])
            b"\xb8" + struct.pack("<I", 4) +
            b"\xbb" + struct.pack("<I", 1) +
            b"\xba" + struct.pack("<I", 5) +
            b"\xcd\x80" +
            b"\xb8" + struct.pack("<I", 1) +
            b"\x31\xdb" + b"\xcd\x80")
        k, term, rc = self._run(code, envp=[b"K=abc"])
        self.assertEqual(term.text, "K=abc")

    def test_open_read_write_roundtrip(self):
        """open("/hello.txt") -> read -> write(1) 全链路."""
        buf = 0x3000
        path_addr = 0x3400
        code = (
            b"\xb8" + struct.pack("<I", 5) +        # mov eax, 5 (open)
            b"\xbb" + struct.pack("<I", path_addr) +
            b"\x31\xc9" +                          # xor ecx, ecx (O_RDONLY)
            b"\x31\xd2" +                          # xor edx, edx
            b"\xcd\x80" +
            b"\x89\xc3" +                          # mov ebx, eax (fd)
            b"\xb8" + struct.pack("<I", 3) +       # mov eax, 3 (read)
            b"\xb9" + struct.pack("<I", buf) +
            b"\xba" + struct.pack("<I", 64) +
            b"\xcd\x80" +
            b"\x89\xc2" +                          # mov edx, eax (读到的字节数)
            b"\xb8" + struct.pack("<I", 4) +       # mov eax, 4 (write)
            b"\xbb" + struct.pack("<I", 1) +
            b"\xb9" + struct.pack("<I", buf) +
            b"\xcd\x80" +
            b"\xb8" + struct.pack("<I", 1) +
            b"\x31\xdb" + b"\xcd\x80")
        k, term, fs = make_kernel()
        v = fs.create("/prog", 0o755)
        fs.write(v, 0, make_aout(code))
        k.boot("/prog", [b"/prog"])
        k.current.mem.write(path_addr, b"/hello.txt\x00")
        k.run(2_000_000)
        self.assertEqual(term.text, "Hello, Minix!\r\n")

    def test_brk_then_use_new_memory(self):
        code = (
            b"\xb8" + struct.pack("<I", 45) +      # mov eax, 45 (brk)
            b"\x31\xdb" +                          # xor ebx, ebx -> 查询当前 brk
            b"\xcd\x80" +
            b"\x8d\x98" + struct.pack("<I", 0x2000) +   # lea ebx, [eax+0x2000]
            b"\xb8" + struct.pack("<I", 45) +
            b"\xcd\x80" +
            b"\x89\xc1" +                          # mov ecx, eax (新 brk)
            b"\xc6\x41\xf0\x5a" +                  # mov byte [ecx-16], 'Z'
            b"\xb8" + struct.pack("<I", 4) +       # write(1, ecx-16, 1)
            b"\xbb" + struct.pack("<I", 1) +
            b"\x83\xe9\x10" +                      # sub ecx, 16
            b"\xba" + struct.pack("<I", 1) +
            b"\xcd\x80" +
            b"\xb8" + struct.pack("<I", 1) +
            b"\x31\xdb" + b"\xcd\x80")
        k, term, rc = self._run(code)
        self.assertEqual(term.text, "Z")

    def test_write_to_created_file(self):
        path_addr = 0x3400
        code = (
            b"\xb8" + struct.pack("<I", 8) +       # mov eax, 8 (creat)
            b"\xbb" + struct.pack("<I", path_addr) +
            b"\xb9" + struct.pack("<I", 0o644) +
            b"\xcd\x80" +
            b"\x89\xc3" +                          # mov ebx, eax
            b"\xb8" + struct.pack("<I", 4) +       # write
            b"\xb9" + struct.pack("<I", path_addr) +
            b"\xba" + struct.pack("<I", 4) +
            b"\xcd\x80" +
            b"\xb8" + struct.pack("<I", 1) +
            b"\x31\xdb" + b"\xcd\x80")
        k, term, fs = make_kernel()
        v = fs.create("/prog", 0o755)
        fs.write(v, 0, make_aout(code))
        k.boot("/prog", [b"/prog"])
        k.current.mem.write(path_addr, b"/out\x00")
        k.run(2_000_000)
        self.assertEqual(fs.read(fs.walk("/out"), 0, 99), b"/out")

    def test_shebang_script_runs_interpreter(self):
        k, term, fs = make_kernel()
        interp = fs.create("/interp", 0o755)
        fs.write(interp, 0, make_aout(hello_program(b"via interp\n")))
        script = fs.create("/script", 0o755)
        fs.write(script, 0, b"#!/interp\n")
        k.boot("/script", [b"/script"])
        k.run(2_000_000)
        self.assertEqual(term.text, "via interp\r\n")

    def test_stdout_and_stderr_share_terminal(self):
        code = (
            b"\xb8" + struct.pack("<I", 4) +
            b"\xbb" + struct.pack("<I", 2) +       # fd 2 (stderr)
            b"\xb9" + struct.pack("<I", 0) +       # 指向 text 开头
            b"\xba" + struct.pack("<I", 1) +
            b"\xcd\x80" +
            b"\xb8" + struct.pack("<I", 1) +
            b"\x31\xdb" + b"\xcd\x80")
        k, term, rc = self._run(code)
        self.assertEqual(len(term.out), 1)      # stderr 也落到同一终端


class TestForkExecWait(unittest.TestCase):
    """多进程原语."""

    def setUp(self):
        self.k, self.term, self.fs = make_kernel()
        self.p = make_proc(self.k, self.fs)
        self.p.cpu = kmod.CPU(self.p.mem, on_int=self.k._on_int,
                              on_fault=self.k._on_fault)
        self.p.cpu.regs[4] = TASK_SIZE - 64

    def fork(self):
        return self.k.syscalls.dispatch(self.p, ksyscall.NR_FORK, 0, 0, 0)

    def test_fork_returns_child_pid_to_parent(self):
        pid = self.fork()
        self.assertGreater(pid, self.p.pid)
        child = self.k.procs[pid]
        self.assertEqual(child.ppid, self.p.pid)
        self.assertEqual(child.cpu.regs[0], 0)        # 子进程返回 0

    def test_fork_memory_is_independent(self):
        self.p.mem.write_u32(0x1000, 0xAAAA)
        pid = self.fork()
        child = self.k.procs[pid]
        child.mem.write_u32(0x1000, 0xBBBB)
        self.assertEqual(self.p.mem.read_u32(0x1000), 0xAAAA)
        self.assertEqual(child.mem.read_u32(0x1000), 0xBBBB)

    def test_fork_shares_file_position(self):
        """fork 后共享 OpenFile, 故共享读写位置 —— `sh > file` 的语义基础."""
        path = put_str(self.p, 0x2800, b"/hello.txt")
        fd = self.k.syscalls.dispatch(self.p, ksyscall.NR_OPEN, path, 0, 0)
        self.k.syscalls.dispatch(self.p, ksyscall.NR_READ, fd, 0x2000, 7)
        pid = self.fork()
        child = self.k.procs[pid]
        self.assertIs(child.fds[fd], self.p.fds[fd])
        n = self.k.syscalls.dispatch(child, ksyscall.NR_READ, fd, 0x2000, 5)
        self.assertEqual(child.mem.read(0x2000, n), b"Minix")   # 接着父进程读

    def test_fork_inherits_cwd_and_umask(self):
        self.p.umask = 0o077
        self.p.cwd = self.fs.walk("/sub")
        child = self.k.procs[self.fork()]
        self.assertEqual(child.umask, 0o077)
        self.assertIs(child.cwd, self.p.cwd)

    def test_waitpid_reaps_zombie_and_gives_status(self):
        pid = self.fork()
        child = self.k.procs[pid]
        self.k._exit_process(child, 5 << 8)
        r = self.k.syscalls.dispatch(self.p, ksyscall.NR_WAITPID,
                                     pid, 0x2000, 0)
        self.assertEqual(r, pid)
        self.assertEqual(self.p.mem.read_u32(0x2000), 5 << 8)
        self.assertNotIn(pid, self.k.procs)       # 僵尸已回收

    def test_waitpid_no_children_is_echild(self):
        r = self.k.syscalls.dispatch(self.p, ksyscall.NR_WAITPID, -1, 0, 0)
        self.assertEqual(r, -kvfs.ECHILD)

    def test_waitpid_wnohang_returns_zero(self):
        self.fork()
        r = self.k.syscalls.dispatch(self.p, ksyscall.NR_WAITPID, -1, 0, 1)
        self.assertEqual(r, 0)

    def test_waitpid_blocks_when_child_alive(self):
        self.fork()
        with self.assertRaises(Blocked):
            self.k.syscalls.dispatch(self.p, ksyscall.NR_WAITPID, -1, 0, 0)

    def test_orphans_reparent_to_init(self):
        pid = self.fork()
        child = self.k.procs[pid]
        gpid = self.k.syscalls.dispatch(child, ksyscall.NR_FORK, 0, 0, 0)
        self.k._exit_process(child, 0)
        self.assertEqual(self.k.procs[gpid].ppid, 1)

    def test_exit_status_encoding(self):
        """正常退出是 code<<8, 被信号杀是 signr."""
        pid = self.fork()
        self.k._exit_process(self.k.procs[pid], 3 << 8)
        self.k.syscalls.dispatch(self.p, ksyscall.NR_WAITPID, pid, 0x2000, 0)
        self.assertEqual(self.p.mem.read_u32(0x2000) >> 8, 3)


class TestPipeSyscall(unittest.TestCase):
    def setUp(self):
        self.k, self.term, self.fs = make_kernel()
        self.p = make_proc(self.k, self.fs)

    def make_pipe(self):
        self.k.syscalls.dispatch(self.p, ksyscall.NR_PIPE, 0x2100, 0, 0)
        return (self.p.mem.read_u32(0x2100), self.p.mem.read_u32(0x2104))

    def test_pipe_returns_two_fds(self):
        r, w = self.make_pipe()
        self.assertNotEqual(r, w)
        self.assertIsInstance(self.p.fds[r].obj, kvfs.Pipe)
        self.assertIs(self.p.fds[r].obj, self.p.fds[w].obj)

    def test_write_then_read_through_pipe(self):
        r, w = self.make_pipe()
        self.p.mem.write(0x2000, b"data")
        self.assertEqual(self.k.syscalls.dispatch(
            self.p, ksyscall.NR_WRITE, w, 0x2000, 4), 4)
        n = self.k.syscalls.dispatch(self.p, ksyscall.NR_READ, r, 0x2200, 10)
        self.assertEqual(self.p.mem.read(0x2200, n), b"data")

    def test_read_empty_pipe_blocks(self):
        r, w = self.make_pipe()
        with self.assertRaises(Blocked) as ctx:
            self.k.syscalls.dispatch(self.p, ksyscall.NR_READ, r, 0x2200, 10)
        self.assertEqual(ctx.exception.channel[0], "piperead")

    def test_read_after_all_writers_closed_is_eof(self):
        r, w = self.make_pipe()
        self.k.syscalls.dispatch(self.p, ksyscall.NR_CLOSE, w, 0, 0)
        self.assertEqual(self.k.syscalls.dispatch(
            self.p, ksyscall.NR_READ, r, 0x2200, 10), 0)

    def test_pipe_counts_track_descriptors_not_openfiles(self):
        """fork 出来的描述符共享 OpenFile, 但管道端计数必须按描述符算,
        否则父进程 close 后写端永远关不掉, 读端等不到 EOF(真实死锁场景)."""
        r, w = self.make_pipe()
        pipe = self.p.fds[r].obj
        self.assertEqual((pipe.readers, pipe.writers), (1, 1))
        self.p.cpu = kmod.CPU(self.p.mem, on_int=self.k._on_int,
                              on_fault=self.k._on_fault)
        self.p.cpu.regs[4] = TASK_SIZE - 64
        cpid = self.k.syscalls.dispatch(self.p, ksyscall.NR_FORK, 0, 0, 0)
        self.assertEqual((pipe.readers, pipe.writers), (2, 2))
        child = self.k.procs[cpid]
        # 父进程关掉两端, 子进程仍持有
        self.k.syscalls.dispatch(self.p, ksyscall.NR_CLOSE, r, 0, 0)
        self.k.syscalls.dispatch(self.p, ksyscall.NR_CLOSE, w, 0, 0)
        self.assertEqual((pipe.readers, pipe.writers), (1, 1))
        # 子进程关写端后, 读端才该见到 EOF
        self.k.syscalls.dispatch(child, ksyscall.NR_CLOSE, w, 0, 0)
        self.assertEqual(pipe.writers, 0)
        self.assertEqual(self.k.syscalls.dispatch(
            child, ksyscall.NR_READ, r, 0x2200, 10), 0)

    def test_dup_increments_pipe_count(self):
        r, w = self.make_pipe()
        pipe = self.p.fds[w].obj
        self.k.syscalls.dispatch(self.p, ksyscall.NR_DUP, w, 0, 0)
        self.assertEqual(pipe.writers, 2)

    def test_lseek_on_pipe_is_espipe(self):
        r, w = self.make_pipe()
        self.assertEqual(self.k.syscalls.dispatch(
            self.p, ksyscall.NR_LSEEK, r, 0, 0), -kvfs.ESPIPE)


class TestSignals(unittest.TestCase):
    def setUp(self):
        self.k, self.term, self.fs = make_kernel()
        self.p = make_proc(self.k, self.fs)
        self.p.cpu = kmod.CPU(self.p.mem, on_int=self.k._on_int,
                              on_fault=self.k._on_fault)
        self.p.cpu.regs[4] = TASK_SIZE - 256

    def test_signal_registers_handler_and_returns_old(self):
        r = self.k.syscalls.dispatch(self.p, ksyscall.NR_SIGNAL, 2, 0x1234, 0x5678)
        self.assertEqual(r, 0)
        self.assertEqual(self.p.sigactions[2][0], 0x1234)
        self.assertEqual(self.p.sigactions[2][3], 0x5678)   # restorer
        r2 = self.k.syscalls.dispatch(self.p, ksyscall.NR_SIGNAL, 2, 1, 0)
        self.assertEqual(r2, 0x1234)                        # 返回旧 handler

    def test_signal_on_sigkill_rejected(self):
        self.assertEqual(self.k.syscalls.dispatch(
            self.p, ksyscall.NR_SIGNAL, kmod.SIGKILL, 0x100, 0), -EINVAL)

    def test_sgetmask_ssetmask(self):
        old = self.k.syscalls.dispatch(self.p, ksyscall.NR_SSETMASK, 0xF0, 0, 0)
        self.assertEqual(old, 0)
        self.assertEqual(self.k.syscalls.dispatch(
            self.p, ksyscall.NR_SGETMASK, 0, 0, 0), 0xF0)

    def test_ssetmask_cannot_block_sigkill(self):
        self.k.syscalls.dispatch(self.p, ksyscall.NR_SSETMASK, 0xFFFFFFFF, 0, 0)
        self.assertEqual(self.p.blocked & (1 << (kmod.SIGKILL - 1)), 0)

    def test_signal_frame_layout(self):
        """帧布局照内核 kernel/signal.c 的 do_signal 逐字断言."""
        self.p.sigactions[kmod.SIGINT] = (0x9000, 0x0, 0, 0xAB00)
        self.p.blocked = 0x55
        cpu = self.p.cpu
        cpu.eip = 0x1234
        cpu.regs[0], cpu.regs[1], cpu.regs[2] = 0xAA, 0xBB, 0xCC
        flags = cpu.eflags
        self.k._build_signal_frame(self.p, kmod.SIGINT)
        self.assertEqual(cpu.eip, 0x9000)                # 跳到 handler
        sp = cpu.regs[4]
        got = [cpu.mem.read_u32(sp + 4 * i) for i in range(8)]
        self.assertEqual(got, [0xAB00,      # sa_restorer(handler 的返回地址)
                               kmod.SIGINT,  # signr(handler 的参数)
                               0x55,         # blocked(非 SA_NOMASK 才有)
                               0xAA, 0xBB, 0xCC,   # eax ecx edx
                               flags, 0x1234])     # eflags, old_eip

    def test_signal_frame_without_mask_when_nomask(self):
        self.p.sigactions[kmod.SIGINT] = (0x9000, 0, kmod.SA_NOMASK, 0xAB00)
        cpu = self.p.cpu
        cpu.eip = 0x1234
        self.k._build_signal_frame(self.p, kmod.SIGINT)
        sp = cpu.regs[4]
        # SA_NOMASK: 只有 7 个长字, 第 3 个直接是 eax 而不是 blocked
        self.assertEqual(cpu.mem.read_u32(sp), 0xAB00)
        self.assertEqual(cpu.mem.read_u32(sp + 4), kmod.SIGINT)
        self.assertEqual(cpu.mem.read_u32(sp + 24), 0x1234)   # 第 7 个长字

    def test_oneshot_resets_handler(self):
        self.p.sigactions[kmod.SIGINT] = (0x9000, 0, kmod.SA_ONESHOT, 0)
        self.k._build_signal_frame(self.p, kmod.SIGINT)
        self.assertEqual(self.p.sigactions[kmod.SIGINT][0], 0)   # 复位 SIG_DFL

    def test_magic_sigreturn_restores_context(self):
        """restorer 为 0 时的兜底: 跳魔数地址 -> 内核弹帧恢复现场."""
        self.p.sigactions[kmod.SIGINT] = (0x9000, 0, 0, 0)
        cpu = self.p.cpu
        cpu.eip = 0x1234
        cpu.regs[0], cpu.regs[1], cpu.regs[2] = 1, 2, 3
        self.p.blocked = 0x11
        self.k._build_signal_frame(self.p, kmod.SIGINT)
        cpu.pop32()                          # 模拟 handler 的 ret 弹掉 restorer
        self.k._sigreturn(self.p)
        self.assertEqual(cpu.eip, 0x1234)
        self.assertEqual([cpu.regs[0], cpu.regs[1], cpu.regs[2]], [1, 2, 3])
        self.assertEqual(self.p.blocked, 0x11)

    def test_kill_posts_signal(self):
        self.assertEqual(self.k.syscalls.dispatch(
            self.p, ksyscall.NR_KILL, self.p.pid, kmod.SIGTERM, 0), 0)
        self.assertTrue(self.p.signal & (1 << (kmod.SIGTERM - 1)))

    def test_kill_signal_zero_probes_only(self):
        self.assertEqual(self.k.syscalls.dispatch(
            self.p, ksyscall.NR_KILL, self.p.pid, 0, 0), 0)
        self.assertEqual(self.p.signal, 0)

    def test_kill_nonexistent_is_esrch(self):
        self.assertEqual(self.k.syscalls.dispatch(
            self.p, ksyscall.NR_KILL, 999, kmod.SIGTERM, 0), -kvfs.ESRCH)

    def test_default_action_terminates(self):
        self.k._take_signal(self.p, kmod.SIGTERM)
        self.assertEqual(self.p.state, kmod.ZOMBIE)

    def test_sigchld_ignored_by_default(self):
        self.k._take_signal(self.p, kmod.SIGCHLD)
        self.assertEqual(self.p.state, kmod.RUNNING)

    def test_stop_signal_stops_process(self):
        self.k._take_signal(self.p, kmod.SIGTSTP)
        self.assertEqual(self.p.state, kmod.STOPPED)

    def test_sig_ign_does_nothing(self):
        self.p.sigactions[kmod.SIGTERM] = (1, 0, 0, 0)      # SIG_IGN
        self.k._take_signal(self.p, kmod.SIGTERM)
        self.assertEqual(self.p.state, kmod.RUNNING)

    def test_lowest_numbered_signal_delivered_first(self):
        """与内核 ret_from_sys_call 里 bsfl 取最低置位一致."""
        self.p.sigactions[kmod.SIGINT] = (0x9000, 0, 0, 0x100)
        self.p.sigactions[kmod.SIGTERM] = (0x9100, 0, 0, 0x100)
        self.p.signal = (1 << (kmod.SIGTERM - 1)) | (1 << (kmod.SIGINT - 1))
        self.k._deliver_pending()
        self.assertEqual(self.p.cpu.eip, 0x9000)        # SIGINT(2) 先于 SIGTERM(15)

    def test_blocked_signal_not_delivered(self):
        self.p.sigactions[kmod.SIGINT] = (0x9000, 0, 0, 0)
        self.p.blocked = 1 << (kmod.SIGINT - 1)
        self.p.signal = 1 << (kmod.SIGINT - 1)
        self.k._deliver_pending()
        self.assertNotEqual(self.p.cpu.eip, 0x9000)
        self.assertTrue(self.p.signal)                  # 仍挂着, 解除屏蔽后再投

    def test_alarm_returns_remaining(self):
        self.assertEqual(self.k.syscalls.dispatch(
            self.p, ksyscall.NR_ALARM, 10, 0, 0), 0)
        self.assertGreater(self.p.alarm_at, 0)
        r = self.k.syscalls.dispatch(self.p, ksyscall.NR_ALARM, 0, 0, 0)
        self.assertEqual(r, 10)
        self.assertEqual(self.p.alarm_at, 0)

    def test_alarm_fires_sigalrm(self):
        self.k.syscalls.dispatch(self.p, ksyscall.NR_ALARM, 1, 0, 0)
        self.k.jiffies = self.p.alarm_at
        self.k._check_alarms()
        self.assertTrue(self.p.signal & (1 << (kmod.SIGALRM - 1)))

    def test_pause_blocks(self):
        with self.assertRaises(Blocked):
            self.k.syscalls.dispatch(self.p, ksyscall.NR_PAUSE, 0, 0, 0)

    def test_setsid_makes_session_leader(self):
        r = self.k.syscalls.dispatch(self.p, ksyscall.NR_SETSID, 0, 0, 0)
        self.assertEqual(r, self.p.pid)
        self.assertTrue(self.p.leader)
        self.assertEqual(self.k.syscalls.dispatch(
            self.p, ksyscall.NR_SETSID, 0, 0, 0), -kvfs.EPERM)

    def test_setpgid(self):
        self.assertEqual(self.k.syscalls.dispatch(
            self.p, ksyscall.NR_SETPGID, 0, 42, 0), 0)
        self.assertEqual(self.p.pgrp, 42)

    def test_sigaction_roundtrip(self):
        vals = (0x1111, 0x2222, 0x3333, 0x4444)
        for i, v in enumerate(vals):
            self.p.mem.write_u32(0x2300 + 4 * i, v)
        self.k.syscalls.dispatch(self.p, ksyscall.NR_SIGACTION, 3, 0x2300, 0)
        self.assertEqual(self.p.sigactions[3], vals)
        self.k.syscalls.dispatch(self.p, ksyscall.NR_SIGACTION, 3, 0, 0x2400)
        got = tuple(self.p.mem.read_u32(0x2400 + 4 * i) for i in range(4))
        self.assertEqual(got, vals)


class TestMultiProcessEndToEnd(unittest.TestCase):
    """手写 a.out 走 fork/exec/管道全链路, 不依赖真实镜像."""

    def _install(self, fs, path, code):
        v = fs.create(path, 0o755)
        fs.write(v, 0, make_aout(code))
        return v

    def test_fork_and_wait(self):
        """父进程 fork, 子进程写 C 后退出, 父进程 waitpid 再写 P."""
        child = (                                    # write(1,[100],1); exit(0)
            b"\xb8" + struct.pack("<I", 4) +
            b"\xbb" + struct.pack("<I", 1) +
            b"\xb9" + struct.pack("<I", 100) +
            b"\xba" + struct.pack("<I", 1) +
            b"\xcd\x80" +
            b"\xb8" + struct.pack("<I", 1) + b"\x31\xdb" + b"\xcd\x80")
        parent = (                       # waitpid(-1,0,0); write(1,[101],1); exit
            b"\xb8" + struct.pack("<I", 7) +
            b"\xbb" + struct.pack("<I", 0xFFFFFFFF) +
            b"\x31\xc9" + b"\x31\xd2" + b"\xcd\x80" +
            b"\xb8" + struct.pack("<I", 4) +
            b"\xbb" + struct.pack("<I", 1) +
            b"\xb9" + struct.pack("<I", 101) +
            b"\xba" + struct.pack("<I", 1) +
            b"\xcd\x80" +
            b"\xb8" + struct.pack("<I", 1) + b"\x31\xdb" + b"\xcd\x80")
        code = (
            b"\xb8" + struct.pack("<I", 2) + b"\xcd\x80" +      # fork
            b"\x85\xc0" +                                       # test eax,eax
            b"\x75" + bytes([len(child)]) +                      # jnz -> parent
            child + parent)
        k, term, fs = make_kernel()
        v = self._install(fs, "/prog", code)
        k.boot("/prog", [b"/prog"])
        k.current.mem.write(100, b"CP")     # 100='C', 101='P'
        k.run(2_000_000)
        # 子进程先写 C, 父进程 wait 到之后写 P
        self.assertEqual(term.text, "CP")

    def test_execve_replaces_image(self):
        k, term, fs = make_kernel()
        self._install(fs, "/target", hello_program(b"target!\n"))
        path_addr = 0x3400
        code = (
            b"\xb8" + struct.pack("<I", 11) +      # execve
            b"\xbb" + struct.pack("<I", path_addr) +
            b"\x31\xc9" + b"\x31\xd2" + b"\xcd\x80" +
            # execve 成功就不会执行到这里
            b"\xb8" + struct.pack("<I", 1) +
            b"\xbb" + struct.pack("<I", 9) + b"\xcd\x80")
        self._install(fs, "/prog", code)
        k.boot("/prog", [b"/prog"])
        k.current.mem.write(path_addr, b"/target\x00")
        rc = k.run(2_000_000)
        self.assertEqual(term.text, "target!\r\n")
        self.assertEqual(rc, 0)               # 不是 9, 说明 execve 真的换了镜像

    def test_pipe_between_parent_and_child(self):
        """父进程写管道, 子进程读出来打印."""
        child = (             # read(rfd, 0x1300, 8); write(1, 0x1300, eax); exit
            b"\x8b\x1d" + struct.pack("<I", 0x1200) +  # mov ebx,[fds+0] (rfd)
            b"\xb8" + struct.pack("<I", 3) +
            b"\xb9" + struct.pack("<I", 0x1300) +
            b"\xba" + struct.pack("<I", 8) +
            b"\xcd\x80" +
            b"\x89\xc2" +                              # mov edx, eax
            b"\xb8" + struct.pack("<I", 4) +
            b"\xbb" + struct.pack("<I", 1) +
            b"\xcd\x80" +
            b"\xb8" + struct.pack("<I", 1) + b"\x31\xdb" + b"\xcd\x80")
        parent = (            # write(wfd,"pipe",4); close(wfd); waitpid; exit
            b"\x8b\x1d" + struct.pack("<I", 0x1204) +  # mov ebx,[fds+4] (wfd)
            b"\xb8" + struct.pack("<I", 4) +
            b"\xb9" + struct.pack("<I", 0x1400) +
            b"\xba" + struct.pack("<I", 4) +
            b"\xcd\x80" +
            b"\xb8" + struct.pack("<I", 6) + b"\xcd\x80" +      # close(wfd)
            b"\xb8" + struct.pack("<I", 7) +
            b"\xbb" + struct.pack("<I", 0xFFFFFFFF) +
            b"\x31\xc9" + b"\x31\xd2" + b"\xcd\x80" +
            b"\xb8" + struct.pack("<I", 1) + b"\x31\xdb" + b"\xcd\x80")
        code = (
            b"\xb8" + struct.pack("<I", 42) +          # pipe(&fds)
            b"\xbb" + struct.pack("<I", 0x1200) +
            b"\xcd\x80" +
            b"\xb8" + struct.pack("<I", 2) + b"\xcd\x80" +      # fork
            b"\x85\xc0" + b"\x75" + bytes([len(child)]) +        # jnz -> parent
            child + parent)
        k, term, fs = make_kernel()
        self._install(fs, "/prog", code)
        k.boot("/prog", [b"/prog"])
        k.current.mem.write(0x1400, b"pipe")
        k.run(3_000_000)
        self.assertEqual(term.text, "pipe")


class TestBuiltinInit(unittest.TestCase):
    """内建 init —— 照内核 init/main.c 的 init() 函数.

    Linux 0.11 的 init 是内核里的函数在用户态执行, 不是磁盘上的 /bin/init。
    这里用迷你镜像 + 手写 a.out 当 /bin/sh, 不依赖真实镜像。
    """

    def setup_world(self, sh_code=None, rc=b"", inputs=None, tty=True):
        k, term, fs = make_kernel(inputs=inputs)
        term._tty = tty
        # /bin/sh: 把 argv[0] 打印出来, 便于验证 login shell 的前导 '-'
        code = sh_code if sh_code is not None else (
            b"\x8b\x6c\x24\x04" +                   # mov ebp,[esp+4]  (argv)
            b"\x8b\x4d\x00" +                       # mov ecx,[ebp]    (argv[0])
            b"\xb8" + struct.pack("<I", 4) +        # write(1, argv[0], 9)
            b"\xbb" + struct.pack("<I", 1) +
            b"\xba" + struct.pack("<I", 9) +
            b"\xcd\x80" +
            b"\xb8" + struct.pack("<I", 1) +        # exit(0)
            b"\x31\xdb" + b"\xcd\x80")
        fs.mkdir("/bin", 0o755)
        v = fs.create("/bin/sh", 0o755)
        fs.write(v, 0, make_aout(code))
        fs.mkdir("/etc", 0o755)
        rcv = fs.create("/etc/rc", 0o644)
        fs.write(rcv, 0, rc)
        return k, term, fs

    def test_runs_rc_then_login_shell(self):
        k, term, fs = self.setup_world(tty=False)
        k.boot_init()
        k.run(3_000_000)
        # 先以 argv[0]="/bin/sh" 跑 rc, 再以 "-/bin/sh" 起 login shell
        self.assertIn("/bin/sh", term.text)
        self.assertIn("-/bin/sh", term.text)
        self.assertLess(term.text.index("/bin/sh"), term.text.index("-/bin/sh"))

    def test_login_shell_argv0_has_leading_dash(self):
        """argv = {"-/bin/sh"} —— 前导 '-' 让 bash 以 login shell 启动读 profile."""
        k, term, fs = self.setup_world(tty=False)
        k.boot_init()
        k.run(3_000_000)
        self.assertIn("-/bin/sh", term.text)

    def test_rc_child_gets_script_on_stdin(self):
        """init 是 close(0) 后 open("/etc/rc") —— sh 从脚本读命令."""
        k, term, fs = self.setup_world(rc=b"# script\n", tty=False)
        k.boot_init()
        k._init_step()                            # 进入 rc 阶段
        child = k.procs[k._init_child]
        self.assertIsNotNone(child.fds[0])
        self.assertEqual(child.fds[0].obj.ino, fs.walk("/etc/rc").ino)

    def test_login_shell_is_session_leader(self):
        k, term, fs = self.setup_world(tty=False)
        k.boot_init()
        k._init_step()                            # rc
        k.procs[k._init_child].state = kmod.ZOMBIE
        k._init_step()                            # 收 rc
        k._init_step()                            # 起 login shell
        shell = k.procs[k._init_child]
        self.assertTrue(shell.leader)
        self.assertEqual(shell.session, shell.pid)
        self.assertEqual(shell.pgrp, shell.pid)

    def test_init_is_pid_1_and_kernel_task(self):
        k, term, fs = self.setup_world(tty=False)
        p = k.boot_init()
        self.assertEqual(p.pid, 1)
        self.assertTrue(p.kernel_task)
        self.assertIsNone(p.cpu)                  # 内核任务不占用户态 CPU

    def test_children_have_init_as_parent(self):
        k, term, fs = self.setup_world(tty=False)
        k.boot_init()
        k._init_step()
        self.assertEqual(k.procs[k._init_child].ppid, 1)

    def test_reports_child_death(self):
        """init 的 while(1) 里会 printf("child %d died with code %04x")."""
        k, term, fs = self.setup_world(tty=True)
        k.boot_init()
        k._init_step()                            # rc
        k.procs[k._init_child].state = kmod.ZOMBIE
        k._init_step()
        k._init_step()                            # 起 shell
        shell_pid = k._init_child
        k.procs[shell_pid].state = kmod.ZOMBIE
        k.procs[shell_pid].exit_code = 0x0200
        k._init_step()                            # 收 shell 并汇报
        self.assertIn(f"child {shell_pid} died with code 0200", term.text)

    def test_respawns_shell_on_a_tty(self):
        """真机控制台不会 EOF, 所以 init 应当反复重启 shell."""
        k, term, fs = self.setup_world(tty=True)
        k.boot_init()
        k._init_step()
        k.procs[k._init_child].state = kmod.ZOMBIE
        k._init_step()
        k._init_step()                            # 第一次 shell
        first = k._init_child
        k.procs[first].state = kmod.ZOMBIE
        k._init_step()
        self.assertEqual(k._init_state, "shell")  # 还要再起
        k._init_step()
        self.assertNotEqual(k._init_child, first)

    def test_stops_respawning_when_input_exhausted(self):
        """输入是管道/脚本时耗尽后不再空转重启."""
        k, term, fs = self.setup_world(tty=False)
        k.boot_init()
        k._init_step()
        k.procs[k._init_child].state = kmod.ZOMBIE
        k._init_step()
        k._init_step()                            # 起 shell
        k.procs[k._init_child].state = kmod.ZOMBIE
        k._init_step()
        self.assertEqual(k._init_state, "done")

    def test_missing_rc_skips_to_shell(self):
        k, term, fs = self.setup_world(tty=False)
        fs.unlink("/etc/rc")
        k.boot_init()
        k._init_step()
        self.assertEqual(k._init_state, "shell")  # 没有 rc 就直接起 shell

    def test_init_needs_no_preset_files(self):
        """内核 init() 开的是镜像里真实存在的 /dev/tty0, 不依赖任何预置文件。

        早先为磁盘上那个错误的 /bin/init 合成过 /dev/console、/etc/utmp、
        /etc/wtmp, 现已删除 —— 这里确认删掉后引导仍能起 rc 子进程。
        """
        k, term, fs = self.setup_world(rc=b"# rc\n", tty=False)
        for path in ("/dev/console", "/etc/utmp", "/etc/wtmp"):
            with self.assertRaises(kvfs.FsError):
                fs.walk(path)               # 确认没有被预置
        k.boot_init()
        k._init_step()                      # rc 阶段应正常 fork 出 sh
        child = k.procs[k._init_child]
        self.assertEqual(child.name, "/bin/sh")
        self.assertEqual(child.fds[0].obj.ino, fs.walk("/etc/rc").ino)

    def test_console_alive_on_tty_always_true(self):
        k, term, fs = self.setup_world(tty=True)
        self.assertTrue(k._console_alive())
        k, term, fs = self.setup_world(tty=False)
        self.assertFalse(k._console_alive())


# ---------------------------------------------------------------------------
# CPU 性能剖析开关
# ---------------------------------------------------------------------------

class TestProfiling(unittest.TestCase):
    def test_off_by_default(self):
        k, _, fs = make_kernel()
        p = make_proc(k, fs)
        self.assertFalse(k.profiling)
        self.assertIsNone(k._make_cpu(AddressSpace(), p).prof)

    def test_set_profiling_gives_each_process_its_own(self):
        k, _, fs = make_kernel()
        p1 = make_proc(k, fs)
        p2 = make_proc(k, fs)
        k.set_profiling(True)
        self.assertTrue(k.profiling)
        # 每进程各一个 Profiler, 不共享(便于按进程/按二进制分析)
        self.assertIsNotNone(p1.prof)
        self.assertIs(p1.cpu.prof, p1.prof)
        self.assertIsNot(p1.prof, p2.prof)

    def test_new_cpu_reuses_process_profiler(self):
        """execve 换 CPU 后应续用同一个进程剖析器, 不新起一份."""
        k, _, fs = make_kernel()
        p = make_proc(k, fs)
        k.set_profiling(True)
        first = p.prof
        cpu2 = k._make_cpu(AddressSpace(), p)      # 模拟 execve 再造 CPU
        self.assertIs(cpu2.prof, first)

    def test_set_profiling_off_keeps_data(self):
        k, _, fs = make_kernel()
        p = make_proc(k, fs)
        k.set_profiling(True)
        p.prof.insns = 3
        k.set_profiling(False)
        self.assertFalse(k.profiling)
        self.assertIsNone(p.cpu.prof)             # 停止采集
        self.assertEqual(p.prof.insns, 3)         # 已采数据保留

    def test_reset_profiling(self):
        k, _, fs = make_kernel()
        p = make_proc(k, fs)
        k.set_profiling(True)
        p.prof.insns = 5
        p.prof.rep_elems = 9
        k.reset_profiling()
        self.assertEqual(p.prof.insns, 0)
        self.assertEqual(p.prof.rep_elems, 0)

    def test_per_process_syscall_counts(self):
        import ksyscall
        k, _, fs = make_kernel()
        p = make_proc(k, fs)
        k._on_int_stats(p, ksyscall.NR_WRITE, 1, 0x100, 5, 5)
        k._on_int_stats(p, ksyscall.NR_WRITE, 1, 0x100, 3, 3)
        self.assertEqual(p.syscall_counts[ksyscall.NR_WRITE], 2)
        self.assertEqual(p.syscall_total, 2)
        self.assertEqual(k.syscall_counts[ksyscall.NR_WRITE], 2)   # 全局也记

    def test_reap_captures_history(self):
        k, _, fs = make_kernel()
        p = make_proc(k, fs)
        p.name = "/bin/thing"
        p.utime = 4242
        p.wall = 0.5
        p.exit_code = 7 << 8
        p.syscall_counts[4] = 3
        prof = cpu86.Profiler()
        p.prof = prof
        pid = p.pid
        k._reap(p)
        self.assertNotIn(pid, k.procs)            # 已从进程表移除
        self.assertEqual(len(k.proc_history), 1)
        rec = k.proc_history[0]
        self.assertEqual((rec.pid, rec.name, rec.icount), (pid, "/bin/thing", 4242))
        self.assertEqual(rec.wall, 0.5)
        self.assertEqual(rec.syscalls[4], 3)
        self.assertIs(rec.prof, prof)
        self.assertEqual(rec.exit_code, 7 << 8)

    def test_end_to_end_per_process_stats(self):
        """开着剖析跑 hello: 该进程记到指令混合、系统调用与墙钟时间。"""
        k, term, fs = make_kernel()
        v = fs.create("/prog", 0o755)
        fs.write(v, 0, make_aout(hello_program(b"hi\n")))
        k.set_profiling(True)
        p = k.boot("/prog", [b"/prog"])
        k.run(2_000_000)
        self.assertGreater(p.utime, 0)            # 指令数
        self.assertGreaterEqual(p.wall, 0.0)      # 墙钟(常开)
        self.assertGreater(p.syscall_total, 0)    # 至少 write+exit
        self.assertGreater(p.prof.cat_counts[cpu86.CAT_MOV], 0)
        self.assertGreater(p.prof.cat_counts[cpu86.CAT_OTHER], 0)   # int 0x80
        self.assertTrue(p.prof.hot)


if __name__ == "__main__":
    unittest.main()
