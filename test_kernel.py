"""kexec 加载器与系统调用层测试.

系统调用测试用 FakeCPU(一个只有 regs 与 mem 的壳), 不需要任何 x86 解码;
端到端合同测试则在迷你镜像里塞一个手写的 a.out, 真正走完
CPU -> int 0x80 -> 内核 -> 终端 这条链, 且不依赖真实镜像。
"""

import io
import struct
import unittest

import kernel as kmod
import kexec
import ksyscall
import ktty
import kvfs
from kernel import Kernel, NR_OPEN, Exited, OpenFile, Process
from kexec import AoutHeader, ExecError, load_aout, parse_shebang, setup_stack
from ksyscall import STAT_FMT, pack_stat
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
    """系统调用测试用的 CPU 壳: 只有寄存器与内存."""

    def __init__(self, mem):
        self.mem = mem
        self.regs = [0] * 8
        self.eip = 0
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


if __name__ == "__main__":
    unittest.main()
