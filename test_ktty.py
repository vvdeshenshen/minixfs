"""ktty 行规程与终端测试.

沿用 pager.py 的注入哲学: 终端可注入, 用脚本化输入驱动、捕获输出,
不需要真实 tty。
"""

import struct
import unittest

import ktty
from ktty import (ECHO, ECHOCTL, ECHOE, ICANON, ICRNL, ISIG, ONLCR, OPOST,
                  ScriptedTerminal, Termios, TTY, VEOF, VERASE, VINTR, VKILL,
                  VQUIT, VSUSP)


class FakeProc:
    """ioctl 测试用的进程壳."""

    def __init__(self, mem):
        self.mem = mem
        self.pgrp = 7
        self.session = 7


class FakeMem:
    def __init__(self):
        self.buf = bytearray(4096)

    def read(self, addr, n):
        return bytes(self.buf[addr:addr + n])

    def write(self, addr, data):
        self.buf[addr:addr + len(data)] = data

    def read_u32(self, addr):
        return struct.unpack_from("<I", self.buf, addr)[0]

    def write_u32(self, addr, val):
        struct.pack_into("<I", self.buf, addr, val & 0xFFFFFFFF)


def make_tty(inputs=None, tty=True, signals=None):
    term = ScriptedTerminal(inputs=inputs or [], tty=tty)
    got = signals if signals is not None else []
    t = TTY(term, post_signal=lambda pgrp, sig: got.append((pgrp, sig)))
    t.pgrp = 7
    return t, term, got


class TestLineDiscipline(unittest.TestCase):
    def test_simple_line(self):
        t, term, _ = make_tty([b"hello\n"])
        self.assertEqual(t.read(100), b"hello\n")

    def test_line_not_delivered_until_newline(self):
        t, term, _ = make_tty([b"partial"])
        self.assertIsNone(t.read(100))          # None = 调用方该阻塞
        t.feed(b"\n")
        self.assertEqual(t.read(100), b"partial\n")

    def test_backspace_erases_and_echoes(self):
        t, term, _ = make_tty([b"ab\x7fc\n"])
        self.assertEqual(t.read(100), b"ac\n")
        self.assertIn("\b \b", term.text)       # ECHOE 的擦除序列

    def test_backspace_at_line_start_is_noop(self):
        t, term, _ = make_tty([b"\x7f\x7fx\n"])
        self.assertEqual(t.read(100), b"x\n")

    def test_kill_line(self):
        t, term, _ = make_tty([b"junk\x15good\n"])
        self.assertEqual(t.read(100), b"good\n")

    def test_eof_at_line_start_returns_empty(self):
        t, term, _ = make_tty([b"\x04"])
        self.assertEqual(t.read(100), b"")      # b"" = EOF

    def test_eof_mid_line_submits_partial(self):
        t, term, _ = make_tty([b"abc\x04"])
        self.assertEqual(t.read(100), b"abc")   # 无换行也提交

    def test_icrnl_maps_cr_to_lf(self):
        t, term, _ = make_tty([b"line\r"])
        self.assertEqual(t.read(100), b"line\n")

    def test_echo_can_be_disabled(self):
        t, term, _ = make_tty([b"secret\n"])
        t.termios.lflag &= ~ECHO
        t.read(100)
        self.assertNotIn("secret", term.text)   # login 的密码输入靠这个

    def test_control_char_echoed_as_caret(self):
        t, term, _ = make_tty([b"\x01x\n"])     # ^A
        t.read(100)
        self.assertIn("^A", term.text)

    def test_partial_read_leaves_rest(self):
        t, term, _ = make_tty([b"abcdef\n"])
        self.assertEqual(t.read(3), b"abc")
        self.assertEqual(t.read(10), b"def\n")

    def test_raw_mode_delivers_bytes_immediately(self):
        t, term, _ = make_tty([b"xy"])
        t.termios.lflag &= ~ICANON
        self.assertEqual(t.read(10), b"xy")     # 无需换行

    def test_multiple_lines_queued(self):
        t, term, _ = make_tty([b"one\ntwo\n"])
        self.assertEqual(t.read(100), b"one\ntwo\n")


class TestSignalChars(unittest.TestCase):
    def test_ctrl_c_sends_sigint_to_foreground_group(self):
        t, term, got = make_tty([b"\x03"])
        t.read(10)
        self.assertEqual(got, [(7, ktty.SIGINT)])

    def test_ctrl_backslash_sends_sigquit(self):
        t, term, got = make_tty([b"\x1c"])
        t.read(10)
        self.assertEqual(got, [(7, ktty.SIGQUIT)])

    def test_ctrl_z_sends_sigtstp(self):
        t, term, got = make_tty([b"\x1a"])
        t.read(10)
        self.assertEqual(got, [(7, ktty.SIGTSTP)])

    def test_ctrl_c_flushes_pending_input(self):
        t, term, got = make_tty([b"typed\x03"])
        self.assertIsNone(t.read(10))           # 输入被清掉了
        self.assertEqual(got, [(7, ktty.SIGINT)])

    def test_isig_off_treats_ctrl_c_as_data(self):
        t, term, got = make_tty([b"\x03\n"])
        t.termios.lflag &= ~ISIG
        self.assertEqual(t.read(10), b"\x03\n")
        self.assertEqual(got, [])


class TestOutput(unittest.TestCase):
    def test_onlcr_expands_newline_on_tty(self):
        t, term, _ = make_tty()
        t.write(b"a\nb\n")
        self.assertEqual(term.text, "a\r\nb\r\n")

    def test_write_returns_requested_count_not_expanded(self):
        """真实 write 返回消耗的输入字节数, 不是 ONLCR 展开后的长度."""
        t, term, _ = make_tty()
        self.assertEqual(t.write(b"a\n"), 2)
        self.assertEqual(len(term.out), 3)      # 终端上是 3 字节

    def test_no_onlcr_when_not_tty(self):
        t, term, _ = make_tty(tty=False)
        t.write(b"a\nb\n")
        self.assertEqual(term.text, "a\nb\n")

    def test_opost_off_passes_through(self):
        t, term, _ = make_tty()
        t.termios.oflag &= ~OPOST
        t.write(b"a\n")
        self.assertEqual(term.text, "a\n")


class TestNonInteractive(unittest.TestCase):
    def test_echo_disabled_when_not_a_tty(self):
        """管道输入时关回显, 免得污染输出."""
        t, term, _ = make_tty([b"cmd\n"], tty=False)
        self.assertFalse(t.termios.lflag & ECHO)
        t.read(100)
        self.assertEqual(term.text, "")


class TestTermiosStruct(unittest.TestCase):
    def test_pack_unpack_roundtrip(self):
        a = Termios()
        a.lflag = 0x1234
        a.cc[VINTR] = 5
        b = Termios()
        b.unpack(a.pack())
        self.assertEqual(b.lflag, 0x1234)
        self.assertEqual(b.cc[VINTR], 5)

    def test_struct_size_is_34_bytes(self):
        """4 个 u32 flags + c_line(u8) + c_cc[17]."""
        self.assertEqual(len(Termios().pack()), 34)
        self.assertEqual(ktty.TERMIOS_FMT.size, 34)

    def test_old_termio_is_17_bytes(self):
        self.assertEqual(len(Termios().pack_old()), 17)

    def test_old_termio_upgrade_keeps_high_bits(self):
        """TCSETA 升格时只覆盖低 16 位, 与内核一致."""
        t = Termios()
        t.lflag = 0xABCD0001
        raw = bytearray(t.pack_old())
        struct.pack_into("<H", raw, 6, 0x0002)      # 改 c_lflag 低 16 位
        t.unpack_old(bytes(raw))
        self.assertEqual(t.lflag, 0xABCD0002)

    def test_default_control_chars(self):
        cc = Termios().cc
        self.assertEqual(cc[VINTR], 3)      # ^C
        self.assertEqual(cc[VQUIT], 28)     # ^\
        self.assertEqual(cc[VERASE], 127)   # DEL
        self.assertEqual(cc[VKILL], 21)     # ^U
        self.assertEqual(cc[VEOF], 4)       # ^D
        self.assertEqual(cc[VSUSP], 26)     # ^Z

    def test_default_flags(self):
        t = Termios()
        self.assertTrue(t.lflag & ICANON)
        self.assertTrue(t.lflag & ECHO)
        self.assertTrue(t.lflag & ISIG)
        self.assertTrue(t.iflag & ICRNL)
        self.assertTrue(t.oflag & OPOST)
        self.assertTrue(t.oflag & ONLCR)


class TestIoctl(unittest.TestCase):
    def setUp(self):
        self.t, self.term, self.got = make_tty()
        self.p = FakeProc(FakeMem())

    def test_tcgets_then_tcsets(self):
        self.assertEqual(self.t.ioctl(self.p, ktty.TCGETS, 0x100), 0)
        raw = bytearray(self.p.mem.read(0x100, 34))
        struct.pack_into("<L", raw, 12, 0)          # 清掉 c_lflag(关 ICANON/ECHO)
        self.p.mem.write(0x200, bytes(raw))
        self.assertEqual(self.t.ioctl(self.p, ktty.TCSETS, 0x200), 0)
        self.assertEqual(self.t.termios.lflag, 0)

    def test_tcgeta_old_struct(self):
        self.assertEqual(self.t.ioctl(self.p, ktty.TCGETA, 0x100), 0)
        i, o, c, l, line, cc = ktty.TERMIO_FMT.unpack(self.p.mem.read(0x100, 17))
        self.assertEqual(l & 0xFFFF, self.t.termios.lflag & 0xFFFF)

    def test_winsize(self):
        self.assertEqual(self.t.ioctl(self.p, ktty.TIOCGWINSZ, 0x100), 0)
        rows, cols, _, _ = ktty.WINSIZE_FMT.unpack(self.p.mem.read(0x100, 8))
        self.assertEqual((rows, cols), (24, 80))

    def test_pgrp_get_set(self):
        self.assertEqual(self.t.ioctl(self.p, ktty.TIOCGPGRP, 0x100), 0)
        self.assertEqual(self.p.mem.read_u32(0x100), 7)
        self.p.mem.write_u32(0x100, 42)
        self.assertEqual(self.t.ioctl(self.p, ktty.TIOCSPGRP, 0x100), 0)
        self.assertEqual(self.t.pgrp, 42)

    def test_tiocsctty_takes_controlling_terminal(self):
        self.p.session = 99
        self.p.pgrp = 99
        self.assertEqual(self.t.ioctl(self.p, ktty.TIOCSCTTY, 0), 0)
        self.assertEqual(self.t.session, 99)

    def test_tiocinq_reports_pending_bytes(self):
        self.t.feed(b"abc\n")
        self.assertEqual(self.t.ioctl(self.p, ktty.TIOCINQ, 0x100), 0)
        self.assertEqual(self.p.mem.read_u32(0x100), 4)

    def test_tcflsh_discards_input(self):
        self.t.feed(b"abc\n")
        self.assertEqual(self.t.ioctl(self.p, ktty.TCFLSH, 0), 0)
        self.assertIsNone(self.t.read(10))

    def test_unknown_request_is_einval(self):
        self.assertEqual(self.t.ioctl(self.p, 0x9999, 0), -22)


class TestPump(unittest.TestCase):
    def test_pump_feeds_input(self):
        t, term, _ = make_tty([b"x\n"])
        t.pump()
        self.assertEqual(bytes(t.ready), b"x\n")

    def test_pump_with_timeout_still_feeds(self):
        """带超时的 pump 必须把读到的字节喂给行规程 —— 早期版本直接调
        term.wait_input() 丢弃了输入, 导致交互模式敲键毫无反应."""
        t, term, _ = make_tty([b"y\n"])
        t.pump(0.01)
        self.assertEqual(bytes(t.ready), b"y\n")


class TestWindowsKeyTranslation(unittest.TestCase):
    """Windows 控制台按键翻译 —— 纯函数, 在任何平台上都能测."""

    def test_backspace_becomes_del(self):
        """Windows 给 BS(0x08), Unix 终端发 DEL(0x7F)。不翻译的话行规程的
        VERASE(默认 127)认不出来, 退格键就失效。"""
        self.assertEqual(ktty.translate_windows_key(b"\x08"), b"\x7f")

    def test_backspace_actually_erases_after_translation(self):
        """端到端: 翻译后的字节喂进行规程, 退格必须真的删掉字符."""
        t, term, _ = make_tty()
        t.feed(b"ab")
        t.feed(ktty.translate_windows_key(b"\x08"))
        t.feed(b"c\n")
        self.assertEqual(t.read(100), b"ac\n")

    def test_carriage_return_passes_through(self):
        """Windows 回车给 CR, 与 Unix 终端一致, 随后由 ICRNL 转 LF."""
        self.assertEqual(ktty.translate_windows_key(b"\r"), b"\r")
        t, term, _ = make_tty()
        t.feed(ktty.translate_windows_key(b"\r"))
        self.assertEqual(t.read(10), b"\n")

    def test_ordinary_chars_pass_through(self):
        for ch in (b"a", b"Z", b"0", b" ", b"~"):
            self.assertEqual(ktty.translate_windows_key(ch), ch)

    def test_control_chars_pass_through_for_isig(self):
        """^C/^D/^U 要原样透传, 交给行规程的 ISIG 与行编辑处理."""
        for ch in (b"\x03", b"\x04", b"\x15", b"\x1a"):
            self.assertEqual(ktty.translate_windows_key(ch), ch)

    def test_ctrl_c_still_raises_sigint_on_windows_path(self):
        t, term, got = make_tty()
        t.feed(ktty.translate_windows_key(b"\x03"))
        t.read(10)
        self.assertEqual(got, [(7, ktty.SIGINT)])

    def test_arrow_keys_become_ansi_sequences(self):
        """特殊键是 0x00/0xE0 前缀 + 扫描码, 要翻成 ANSI 序列 bash 才认得."""
        cases = {b"H": b"\x1b[A", b"P": b"\x1b[B",
                 b"M": b"\x1b[C", b"K": b"\x1b[D"}
        for scan, want in cases.items():
            self.assertEqual(ktty.translate_windows_key(b"\xe0", scan), want)
            self.assertEqual(ktty.translate_windows_key(b"\x00", scan), want)

    def test_home_end_delete_pgup_pgdn(self):
        self.assertEqual(ktty.translate_windows_key(b"\xe0", b"G"), b"\x1b[H")
        self.assertEqual(ktty.translate_windows_key(b"\xe0", b"O"), b"\x1b[F")
        self.assertEqual(ktty.translate_windows_key(b"\xe0", b"S"), b"\x1b[3~")
        self.assertEqual(ktty.translate_windows_key(b"\xe0", b"I"), b"\x1b[5~")
        self.assertEqual(ktty.translate_windows_key(b"\xe0", b"Q"), b"\x1b[6~")

    def test_unknown_scancode_is_dropped(self):
        """未识别的功能键(F1 等)丢掉, 不能把扫描码当数据塞给 shell."""
        self.assertEqual(ktty.translate_windows_key(b"\x00", b"\x3b"), b"")
        self.assertEqual(ktty.translate_windows_key(b"\xe0", b"?"), b"")


class TestHostTerminalPlatformDispatch(unittest.TestCase):
    """HostTerminal 的平台分派与 EOF 语义(不真的碰宿主 tty)."""

    class FakeStdin:
        """假 stdin: 可控制 isatty 与 fileno."""

        def __init__(self, tty=False, data=b""):
            self._tty = tty
            import io
            self.buffer = io.BytesIO(data)

        def isatty(self):
            return self._tty

        def fileno(self):
            raise OSError("没有真实 fd")

    class FakeStdout:
        def __init__(self):
            import io
            self.buffer = io.BytesIO()

    def test_non_tty_stdin_reports_not_a_tty(self):
        h = ktty.HostTerminal(self.FakeStdin(tty=False), self.FakeStdout())
        self.assertFalse(h.is_tty())

    def test_interactive_console_never_reports_eof(self):
        """真机控制台不会 EOF —— init 的 respawn 循环依赖这个判断."""
        h = ktty.HostTerminal(self.FakeStdin(tty=True), self.FakeStdout())
        h._is_tty = True
        h._eof = True
        self.assertFalse(h.at_eof)

    def test_write_out_uses_binary_buffer(self):
        """必须写 buffer(二进制), 否则 Windows 的文本层会把 \\n 再变成 \\r\\n,
        与我们 ONLCR 已经加的 CR 撞成双份."""
        out = self.FakeStdout()
        h = ktty.HostTerminal(self.FakeStdin(), out)
        h.write_out(b"a\r\n")
        self.assertEqual(out.buffer.getvalue(), b"a\r\n")

    def test_thread_reader_drains_piped_bytes(self):
        """Windows 管道走后台线程(select 在 Windows 上用不了)."""
        import time
        h = ktty.HostTerminal.__new__(ktty.HostTerminal)
        h.stdin = self.FakeStdin(data=b"hello\n")
        h.stdout = self.FakeStdout()
        h._eof = False
        h._is_tty = False
        h._thread_buf = bytearray()
        h._thread = None
        h._lock = None
        h._start_reader_thread()
        got = b""
        for _ in range(200):
            got += h._read_thread(0.05)
            if got.endswith(b"\n"):
                break
            time.sleep(0.005)
        self.assertEqual(got, b"hello\n")

    def test_thread_reader_reports_eof_after_drain(self):
        import time
        h = ktty.HostTerminal.__new__(ktty.HostTerminal)
        h.stdin = self.FakeStdin(data=b"x")
        h.stdout = self.FakeStdout()
        h._eof = False
        h._is_tty = False
        h._thread_buf = bytearray()
        h._thread = None
        h._lock = None
        h._start_reader_thread()
        for _ in range(200):
            if h._read_thread(0.05) == b"x":
                break
            time.sleep(0.005)
        for _ in range(100):
            if h.at_eof:
                break
            time.sleep(0.01)
        self.assertTrue(h.at_eof)      # 读完且流已关 -> EOF


if __name__ == "__main__":
    unittest.main()
