"""终端与行规程.

分层沿用 pager.py 的可注入哲学:
    TTY(行规程, 纯逻辑, 可测) ←→ Terminal(可注入)
                                  ├─ HostTerminal      宿主 stdin/stdout
                                  └─ ScriptedTerminal  测试用
ioctl 请求码与 struct termios 布局取自镜像内核 include/termios.h。
"""

from __future__ import annotations

import collections
import os
import select
import struct
import sys
from typing import List, Optional, Tuple

# ioctl 请求码(镜像内核 include/termios.h)
TCGETS, TCSETS, TCSETSW, TCSETSF = 0x5401, 0x5402, 0x5403, 0x5404
TCGETA, TCSETA, TCSETAW, TCSETAF = 0x5405, 0x5406, 0x5407, 0x5408
TCSBRK, TCXONC, TCFLSH = 0x5409, 0x540A, 0x540B
TIOCEXCL, TIOCNXCL, TIOCSCTTY = 0x540C, 0x540D, 0x540E
TIOCGPGRP, TIOCSPGRP = 0x540F, 0x5410
TIOCOUTQ, TIOCSTI = 0x5411, 0x5412
TIOCGWINSZ, TIOCSWINSZ = 0x5413, 0x5414
TIOCINQ = 0x541B
FIONREAD = TIOCINQ

# c_iflag
BRKINT, ICRNL, IXON = 0o002, 0o400, 0o002000
# c_oflag
OPOST, ONLCR = 0o1, 0o4
# c_cflag
CS8, CREAD, B9600 = 0o60, 0o200, 0o15
# c_lflag
ISIG, ICANON, ECHO, ECHOE, ECHOK, ECHONL, NOFLSH = \
    0o1, 0o2, 0o10, 0o20, 0o40, 0o100, 0o200
ECHOCTL, ECHOKE = 0o1000, 0o4000

NCCS = 17
# c_cc 下标(内核 termios.h)
VINTR, VQUIT, VERASE, VKILL, VEOF, VTIME, VMIN, VSWTC = range(8)
VSTART, VSTOP, VSUSP, VEOL, VREPRINT, VDISCARD, VWERASE, VLNEXT, VEOL2 = range(8, 17)

# 信号编号(镜像 /usr/include/signal.h)
SIGHUP, SIGINT, SIGQUIT = 1, 2, 3
SIGTSTP = 20

TERMIOS_FMT = struct.Struct("<4LB17s")     # 4 个 u32 + c_line + c_cc[17] = 34 字节
TERMIO_FMT = struct.Struct("<4HB8s")       # 老 SysV: 4 个 u16 + c_line + c_cc[8]
WINSIZE_FMT = struct.Struct("<4H")


def default_cc() -> bytearray:
    """默认控制字符, 对应内核的 INIT_C_CC."""
    cc = bytearray(NCCS)
    cc[VINTR] = 3        # ^C
    cc[VQUIT] = 28       # ^\
    cc[VERASE] = 127     # DEL
    cc[VKILL] = 21       # ^U
    cc[VEOF] = 4         # ^D
    cc[VTIME] = 0
    cc[VMIN] = 1
    cc[VSTART] = 17      # ^Q
    cc[VSTOP] = 19       # ^S
    cc[VSUSP] = 26       # ^Z
    cc[VEOL] = 0
    cc[VREPRINT] = 18    # ^R
    cc[VDISCARD] = 15    # ^O
    cc[VWERASE] = 23     # ^W
    cc[VLNEXT] = 22      # ^V
    return cc


class Termios:
    def __init__(self):
        self.iflag = ICRNL | BRKINT | IXON
        self.oflag = OPOST | ONLCR
        self.cflag = CS8 | CREAD | B9600
        self.lflag = ISIG | ICANON | ECHO | ECHOE | ECHOK | ECHOCTL | ECHOKE
        self.line = 0
        self.cc = default_cc()

    def pack(self) -> bytes:
        return TERMIOS_FMT.pack(self.iflag, self.oflag, self.cflag,
                                self.lflag, self.line, bytes(self.cc))

    def unpack(self, raw: bytes) -> None:
        (self.iflag, self.oflag, self.cflag, self.lflag,
         self.line, cc) = TERMIOS_FMT.unpack(raw[:TERMIOS_FMT.size])
        self.cc = bytearray(cc)

    def pack_old(self) -> bytes:
        """老 SysV struct termio(u16 版), TCGETA 用."""
        return TERMIO_FMT.pack(self.iflag & 0xFFFF, self.oflag & 0xFFFF,
                               self.cflag & 0xFFFF, self.lflag & 0xFFFF,
                               self.line, bytes(self.cc[:8]))

    def unpack_old(self, raw: bytes) -> None:
        (i, o, cf, lf, self.line, cc) = TERMIO_FMT.unpack(raw[:TERMIO_FMT.size])
        # 升格时只覆盖低 16 位与前 8 个 c_cc, 与内核一致
        self.iflag = (self.iflag & ~0xFFFF) | i
        self.oflag = (self.oflag & ~0xFFFF) | o
        self.cflag = (self.cflag & ~0xFFFF) | cf
        self.lflag = (self.lflag & ~0xFFFF) | lf
        self.cc[:8] = cc


class ScriptedTerminal:
    """测试用: 预置输入, 捕获输出."""

    def __init__(self, inputs: Optional[List[bytes]] = None,
                 rows: int = 24, cols: int = 80, tty: bool = True):
        self.pending = list(inputs or [])
        self.out = bytearray()
        self.rows, self.cols = rows, cols
        self._tty = tty

    def poll_input(self) -> bytes:
        return self.pending.pop(0) if self.pending else b""

    def wait_input(self, timeout: float) -> bytes:
        return self.poll_input()

    def write_out(self, data: bytes) -> None:
        self.out.extend(data)

    def size(self) -> Tuple[int, int]:
        return self.rows, self.cols

    def is_tty(self) -> bool:
        return self._tty

    def restore(self) -> None:
        pass

    def suspend(self) -> None:
        pass

    def resume(self) -> None:
        pass

    @property
    def text(self) -> str:
        return self.out.decode("latin-1")

    @property
    def text_utf8(self) -> str:
        """内核自己的消息是 UTF-8(含中文), 用这个视图看."""
        return self.out.decode("utf-8", "replace")


IS_WINDOWS = os.name == "nt"

# Windows 控制台特殊键的两字节序列: getch 先给 0x00 或 0xE0, 再给扫描码。
# 翻译成 Unix 终端会发的 ANSI 序列, 这样 bash/readline 才认得。
_WIN_SCANCODE_TO_ANSI = {
    b"H": b"\x1b[A",    # ↑
    b"P": b"\x1b[B",    # ↓
    b"M": b"\x1b[C",    # →
    b"K": b"\x1b[D",    # ←
    b"G": b"\x1b[H",    # Home
    b"O": b"\x1b[F",    # End
    b"R": b"\x1b[2~",   # Insert
    b"S": b"\x1b[3~",   # Delete
    b"I": b"\x1b[5~",   # PgUp
    b"Q": b"\x1b[6~",   # PgDn
}


def translate_windows_key(ch: bytes, scancode: bytes = b"") -> bytes:
    """把 Windows 控制台的一次按键翻译成 Unix 终端等价字节.

    - 回车: Windows 给 CR(0x0D), 与 Unix 终端一致(随后由 ICRNL 转成 LF)
    - 退格: Windows 给 BS(0x08), 而 Unix 终端发 DEL(0x7F) —— 必须翻译,
      否则行规程的 VERASE(默认 127)认不出来, 退格键失效
    - 特殊键: 0x00/0xE0 前缀 + 扫描码, 翻成 ANSI 转义序列
    - 其余原样透传(含 ^C=0x03 等控制字符, 交给行规程的 ISIG 处理)
    """
    if ch in (b"\x00", b"\xe0"):
        return _WIN_SCANCODE_TO_ANSI.get(scancode, b"")
    if ch == b"\x08":
        return b"\x7f"
    return ch


def _enable_windows_ansi(stdout) -> None:
    """给 Windows 控制台打开 VT 处理, 否则 bash/less 发的转义序列会显示成乱码."""
    try:
        import ctypes

        kernel32 = ctypes.windll.kernel32
        handle = kernel32.GetStdHandle(-11)          # STD_OUTPUT_HANDLE
        mode = ctypes.c_uint32()
        if kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
            # ENABLE_VIRTUAL_TERMINAL_PROCESSING = 0x0004
            kernel32.SetConsoleMode(handle, mode.value | 0x0004)
    except Exception:
        pass


class HostTerminal:
    """宿主终端. 交互时按键逐个读入, 回显与行编辑由 TTY 行规程负责.

    输入后端按平台分派:
      - POSIX 交互/管道: stdin 设 raw + select 轮询
      - Windows 交互: msvcrt.kbhit/getch(select 在 Windows 上只能用于 socket,
        对控制台句柄会直接失败, 这正是之前 Windows 下敲键没有回显的原因)
      - Windows 管道: 后台线程读进队列(同样因为 select 用不了)
    """

    def __init__(self, stdin=None, stdout=None):
        self.stdin = stdin or sys.stdin
        self.stdout = stdout or sys.stdout
        self._raw = False
        self._saved = None
        self._eof = False
        try:
            self._fd = self.stdin.fileno()
        except (AttributeError, OSError):
            self._fd = None
        try:
            self._is_tty = bool(self._fd is not None and self.stdin.isatty())
        except (AttributeError, ValueError):
            self._is_tty = False
        self._thread_buf = bytearray()
        self._thread = None
        self._lock = None
        if IS_WINDOWS:
            if self._is_tty:
                _enable_windows_ansi(self.stdout)
            else:
                self._start_reader_thread()
        elif self._is_tty:
            self._enter_raw()

    # ---- POSIX raw 模式 -----------------------------------------------

    def _enter_raw(self) -> None:
        try:
            import termios
            import tty
            self._saved = termios.tcgetattr(self._fd)
            tty.setraw(self._fd)
            self._raw = True
        except Exception:
            self._raw = False

    def restore(self) -> None:
        if self._raw and self._saved is not None:
            import termios
            termios.tcsetattr(self._fd, termios.TCSADRAIN, self._saved)
            self._raw = False

    def suspend(self) -> None:
        """暂时恢复宿主终端的常规模式(monitor 要用 input() 读整行)."""
        self._was_raw = self._raw
        self.restore()

    def resume(self) -> None:
        """回到 raw 模式继续仿真."""
        if getattr(self, "_was_raw", False) and self._is_tty and not IS_WINDOWS:
            self._enter_raw()

    # ---- Windows 管道: 后台读取线程 -------------------------------------

    def _start_reader_thread(self) -> None:
        import threading

        self._lock = threading.Lock()
        stream = getattr(self.stdin, "buffer", self.stdin)

        def reader():
            while True:
                try:
                    chunk = stream.read(1)
                except Exception:
                    chunk = b""
                if not chunk:
                    with self._lock:
                        self._eof = True
                    return
                if isinstance(chunk, str):
                    chunk = chunk.encode("latin-1")
                with self._lock:
                    self._thread_buf.extend(chunk)

        self._thread = threading.Thread(target=reader, daemon=True)
        self._thread.start()

    def _drain_thread_buf(self) -> bytes:
        with self._lock:
            data = bytes(self._thread_buf)
            self._thread_buf.clear()
        return data

    # ---- 统一读接口 ---------------------------------------------------

    def poll_input(self) -> bytes:
        return self._read(0)

    def wait_input(self, timeout: float) -> bytes:
        return self._read(timeout)

    def _read(self, timeout: float) -> bytes:
        if IS_WINDOWS:
            return (self._read_windows_console(timeout) if self._is_tty
                    else self._read_thread(timeout))
        return self._read_posix(timeout)

    def _read_posix(self, timeout: float) -> bytes:
        if self._fd is None or self._eof:
            return b""
        try:
            r, _, _ = select.select([self._fd], [], [], timeout)
        except (OSError, ValueError):
            return b""
        if not r:
            return b""
        try:
            data = os.read(self._fd, 4096)
        except OSError:
            return b""
        if not data:
            self._eof = True
        return data

    def _read_windows_console(self, timeout: float) -> bytes:
        """用 msvcrt 逐键读控制台. getch 不回显, 正好交给行规程做回显."""
        import msvcrt
        import time as _time

        deadline = _time.monotonic() + max(timeout, 0.0)
        out = bytearray()
        while True:
            while msvcrt.kbhit():
                ch = msvcrt.getch()
                scancode = msvcrt.getch() if ch in (b"\x00", b"\xe0") else b""
                out += translate_windows_key(ch, scancode)
            if out or timeout <= 0:
                return bytes(out)
            if _time.monotonic() >= deadline:
                return b""
            _time.sleep(0.005)

    def _read_thread(self, timeout: float) -> bytes:
        import time as _time

        deadline = _time.monotonic() + max(timeout, 0.0)
        while True:
            data = self._drain_thread_buf()
            if data or timeout <= 0:
                return data
            if self._eof or _time.monotonic() >= deadline:
                return b""
            _time.sleep(0.005)

    @property
    def at_eof(self) -> bool:
        """交互控制台永不 EOF(真机上控制台也不会), 只有管道/文件才会读完."""
        if self._is_tty:
            return False
        if self._lock is not None:
            with self._lock:
                return self._eof and not self._thread_buf
        return self._eof

    def write_out(self, data: bytes) -> None:
        buf = getattr(self.stdout, "buffer", None)
        if buf is not None:
            buf.write(data)
            buf.flush()
        else:
            self.stdout.write(data.decode("latin-1"))
            self.stdout.flush()

    def size(self) -> Tuple[int, int]:
        import shutil
        sz = shutil.get_terminal_size((80, 24))
        return sz.lines, sz.columns

    def is_tty(self) -> bool:
        return self._is_tty


class TTY:
    """终端行规程: 回显、行编辑、信号字符."""

    def __init__(self, term, post_signal=None, escape: int = 0x01,
                 on_escape=None):
        self.term = term
        self.post_signal = post_signal or (lambda pgrp, sig: None)
        self.termios = Termios()
        self.pgrp = 0
        self.session = 0
        self.line = bytearray()          # 正在编辑的行
        self.ready = bytearray()         # 已提交、待 read 的数据
        self.eof_pending = False
        # 转义键(默认 Ctrl-A, 仿 qemu): 在行规程之前拦截, 所以不受被仿真程序
        # 的 termios 设置影响 —— raw 模式下的 bash 也照样能用 Ctrl-A x 退出。
        self.escape = escape
        self.on_escape = on_escape
        self._escape_armed = False
        # 控制台输出留存(供 monitor 的 info console 回看最近输出), 环形字节缓冲
        self.console_tail = collections.deque(maxlen=8192)
        if not term.is_tty():
            # 非交互: 关回显, 免得污染输出
            self.termios.lflag &= ~(ECHO | ECHOE | ECHOK | ECHOCTL)

    # ---- 输入侧 -------------------------------------------------------

    def pump(self, timeout: float = 0.0) -> None:
        """把宿主输入喂进行规程.

        timeout > 0 时阻塞等待(调度器发现全员睡眠时用), 否则非阻塞轮询。
        注意必须把读到的字节交给 feed —— 早期版本在空闲分支里直接调
        term.wait_input() 会把输入读走丢弃, 交互模式下敲键毫无反应。
        """
        data = self.term.wait_input(timeout) if timeout > 0 \
            else self.term.poll_input()
        if data:
            self.feed(data)
        elif getattr(self.term, "at_eof", False) and not self.ready:
            self.eof_pending = True

    def feed(self, data: bytes) -> None:
        if self.on_escape is not None:
            data = self._strip_escapes(data)
            if not data:
                return
        self._feed_cooked(data)

    def _strip_escapes(self, data: bytes) -> bytes:
        """抽掉转义键序列, 剩下的才交给行规程.

        Ctrl-A 之后的一个字符是命令; Ctrl-A Ctrl-A(或 Ctrl-A a)表示要发一个
        真正的 Ctrl-A 给被仿真程序。
        """
        out = bytearray()
        for byte in data:
            if self._escape_armed:
                self._escape_armed = False
                if byte in (self.escape, ord("a"), ord("A")):
                    out.append(self.escape)      # 透传一个真正的转义键
                else:
                    self.on_escape(bytes((byte,)))
                continue
            if byte == self.escape:
                self._escape_armed = True
                continue
            out.append(byte)
        return bytes(out)

    def _feed_cooked(self, data: bytes) -> None:
        t = self.termios
        canon = bool(t.lflag & ICANON)
        for byte in data:
            ch = bytes((byte,))
            if t.iflag & ICRNL and byte == 13:
                byte, ch = 10, b"\n"
            if t.lflag & ISIG:
                if byte == t.cc[VINTR]:
                    self._echo_ctl(byte)
                    self._flush_input()
                    self.post_signal(self.pgrp, SIGINT)
                    continue
                if byte == t.cc[VQUIT]:
                    self._echo_ctl(byte)
                    self._flush_input()
                    self.post_signal(self.pgrp, SIGQUIT)
                    continue
                if byte == t.cc[VSUSP]:
                    self._echo_ctl(byte)
                    self.post_signal(self.pgrp, SIGTSTP)
                    continue
            if not canon:
                self.ready.append(byte)
                self._echo(ch)
                continue
            if byte == t.cc[VERASE]:
                if self.line:
                    self.line.pop()
                    if t.lflag & ECHOE:
                        self.write(b"\b \b")
                continue
            if byte == t.cc[VKILL]:
                if t.lflag & ECHOE:
                    self.write(b"\b \b" * len(self.line))
                self.line.clear()
                continue
            if byte == t.cc[VEOF]:
                if self.line:
                    self.ready.extend(self.line)
                    self.line.clear()
                else:
                    self.eof_pending = True
                continue
            self._echo(ch)
            self.line.append(byte)
            if byte == 10 or (t.cc[VEOL] and byte == t.cc[VEOL]):
                self.ready.extend(self.line)
                self.line.clear()

    def _echo(self, ch: bytes) -> None:
        t = self.termios
        if not (t.lflag & ECHO):
            return
        if ch == b"\n":
            self.write(b"\n")
        elif len(ch) == 1 and ch[0] < 32 and t.lflag & ECHOCTL:
            self.write(b"^" + bytes((ch[0] + 64,)))
        else:
            self.write(ch)

    def _echo_ctl(self, byte: int) -> None:
        if self.termios.lflag & (ECHO | ECHOCTL) == (ECHO | ECHOCTL):
            self.write(b"^" + bytes((byte + 64,)))

    def _flush_input(self) -> None:
        if not (self.termios.lflag & NOFLSH):
            self.line.clear()
            self.ready.clear()

    def read(self, n: int) -> Optional[bytes]:
        """无数据时返回 None(调用方应阻塞); EOF 返回 b""."""
        self.pump()
        if self.ready:
            out = bytes(self.ready[:n])
            del self.ready[:n]
            return out
        if self.eof_pending:
            self.eof_pending = False
            return b""
        return None

    # ---- 输出侧 -------------------------------------------------------

    def write(self, data: bytes) -> int:
        """写终端. 返回的是**程序请求的字节数**, 不是 ONLCR 展开后的字节数."""
        t = self.termios
        out = data
        if t.oflag & OPOST and t.oflag & ONLCR and self.term.is_tty():
            out = data.replace(b"\n", b"\r\n")
        self.term.write_out(out)
        self.console_tail.extend(data)          # 留存逻辑输出(ONLCR 展开前)
        return len(data)

    # ---- ioctl --------------------------------------------------------

    def ioctl(self, proc, cmd: int, argp: int) -> int:
        mem = proc.mem
        if cmd == TCGETS:
            mem.write(argp, self.termios.pack())
            return 0
        if cmd in (TCSETS, TCSETSW, TCSETSF):
            self.termios.unpack(mem.read(argp, TERMIOS_FMT.size))
            if cmd == TCSETSF:
                self._flush_input()
            return 0
        if cmd == TCGETA:
            mem.write(argp, self.termios.pack_old())
            return 0
        if cmd in (TCSETA, TCSETAW, TCSETAF):
            self.termios.unpack_old(mem.read(argp, TERMIO_FMT.size))
            if cmd == TCSETAF:
                self._flush_input()
            return 0
        if cmd == TIOCGWINSZ:
            rows, cols = self.term.size()
            mem.write(argp, WINSIZE_FMT.pack(rows, cols, 0, 0))
            return 0
        if cmd == TIOCSWINSZ:
            return 0
        if cmd == TIOCGPGRP:
            mem.write_u32(argp, self.pgrp)
            return 0
        if cmd == TIOCSPGRP:
            self.pgrp = mem.read_u32(argp)
            return 0
        if cmd == TIOCSCTTY:
            self.session = proc.session
            self.pgrp = proc.pgrp
            return 0
        if cmd in (TIOCINQ, FIONREAD):
            self.pump()
            mem.write_u32(argp, len(self.ready))
            return 0
        if cmd in (TCFLSH, TCSBRK, TCXONC):
            if cmd == TCFLSH:
                self._flush_input()
            return 0
        return -22        # EINVAL
