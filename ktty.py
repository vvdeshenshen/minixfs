"""终端与行规程.

分层沿用 pager.py 的可注入哲学:
    TTY(行规程, 纯逻辑, 可测) ←→ Terminal(可注入)
                                  ├─ HostTerminal      宿主 stdin/stdout
                                  └─ ScriptedTerminal  测试用
ioctl 请求码与 struct termios 布局取自镜像内核 include/termios.h。
"""

from __future__ import annotations

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

    @property
    def text(self) -> str:
        return self.out.decode("latin-1")


class HostTerminal:
    """宿主终端. 交互时把 stdin 设为 raw, 回显与行编辑由 TTY 行规程负责."""

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
        self._is_tty = bool(self._fd is not None and self.stdin.isatty())
        if self._is_tty:
            self._enter_raw()

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

    def poll_input(self) -> bytes:
        return self._read(0)

    def wait_input(self, timeout: float) -> bytes:
        return self._read(timeout)

    def _read(self, timeout: float) -> bytes:
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

    @property
    def at_eof(self) -> bool:
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

    def __init__(self, term, post_signal=None):
        self.term = term
        self.post_signal = post_signal or (lambda pgrp, sig: None)
        self.termios = Termios()
        self.pgrp = 0
        self.session = 0
        self.line = bytearray()          # 正在编辑的行
        self.ready = bytearray()         # 已提交、待 read 的数据
        self.eof_pending = False
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
