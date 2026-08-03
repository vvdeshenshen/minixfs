"""less 风格的终端分页器.

按键:
    j / 回车 / ↓     下一行          k / ↑           上一行
    f / 空格 / PgDn  下一屏          b / PgUp        上一屏
    n                下一屏          p               上一屏
    d / Ctrl-D       下半屏          u / Ctrl-U      上半屏
    g                跳到开头        G               跳到结尾
    q / Q / Ctrl-C   退出
"""

from __future__ import annotations

import shutil
import sys
from typing import Callable, List, Optional


def _decode_key(getch: Callable[[], str]) -> str:
    """读一个按键, 把方向键/翻页键的转义序列翻译成等价字母键."""
    ch = getch()
    if ch == "\x1b":
        c2 = getch()
        if c2 in ("[", "O"):
            c3 = getch()
            if c3 == "A":
                return "k"      # ↑
            if c3 == "B":
                return "j"      # ↓
            if c3 == "5":
                getch()         # 吃掉 '~'
                return "b"      # PgUp
            if c3 == "6":
                getch()
                return "f"      # PgDn
        return "q"              # 其他 ESC 序列当作退出
    if ch in ("\x03", ""):      # Ctrl-C / EOF
        return "q"
    if ch == "\x04":            # Ctrl-D
        return "d"
    if ch == "\x15":            # Ctrl-U
        return "u"
    return ch


def read_key_tty() -> str:
    """在真实终端上以 cbreak 模式读一个按键."""
    import termios
    import tty

    fd = sys.stdin.fileno()
    old = termios.tcgetattr(fd)
    try:
        tty.setcbreak(fd)
        return _decode_key(lambda: sys.stdin.read(1))
    except KeyboardInterrupt:
        return "q"
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, old)


class Pager:
    """对一组文本行做 less 风格分页显示.

    read_key 为 None 时是非交互模式, 直接输出全部内容(类似
    less 的输出被重定向时); 传入 read_key 则进入交互循环.
    write/height/width/use_ansi 均可注入, 便于单元测试.
    """

    def __init__(self, lines: List[str], name: str = "",
                 height: Optional[int] = None, width: Optional[int] = None,
                 write: Optional[Callable[[str], None]] = None,
                 read_key: Optional[Callable[[], str]] = None,
                 use_ansi: bool = False):
        term = shutil.get_terminal_size((80, 24))
        self.lines = lines
        self.name = name
        self.height = height if height is not None else max(term.lines - 1, 1)
        self.width = width if width is not None else term.columns
        self.write = write if write is not None else sys.stdout.write
        self.read_key = read_key
        self.use_ansi = use_ansi

    # ---- 绘制 ---------------------------------------------------------

    def _status(self, top: int) -> str:
        total = len(self.lines)
        end = min(top + self.height, total)
        pct = end / total * 100 if total else 100
        text = f"{self.name} {top + 1}-{end}/{total} 行 ({pct:.0f}%)"
        if end >= total:
            text += " (END)"
        return text

    def _draw(self, top: int) -> None:
        if self.use_ansi:
            self.write("\x1b[2J\x1b[H")  # 清屏并回到左上角
        for line in self.lines[top:top + self.height]:
            self.write(line[:self.width] + "\n")
        status = self._status(top)
        if self.use_ansi:
            self.write(f"\x1b[7m{status}\x1b[0m")  # 反显状态栏, 不换行
            if hasattr(sys.stdout, "flush"):
                sys.stdout.flush()
        else:
            self.write(status + "\n")

    # ---- 主循环 ---------------------------------------------------------

    def run(self) -> None:
        if not self.lines:
            return
        if self.read_key is None:
            for line in self.lines:
                self.write(line + "\n")
            return
        if len(self.lines) <= self.height:
            # 一屏放得下, 无需交互(类似 less -F)
            for line in self.lines:
                self.write(line + "\n")
            return

        half = max(self.height // 2, 1)
        max_top = len(self.lines) - self.height
        top = 0
        while True:
            self._draw(top)
            try:
                key = self.read_key()
            except (EOFError, KeyboardInterrupt, StopIteration):
                key = "q"
            if key in ("q", "Q"):
                break
            elif key in ("j", "\r", "\n"):
                top = min(top + 1, max_top)
            elif key == "k":
                top = max(top - 1, 0)
            elif key in ("f", " ", "n"):
                top = min(top + self.height, max_top)
            elif key in ("b", "p"):
                top = max(top - self.height, 0)
            elif key == "d":
                top = min(top + half, max_top)
            elif key == "u":
                top = max(top - half, 0)
            elif key == "g":
                top = 0
            elif key == "G":
                top = max_top
            # 其他按键忽略
        if self.use_ansi:
            self.write("\n")  # 退出时把光标从状态栏移到新行
