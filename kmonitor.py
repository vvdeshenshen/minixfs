"""仿真器 monitor —— 类似 qemu 的 monitor 控制台.

进入方式(默认转义键 Ctrl-A, 仿 qemu 的 Ctrl-A 前缀):
    Ctrl-A c    进入 monitor
    Ctrl-A x    直接退出仿真器
    Ctrl-A a    向被仿真程序发一个真正的 Ctrl-A
    Ctrl-A ?    显示按键帮助

monitor 里的命令(输入 help 查看):
    info procs / mem / fs / syscalls / cpu / fds / tty
    ps  regs  kill  trace  cont  quit

读写全部可注入(read_line/write), 所以能用脚本化输入做单元测试, 不必真的
占用宿主终端 —— 与 pager.py 的注入哲学一致。
"""

from __future__ import annotations

import unicodedata
from typing import Callable, List, Optional

import kernel as kmod
import kvfs

STATE_NAMES = {0: "运行", 1: "睡眠", 2: "僵尸", 3: "停止"}

# errno 名字(取自镜像 /usr/include/errno.h), 用于把 -2 这类返回值标成 -2(ENOENT)
ERRNO_NAMES = {
    1: "EPERM", 2: "ENOENT", 3: "ESRCH", 4: "EINTR", 5: "EIO", 6: "ENXIO",
    7: "E2BIG", 8: "ENOEXEC", 9: "EBADF", 10: "ECHILD", 11: "EAGAIN",
    12: "ENOMEM", 13: "EACCES", 14: "EFAULT", 16: "EBUSY", 17: "EEXIST",
    18: "EXDEV", 19: "ENODEV", 20: "ENOTDIR", 21: "EISDIR", 22: "EINVAL",
    23: "ENFILE", 24: "EMFILE", 25: "ENOTTY", 26: "ETXTBSY", 27: "EFBIG",
    28: "ENOSPC", 29: "ESPIPE", 30: "EROFS", 31: "EMLINK", 32: "EPIPE",
    34: "ERANGE", 38: "ENOSYS", 39: "ENOTEMPTY",
}

ESCAPE_HELP = """\
Ctrl-A c   进入 monitor 控制台
Ctrl-A x   退出仿真器
Ctrl-A a   发送一个真正的 Ctrl-A 给被仿真程序
Ctrl-A ?   显示这份帮助
"""

MONITOR_HELP = """\
info procs        进程表(pid/父/状态/程序/已执行指令/等待对象)
info mem          各进程地址空间与堆栈用量
info fs           覆盖层与底层镜像的文件系统统计
info syscalls     系统调用次数统计与最近调用
info trace [n]    翻看轨迹缓冲里最近 n 条调用(默认 30)
info cpu [pid]    寄存器与标志位
info fds [pid]    文件描述符表
info tty          终端与行规程状态
ps                = info procs
regs [pid]        = info cpu
kill <pid> [信号] 给被仿真进程发信号(默认 15/SIGTERM)
trace show [n]    同 info trace
trace on [容量]   放大轨迹缓冲以留更长历史(默认 5000 条)
trace off         缩回默认容量(轨迹始终在记, 只是历史更短)
cont              退出 monitor, 继续仿真
quit              停止仿真并退出
help              这份帮助
"""


def fmt_bytes(n: int) -> str:
    """字节数转成人类可读(KB/MB)."""
    if n < 1024:
        return f"{n}B"
    if n < 1024 * 1024:
        return f"{n / 1024:.1f}KB"
    return f"{n / (1024 * 1024):.1f}MB"


def dwidth(s: str) -> int:
    """字符串在终端里占的**显示列数**.

    中文等东亚宽字符一个字符占两列, 而 Python 的 f"{s:<5}" 是按字符数补齐的
    —— 表头写"状态"(2 字符 / 4 列)时就会少补 2 列, 整张表跟着错位。
    """
    return sum(2 if unicodedata.east_asian_width(c) in "WF" else 1 for c in s)


def ljust(s: str, n: int) -> str:
    """按显示列数左对齐."""
    return s + " " * max(n - dwidth(s), 0)


def rjust(s: str, n: int) -> str:
    """按显示列数右对齐."""
    return " " * max(n - dwidth(s), 0) + s


def table(headers, rows, aligns=None) -> List[str]:
    """按显示列宽排版一张表, 列宽取表头与各行的最大值.

    aligns: 每列 "l"/"r", 默认全部左对齐。
    """
    cols = len(headers)
    aligns = aligns or ["l"] * cols
    cells = [[str(c) for c in row] for row in rows]
    widths = [max([dwidth(headers[i])] +
                  [dwidth(r[i]) for r in cells]) for i in range(cols)]
    out = []
    for row in [list(headers)] + cells:
        parts = [(rjust if aligns[i] == "r" else ljust)(row[i], widths[i])
                 for i in range(cols)]
        out.append("  ".join(parts).rstrip())
    return out


class Monitor:
    """monitor 控制台."""

    def __init__(self, kernel, read_line: Optional[Callable[[str], str]] = None,
                 write: Optional[Callable[[str], None]] = None):
        self.k = kernel
        self._read_line = read_line
        self._write = write
        self.entered = 0

    # ---- 输入输出(可注入) ----------------------------------------------

    def out(self, text: str = "") -> None:
        if self._write is not None:
            self._write(text + "\n")
        else:
            print(text)

    def read_line(self, prompt: str = "(minix) ") -> str:
        if self._read_line is not None:
            return self._read_line(prompt)
        try:
            return input(prompt)
        except (EOFError, KeyboardInterrupt):
            return "cont"

    # ---- 主循环 -------------------------------------------------------

    def interact(self) -> None:
        """进入 monitor, 直到用户 cont 或 quit."""
        self.entered += 1
        term = getattr(self.k.terminal, "term", None)
        if term is not None and hasattr(term, "suspend"):
            term.suspend()                 # 暂时恢复宿主终端的常规模式
        try:
            self.out()
            self.out("已进入 monitor(输入 help 看命令, cont 继续仿真, quit 退出)")
            while True:
                try:
                    line = self.read_line()
                except Exception:
                    return
                if line is None:
                    return
                if self.dispatch(line.strip()):
                    return
        finally:
            if term is not None and hasattr(term, "resume"):
                term.resume()

    def dispatch(self, line: str) -> bool:
        """执行一条命令; 返回 True 表示该离开 monitor."""
        if not line:
            return False
        parts = line.split()
        cmd, args = parts[0].lower(), parts[1:]
        if cmd in ("cont", "c", "continue"):
            self.out("继续仿真。")
            return True
        if cmd in ("quit", "q", "exit"):
            self.k.quit_requested = True
            self.out("停止仿真。")
            return True
        if cmd in ("help", "h", "?"):
            self.out(MONITOR_HELP.rstrip())
            return False
        if cmd == "info":
            self.cmd_info(args)
            return False
        if cmd == "ps":
            self.info_procs()
            return False
        if cmd == "regs":
            self.info_cpu(args)
            return False
        if cmd == "kill":
            self.cmd_kill(args)
            return False
        if cmd == "trace":
            self.cmd_trace(args)
            return False
        self.out(f"未知命令: {cmd}(输入 help 看命令)")
        return False

    # ---- info 分派 ----------------------------------------------------

    def cmd_info(self, args: List[str]) -> None:
        if not args:
            self.out("用法: info procs|mem|fs|syscalls|trace|cpu|fds|tty")
            return
        what = args[0].lower()
        rest = args[1:]
        handlers = {
            "procs": lambda: self.info_procs(),
            "proc": lambda: self.info_procs(),
            "mem": lambda: self.info_mem(),
            "memory": lambda: self.info_mem(),
            "fs": lambda: self.info_fs(),
            "syscalls": lambda: self.info_syscalls(),
            "syscall": lambda: self.info_syscalls(),
            "cpu": lambda: self.info_cpu(rest),
            "regs": lambda: self.info_cpu(rest),
            "fds": lambda: self.info_fds(rest),
            "fd": lambda: self.info_fds(rest),
            "tty": lambda: self.info_tty(),
            "trace": lambda: self.show_trace(
                int(rest[0]) if rest and rest[0].lstrip("-").isdigit() else 30),
        }
        fn = handlers.get(what)
        if fn is None:
            self.out(f"未知的 info 项: {what}")
            return
        fn()

    # ---- 进程 ---------------------------------------------------------

    def info_procs(self) -> None:
        k = self.k
        rows = []
        for pid in sorted(k.procs):
            p = k.procs[pid]
            ic = p.cpu.icount if p.cpu is not None else 0
            kind = "(内核任务)" if p.kernel_task else ""
            rows.append((p.pid, p.ppid, p.pgrp, STATE_NAMES.get(p.state, "?"),
                         f"{ic:,}", self._chan(p), f"{p.name}{kind}"))
        for line in table(("PID", "PPID", "PGRP", "状态", "指令数",
                           "等待", "程序"), rows,
                          aligns=["r", "r", "r", "l", "r", "l", "l"]):
            self.out(line)
        cur = k.current.pid if k.current is not None else "-"
        self.out(f"当前进程: {cur}   jiffies: {k.jiffies}   "
                 f"运行队列: {k.runq}   init 状态: {k._init_state}")

    @staticmethod
    def _chan(p) -> str:
        ch = p.wait_channel
        if ch is None:
            return "-"
        if isinstance(ch, tuple):
            if len(ch) == 2 and isinstance(ch[1], kvfs.Pipe):
                pipe = ch[1]
                return f"{ch[0]}({len(pipe.buf)}B)"
            return str(ch[0])
        return "tty" if ch is getattr(p, "tty", None) else type(ch).__name__

    # ---- 内存 ---------------------------------------------------------

    def info_mem(self) -> None:
        k = self.k
        rows = []
        total = 0
        for pid in sorted(k.procs):
            p = k.procs[pid]
            m = p.mem
            if m is None:
                continue
            low, stack = m.low_end, len(m.stack)
            tot = low + stack
            total += tot
            rows.append((p.pid, fmt_bytes(low), f"{m.brk:#x}",
                         fmt_bytes(stack), fmt_bytes(tot), p.name))
        for line in table(("PID", "代码+数据+堆", "brk", "栈", "合计", "程序"),
                          rows, aligns=["r", "r", "r", "r", "r", "l"]):
            self.out(line)
        self.out(f"全部进程合计 {fmt_bytes(total)}; "
                 f"用户空间上限 {fmt_bytes(0x4000000)}/进程(内核 change_ldt)")

    # ---- 文件系统 -----------------------------------------------------

    def info_fs(self, limit: int = 40) -> None:
        fs = self.k.fs
        st = fs.overlay_stats()
        self.out("覆盖层(全部改动只在内存里, 镜像文件永不被写):")
        self.out(f"  被改动的文件 {st['cow_files']} 个, "
                 f"被改动的目录 {st['cow_dirs']} 个, "
                 f"新建 {st['new_inodes']} 个, 已删除 {st['deleted']} 个")
        self.out(f"  覆盖层占用内存 {fmt_bytes(st['bytes'])}; "
                 f"下一个新 inode 号 {st['next_ino']}")
        rows = fs.changed_paths()
        if rows:
            self.out(f"  改动明细({len(rows)} 项"
                     f"{f', 只列前 {limit} 项' if len(rows) > limit else ''}):")
            body = [(kind, ino, fmt_bytes(size), path)
                    for path, kind, ino, size in rows[:limit]]
            for line in table(("变化", "inode", "大小", "路径"), body,
                              aligns=["l", "r", "r", "l"]):
                self.out("    " + line)
        base = fs.base.fs_stats()
        sb = fs.base.sb
        ip = base["used_inodes"] / base["total_inodes"] * 100
        zp = base["used_zones"] / base["total_zones"] * 100
        self.out("底层镜像(只读):")
        self.out(f"  inode {base['used_inodes']}/{base['total_inodes']} "
                 f"({ip:.1f}%), data zone {base['used_zones']}/"
                 f"{base['total_zones']} ({zp:.1f}%)")
        self.out(f"  块大小 1024B, magic {sb.magic:#06x}, "
                 f"文件名上限 {sb.name_len} 字符")

    # ---- 系统调用 -----------------------------------------------------

    def info_syscalls(self) -> None:
        k = self.k
        counts = k.syscall_counts
        if not counts:
            self.out("还没有系统调用记录。")
            return
        total = sum(counts.values())
        self.out(f"系统调用共 {total} 次, 按次数排序:")
        rows = [(nr, self.syscall_name(nr), f"{n:,}")
                for nr, n in sorted(counts.items(), key=lambda kv: -kv[1])[:20]]
        for line in table(("号", "名字", "次数"), rows,
                          aligns=["r", "l", "r"]):
            self.out("  " + line)
        self.show_trace(10)
        self.out(f"轨迹缓冲: 已存 {len(k.recent_syscalls)}/{k.trace_capacity} 条"
                 f"(trace show [n] 翻看, trace on|off 调容量)")

    def show_trace(self, n: int = 30) -> None:
        """翻看轨迹缓冲里最近的 n 条调用."""
        k = self.k
        if not k.recent_syscalls:
            self.out("轨迹缓冲是空的(还没有系统调用)。")
            return
        recs = list(k.recent_syscalls)[-max(n, 1):]
        self.out(f"最近 {len(recs)} 次调用(共存了 {len(k.recent_syscalls)} 条):")
        rows = [(pid, self.syscall_name(nr),
                 f"{a:#x}", f"{b:#x}", f"{c:#x}", self._fmt_ret(ret))
                for pid, nr, a, b, c, ret in recs]
        for line in table(("pid", "调用", "参数1", "参数2", "参数3", "返回"),
                          rows, aligns=["r", "l", "r", "r", "r", "r"]):
            self.out("  " + line)

    @staticmethod
    def _fmt_ret(ret: int) -> str:
        """负返回值是 -errno, 顺手标出 errno 名字."""
        if -40 < ret < 0:
            return f"{ret}({ERRNO_NAMES.get(-ret, '?')})"
        return str(ret)

    @staticmethod
    def syscall_name(nr: int) -> str:
        import ksyscall
        for name in dir(ksyscall):
            if name.startswith("NR_") and getattr(ksyscall, name) == nr:
                return name[3:].lower()
        return f"#{nr}"

    # ---- CPU ----------------------------------------------------------

    def _pick_proc(self, args: List[str]):
        k = self.k
        if args:
            try:
                pid = int(args[0])
            except ValueError:
                self.out(f"无效 pid: {args[0]}")
                return None
            p = k.procs.get(pid)
            if p is None:
                self.out(f"没有 pid {pid} 这个进程")
                return None
            return p
        p = k.current
        if p is None or p.cpu is None:
            for q in k.procs.values():
                if q.cpu is not None:
                    return q
        return p

    def info_cpu(self, args: List[str]) -> None:
        p = self._pick_proc(args)
        if p is None:
            return
        if p.cpu is None:
            self.out(f"pid {p.pid}({p.name}) 是内核任务, 没有用户态 CPU。")
            return
        cpu = p.cpu
        names = ("eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi")
        self.out(f"pid {p.pid} ({p.name})  已执行 {cpu.icount:,} 条指令")
        for i in range(0, 8, 4):
            self.out("  " + "  ".join(
                f"{names[j]}={cpu.regs[j]:#010x}" for j in range(i, i + 4)))
        f = cpu.eflags
        flags = "".join(ch for ch, bit in
                        (("C", 0x1), ("P", 0x4), ("A", 0x10), ("Z", 0x40),
                         ("S", 0x80), ("D", 0x400), ("O", 0x800)) if f & bit)
        self.out(f"  eip={cpu.eip:#010x}  eflags={f:#06x} [{flags or '-'}]")
        try:
            self.out(f"  eip 处字节: {p.mem.read(cpu.eip, 8).hex(' ')}")
        except Exception:
            self.out("  eip 处字节: <读不到>")

    # ---- 文件描述符 ---------------------------------------------------

    def info_fds(self, args: List[str]) -> None:
        p = self._pick_proc(args)
        if p is None:
            return
        self.out(f"pid {p.pid} ({p.name}) 的文件描述符:")
        empty = True
        for fd, f in enumerate(p.fds):
            if f is None:
                continue
            empty = False
            obj = f.obj
            if isinstance(obj, kvfs.VInode):
                kind = f"inode {obj.ino} size={obj.size}"
            elif isinstance(obj, kvfs.Pipe):
                kind = (f"管道 buf={len(obj.buf)}B "
                        f"读端={obj.readers} 写端={obj.writers}")
            elif obj is self.k.terminal:
                kind = "终端"
            else:
                kind = type(obj).__name__
            cloexec = " cloexec" if p.close_on_exec & (1 << fd) else ""
            self.out(f"  {fd:>2}: {kind}  pos={f.pos} "
                     f"flags={f.flags:#o} refs={f.refs}{cloexec}")
        if empty:
            self.out("  (无)")

    # ---- 终端 ---------------------------------------------------------

    def info_tty(self) -> None:
        tty = self.k.terminal
        if tty is None:
            self.out("没有终端。")
            return
        t = tty.termios
        on = lambda bit, name: name if t.lflag & bit else ""
        import ktty
        modes = " ".join(x for x in (
            on(ktty.ICANON, "ICANON"), on(ktty.ECHO, "ECHO"),
            on(ktty.ISIG, "ISIG"), on(ktty.ECHOE, "ECHOE")) if x)
        rows, cols = tty.term.size()
        self.out(f"终端: {type(tty.term).__name__}  "
                 f"{'交互(tty)' if tty.term.is_tty() else '非交互(管道/文件)'}  "
                 f"{rows}x{cols}")
        self.out(f"  行规程: {modes or '(全关, 即 raw 模式)'}")
        self.out(f"  前台进程组 pgrp={tty.pgrp} 会话 session={tty.session}")
        self.out(f"  待读 {len(tty.ready)}B, 正在编辑的行 {len(tty.line)}B, "
                 f"EOF 待投递={tty.eof_pending}")
        self.out(f"  c_cc: INTR=^{chr(64 + t.cc[ktty.VINTR])} "
                 f"ERASE={t.cc[ktty.VERASE]} "
                 f"EOF=^{chr(64 + t.cc[ktty.VEOF])}")

    # ---- 其它命令 -----------------------------------------------------

    def cmd_kill(self, args: List[str]) -> None:
        if not args:
            self.out("用法: kill <pid> [信号]")
            return
        try:
            pid = int(args[0])
            sig = int(args[1]) if len(args) > 1 else 15
        except ValueError:
            self.out("pid 与信号必须是整数")
            return
        p = self.k.procs.get(pid)
        if p is None:
            self.out(f"没有 pid {pid} 这个进程")
            return
        self.k.post_signal(p, sig)
        self.out(f"已向 pid {pid}({p.name}) 投递信号 {sig}")

    def cmd_trace(self, args: List[str]) -> None:
        """trace show [n] | trace on [容量] | trace off.

        轨迹本身是常开的(只有一份环形缓冲), on/off 调的是容量:
        on 把缓冲放大以便留更长历史, off 缩回默认值。
        """
        k = self.k
        if not args:
            self.out(f"用法: trace show [n] | trace on [容量] | trace off"
                     f"(当前容量 {k.trace_capacity}, 已存 "
                     f"{len(k.recent_syscalls)} 条)")
            return
        sub = args[0].lower()
        if sub in ("show", "list", "dump"):
            n = 30
            if len(args) > 1:
                try:
                    n = int(args[1])
                except ValueError:
                    self.out(f"条数必须是整数: {args[1]}")
                    return
            self.show_trace(n)
            return
        if sub == "on":
            cap = kmod.TRACE_VERBOSE
            if len(args) > 1:
                try:
                    cap = int(args[1])
                except ValueError:
                    self.out(f"容量必须是整数: {args[1]}")
                    return
            k.set_trace_capacity(cap)
            k.verbose = True
            self.out(f"轨迹缓冲容量已设为 {k.trace_capacity} 条"
                     f"(退出时也会把它转储到 stderr)")
            return
        if sub == "off":
            k.set_trace_capacity(kmod.TRACE_DEFAULT)
            k.verbose = False
            self.out(f"轨迹缓冲容量已缩回 {k.trace_capacity} 条"
                     f"(仍在记录, 只是历史更短)")
            return
        self.out(f"未知的 trace 子命令: {sub}")
