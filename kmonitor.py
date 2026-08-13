"""仿真器 monitor —— 类似 qemu 的 monitor 控制台.

进入方式(默认转义键 Ctrl-A, 仿 qemu 的 Ctrl-A 前缀):
    Ctrl-A c    进入 monitor
    Ctrl-A x    直接退出仿真器
    Ctrl-A a    向被仿真程序发一个真正的 Ctrl-A
    Ctrl-A ?    显示按键帮助

monitor 里的命令(输入 help 查看):
    info procs / mem / fs / syscalls / cpu / fds / tty / profile
    ps  regs  kill  trace  prof  cont  quit

读写全部可注入(read_line/write), 所以能用脚本化输入做单元测试, 不必真的
占用宿主终端 —— 与 pager.py 的注入哲学一致。
"""

from __future__ import annotations

import unicodedata
from typing import Callable, List, Optional

import cpu86
import cpu_disasm
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
info profile      按进程性能: 指令数/仿真时间/系统调用(含已死进程历史)
info profile <pid> 单个进程的指令分布/热点/系统调用(指令分布需 prof on)
info console      最近的控制台输出
ps                = info procs
regs [pid]        = info cpu
kill <pid> [信号] 给被仿真进程发信号(默认 15/SIGTERM)
trace show [n]    同 info trace
trace on [容量]   放大轨迹缓冲以留更长历史(默认 5000 条)
trace off         缩回默认容量(轨迹始终在记, 只是历史更短)
prof on|off       开关 CPU 性能剖析(默认关; 开着会拖慢仿真)
prof reset        清零剖析计数
── 单步调试(gdb 风格)──
si / stepi [n]    单步执行 n 条指令(默认 1), 停后显示反汇编与寄存器
disas [addr] [n]  反汇编 n 条(默认从 eip 起 8 条)
x /NFU addr       检查内存: N 个单位, 格式 x/d/u/c/i, 单位 b/h/w(i=反汇编)
break <addr>      设断点; break list 列出; break del <addr|all> 删除
until <addr>      运行到该地址(一次性断点)
layout [on|off]   gdb 风格三栏视图(反汇编/寄存器/栈); 停下时自动刷新
(回车)            空行重复上一条命令(连按回车即可反复 si 单步)
cont              退出 monitor 继续跑(断点仍会命中)
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
        self._last_addr = None          # x / disas 续址
        self._last_cmd = ""             # 空行(回车)重复的上一条命令
        self._layout = False            # gdb 风格 layout: 停下时显示反汇编/寄存器/栈

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
        term = getattr(self.k.terminal, "term", None)
        if term is not None and hasattr(term, "suspend"):
            term.suspend()                 # 暂时恢复宿主终端的常规模式
        try:
            if self.k.debug_stop is not None:
                self._print_debug_stop(self.k.debug_stop)
                self.k.debug_stop = None
            else:
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
        """执行一条命令; 返回 True 表示该离开 monitor.

        空行(直接回车)重复上一条命令 —— 仿 gdb, 便于连按回车反复 si 单步。
        """
        if not line:
            line = self._last_cmd
            if not line:
                return False
        parts = line.split()
        cmd, args = parts[0].lower(), parts[1:]
        # 离开类命令不记为"上一条", 免得回车重进后误触发
        if cmd not in ("cont", "c", "continue", "quit", "q", "exit"):
            self._last_cmd = line
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
        if cmd == "prof":
            self.cmd_prof(args)
            return False
        if cmd in ("si", "stepi", "step", "s"):
            return self.cmd_step(args)
        if cmd in ("disas", "disassemble", "u"):
            self.cmd_disas(args)
            return False
        if cmd == "x" or cmd.startswith("x/"):
            self.cmd_x(([cmd[1:]] + args) if cmd != "x" else args)
            return False
        if cmd in ("break", "b", "bp"):
            self.cmd_break(args)
            return False
        if cmd == "until":
            return self.cmd_until(args)
        if cmd in ("layout", "lay"):
            self.cmd_layout(args)
            return False
        self.out(f"未知命令: {cmd}(输入 help 看命令)")
        return False

    # ---- info 分派 ----------------------------------------------------

    def cmd_info(self, args: List[str]) -> None:
        if not args:
            self.out("用法: info procs|mem|fs|syscalls|trace|cpu|fds|tty|"
                     "profile|console")
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
            "profile": lambda: self.info_profile(rest),
            "prof": lambda: self.info_profile(rest),
            "console": lambda: self.info_console(rest),
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
        return type(ch).__name__

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
        state = "开(info profile 看统计)" if self.k.profiling else "关(prof on 打开)"
        self.out(f"  性能剖析: {state}")

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
            self.out(f"轨迹缓冲容量已设为 {k.trace_capacity} 条")
            return
        if sub == "off":
            k.set_trace_capacity(kmod.TRACE_DEFAULT)
            self.out(f"轨迹缓冲容量已缩回 {k.trace_capacity} 条"
                     f"(仍在记录, 只是历史更短)")
            return
        self.out(f"未知的 trace 子命令: {sub}")

    # ---- 性能剖析 -----------------------------------------------------

    def cmd_prof(self, args: List[str]) -> None:
        """prof on | off | reset —— 开关 CPU 指令混合剖析并清零计数.

        指令混合剖析默认关: cpu86 是纯 Python 解释器, 逐指令插桩有成本, 开着会
        拖慢仿真。(按进程的指令数/仿真时间/系统调用统计始终常开, 不受此开关影响,
        info profile 随时能看。)
        """
        k = self.k
        sub = args[0].lower() if args else "show"
        if sub == "on":
            k.set_profiling(True)
            self.out("指令混合剖析已开启(会拖慢仿真; info profile 看统计)。")
            return
        if sub == "off":
            k.set_profiling(False)
            self.out("指令混合剖析已关闭(常开的进程统计仍在)。")
            return
        if sub == "reset":
            k.reset_profiling()
            self.out("现存进程的指令混合计数已清零。")
            return
        self.out(f"用法: prof on|off|reset(当前"
                 f"{'开' if k.profiling else '关'})")

    # ---- 按进程的性能视图 ----

    def _perf_entries(self) -> list:
        """把活着的进程与历史里的死进程统一成一串性能条目."""
        ents = []
        for p in self.k.procs.values():
            if p.kernel_task:                 # init 等内核任务无用户态, 跳过
                continue
            ents.append({
                "pid": p.pid, "name": p.name or "?", "icount": p.utime,
                "wall": p.wall, "syscalls": p.syscall_counts, "prof": p.prof,
                "state": STATE_NAMES.get(p.state, "?"), "alive": True})
        for r in self.k.proc_history:
            ents.append({
                "pid": r.pid, "name": r.name or "?", "icount": r.icount,
                "wall": r.wall, "syscalls": r.syscalls, "prof": r.prof,
                "state": f"退{(r.exit_code >> 8) & 0xFF}", "alive": False})
        return ents

    @staticmethod
    def _basename(path: str) -> str:
        return path.rsplit("/", 1)[-1] or path

    def info_profile(self, args: Optional[List[str]] = None) -> None:
        if args:
            self._info_profile_one(args[0])
            return
        ents = self._perf_entries()
        if not ents:
            self.out("还没有可统计的进程。")
            return
        ents.sort(key=lambda e: -e["icount"])
        self.out(f"按进程性能(活 {sum(e['alive'] for e in ents)} + 历史 "
                 f"{sum(not e['alive'] for e in ents)}; 指令混合"
                 f"{'开' if self.k.profiling else '关, prof on 打开'}):")
        rows = []
        for e in ents:
            wall_ms = e["wall"] * 1000
            speed = (f"{e['icount'] / e['wall'] / 1e6:.2f}"
                     if e["wall"] > 1e-9 else "-")
            prof = e["prof"]
            if prof is not None and prof.insns:
                i = max(range(len(cpu86.CAT_NAMES)),
                        key=lambda k: prof.cat_counts[k])
                top = f"{cpu86.CAT_NAMES[i]} {prof.cat_counts[i]*100/prof.insns:.0f}%"
            else:
                top = "-"
            rows.append((e["pid"], self._basename(e["name"]), e["state"],
                         f"{e['icount']:,}", f"{wall_ms:.1f}", speed,
                         f"{sum(e['syscalls'].values()):,}", top))
        for line in table(
                ("pid", "程序", "状态", "指令数", "仿真ms", "M/s", "调用", "主类别"),
                rows, aligns=["r", "l", "l", "r", "r", "r", "r", "l"]):
            self.out("  " + line)
        self.out("  (info profile <pid> 看单个进程的指令分布/热点/系统调用)")

    def _info_profile_one(self, pid_str: str) -> None:
        try:
            pid = int(pid_str)
        except ValueError:
            self.out(f"无效 pid: {pid_str}")
            return
        e = next((x for x in self._perf_entries() if x["pid"] == pid), None)
        if e is None:
            self.out(f"没有 pid {pid} 的性能记录(活进程或历史里都没有)。")
            return
        wall_ms = e["wall"] * 1000
        speed = (f"{e['icount'] / e['wall'] / 1e6:.2f} M/s"
                 if e["wall"] > 1e-9 else "-")
        tag = "活" if e["alive"] else "已退出"
        self.out(f"pid {pid} ({e['name']})  [{tag}, {e['state']}]")
        self.out(f"  指令数 {e['icount']:,}   仿真墙钟 {wall_ms:.1f}ms   速度 {speed}")

        # 系统调用分布
        sc = e["syscalls"]
        if sc:
            self.out(f"  系统调用共 {sum(sc.values()):,} 次:")
            srows = [(self.syscall_name(nr), f"{n:,}")
                     for nr, n in sorted(sc.items(), key=lambda kv: -kv[1])[:15]]
            for line in table(("调用", "次数"), srows, aligns=["l", "r"]):
                self.out("    " + line)
        else:
            self.out("  无系统调用记录。")

        # 指令分布(需 prof on 时采集)
        self._render_prof_detail(e["prof"])

    def dump_profile(self) -> None:
        """退出时的完整转储: 概览 + 每个进程的明细(供 --profile 用)."""
        self.info_profile()
        seen = set()
        for e in sorted(self._perf_entries(), key=lambda x: -x["icount"]):
            if e["pid"] in seen:
                continue
            seen.add(e["pid"])
            self.out("")
            self._info_profile_one(str(e["pid"]))

    def _render_prof_detail(self, prof) -> None:
        if prof is None or prof.insns == 0:
            self.out("  指令分布: 未采集(prof on 后重跑该程序)。")
            return
        total = prof.insns
        self.out(f"  指令分布(采样 {total:,} 条):")
        order = sorted(range(len(cpu86.CAT_NAMES)),
                       key=lambda i: -prof.cat_counts[i])
        rows = [(cpu86.CAT_NAMES[i], f"{prof.cat_counts[i]:,}",
                 f"{prof.cat_counts[i] * 100 / total:.1f}%")
                for i in order if prof.cat_counts[i]]
        for line in table(("类别", "计数", "占比"), rows, aligns=["l", "r", "r"]):
            self.out("    " + line)

        span = 1 << prof.bucket_shift
        top = sorted(prof.hot.items(), key=lambda kv: -kv[1])[:10]
        self.out(f"  热点地址(每桶 {span}B, 前 {len(top)} 名):")
        hrows = [(f"{b * span:#010x}-{b * span + span - 1:#06x}",
                  f"{n:,}", f"{n * 100 / total:.1f}%") for b, n in top]
        for line in table(("地址区间", "计数", "占比"), hrows,
                          aligns=["l", "r", "r"]):
            self.out("    " + line)

        c = prof.cat_counts
        mem_insns = sum(c[i] for i in cpu86._CAT_MEMORY)
        branches = c[cpu86.CAT_BRANCH]
        strings = c[cpu86.CAT_STRING]
        self.out("  派生指标:")
        self.out(f"    访存指令占比  {mem_insns * 100 / total:.1f}%(MOV+栈+串)")
        self.out(f"    控制流密度    {branches * 100 / total:.1f}%(分支 / 全部)")
        avg_bb = total / branches if branches else float(total)
        self.out(f"    平均基本块长  {avg_bb:.1f} 条 / 分支")
        if strings:
            self.out(f"    rep 放大倍数  {prof.rep_elems / strings:.1f}"
                     f"(串搬 {prof.rep_elems:,} 元素 / {strings:,} 条串指令)")

    # ---- 单步调试 -----------------------------------------------------

    STOP_DESC = {"step": "单步", "break": "命中断点", "until": "运行到",
                 "exited": "进程退出", "blocked": "阻塞", "execve": "execve 换映像",
                 "sigreturn": "信号返回", "halted": "halt 停机"}

    def _debug_proc(self):
        """当前调试目标进程(优先 debug_target_pid, 否则当前有 CPU 的进程)."""
        pid = self.k.debug_target_pid
        if pid is not None and pid in self.k.procs:
            return self.k.procs[pid]
        return self._pick_proc([])

    def _regline(self, cpu) -> str:
        n = ("eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi")
        return " ".join(f"{n[j]}={cpu.regs[j]:08x}" for j in range(8))

    def _cur_insn(self, p) -> str:
        length, text, raw = cpu_disasm.disasm_one(p.mem, p.cpu.eip)
        return f"{p.cpu.eip:08x}: {raw.hex(' '):<20} {text}"

    def _print_debug_stop(self, reason: tuple) -> None:
        kind = reason[0]
        desc = self.STOP_DESC.get(kind, kind)
        pid = reason[1] if len(reason) > 1 else None
        p = self.k.procs.get(pid) if pid is not None else None
        if kind in ("break", "until"):
            self.out(f"[{desc} 0x{reason[2]:x}] pid {pid}")
        elif kind == "exited":
            self.out(f"[{desc}] pid {pid} 退出码 {reason[2] >> 8}")
            return
        elif kind == "blocked":
            self.out(f"[{desc}] pid {pid} 等待 {reason[2]}(该进程已睡眠, "
                     f"用 cont 让它继续)")
        else:
            self.out(f"[{desc}] pid {pid}")
        if p is not None and p.cpu is not None:
            if self._layout:
                self._render_layout(p)
            else:
                self.out("  " + self._cur_insn(p))
                self.out("  " + self._regline(p.cpu))

    def cmd_layout(self, args: List[str]) -> None:
        """layout [on|off] —— gdb 风格视图: 停下时显示反汇编/寄存器/栈三栏。

        无参数时切换开关; 开启(或已开)时立即渲染一次当前进程的视图。
        """
        sub = args[0].lower() if args else "toggle"
        if sub in ("off", "none", "0", "no"):
            self._layout = False
            self.out("layout 已关闭(停下只显示一行)。")
            return
        if sub in ("on", "asm", "1", "yes"):
            self._layout = True
        else:                                    # toggle
            self._layout = not self._layout
        if not self._layout:
            self.out("layout 已关闭(停下只显示一行)。")
            return
        self.out("layout 已开启(单步/断点停下会显示三栏; 回车重复上一条命令)。")
        p = self._debug_proc()
        if p is not None and p.cpu is not None:
            self._render_layout(p)

    def _render_layout(self, p) -> None:
        """三栏视图: 反汇编窗口(当前 eip 起 8 条, → 标当前) + 寄存器 + 栈顶。"""
        cpu = p.cpu
        self.out("── 反汇编 " + "─" * 34)
        for a, raw, text in cpu_disasm.disasm_range(p.mem, cpu.eip, 8):
            mark = "→" if a == cpu.eip else " "
            self.out(f" {mark} {a:08x}: {raw.hex(' '):<20} {text}")
        self.out("── 寄存器 " + "─" * 34)
        names = ("eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi")
        for i in range(0, 8, 4):
            self.out("  " + "  ".join(
                f"{names[j]}={cpu.regs[j]:08x}" for j in range(i, i + 4)))
        f = cpu.eflags
        flags = "".join(ch for ch, bit in
                        (("C", 0x1), ("P", 0x4), ("A", 0x10), ("Z", 0x40),
                         ("S", 0x80), ("D", 0x400), ("O", 0x800)) if f & bit)
        self.out(f"  eip={cpu.eip:08x}  eflags={f:#06x} [{flags or '-'}]")
        self.out("── 栈 " + "─" * 38)
        esp = cpu.regs[4]
        for i in range(6):
            a = (esp + i * 4) & 0xFFFFFFFF
            try:
                v = p.mem.read_u32(a)
            except Exception:
                break
            top = "  <- esp" if i == 0 else ""
            self.out(f"  {a:08x}: 0x{v:08x}{top}")

    def cmd_step(self, args: List[str]) -> bool:
        """si / stepi [n]: 单步 n 条; 置 step_request 后离开 monitor 让调度器跑。"""
        p = self._debug_proc()
        if p is None or p.cpu is None:
            self.out("没有可单步的用户态进程。")
            return False
        if p.state != kmod.RUNNING:
            self.out(f"pid {p.pid} 当前不可运行({STATE_NAMES.get(p.state, '?')}), "
                     f"用 cont 让它继续。")
            return False
        n = 1
        if args:
            try:
                n = max(int(args[0]), 1)
            except ValueError:
                self.out(f"步数必须是整数: {args[0]}")
                return False
        self.k.step_request = n
        return True                          # 离开 monitor, 由调度器执行并回来

    def cmd_disas(self, args: List[str]) -> None:
        p = self._debug_proc()
        if p is None or p.cpu is None:
            self.out("没有可反汇编的进程。")
            return
        count = 8
        addr = p.cpu.eip
        rest = list(args)
        if rest and not rest[-1].startswith("0x") and rest[-1].isdigit() \
                and len(rest) >= 2:
            count = int(rest.pop())
        if rest:
            a = self._parse_addr(rest[0], p)
            if a is None:
                return
            addr = a
        elif self._last_addr is not None and not args:
            addr = self._last_addr
        cur = p.cpu.eip
        for a, raw, text in cpu_disasm.disasm_range(p.mem, addr, count):
            mark = "→" if a == cur else " "
            self.out(f"{mark} {a:08x}: {raw.hex(' '):<20} {text}")
            self._last_addr = (a + len(raw)) & 0xFFFFFFFF

    def cmd_x(self, args: List[str]) -> None:
        """x /NFU addr —— 检查内存。N 个单位, 格式 x/d/u/c/i, 单位 b/h/w。"""
        p = self._debug_proc()
        if p is None or p.cpu is None:
            self.out("没有进程可查内存。")
            return
        count, fmt, unit = 1, "x", "w"
        rest = list(args)
        if rest and rest[0].startswith("/"):
            spec = rest.pop(0)[1:]
            num = "".join(c for c in spec if c.isdigit())
            if num:
                count = int(num)
            for c in spec:
                if c in "xduci":
                    fmt = c
                elif c in "bhw":
                    unit = c
        addr = self._last_addr if (not rest and self._last_addr is not None) \
            else None
        if rest:
            addr = self._parse_addr(rest[0], p)
        if addr is None:
            self.out("用法: x /NFU addr(如 x/8xw 0x1000, x/5i eip)")
            return
        if fmt == "i":
            for a, raw, text in cpu_disasm.disasm_range(p.mem, addr, count):
                self.out(f"  {a:08x}: {raw.hex(' '):<20} {text}")
                addr = (a + len(raw)) & 0xFFFFFFFF
            self._last_addr = addr
            return
        size = {"b": 1, "h": 2, "w": 4}[unit]
        per = 16 // size
        vals = []
        for i in range(count):
            a = (addr + i * size) & 0xFFFFFFFF
            try:
                v = (p.mem.read_u8(a) if size == 1 else
                     p.mem.read_u16(a) if size == 2 else p.mem.read_u32(a))
            except Exception:
                vals.append("<越界>")
                continue
            vals.append(self._fmt_unit(v, fmt, size))
        for i in range(0, len(vals), per):
            chunk = vals[i:i + per]
            self.out(f"  {(addr + i * size) & 0xFFFFFFFF:08x}: "
                     + " ".join(chunk))
        self._last_addr = (addr + count * size) & 0xFFFFFFFF

    @staticmethod
    def _fmt_unit(v: int, fmt: str, size: int) -> str:
        if fmt == "d":
            sign = 1 << (size * 8 - 1)
            return str(v - (1 << (size * 8)) if v & sign else v)
        if fmt == "u":
            return str(v)
        if fmt == "c":
            return repr(chr(v & 0xFF))
        return f"0x{v:0{size * 2}x}"

    def cmd_break(self, args: List[str]) -> None:
        k = self.k
        if not args or args[0] in ("list", "ls"):
            if not k.breakpoints:
                self.out("没有断点。")
            else:
                self.out("断点: " + ", ".join(f"0x{a:x}"
                                             for a in sorted(k.breakpoints)))
            return
        if args[0] in ("del", "delete", "d", "clear"):
            if len(args) > 1 and args[1] == "all":
                k.breakpoints.clear()
                self.out("已清除所有断点。")
                return
            a = self._parse_addr(args[1], self._debug_proc()) if len(args) > 1 \
                else None
            if a is not None:
                k.breakpoints.discard(a)
                self.out(f"已删断点 0x{a:x}。")
            return
        a = self._parse_addr(args[0], self._debug_proc())
        if a is not None:
            k.breakpoints.add(a)
            self.out(f"已设断点 0x{a:x}。")

    def cmd_until(self, args: List[str]) -> bool:
        p = self._debug_proc()
        if not args:
            self.out("用法: until <addr>")
            return False
        a = self._parse_addr(args[0], p)
        if a is None:
            return False
        self.k.temp_breakpoints.add(a)
        return True                          # 离开 monitor 跑到该地址

    def info_console(self, args: List[str] = None) -> None:
        term = self.k.terminal
        tail = getattr(term, "console_tail", None)
        if tail is None:
            self.out("此终端没有输出留存。")
            return
        data = bytes(tail)
        if not data:
            self.out("控制台还没有输出。")
            return
        text = data.decode("utf-8", "replace")
        self.out(f"最近控制台输出({len(data)} 字节):")
        for line in text.splitlines():
            self.out("  " + line)

    def _parse_addr(self, tok: str, p=None):
        """解析地址: 0x.. / 十进制 / 寄存器名(eip|esp|$eax..)。失败返回 None 并报错。"""
        tok = tok.strip()
        name = tok[1:] if tok.startswith("$") else tok   # 认 gdb 的 $ 前缀
        if name in ("eip", "pc"):
            name = "_eip"
        if name == "_eip" or name in cpu86.REG32_NAMES:
            if p is None or p.cpu is None:
                self.out("没有当前进程的寄存器可用。")
                return None
            return p.cpu.eip if name == "_eip" \
                else p.cpu.regs[cpu86.REG32_NAMES.index(name)]
        try:
            return int(tok, 0) & 0xFFFFFFFF
        except ValueError:
            self.out(f"无效地址: {tok}")
            return None
