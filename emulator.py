#!/usr/bin/env python3
"""Linux 0.11 仿真器: 运行 Minix v1 镜像里的 a.out 二进制.

用法:
    python3 emulator.py <镜像> [程序 [参数...]]
    python3 emulator.py hdc-0.11.img /bin/date
    printf 'echo hi\\n' | python3 emulator.py hdc-0.11.img /bin/sh
"""

from __future__ import annotations

import argparse
import pickle
import sys

import kernel as kmod
import kmonitor
import ktty
from kernel import Kernel
from kexec import ExecError
from kvfs import FsError, OverlayFS
from minixfs import MinixError, MinixFS


def build_kernel(image: str, offset=None, scripted_input=None,
                 escape: int = 0x01):
    """搭起 镜像 -> 覆盖层 -> 终端 -> 内核 -> monitor 这条链.

    不需要在覆盖层里预置任何文件: 内核 init() 打开的是镜像里真实存在的
    /dev/tty0(早先为 /bin/init 那条错误引导路径合成过 /dev/console 与
    /etc/utmp, 已随之删除)。
    """
    fs = OverlayFS(MinixFS.open(image, offset=offset))
    if scripted_input is None:
        term = ktty.HostTerminal()
    else:
        term = ktty.ScriptedTerminal(inputs=scripted_input)
    k = Kernel(fs)
    # 转义键回调要指到内核, 所以 TTY 在 Kernel 之后建, 再回填
    tty = ktty.TTY(term, escape=escape, on_escape=k.on_escape)
    k.terminal = tty
    k.monitor = kmonitor.Monitor(k)
    return k, term


# 需要跟一个值的仿真器选项(拆分参数时要把值一起带走)
VALUE_OPTS = {"--offset", "--max-insns", "--save-overlay", "--load-overlay",
              "--escape"}


def split_argv(argv: list) -> tuple:
    """把命令行拆成 [仿真器自己的部分] 与 [程序及其参数].

    形态是 `emulator.py [选项] 镜像 [选项] [程序 [程序参数...]]`, 程序名之后的
    一切都原样透传给被仿真程序(好让 `ls -l` 的 `-l` 不被吃掉)。

    不能用 argparse 的 nargs=REMAINDER 来做: 它会把本该落到 `program` 的那个
    位置参数也一起吞进 args, 于是 `--trace /bin/date` 会变成 program=None、
    args=['/bin/date'], 结果跑的是引导链而不是 date。
    """
    head, tail = [], []
    seen_image = False
    i = 0
    while i < len(argv):
        a = argv[i]
        if a.startswith("-") and a != "-":
            head.append(a)
            if a in VALUE_OPTS and i + 1 < len(argv):
                head.append(argv[i + 1])
                i += 1
        elif not seen_image:
            head.append(a)                 # 镜像
            seen_image = True
        else:
            tail = list(argv[i:])          # 程序及其后全部透传
            break
        i += 1
    return head, tail


def main(argv=None) -> int:
    if argv is None:
        argv = sys.argv[1:]
    head, tail = split_argv(list(argv))
    program = tail[0] if tail else None
    prog_args = tail[1:]

    ap = argparse.ArgumentParser(
        description="Linux 0.11 用户态仿真器",
        usage="%(prog)s [选项] 镜像 [程序 [程序参数...]]",
        epilog="注意: 仿真器自己的选项要写在程序名之前 —— 程序名之后的一切"
               "都原样透传给被仿真程序。")
    ap.add_argument("image", help="磁盘镜像(裸 minix 或带 MBR)")
    ap.add_argument("--offset", type=int, default=None, help="文件系统起始偏移")
    ap.add_argument("--max-insns", type=int, default=2_000_000_000,
                    help="指令数上限(防跑飞)")
    ap.add_argument("--trace", action="store_true",
                    help="放大轨迹缓冲, 并在退出时把它转储到 stderr")
    ap.add_argument("--save-overlay", metavar="FILE",
                    help="退出时把覆盖层改动导出到文件")
    ap.add_argument("--load-overlay", metavar="FILE",
                    help="启动时加载之前导出的覆盖层")
    ap.add_argument("--monitor", action="store_true",
                    help="启动后先进入 monitor 控制台")
    ap.add_argument("--escape", metavar="CHAR", default="a",
                    help="monitor 转义键(默认 a, 即 Ctrl-A); 传 none 关闭")
    a = ap.parse_args(head)

    if a.escape.lower() in ("none", "off", ""):
        escape = 0
    elif len(a.escape) == 1:
        escape = ord(a.escape.upper()) & 0x1F      # 'a' -> Ctrl-A(0x01)
    else:
        print(f"--escape 只接受单个字符或 none: {a.escape}", file=sys.stderr)
        return 2

    try:
        k, term = build_kernel(a.image, a.offset, escape=escape)
        if a.trace:
            k.set_trace_capacity(kmod.TRACE_VERBOSE)
    except (OSError, MinixError) as e:
        print(f"打开镜像失败: {e}", file=sys.stderr)
        return 1
    if escape == 0:
        k.terminal.on_escape = None                # 关掉转义键
    elif term.is_tty():
        name = chr(64 + escape)
        print(f"[monitor: Ctrl-{name} c 进入控制台, Ctrl-{name} x 退出, "
              f"Ctrl-{name} ? 帮助]")

    if a.load_overlay:
        with open(a.load_overlay, "rb") as f:
            k.fs.import_changes(pickle.load(f))

    try:
        if program is None:
            k.boot_init()               # 内核 init(): /etc/rc -> login shell
        else:
            argv_list = [program.encode()] + [x.encode() for x in prog_args]
            k.boot(program, argv_list)
    except (FsError, ExecError) as e:
        term.restore()
        print(f"启动失败: {e}", file=sys.stderr)
        return 1

    if a.monitor:
        k.monitor_pending = True

    try:
        code = k.run(a.max_insns)
    except KeyboardInterrupt:
        code = -1
    finally:
        term.restore()
        if a.trace:
            # 转储与 monitor 的 `trace show` 同一份数据(带 pid 与 errno 名)
            dump = kmonitor.Monitor(k, write=lambda s: sys.stderr.write(s))
            dump.show_trace(k.trace_capacity)

    if a.save_overlay:
        with open(a.save_overlay, "wb") as f:
            pickle.dump(k.fs.export_changes(), f)

    return (code >> 8) & 0xFF if code and code > 0 else 0


if __name__ == "__main__":
    sys.exit(main())
