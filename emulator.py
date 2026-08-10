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
                 verbose: bool = False, escape: int = 0x01):
    """搭起 镜像 -> 覆盖层 -> 终端 -> 内核 -> monitor 这条链."""
    fs = OverlayFS(MinixFS.open(image, offset=offset))
    if scripted_input is None:
        term = ktty.HostTerminal()
    else:
        term = ktty.ScriptedTerminal(inputs=scripted_input)
    k = Kernel(fs, verbose=verbose)
    # 转义键回调要指到内核, 所以 TTY 在 Kernel 之后建, 再回填
    tty = ktty.TTY(term, escape=escape, on_escape=k.on_escape)
    k.terminal = tty
    k.monitor = kmonitor.Monitor(k)
    _preset_overlay(k)
    return k, term


def _preset_overlay(k: Kernel) -> None:
    """在覆盖层里补上镜像缺失的东西(纯内存, 不改镜像).

    镜像里没有 /dev/console, 但 /bin/init 等要打开它; /etc/utmp 与
    /etc/wtmp 也不存在而 login 要写。
    """
    fs = k.fs
    for path, mode, dev in (("/dev/console", 0o020600, (5 << 8) | 0),):
        try:
            fs.walk(path)
        except FsError:
            try:
                fs.mknod(path, mode, dev)
            except FsError:
                pass
    for path in ("/etc/utmp", "/etc/wtmp"):
        try:
            fs.walk(path)
        except FsError:
            try:
                fs.create(path, 0o644)
            except FsError:
                pass


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Linux 0.11 用户态仿真器")
    ap.add_argument("image", help="磁盘镜像(裸 minix 或带 MBR)")
    # 不传程序名时走内核 init/main.c 的 init(): 跑 /etc/rc, 再起 login shell。
    # 注意 Linux 0.11 的 init 是内核里的函数, 不是磁盘上的 /bin/init
    # (镜像里那个 /bin/init 是后来某个软件包的东西, 不在引导链上)。
    ap.add_argument("program", nargs="?", default=None,
                    help="要运行的程序; 省略则走内核 init(): /etc/rc + login shell")
    # REMAINDER: 程序名之后的一切原样透传, 这样 `ls -l` 的 -l 不会被本脚本吃掉
    ap.add_argument("args", nargs=argparse.REMAINDER,
                    help="传给程序的参数(原样透传)")
    ap.add_argument("--offset", type=int, default=None, help="文件系统起始偏移")
    ap.add_argument("--max-insns", type=int, default=2_000_000_000,
                    help="指令数上限(防跑飞)")
    ap.add_argument("--trace", action="store_true", help="打印系统调用轨迹")
    ap.add_argument("--save-overlay", metavar="FILE",
                    help="退出时把覆盖层改动导出到文件")
    ap.add_argument("--load-overlay", metavar="FILE",
                    help="启动时加载之前导出的覆盖层")
    ap.add_argument("--monitor", action="store_true",
                    help="启动后先进入 monitor 控制台")
    ap.add_argument("--escape", metavar="CHAR", default="a",
                    help="monitor 转义键(默认 a, 即 Ctrl-A); 传 none 关闭")
    a = ap.parse_args(argv)

    if a.escape.lower() in ("none", "off", ""):
        escape = 0
    elif len(a.escape) == 1:
        escape = ord(a.escape.upper()) & 0x1F      # 'a' -> Ctrl-A(0x01)
    else:
        print(f"--escape 只接受单个字符或 none: {a.escape}", file=sys.stderr)
        return 2

    try:
        k, term = build_kernel(a.image, a.offset, verbose=a.trace,
                               escape=escape)
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
        if a.program is None:
            k.boot_init()               # 内核 init(): /etc/rc -> login shell
        else:
            argv_list = [a.program.encode()] + [x.encode() for x in a.args]
            k.boot(a.program, argv_list)
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
            for line in k.trace[-200:]:
                print(line, file=sys.stderr)

    if a.save_overlay:
        with open(a.save_overlay, "wb") as f:
            pickle.dump(k.fs.export_changes(), f)

    return (code >> 8) & 0xFF if code and code > 0 else 0


if __name__ == "__main__":
    sys.exit(main())
