#!/usr/bin/env python3
"""Minix v1 文件系统镜像的交互式浏览 shell.

用法: python3 minix_shell.py <镜像文件> [--offset 字节偏移]
"""

from __future__ import annotations

import argparse
import cmd
import shlex
import sys

from minixfs import Inode, MinixError, MinixFS


def normalize_path(base: str, path: str) -> str:
    """把相对/绝对路径规范化为以 / 开头的干净路径(用于 pwd 显示)."""
    if not path.startswith("/"):
        path = base.rstrip("/") + "/" + path
    parts = []
    for part in path.split("/"):
        if part in ("", "."):
            continue
        if part == "..":
            if parts:
                parts.pop()
        else:
            parts.append(part)
    return "/" + "/".join(parts)


class MinixShell(cmd.Cmd):
    intro = "Minix v1 文件系统浏览器, 输入 help 查看命令."

    def __init__(self, fs: MinixFS, page_size: int = 23, input_fn=input, **kwargs):
        super().__init__(**kwargs)
        self.fs = fs
        self.cwd = fs.root
        self.cwd_path = "/"
        self.page_size = page_size   # less 每页行数
        self.input_fn = input_fn     # less 翻页交互, 测试时可注入
        self._update_prompt()

    # ---- 基础设施 ----------------------------------------------------

    def _update_prompt(self) -> None:
        self.prompt = f"minix:{self.cwd_path}$ "

    def _print(self, text: str = "") -> None:
        self.stdout.write(text + "\n")

    def _resolve(self, path: str) -> Inode:
        return self.fs.resolve(path, cwd=self.cwd)

    def _args(self, line: str) -> list:
        return shlex.split(line)

    def onecmd(self, line: str) -> bool:
        try:
            return super().onecmd(line)
        except MinixError as e:
            self._print(f"错误: {e}")
            return False

    def emptyline(self) -> bool:
        return False

    def default(self, line: str) -> bool:
        self._print(f"未知命令: {line.split()[0]}, 输入 help 查看命令")
        return False

    def do_exit(self, arg: str) -> bool:
        """exit -- 退出"""
        return True

    do_quit = do_q = do_exit
    do_EOF = do_exit

    # ---- pwd / cd / ls ------------------------------------------------

    def do_pwd(self, arg: str) -> None:
        """pwd -- 显示当前目录"""
        self._print(self.cwd_path)

    def do_cd(self, arg: str) -> None:
        """cd [路径] -- 切换目录, 无参数回到根目录"""
        args = self._args(arg)
        path = args[0] if args else "/"
        inode = self._resolve(path)
        if not inode.is_dir:
            self._print(f"cd: 不是目录: {path}")
            return
        self.cwd = inode
        self.cwd_path = normalize_path(self.cwd_path, path)
        self._update_prompt()

    def _format_long(self, inode: Inode, name: str) -> str:
        if inode.is_device:
            major, minor = inode.devno
            size = f"{major:3d},{minor:4d}"
        else:
            size = f"{inode.size:8d}"
        return (f"{inode.mode_string()} {inode.nlinks:3d} "
                f"{inode.uid:4d} {inode.gid:4d} {size} "
                f"{inode.mtime_string()} {name}")

    def do_ls(self, arg: str) -> None:
        """ls [-l] [路径] -- 列目录; -l 显示详细信息(权限/链接数/属主/大小/时间)"""
        args = self._args(arg)
        long_fmt = "-l" in args
        paths = [a for a in args if not a.startswith("-")] or ["."]
        multiple = len(paths) > 1
        for i, path in enumerate(paths):
            inode = self._resolve(path)
            if multiple:
                if i:
                    self._print()
                self._print(f"{path}:")
            if inode.is_dir:
                entries = sorted(self.fs.read_dir(inode), key=lambda e: e[1])
                if long_fmt:
                    for ino_num, name in entries:
                        child = self.fs.get_inode(ino_num)
                        self._print(self._format_long(child, name))
                else:
                    names = [n for _, n in entries if n not in (".", "..")]
                    self._print("  ".join(names))
            else:
                self._print(self._format_long(inode, path) if long_fmt else path)


    # ---- stat / inode --------------------------------------------------

    def _print_inode_info(self, inode: Inode, name: str = None) -> None:
        if name is not None:
            self._print(f"  文件: {name}")
        if inode.is_device:
            major, minor = inode.devno
            size_line = f"设备号: {major}, {minor} (raw {inode.zones[0]:#06x})"
        else:
            blocks = (inode.size + 1023) // 1024
            size_line = f"大小: {inode.size} 字节 ({blocks} 块)"
        self._print(f"  inode: {inode.num}    类型: {inode.type_name}")
        self._print(f"  {size_line}")
        self._print(f"  权限: {inode.mode_string()} ({inode.mode & 0o7777:04o})    "
                    f"硬链接: {inode.nlinks}")
        self._print(f"  属主: uid={inode.uid} gid={inode.gid}")
        self._print(f"  修改时间: {inode.mtime_string()}")

    def _print_fs_stats(self) -> None:
        sb = self.fs.sb
        st = self.fs.fs_stats()
        ipct = st["used_inodes"] / st["total_inodes"] * 100 if st["total_inodes"] else 0
        zpct = st["used_zones"] / st["total_zones"] * 100 if st["total_zones"] else 0
        self._print("文件系统统计:")
        self._print(f"  块大小:    1024 字节    magic: {sb.magic:#06x} "
                    f"(文件名上限 {sb.name_len} 字符)")
        self._print(f"  inode:     {st['used_inodes']} / {st['total_inodes']} "
                    f"已用 ({ipct:.1f}%)")
        self._print(f"  data zone: {st['used_zones']} / {st['total_zones']} "
                    f"已用 ({zpct:.1f}%), 起始 zone {sb.firstdatazone}")
        self._print(f"  容量:      共 {st['total_zones'] * 1024} 字节, "
                    f"已用 {st['used_zones'] * 1024} 字节, "
                    f"空闲 {(st['total_zones'] - st['used_zones']) * 1024} 字节")

    def do_stat(self, arg: str) -> None:
        """stat [路径]... -- 显示文件的 inode 元数据; 无参数时显示文件系统统计"""
        args = self._args(arg)
        if not args:
            self._print_fs_stats()
            return
        for i, path in enumerate(args):
            if i:
                self._print()
            self._print_inode_info(self._resolve(path), name=path)

    def do_inode(self, arg: str) -> None:
        """inode <编号> -- 按编号显示 inode 的原始信息"""
        args = self._args(arg)
        if len(args) != 1:
            self._print("用法: inode <编号>")
            return
        try:
            num = int(args[0], 0)
        except ValueError:
            self._print(f"inode: 无效编号: {args[0]}")
            return
        inode = self.fs.get_inode(num)
        allocated = self.fs.inode_allocated(num)
        self._print(f"inode {num} ({'已分配' if allocated else '未分配'})")
        self._print(f"  mode  = {inode.mode:#06x} ({inode.mode_string()}, "
                    f"{inode.type_name})")
        self._print(f"  uid   = {inode.uid}    gid = {inode.gid}    "
                    f"nlinks = {inode.nlinks}")
        self._print(f"  size  = {inode.size}")
        self._print(f"  mtime = {inode.mtime} ({inode.mtime_string()})")
        self._print(f"  zones = {list(inode.zones[:7])} "
                    f"间接={inode.zones[7]} 二级间接={inode.zones[8]}")


    # ---- file / dump / less --------------------------------------------

    AOUT_MAGIC = {0o407: "OMAGIC", 0o410: "NMAGIC", 0o413: "ZMAGIC",
                  0o314: "QMAGIC"}

    def _classify(self, inode: Inode) -> str:
        """file 命令的类型判定."""
        if not inode.is_regular:
            return inode.type_name
        if inode.size == 0:
            return "empty"
        head = self.fs.read_file(inode, 0, 1024)
        if len(head) >= 4:
            magic = int.from_bytes(head[:4], "little")
            if magic in self.AOUT_MAGIC:
                return f"a.out 可执行文件 ({self.AOUT_MAGIC[magic]})"
        if head.startswith(b"#!"):
            interp = head[2:].split(b"\n", 1)[0].strip().decode("latin-1")
            return f"脚本, 解释器 {interp}"
        if head.startswith(b"\x1f\x8b"):
            return "gzip 压缩数据"
        if head.startswith(b"\x1f\x9d"):
            return "compress 压缩数据"
        # 文本启发式: 无 NUL 且可打印字符占比高
        if b"\x00" not in head:
            printable = sum(1 for b in head if 32 <= b < 127 or b in (9, 10, 13))
            if printable / len(head) > 0.95:
                return "ASCII 文本"
        return "二进制数据"

    def do_file(self, arg: str) -> None:
        """file <路径>... -- 判断文件类型(目录/设备/a.out/脚本/文本/二进制)"""
        args = self._args(arg)
        if not args:
            self._print("用法: file <路径>...")
            return
        for path in args:
            self._print(f"{path}: {self._classify(self._resolve(path))}")

    def do_dump(self, arg: str) -> None:
        """dump <路径> [偏移 [长度]] -- 十六进制转储文件内容"""
        args = self._args(arg)
        if not 1 <= len(args) <= 3:
            self._print("用法: dump <路径> [偏移 [长度]]")
            return
        inode = self._resolve(args[0])
        try:
            offset = int(args[1], 0) if len(args) > 1 else 0
            length = int(args[2], 0) if len(args) > 2 else None
        except ValueError:
            self._print("dump: 偏移/长度必须是整数")
            return
        data = self.fs.read_file(inode, offset, length)
        for pos in range(0, len(data), 16):
            row = data[pos:pos + 16]
            hexpart = " ".join(
                f"{b:02x}" if i < len(row) else "  "
                for i, b in enumerate(row.ljust(16, b"\x00")))
            hexpart = hexpart[:23] + " " + hexpart[23:]  # 8 字节分组
            ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in row)
            self._print(f"{offset + pos:08x}  {hexpart}  |{ascii_part}|")
        self._print(f"{offset + len(data):08x}")

    def do_less(self, arg: str) -> None:
        """less <路径> -- 分页查看文本文件, 空格/回车翻页, q 退出"""
        args = self._args(arg)
        if len(args) != 1:
            self._print("用法: less <路径>")
            return
        inode = self._resolve(args[0])
        text = self.fs.read_file(inode).decode("latin-1")
        lines = text.splitlines()
        page = self.page_size
        pos = 0
        while pos < len(lines):
            for line in lines[pos:pos + page]:
                self._print(line)
            pos += page
            if pos >= len(lines):
                break
            try:
                key = self.input_fn(f"--更多-- ({min(pos, len(lines))}/{len(lines)} 行) ")
            except (EOFError, KeyboardInterrupt):
                self._print()
                break
            if key.strip().lower() == "q":
                break


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Minix v1 文件系统镜像浏览器")
    parser.add_argument("image", help="镜像文件路径(裸文件系统或带 MBR 的磁盘镜像)")
    parser.add_argument("--offset", type=int, default=None,
                        help="文件系统起始字节偏移(默认自动探测)")
    args = parser.parse_args(argv)

    try:
        fs = MinixFS.open(args.image, offset=args.offset)
    except (OSError, MinixError) as e:
        print(f"打开镜像失败: {e}", file=sys.stderr)
        return 1

    with fs:
        sb = fs.sb
        print(f"已加载 {args.image} (偏移 {fs.offset}): "
              f"{sb.ninodes} inodes, {sb.nzones} zones, "
              f"文件名上限 {sb.name_len} 字符")
        try:
            MinixShell(fs).cmdloop()
        except KeyboardInterrupt:
            print()
    return 0


if __name__ == "__main__":
    sys.exit(main())
