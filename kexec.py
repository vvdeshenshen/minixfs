"""a.out ZMAGIC 加载器与初始栈构造.

格式与布局全部照镜像里的内核源码 fs/exec.c:
- 头 32 字节 8 个小端 u32: magic/text/data/bss/syms/entry/trsize/drsize
- ZMAGIC(0o413) 的代码从文件偏移 1024(N_TXTOFF == BLOCK_SIZE)开始
- text 装到虚址 0, 紧跟 data, 再 bss 清零, brk = text+data+bss
- 内核还校验 trsize==drsize==0 且 text+data+bss <= 0x3000000
- 内核处理 shebang(sh_bang/restart_interp), 所以 #! 脚本也要支持
"""

from __future__ import annotations

import struct
from typing import List, Optional, Tuple

from kvfs import E2BIG, EACCES, ENOEXEC, OverlayFS, VInode
from x86mem import ARG_AREA, AddressSpace, TASK_SIZE

ZMAGIC = 0o413            # 0x10b
OMAGIC = 0o407
NMAGIC = 0o410
QMAGIC = 0o314
N_TXTOFF = 1024           # ZMAGIC 的代码起始文件偏移(= BLOCK_SIZE)
EXEC_HDR = 32
MAX_TOTAL = 0x3000000     # 内核: text+data+bss 上限 48MB

_HDR = struct.Struct("<8I")


class ExecError(Exception):
    """加载可执行文件失败, 带 errno."""

    def __init__(self, errno: int, msg: str = ""):
        super().__init__(msg or f"errno={errno}")
        self.errno = errno


class AoutHeader:
    """a.out 头."""

    __slots__ = ("magic", "text", "data", "bss", "syms", "entry",
                 "trsize", "drsize")

    def __init__(self, raw: bytes):
        if len(raw) < EXEC_HDR:
            raise ExecError(ENOEXEC, "文件太短, 装不下 a.out 头")
        (self.magic, self.text, self.data, self.bss, self.syms,
         self.entry, self.trsize, self.drsize) = _HDR.unpack(raw[:EXEC_HDR])

    def validate(self, file_size: int) -> None:
        """照内核 do_execve 的校验."""
        if self.magic != ZMAGIC:
            raise ExecError(ENOEXEC, f"不是 ZMAGIC: magic={self.magic:#o}")
        if self.trsize or self.drsize:
            raise ExecError(ENOEXEC, "带重定位信息, 内核不接受")
        if self.text + self.data + self.bss > MAX_TOTAL:
            raise ExecError(ENOEXEC, "text+data+bss 超过 48MB")
        if file_size < self.text + self.data + self.syms + N_TXTOFF:
            raise ExecError(ENOEXEC, "文件长度与头部声明不符")

    def __repr__(self) -> str:
        return (f"<a.out magic={self.magic:#o} text={self.text} "
                f"data={self.data} bss={self.bss} entry={self.entry:#x}>")


def parse_shebang(head: bytes) -> Optional[Tuple[str, Optional[str]]]:
    """解析 #! 首行, 返回 (解释器, 可选的单个参数); 不是脚本则 None."""
    if not head.startswith(b"#!"):
        return None
    line = head[2:].split(b"\n", 1)[0]
    line = line.split(b"\x00", 1)[0].strip()
    if not line:
        return None
    text = line.decode("latin-1")
    parts = text.split(None, 1)
    interp = parts[0]
    arg = parts[1].strip() if len(parts) > 1 and parts[1].strip() else None
    return interp, arg


def load_aout(mem: AddressSpace, fs: OverlayFS, v: VInode) -> Tuple[int, int]:
    """把 ZMAGIC 程序装入地址空间, 返回 (entry, brk)."""
    if not v.is_regular:
        raise ExecError(EACCES, "不是普通文件")
    if not (v.mode & 0o111):
        raise ExecError(EACCES, "没有执行权限位")
    hdr = AoutHeader(fs.read(v, 0, EXEC_HDR))
    hdr.validate(v.size)
    body = fs.read(v, N_TXTOFF, hdr.text + hdr.data)
    if len(body) < hdr.text + hdr.data:
        body = body + bytes(hdr.text + hdr.data - len(body))
    mem.load_program(body[:hdr.text], body[hdr.text:], hdr.bss)
    return hdr.entry, mem.brk


def setup_stack(mem: AddressSpace, argv: List[bytes],
                envp: List[bytes]) -> int:
    """按内核 create_tables 的布局建初始栈, 返回 esp.

    栈顶 TASK_SIZE 向下: 先放 env 与 arg 的字符串区, 然后 4 字节对齐,
    再依次压 envp 指针数组(带 NULL)、argv 指针数组(带 NULL),
    最后压 envp、argv、argc 三个字。esp 指向 argc。
    这个布局已被 /bin/date 入口的 `mov eax,[esp+8]`(取 envp)佐证。
    """
    total = sum(len(a) + 1 for a in argv) + sum(len(e) + 1 for e in envp)
    if total > ARG_AREA:
        raise ExecError(E2BIG, f"参数区超过 {ARG_AREA} 字节")

    p = TASK_SIZE
    # 内核先拷 envp 再拷 argv(都是自顶向下), 我们照同样顺序算地址
    env_addrs = []
    for s in reversed(envp):
        p -= len(s) + 1
        env_addrs.append(p)
        mem.write(p, s + b"\x00")
    env_addrs.reverse()

    arg_addrs = []
    for s in reversed(argv):
        p -= len(s) + 1
        arg_addrs.append(p)
        mem.write(p, s + b"\x00")
    arg_addrs.reverse()

    sp = p & 0xFFFFFFFC
    sp -= 4 * (len(envp) + 1)
    envp_base = sp
    sp -= 4 * (len(argv) + 1)
    argv_base = sp
    sp -= 4
    mem.write_u32(sp, envp_base)
    sp -= 4
    mem.write_u32(sp, argv_base)
    sp -= 4
    mem.write_u32(sp, len(argv))

    for i, a in enumerate(arg_addrs):
        mem.write_u32(argv_base + 4 * i, a)
    mem.write_u32(argv_base + 4 * len(argv), 0)
    for i, e in enumerate(env_addrs):
        mem.write_u32(envp_base + 4 * i, e)
    mem.write_u32(envp_base + 4 * len(envp), 0)

    mem.start_stack = sp & 0xFFFFF000
    return sp


def resolve_exec(fs: OverlayFS, path: str, argv: List[bytes],
                 cwd=None, root=None, depth: int = 0) -> Tuple[VInode, List[bytes]]:
    """定位可执行文件, 处理 #! 脚本.

    返回 (最终要加载的 VInode, 调整后的 argv)。
    脚本的 argv 重组为 [interp, arg?, script_path, *argv[1:]]。
    """
    if depth > 4:
        raise ExecError(ENOEXEC, "解释器嵌套过深")
    v = fs.walk(path, cwd, root)
    if not v.is_regular:
        raise ExecError(EACCES, f"{path} 不是普通文件")
    head = fs.read(v, 0, 128)
    sb = parse_shebang(head)
    if sb is None:
        return v, argv
    interp, arg = sb
    new_argv = [interp.encode("latin-1")]
    if arg:
        new_argv.append(arg.encode("latin-1"))
    new_argv.append(path.encode("latin-1"))
    new_argv.extend(argv[1:])
    return resolve_exec(fs, interp, new_argv, cwd, root, depth + 1)
