"""x86 只读反汇编器(Intel 语法).

只解码、绝不执行, 也绝不碰 CPU 状态: 给定一段内存与地址, 逐字节游走, 还原出
一条指令的 (长度, 文本, 原始字节)。解码结构严格镜像 cpu86.py 的 `_execute`/
`_execute_0f`/`_modrm` —— 覆盖的 opcode 集就是 cpu86 实际实现的那一套, 其余
(cpu86 本就 `_bad` 拒绝的)回退成 `.byte 0xNN`(长度 1)以便多条反汇编能重新对齐。

长度正确性是第一位的: 多条反汇编靠上一条的长度定位下一条地址, 长度错一条则后面
全错。故 disasm_one 的长度必须与 cpu86 执行同一条指令时 eip 前进的字节数一致
(有单测用执行器做长度对照)。

只依赖 cpu86 的寄存器名常量与内存对象, 不 import 内核/仿真器。
"""

from __future__ import annotations

from cpu86 import REG8_NAMES, REG32_NAMES

MASK32 = 0xFFFFFFFF

REG16_NAMES = ("ax", "cx", "dx", "bx", "sp", "bp", "si", "di")

ALU_NAMES = ("add", "or", "adc", "sbb", "and", "sub", "xor", "cmp")
# jcc/setcc 条件码低 4 位 -> 助记后缀(与 cpu86._cond 对齐)
CC_NAMES = ("o", "no", "b", "ae", "e", "ne", "be", "a",
            "s", "ns", "p", "np", "l", "ge", "le", "g")
GRP3_NAMES = ("test", "test", "not", "neg", "mul", "imul", "div", "idiv")
GRP5_NAMES = ("inc", "dec", "call", "callf", "jmp", "jmpf", "push", "?")
SHIFT_NAMES = ("rol", "ror", "rcl", "rcr", "shl", "shr", "sal", "sar")
STRING_NAMES = {0xA4: "movs", 0xA5: "movs", 0xA6: "cmps", 0xA7: "cmps",
                0xAA: "stos", 0xAB: "stos", 0xAC: "lods", 0xAD: "lods",
                0xAE: "scas", 0xAF: "scas"}
SIZEWORD = {1: "byte", 2: "word", 4: "dword"}
SEG_PREFIX = (0x2E, 0x36, 0x3E, 0x26, 0x64, 0x65)


class _Bad(Exception):
    """解码遇到未知 opcode 或读越界, 回退单字节."""


class _Reader:
    """按字节前进的只读游标; 读越界抛 _Bad(不改任何状态)."""

    def __init__(self, mem, addr: int):
        self.mem = mem
        self.start = addr & MASK32
        self.pos = addr & MASK32

    def u8(self) -> int:
        try:
            v = self.mem.read_u8(self.pos)
        except Exception:
            raise _Bad()
        self.pos = (self.pos + 1) & MASK32
        return v

    def u16(self) -> int:
        lo = self.u8()
        return lo | (self.u8() << 8)

    def u32(self) -> int:
        b0 = self.u8()
        b1 = self.u8()
        b2 = self.u8()
        return b0 | (b1 << 8) | (b2 << 16) | (self.u8() << 24)

    def s8(self) -> int:
        v = self.u8()
        return v - 256 if v >= 128 else v

    def s32(self) -> int:
        v = self.u32()
        return v - 0x100000000 if v >= 0x80000000 else v

    @property
    def length(self) -> int:
        return (self.pos - self.start) & MASK32


def _reg(idx: int, size: int) -> str:
    if size == 1:
        return REG8_NAMES[idx]
    if size == 2:
        return REG16_NAMES[idx]
    return REG32_NAMES[idx]


def _uhex(v: int) -> str:
    return f"0x{v & MASK32:x}"


def _disp(d: int) -> str:
    return f"+0x{d:x}" if d >= 0 else f"-0x{-d:x}"


def _ptr(size: int, opstr: str) -> str:
    """内存操作数在尺寸不由寄存器隐含时, 前缀 dword/word/byte ptr."""
    if opstr.startswith("["):
        return f"{SIZEWORD.get(size, 'dword')} {opstr}"
    return opstr


def _modrm(r: _Reader, size: int):
    """解码 ModRM(+可能的 SIB/disp), 返回 (mod, reg, rm, opstr).

    mod==3 时 opstr 是寄存器名; 否则是形如 `[eax+ecx*4+0x10]` 的内存串
    (不含尺寸前缀, 由调用方按需用 _ptr 补)。
    """
    b = r.u8()
    mod = b >> 6
    reg = (b >> 3) & 7
    rm = b & 7
    if mod == 3:
        return mod, reg, rm, _reg(rm, size)

    base = None
    index = None
    scale = 1
    disp = 0
    if rm == 4:                       # SIB
        sib = r.u8()
        scale = 1 << (sib >> 6)
        idx = (sib >> 3) & 7
        bse = sib & 7
        if idx != 4:                  # idx==4 表示无索引
            index = idx
        if bse == 5 and mod == 0:
            disp = r.s32()
        else:
            base = bse
    elif rm == 5 and mod == 0:        # disp32 绝对寻址
        disp = r.s32()
    else:
        base = rm

    if mod == 1:
        disp = r.s8()
    elif mod == 2:
        disp = r.s32()

    parts = []
    if base is not None:
        parts.append(REG32_NAMES[base])
    if index is not None:
        parts.append(f"{REG32_NAMES[index]}*{scale}" if scale > 1
                     else REG32_NAMES[index])
    if parts:
        s = "+".join(parts)
        if disp:
            s += _disp(disp)
        return mod, reg, rm, f"[{s}]"
    return mod, reg, rm, f"[{_uhex(disp)}]"


def disasm_one(mem, addr: int):
    """反汇编 addr 处的一条指令, 返回 (length, text, raw_bytes).

    未知 opcode 或读越界回退 `.byte 0xNN`(长度 1), 绝不抛异常。
    """
    r = _Reader(mem, addr)
    try:
        text = _decode(r)
        length = r.length or 1
    except _Bad:
        b = _safe_u8(mem, addr)
        if b is None:
            return 1, "(bad)", b""
        return 1, f".byte 0x{b:02x}", bytes([b])
    return length, text, _safe_bytes(mem, addr, length)


def disasm_range(mem, addr: int, count: int):
    """连续反汇编 count 条, 返回 [(addr, raw_bytes, text), ...]."""
    out = []
    a = addr & MASK32
    for _ in range(count):
        length, text, raw = disasm_one(mem, a)
        out.append((a, raw, text))
        a = (a + length) & MASK32
    return out


def _safe_u8(mem, addr: int):
    try:
        return mem.read_u8(addr & MASK32)
    except Exception:
        return None


def _safe_bytes(mem, addr: int, n: int) -> bytes:
    out = bytearray()
    for i in range(n):
        try:
            out.append(mem.read_u8((addr + i) & MASK32))
        except Exception:
            break
    return bytes(out)


def _decode(r: _Reader) -> str:
    """消费前缀后分派. 镜像 cpu86.CPU.step 的前缀循环。"""
    opsize = 4
    rep = None
    while True:
        op = r.u8()
        if op == 0x66:
            opsize = 2
            continue
        if op in SEG_PREFIX or op == 0xF0:   # 段/lock 前缀: 文本里忽略
            continue
        if op in (0xF2, 0xF3):
            rep = op
            continue
        break
    if rep is not None and 0xA4 <= op <= 0xAF and op not in (0xA8, 0xA9):
        return _string(op, opsize, rep)
    if rep == 0xF3 and op == 0x90:
        return "pause"
    return _one(r, op, opsize)


def _string(op: int, opsize: int, rep) -> str:
    size = 1 if op in (0xA4, 0xA6, 0xAA, 0xAC, 0xAE) else opsize
    suffix = {1: "b", 2: "w", 4: "d"}[size]
    name = STRING_NAMES[op] + suffix
    if rep == 0xF3:
        name = ("repe " if op in (0xA6, 0xA7, 0xAE, 0xAF) else "rep ") + name
    elif rep == 0xF2:
        name = "repne " + name
    return name


def _one(r: _Reader, op: int, opsize: int) -> str:
    # ---- ALU 00-3F ----
    if op < 0x40 and (op & 7) < 6:
        name = ALU_NAMES[op >> 3]
        form = op & 7
        if form == 0:
            _, reg, _, rm = _modrm(r, 1)
            return f"{name} {_ptr(1, rm)}, {REG8_NAMES[reg]}"
        if form == 1:
            _, reg, _, rm = _modrm(r, opsize)
            return f"{name} {_ptr(opsize, rm)}, {_reg(reg, opsize)}"
        if form == 2:
            _, reg, _, rm = _modrm(r, 1)
            return f"{name} {REG8_NAMES[reg]}, {_ptr(1, rm)}"
        if form == 3:
            _, reg, _, rm = _modrm(r, opsize)
            return f"{name} {_reg(reg, opsize)}, {_ptr(opsize, rm)}"
        if form == 4:
            return f"{name} al, {_uhex(r.u8())}"
        imm = r.u16() if opsize == 2 else r.u32()
        return f"{name} {_reg(0, opsize)}, {_uhex(imm)}"

    # ---- 40-4F inc/dec reg ----
    if 0x40 <= op <= 0x4F:
        name = "inc" if op < 0x48 else "dec"
        return f"{name} {_reg(op & 7, opsize)}"

    # ---- 50-5F push/pop reg ----
    if 0x50 <= op <= 0x57:
        return f"push {_reg(op & 7, opsize)}"
    if 0x58 <= op <= 0x5F:
        return f"pop {_reg(op & 7, opsize)}"

    # ---- 68/6A push imm ----
    if op == 0x68:
        imm = r.u16() if opsize == 2 else r.u32()
        return f"push {_uhex(imm)}"
    if op == 0x6A:
        return f"push {_uhex(r.s8() & MASK32)}"

    # ---- 69/6B imul r, r/m, imm ----
    if op in (0x69, 0x6B):
        _, reg, _, rm = _modrm(r, opsize)
        imm = (r.u16() if opsize == 2 else r.u32()) if op == 0x69 else (r.s8() & MASK32)
        return f"imul {_reg(reg, opsize)}, {_ptr(opsize, rm)}, {_uhex(imm)}"

    # ---- 70-7F jcc rel8 ----
    if 0x70 <= op <= 0x7F:
        rel = r.s8()
        return f"j{CC_NAMES[op & 0xF]} {_uhex((r.pos + rel) & MASK32)}"

    # ---- 80/81/83 ALU r/m, imm ----
    if op in (0x80, 0x81, 0x83):
        size = 1 if op == 0x80 else opsize
        _, reg, _, rm = _modrm(r, size)
        if op == 0x80:
            imm = r.u8()
        elif op == 0x81:
            imm = r.u16() if size == 2 else r.u32()
        else:
            imm = r.s8() & MASK32
        return f"{ALU_NAMES[reg]} {_ptr(size, rm)}, {_uhex(imm)}"

    # ---- 84/85 test ; 86/87 xchg ----
    if op in (0x84, 0x85):
        size = 1 if op == 0x84 else opsize
        _, reg, _, rm = _modrm(r, size)
        return f"test {_ptr(size, rm)}, {_reg(reg, size)}"
    if op in (0x86, 0x87):
        size = 1 if op == 0x86 else opsize
        _, reg, _, rm = _modrm(r, size)
        return f"xchg {_ptr(size, rm)}, {_reg(reg, size)}"

    # ---- 88-8B mov ----
    if op == 0x88:
        _, reg, _, rm = _modrm(r, 1)
        return f"mov {_ptr(1, rm)}, {REG8_NAMES[reg]}"
    if op == 0x89:
        _, reg, _, rm = _modrm(r, opsize)
        return f"mov {_ptr(opsize, rm)}, {_reg(reg, opsize)}"
    if op == 0x8A:
        _, reg, _, rm = _modrm(r, 1)
        return f"mov {REG8_NAMES[reg]}, {_ptr(1, rm)}"
    if op == 0x8B:
        _, reg, _, rm = _modrm(r, opsize)
        return f"mov {_reg(reg, opsize)}, {_ptr(opsize, rm)}"

    # ---- 8D lea ----
    if op == 0x8D:
        _, reg, _, rm = _modrm(r, opsize)
        return f"lea {_reg(reg, opsize)}, {rm}"

    # ---- 8F pop r/m ----
    if op == 0x8F:
        _, _, _, rm = _modrm(r, opsize)
        return f"pop {_ptr(opsize, rm)}"

    # ---- 90 nop / 91-97 xchg eax,r ----
    if op == 0x90:
        return "nop"
    if 0x91 <= op <= 0x97:
        return f"xchg {_reg(0, opsize)}, {_reg(op & 7, opsize)}"

    # ---- 98/99 符号扩展 ----
    if op == 0x98:
        return "cbw" if opsize == 2 else "cwde"
    if op == 0x99:
        return "cwd" if opsize == 2 else "cdq"

    # ---- 9C/9D pushf/popf, 9E/9F sahf/lahf ----
    if op == 0x9C:
        return "pushf" if opsize == 2 else "pushfd"
    if op == 0x9D:
        return "popf" if opsize == 2 else "popfd"
    if op == 0x9E:
        return "sahf"
    if op == 0x9F:
        return "lahf"

    # ---- A0-A3 mov eax <-> moffs ----
    if op == 0xA0:
        return f"mov al, [{_uhex(r.u32())}]"
    if op == 0xA1:
        return f"mov {_reg(0, opsize)}, [{_uhex(r.u32())}]"
    if op == 0xA2:
        return f"mov [{_uhex(r.u32())}], al"
    if op == 0xA3:
        return f"mov [{_uhex(r.u32())}], {_reg(0, opsize)}"

    # ---- A4-AF 串(无 rep) ----
    if 0xA4 <= op <= 0xAF and op not in (0xA8, 0xA9):
        return _string(op, opsize, None)

    # ---- A8/A9 test al/eax, imm ----
    if op == 0xA8:
        return f"test al, {_uhex(r.u8())}"
    if op == 0xA9:
        imm = r.u16() if opsize == 2 else r.u32()
        return f"test {_reg(0, opsize)}, {_uhex(imm)}"

    # ---- B0-BF mov reg, imm ----
    if 0xB0 <= op <= 0xB7:
        return f"mov {REG8_NAMES[op & 7]}, {_uhex(r.u8())}"
    if 0xB8 <= op <= 0xBF:
        imm = r.u16() if opsize == 2 else r.u32()
        return f"mov {_reg(op & 7, opsize)}, {_uhex(imm)}"

    # ---- C0/C1/D0-D3 移位组 ----
    if op in (0xC0, 0xC1, 0xD0, 0xD1, 0xD2, 0xD3):
        size = 1 if op in (0xC0, 0xD0, 0xD2) else opsize
        _, reg, _, rm = _modrm(r, size)
        if op in (0xC0, 0xC1):
            cnt = _uhex(r.u8())
        elif op in (0xD0, 0xD1):
            cnt = "1"
        else:
            cnt = "cl"
        return f"{SHIFT_NAMES[reg]} {_ptr(size, rm)}, {cnt}"

    # ---- C2/C3 ret ----
    if op == 0xC3:
        return "ret"
    if op == 0xC2:
        return f"ret {_uhex(r.u16())}"

    # ---- C6/C7 mov r/m, imm ----
    if op == 0xC6:
        _, _, _, rm = _modrm(r, 1)
        return f"mov {_ptr(1, rm)}, {_uhex(r.u8())}"
    if op == 0xC7:
        _, _, _, rm = _modrm(r, opsize)
        imm = r.u16() if opsize == 2 else r.u32()
        return f"mov {_ptr(opsize, rm)}, {_uhex(imm)}"

    # ---- C8/C9 enter/leave ----
    if op == 0xC8:
        alloc = r.u16()
        level = r.u8()
        return f"enter {_uhex(alloc)}, {_uhex(level)}"
    if op == 0xC9:
        return "leave"

    # ---- CC/CD int ----
    if op == 0xCC:
        return "int3"
    if op == 0xCD:
        return f"int {_uhex(r.u8())}"

    # ---- D7 xlat ----
    if op == 0xD7:
        return "xlat"

    # ---- E0-E3 loop 族 ----
    if 0xE0 <= op <= 0xE3:
        name = ("loopne", "loope", "loop", "jecxz")[op - 0xE0]
        rel = r.s8()
        return f"{name} {_uhex((r.pos + rel) & MASK32)}"

    # ---- E8/E9/EB call/jmp ----
    if op == 0xE8:
        rel = r.s32()
        return f"call {_uhex((r.pos + rel) & MASK32)}"
    if op == 0xE9:
        rel = r.s32()
        return f"jmp {_uhex((r.pos + rel) & MASK32)}"
    if op == 0xEB:
        rel = r.s8()
        return f"jmp {_uhex((r.pos + rel) & MASK32)}"

    # ---- F4 hlt ----
    if op == 0xF4:
        return "hlt"

    # ---- F6/F7 组 ----
    if op in (0xF6, 0xF7):
        size = 1 if op == 0xF6 else opsize
        _, reg, _, rm = _modrm(r, size)
        name = GRP3_NAMES[reg]
        if reg in (0, 1):                       # test r/m, imm
            imm = r.u8() if size == 1 else (r.u16() if size == 2 else r.u32())
            return f"test {_ptr(size, rm)}, {_uhex(imm)}"
        return f"{name} {_ptr(size, rm)}"

    # ---- F8-FD 标志位 ----
    if op == 0xF8:
        return "clc"
    if op == 0xF9:
        return "stc"
    if op == 0xFC:
        return "cld"
    if op == 0xFD:
        return "std"

    # ---- FE/FF 组 ----
    if op in (0xFE, 0xFF):
        size = 1 if op == 0xFE else opsize
        _, reg, _, rm = _modrm(r, size)
        return f"{GRP5_NAMES[reg]} {_ptr(size, rm)}"

    # ---- 0F 两字节 ----
    if op == 0x0F:
        return _one_0f(r, r.u8(), opsize)

    raise _Bad()


def _one_0f(r: _Reader, op: int, opsize: int) -> str:
    if 0x80 <= op <= 0x8F:                       # jcc rel32
        rel = r.s32()
        return f"j{CC_NAMES[op & 0xF]} {_uhex((r.pos + rel) & MASK32)}"
    if 0x90 <= op <= 0x9F:                       # setcc r/m8
        _, _, _, rm = _modrm(r, 1)
        return f"set{CC_NAMES[op & 0xF]} {_ptr(1, rm)}"
    if op == 0xAF:                               # imul r, r/m
        _, reg, _, rm = _modrm(r, opsize)
        return f"imul {_reg(reg, opsize)}, {_ptr(opsize, rm)}"
    if op in (0xA3, 0xAB, 0xB3, 0xBB):           # bt/bts/btr/btc r/m, reg
        name = {0xA3: "bt", 0xAB: "bts", 0xB3: "btr", 0xBB: "btc"}[op]
        _, reg, _, rm = _modrm(r, opsize)
        return f"{name} {_ptr(opsize, rm)}, {_reg(reg, opsize)}"
    if op == 0xBA:                               # bt 族 r/m, imm8(reg=4..7)
        _, reg, _, rm = _modrm(r, opsize)
        name = {4: "bt", 5: "bts", 6: "btr", 7: "btc"}.get(reg)
        if name is None:
            raise _Bad()
        return f"{name} {_ptr(opsize, rm)}, {_uhex(r.u8())}"
    if op in (0xBC, 0xBD):                       # bsf/bsr reg, r/m
        _, reg, _, rm = _modrm(r, opsize)
        return f"{'bsf' if op == 0xBC else 'bsr'} {_reg(reg, opsize)}, {_ptr(opsize, rm)}"
    if op in (0xA4, 0xA5, 0xAC, 0xAD):           # shld/shrd r/m, reg, imm8|cl
        name = "shld" if op in (0xA4, 0xA5) else "shrd"
        _, reg, _, rm = _modrm(r, opsize)
        cnt = _uhex(r.u8()) if op in (0xA4, 0xAC) else "cl"
        return f"{name} {_ptr(opsize, rm)}, {_reg(reg, opsize)}, {cnt}"
    if op in (0xB6, 0xB7, 0xBE, 0xBF):           # movzx/movsx reg, r/m(src)
        name = "movzx" if op in (0xB6, 0xB7) else "movsx"
        src = 1 if op in (0xB6, 0xBE) else 2
        _, reg, _, rm = _modrm(r, src)
        return f"{name} {_reg(reg, opsize)}, {_ptr(src, rm)}"
    raise _Bad()
