"""i386 用户态指令解释器.

只解释 ring-3 用户代码: 平坦地址空间、不管段寄存器、不管分页与特权级。
遇到 `int N` 调用注入的 on_int 回调(内核层在那里实现系统调用),
遇到除零/非法指令/越界访存调用 on_fault。

寄存器用 list, 下标即 ModRM 的 reg 编码:
    0=EAX 1=ECX 2=EDX 3=EBX 4=ESP 5=EBP 6=ESI 7=EDI
EFLAGS 按朴素方式即时计算(正确性优先), 但标志计算已内联进各 handler。

执行模型: **解码与执行分离 + 解码缓存**。
- `CPU._decode(eip)` 把一条指令解成不可变元组
      e = (fn, length, size, reg, base, index, scale, disp, imm, mod)
  fn 是模块级函数 `fn(cpu, e)`, 直接执行; 其余字段是解码期就能确定的常量
  (寄存器号、位移、立即数、已算好的跳转目标等), 运行期不再取指、不再解 ModRM。
- 解码用 256 项表 `_DEC`(0F 两字节用 `_DEC0F`)分派, 没有 if 链。
- ModRM 族指令(ALU/mov/test/inc/dec/移位/movzx...)的 fn 由 `_generate()` 按
  (操作 × 尺寸 × 寻址形态) 从模板生成: mask/符号位是字面量, 标志计算内联,
  寄存器形态直接 `regs[i]`, `[base+disp]` 形态直接 `regs[b] + d`。
  设环境变量 CPU86_DUMP_GEN=1 可把生成的源码转储到 stderr。
- text 区内的 e 缓存在 `AddressSpace.icache[eip]`(按 eip 下标的 list), 命中时
  只需 `eip += length` 再调 fn; 写 text 会就地失效对应槽位(见 x86mem)。
- 关键约定: **fn 执行前 eip 已指向下一条指令**(无论命中还是刚解码), 所以
  `int 0x80` 阻塞回卷的 `eip -= 2`、反汇编长度对照(`eip - start`)、`_bad`
  报错取字节都成立; 转移指令则在 fn 里改写 eip。
"""

from __future__ import annotations

import os
import sys
from typing import Callable, Optional

from x86mem import AddressSpace, SegFault

MASK32 = 0xFFFFFFFF
SIGN32 = 0x80000000
M = MASK32

EAX, ECX, EDX, EBX, ESP, EBP, ESI, EDI = range(8)

# 8 位寄存器编码: 0-3 是 AL CL DL BL(低字节), 4-7 是 AH CH DH BH(次低字节)
REG8_NAMES = ("al", "cl", "dl", "bl", "ah", "ch", "dh", "bh")
REG32_NAMES = ("eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi")

# EFLAGS 位
CF = 0x0001
PF = 0x0004
AF = 0x0010
ZF = 0x0040
SF = 0x0080
TF = 0x0100
IF = 0x0200
DF = 0x0400
OF = 0x0800
EFLAGS_BASE = 0x0202          # 保留位 1 恒为 1, IF 置位(用户态中断使能)

# 奇偶标志查表: 低 8 位中 1 的个数为偶数则 PF=1
_PARITY = tuple(PF if bin(i).count("1") % 2 == 0 else 0 for i in range(256))


class CpuError(Exception):
    """非法或未实现的指令."""

    def __init__(self, message: str, eip: int, opcode_bytes: bytes):
        super().__init__(f"{message} @ eip={eip:#x} "
                         f"字节={opcode_bytes.hex(' ')}")
        self.message = message
        self.eip = eip
        self.opcode_bytes = opcode_bytes


class DivideError(Exception):
    """除零或除法溢出(#DE), 内核层应转为 SIGFPE."""


# 执行流跳到这个地址之上视为魔数返回(内核用它兜底信号返回)
MAGIC_EIP_BASE = 0xFFFF0000


class MagicJump(Exception):
    """执行流跳到魔数地址, 由内核层处理(信号返回)."""

    def __init__(self, eip: int):
        super().__init__(f"跳转到魔数地址 {eip:#x}")
        self.eip = eip


class _Halt(Exception):
    """hlt(或无 on_int 时的 int)已置 halted, 用异常跳出主循环, 免得每条指令查一次 halted."""


# ---- 性能剖析: 指令类别 -----------------------------------------------
# 类别用小整数, 供 Profiler 以 list 下标计数(比 dict 快)。类别边界与 _DEC
# 表实现的 opcode 集对应, 只用于统计, 粗粒度即可。
CAT_ALU, CAT_MOV, CAT_STACK, CAT_BRANCH, CAT_STRING, CAT_MULDIV, \
    CAT_FLAG, CAT_OTHER = range(8)

CAT_NAMES = ("ALU", "MOV", "栈", "分支", "串", "乘除", "标志", "其他")

# 访存类别(用于估算访存指令占比): 串与栈几乎必然访存, MOV 大多访存
_CAT_MEMORY = frozenset({CAT_MOV, CAT_STACK, CAT_STRING})


def _build_op_category() -> list:
    """构造 256 项单字节 opcode -> 类别表。"""
    t = [CAT_OTHER] * 256
    for op in range(0x40):                 # 00-3F ALU 族(每族前 6 个编码)
        if (op & 7) < 6:
            t[op] = CAT_ALU
    for op in range(0x40, 0x50):           # 40-4F inc/dec
        t[op] = CAT_ALU
    for op in range(0x50, 0x60):           # 50-5F push/pop reg
        t[op] = CAT_STACK
    t[0x68] = t[0x6A] = CAT_STACK          # push imm
    t[0x69] = t[0x6B] = CAT_MULDIV         # imul r,r/m,imm
    for op in range(0x70, 0x80):           # 70-7F jcc rel8
        t[op] = CAT_BRANCH
    t[0x80] = t[0x81] = t[0x83] = CAT_ALU  # ALU r/m,imm
    t[0x84] = t[0x85] = CAT_ALU            # test
    t[0x86] = t[0x87] = CAT_MOV            # xchg
    for op in range(0x88, 0x8C):           # 88-8B mov
        t[op] = CAT_MOV
    t[0x8D] = CAT_MOV                      # lea
    t[0x8F] = CAT_STACK                    # pop r/m
    for op in range(0x91, 0x98):           # 91-97 xchg eax,r
        t[op] = CAT_MOV
    t[0x98] = t[0x99] = CAT_MOV            # cbw/cwd(符号扩展 eax)
    t[0x9C] = t[0x9D] = CAT_STACK          # pushf/popf
    t[0x9E] = t[0x9F] = CAT_FLAG           # sahf/lahf
    for op in range(0xA0, 0xA4):           # A0-A3 mov moffs
        t[op] = CAT_MOV
    for op in range(0xA4, 0xB0):           # A4-AF 串
        t[op] = CAT_STRING
    t[0xA8] = t[0xA9] = CAT_ALU            # test al/eax,imm
    for op in range(0xB0, 0xC0):           # B0-BF mov imm
        t[op] = CAT_MOV
    t[0xC0] = t[0xC1] = CAT_ALU            # 移位 imm
    t[0xC2] = t[0xC3] = CAT_BRANCH         # ret
    t[0xC6] = t[0xC7] = CAT_MOV            # mov r/m,imm
    t[0xC8] = t[0xC9] = CAT_STACK          # enter/leave
    t[0xD0] = t[0xD1] = t[0xD2] = t[0xD3] = CAT_ALU  # 移位
    t[0xD7] = CAT_MOV                      # xlat
    for op in range(0xE0, 0xE4):           # E0-E3 loop/jecxz
        t[op] = CAT_BRANCH
    t[0xE8] = t[0xE9] = t[0xEB] = CAT_BRANCH  # call/jmp
    t[0xF6] = t[0xF7] = CAT_MULDIV         # mul/div 组(含 test/not/neg)
    t[0xF8] = t[0xF9] = t[0xFC] = t[0xFD] = CAT_FLAG  # clc/stc/cld/std
    # 0xCC/0xCD(int)、0xF4(hlt)、0xFE/0xFF(inc/dec/call/jmp/push 混合组)
    # 归 CAT_OTHER; 0F 两字节走 _OP0F_CATEGORY。
    return t


def _build_op0f_category() -> list:
    """构造 0F 两字节 opcode -> 类别表。"""
    t = [CAT_OTHER] * 256
    for op in range(0x80, 0x90):           # jcc rel32
        t[op] = CAT_BRANCH
    for op in range(0x90, 0xA0):           # setcc r/m8
        t[op] = CAT_MOV
    t[0xAF] = CAT_MULDIV                    # imul
    for op in (0xA3, 0xAB, 0xB3, 0xBB, 0xBA, 0xBC, 0xBD,
               0xA4, 0xA5, 0xAC, 0xAD):     # bt 族 / bsf/bsr / shld/shrd
        t[op] = CAT_ALU
    for op in (0xB6, 0xB7, 0xBE, 0xBF):     # movzx/movsx
        t[op] = CAT_MOV
    return t


_OP_CATEGORY = _build_op_category()
_OP0F_CATEGORY = _build_op0f_category()

# rep/串前缀字节: 计类别时从 _insn_start 跳过
_PREFIX_BYTES = frozenset({0x66, 0x67, 0xF0, 0xF2, 0xF3,
                           0x2E, 0x36, 0x3E, 0x26, 0x64, 0x65})


class Profiler:
    """CPU 性能剖析器: 按需开启, 逐指令采集指令混合、热点与串强度。

    只在 CPU._run_profiled(即 self.prof 非空)里被调用; 剖析关闭时主循环
    完全走原 run(), 一条额外分支都不多走。所有派生比率在展示时才算,
    不进热循环。
    """

    __slots__ = ("cat_counts", "hot", "rep_elems", "bucket_shift", "insns")

    def __init__(self, bucket_shift: int = 6):
        self.cat_counts = [0] * len(CAT_NAMES)  # 各类别指令数
        self.hot = {}                           # eip 桶 -> 指令数
        self.rep_elems = 0                       # rep/串搬运的元素总数
        self.bucket_shift = bucket_shift         # 热点地址桶大小 = 1<<shift
        self.insns = 0                           # 采样到的指令数(校验用)

    def record(self, insn_start: int, mem: AddressSpace) -> None:
        """记录一条指令: 读 opcode(跳前缀)定类别, 并累加 eip 热点桶。"""
        self.insns += 1
        eip = insn_start
        op = mem.read_u8(eip)
        while op in _PREFIX_BYTES:              # 跳过前缀取真正的 opcode
            eip += 1
            op = mem.read_u8(eip)
        if op == 0x0F:
            cat = _OP0F_CATEGORY[mem.read_u8(eip + 1)]
        else:
            cat = _OP_CATEGORY[op]
        self.cat_counts[cat] += 1
        bucket = insn_start >> self.bucket_shift
        self.hot[bucket] = self.hot.get(bucket, 0) + 1

    def reset(self) -> None:
        self.cat_counts = [0] * len(CAT_NAMES)
        self.hot = {}
        self.rep_elems = 0
        self.insns = 0


def _sx8(v: int) -> int:
    """8 位有符号扩展为 Python 整数."""
    return v - 256 if v >= 128 else v


def _sx16(v: int) -> int:
    return v - 0x10000 if v >= 0x8000 else v


def _sx32(v: int) -> int:
    return v - 0x100000000 if v >= SIGN32 else v


# 按操作数尺寸(字节数)查 mask / 符号位: 元组下标比算式或方法调用便宜一个量级
_MASK = (0, 0xFF, 0xFFFF, 0, 0xFFFFFFFF)
_SIGN = (0, 0x80, 0x8000, 0, 0x80000000)

# 前缀字节集合: 0x66 操作数尺寸, 段前缀, lock, rep/repne
_PREFIXES = frozenset({0x66, 0x2E, 0x36, 0x3E, 0x26, 0x64, 0x65,
                       0xF0, 0xF2, 0xF3})


def _reg_property(idx: int) -> property:
    """按名字访问 32 位寄存器(cpu.eax 等)的 property。

    早先用 __getattr__/__setattr__ 钩子实现, 代价是热循环里每次 self.eip=/
    self.flags= 赋值都要先过一遍 Python 级的 `name in REG32_NAMES` 判断,
    实测占总耗时约 19%; property 只在真正按名字访问寄存器时才有开销。
    """
    def getter(self):
        return self.regs[idx]

    def setter(self, val):
        self.regs[idx] = val & MASK32
    return property(getter, setter)


# ---------------------------------------------------------------------------
# 已解码指令元组 e 的字段下标(见模块 docstring)
#   e[0] fn      handler(cpu, e)
#   e[1] length  整条指令字节数(含前缀)
#   e[2] size    操作数尺寸 1/2/4
#   e[3] reg     ModRM.reg / opcode 内编码的寄存器 / 条件码 / 子操作码
#   e[4] base    寄存器形态: rm 寄存器号; 内存形态: 基址寄存器号或 None
#   e[5] index   SIB 索引寄存器号或 None
#   e[6] scale   0..3
#   e[7] disp    位移(内存绝对寻址形态已 & MASK32, 其余为有符号整数)
#   e[8] imm     立即数 / 绝对跳转目标 / rep 前缀 / 其它常量
#   e[9] mod     ModRM.mod(3 = 寄存器形态; 无 ModRM 的指令填 3)
# 寻址形态 form: 0 = 寄存器, 1 = [disp32] 绝对, 2 = [base+disp], 3 = 含索引的通用 SIB
# ---------------------------------------------------------------------------


def _ea_of(regs: list, e: tuple) -> Optional[int]:
    """任意形态的有效地址; 寄存器形态返回 None(供复用旧式 _read_rm/_write_rm 的胖 handler)."""
    if e[9] == 3:
        return None
    a = e[7]
    b = e[4]
    if b is not None:
        a += regs[b]
    i = e[5]
    if i is not None:
        a += regs[i] << e[6]
    return a & M


# ---------------------------------------------------------------------------
# 模板代码生成: ModRM 族指令的专用 handler
# ---------------------------------------------------------------------------

def _rd_reg(size: int, r: str) -> str:
    """读寄存器 r(变量名)的表达式."""
    if size == 4:
        return f"regs[{r}]"
    if size == 2:
        return f"regs[{r}] & 0xFFFF"
    return f"((regs[{r}] & 0xFF) if {r} < 4 else ((regs[{r} - 4] >> 8) & 0xFF))"


def _wr_reg(size: int, r: str, v: str, masked: bool = False) -> list:
    """写寄存器 r 的语句列表; masked 表示 v 已在尺寸范围内."""
    if size == 4:
        return [f"regs[{r}] = {v}" if masked else f"regs[{r}] = ({v}) & M"]
    if size == 2:
        return [f"regs[{r}] = (regs[{r}] & 0xFFFF0000) | (({v}) & 0xFFFF)"]
    return [f"if {r} < 4:",
            f"    regs[{r}] = (regs[{r}] & 0xFFFFFF00) | (({v}) & 0xFF)",
            "else:",
            f"    regs[{r} - 4] = (regs[{r} - 4] & 0xFFFF00FF) | ((({v}) & 0xFF) << 8)"]


_RD_MEM = {4: "mem.read_u32(addr)", 2: "mem.read_u16(addr)", 1: "mem.read_u8(addr)"}
_WR_MEM = {4: "mem.write_u32(addr, {v})", 2: "mem.write_u16(addr, {v})",
           1: "mem.write_u8(addr, {v})"}
_EA_EXPR = {1: "e[7]",
            2: "(regs[e[4]] + e[7]) & M",
            3: "(e[7] + (regs[e[5]] << e[6]) + (regs[e[4]] if e[4] is not None else 0)) & M"}


def _setup(form: int) -> list:
    """r/m 操作数的准备语句: 寄存器形态取寄存器号, 内存形态算有效地址."""
    if form == 0:
        return ["d = e[4]"]
    return ["mem = cpu.mem", f"addr = {_EA_EXPR[form]}"]


def _rm_rd(form: int, size: int) -> str:
    return _rd_reg(size, "d") if form == 0 else _RD_MEM[size]


def _rm_wr(form: int, size: int, v: str, masked: bool = False) -> list:
    if form == 0:
        return _wr_reg(size, "d", v, masked)
    return [_WR_MEM[size].format(v=v)]


# 标志计算片段: 用 MASK/SIGN/BITS 占位, 生成时替换成字面量
_F_LOGIC = ["f = EFLAGS_BASE | (cpu.flags & DF)",
            "if res == 0: f |= ZF",
            "if res & SIGN: f |= SF",
            "cpu.flags = f | _PARITY[res & 0xFF]"]


def _f_add(c: str) -> list:
    return ["t = res & MASK",
            "f = EFLAGS_BASE | (cpu.flags & DF)",
            "if res > MASK: f |= CF",
            "if t == 0: f |= ZF",
            "if t & SIGN: f |= SF",
            "if (~(a ^ b)) & (a ^ t) & SIGN: f |= OF",
            f"if (a & 0xF) + (b & 0xF){c} > 0xF: f |= AF",
            "cpu.flags = f | _PARITY[t & 0xFF]",
            "res = t"]


def _f_sub(c: str) -> list:
    return ["t = res & MASK",
            "f = EFLAGS_BASE | (cpu.flags & DF)",
            "if res < 0: f |= CF",
            "if t == 0: f |= ZF",
            "if t & SIGN: f |= SF",
            "if (a ^ b) & (a ^ t) & SIGN: f |= OF",
            f"if (a & 0xF) - (b & 0xF){c} < 0: f |= AF",
            "cpu.flags = f | _PARITY[t & 0xFF]",
            "res = t"]


def _alu_body(op: int) -> list:
    """op: 0=add 1=or 2=adc 3=sbb 4=and 5=sub 6=xor 7=cmp; 输入 a, b, 输出已截断的 res."""
    if op == 0:
        return ["res = a + b"] + _f_add("")
    if op == 2:
        return ["c = cpu.flags & CF", "res = a + b + c"] + _f_add(" + c")
    if op == 5 or op == 7:
        return ["res = a - b"] + _f_sub("")
    if op == 3:
        return ["c = cpu.flags & CF", "res = a - b - c"] + _f_sub(" - c")
    sym = {1: "|", 4: "&", 6: "^"}[op]
    return [f"res = a {sym} b"] + _F_LOGIC


_INC_BODY = ["res = (a + 1) & MASK",
             "f = EFLAGS_BASE | (cpu.flags & (DF | CF))",     # inc/dec 不改 CF
             "if res == 0: f |= ZF",
             "if res & SIGN: f |= SF",
             "if (~(a ^ 1)) & (a ^ res) & SIGN: f |= OF",
             "if (a & 0xF) + 1 > 0xF: f |= AF",
             "cpu.flags = f | _PARITY[res & 0xFF]"]
_DEC_BODY = ["res = (a - 1) & MASK",
             "f = EFLAGS_BASE | (cpu.flags & (DF | CF))",
             "if res == 0: f |= ZF",
             "if res & SIGN: f |= SF",
             "if (a ^ 1) & (a ^ res) & SIGN: f |= OF",
             "if (a & 0xF) - 1 < 0: f |= AF",
             "cpu.flags = f | _PARITY[res & 0xFF]"]


def _shift_body(kind: int) -> list:
    """kind: 0 rol 1 ror 4/6 shl 5 shr 7 sar; 输入 a, cnt(1..31), 输出 res, cf, of."""
    if kind == 4 or kind == 6:
        return ["res = a << cnt",
                "cf = (res >> BITS) & 1",
                "res &= MASK",
                "of = ((res & SIGN) != 0) != bool(cf)"]
    if kind == 5:
        return ["cf = (a >> (cnt - 1)) & 1 if cnt <= BITS else 0",
                "res = (a >> cnt) & MASK",
                "of = bool(a & SIGN) if cnt == 1 else False"]
    if kind == 7:
        return ["sv = a - (MASK + 1) if a & SIGN else a",
                "cf = (sv >> (cnt - 1)) & 1",
                "res = (sv >> cnt) & MASK",
                "of = False"]
    if kind == 0:
        return ["c = cnt % BITS",
                "res = ((a << c) | (a >> (BITS - c))) & MASK if c else a",
                "cf = res & 1",
                "of = ((res & SIGN) != 0) != bool(cf)"]
    return ["c = cnt % BITS",                                   # ror
            "res = ((a >> c) | (a << (BITS - c))) & MASK if c else a",
            "cf = 1 if res & SIGN else 0",
            "of = bool(res & SIGN) != bool(res & (SIGN >> 1))"]


def _shift_flags(kind: int) -> list:
    lines = ["f = EFLAGS_BASE | (cpu.flags & DF)", "if cf: f |= CF"]
    if kind == 0 or kind == 1:                     # 循环移位只改 CF/OF
        return lines + ["if of: f |= OF",
                        "cpu.flags = f | (cpu.flags & (ZF | SF | PF | AF))"]
    return lines + ["if res == 0: f |= ZF",
                    "if res & SIGN: f |= SF",
                    "if of and cnt == 1: f |= OF",
                    "cpu.flags = f | _PARITY[res & 0xFF]"]


# 条件码 0..F 对应的判断表达式(f 为当前 EFLAGS); SF 在第 7 位, OF 在第 11 位
_SF_NE_OF = "(((f >> 7) ^ (f >> 11)) & 1)"
_COND_EXPR = (
    "f & OF", "not (f & OF)",                              # o / no
    "f & CF", "not (f & CF)",                              # b / ae
    "f & ZF", "not (f & ZF)",                              # e / ne
    "f & (CF | ZF)", "not (f & (CF | ZF))",                # be / a
    "f & SF", "not (f & SF)",                              # s / ns
    "f & PF", "not (f & PF)",                              # p / np
    _SF_NE_OF, f"not {_SF_NE_OF}",                         # l / ge
    f"(f & ZF) or {_SF_NE_OF}",                            # le
    f"not (f & ZF) and not {_SF_NE_OF}",                   # g
)
_COND_FN = tuple(eval("lambda f: " + expr, {"CF": CF, "ZF": ZF, "SF": SF, "OF": OF, "PF": PF})
                 for expr in _COND_EXPR)

_SHIFT_KINDS = (0, 1, 4, 5, 6, 7)

_GEN_NS = {"M": M, "EFLAGS_BASE": EFLAGS_BASE, "CF": CF, "PF": PF, "AF": AF,
           "ZF": ZF, "SF": SF, "DF": DF, "OF": OF, "_PARITY": _PARITY}
_R = ["regs = cpu.regs"]


def _emit(kind: str, args: tuple, form: int) -> tuple:
    """返回 (size, 语句列表): kind 族、参数 args、寻址形态 form 的 handler 体.

    size 决定 MASK/SIGN/BITS 占位符替换成哪套字面量。
    """
    S = _setup(form)
    if kind == "jcc":
        (cc,) = args
        return 4, ["f = cpu.flags", f"if {_COND_EXPR[cc]}: cpu.eip = e[8]"]
    if kind == "lea":
        (size,) = args
        return size, _R + _wr_reg(size, "e[3]", _EA_EXPR[form], size == 4)
    if kind in ("call_rm", "jmp_rm", "push_rm"):
        rd = _rm_rd(form, 4)
        if kind == "call_rm":
            return 4, _R + S + [f"target = {rd}", "sp = (regs[4] - 4) & M",
                                "cpu.mem.write_u32(sp, cpu.eip)", "regs[4] = sp",
                                "cpu.eip = target"]
        if kind == "jmp_rm":
            return 4, _R + S + [f"cpu.eip = {rd}"]
        return 4, _R + S + [f"v = {rd}", "sp = (regs[4] - 4) & M",
                            "cpu.mem.write_u32(sp, v)", "regs[4] = sp"]
    if kind == "setcc":
        (cc,) = args
        return 1, _R + S + ["f = cpu.flags"] + _rm_wr(form, 1, f"1 if {_COND_EXPR[cc]} else 0", True)
    if kind == "movx":
        sx, size, dst = args
        lines = _R + S + [f"v = {_rm_rd(form, size)}"]
        if sx:
            lines.append("if v & SIGN: v -= MASK + 1")
        return size, lines + _wr_reg(dst, "e[3]", "v")
    if kind == "shift":
        skind, size, src = args
        cnt = "cnt = e[8]" if src == 0 else "cnt = regs[1] & 31"
        return size, (_R + S + [cnt, "if cnt == 0: return", f"a = {_rm_rd(form, size)}"]
                      + _shift_body(skind) + _rm_wr(form, size, "res", True)
                      + _shift_flags(skind))
    if kind.startswith("alu_"):
        op, size = args
        rd = _rm_rd(form, size)
        body = _alu_body(op)
        wb = [] if op == 7 else _rm_wr(form, size, "res", True)
        if kind == "alu_rm_r":
            return size, _R + S + [f"a = {rd}", "r = e[3]", f"b = {_rd_reg(size, 'r')}"] + body + wb
        if kind == "alu_r_rm":
            return size, (_R + S + ["r = e[3]", f"a = {_rd_reg(size, 'r')}", f"b = {rd}"] + body
                          + ([] if op == 7 else _wr_reg(size, "r", "res", True)))
        return size, _R + S + [f"a = {rd}", "b = e[8]"] + body + wb      # alu_rm_imm
    (size,) = args
    rd = _rm_rd(form, size)
    if kind == "test_rm_r":
        return size, _R + S + [f"a = {rd}", "r = e[3]", f"res = a & {_rd_reg(size, 'r')}"] + _F_LOGIC
    if kind == "test_rm_imm":
        return size, _R + S + [f"res = {rd} & e[8]"] + _F_LOGIC
    if kind == "mov_rm_r":
        return size, _R + S + ["r = e[3]"] + _rm_wr(form, size, _rd_reg(size, "r"), True)
    if kind == "mov_r_rm":
        return size, _R + S + ["r = e[3]"] + _wr_reg(size, "r", rd, True)
    if kind == "mov_rm_imm":
        return size, _R + S + _rm_wr(form, size, "e[8]", True)
    if kind == "xchg":
        return size, (_R + S + [f"a = {rd}", "r = e[3]", f"b = {_rd_reg(size, 'r')}"]
                      + _rm_wr(form, size, "b", True) + _wr_reg(size, "r", "a", True))
    if kind == "inc":
        return size, _R + S + [f"a = {rd}"] + _INC_BODY + _rm_wr(form, size, "res", True)
    if kind == "dec":
        return size, _R + S + [f"a = {rd}"] + _DEC_BODY + _rm_wr(form, size, "res", True)
    if kind == "not":
        return size, _R + S + [f"a = {rd}"] + _rm_wr(form, size, "(~a) & MASK", True)
    if kind == "neg":                                  # neg = 0 - b, 标志同 sub
        return size, _R + S + ["a = 0", f"b = {rd}", "res = a - b"] + _f_sub("") + _rm_wr(form, size, "res", True)
    raise KeyError(kind)


def _gen(kind: str, args: tuple, forms: tuple) -> tuple:
    """生成 kind(args) 在 forms 各形态下的 handler: 拼源码、编译一次、返回函数元组.

    源码登记进 linecache, traceback 能显示生成的行; CPU86_DUMP_GEN=1 时转储到 stderr。
    """
    srcs = []
    names = []
    tag = "_".join(str(a) for a in args)
    for form in forms:
        size, lines = _emit(kind, args, form)
        name = f"h_{kind}_{tag}_{form}" if tag else f"h_{kind}_{form}"
        body = "\n".join("    " + ln for ln in lines)
        body = (body.replace("MASK", hex(_MASK[size])).replace("SIGN", hex(_SIGN[size]))
                .replace("BITS", str(size * 8)))
        srcs.append(f"def {name}(cpu, e):\n{body}\n")
        names.append(name)
    src = "\n".join(srcs)
    filename = f"<cpu86 gen {kind} {tag}>"
    import linecache                      # 延迟 import: 它会拉起 tokenize, 不必在 import cpu86 时付
    linecache.cache[filename] = (len(src), None, src.splitlines(True), filename)
    if os.environ.get("CPU86_DUMP_GEN"):
        sys.stderr.write(src + "\n")
    ns = dict(_GEN_NS)
    exec(compile(src, filename, "exec"), ns)
    return tuple(ns[n] for n in names)


class _LazyForms(dict):
    """{args: 各形态 handler 元组}: 首次取用某一族/尺寸时才生成并编译.

    全部 680 多个变体一次生成要 150ms 的 import 时间, 而一个程序实际只用到其中
    一两百个; 惰性生成把成本摊到首次执行, 且只付用到的部分。
    """

    __slots__ = ("kind", "forms", "prefix")

    def __init__(self, kind: str, forms: tuple = (0, 1, 2, 3), prefix: tuple = ()):
        super().__init__()
        self.kind = kind
        self.forms = forms
        self.prefix = prefix                 # 放在形态元组前面的固定项(lea 的寄存器形态报错)

    def __missing__(self, key):
        args = key if isinstance(key, tuple) else (key,)
        v = self.prefix + _gen(self.kind, args, self.forms)
        self[key] = v
        return v


# ---------------------------------------------------------------------------
# 手写 handler(形状单一的指令, 以及复用旧式 _read_rm/_write_rm 的罕见指令)
# ---------------------------------------------------------------------------

def _h_nop(cpu, e):
    pass


def _h_hlt(cpu, e):
    cpu.halted = True
    raise _Halt


def _h_int(cpu, e):
    if cpu.on_int is None:
        cpu.halted = True
        raise _Halt
    cpu.on_int(cpu, e[8])


def _h_bad(cpu, e):
    cpu._bad(e[3], e[8], cpu.eip - e[1])       # eip 已在指令末尾, 减长度即起点


def _h_lea_reg(cpu, e):
    cpu._bad(0x8D, "lea 的操作数不能是寄存器", cpu.eip - e[1])


def _h_push_r32(cpu, e):
    regs = cpu.regs
    sp = (regs[4] - 4) & M
    cpu.mem.write_u32(sp, regs[e[3]])
    regs[4] = sp


def _h_pop_r32(cpu, e):
    regs = cpu.regs
    sp = regs[4]
    v = cpu.mem.read_u32(sp)
    regs[4] = (sp + 4) & M          # 先动 ESP 再写目标: pop esp 的结果是弹出值
    regs[e[3]] = v


def _h_push_r16(cpu, e):
    cpu.push16(cpu.get_reg16(e[3]))


def _h_pop_r16(cpu, e):
    cpu.set_reg16(e[3], cpu.pop16())


def _h_push_imm32(cpu, e):
    regs = cpu.regs
    sp = (regs[4] - 4) & M
    cpu.mem.write_u32(sp, e[8])
    regs[4] = sp


def _h_push_imm16(cpu, e):
    cpu.push16(e[8])


def _h_mov_r32_imm(cpu, e):
    cpu.regs[e[3]] = e[8]


def _h_mov_r16_imm(cpu, e):
    cpu.set_reg16(e[3], e[8])


def _h_mov_r8_imm(cpu, e):
    cpu.set_reg8(e[3], e[8])


def _h_call_rel(cpu, e):
    regs = cpu.regs
    sp = (regs[4] - 4) & M
    cpu.mem.write_u32(sp, cpu.eip)      # eip 已是下一条 = 返回地址
    regs[4] = sp
    cpu.eip = e[8]


def _h_jmp(cpu, e):
    cpu.eip = e[8]


def _h_ret(cpu, e):
    regs = cpu.regs
    sp = regs[4]
    cpu.eip = cpu.mem.read_u32(sp)
    regs[4] = (sp + 4) & M


def _h_ret_n(cpu, e):
    regs = cpu.regs
    sp = regs[4]
    cpu.eip = cpu.mem.read_u32(sp)
    regs[4] = (sp + 4 + e[8]) & M


def _h_leave(cpu, e):
    regs = cpu.regs
    regs[4] = regs[5]
    regs[5] = cpu.pop32()


def _h_enter(cpu, e):
    regs = cpu.regs
    mem = cpu.mem
    alloc, level = e[8], e[3]
    cpu.push32(regs[EBP])
    frame = regs[ESP]
    for _ in range(level):
        regs[EBP] = (regs[EBP] - 4) & M
        cpu.push32(mem.read_u32(regs[EBP]))
    if level:
        cpu.push32(frame)
    regs[EBP] = frame
    regs[ESP] = (regs[ESP] - alloc) & M


def _h_xchg_eax_r(cpu, e):
    size, r = e[2], e[3]
    a = cpu._read_reg(0, size)
    cpu._write_reg(0, size, cpu._read_reg(r, size))
    cpu._write_reg(r, size, a)


def _h_cbw(cpu, e):
    if e[2] == 2:
        cpu.set_reg16(0, _sx8(cpu.get_reg8(0)) & 0xFFFF)
    else:
        cpu.regs[EAX] = _sx16(cpu.regs[EAX] & 0xFFFF) & M


def _h_cwd(cpu, e):
    regs = cpu.regs
    if e[2] == 2:
        cpu.set_reg16(EDX, 0xFFFF if regs[EAX] & 0x8000 else 0)
    else:
        regs[EDX] = M if regs[EAX] & SIGN32 else 0


def _h_pushf(cpu, e):
    if e[2] == 2:
        cpu.push16(cpu.flags & 0xFFFF)
    else:
        cpu.push32(cpu.flags)


def _h_popf(cpu, e):
    cpu.eflags = cpu.pop16() if e[2] == 2 else cpu.pop32()


def _h_sahf(cpu, e):
    ah = cpu.get_reg8(4)
    cpu.flags = (cpu.flags & ~0xFF) | (ah & 0xD5) | 0x02


def _h_lahf(cpu, e):
    cpu.set_reg8(4, cpu.flags & 0xFF)


def _h_xlat(cpu, e):
    cpu.set_reg8(0, cpu.mem.read_u8((cpu.regs[EBX] + cpu.get_reg8(0)) & M))


def _h_mov_al_moffs(cpu, e):
    cpu.set_reg8(0, cpu.mem.read_u8(e[8]))


def _h_mov_ax_moffs(cpu, e):
    cpu._write_reg(0, e[2], cpu._read_rm(0, 0, e[8], e[2]))


def _h_mov_moffs_al(cpu, e):
    cpu.mem.write_u8(e[8], cpu.get_reg8(0))


def _h_mov_moffs_ax(cpu, e):
    cpu._write_rm(0, 0, e[8], e[2], cpu._read_reg(0, e[2]))


def _h_string(cpu, e):
    cpu._string_op(e[3], e[2], e[8])


def _h_loop(cpu, e):
    """E0 loopne / E1 loope / E2 loop / E3 jecxz; e[3]=opcode, e[8]=目标."""
    regs = cpu.regs
    op = e[3]
    if op == 0xE3:
        take = regs[ECX] == 0
    else:
        regs[ECX] = (regs[ECX] - 1) & M
        take = regs[ECX] != 0
        if op == 0xE1:
            take = take and bool(cpu.flags & ZF)
        elif op == 0xE0:
            take = take and not (cpu.flags & ZF)
    if take:
        cpu.eip = e[8]


def _h_clc(cpu, e):
    cpu.flags &= ~CF


def _h_stc(cpu, e):
    cpu.flags |= CF


def _h_cld(cpu, e):
    cpu.flags &= ~DF


def _h_std(cpu, e):
    cpu.flags |= DF


def _imul_flags(cpu, res: int, size: int) -> None:
    lim = 0x7FFF if size == 2 else 0x7FFFFFFF
    f = EFLAGS_BASE | (cpu.flags & DF)
    if not (-lim - 1 <= res <= lim):
        f |= CF | OF
    low = res & _MASK[size]
    if low == 0:
        f |= ZF
    if low & _SIGN[size]:
        f |= SF
    cpu.flags = f | _PARITY[low & 0xFF]


def _h_imul3(cpu, e):
    """69/6B imul r, r/m, imm; e[8] 是已符号扩展的立即数."""
    size = e[2]
    src = cpu._read_rm(e[9], e[4], _ea_of(cpu.regs, e), size)
    a = _sx16(src) if size == 2 else _sx32(src)
    res = a * e[8]
    cpu._write_reg(e[3], size, res)
    _imul_flags(cpu, res, size)


def _h_imul2(cpu, e):
    """0F AF imul r, r/m."""
    size = e[2]
    a = cpu._read_reg(e[3], size)
    a = _sx32(a) if size == 4 else _sx16(a)
    b = cpu._read_rm(e[9], e[4], _ea_of(cpu.regs, e), size)
    b = _sx32(b) if size == 4 else _sx16(b)
    res = a * b
    cpu._write_reg(e[3], size, res)
    _imul_flags(cpu, res, size)


def _h_muldiv(cpu, e):
    """F6/F7 /4-/7: mul imul div idiv; e[3] 是子操作码."""
    size = e[2]
    a = cpu._read_rm(e[9], e[4], _ea_of(cpu.regs, e), size)
    sub = e[3]
    if sub == 4:
        cpu._mul_unsigned(a, size)
    elif sub == 5:
        cpu._mul_signed(a, size)
    elif sub == 6:
        cpu._div_unsigned(a, size)
    else:
        cpu._div_signed(a, size)


def _h_pop_rm(cpu, e):
    size = e[2]
    addr = _ea_of(cpu.regs, e)          # 先按弹出前的 ESP 算地址, 再弹
    val = cpu.pop16() if size == 2 else cpu.pop32()
    cpu._write_rm(e[9], e[4], addr, size, val)


def _h_push_rm16(cpu, e):
    cpu.push16(cpu._read_rm(e[9], e[4], _ea_of(cpu.regs, e), 2))


def _bt_impl(cpu, e, sub: int, bit: int) -> None:
    size = e[2]
    bits = size * 8
    mod, rm = e[9], e[4]
    if mod == 3:
        bit &= bits - 1
        val = cpu._read_rm(3, rm, None, size)
        addr = None
    else:
        addr = (_ea_of(cpu.regs, e) + (bit // bits) * size) & M
        bit &= bits - 1
        val = cpu._read_mem_sized(addr, size)
    cur = (val >> bit) & 1
    cpu.flags = (cpu.flags & ~CF) | (CF if cur else 0)
    if sub == 5:
        val |= 1 << bit
    elif sub == 6:
        val &= ~(1 << bit)
    elif sub == 7:
        val ^= 1 << bit
    if sub != 4:
        if mod == 3:
            cpu._write_rm(3, rm, None, size, val)
        else:
            cpu._write_mem_sized(addr, size, val)


def _h_bt_r(cpu, e):
    """0F A3/AB/B3/BB bt/bts/btr/btc r/m, r; e[8] 是子操作(4..7)."""
    _bt_impl(cpu, e, e[8], cpu._read_reg(e[3], e[2]))


def _h_bt_i(cpu, e):
    """0F BA /4-/7 bt 族立即数形式; e[3] 子操作, e[8] 位号."""
    _bt_impl(cpu, e, e[3], e[8])


def _h_bsf(cpu, e):
    """0F BC bsf / BD bsr; e[8] 是 op2."""
    size = e[2]
    v = cpu._read_rm(e[9], e[4], _ea_of(cpu.regs, e), size)
    if v == 0:
        cpu.flags |= ZF
        return
    cpu.flags &= ~ZF
    idx = (v & -v).bit_length() - 1 if e[8] == 0xBC else v.bit_length() - 1
    cpu._write_reg(e[3], size, idx)


def _h_shd(cpu, e):
    """0F A4/A5 shld, AC/AD shrd; e[8] = (op2 << 8) | imm8."""
    size = e[2]
    op = e[8] >> 8
    cnt = (e[8] & 0xFF) if op in (0xA4, 0xAC) else cpu.get_reg8(ECX)
    cnt &= 31
    bits = size * 8
    mask = _MASK[size]
    mod, rm = e[9], e[4]
    addr = _ea_of(cpu.regs, e)
    dst = cpu._read_rm(mod, rm, addr, size)
    src = cpu._read_reg(e[3], size)
    if cnt == 0:
        return
    if op in (0xA4, 0xA5):                       # shld: 左移, 从 src 高位补入
        wide = ((dst << bits) | src) & ((1 << (bits * 2)) - 1)
        res = (wide << cnt) >> bits
        cf = (dst >> (bits - cnt)) & 1
    else:                                        # shrd: 右移, 从 src 低位补入
        wide = ((src << bits) | dst) & ((1 << (bits * 2)) - 1)
        res = wide >> cnt
        cf = (dst >> (cnt - 1)) & 1
    res &= mask
    cpu._write_rm(mod, rm, addr, size, res)
    f = EFLAGS_BASE | (cpu.flags & DF)
    if cf:
        f |= CF
    if res == 0:
        f |= ZF
    if res & _SIGN[size]:
        f |= SF
    cpu.flags = f | _PARITY[res & 0xFF]


# ---------------------------------------------------------------------------
# 解码器: _DEC[op](cpu, op, opsize, start) -> e
# 进入时 cpu.eip 已越过 opcode 字节; 解码器用 cpu._fetch*() 继续前进,
# 返回时 cpu.eip 指向下一条指令, length = cpu.eip - start。
# ---------------------------------------------------------------------------

def _modrm_dec(cpu) -> tuple:
    """解 ModRM(+SIB+disp), 返回 (mod, reg, base, index, scale, disp).

    mod==3 时 base 是 rm 寄存器号; 内存形态 base 可为 None(无基址), index 为
    None 表示无索引。disp 为有符号整数。
    """
    mem = cpu.mem
    eip = cpu.eip
    b = mem.read_u8(eip)
    eip += 1
    mod = b >> 6
    reg = (b >> 3) & 7
    rm = b & 7
    if mod == 3:
        cpu.eip = eip
        return 3, reg, rm, None, 0, 0
    index = None
    scale = 0
    disp = 0
    base = rm
    if rm == 4:                                  # SIB
        sib = mem.read_u8(eip)
        eip += 1
        scale = sib >> 6
        idx = (sib >> 3) & 7
        base = sib & 7
        if idx != 4:                             # index==4(ESP) 表示无索引
            index = idx
        if base == 5 and mod == 0:
            base = None
            disp = _sx32(mem.read_u32(eip))
            eip += 4
    elif rm == 5 and mod == 0:                   # disp32 绝对寻址
        base = None
        disp = _sx32(mem.read_u32(eip))
        eip += 4
    if mod == 1:
        disp += _sx8(mem.read_u8(eip))
        eip += 1
    elif mod == 2:
        disp += _sx32(mem.read_u32(eip))
        eip += 4
    cpu.eip = eip
    return mod, reg, base, index, scale, disp


def _mk(cpu, start: int, variants: tuple, size: int, m: tuple, imm=0) -> tuple:
    """按 ModRM 解码结果选寻址形态变体, 组装 e."""
    mod, reg, base, index, scale, disp = m
    if mod == 3:
        form = 0
    elif index is None:
        if base is None:
            form = 1
            disp &= M
        else:
            form = 2
    else:
        form = 3
    return (variants[form], cpu.eip - start, size, reg, base, index, scale,
            disp, imm, mod)


def _mk_bad(cpu, start: int, size: int, m: tuple, op: int, msg: str) -> tuple:
    """执行时报 CpuError 的 e(未实现的 ModRM 子操作)."""
    e = _mk(cpu, start, (_h_bad,) * 4, size, m, msg)
    return e[:3] + (op,) + e[4:]


def _E(cpu, start: int, fn, size: int = 4, reg: int = 0, imm=0) -> tuple:
    """无 ModRM 指令的 e."""
    return (fn, cpu.eip - start, size, reg, 0, None, 0, 0, imm, 3)


def _imm(cpu, size: int) -> int:
    if size == 4:
        return cpu._fetch32()
    if size == 2:
        return cpu._fetch16()
    return cpu._fetch8()


def _dec_bad(cpu, op, opsize, start):
    return _E(cpu, start, _h_bad, reg=op, imm="未实现的指令")


def _dec_bad0f(cpu, op, opsize, start):
    return _E(cpu, start, _h_bad, reg=0x0F00 | op, imm=f"0F {op:02x} 未实现")


_DEC = [_dec_bad] * 256
_DEC0F = [_dec_bad0f] * 256

# 各族的形态变体表(惰性): 解码时按 [args] 取 4 个寻址形态的 handler 元组
_ALU_RM_R = _LazyForms("alu_rm_r")           # key (op, size)
_ALU_R_RM = _LazyForms("alu_r_rm")
_ALU_RM_IMM = _LazyForms("alu_rm_imm")
_TEST_RM_R = _LazyForms("test_rm_r")         # key size
_TEST_RM_IMM = _LazyForms("test_rm_imm")
_MOV_RM_R = _LazyForms("mov_rm_r")
_MOV_R_RM = _LazyForms("mov_r_rm")
_MOV_RM_IMM = _LazyForms("mov_rm_imm")
_XCHG = _LazyForms("xchg")
_INC = _LazyForms("inc")
_DEC_ = _LazyForms("dec")
_NOT = _LazyForms("not")
_NEG = _LazyForms("neg")
_SHIFT = _LazyForms("shift")                 # key (kind, size, src)
_SETCC = _LazyForms("setcc")                 # key cc
_MOVX = _LazyForms("movx")                   # key (sx, src_size, dst_size)
_LEA = _LazyForms("lea", forms=(1, 2, 3), prefix=(_h_lea_reg,))   # key size
_CALL_RM = _LazyForms("call_rm")             # key ()
_JMP_RM = _LazyForms("jmp_rm")
_PUSH_RM = _LazyForms("push_rm")
_JCC = _LazyForms("jcc", forms=(0,))         # key cc -> 1 元组


def _reg_dec(table: list, ops, fn) -> None:
    for op in ops:
        table[op] = fn


# ---- 00-3F ALU 族 ----
def _dec_alu(cpu, op, opsize, start):
    alu = op >> 3
    form = op & 7
    if form == 0:                                # r/m8, r8
        return _mk(cpu, start, _ALU_RM_R[alu, 1], 1, _modrm_dec(cpu))
    if form == 1:                                # r/m, r
        return _mk(cpu, start, _ALU_RM_R[alu, opsize], opsize, _modrm_dec(cpu))
    if form == 2:                                # r8, r/m8
        return _mk(cpu, start, _ALU_R_RM[alu, 1], 1, _modrm_dec(cpu))
    if form == 3:                                # r, r/m
        return _mk(cpu, start, _ALU_R_RM[alu, opsize], opsize, _modrm_dec(cpu))
    if form == 4:                                # al, imm8
        imm = cpu._fetch8()
        return (_ALU_RM_IMM[alu, 1][0], cpu.eip - start, 1, 0, 0, None, 0, 0, imm, 3)
    imm = _imm(cpu, opsize)                      # eax, imm
    return (_ALU_RM_IMM[alu, opsize][0], cpu.eip - start, opsize, 0, 0, None, 0, 0, imm, 3)


_reg_dec(_DEC, [op for op in range(0x40) if (op & 7) < 6], _dec_alu)


# ---- 40-4F inc/dec r ----
def _dec_incdec_r(cpu, op, opsize, start):
    table = _INC if op < 0x48 else _DEC_
    return (table[opsize][0], cpu.eip - start, opsize, 0, op & 7, None, 0, 0, 0, 3)


_reg_dec(_DEC, range(0x40, 0x50), _dec_incdec_r)


# ---- 50-5F push/pop r ----
def _dec_push_r(cpu, op, opsize, start):
    return _E(cpu, start, _h_push_r32 if opsize == 4 else _h_push_r16, opsize, op & 7)


def _dec_pop_r(cpu, op, opsize, start):
    return _E(cpu, start, _h_pop_r32 if opsize == 4 else _h_pop_r16, opsize, op & 7)


_reg_dec(_DEC, range(0x50, 0x58), _dec_push_r)
_reg_dec(_DEC, range(0x58, 0x60), _dec_pop_r)


# ---- 68/6A push imm ----
def _dec_push_imm(cpu, op, opsize, start):
    if op == 0x68:
        imm = _imm(cpu, opsize)
    else:
        imm = _sx8(cpu._fetch8()) & _MASK[opsize]
    return _E(cpu, start, _h_push_imm32 if opsize == 4 else _h_push_imm16, opsize, 0, imm)


_DEC[0x68] = _DEC[0x6A] = _dec_push_imm


# ---- 69/6B imul r, r/m, imm ----
def _dec_imul3(cpu, op, opsize, start):
    m = _modrm_dec(cpu)
    if op == 0x69:
        imm = _imm(cpu, opsize)
        imm = _sx16(imm) if opsize == 2 else _sx32(imm)
    else:
        imm = _sx8(cpu._fetch8())
    return _mk(cpu, start, (_h_imul3,) * 4, opsize, m, imm)


_DEC[0x69] = _DEC[0x6B] = _dec_imul3


# ---- 70-7F jcc rel8 ----
def _dec_jcc8(cpu, op, opsize, start):
    rel = _sx8(cpu._fetch8())
    return _E(cpu, start, _JCC[op & 0xF][0], 4, op & 0xF, (cpu.eip + rel) & M)


_reg_dec(_DEC, range(0x70, 0x80), _dec_jcc8)


# ---- 80/81/83 ALU r/m, imm ----
def _dec_alu_imm(cpu, op, opsize, start):
    size = 1 if op == 0x80 else opsize
    m = _modrm_dec(cpu)
    if op == 0x80:
        imm = cpu._fetch8()
    elif op == 0x81:
        imm = _imm(cpu, size)
    else:
        imm = _sx8(cpu._fetch8()) & _MASK[size]
    return _mk(cpu, start, _ALU_RM_IMM[m[1], size], size, m, imm)


_DEC[0x80] = _DEC[0x81] = _DEC[0x83] = _dec_alu_imm


# ---- 84/85 test, 86/87 xchg, 88-8B mov ----
def _dec_test_rm_r(cpu, op, opsize, start):
    size = 1 if op == 0x84 else opsize
    return _mk(cpu, start, _TEST_RM_R[size], size, _modrm_dec(cpu))


def _dec_xchg(cpu, op, opsize, start):
    size = 1 if op == 0x86 else opsize
    return _mk(cpu, start, _XCHG[size], size, _modrm_dec(cpu))


def _dec_mov_rm_r(cpu, op, opsize, start):
    size = 1 if op == 0x88 else opsize
    return _mk(cpu, start, _MOV_RM_R[size], size, _modrm_dec(cpu))


def _dec_mov_r_rm(cpu, op, opsize, start):
    size = 1 if op == 0x8A else opsize
    return _mk(cpu, start, _MOV_R_RM[size], size, _modrm_dec(cpu))


_DEC[0x84] = _DEC[0x85] = _dec_test_rm_r
_DEC[0x86] = _DEC[0x87] = _dec_xchg
_DEC[0x88] = _DEC[0x89] = _dec_mov_rm_r
_DEC[0x8A] = _DEC[0x8B] = _dec_mov_r_rm


# ---- 8D lea, 8F pop r/m ----
def _dec_lea(cpu, op, opsize, start):
    return _mk(cpu, start, _LEA[opsize], opsize, _modrm_dec(cpu))


def _dec_pop_rm(cpu, op, opsize, start):
    return _mk(cpu, start, (_h_pop_rm,) * 4, opsize, _modrm_dec(cpu))


_DEC[0x8D] = _dec_lea
_DEC[0x8F] = _dec_pop_rm


# ---- 90-9F ----
def _dec_simple(fn):
    """无操作数、只看 opsize 的指令."""
    def dec(cpu, op, opsize, start):
        return _E(cpu, start, fn, opsize)
    return dec


def _dec_xchg_eax_r(cpu, op, opsize, start):
    return _E(cpu, start, _h_xchg_eax_r, opsize, op & 7)


_DEC[0x90] = _dec_simple(_h_nop)
_reg_dec(_DEC, range(0x91, 0x98), _dec_xchg_eax_r)
_DEC[0x98] = _dec_simple(_h_cbw)
_DEC[0x99] = _dec_simple(_h_cwd)
_DEC[0x9C] = _dec_simple(_h_pushf)
_DEC[0x9D] = _dec_simple(_h_popf)
_DEC[0x9E] = _dec_simple(_h_sahf)
_DEC[0x9F] = _dec_simple(_h_lahf)


# ---- A0-A3 mov eax <-> moffs ----
def _dec_moffs(cpu, op, opsize, start):
    addr = cpu._fetch32()
    fn = (_h_mov_al_moffs, _h_mov_ax_moffs, _h_mov_moffs_al, _h_mov_moffs_ax)[op - 0xA0]
    return _E(cpu, start, fn, opsize, 0, addr)


_reg_dec(_DEC, range(0xA0, 0xA4), _dec_moffs)


# ---- A4-AF 串指令(无 rep), A8/A9 test acc, imm ----
def _dec_string(cpu, op, opsize, start):
    return _E(cpu, start, _h_string, opsize, op, 0)


def _dec_test_acc_imm(cpu, op, opsize, start):
    size = 1 if op == 0xA8 else opsize
    imm = _imm(cpu, size)
    return (_TEST_RM_IMM[size][0], cpu.eip - start, size, 0, 0, None, 0, 0, imm, 3)


_reg_dec(_DEC, [op for op in range(0xA4, 0xB0) if op not in (0xA8, 0xA9)], _dec_string)
_DEC[0xA8] = _DEC[0xA9] = _dec_test_acc_imm


# ---- B0-BF mov r, imm ----
def _dec_mov_r8_imm(cpu, op, opsize, start):
    imm = cpu._fetch8()
    return _E(cpu, start, _h_mov_r8_imm, 1, op & 7, imm)


def _dec_mov_r_imm(cpu, op, opsize, start):
    imm = _imm(cpu, opsize)
    return _E(cpu, start, _h_mov_r32_imm if opsize == 4 else _h_mov_r16_imm,
              opsize, op & 7, imm)


_reg_dec(_DEC, range(0xB0, 0xB8), _dec_mov_r8_imm)
_reg_dec(_DEC, range(0xB8, 0xC0), _dec_mov_r_imm)


# ---- C0/C1/D0-D3 移位组 ----
def _dec_shift(cpu, op, opsize, start):
    size = 1 if op in (0xC0, 0xD0, 0xD2) else opsize
    m = _modrm_dec(cpu)
    kind = m[1]
    if op in (0xC0, 0xC1):
        cnt, src = cpu._fetch8() & 31, 0
    elif op in (0xD0, 0xD1):
        cnt, src = 1, 0
    else:
        cnt, src = 0, 1                          # 按 CL
    if kind == 2 or kind == 3:                   # rcl/rcr 未实现
        return _mk_bad(cpu, start, size, m, 0xC1, f"移位组 /{kind}(rcl/rcr) 未实现")
    return _mk(cpu, start, _SHIFT[kind, size, src], size, m, cnt)


_reg_dec(_DEC, (0xC0, 0xC1, 0xD0, 0xD1, 0xD2, 0xD3), _dec_shift)


# ---- C2/C3 ret, C6/C7 mov r/m, imm, C8/C9 enter/leave ----
def _dec_ret_n(cpu, op, opsize, start):
    n = cpu._fetch16()
    return _E(cpu, start, _h_ret_n, 4, 0, n)


def _dec_mov_rm_imm(cpu, op, opsize, start):
    size = 1 if op == 0xC6 else opsize
    m = _modrm_dec(cpu)
    imm = _imm(cpu, size)
    return _mk(cpu, start, _MOV_RM_IMM[size], size, m, imm)


def _dec_enter(cpu, op, opsize, start):
    alloc = cpu._fetch16()
    level = cpu._fetch8() & 31
    return _E(cpu, start, _h_enter, 4, level, alloc)


_DEC[0xC2] = _dec_ret_n
_DEC[0xC3] = _dec_simple(_h_ret)
_DEC[0xC6] = _DEC[0xC7] = _dec_mov_rm_imm
_DEC[0xC8] = _dec_enter
_DEC[0xC9] = _dec_simple(_h_leave)


# ---- CC/CD int, D7 xlat ----
def _dec_int(cpu, op, opsize, start):
    vec = 3 if op == 0xCC else cpu._fetch8()
    return _E(cpu, start, _h_int, 4, 0, vec)


_DEC[0xCC] = _DEC[0xCD] = _dec_int
_DEC[0xD7] = _dec_simple(_h_xlat)


# ---- E0-E3 loop 族, E8/E9/EB call/jmp, F4 hlt ----
def _dec_loop(cpu, op, opsize, start):
    rel = _sx8(cpu._fetch8())
    return _E(cpu, start, _h_loop, 4, op, (cpu.eip + rel) & M)


def _dec_call_rel(cpu, op, opsize, start):
    rel = _sx32(cpu._fetch32())
    return _E(cpu, start, _h_call_rel, 4, 0, (cpu.eip + rel) & M)


def _dec_jmp_rel32(cpu, op, opsize, start):
    rel = _sx32(cpu._fetch32())
    return _E(cpu, start, _h_jmp, 4, 0, (cpu.eip + rel) & M)


def _dec_jmp_rel8(cpu, op, opsize, start):
    rel = _sx8(cpu._fetch8())
    return _E(cpu, start, _h_jmp, 4, 0, (cpu.eip + rel) & M)


_reg_dec(_DEC, range(0xE0, 0xE4), _dec_loop)
_DEC[0xE8] = _dec_call_rel
_DEC[0xE9] = _dec_jmp_rel32
_DEC[0xEB] = _dec_jmp_rel8
_DEC[0xF4] = _dec_simple(_h_hlt)


# ---- F6/F7 组: test/not/neg/mul/imul/div/idiv ----
def _dec_grp_f7(cpu, op, opsize, start):
    size = 1 if op == 0xF6 else opsize
    m = _modrm_dec(cpu)
    sub = m[1]
    if sub == 0 or sub == 1:
        imm = _imm(cpu, size)
        return _mk(cpu, start, _TEST_RM_IMM[size], size, m, imm)
    if sub == 2:
        return _mk(cpu, start, _NOT[size], size, m)
    if sub == 3:
        return _mk(cpu, start, _NEG[size], size, m)
    return _mk(cpu, start, (_h_muldiv,) * 4, size, m)


_DEC[0xF6] = _DEC[0xF7] = _dec_grp_f7
_DEC[0xF8] = _dec_simple(_h_clc)
_DEC[0xF9] = _dec_simple(_h_stc)
_DEC[0xFC] = _dec_simple(_h_cld)
_DEC[0xFD] = _dec_simple(_h_std)


# ---- FE/FF 组: inc/dec/call/jmp/push ----
def _dec_grp_ff(cpu, op, opsize, start):
    size = 1 if op == 0xFE else opsize
    m = _modrm_dec(cpu)
    sub = m[1]
    if sub == 0:
        return _mk(cpu, start, _INC[size], size, m)
    if sub == 1:
        return _mk(cpu, start, _DEC_[size], size, m)
    if op == 0xFF:
        if sub == 2:
            return _mk(cpu, start, _CALL_RM[()], 4, m)
        if sub == 4:
            return _mk(cpu, start, _JMP_RM[()], 4, m)
        if sub == 6:
            if opsize == 4:
                return _mk(cpu, start, _PUSH_RM[()], 4, m)
            return _mk(cpu, start, (_h_push_rm16,) * 4, 2, m)
    return _mk_bad(cpu, start, size, m, op, f"FF 组 /{sub} 未实现")


_DEC[0xFE] = _DEC[0xFF] = _dec_grp_ff


# ---- 0F 两字节 ----
def _dec_0f(cpu, op, opsize, start):
    op2 = cpu._fetch8()
    return _DEC0F[op2](cpu, op2, opsize, start)


_DEC[0x0F] = _dec_0f


def _dec_jcc32(cpu, op, opsize, start):
    rel = _sx32(cpu._fetch32())
    return _E(cpu, start, _JCC[op & 0xF][0], 4, op & 0xF, (cpu.eip + rel) & M)


def _dec_setcc(cpu, op, opsize, start):
    return _mk(cpu, start, _SETCC[op & 0xF], 1, _modrm_dec(cpu))


def _dec_imul2(cpu, op, opsize, start):
    return _mk(cpu, start, (_h_imul2,) * 4, opsize, _modrm_dec(cpu))


_BT_SUB = {0xA3: 4, 0xAB: 5, 0xB3: 6, 0xBB: 7}


def _dec_bt(cpu, op, opsize, start):
    m = _modrm_dec(cpu)
    if op == 0xBA:
        sub = m[1]
        if sub < 4:
            return _mk_bad(cpu, start, opsize, m, 0x0F00 | op, f"0F BA /{sub} 未实现")
        bit = cpu._fetch8()
        return _mk(cpu, start, (_h_bt_i,) * 4, opsize, m, bit)
    return _mk(cpu, start, (_h_bt_r,) * 4, opsize, m, _BT_SUB[op])


def _dec_bsf(cpu, op, opsize, start):
    return _mk(cpu, start, (_h_bsf,) * 4, opsize, _modrm_dec(cpu), op)


def _dec_shd(cpu, op, opsize, start):
    m = _modrm_dec(cpu)
    imm = cpu._fetch8() if op in (0xA4, 0xAC) else 0
    return _mk(cpu, start, (_h_shd,) * 4, opsize, m, (op << 8) | imm)


def _dec_movx(cpu, op, opsize, start):
    src_size = 1 if op in (0xB6, 0xBE) else 2
    sx = 1 if op in (0xBE, 0xBF) else 0
    return _mk(cpu, start, _MOVX[sx, src_size, opsize], src_size, _modrm_dec(cpu))


_reg_dec(_DEC0F, range(0x80, 0x90), _dec_jcc32)
_reg_dec(_DEC0F, range(0x90, 0xA0), _dec_setcc)
_DEC0F[0xAF] = _dec_imul2
_reg_dec(_DEC0F, (0xA3, 0xAB, 0xB3, 0xBB, 0xBA), _dec_bt)
_DEC0F[0xBC] = _DEC0F[0xBD] = _dec_bsf
_reg_dec(_DEC0F, (0xA4, 0xA5, 0xAC, 0xAD), _dec_shd)
_reg_dec(_DEC0F, (0xB6, 0xB7, 0xBE, 0xBF), _dec_movx)


class CPU:
    """i386 用户态解释器."""

    def __init__(self, mem: AddressSpace,
                 on_int: Optional[Callable[["CPU", int], None]] = None,
                 on_fault: Optional[Callable[["CPU", BaseException], None]] = None):
        self.mem = mem
        self.regs = [0] * 8
        self.eip = 0
        self.flags = EFLAGS_BASE
        self.on_int = on_int
        self.on_fault = on_fault
        self.halted = False
        self.icount = 0
        self._insn_start = 0          # 最近一次解码/单步的指令起点(报错兜底用; 热循环不维护)
        # 性能剖析器: None=关闭(默认), 非空时 run() 改走 _run_profiled
        self.prof: Optional[Profiler] = None

    # ---- 寄存器视图 ---------------------------------------------------

    def get_reg8(self, idx: int) -> int:
        if idx < 4:
            return self.regs[idx] & 0xFF
        return (self.regs[idx - 4] >> 8) & 0xFF

    def set_reg8(self, idx: int, val: int) -> None:
        val &= 0xFF
        if idx < 4:
            self.regs[idx] = (self.regs[idx] & 0xFFFFFF00) | val
        else:
            r = idx - 4
            self.regs[r] = (self.regs[r] & 0xFFFF00FF) | (val << 8)

    def get_reg16(self, idx: int) -> int:
        return self.regs[idx] & 0xFFFF

    def set_reg16(self, idx: int, val: int) -> None:
        self.regs[idx] = (self.regs[idx] & 0xFFFF0000) | (val & 0xFFFF)

    # 便捷属性(测试与内核层用名字访问更清楚), 见 _reg_property 的说明
    eax = _reg_property(EAX)
    ecx = _reg_property(ECX)
    edx = _reg_property(EDX)
    ebx = _reg_property(EBX)
    esp = _reg_property(ESP)
    ebp = _reg_property(EBP)
    esi = _reg_property(ESI)
    edi = _reg_property(EDI)

    @property
    def eflags(self) -> int:
        return self.flags

    @eflags.setter
    def eflags(self, val: int) -> None:
        self.flags = (val & 0x0CD5) | EFLAGS_BASE

    # ---- 取指(只在解码期用) ---------------------------------------------

    def _fetch8(self) -> int:
        eip = self.eip
        v = self.mem.read_u8(eip)
        self.eip = eip + 1
        return v

    def _fetch16(self) -> int:
        eip = self.eip
        v = self.mem.read_u16(eip)
        self.eip = eip + 2
        return v

    def _fetch32(self) -> int:
        eip = self.eip
        v = self.mem.read_u32(eip)
        self.eip = eip + 4
        return v

    # ---- 栈 -----------------------------------------------------------

    def push32(self, val: int) -> None:
        sp = (self.regs[ESP] - 4) & MASK32
        self.mem.write_u32(sp, val)
        self.regs[ESP] = sp

    def pop32(self) -> int:
        sp = self.regs[ESP]
        val = self.mem.read_u32(sp)
        self.regs[ESP] = (sp + 4) & MASK32
        return val

    def push16(self, val: int) -> None:
        sp = (self.regs[ESP] - 2) & MASK32
        self.mem.write_u16(sp, val)
        self.regs[ESP] = sp

    def pop16(self) -> int:
        sp = self.regs[ESP]
        val = self.mem.read_u16(sp)
        self.regs[ESP] = (sp + 2) & MASK32
        return val

    # ---- 快照(fork 与信号帧用) -----------------------------------------

    def snapshot(self) -> dict:
        return {"regs": list(self.regs), "eip": self.eip, "flags": self.flags}

    def restore(self, st: dict) -> None:
        self.regs = list(st["regs"])
        self.eip = st["eip"]
        self.flags = st["flags"]

    # ---- 操作数读写(供胖 handler 与串指令复用) ------------------------

    def _read_rm(self, mod: int, rm: int, addr: Optional[int], size: int) -> int:
        if mod == 3:
            if size == 4:
                return self.regs[rm]
            if size == 1:
                return self.get_reg8(rm)
            return self.regs[rm] & 0xFFFF
        if size == 4:
            return self.mem.read_u32(addr)
        if size == 1:
            return self.mem.read_u8(addr)
        return self.mem.read_u16(addr)

    def _write_rm(self, mod: int, rm: int, addr: Optional[int],
                  size: int, val: int) -> None:
        if mod == 3:
            if size == 4:
                self.regs[rm] = val & MASK32
            elif size == 1:
                self.set_reg8(rm, val)
            else:
                self.set_reg16(rm, val)
            return
        if size == 4:
            self.mem.write_u32(addr, val)
        elif size == 1:
            self.mem.write_u8(addr, val)
        else:
            self.mem.write_u16(addr, val)

    def _read_reg(self, reg: int, size: int) -> int:
        if size == 4:
            return self.regs[reg]
        if size == 1:
            return self.get_reg8(reg)
        return self.regs[reg] & 0xFFFF

    def _write_reg(self, reg: int, size: int, val: int) -> None:
        if size == 4:
            self.regs[reg] = val & MASK32
        elif size == 1:
            self.set_reg8(reg, val)
        else:
            self.set_reg16(reg, val)

    # ---- 标志位计算(串指令 cmps/scas 与测试用; ALU 族已内联进 handler) --

    @staticmethod
    def _mask_of(size: int) -> int:
        return _MASK[size]

    @staticmethod
    def _sign_of(size: int) -> int:
        return _SIGN[size]

    def _set_logic_flags(self, res: int, size: int) -> None:
        """and/or/xor/test: CF=OF=0, AF 未定义(置 0)."""
        res &= _MASK[size]
        f = EFLAGS_BASE | (self.flags & DF)
        if res == 0:
            f |= ZF
        if res & _SIGN[size]:
            f |= SF
        self.flags = f | _PARITY[res & 0xFF]

    def _set_add_flags(self, a: int, b: int, res: int, size: int,
                       carry_in: int = 0) -> None:
        mask = _MASK[size]
        sign = _SIGN[size]
        trunc = res & mask
        f = EFLAGS_BASE | (self.flags & DF)
        if res > mask:
            f |= CF
        if trunc == 0:
            f |= ZF
        if trunc & sign:
            f |= SF
        if (~(a ^ b)) & (a ^ trunc) & sign:
            f |= OF
        if ((a & 0xF) + (b & 0xF) + carry_in) > 0xF:
            f |= AF
        self.flags = f | _PARITY[trunc & 0xFF]

    def _set_sub_flags(self, a: int, b: int, res: int, size: int,
                       borrow_in: int = 0) -> None:
        mask = _MASK[size]
        sign = _SIGN[size]
        trunc = res & mask
        f = EFLAGS_BASE | (self.flags & DF)
        if res < 0:
            f |= CF
        if trunc == 0:
            f |= ZF
        if trunc & sign:
            f |= SF
        if (a ^ b) & (a ^ trunc) & sign:
            f |= OF
        if ((a & 0xF) - (b & 0xF) - borrow_in) < 0:
            f |= AF
        self.flags = f | _PARITY[trunc & 0xFF]

    def _cond(self, code: int) -> bool:
        """条件码 -> 布尔(非热路径; jcc/setcc 已按条件码生成专用 handler)."""
        return bool(_COND_FN[code](self.flags))

    # ---- 主循环 -------------------------------------------------------

    def run(self, max_steps: int) -> int:
        """执行至多 max_steps 条指令, 返回实际执行条数.

        每条指令: 查解码缓存(text 区内按 eip 下标), 未命中则解码并缓存;
        然后调 e[0](self, e)。icount 在 finally 里一次性累加 —— Blocked/Exited/
        Replaced/MagicJump 都是异常穿出, 已完成的条数照样计入(调度器靠 icount
        差值记账)。
        """
        if self.prof is not None:
            return self._run_profiled(max_steps)
        if self.halted:
            return 0
        mem = self.mem
        cache = mem.icache
        cache_end = len(cache)
        on_fault = self.on_fault
        done = 0
        try:
            for _ in range(max_steps):
                eip = self.eip
                if eip >= MAGIC_EIP_BASE:
                    raise MagicJump(eip)
                try:
                    if eip < cache_end:
                        e = cache[eip]
                        if e is None:
                            e = self._decode(eip)
                            if self.eip <= cache_end:       # 整条都在 text 内才缓存
                                cache[eip] = e
                        else:
                            self.eip = eip + e[1]
                    else:
                        e = self._decode(eip)
                    e[0](self, e)
                except SegFault as ex:
                    if on_fault is None:
                        raise
                    on_fault(self, ex)
                except DivideError as ex:
                    if on_fault is None:
                        raise
                    on_fault(self, ex)
                done += 1
        except _Halt:
            done += 1                        # hlt 那条也算执行了
        finally:
            self.icount += done
        return done

    def _run_profiled(self, max_steps: int) -> int:
        """run() 的插桩版: 每条指令后交给 self.prof 采样。仅剖析开启时运行。"""
        if self.halted:
            return 0
        prof = self.prof
        mem = self.mem
        cache = mem.icache
        cache_end = len(cache)
        on_fault = self.on_fault
        done = 0
        try:
            for _ in range(max_steps):
                eip = self.eip
                if eip >= MAGIC_EIP_BASE:
                    raise MagicJump(eip)
                try:
                    if eip < cache_end:
                        e = cache[eip]
                        if e is None:
                            e = self._decode(eip)
                            if self.eip <= cache_end:
                                cache[eip] = e
                        else:
                            self.eip = eip + e[1]
                    else:
                        e = self._decode(eip)
                    e[0](self, e)
                except SegFault as ex:
                    if on_fault is None:
                        raise
                    on_fault(self, ex)
                except DivideError as ex:
                    if on_fault is None:
                        raise
                    on_fault(self, ex)
                else:
                    prof.record(eip, mem)
                done += 1
        except _Halt:
            prof.record(eip, mem)
            done += 1
        finally:
            self.icount += done
        return done

    def step(self) -> None:
        """执行一条指令(与 run() 同一条缓存路径, 供单步与测试用)."""
        eip = self.eip
        if eip >= MAGIC_EIP_BASE:
            # 执行流落到魔数地址: 内核用它兜底信号返回(restorer 为 0 时)
            raise MagicJump(eip)
        self._insn_start = eip
        cache = self.mem.icache
        cache_end = len(cache)
        if eip < cache_end:
            e = cache[eip]
            if e is None:
                e = self._decode(eip)
                if self.eip <= cache_end:
                    cache[eip] = e
            else:
                self.eip = eip + e[1]
        else:
            e = self._decode(eip)
        try:
            e[0](self, e)
        except _Halt:
            pass

    def _decode(self, start: int) -> tuple:
        """把 start 处的一条指令解成 e 元组; 返回时 self.eip 指向下一条."""
        self._insn_start = start
        mem = self.mem
        eip = start
        op = mem.read_u8(eip)
        eip += 1
        if op in _PREFIXES:
            opsize = 4
            rep = 0                   # 0=无, 0xF3=rep/repe, 0xF2=repne
            while op in _PREFIXES:
                if op == 0x66:        # 操作数尺寸前缀
                    opsize = 2
                elif op == 0xF2 or op == 0xF3:
                    rep = op
                # 其余(段前缀/lock): 平坦模型下忽略
                op = mem.read_u8(eip)
                eip += 1
            self.eip = eip
            if rep and 0xA4 <= op <= 0xAF and op != 0xA8 and op != 0xA9:
                return (_h_string, eip - start, opsize, op, 0, None, 0, 0, rep, 3)
            if rep and op == 0x90:    # pause = f3 90
                return (_h_nop, eip - start, opsize, 0, 0, None, 0, 0, 0, 3)
            return _DEC[op](self, op, opsize, start)
        self.eip = eip
        return _DEC[op](self, op, 4, start)

    def _bad(self, op: int, extra: str = "未实现的指令",
             start: Optional[int] = None) -> None:
        """抛 CpuError, 带指令起点与机器码字节. start 缺省取 _insn_start(step/decode 记录)."""
        if start is None:
            start = self._insn_start
        n = self.eip - start
        raw = self.mem.read(start, max(n, 1) + 3)
        raise CpuError(f"{extra} opcode={op:#04x}", start, raw)

    # ---- 乘除 -----------------------------------------------------------

    def _mul_unsigned(self, src: int, size: int) -> None:
        if size == 1:
            res = self.get_reg8(0) * src
            self.set_reg16(0, res)
            hi = res >> 8
        elif size == 2:
            res = self.get_reg16(0) * src
            self.set_reg16(0, res & 0xFFFF)
            self.set_reg16(EDX, res >> 16)
            hi = res >> 16
        else:
            res = (self.regs[EAX] & MASK32) * src
            self.regs[EAX] = res & MASK32
            self.regs[EDX] = (res >> 32) & MASK32
            hi = res >> 32
        f = EFLAGS_BASE | (self.flags & DF)
        if hi:
            f |= CF | OF
        low = res & _MASK[size]
        if low == 0:
            f |= ZF
        if low & _SIGN[size]:
            f |= SF
        self.flags = f | _PARITY[low & 0xFF]

    def _mul_signed(self, src: int, size: int) -> None:
        if size == 1:
            a, b = _sx8(self.get_reg8(0)), _sx8(src)
            res = a * b
            self.set_reg16(0, res & 0xFFFF)
            fits = -128 <= res <= 127
        elif size == 2:
            a, b = _sx16(self.get_reg16(0)), _sx16(src)
            res = a * b
            self.set_reg16(0, res & 0xFFFF)
            self.set_reg16(EDX, (res >> 16) & 0xFFFF)
            fits = -0x8000 <= res <= 0x7FFF
        else:
            a, b = _sx32(self.regs[EAX]), _sx32(src)
            res = a * b
            self.regs[EAX] = res & MASK32
            self.regs[EDX] = (res >> 32) & MASK32
            fits = -0x80000000 <= res <= 0x7FFFFFFF
        f = EFLAGS_BASE | (self.flags & DF)
        if not fits:
            f |= CF | OF
        low = res & _MASK[size]
        if low == 0:
            f |= ZF
        if low & _SIGN[size]:
            f |= SF
        self.flags = f | _PARITY[low & 0xFF]

    def _div_unsigned(self, src: int, size: int) -> None:
        if src == 0:
            raise DivideError("除零")
        if size == 1:
            num = self.get_reg16(0)
            q, r = divmod(num, src)
            if q > 0xFF:
                raise DivideError("除法溢出")
            self.set_reg8(0, q)
            self.set_reg8(4, r)          # AH
        elif size == 2:
            num = (self.get_reg16(EDX) << 16) | self.get_reg16(0)
            q, r = divmod(num, src)
            if q > 0xFFFF:
                raise DivideError("除法溢出")
            self.set_reg16(0, q)
            self.set_reg16(EDX, r)
        else:
            num = ((self.regs[EDX] & MASK32) << 32) | (self.regs[EAX] & MASK32)
            q, r = divmod(num, src)
            if q > MASK32:
                raise DivideError("除法溢出")
            self.regs[EAX] = q
            self.regs[EDX] = r

    def _div_signed(self, src: int, size: int) -> None:
        if src == 0:
            raise DivideError("除零")
        if size == 1:
            num = _sx16(self.get_reg16(0))
            d = _sx8(src)
            q, r = self._trunc_divmod(num, d)
            if not -128 <= q <= 127:
                raise DivideError("除法溢出")
            self.set_reg8(0, q & 0xFF)
            self.set_reg8(4, r & 0xFF)
        elif size == 2:
            num = _sx32((self.get_reg16(EDX) << 16) | self.get_reg16(0))
            d = _sx16(src)
            q, r = self._trunc_divmod(num, d)
            if not -0x8000 <= q <= 0x7FFF:
                raise DivideError("除法溢出")
            self.set_reg16(0, q & 0xFFFF)
            self.set_reg16(EDX, r & 0xFFFF)
        else:
            raw = ((self.regs[EDX] & MASK32) << 32) | (self.regs[EAX] & MASK32)
            num = raw - (1 << 64) if raw >= (1 << 63) else raw
            d = _sx32(src)
            q, r = self._trunc_divmod(num, d)
            if not -0x80000000 <= q <= 0x7FFFFFFF:
                raise DivideError("除法溢出")
            self.regs[EAX] = q & MASK32
            self.regs[EDX] = r & MASK32

    @staticmethod
    def _trunc_divmod(a: int, b: int):
        """x86 的除法向零取整, 与 Python 的向下取整不同."""
        q = abs(a) // abs(b)
        if (a < 0) != (b < 0):
            q = -q
        return q, a - q * b

    # ---- 字符串指令 ---------------------------------------------------

    def _string_op(self, op: int, opsize: int, rep: int) -> None:
        """movs/stos/lods/scas/cmps, 可带 rep/repe/repne 前缀.

        剖析开启时顺带累加本次搬运的元素数: 单条 rep 只算一条指令却动 N 个
        元素, 是最强的访存/串强度信号。用 ECX 差值算, 对 impl 零侵入。
        """
        if self.prof is None:
            self._string_op_impl(op, opsize, rep)
            return
        ecx0 = self.regs[ECX] & MASK32
        self._string_op_impl(op, opsize, rep)
        self.prof.rep_elems += (ecx0 - (self.regs[ECX] & MASK32)) if rep else 1

    def _string_op_impl(self, op: int, opsize: int, rep: int) -> None:
        """执行串指令本体. rep 为 0 时执行一次; 否则按 ecx 计数循环。
        DF=1 时地址递减(memmove 反向拷贝要用)。"""
        size = 1 if op in (0xA4, 0xA6, 0xAA, 0xAC, 0xAE) else opsize
        back = bool(self.flags & DF)
        delta = -size if back else size
        regs = self.regs
        mem = self.mem

        if rep:
            cnt = regs[ECX] & MASK32
            if cnt == 0:
                return
        else:
            cnt = 1

        # movs 与 stos 在正向、无重叠时可整块搬, 一条指令一次 memcpy
        if not back and rep and op in (0xA4, 0xA5) and cnt > 1:
            n = cnt * size
            src, dst = regs[ESI] & MASK32, regs[EDI] & MASK32
            if abs(dst - src) >= n:                    # 无重叠才能整块搬
                mem.write(dst, mem.read(src, n))
                regs[ESI] = (src + n) & MASK32
                regs[EDI] = (dst + n) & MASK32
                regs[ECX] = 0
                return
        if not back and rep and op in (0xAA, 0xAB) and cnt > 1:
            val = self._read_reg(0, size)
            chunk = val.to_bytes(size, "little") * cnt
            dst = regs[EDI] & MASK32
            mem.write(dst, chunk)
            regs[EDI] = (dst + len(chunk)) & MASK32
            regs[ECX] = 0
            return

        while cnt:
            if op in (0xA4, 0xA5):                     # movs
                v = self._read_mem_sized(regs[ESI], size)
                self._write_mem_sized(regs[EDI], size, v)
                regs[ESI] = (regs[ESI] + delta) & MASK32
                regs[EDI] = (regs[EDI] + delta) & MASK32
            elif op in (0xAA, 0xAB):                   # stos
                self._write_mem_sized(regs[EDI], size, self._read_reg(0, size))
                regs[EDI] = (regs[EDI] + delta) & MASK32
            elif op in (0xAC, 0xAD):                   # lods
                self._write_reg(0, size,
                                self._read_mem_sized(regs[ESI], size))
                regs[ESI] = (regs[ESI] + delta) & MASK32
            elif op in (0xA6, 0xA7):                   # cmps
                a = self._read_mem_sized(regs[ESI], size)
                b = self._read_mem_sized(regs[EDI], size)
                self._set_sub_flags(a, b, a - b, size)
                regs[ESI] = (regs[ESI] + delta) & MASK32
                regs[EDI] = (regs[EDI] + delta) & MASK32
            elif op in (0xAE, 0xAF):                   # scas
                a = self._read_reg(0, size)
                b = self._read_mem_sized(regs[EDI], size)
                self._set_sub_flags(a, b, a - b, size)
                regs[EDI] = (regs[EDI] + delta) & MASK32
            else:
                self._bad(op, "字符串指令")
                return

            cnt -= 1
            if rep:
                regs[ECX] = cnt
                # cmps/scas 带 repe/repne 时按 ZF 提前结束
                if op in (0xA6, 0xA7, 0xAE, 0xAF):
                    zf = bool(self.flags & ZF)
                    if (rep == 0xF3 and not zf) or (rep == 0xF2 and zf):
                        return

    def _read_mem_sized(self, addr: int, size: int) -> int:
        if size == 1:
            return self.mem.read_u8(addr)
        if size == 2:
            return self.mem.read_u16(addr)
        return self.mem.read_u32(addr)

    def _write_mem_sized(self, addr: int, size: int, val: int) -> None:
        if size == 1:
            self.mem.write_u8(addr, val)
        elif size == 2:
            self.mem.write_u16(addr, val)
        else:
            self.mem.write_u32(addr, val)
