"""cpu86 与 x86mem 的单元测试.

不做文本汇编器, 用机器码构造函数库(asm 前缀的小函数)拼字节:
文本解析式汇编器要写词法与寻址语法, 两百多行且自身容易有 bug;
构造函数几行写完, 字节即文档。期望字节均已人工核对过编码。
"""

import struct
import unittest

import cpu86
import x86mem
from cpu86 import (AF, CF, CPU, DF, EAX, EBP, EBX, ECX, EDI, EDX, ESI, ESP,
                   OF, PF, SF, ZF, CpuError, DivideError)
from x86mem import AddressSpace, SegFault, TASK_SIZE


# ---------------------------------------------------------------------------
# 机器码构造函数库
# ---------------------------------------------------------------------------

def p32(v):
    return struct.pack("<I", v & 0xFFFFFFFF)


def p16(v):
    return struct.pack("<H", v & 0xFFFF)


def modrm(mod, reg, rm):
    return bytes([(mod << 6) | (reg << 3) | rm])


def rr(reg, rm):
    """mod=3 的 ModRM: 两个操作数都是寄存器."""
    return modrm(3, reg, rm)


def mov_ri(reg, imm):
    return bytes([0xB8 + reg]) + p32(imm)


def mov_r8i(reg, imm):
    return bytes([0xB0 + reg, imm & 0xFF])


def mov_rr(dst, src):
    return bytes([0x89]) + rr(src, dst)          # mov r/m32, r32


def mov_rm(dst, base, disp8):
    """mov dst, [base+disp8]"""
    return bytes([0x8B]) + modrm(1, dst, base) + bytes([disp8 & 0xFF])


def mov_mr(base, disp8, src):
    """mov [base+disp8], src"""
    return bytes([0x89]) + modrm(1, src, base) + bytes([disp8 & 0xFF])


def alu_rr(op, dst, src):
    """op: 0=add 1=or 2=adc 3=sbb 4=and 5=sub 6=xor 7=cmp; dst = op(dst, src)"""
    return bytes([(op << 3) | 1]) + rr(src, dst)


def alu_ri32(op, reg, imm):
    return bytes([0x81]) + rr(op, reg) + p32(imm)


def alu_ri8(op, reg, imm):
    """83 /op: 立即数是符号扩展的 imm8"""
    return bytes([0x83]) + rr(op, reg) + bytes([imm & 0xFF])


def lea(dst, base, disp8):
    return bytes([0x8D]) + modrm(1, dst, base) + bytes([disp8 & 0xFF])


def lea_sib(dst, base, index, scale, disp8):
    """lea dst, [base + index*2^scale + disp8]"""
    return (bytes([0x8D]) + modrm(1, dst, 4)
            + bytes([(scale << 6) | (index << 3) | base, disp8 & 0xFF]))


def inc_r(reg):
    return bytes([0x40 + reg])


def dec_r(reg):
    return bytes([0x48 + reg])


def push_r(reg):
    return bytes([0x50 + reg])


def pop_r(reg):
    return bytes([0x58 + reg])


def push_i32(imm):
    return bytes([0x68]) + p32(imm)


def push_i8(imm):
    return bytes([0x6A, imm & 0xFF])


def test_rr(a, b):
    return bytes([0x85]) + rr(b, a)


def not_r(reg):
    return bytes([0xF7]) + rr(2, reg)


def neg_r(reg):
    return bytes([0xF7]) + rr(3, reg)


def mul_r(reg):
    return bytes([0xF7]) + rr(4, reg)


def imul_r(reg):
    return bytes([0xF7]) + rr(5, reg)


def div_r(reg):
    return bytes([0xF7]) + rr(6, reg)


def idiv_r(reg):
    return bytes([0xF7]) + rr(7, reg)


def imul_rr(dst, src):
    return bytes([0x0F, 0xAF]) + rr(dst, src)


def cdq():
    return b"\x99"


def cwde():
    return b"\x98"


def shift_ri(op, reg, cnt):
    """op: 0=rol 1=ror 4=shl 5=shr 7=sar"""
    return bytes([0xC1]) + rr(op, reg) + bytes([cnt & 0xFF])


def shift_r1(op, reg):
    return bytes([0xD1]) + rr(op, reg)


def shift_rcl(op, reg):
    """按 CL 移位"""
    return bytes([0xD3]) + rr(op, reg)


def jcc(cond, rel8):
    return bytes([0x70 + cond, rel8 & 0xFF])


def jcc_near(cond, rel32):
    return bytes([0x0F, 0x80 + cond]) + p32(rel32)


def setcc(cond, reg):
    return bytes([0x0F, 0x90 + cond]) + rr(0, reg)


def jmp_rel8(rel):
    return bytes([0xEB, rel & 0xFF])


def jmp_rel32(rel):
    return bytes([0xE9]) + p32(rel)


def call_rel32(rel):
    return bytes([0xE8]) + p32(rel)


def ret():
    return b"\xc3"


def leave():
    return b"\xc9"


def movzx8(dst, src):
    return bytes([0x0F, 0xB6]) + rr(dst, src)


def movsx8(dst, src):
    return bytes([0x0F, 0xBE]) + rr(dst, src)


def movzx16(dst, src):
    return bytes([0x0F, 0xB7]) + rr(dst, src)


def movsx16(dst, src):
    return bytes([0x0F, 0xBF]) + rr(dst, src)


def xchg_rr(a, b):
    return bytes([0x87]) + rr(b, a)


def movsb():
    return b"\xa4"


def movsd_():
    return b"\xa5"


def stosb():
    return b"\xaa"


def stosd():
    return b"\xab"


def lodsb():
    return b"\xac"


def lodsd():
    return b"\xad"


def cmpsb():
    return b"\xa6"


def scasb():
    return b"\xae"


def rep(code):
    return b"\xf3" + code


def repne(code):
    return b"\xf2" + code


def bt_ri(reg, bit):
    return bytes([0x0F, 0xBA]) + rr(4, reg) + bytes([bit])


def bts_ri(reg, bit):
    return bytes([0x0F, 0xBA]) + rr(5, reg) + bytes([bit])


def btr_ri(reg, bit):
    return bytes([0x0F, 0xBA]) + rr(6, reg) + bytes([bit])


def bt_rr(rm, reg):
    return bytes([0x0F, 0xA3]) + rr(reg, rm)


def bsf(dst, src):
    return bytes([0x0F, 0xBC]) + rr(dst, src)


def bsr(dst, src):
    return bytes([0x0F, 0xBD]) + rr(dst, src)


def shld_ri(rm, reg, cnt):
    return bytes([0x0F, 0xA4]) + rr(reg, rm) + bytes([cnt])


def shrd_ri(rm, reg, cnt):
    return bytes([0x0F, 0xAC]) + rr(reg, rm) + bytes([cnt])


def loop(rel8):
    return bytes([0xE2, rel8 & 0xFF])


def jecxz(rel8):
    return bytes([0xE3, rel8 & 0xFF])


def xlat():
    return b"\xd7"


def sahf():
    return b"\x9e"


def lahf():
    return b"\x9f"


HLT = b"\xf4"
NOP = b"\x90"
INT80 = b"\xcd\x80"
CLD = b"\xfc"
STD = b"\xfd"
CLC = b"\xf8"
STC = b"\xf9"
PUSHF = b"\x9c"
POPF = b"\x9d"


def build_cpu(*chunks, regs=None, data_size=0x2000, on_int=None, on_fault=None):
    """把机器码装进地址空间, 返回未运行的 CPU."""
    code = b"".join(chunks)
    mem = AddressSpace(stack_size=0x4000)
    mem.load_program(code, b"", data_size)
    cpu = CPU(mem, on_int=on_int, on_fault=on_fault)
    cpu.regs[ESP] = TASK_SIZE - 16
    if regs:
        for name, val in regs.items():
            cpu.regs[cpu86.REG32_NAMES.index(name)] = val & 0xFFFFFFFF
    return cpu


def run_code(*chunks, regs=None, max_steps=200, **kw):
    """执行到 hlt(或步数上限), 返回 CPU 供断言."""
    cpu = build_cpu(*chunks, HLT, regs=regs, **kw)
    cpu.run(max_steps)
    return cpu


class FlagAsserts(unittest.TestCase):
    def assertFlags(self, cpu, cf=None, zf=None, sf=None, of=None,
                    pf=None, af=None):
        for name, bit, want in (("CF", CF, cf), ("ZF", ZF, zf), ("SF", SF, sf),
                                ("OF", OF, of), ("PF", PF, pf), ("AF", AF, af)):
            if want is None:
                continue
            got = bool(cpu.flags & bit)
            self.assertEqual(got, bool(want),
                             f"{name} 期望 {int(bool(want))} 实为 {int(got)} "
                             f"(flags={cpu.flags:#06x})")


# ---------------------------------------------------------------------------
# 地址空间
# ---------------------------------------------------------------------------

class TestAddressSpace(unittest.TestCase):
    def setUp(self):
        self.m = AddressSpace(stack_size=0x2000)
        self.m.load_program(b"\x01\x02\x03\x04", b"\xaa\xbb", 16)

    def test_load_layout(self):
        self.assertEqual(self.m.text_end, 4)
        self.assertEqual(self.m.low_end, 4 + 2 + 16)
        self.assertEqual(self.m.brk, 22)
        self.assertEqual(self.m.read(0, 6), b"\x01\x02\x03\x04\xaa\xbb")
        self.assertEqual(self.m.read(6, 16), bytes(16))   # bss 已清零

    def test_read_write_widths(self):
        self.m.write_u32(8, 0x12345678)
        self.assertEqual(self.m.read_u32(8), 0x12345678)
        self.assertEqual(self.m.read_u16(8), 0x5678)
        self.assertEqual(self.m.read_u8(8), 0x78)
        self.m.write_u16(8, 0xBEEF)
        self.assertEqual(self.m.read_u16(8), 0xBEEF)
        self.m.write_u8(8, 0x11)
        self.assertEqual(self.m.read_u8(8), 0x11)

    def test_stack_region(self):
        addr = TASK_SIZE - 8
        self.m.write_u32(addr, 0xCAFEBABE)
        self.assertEqual(self.m.read_u32(addr), 0xCAFEBABE)

    def test_segfault_in_hole(self):
        with self.assertRaises(SegFault) as ctx:
            self.m.read(0x100000, 4)
        self.assertFalse(ctx.exception.is_write)
        self.assertEqual(ctx.exception.addr, 0x100000)

    def test_segfault_beyond_task_size(self):
        with self.assertRaises(SegFault):
            self.m.read_u32(TASK_SIZE)

    def test_stack_auto_grow(self):
        below = self.m.stack_low - 32
        self.m.write_u32(below, 0xDEAD)      # 写空洞里靠近栈的位置 -> 自动扩栈
        self.assertEqual(self.m.read_u32(below), 0xDEAD)
        self.assertLessEqual(self.m.stack_low, below)

    def test_set_brk_semantics(self):
        # sys_brk: 合法则更新, 恒返回当前 brk
        old = self.m.brk
        self.assertEqual(self.m.set_brk(old + 4096), old + 4096)
        self.assertEqual(self.m.low_end, old + 4096)
        # 低于 text_end 非法, 返回旧值不变
        self.assertEqual(self.m.set_brk(1), old + 4096)
        # 太靠近栈顶非法
        self.assertEqual(self.m.set_brk(TASK_SIZE - 8), old + 4096)

    def test_clone_independent(self):
        self.m.write_u32(8, 0xAAAA)
        other = self.m.clone()
        other.write_u32(8, 0xBBBB)
        self.assertEqual(self.m.read_u32(8), 0xAAAA)
        self.assertEqual(other.read_u32(8), 0xBBBB)

    def test_read_cstr(self):
        self.m.write(8, b"hi\x00rest")
        self.assertEqual(self.m.read_cstr(8), b"hi")


# ---------------------------------------------------------------------------
# 基础数据移动与栈
# ---------------------------------------------------------------------------

class TestBasics(unittest.TestCase):
    def test_add_one_plus_one(self):
        # 方案里作为 M1 完成标志的最小用例
        cpu = run_code(mov_ri(EAX, 1), alu_ri8(0, EAX, 1))
        self.assertEqual(cpu.regs[EAX], 2)

    def test_mov_imm_and_reg(self):
        cpu = run_code(mov_ri(EBX, 0xDEADBEEF), mov_rr(ECX, EBX))
        self.assertEqual(cpu.regs[ECX], 0xDEADBEEF)

    def test_mov_r8_subregisters(self):
        cpu = run_code(mov_ri(EAX, 0x11223344),
                       mov_r8i(0, 0xAA),        # al
                       mov_r8i(4, 0xBB))        # ah
        self.assertEqual(cpu.regs[EAX], 0x1122BBAA)

    def test_reg8_high_of_ebx(self):
        cpu = run_code(mov_ri(EBX, 0), mov_r8i(7, 0x5A))   # bh
        self.assertEqual(cpu.regs[EBX], 0x5A00)

    def test_mov_memory_roundtrip(self):
        cpu = run_code(mov_ri(EBP, 0x1000), mov_ri(EAX, 0x12345678),
                       mov_mr(EBP, 8, EAX), mov_rm(ECX, EBP, 8))
        self.assertEqual(cpu.regs[ECX], 0x12345678)
        self.assertEqual(cpu.mem.read_u32(0x1008), 0x12345678)

    def test_push_pop(self):
        cpu = run_code(mov_ri(EAX, 0xAABBCCDD), push_r(EAX), pop_r(EBX))
        self.assertEqual(cpu.regs[EBX], 0xAABBCCDD)

    def test_push_imm8_sign_extends(self):
        cpu = run_code(push_i8(0xFF), pop_r(EAX))
        self.assertEqual(cpu.regs[EAX], 0xFFFFFFFF)

    def test_push_imm32(self):
        cpu = run_code(push_i32(0x1234), pop_r(EDX))
        self.assertEqual(cpu.regs[EDX], 0x1234)

    def test_xchg(self):
        cpu = run_code(mov_ri(EAX, 1), mov_ri(EBX, 2), xchg_rr(EAX, EBX))
        self.assertEqual((cpu.regs[EAX], cpu.regs[EBX]), (2, 1))

    def test_xchg_eax_shortform(self):
        cpu = run_code(mov_ri(EAX, 7), mov_ri(ECX, 9), b"\x91")   # xchg eax,ecx
        self.assertEqual((cpu.regs[EAX], cpu.regs[ECX]), (9, 7))

    def test_lea_no_flags_change(self):
        cpu = run_code(mov_ri(EBX, 0x100), lea(EAX, EBX, 0x10))
        self.assertEqual(cpu.regs[EAX], 0x110)

    def test_lea_sib_scaled_index(self):
        # lea eax, [ebx + ecx*4 + 8]
        cpu = run_code(mov_ri(EBX, 0x1000), mov_ri(ECX, 3),
                       lea_sib(EAX, EBX, ECX, 2, 8))
        self.assertEqual(cpu.regs[EAX], 0x1000 + 12 + 8)

    def test_leave(self):
        cpu = run_code(mov_ri(EAX, 0xBEEF), push_r(EAX),      # 假的旧 ebp
                       mov_rr(EBP, ESP), mov_ri(ESP, 0x1000),
                       mov_rr(ESP, EBP), leave())
        self.assertEqual(cpu.regs[EBP], 0xBEEF)

    def test_movzx_movsx(self):
        cpu = run_code(mov_ri(EBX, 0xFF), movzx8(EAX, EBX), movsx8(ECX, EBX))
        self.assertEqual(cpu.regs[EAX], 0xFF)
        self.assertEqual(cpu.regs[ECX], 0xFFFFFFFF)

    def test_movzx16_movsx16(self):
        cpu = run_code(mov_ri(EBX, 0x8000), movzx16(EAX, EBX), movsx16(ECX, EBX))
        self.assertEqual(cpu.regs[EAX], 0x8000)
        self.assertEqual(cpu.regs[ECX], 0xFFFF8000)

    def test_cwde_and_cdq(self):
        cpu = run_code(mov_ri(EAX, 0xFFFF), cwde())
        self.assertEqual(cpu.regs[EAX], 0xFFFFFFFF)
        cpu = run_code(mov_ri(EAX, 0x80000000), cdq())
        self.assertEqual(cpu.regs[EDX], 0xFFFFFFFF)
        cpu = run_code(mov_ri(EAX, 1), cdq())
        self.assertEqual(cpu.regs[EDX], 0)

    def test_operand_size_prefix_16bit(self):
        # 66 B8 imm16 = mov ax, imm16, 高 16 位保持不变
        cpu = run_code(mov_ri(EAX, 0xFFFFFFFF), b"\x66\xb8" + p16(0x1234))
        self.assertEqual(cpu.regs[EAX], 0xFFFF1234)

    def test_segment_prefix_ignored(self):
        cpu = run_code(b"\x2e" + mov_ri(EAX, 5))
        self.assertEqual(cpu.regs[EAX], 5)

    def test_moffs_forms(self):
        cpu = run_code(mov_ri(EAX, 0x99), b"\xa3" + p32(0x1000),  # mov [0x1000],eax
                       mov_ri(EAX, 0), b"\xa1" + p32(0x1000))     # mov eax,[0x1000]
        self.assertEqual(cpu.regs[EAX], 0x99)

    def test_mov_rm_imm(self):
        cpu = run_code(mov_ri(EBP, 0x1000),
                       b"\xc7" + modrm(1, 0, EBP) + b"\x04" + p32(0x7777))
        self.assertEqual(cpu.mem.read_u32(0x1004), 0x7777)

    def test_pop_rm(self):
        cpu = run_code(mov_ri(EBP, 0x1000), push_i32(0x4242),
                       b"\x8f" + modrm(1, 0, EBP) + b"\x08")
        self.assertEqual(cpu.mem.read_u32(0x1008), 0x4242)


# ---------------------------------------------------------------------------
# ModRM 寻址矩阵
# ---------------------------------------------------------------------------

class TestModRM(unittest.TestCase):
    def test_all_base_registers_mod01(self):
        """mod=01 各 base 寄存器(rm=4 走 SIB, rm=5 是 [ebp+disp8])."""
        for base in range(8):
            if base == ESP:            # rm=100 是 SIB, 单独测
                continue
            with self.subTest(base=cpu86.REG32_NAMES[base]):
                cpu = build_cpu(mov_ri(base, 0x1200),
                                mov_ri(EAX, 0xABCD) if base != EAX else b"",
                                bytes([0x89]) + modrm(1, EAX, base) + b"\x04",
                                HLT)
                if base == EAX:
                    cpu.regs[EAX] = 0x1200
                cpu.run(50)
                want = 0x1200 if base == EAX else 0xABCD
                self.assertEqual(cpu.mem.read_u32(0x1204), want)

    def test_sib_all_scales(self):
        for scale in range(4):
            with self.subTest(scale=scale):
                cpu = run_code(mov_ri(EBX, 0x1000), mov_ri(ESI, 2),
                               lea_sib(EAX, EBX, ESI, scale, 0))
                self.assertEqual(cpu.regs[EAX], 0x1000 + (2 << scale))

    def test_sib_no_index(self):
        # index=100(ESP) 表示无索引项
        cpu = run_code(mov_ri(EBX, 0x1000),
                       bytes([0x8D]) + modrm(1, EAX, 4)
                       + bytes([(0 << 6) | (4 << 3) | EBX, 0x10]))
        self.assertEqual(cpu.regs[EAX], 0x1010)

    def test_disp32_absolute(self):
        # mod=00 rm=101 是 disp32 绝对地址
        cpu = run_code(mov_ri(EAX, 0x55),
                       bytes([0x89]) + modrm(0, EAX, 5) + p32(0x1500))
        self.assertEqual(cpu.mem.read_u32(0x1500), 0x55)

    def test_mod10_disp32(self):
        cpu = run_code(mov_ri(EBX, 0x1000), mov_ri(EAX, 0x66),
                       bytes([0x89]) + modrm(2, EAX, EBX) + p32(0x200))
        self.assertEqual(cpu.mem.read_u32(0x1200), 0x66)

    def test_sib_base_ebp_mod00_uses_disp32(self):
        # SIB base=101 且 mod=00 时 base 换成 disp32
        cpu = run_code(mov_ri(ESI, 4),
                       bytes([0x8D]) + modrm(0, EAX, 4)
                       + bytes([(1 << 6) | (ESI << 3) | 5]) + p32(0x1400))
        self.assertEqual(cpu.regs[EAX], 0x1400 + 8)

    def test_lea_on_register_operand_errors(self):
        cpu = build_cpu(bytes([0x8D]) + rr(EAX, EBX), HLT)
        with self.assertRaises(CpuError):
            cpu.step()


# ---------------------------------------------------------------------------
# ALU 与标志位
# ---------------------------------------------------------------------------

class TestAlu(FlagAsserts):
    def test_all_eight_ops(self):
        cases = [(0, 10, 3, 13), (1, 0b1010, 0b0101, 0b1111),
                 (4, 0b1100, 0b1010, 0b1000), (5, 10, 3, 7),
                 (6, 0b1100, 0b1010, 0b0110)]
        for op, a, b, want in cases:
            with self.subTest(op=op):
                cpu = run_code(mov_ri(EAX, a), mov_ri(EBX, b),
                               alu_rr(op, EAX, EBX))
                self.assertEqual(cpu.regs[EAX], want)

    def test_cmp_does_not_write_back(self):
        cpu = run_code(mov_ri(EAX, 5), mov_ri(EBX, 5), alu_rr(7, EAX, EBX))
        self.assertEqual(cpu.regs[EAX], 5)
        self.assertFlags(cpu, zf=1, cf=0)

    def test_adc_sbb_carry_chain(self):
        # 64 位加法: (0xFFFFFFFF + 1) 产生进位, adc 把它带上
        cpu = run_code(mov_ri(EAX, 0xFFFFFFFF), mov_ri(EBX, 1),
                       mov_ri(ECX, 0), mov_ri(EDX, 0),
                       alu_rr(0, EAX, EBX),        # add eax, ebx -> CF=1
                       alu_rr(2, ECX, EDX))        # adc ecx, edx -> ecx=1
        self.assertEqual(cpu.regs[EAX], 0)
        self.assertEqual(cpu.regs[ECX], 1)

    def test_sbb_borrow(self):
        cpu = run_code(mov_ri(EAX, 0), mov_ri(EBX, 1),
                       alu_rr(5, EAX, EBX),        # sub -> CF=1
                       mov_ri(ECX, 5), mov_ri(EDX, 0),
                       alu_rr(3, ECX, EDX))        # sbb ecx,edx -> 5-0-1=4
        self.assertEqual(cpu.regs[ECX], 4)

    def test_imm8_sign_extension(self):
        # 83 /0 的 imm8 = 0xFF 应符号扩展为 -1
        cpu = run_code(mov_ri(EAX, 10), alu_ri8(0, EAX, 0xFF))
        self.assertEqual(cpu.regs[EAX], 9)

    def test_imm32_form(self):
        cpu = run_code(mov_ri(EAX, 1), alu_ri32(0, EAX, 0x10000))
        self.assertEqual(cpu.regs[EAX], 0x10001)

    def test_byte_alu_forms(self):
        cpu = run_code(mov_ri(EAX, 0x1F), mov_ri(EBX, 0x01),
                       bytes([0x00]) + rr(EBX, EAX))    # add al, bl
        self.assertEqual(cpu.regs[EAX] & 0xFF, 0x20)

    def test_alu_memory_destination(self):
        cpu = run_code(mov_ri(EBP, 0x1000), mov_ri(EAX, 100),
                       mov_mr(EBP, 0, EAX), mov_ri(EBX, 23),
                       bytes([0x01]) + modrm(1, EBX, EBP) + b"\x00")  # add [ebp],ebx
        self.assertEqual(cpu.mem.read_u32(0x1000), 123)

    # ---- 标志位边界 ----

    def test_overflow_positive(self):
        cpu = run_code(mov_ri(EAX, 0x7FFFFFFF), alu_ri8(0, EAX, 1))
        self.assertFlags(cpu, of=1, cf=0, sf=1, zf=0)

    def test_overflow_negative(self):
        cpu = run_code(mov_ri(EAX, 0x80000000), alu_ri8(5, EAX, 1))
        self.assertFlags(cpu, of=1, sf=0)

    def test_borrow(self):
        cpu = run_code(mov_ri(EAX, 0), alu_ri8(5, EAX, 1))
        self.assertFlags(cpu, cf=1, sf=1, of=0)
        self.assertEqual(cpu.regs[EAX], 0xFFFFFFFF)

    def test_carry_and_zero(self):
        cpu = run_code(mov_ri(EAX, 0xFFFFFFFF), alu_ri8(0, EAX, 1))
        self.assertFlags(cpu, cf=1, zf=1, sf=0, of=0)

    def test_neg_flags(self):
        cpu = run_code(mov_ri(EAX, 0), neg_r(EAX))
        self.assertFlags(cpu, cf=0, zf=1)
        cpu = run_code(mov_ri(EAX, 5), neg_r(EAX))
        self.assertEqual(cpu.regs[EAX], 0xFFFFFFFB)
        self.assertFlags(cpu, cf=1)
        cpu = run_code(mov_ri(EAX, 0x80000000), neg_r(EAX))
        self.assertFlags(cpu, of=1, cf=1)

    def test_not_preserves_flags(self):
        cpu = run_code(mov_ri(EAX, 0), alu_ri8(5, EAX, 1),   # 置 CF
                       mov_ri(EBX, 0xF0F0), not_r(EBX))
        self.assertEqual(cpu.regs[EBX], 0xFFFF0F0F)
        self.assertFlags(cpu, cf=1)                          # not 不动标志

    def test_inc_dec_preserve_cf(self):
        cpu = run_code(mov_ri(EAX, 0), alu_ri8(5, EAX, 1),   # sub -> CF=1
                       mov_ri(EBX, 5), inc_r(EBX))
        self.assertEqual(cpu.regs[EBX], 6)
        self.assertFlags(cpu, cf=1)                          # CF 未被 inc 改动
        cpu = run_code(mov_ri(EAX, 1), alu_ri8(5, EAX, 1),   # sub -> CF=0, ZF=1
                       mov_ri(EBX, 5), dec_r(EBX))
        self.assertFlags(cpu, cf=0)

    def test_inc_overflow_still_set(self):
        cpu = run_code(mov_ri(EAX, 0x7FFFFFFF), inc_r(EAX))
        self.assertFlags(cpu, of=1, sf=1)

    def test_parity_low_byte_only(self):
        # 0x100 的低 8 位是 0 -> 1 的个数为偶 -> PF=1
        cpu = run_code(mov_ri(EAX, 0xFF), alu_ri8(0, EAX, 1))
        self.assertFlags(cpu, pf=1)
        # 0x01 低 8 位一个 1 -> PF=0
        cpu = run_code(mov_ri(EAX, 0), alu_ri8(0, EAX, 1))
        self.assertFlags(cpu, pf=0)

    def test_af_nibble_carry(self):
        cpu = run_code(mov_ri(EAX, 0x0F), alu_ri8(0, EAX, 1))
        self.assertFlags(cpu, af=1)
        cpu = run_code(mov_ri(EAX, 0x01), alu_ri8(0, EAX, 1))
        self.assertFlags(cpu, af=0)

    def test_logic_ops_clear_cf_of(self):
        cpu = run_code(mov_ri(EAX, 0x7FFFFFFF), alu_ri8(0, EAX, 1),   # OF=1
                       mov_ri(EBX, 0xFF), alu_ri32(4, EBX, 0x0F))     # and
        self.assertFlags(cpu, cf=0, of=0)
        self.assertEqual(cpu.regs[EBX], 0x0F)

    def test_test_sets_flags_without_write(self):
        cpu = run_code(mov_ri(EAX, 0xF0), mov_ri(EBX, 0x0F), test_rr(EAX, EBX))
        self.assertEqual(cpu.regs[EAX], 0xF0)
        self.assertFlags(cpu, zf=1, cf=0, of=0)

    def test_test_imm_forms(self):
        cpu = run_code(mov_ri(EAX, 0x80), b"\xa8\x80")      # test al, 0x80
        self.assertFlags(cpu, zf=0, sf=1)
        cpu = run_code(mov_ri(EAX, 1), b"\xa9" + p32(2))    # test eax, 2
        self.assertFlags(cpu, zf=1)

    def test_16bit_alu_flags(self):
        # 66 前缀下按 16 位算标志: 0xFFFF+1 -> CF=1 ZF=1
        cpu = run_code(mov_ri(EAX, 0xFFFF), b"\x66" + alu_ri8(0, EAX, 1))
        self.assertFlags(cpu, cf=1, zf=1)

    def test_clc_stc(self):
        cpu = run_code(STC)
        self.assertFlags(cpu, cf=1)
        cpu = run_code(STC, CLC)
        self.assertFlags(cpu, cf=0)

    def test_pushf_popf_roundtrip(self):
        cpu = run_code(STC, PUSHF, CLC, POPF)
        self.assertFlags(cpu, cf=1)


# ---------------------------------------------------------------------------
# 乘除法
# ---------------------------------------------------------------------------

class TestMulDiv(FlagAsserts):
    def test_mul_unsigned(self):
        cpu = run_code(mov_ri(EAX, 0x10000), mov_ri(EBX, 0x10000), mul_r(EBX))
        self.assertEqual(cpu.regs[EAX], 0)
        self.assertEqual(cpu.regs[EDX], 1)
        self.assertFlags(cpu, cf=1, of=1)

    def test_mul_no_overflow_clears_cf(self):
        cpu = run_code(mov_ri(EAX, 3), mov_ri(EBX, 4), mul_r(EBX))
        self.assertEqual((cpu.regs[EAX], cpu.regs[EDX]), (12, 0))
        self.assertFlags(cpu, cf=0, of=0)

    def test_imul_signed_negative(self):
        cpu = run_code(mov_ri(EAX, 0xFFFFFFFF),      # -1
                       mov_ri(EBX, 5), imul_r(EBX))
        self.assertEqual(cpu.regs[EAX], 0xFFFFFFFB)  # -5
        self.assertEqual(cpu.regs[EDX], 0xFFFFFFFF)

    def test_imul_three_operand_imm32(self):
        """69 /r imm32 —— 真实的 /bin/init 里就用了这条."""
        cpu = run_code(mov_ri(EBX, 20),
                       bytes([0x69]) + rr(EAX, EBX) + p32(276))   # imul eax,ebx,276
        self.assertEqual(cpu.regs[EAX], 20 * 276)

    def test_imul_three_operand_negative_imm(self):
        cpu = run_code(mov_ri(EBX, 5),
                       bytes([0x69]) + rr(EAX, EBX) + p32(0xFFFFFFFF))  # imm = -1
        self.assertEqual(cpu.regs[EAX], 0xFFFFFFFB)               # -5

    def test_imul_three_operand_imm8(self):
        cpu = run_code(mov_ri(EBX, 7),
                       bytes([0x6B]) + rr(EAX, EBX) + b"\x03")    # imul eax,ebx,3
        self.assertEqual(cpu.regs[EAX], 21)

    def test_imul_three_operand_imm8_sign_extends(self):
        cpu = run_code(mov_ri(EBX, 4),
                       bytes([0x6B]) + rr(EAX, EBX) + b"\xff")    # imm = -1
        self.assertEqual(cpu.regs[EAX], 0xFFFFFFFC)               # -4

    def test_imul_three_operand_overflow_flags(self):
        cpu = run_code(mov_ri(EBX, 0x10000),
                       bytes([0x69]) + rr(EAX, EBX) + p32(0x10000))
        self.assertFlags(cpu, cf=1, of=1)

    def test_imul_three_operand_memory_source(self):
        cpu = run_code(mov_ri(EBP, 0x1000), mov_ri(ECX, 9), mov_mr(EBP, 4, ECX),
                       bytes([0x6B]) + modrm(1, EAX, EBP) + b"\x04\x02")
        self.assertEqual(cpu.regs[EAX], 18)

    def test_imul_two_operand(self):
        cpu = run_code(mov_ri(EAX, 0xFFFFFFFE), mov_ri(EBX, 3),
                       imul_rr(EAX, EBX))
        self.assertEqual(cpu.regs[EAX], 0xFFFFFFFA)  # -6

    def test_div_unsigned(self):
        cpu = run_code(mov_ri(EAX, 17), mov_ri(EDX, 0),
                       mov_ri(EBX, 5), div_r(EBX))
        self.assertEqual((cpu.regs[EAX], cpu.regs[EDX]), (3, 2))

    def test_idiv_truncates_toward_zero(self):
        # -7 / 2 在 x86 上是 -3 余 -1(向零取整), 不是 Python 的 -4 余 1
        cpu = run_code(mov_ri(EAX, 0xFFFFFFF9), cdq(),
                       mov_ri(EBX, 2), idiv_r(EBX))
        self.assertEqual(cpu.regs[EAX], 0xFFFFFFFD)   # -3
        self.assertEqual(cpu.regs[EDX], 0xFFFFFFFF)   # -1

    def test_idiv_negative_divisor(self):
        cpu = run_code(mov_ri(EAX, 7), cdq(),
                       mov_ri(EBX, 0xFFFFFFFE), idiv_r(EBX))   # 7 / -2
        self.assertEqual(cpu.regs[EAX], 0xFFFFFFFD)   # -3
        self.assertEqual(cpu.regs[EDX], 1)

    def test_divide_by_zero_raises(self):
        cpu = build_cpu(mov_ri(EAX, 1), mov_ri(EDX, 0), mov_ri(EBX, 0),
                        div_r(EBX), HLT)
        with self.assertRaises(DivideError):
            cpu.run(10)

    def test_divide_overflow_raises(self):
        cpu = build_cpu(mov_ri(EAX, 0), mov_ri(EDX, 1), mov_ri(EBX, 1),
                        div_r(EBX), HLT)
        with self.assertRaises(DivideError):
            cpu.run(10)

    def test_divide_error_goes_to_on_fault(self):
        seen = []
        cpu = build_cpu(mov_ri(EBX, 0), div_r(EBX), HLT,
                        on_fault=lambda c, e: seen.append(e))
        cpu.run(10)
        self.assertEqual(len(seen), 1)
        self.assertIsInstance(seen[0], DivideError)

    def test_mul_8bit(self):
        cpu = run_code(mov_r8i(0, 10), mov_r8i(3, 20),
                       bytes([0xF6]) + rr(4, EBX))       # mul bl
        self.assertEqual(cpu.regs[EAX] & 0xFFFF, 200)


# ---------------------------------------------------------------------------
# 移位
# ---------------------------------------------------------------------------

class TestShifts(FlagAsserts):
    def test_shl(self):
        cpu = run_code(mov_ri(EAX, 1), shift_ri(4, EAX, 4))
        self.assertEqual(cpu.regs[EAX], 16)

    def test_shl_carry_out(self):
        cpu = run_code(mov_ri(EAX, 0x80000000), shift_ri(4, EAX, 1))
        self.assertEqual(cpu.regs[EAX], 0)
        self.assertFlags(cpu, cf=1, zf=1)

    def test_shr(self):
        cpu = run_code(mov_ri(EAX, 0x80000000), shift_ri(5, EAX, 31))
        self.assertEqual(cpu.regs[EAX], 1)

    def test_sar_sign_extends(self):
        cpu = run_code(mov_ri(EAX, 0xFFFFFFF0), shift_ri(7, EAX, 4))
        self.assertEqual(cpu.regs[EAX], 0xFFFFFFFF)

    def test_sar_carry_is_shifted_out_bit(self):
        cpu = run_code(mov_ri(EAX, 0b11), shift_ri(7, EAX, 1))
        self.assertEqual(cpu.regs[EAX], 1)
        self.assertFlags(cpu, cf=1)

    def test_shift_count_masked_to_31(self):
        # 计数 33 & 31 = 1
        cpu = run_code(mov_ri(EAX, 1), shift_ri(4, EAX, 33))
        self.assertEqual(cpu.regs[EAX], 2)

    def test_shift_by_zero_preserves_flags(self):
        cpu = run_code(mov_ri(EAX, 0), alu_ri8(5, EAX, 1),   # CF=1
                       mov_ri(EBX, 8), shift_ri(4, EBX, 0))
        self.assertEqual(cpu.regs[EBX], 8)
        self.assertFlags(cpu, cf=1)

    def test_shift_by_one_opcode_d1(self):
        cpu = run_code(mov_ri(EAX, 5), shift_r1(4, EAX))
        self.assertEqual(cpu.regs[EAX], 10)

    def test_shift_by_cl(self):
        cpu = run_code(mov_ri(EAX, 1), mov_ri(ECX, 8), shift_rcl(4, EAX))
        self.assertEqual(cpu.regs[EAX], 256)

    def test_rol_ror(self):
        cpu = run_code(mov_ri(EAX, 0x80000001), shift_ri(0, EAX, 1))   # rol
        self.assertEqual(cpu.regs[EAX], 3)
        cpu = run_code(mov_ri(EAX, 3), shift_ri(1, EAX, 1))            # ror
        self.assertEqual(cpu.regs[EAX], 0x80000001)

    def test_shift_8bit(self):
        cpu = run_code(mov_ri(EAX, 0x1234), bytes([0xC0]) + rr(4, 0) + b"\x04")
        self.assertEqual(cpu.regs[EAX] & 0xFF, 0x40)     # 0x34 << 4 = 0x340 -> 0x40


# ---------------------------------------------------------------------------
# 控制流
# ---------------------------------------------------------------------------

class TestControlFlow(unittest.TestCase):
    def test_jz_taken(self):
        cpu = run_code(mov_ri(EAX, 0), test_rr(EAX, EAX),
                       jcc(4, 5),                  # jz +5 跳过下一条 mov(5 字节)
                       mov_ri(EAX, 0xBAD))
        self.assertEqual(cpu.regs[EAX], 0)

    def test_jz_not_taken(self):
        cpu = run_code(mov_ri(EAX, 1), test_rr(EAX, EAX),
                       jcc(4, 5), mov_ri(EAX, 0x777))
        self.assertEqual(cpu.regs[EAX], 0x777)

    def test_all_16_conditions_consistent(self):
        """每个条件码与其反码恰好一个成立."""
        for base in range(0, 16, 2):
            for a, b in ((1, 2), (2, 1), (5, 5), (0x80000000, 1)):
                with self.subTest(cond=base, a=a, b=b):
                    pre = (mov_ri(EAX, a), mov_ri(EBX, b), alu_rr(7, EAX, EBX))
                    t = run_code(*pre, setcc(base, ECX)).regs[ECX]
                    f = run_code(*pre, setcc(base + 1, ECX)).regs[ECX]
                    self.assertEqual(t + f, 1)

    def test_signed_vs_unsigned_comparison(self):
        # -1 vs 1: 无符号看 0xFFFFFFFF > 1(CF=0), 有符号看 -1 < 1(SF!=OF)
        pre = (mov_ri(EAX, 0xFFFFFFFF), mov_ri(EBX, 1), alu_rr(7, EAX, EBX))
        self.assertEqual(run_code(*pre, setcc(0x7, ECX)).regs[ECX], 1)  # seta
        self.assertEqual(run_code(*pre, setcc(0xC, ECX)).regs[ECX], 1)  # setl

    def test_jcc_near_rel32(self):
        cpu = run_code(mov_ri(EAX, 0), test_rr(EAX, EAX),
                       jcc_near(4, 5), mov_ri(EAX, 0xBAD))
        self.assertEqual(cpu.regs[EAX], 0)

    def test_jcc_backward_loop(self):
        # 数到 5: mov ecx,5; dec ecx; jnz -3
        cpu = run_code(mov_ri(ECX, 5), dec_r(ECX), jcc(5, -3))
        self.assertEqual(cpu.regs[ECX], 0)

    def test_jmp_short_and_near(self):
        cpu = run_code(jmp_rel8(5), mov_ri(EAX, 0xBAD), mov_ri(EAX, 1))
        self.assertEqual(cpu.regs[EAX], 1)
        cpu = run_code(jmp_rel32(5), mov_ri(EAX, 0xBAD), mov_ri(EAX, 2))
        self.assertEqual(cpu.regs[EAX], 2)

    def test_call_ret(self):
        # call +1(跳过 hlt 落到子程序), 子程序设 eax 后 ret
        cpu = build_cpu(call_rel32(1), HLT, mov_ri(EAX, 0x1234), ret())
        cpu.run(20)
        self.assertEqual(cpu.regs[EAX], 0x1234)
        self.assertTrue(cpu.halted)

    def test_ret_imm16_pops_args(self):
        cpu = build_cpu(push_i32(9), call_rel32(1), HLT,
                        b"\xc2" + p16(4))       # ret 4
        sp_before = cpu.regs[ESP]
        cpu.run(20)
        self.assertEqual(cpu.regs[ESP], sp_before)   # 参数已被 ret 4 弹掉

    def test_call_indirect_via_register(self):
        cpu = build_cpu(mov_ri(EBX, 12), bytes([0xFF]) + rr(2, EBX), HLT,
                        NOP * 4, mov_ri(EAX, 0x55), ret())
        # 目标地址 12 需与代码布局一致: 5(mov) + 2(call ff d3) + 1(hlt) + 4(nop) = 12
        cpu.run(20)
        self.assertEqual(cpu.regs[EAX], 0x55)

    def test_jmp_indirect(self):
        cpu = build_cpu(mov_ri(EBX, 9), bytes([0xFF]) + rr(4, EBX),
                        HLT, NOP, mov_ri(EAX, 0x66), HLT)
        cpu.run(20)
        self.assertEqual(cpu.regs[EAX], 0x66)

    def test_push_rm_memory(self):
        cpu = run_code(mov_ri(EBP, 0x1000), mov_ri(EAX, 0x321),
                       mov_mr(EBP, 0, EAX),
                       bytes([0xFF]) + modrm(1, 6, EBP) + b"\x00",
                       pop_r(ECX))
        self.assertEqual(cpu.regs[ECX], 0x321)


# ---------------------------------------------------------------------------
# 字符串指令
# ---------------------------------------------------------------------------

class TestStringOps(FlagAsserts):
    def _cpu_with_data(self, *chunks, src=b"", regs=None):
        cpu = build_cpu(*chunks, HLT, regs=regs)
        if src:
            cpu.mem.write(0x1000, src)
        return cpu

    def test_movsb_single(self):
        cpu = self._cpu_with_data(movsb(), src=b"XY",
                                  regs={"esi": 0x1000, "edi": 0x1100})
        cpu.run(10)
        self.assertEqual(cpu.mem.read(0x1100, 1), b"X")
        self.assertEqual((cpu.regs[ESI], cpu.regs[EDI]), (0x1001, 0x1101))

    def test_movsb_backward_when_df_set(self):
        cpu = self._cpu_with_data(STD, movsb(), src=b"XY",
                                  regs={"esi": 0x1000, "edi": 0x1100})
        cpu.run(10)
        self.assertEqual((cpu.regs[ESI], cpu.regs[EDI]), (0x0FFF, 0x10FF))

    def test_rep_movsb_copies_block(self):
        data = bytes(range(64))
        cpu = self._cpu_with_data(rep(movsb()), src=data,
                                  regs={"esi": 0x1000, "edi": 0x1200,
                                        "ecx": 64})
        cpu.run(10)
        self.assertEqual(cpu.mem.read(0x1200, 64), data)
        self.assertEqual(cpu.regs[ECX], 0)

    def test_rep_movsd_copies_dwords(self):
        data = struct.pack("<4I", 1, 2, 3, 4)
        cpu = self._cpu_with_data(rep(movsd_()), src=data,
                                  regs={"esi": 0x1000, "edi": 0x1200,
                                        "ecx": 4})
        cpu.run(10)
        self.assertEqual(cpu.mem.read(0x1200, 16), data)
        self.assertEqual((cpu.regs[ESI], cpu.regs[EDI]), (0x1010, 0x1210))

    def test_rep_movs_fast_path_matches_slow_path(self):
        """整块搬的快路径与逐条慢路径(DF=1 反向)结果必须一致."""
        data = bytes((i * 7) & 0xFF for i in range(32))
        fast = self._cpu_with_data(rep(movsb()), src=data,
                                   regs={"esi": 0x1000, "edi": 0x1200,
                                         "ecx": 32})
        fast.run(10)
        # 反向: 从末字节开始, 目标也从末字节开始, 结果应完全相同
        slow = self._cpu_with_data(STD, rep(movsb()), src=data,
                                   regs={"esi": 0x1000 + 31, "edi": 0x1200 + 31,
                                         "ecx": 32})
        slow.run(10)
        self.assertEqual(fast.mem.read(0x1200, 32), data)
        self.assertEqual(slow.mem.read(0x1200, 32), data)

    def test_rep_movs_overlapping_uses_slow_path(self):
        # 目标与源重叠 1 字节: 必须逐条搬(会产生字节复制效果), 不能整块搬
        cpu = self._cpu_with_data(rep(movsb()), src=b"AB" + bytes(8),
                                  regs={"esi": 0x1000, "edi": 0x1001,
                                        "ecx": 4})
        cpu.run(10)
        # 逐条: [1001]=A, [1002]=B(此时源已是刚写的?) —— x86 语义是逐字节顺序搬
        self.assertEqual(cpu.mem.read(0x1000, 5), b"AAAAA")

    def test_rep_with_zero_count_is_noop(self):
        cpu = self._cpu_with_data(rep(movsb()), src=b"XY",
                                  regs={"esi": 0x1000, "edi": 0x1100,
                                        "ecx": 0})
        cpu.run(10)
        self.assertEqual(cpu.mem.read(0x1100, 1), b"\x00")
        self.assertEqual(cpu.regs[ESI], 0x1000)

    def test_rep_stosb_fills(self):
        cpu = build_cpu(mov_r8i(0, 0x41), rep(stosb()), HLT,
                        regs={"edi": 0x1000, "ecx": 10})
        cpu.run(10)
        self.assertEqual(cpu.mem.read(0x1000, 11), b"A" * 10 + b"\x00")

    def test_rep_stosd_fills_dwords(self):
        cpu = build_cpu(mov_ri(EAX, 0xDEADBEEF), rep(stosd()), HLT,
                        regs={"edi": 0x1000, "ecx": 3})
        cpu.run(10)
        self.assertEqual(cpu.mem.read(0x1000, 12),
                         struct.pack("<3I", 0xDEADBEEF, 0xDEADBEEF, 0xDEADBEEF))

    def test_lodsb_and_lodsd(self):
        cpu = self._cpu_with_data(lodsb(), src=b"\x5a", regs={"esi": 0x1000})
        cpu.run(10)
        self.assertEqual(cpu.regs[EAX] & 0xFF, 0x5A)
        cpu = self._cpu_with_data(lodsd(), src=p32(0x11223344),
                                  regs={"esi": 0x1000})
        cpu.run(10)
        self.assertEqual(cpu.regs[EAX], 0x11223344)

    def test_cmpsb_sets_flags(self):
        cpu = build_cpu(cmpsb(), HLT, regs={"esi": 0x1000, "edi": 0x1100})
        cpu.mem.write(0x1000, b"A")
        cpu.mem.write(0x1100, b"A")
        cpu.run(10)
        self.assertFlags(cpu, zf=1)

    def test_repe_cmpsb_stops_at_difference(self):
        # 比较 "abcXef" 与 "abcYef": 在第 4 字节不等时停下
        cpu = build_cpu(rep(cmpsb()), HLT,
                        regs={"esi": 0x1000, "edi": 0x1100, "ecx": 6})
        cpu.mem.write(0x1000, b"abcXef")
        cpu.mem.write(0x1100, b"abcYef")
        cpu.run(10)
        self.assertFlags(cpu, zf=0)
        self.assertEqual(cpu.regs[ECX], 2)      # 消耗了 4 次, 剩 2
        self.assertEqual(cpu.regs[ESI], 0x1004)

    def test_repe_cmpsb_full_match(self):
        cpu = build_cpu(rep(cmpsb()), HLT,
                        regs={"esi": 0x1000, "edi": 0x1100, "ecx": 3})
        cpu.mem.write(0x1000, b"abc")
        cpu.mem.write(0x1100, b"abc")
        cpu.run(10)
        self.assertFlags(cpu, zf=1)
        self.assertEqual(cpu.regs[ECX], 0)

    def test_repne_scasb_finds_byte(self):
        # 经典 strlen: 在 "hello\0" 里找 0
        cpu = build_cpu(mov_r8i(0, 0), repne(scasb()), HLT,
                        regs={"edi": 0x1000, "ecx": 0xFFFF})
        cpu.mem.write(0x1000, b"hello\x00")
        cpu.run(10)
        # edi 停在 0 字节之后, 长度 = 扫过的字节数 - 1
        self.assertEqual(cpu.regs[EDI], 0x1006)
        self.assertEqual(0xFFFF - cpu.regs[ECX] - 1, 5)

    def test_scasb_single(self):
        cpu = build_cpu(mov_r8i(0, 0x41), scasb(), HLT, regs={"edi": 0x1000})
        cpu.mem.write(0x1000, b"A")
        cpu.run(10)
        self.assertFlags(cpu, zf=1)

    def test_16bit_movs_with_prefix(self):
        cpu = self._cpu_with_data(b"\x66" + movsd_(), src=p16(0xBEEF),
                                  regs={"esi": 0x1000, "edi": 0x1100})
        cpu.run(10)
        self.assertEqual(cpu.mem.read_u16(0x1100), 0xBEEF)
        self.assertEqual(cpu.regs[ESI], 0x1002)

    def test_cld_std_control_direction(self):
        cpu = run_code(STD)
        self.assertTrue(cpu.flags & DF)
        cpu = run_code(STD, CLD)
        self.assertFalse(cpu.flags & DF)

    def test_string_op_preserves_df_across_alu(self):
        # ALU 指令不应清掉 DF
        cpu = run_code(STD, mov_ri(EAX, 1), alu_ri8(0, EAX, 1))
        self.assertTrue(cpu.flags & DF)


# ---------------------------------------------------------------------------
# 位操作与其余第二批指令
# ---------------------------------------------------------------------------

class TestBitOps(FlagAsserts):
    def test_bt_reads_bit(self):
        cpu = run_code(mov_ri(EAX, 0b1000), bt_ri(EAX, 3))
        self.assertFlags(cpu, cf=1)
        cpu = run_code(mov_ri(EAX, 0b1000), bt_ri(EAX, 2))
        self.assertFlags(cpu, cf=0)

    def test_bts_sets_bit(self):
        cpu = run_code(mov_ri(EAX, 0), bts_ri(EAX, 5))
        self.assertEqual(cpu.regs[EAX], 0b100000)
        self.assertFlags(cpu, cf=0)

    def test_btr_clears_bit(self):
        cpu = run_code(mov_ri(EAX, 0xFF), btr_ri(EAX, 0))
        self.assertEqual(cpu.regs[EAX], 0xFE)
        self.assertFlags(cpu, cf=1)

    def test_bt_register_form_masks_count(self):
        # 寄存器形式对寄存器操作数取模 32
        cpu = run_code(mov_ri(EAX, 1), mov_ri(EBX, 32), bt_rr(EAX, EBX))
        self.assertFlags(cpu, cf=1)         # 32 & 31 = 0, 第 0 位是 1

    def test_bsf_bsr(self):
        cpu = run_code(mov_ri(EBX, 0b101000), bsf(EAX, EBX), bsr(ECX, EBX))
        self.assertEqual(cpu.regs[EAX], 3)
        self.assertEqual(cpu.regs[ECX], 5)

    def test_bsf_zero_sets_zf(self):
        cpu = run_code(mov_ri(EAX, 0xFF), mov_ri(EBX, 0), bsf(EAX, EBX))
        self.assertFlags(cpu, zf=1)
        self.assertEqual(cpu.regs[EAX], 0xFF)   # 源为 0 时目标不变

    def test_shld_shrd(self):
        cpu = run_code(mov_ri(EAX, 0xF0000000), mov_ri(EBX, 0x0000000F),
                       shld_ri(EAX, EBX, 4))
        self.assertEqual(cpu.regs[EAX], 0x00000000)
        cpu = run_code(mov_ri(EAX, 0x0000000F), mov_ri(EBX, 0xF0000000),
                       shrd_ri(EAX, EBX, 4))
        self.assertEqual(cpu.regs[EAX], 0x00000000)

    def test_shrd_shifts_in_from_src(self):
        cpu = run_code(mov_ri(EAX, 0x10), mov_ri(EBX, 0xFFFFFFFF),
                       shrd_ri(EAX, EBX, 4))
        self.assertEqual(cpu.regs[EAX], 0xF0000001)

    def test_loop_counts_down(self):
        cpu = run_code(mov_ri(ECX, 5), mov_ri(EAX, 0),
                       inc_r(EAX), loop(-3))
        self.assertEqual(cpu.regs[EAX], 5)
        self.assertEqual(cpu.regs[ECX], 0)

    def test_jecxz(self):
        cpu = run_code(mov_ri(ECX, 0), jecxz(5), mov_ri(EAX, 0xBAD))
        self.assertEqual(cpu.regs[EAX], 0)

    def test_xlat(self):
        cpu = build_cpu(mov_ri(EBX, 0x1000), mov_r8i(0, 2), xlat(), HLT)
        cpu.mem.write(0x1000, b"\x10\x20\x30\x40")
        cpu.run(10)
        self.assertEqual(cpu.regs[EAX] & 0xFF, 0x30)

    def test_sahf_lahf_roundtrip(self):
        cpu = run_code(STC, lahf(), CLC, sahf())
        self.assertFlags(cpu, cf=1)

    def test_enter_builds_frame(self):
        cpu = run_code(mov_ri(EBP, 0xAAAA),
                       b"\xc8" + p16(0x10) + b"\x00")     # enter 0x10, 0
        # ebp 变为新帧指针, esp 再降 0x10
        self.assertEqual(cpu.regs[ESP], cpu.regs[EBP] - 0x10)
        self.assertEqual(cpu.mem.read_u32(cpu.regs[EBP]), 0xAAAA)


# ---------------------------------------------------------------------------
# 陷入与错误
# ---------------------------------------------------------------------------

class TestTrapsAndFaults(unittest.TestCase):
    def test_int80_callback_sees_registers(self):
        seen = []

        def on_int(cpu, vec):
            seen.append((vec, cpu.regs[EAX], cpu.regs[EBX]))
            cpu.regs[EAX] = 0x2A          # 模拟内核写返回值

        cpu = build_cpu(mov_ri(EAX, 4), mov_ri(EBX, 1), INT80, HLT,
                        on_int=on_int)
        cpu.run(20)
        self.assertEqual(seen, [(0x80, 4, 1)])
        self.assertEqual(cpu.regs[EAX], 0x2A)

    def test_int3_vector(self):
        seen = []
        cpu = build_cpu(b"\xcc", HLT, on_int=lambda c, v: seen.append(v))
        cpu.run(5)
        self.assertEqual(seen, [3])

    def test_int_without_callback_halts(self):
        cpu = build_cpu(INT80, mov_ri(EAX, 0xBAD))
        cpu.run(10)
        self.assertTrue(cpu.halted)
        self.assertEqual(cpu.regs[EAX], 0)

    def test_segfault_to_on_fault(self):
        seen = []
        cpu = build_cpu(mov_ri(EBX, 0x300000), mov_rm(EAX, EBX, 0), HLT,
                        on_fault=lambda c, e: seen.append(e))
        cpu.run(10)
        self.assertEqual(len(seen), 1)
        self.assertIsInstance(seen[0], SegFault)

    def test_segfault_propagates_without_handler(self):
        cpu = build_cpu(mov_ri(EBX, 0x300000), mov_rm(EAX, EBX, 0), HLT)
        with self.assertRaises(SegFault):
            cpu.run(10)

    def test_unimplemented_opcode_reports_eip_and_bytes(self):
        cpu = build_cpu(NOP, b"\x62\x00")          # 0x62 = bound, 未实现
        cpu.step()                                  # nop
        with self.assertRaises(CpuError) as ctx:
            cpu.step()
        self.assertEqual(ctx.exception.eip, 1)
        self.assertIn("62", str(ctx.exception))

    def test_unimplemented_0f_opcode(self):
        cpu = build_cpu(b"\x0f\x0b")               # ud2
        with self.assertRaises(CpuError):
            cpu.step()

    def test_hlt_stops_run(self):
        cpu = build_cpu(NOP, HLT, mov_ri(EAX, 0xBAD))
        n = cpu.run(100)
        self.assertTrue(cpu.halted)
        self.assertEqual(cpu.regs[EAX], 0)
        self.assertLess(n, 100)


# ---------------------------------------------------------------------------
# 执行控制与快照
# ---------------------------------------------------------------------------

class TestExecutionControl(unittest.TestCase):
    def test_run_respects_step_budget(self):
        cpu = build_cpu(NOP * 50)
        self.assertEqual(cpu.run(10), 10)
        self.assertEqual(cpu.eip, 10)
        self.assertEqual(cpu.run(5), 5)
        self.assertEqual(cpu.eip, 15)

    def test_icount_accumulates(self):
        cpu = build_cpu(NOP * 20)
        cpu.run(7)
        cpu.run(3)
        self.assertEqual(cpu.icount, 10)

    def test_step_single(self):
        cpu = build_cpu(mov_ri(EAX, 1), mov_ri(EAX, 2))
        cpu.step()
        self.assertEqual(cpu.regs[EAX], 1)
        cpu.step()
        self.assertEqual(cpu.regs[EAX], 2)

    def test_snapshot_restore(self):
        cpu = build_cpu(mov_ri(EAX, 1), STC, HLT)
        cpu.step()
        snap = cpu.snapshot()
        cpu.step()
        self.assertTrue(cpu.flags & CF)
        cpu.restore(snap)
        self.assertFalse(cpu.flags & CF)
        self.assertEqual(cpu.eip, snap["eip"])

    def test_named_register_access(self):
        cpu = build_cpu(NOP)
        cpu.eax = 0x1234
        self.assertEqual(cpu.regs[EAX], 0x1234)
        self.assertEqual(cpu.eax, 0x1234)
        cpu.esp = 0xFFFFFFFF0
        self.assertEqual(cpu.regs[ESP], 0xFFFFFFF0)

    def test_eflags_property_masks_reserved(self):
        cpu = build_cpu(NOP)
        cpu.eflags = 0xFFFFFFFF
        self.assertTrue(cpu.flags & CF)
        self.assertEqual(cpu.flags & 0x02, 0x02)     # 保留位 1 恒置


# ---------------------------------------------------------------------------
# 综合: 用真实编译器会生成的序列
# ---------------------------------------------------------------------------

class TestRealisticSequences(unittest.TestCase):
    def test_gcc_style_prologue_epilogue(self):
        # push ebp; mov ebp,esp; sub esp,0x10; ...; leave; ret
        cpu = build_cpu(
            call_rel32(1), HLT,
            push_r(EBP), mov_rr(EBP, ESP), alu_ri8(5, ESP, 0x10),
            mov_ri(EAX, 42), mov_mr(EBP, -4, EAX),
            mov_rm(ECX, EBP, -4),
            leave(), ret())
        sp0 = cpu.regs[ESP]
        cpu.run(50)
        self.assertEqual(cpu.regs[ECX], 42)
        self.assertEqual(cpu.regs[ESP], sp0)      # 栈平衡

    def test_sum_loop(self):
        # 累加 1..10 = 55。循环体 add(2) + dec(1) + jcc(2) = 5 字节, 故 rel = -5
        cpu = run_code(
            mov_ri(EAX, 0), mov_ri(ECX, 10),
            alu_rr(0, EAX, ECX),          # add eax, ecx
            dec_r(ECX),
            jcc(5, -5),                   # jnz 回到 add
            max_steps=200)
        self.assertEqual(cpu.regs[EAX], 55)

    def test_strlen_style_scan(self):
        # 手写: 逐字节找 0, 统计长度
        cpu = build_cpu(
            mov_ri(ESI, 0x1000), mov_ri(EAX, 0),
            # loop: cmp byte [esi], 0; jz done; inc esi; inc eax; jmp loop
            # 偏移: cmp 在 10, jz 在 13(下一条 eip=15), inc/inc/jmp 占 15..18, hlt 在 19
            bytes([0x80]) + modrm(0, 7, ESI) + b"\x00",      # cmp byte [esi],0
            jcc(4, 4),                                        # jz -> hlt(19)
            inc_r(ESI), inc_r(EAX), jmp_rel8(-9),             # jmp 回 cmp(10)
            HLT)
        cpu.mem.write(0x1000, b"hello\x00")
        cpu.run(500)
        self.assertEqual(cpu.regs[EAX], 5)

    def test_switch_style_jump_table(self):
        # mov eax,[table + ebx*4]; jmp eax
        cpu = build_cpu(
            mov_ri(EBX, 1),
            bytes([0x8B]) + modrm(0, EAX, 4)
            + bytes([(2 << 6) | (EBX << 3) | 5]) + p32(0x1000),  # mov eax,[ebx*4+0x1000]
            bytes([0xFF]) + rr(4, EAX),                          # jmp eax
            HLT, NOP * 3,
            mov_ri(ECX, 0xAAA), HLT,
            mov_ri(ECX, 0xBBB), HLT)
        # 表项 1 指向第二个分支
        base = 5 + 7 + 2 + 1 + 3      # mov ebx, mov eax, jmp, hlt, nops
        cpu.mem.write_u32(0x1000, base)
        cpu.mem.write_u32(0x1004, base + 6)
        cpu.run(50)
        self.assertEqual(cpu.regs[ECX], 0xBBB)


class TestRealLibcCode(unittest.TestCase):
    """跑镜像 /bin/date 里摘出的真实 libc 机器码.

    字节序列是从 hdc-0.11.img 的 text 段原样摘录后硬编码在此(不依赖镜像),
    比手写用例更能证明解码器面对真实编译器输出是对的。
    """

    # /bin/date text+0x455 起的 strlen:
    #   b9 ff ff ff ff   mov  ecx, 0xffffffff
    #   8b 7d 08         mov  edi, [ebp+8]
    #   31 c0            xor  eax, eax
    #   fc               cld
    #   f2 ae            repne scasb
    #   f7 d1            not  ecx
    #   49               dec  ecx
    STRLEN = bytes.fromhex("b9 ffffffff 8b7d08 31c0 fc f2ae f7d1 49".replace(" ", ""))

    # /bin/date text+0x7565 起的三字搬运:
    #   83 ec 0c         sub  esp, 12
    #   89 e7            mov  edi, esp
    #   8d 75 f4         lea  esi, [ebp-12]
    #   b9 03 00 00 00   mov  ecx, 3
    #   fc               cld
    #   f3 a5            rep  movsd
    MEMCPY3 = bytes.fromhex("83ec0c 89e7 8d75f4 b903000000 fc f3a5".replace(" ", ""))

    def test_libc_strlen_on_various_strings(self):
        for s in (b"", b"a", b"hello", b"x" * 200,
                  bytes(range(1, 256))):          # 含全部非零字节值
            with self.subTest(length=len(s)):
                cpu = build_cpu(self.STRLEN, HLT)
                cpu.regs[EBP] = 0x1000
                cpu.mem.write_u32(0x1008, 0x1400)       # [ebp+8] = 字符串指针
                cpu.mem.write(0x1400, s + b"\x00")
                cpu.run(2000)
                self.assertEqual(cpu.regs[ECX], len(s))

    def test_libc_strlen_leaves_edi_past_nul(self):
        cpu = build_cpu(self.STRLEN, HLT)
        cpu.regs[EBP] = 0x1000
        cpu.mem.write_u32(0x1008, 0x1400)
        cpu.mem.write(0x1400, b"abc\x00")
        cpu.run(2000)
        self.assertEqual(cpu.regs[EDI], 0x1404)   # 停在 NUL 之后

    def test_libc_memcpy_three_dwords(self):
        cpu = build_cpu(self.MEMCPY3, HLT)
        cpu.regs[EBP] = 0x1400
        payload = struct.pack("<3I", 0x11111111, 0x22222222, 0x33333333)
        cpu.mem.write(0x1400 - 12, payload)       # [ebp-12] 起的源数据
        sp_before = cpu.regs[ESP]
        cpu.run(2000)
        self.assertEqual(cpu.mem.read(sp_before - 12, 12), payload)
        self.assertEqual(cpu.regs[ECX], 0)

    def test_date_entry_prologue_decodes(self):
        """/bin/date 入口的前几条指令: 取 envp 存入 environ.

        8b 44 24 08   mov eax, [esp+8]      <- envp(内核 create_tables 的布局)
        a3 00 90 00 00  mov [0x9000], eax   <- data 段的 environ
        """
        entry = bytes.fromhex("8b442408" "a300900000")
        cpu = build_cpu(entry, HLT, data_size=0x10000)
        cpu.regs[ESP] = 0x3FFF000
        cpu.mem.write_u32(0x3FFF008, 0xCAFE)      # 假的 envp 指针
        cpu.run(10)
        self.assertEqual(cpu.regs[EAX], 0xCAFE)
        self.assertEqual(cpu.mem.read_u32(0x9000), 0xCAFE)


if __name__ == "__main__":
    unittest.main()
