"""cpu_disasm(只读反汇编器)测试.

两条主线:
1. 长度对照(最值钱): 对 test_cpu86 各机器码构造器产出的字节, 用真实 CPU 执行
   一条, 断言反汇编算出的长度 == 执行器让 eip 前进的字节数。这把"解码长度"跨整套
   已实现 opcode 免费交叉校验, 是防多条反汇编串行错位的护栏。
2. 金标文本: 断言若干指令的确切 Intel 文本; 未实现 opcode 回退 .byte; 读越界不抛。
"""

import unittest

import cpu86
from cpu86 import (CPU, CpuError, DivideError, EAX, EBX, ECX, EDX, EBP, ESI,
                   EDI, MagicJump)
from x86mem import AddressSpace, SegFault
from cpu_disasm import disasm_one, disasm_range
import test_cpu86 as T


def _exec_len(*chunks, regs=None):
    """执行一条, 返回 (指令长度, cpu). 即便 execute 阶段访存出错, eip 也已越过
    整条指令的编码(所有取指在解码阶段完成), 故长度仍准; 但控制流指令会改 eip,
    不能用于此法。"""
    cpu = T.build_cpu(*chunks, regs=regs)
    start = cpu.eip
    try:
        cpu.step()
    except (SegFault, DivideError, MagicJump, CpuError):
        pass
    return (cpu.eip - start) & 0xFFFFFFFF, cpu, start


# 直线指令(不改控制流; jcc 用不跳的条件), 基址寄存器指向已映射低区避免解码外的坑
SAFE_REGS = {"ebx": 0x100, "ebp": 0x200, "esi": 0x100, "edi": 0x100, "ecx": 1}


class TestLengthOracle(unittest.TestCase):
    def _check(self, *chunks, regs=None):
        r = dict(SAFE_REGS)
        if regs:
            r.update(regs)
        L, cpu, start = _exec_len(*chunks, regs=r)
        dl, text, raw = disasm_one(cpu.mem, start)
        self.assertEqual(dl, L, f"长度不符 {text!r} 字节={b''.join(chunks).hex(' ')}")
        self.assertEqual(len(raw), L)

    def test_straight_line_forms(self):
        cases = [
            T.mov_ri(EAX, 0x12345678),
            T.mov_r8i(ECX, 0x42),
            T.mov_rr(EAX, EBX),
            T.mov_rm(EAX, EBX, 0x10),          # mov eax, [ebx+0x10]
            T.mov_mr(EBX, 0x10, EAX),          # mov [ebx+0x10], eax
            T.inc_r(ESI), T.dec_r(EDI),
            T.push_r(EBP), T.pop_r(EBP),
            T.push_i32(0xDEAD), T.push_i8(0x7F),
            T.movzx8(EAX, ECX), T.movsx8(EAX, ECX),
            T.movzx16(EAX, ECX), T.movsx16(EAX, ECX),
            T.xchg_rr(EAX, EDX),
            T.bt_ri(EBX, 3), T.bts_ri(EBX, 3),
            T.bt_rr(EBX, EAX),
            T.bsf(EAX, EBX), T.bsr(EAX, EBX),
            T.shld_ri(EBX, EAX, 4), T.shrd_ri(EBX, EAX, 4),
        ]
        # ALU 各形 (add 家族) 与其它
        cases += [
            bytes([0x01]) + T.rr(EAX, EBX),    # add ebx, eax (r/m,r)
            bytes([0x03]) + T.rr(EAX, EBX),    # add eax, ebx (r,r/m)
            bytes([0x05]) + T.p32(0x1234),     # add eax, imm32
            bytes([0x04, 0x12]),               # add al, imm8
            bytes([0x83]) + T.rr(0, EBX) + b"\x05",   # add ebx, imm8(符号扩展)
            bytes([0x81]) + T.rr(0, EBX) + T.p32(0x1000),  # add ebx, imm32
            bytes([0x85]) + T.rr(EAX, EBX),    # test ebx, eax
            bytes([0x8D]) + T.modrm(1, EAX, EBX) + b"\x04",  # lea eax,[ebx+4]
            bytes([0xC7]) + T.rr(0, EBX) + T.p32(0x99),      # mov ebx, imm32
            bytes([0xC1]) + T.rr(4, EBX) + b"\x03",          # shl ebx, 3
            bytes([0xD1]) + T.rr(4, EBX),                    # shl ebx, 1
            bytes([0xF7]) + T.rr(3, EBX),                    # neg ebx
            bytes([0xFF]) + T.rr(0, EBX),                    # inc ebx (FF/0)
            bytes([0x66, 0x89]) + T.rr(EAX, EBX),            # mov bx, ax (16位)
            T.jcc(4, 0x10),                    # jz +0x10, ZF=0 不跳 -> 顺序
        ]
        for c in cases:
            self._check(c)

    def test_sib_and_absolute(self):
        # mov eax, [ebx+ecx*4+0x10]  (SIB)
        sib = bytes([0x8B, 0x84, (2 << 6) | (ECX << 3) | EBX]) + T.p32(0x10)
        self._check(sib)
        # mov eax, [0x1500] (disp32 绝对, rm=5 mod=0)
        absol = bytes([0x8B, 0x05]) + T.p32(0x1500)
        self._check(absol, regs={"ebx": 0x100})


class TestGoldenText(unittest.TestCase):
    def _dis(self, code, base=0, mem=None):
        if mem is None:
            mem = AddressSpace(stack_size=0x1000)
            mem.load_program(code, b"", 0x100)
        return disasm_one(mem, base)

    def test_mnemonics(self):
        checks = [
            (T.mov_ri(EAX, 0x10), 5, "mov eax, 0x10"),
            (T.mov_rr(EAX, EBX), 2, "mov eax, ebx"),        # 89: mov r/m,r
            (bytes([0x03]) + T.rr(EAX, EBX), 2, "add eax, ebx"),
            (bytes([0x8D]) + T.modrm(1, EAX, EBX) + b"\x04", 3,
             "lea eax, [ebx+0x4]"),
            (T.jcc(5, 0x10), 2, "jne 0x12"),                 # 0+2+0x10
            (bytes([0xEB, 0xFE]), 2, "jmp 0x0"),             # jmp $ (自身)
            (bytes([0xE8]) + T.p32(0x100), 5, "call 0x105"),
            (b"\xc3", 1, "ret"),
            (b"\x55", 1, "push ebp"),
            (b"\xcd\x80", 2, "int 0x80"),
            (b"\x90", 1, "nop"),
            (bytes([0xC7]) + T.rr(0, EBX) + T.p32(0x99), 6, "mov ebx, 0x99"),
            (bytes([0xC6, 0x03, 0x41]), 3, "mov byte [ebx], 0x41"),
            (bytes([0xF7]) + T.rr(3, ECX), 2, "neg ecx"),
            (bytes([0xFF]) + T.rr(6, EAX), 2, "push eax"),   # FF/6 push r
        ]
        for code, length, text in checks:
            L, t, raw = self._dis(code)
            self.assertEqual((L, t), (length, text), f"{code.hex(' ')}")

    def test_rep_string(self):
        self.assertEqual(self._dis(b"\xf3\xa5")[1], "rep movsd")
        self.assertEqual(self._dis(b"\xa4")[1], "movsb")
        self.assertEqual(self._dis(b"\xf2\xae")[1], "repne scasb")

    def test_unknown_opcode_falls_back(self):
        L, t, raw = self._dis(b"\x62\x00")   # bound: cpu86 未实现
        self.assertEqual(L, 1)
        self.assertEqual(t, ".byte 0x62")

    def test_unmapped_does_not_raise(self):
        mem = AddressSpace(stack_size=0x1000)
        mem.load_program(b"\x90", b"", 0x10)
        L, t, raw = disasm_one(mem, 0x00FF0000)   # 空洞
        self.assertEqual(L, 1)
        self.assertIn(t, ("(bad)",))

    def test_disasm_range_addresses(self):
        code = T.mov_ri(EAX, 1) + T.mov_ri(EBX, 2) + b"\x90"
        mem = AddressSpace(stack_size=0x1000)
        mem.load_program(code, b"", 0x100)
        lines = disasm_range(mem, 0, 3)
        self.assertEqual([a for a, _, _ in lines], [0, 5, 10])
        self.assertEqual(lines[0][2], "mov eax, 0x1")
        self.assertEqual(lines[1][2], "mov ebx, 0x2")
        self.assertEqual(lines[2][2], "nop")


if __name__ == "__main__":
    unittest.main()
