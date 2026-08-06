"""i386 用户态指令解释器.

只解释 ring-3 用户代码: 平坦地址空间、不管段寄存器、不管分页与特权级。
遇到 `int N` 调用注入的 on_int 回调(内核层在那里实现系统调用),
遇到除零/非法指令/越界访存调用 on_fault。

寄存器用 list, 下标即 ModRM 的 reg 编码:
    0=EAX 1=ECX 2=EDX 3=EBX 4=ESP 5=EBP 6=ESI 7=EDI
EFLAGS 本阶段按朴素方式即时计算(正确性优先), 后续再换惰性方案。
"""

from __future__ import annotations

from typing import Callable, Optional

from x86mem import AddressSpace, SegFault

MASK32 = 0xFFFFFFFF
SIGN32 = 0x80000000

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


def _sx8(v: int) -> int:
    """8 位有符号扩展为 Python 整数."""
    return v - 256 if v >= 128 else v


def _sx16(v: int) -> int:
    return v - 0x10000 if v >= 0x8000 else v


def _sx32(v: int) -> int:
    return v - 0x100000000 if v >= SIGN32 else v


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
        # 解码期缓存: opcode 字节由 _fetch* 前进 eip, 本阶段不做解码缓存
        self._insn_start = 0

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

    # 便捷属性(测试与内核层用名字访问更清楚)
    def __getattr__(self, name):
        try:
            return self.regs[REG32_NAMES.index(name)]
        except ValueError:
            raise AttributeError(name) from None

    def __setattr__(self, name, value):
        if name in REG32_NAMES:
            self.regs[REG32_NAMES.index(name)] = value & MASK32
        else:
            object.__setattr__(self, name, value)

    @property
    def eflags(self) -> int:
        return self.flags

    @eflags.setter
    def eflags(self, val: int) -> None:
        self.flags = (val & 0x0CD5) | EFLAGS_BASE

    # ---- 取指 ---------------------------------------------------------

    def _fetch8(self) -> int:
        v = self.mem.read_u8(self.eip)
        self.eip = (self.eip + 1) & MASK32
        return v

    def _fetch16(self) -> int:
        v = self.mem.read_u16(self.eip)
        self.eip = (self.eip + 2) & MASK32
        return v

    def _fetch32(self) -> int:
        v = self.mem.read_u32(self.eip)
        self.eip = (self.eip + 4) & MASK32
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

    # ---- ModRM 解码 ---------------------------------------------------

    def _modrm(self, addr_size_16: bool = False):
        """解码 ModRM 字节.

        返回 (mod, reg, rm, addr): mod==3 时 addr 为 None(操作数在寄存器),
        否则 addr 是计算好的有效地址。
        """
        modrm = self._fetch8()
        mod = modrm >> 6
        reg = (modrm >> 3) & 7
        rm = modrm & 7
        if mod == 3:
            return mod, reg, rm, None

        if rm == 4:                       # 走 SIB
            sib = self._fetch8()
            scale = sib >> 6
            index = (sib >> 3) & 7
            base = sib & 7
            addr = 0
            if index != 4:                # index==4(ESP) 表示无索引
                addr += self.regs[index] << scale
            if base == 5 and mod == 0:
                addr += _sx32(self._fetch32())
            else:
                addr += self.regs[base]
        elif rm == 5 and mod == 0:        # disp32 绝对寻址
            addr = _sx32(self._fetch32())
        else:
            addr = self.regs[rm]

        if mod == 1:
            addr += _sx8(self._fetch8())
        elif mod == 2:
            addr += _sx32(self._fetch32())
        return mod, reg, rm, addr & MASK32

    # ---- 操作数读写 ---------------------------------------------------

    def _read_rm(self, mod: int, rm: int, addr: Optional[int], size: int) -> int:
        if mod == 3:
            if size == 1:
                return self.get_reg8(rm)
            if size == 2:
                return self.get_reg16(rm)
            return self.regs[rm] & MASK32
        if size == 1:
            return self.mem.read_u8(addr)
        if size == 2:
            return self.mem.read_u16(addr)
        return self.mem.read_u32(addr)

    def _write_rm(self, mod: int, rm: int, addr: Optional[int],
                  size: int, val: int) -> None:
        if mod == 3:
            if size == 1:
                self.set_reg8(rm, val)
            elif size == 2:
                self.set_reg16(rm, val)
            else:
                self.regs[rm] = val & MASK32
            return
        if size == 1:
            self.mem.write_u8(addr, val)
        elif size == 2:
            self.mem.write_u16(addr, val)
        else:
            self.mem.write_u32(addr, val)

    def _read_reg(self, reg: int, size: int) -> int:
        if size == 1:
            return self.get_reg8(reg)
        if size == 2:
            return self.get_reg16(reg)
        return self.regs[reg] & MASK32

    def _write_reg(self, reg: int, size: int, val: int) -> None:
        if size == 1:
            self.set_reg8(reg, val)
        elif size == 2:
            self.set_reg16(reg, val)
        else:
            self.regs[reg] = val & MASK32

    # ---- 标志位计算 ---------------------------------------------------

    @staticmethod
    def _mask_of(size: int) -> int:
        return (1 << (size * 8)) - 1

    @staticmethod
    def _sign_of(size: int) -> int:
        return 1 << (size * 8 - 1)

    def _set_logic_flags(self, res: int, size: int) -> None:
        """and/or/xor/test: CF=OF=0, AF 未定义(置 0)."""
        mask = self._mask_of(size)
        res &= mask
        f = EFLAGS_BASE | (self.flags & DF)
        if res == 0:
            f |= ZF
        if res & self._sign_of(size):
            f |= SF
        f |= _PARITY[res & 0xFF]
        self.flags = f

    def _set_add_flags(self, a: int, b: int, res: int, size: int,
                       carry_in: int = 0) -> None:
        mask = self._mask_of(size)
        sign = self._sign_of(size)
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
        f |= _PARITY[trunc & 0xFF]
        self.flags = f

    def _set_sub_flags(self, a: int, b: int, res: int, size: int,
                       borrow_in: int = 0) -> None:
        mask = self._mask_of(size)
        sign = self._sign_of(size)
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
        f |= _PARITY[trunc & 0xFF]
        self.flags = f

    def _set_inc_flags(self, res: int, size: int, was_inc: bool,
                       before: int) -> None:
        """inc/dec 不改 CF, 其余标志按 add/sub 规则."""
        old_cf = self.flags & CF
        if was_inc:
            self._set_add_flags(before, 1, before + 1, size)
        else:
            self._set_sub_flags(before, 1, before - 1, size)
        self.flags = (self.flags & ~CF) | old_cf

    # ---- 条件判断 -----------------------------------------------------

    def _cond(self, code: int) -> bool:
        f = self.flags
        if code == 0x0:   return bool(f & OF)                      # o
        if code == 0x1:   return not (f & OF)                      # no
        if code == 0x2:   return bool(f & CF)                      # b/nae
        if code == 0x3:   return not (f & CF)                      # ae/nb
        if code == 0x4:   return bool(f & ZF)                      # e/z
        if code == 0x5:   return not (f & ZF)                      # ne/nz
        if code == 0x6:   return bool(f & (CF | ZF))               # be/na
        if code == 0x7:   return not (f & (CF | ZF))               # a/nbe
        if code == 0x8:   return bool(f & SF)                      # s
        if code == 0x9:   return not (f & SF)                      # ns
        if code == 0xA:   return bool(f & PF)                      # p/pe
        if code == 0xB:   return not (f & PF)                      # np/po
        sf = bool(f & SF)
        of = bool(f & OF)
        if code == 0xC:   return sf != of                          # l/nge
        if code == 0xD:   return sf == of                          # ge/nl
        if code == 0xE:   return (f & ZF) or (sf != of)            # le/ng
        return (not (f & ZF)) and (sf == of)                       # g/nle

    # ---- ALU 分派 -----------------------------------------------------

    def _alu(self, op: int, a: int, b: int, size: int) -> Optional[int]:
        """op: 0=add 1=or 2=adc 3=sbb 4=and 5=sub 6=xor 7=cmp.

        返回结果(cmp 返回 None 表示不写回)。
        """
        mask = self._mask_of(size)
        if op == 0:
            res = a + b
            self._set_add_flags(a, b, res, size)
            return res & mask
        if op == 1:
            res = a | b
            self._set_logic_flags(res, size)
            return res & mask
        if op == 2:
            c = 1 if self.flags & CF else 0
            res = a + b + c
            self._set_add_flags(a, b, res, size, c)
            return res & mask
        if op == 3:
            c = 1 if self.flags & CF else 0
            res = a - b - c
            self._set_sub_flags(a, b, res, size, c)
            return res & mask
        if op == 4:
            res = a & b
            self._set_logic_flags(res, size)
            return res & mask
        if op == 5:
            res = a - b
            self._set_sub_flags(a, b, res, size)
            return res & mask
        if op == 6:
            res = a ^ b
            self._set_logic_flags(res, size)
            return res & mask
        # cmp
        self._set_sub_flags(a, b, a - b, size)
        return None

    # ---- 主循环 -------------------------------------------------------

    def run(self, max_steps: int) -> int:
        """执行至多 max_steps 条指令, 返回实际执行条数."""
        n = 0
        while n < max_steps and not self.halted:
            try:
                self.step()
            except SegFault as e:
                if self.on_fault is None:
                    raise
                self.on_fault(self, e)
            except DivideError as e:
                if self.on_fault is None:
                    raise
                self.on_fault(self, e)
            n += 1
            self.icount += 1
        return n

    def step(self) -> None:
        """执行一条指令."""
        self._insn_start = self.eip
        opsize = 4
        rep = 0                       # 0=无, 0xF3=rep/repe, 0xF2=repne
        while True:
            op = self._fetch8()
            if op == 0x66:            # 操作数尺寸前缀
                opsize = 2
                continue
            if op in (0x2E, 0x36, 0x3E, 0x26, 0x64, 0x65):
                continue              # 段前缀: 平坦模型下忽略
            if op == 0xF0:            # lock
                continue
            if op in (0xF2, 0xF3):
                rep = op
                continue
            break
        if rep and 0xA4 <= op <= 0xAF:
            self._string_op(op, opsize, rep)
            return
        if rep and op in (0x90,):     # pause = f3 90
            return
        self._execute(op, opsize)

    def _bad(self, op: int, extra: str = "未实现的指令") -> None:
        n = self.eip - self._insn_start
        raw = self.mem.read(self._insn_start, max(n, 1) + 3)
        raise CpuError(f"{extra} opcode={op:#04x}", self._insn_start, raw)

    def _execute(self, op: int, opsize: int) -> None:
        regs = self.regs
        mem = self.mem

        # ---- ALU 组: 00-3F, 每族 6 个编码 ----
        if op < 0x40 and (op & 7) < 6:
            alu_op = op >> 3
            form = op & 7
            if form == 0:      # r/m8, r8
                mod, reg, rm, addr = self._modrm()
                a = self._read_rm(mod, rm, addr, 1)
                res = self._alu(alu_op, a, self.get_reg8(reg), 1)
                if res is not None:
                    self._write_rm(mod, rm, addr, 1, res)
            elif form == 1:    # r/m, r
                mod, reg, rm, addr = self._modrm()
                a = self._read_rm(mod, rm, addr, opsize)
                res = self._alu(alu_op, a, self._read_reg(reg, opsize), opsize)
                if res is not None:
                    self._write_rm(mod, rm, addr, opsize, res)
            elif form == 2:    # r8, r/m8
                mod, reg, rm, addr = self._modrm()
                a = self.get_reg8(reg)
                res = self._alu(alu_op, a, self._read_rm(mod, rm, addr, 1), 1)
                if res is not None:
                    self.set_reg8(reg, res)
            elif form == 3:    # r, r/m
                mod, reg, rm, addr = self._modrm()
                a = self._read_reg(reg, opsize)
                res = self._alu(alu_op, a,
                                self._read_rm(mod, rm, addr, opsize), opsize)
                if res is not None:
                    self._write_reg(reg, opsize, res)
            elif form == 4:    # al, imm8
                res = self._alu(alu_op, self.get_reg8(0), self._fetch8(), 1)
                if res is not None:
                    self.set_reg8(0, res)
            else:              # eax, imm
                imm = self._fetch16() if opsize == 2 else self._fetch32()
                res = self._alu(alu_op, self._read_reg(0, opsize), imm, opsize)
                if res is not None:
                    self._write_reg(0, opsize, res)
            return

        # ---- 40-47 inc r / 48-4F dec r ----
        if 0x40 <= op <= 0x4F:
            r = op & 7
            before = self._read_reg(r, opsize)
            is_inc = op < 0x48
            after = (before + 1) if is_inc else (before - 1)
            self._write_reg(r, opsize, after)
            self._set_inc_flags(after, opsize, is_inc, before)
            return

        # ---- 50-57 push r / 58-5F pop r ----
        if 0x50 <= op <= 0x57:
            if opsize == 2:
                self.push16(self.get_reg16(op & 7))
            else:
                self.push32(regs[op & 7])
            return
        if 0x58 <= op <= 0x5F:
            if opsize == 2:
                self.set_reg16(op & 7, self.pop16())
            else:
                regs[op & 7] = self.pop32()
            return

        # ---- 68/6A push imm ----
        if op == 0x68:
            imm = self._fetch16() if opsize == 2 else self._fetch32()
            self.push16(imm) if opsize == 2 else self.push32(imm)
            return
        if op == 0x6A:
            imm = _sx8(self._fetch8()) & MASK32
            self.push16(imm & 0xFFFF) if opsize == 2 else self.push32(imm)
            return

        # ---- 70-7F jcc rel8 ----
        if 0x70 <= op <= 0x7F:
            rel = _sx8(self._fetch8())
            if self._cond(op & 0xF):
                self.eip = (self.eip + rel) & MASK32
            return

        # ---- 80/81/83 ALU r/m, imm ----
        if op in (0x80, 0x81, 0x83):
            size = 1 if op == 0x80 else opsize
            mod, reg, rm, addr = self._modrm()
            a = self._read_rm(mod, rm, addr, size)
            if op == 0x80:
                imm = self._fetch8()
            elif op == 0x81:
                imm = self._fetch16() if size == 2 else self._fetch32()
            else:
                imm = _sx8(self._fetch8()) & self._mask_of(size)
            res = self._alu(reg, a, imm, size)
            if res is not None:
                self._write_rm(mod, rm, addr, size, res)
            return

        # ---- 84/85 test r/m, r ----
        if op in (0x84, 0x85):
            size = 1 if op == 0x84 else opsize
            mod, reg, rm, addr = self._modrm()
            a = self._read_rm(mod, rm, addr, size)
            self._set_logic_flags(a & self._read_reg(reg, size), size)
            return

        # ---- 86/87 xchg r/m, r ----
        if op in (0x86, 0x87):
            size = 1 if op == 0x86 else opsize
            mod, reg, rm, addr = self._modrm()
            a = self._read_rm(mod, rm, addr, size)
            b = self._read_reg(reg, size)
            self._write_rm(mod, rm, addr, size, b)
            self._write_reg(reg, size, a)
            return

        # ---- 88-8B mov ----
        if op == 0x88:
            mod, reg, rm, addr = self._modrm()
            self._write_rm(mod, rm, addr, 1, self.get_reg8(reg))
            return
        if op == 0x89:
            mod, reg, rm, addr = self._modrm()
            self._write_rm(mod, rm, addr, opsize, self._read_reg(reg, opsize))
            return
        if op == 0x8A:
            mod, reg, rm, addr = self._modrm()
            self.set_reg8(reg, self._read_rm(mod, rm, addr, 1))
            return
        if op == 0x8B:
            mod, reg, rm, addr = self._modrm()
            self._write_reg(reg, opsize, self._read_rm(mod, rm, addr, opsize))
            return

        # ---- 8D lea ----
        if op == 0x8D:
            mod, reg, rm, addr = self._modrm()
            if mod == 3:
                self._bad(op, "lea 的操作数不能是寄存器")
            self._write_reg(reg, opsize, addr)
            return

        # ---- 8F pop r/m ----
        if op == 0x8F:
            mod, reg, rm, addr = self._modrm()
            val = self.pop16() if opsize == 2 else self.pop32()
            self._write_rm(mod, rm, addr, opsize, val)
            return

        # ---- 90 nop / 91-97 xchg eax, r ----
        if op == 0x90:
            return
        if 0x91 <= op <= 0x97:
            r = op & 7
            a = self._read_reg(0, opsize)
            self._write_reg(0, opsize, self._read_reg(r, opsize))
            self._write_reg(r, opsize, a)
            return

        # ---- 98 cbw/cwde ----
        if op == 0x98:
            if opsize == 2:
                self.set_reg16(0, _sx8(self.get_reg8(0)) & 0xFFFF)
            else:
                regs[EAX] = _sx16(self.get_reg16(0)) & MASK32
            return

        # ---- 99 cwd/cdq ----
        if op == 0x99:
            if opsize == 2:
                self.set_reg16(EDX, 0xFFFF if self.get_reg16(0) & 0x8000 else 0)
            else:
                regs[EDX] = MASK32 if regs[EAX] & SIGN32 else 0
            return

        # ---- 9C pushf / 9D popf ----
        if op == 0x9C:
            self.push16(self.flags & 0xFFFF) if opsize == 2 \
                else self.push32(self.flags)
            return
        if op == 0x9D:
            self.eflags = self.pop16() if opsize == 2 else self.pop32()
            return

        # ---- A0-A3 mov eax <-> moffs ----
        if op == 0xA0:
            self.set_reg8(0, mem.read_u8(self._fetch32()))
            return
        if op == 0xA1:
            self._write_reg(0, opsize, self._read_rm(0, 0, self._fetch32(), opsize))
            return
        if op == 0xA2:
            mem.write_u8(self._fetch32(), self.get_reg8(0))
            return
        if op == 0xA3:
            self._write_rm(0, 0, self._fetch32(), opsize, self._read_reg(0, opsize))
            return

        # ---- A4-AF 字符串指令(无 rep 前缀, 执行一次) ----
        if 0xA4 <= op <= 0xAF and op not in (0xA8, 0xA9):
            self._string_op(op, opsize, 0)
            return

        # ---- A8/A9 test al/eax, imm ----
        if op == 0xA8:
            self._set_logic_flags(self.get_reg8(0) & self._fetch8(), 1)
            return
        if op == 0xA9:
            imm = self._fetch16() if opsize == 2 else self._fetch32()
            self._set_logic_flags(self._read_reg(0, opsize) & imm, opsize)
            return

        # ---- B0-B7 mov r8, imm8 / B8-BF mov r, imm ----
        if 0xB0 <= op <= 0xB7:
            self.set_reg8(op & 7, self._fetch8())
            return
        if 0xB8 <= op <= 0xBF:
            imm = self._fetch16() if opsize == 2 else self._fetch32()
            self._write_reg(op & 7, opsize, imm)
            return

        # ---- C2/C3 ret ----
        if op == 0xC3:
            self.eip = self.pop32()
            return
        if op == 0xC2:
            n = self._fetch16()
            self.eip = self.pop32()
            regs[ESP] = (regs[ESP] + n) & MASK32
            return

        # ---- C6/C7 mov r/m, imm ----
        if op == 0xC6:
            mod, reg, rm, addr = self._modrm()
            self._write_rm(mod, rm, addr, 1, self._fetch8())
            return
        if op == 0xC7:
            mod, reg, rm, addr = self._modrm()
            imm = self._fetch16() if opsize == 2 else self._fetch32()
            self._write_rm(mod, rm, addr, opsize, imm)
            return

        # ---- C9 leave ----
        if op == 0xC9:
            regs[ESP] = regs[EBP]
            regs[EBP] = self.pop32()
            return

        # ---- CC int3 / CD int imm8 ----
        if op in (0xCC, 0xCD):
            vec = 3 if op == 0xCC else self._fetch8()
            if self.on_int is None:
                self.halted = True
                return
            self.on_int(self, vec)
            return

        # ---- E8 call rel32 / E9 jmp rel32 / EB jmp rel8 ----
        if op == 0xE8:
            rel = _sx32(self._fetch32())
            self.push32(self.eip)
            self.eip = (self.eip + rel) & MASK32
            return
        if op == 0xE9:
            rel = _sx32(self._fetch32())
            self.eip = (self.eip + rel) & MASK32
            return
        if op == 0xEB:
            rel = _sx8(self._fetch8())
            self.eip = (self.eip + rel) & MASK32
            return

        # ---- F4 hlt ----
        if op == 0xF4:
            self.halted = True
            return

        # ---- 9E sahf / 9F lahf ----
        if op == 0x9E:
            ah = self.get_reg8(4)
            self.flags = (self.flags & ~0xFF) | (ah & 0xD5) | 0x02
            return
        if op == 0x9F:
            self.set_reg8(4, self.flags & 0xFF)
            return

        # ---- C8 enter ----
        if op == 0xC8:
            alloc = self._fetch16()
            level = self._fetch8() & 31
            self.push32(regs[EBP])
            frame = regs[ESP]
            for _ in range(level):
                regs[EBP] = (regs[EBP] - 4) & MASK32
                self.push32(mem.read_u32(regs[EBP]))
            if level:
                self.push32(frame)
            regs[EBP] = frame
            regs[ESP] = (regs[ESP] - alloc) & MASK32
            return

        # ---- D7 xlat ----
        if op == 0xD7:
            self.set_reg8(0, mem.read_u8((regs[EBX] + self.get_reg8(0)) & MASK32))
            return

        # ---- E0-E2 loop 族 / E3 jecxz ----
        if 0xE0 <= op <= 0xE3:
            rel = _sx8(self._fetch8())
            if op == 0xE3:
                take = (regs[ECX] & MASK32) == 0
            else:
                regs[ECX] = (regs[ECX] - 1) & MASK32
                take = regs[ECX] != 0
                if op == 0xE1:                       # loope
                    take = take and bool(self.flags & ZF)
                elif op == 0xE0:                     # loopne
                    take = take and not (self.flags & ZF)
            if take:
                self.eip = (self.eip + rel) & MASK32
            return

        # ---- F6/F7 组: test/not/neg/mul/imul/div/idiv ----
        if op in (0xF6, 0xF7):
            size = 1 if op == 0xF6 else opsize
            mod, reg, rm, addr = self._modrm()
            self._group_f7(reg, mod, rm, addr, size)
            return

        # ---- F8-FD 标志位操作 ----
        if op == 0xF8:
            self.flags &= ~CF
            return
        if op == 0xF9:
            self.flags |= CF
            return
        if op == 0xFC:
            self.flags &= ~DF
            return
        if op == 0xFD:
            self.flags |= DF
            return

        # ---- FE/FF 组: inc/dec/call/jmp/push ----
        if op in (0xFE, 0xFF):
            size = 1 if op == 0xFE else opsize
            mod, reg, rm, addr = self._modrm()
            self._group_ff(reg, mod, rm, addr, size, opsize)
            return

        # ---- C0/C1/D0-D3 移位组 ----
        if op in (0xC0, 0xC1, 0xD0, 0xD1, 0xD2, 0xD3):
            size = 1 if op in (0xC0, 0xD0, 0xD2) else opsize
            mod, reg, rm, addr = self._modrm()
            if op in (0xC0, 0xC1):
                cnt = self._fetch8()
            elif op in (0xD0, 0xD1):
                cnt = 1
            else:
                cnt = self.get_reg8(ECX)
            self._shift(reg, mod, rm, addr, size, cnt)
            return

        # ---- 0F 两字节 opcode ----
        if op == 0x0F:
            self._execute_0f(self._fetch8(), opsize)
            return

        self._bad(op)

    # ---- F6/F7 组 -----------------------------------------------------

    def _group_f7(self, reg: int, mod: int, rm: int,
                  addr: Optional[int], size: int) -> None:
        mask = self._mask_of(size)
        if reg in (0, 1):                        # test r/m, imm
            if size == 1:
                imm = self._fetch8()
            elif size == 2:
                imm = self._fetch16()
            else:
                imm = self._fetch32()
            a = self._read_rm(mod, rm, addr, size)
            self._set_logic_flags(a & imm, size)
            return
        a = self._read_rm(mod, rm, addr, size)
        if reg == 2:                             # not(不改标志)
            self._write_rm(mod, rm, addr, size, (~a) & mask)
            return
        if reg == 3:                             # neg
            res = -a
            self._set_sub_flags(0, a, res, size)
            self._write_rm(mod, rm, addr, size, res & mask)
            return
        if reg == 4:                             # mul(无符号)
            self._mul_unsigned(a, size)
            return
        if reg == 5:                             # imul(有符号)
            self._mul_signed(a, size)
            return
        if reg == 6:                             # div
            self._div_unsigned(a, size)
            return
        # idiv
        self._div_signed(a, size)

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
        low = res & self._mask_of(size)
        if low == 0:
            f |= ZF
        if low & self._sign_of(size):
            f |= SF
        f |= _PARITY[low & 0xFF]
        self.flags = f

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
        low = res & self._mask_of(size)
        if low == 0:
            f |= ZF
        if low & self._sign_of(size):
            f |= SF
        f |= _PARITY[low & 0xFF]
        self.flags = f

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

    # ---- FE/FF 组 -----------------------------------------------------

    def _group_ff(self, reg: int, mod: int, rm: int, addr: Optional[int],
                  size: int, opsize: int) -> None:
        if reg == 0 or reg == 1:                 # inc / dec
            before = self._read_rm(mod, rm, addr, size)
            is_inc = reg == 0
            after = (before + 1) if is_inc else (before - 1)
            self._write_rm(mod, rm, addr, size, after)
            self._set_inc_flags(after, size, is_inc, before)
            return
        if reg == 2:                             # call r/m
            target = self._read_rm(mod, rm, addr, opsize)
            self.push32(self.eip)
            self.eip = target & MASK32
            return
        if reg == 4:                             # jmp r/m
            self.eip = self._read_rm(mod, rm, addr, opsize) & MASK32
            return
        if reg == 6:                             # push r/m
            val = self._read_rm(mod, rm, addr, opsize)
            self.push16(val) if opsize == 2 else self.push32(val)
            return
        self._bad(0xFF, f"FF 组 /{reg} 未实现")

    # ---- 移位组 -------------------------------------------------------

    def _shift(self, reg: int, mod: int, rm: int, addr: Optional[int],
               size: int, cnt: int) -> None:
        cnt &= 31
        if cnt == 0:
            return                               # 计数为 0 时标志不变
        mask = self._mask_of(size)
        sign = self._sign_of(size)
        bits = size * 8
        a = self._read_rm(mod, rm, addr, size)

        if reg == 4 or reg == 6:                 # shl / sal
            res = a << cnt
            cf = (res >> bits) & 1
            res &= mask
            of = ((res & sign) != 0) != bool(cf)
        elif reg == 5:                           # shr
            cf = (a >> (cnt - 1)) & 1 if cnt <= bits else 0
            res = (a >> cnt) & mask
            of = bool(a & sign) if cnt == 1 else False
        elif reg == 7:                           # sar
            sv = a - (mask + 1) if a & sign else a
            cf = (sv >> (cnt - 1)) & 1
            res = (sv >> cnt) & mask
            of = False
        elif reg == 0:                           # rol
            c = cnt % bits
            res = ((a << c) | (a >> (bits - c))) & mask if c else a
            cf = res & 1
            of = bool((res & sign) != 0) != bool(cf)
        elif reg == 1:                           # ror
            c = cnt % bits
            res = ((a >> c) | (a << (bits - c))) & mask if c else a
            cf = 1 if res & sign else 0
            of = bool(res & sign) != bool(res & (sign >> 1))
        else:
            self._bad(0xC1, f"移位组 /{reg}(rcl/rcr) 未实现")
            return

        self._write_rm(mod, rm, addr, size, res)
        f = EFLAGS_BASE | (self.flags & DF)
        if cf:
            f |= CF
        if reg in (0, 1):                        # 循环移位只改 CF/OF
            if of:
                f |= OF
            f |= self.flags & (ZF | SF | PF | AF)
            self.flags = f
            return
        if res == 0:
            f |= ZF
        if res & sign:
            f |= SF
        if of and cnt == 1:
            f |= OF
        f |= _PARITY[res & 0xFF]
        self.flags = f

    # ---- 字符串指令 ---------------------------------------------------

    def _string_op(self, op: int, opsize: int, rep: int) -> None:
        """movs/stos/lods/scas/cmps, 可带 rep/repe/repne 前缀.

        rep 为 0 时执行一次; 否则按 ecx 计数循环。
        DF=1 时地址递减(memmove 反向拷贝要用)。
        """
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

    # ---- 0F 两字节 opcode ---------------------------------------------

    def _execute_0f(self, op: int, opsize: int) -> None:
        # 80-8F jcc rel32
        if 0x80 <= op <= 0x8F:
            rel = _sx32(self._fetch32())
            if self._cond(op & 0xF):
                self.eip = (self.eip + rel) & MASK32
            return
        # 90-9F setcc r/m8
        if 0x90 <= op <= 0x9F:
            mod, reg, rm, addr = self._modrm()
            self._write_rm(mod, rm, addr, 1, 1 if self._cond(op & 0xF) else 0)
            return
        # AF imul r, r/m
        if op == 0xAF:
            mod, reg, rm, addr = self._modrm()
            a = _sx32(self._read_reg(reg, opsize)) if opsize == 4 \
                else _sx16(self._read_reg(reg, 2))
            b = self._read_rm(mod, rm, addr, opsize)
            b = _sx32(b) if opsize == 4 else _sx16(b)
            res = a * b
            self._write_reg(reg, opsize, res)
            lim = 0x7FFFFFFF if opsize == 4 else 0x7FFF
            f = EFLAGS_BASE | (self.flags & DF)
            if not (-lim - 1 <= res <= lim):
                f |= CF | OF
            low = res & self._mask_of(opsize)
            if low == 0:
                f |= ZF
            if low & self._sign_of(opsize):
                f |= SF
            f |= _PARITY[low & 0xFF]
            self.flags = f
            return
        # A3/AB/B3/BB bt/bts/btr/btc(寄存器形式), BA /4-/7 是立即数形式
        if op in (0xA3, 0xAB, 0xB3, 0xBB, 0xBA):
            mod, reg, rm, addr = self._modrm()
            if op == 0xBA:
                sub = reg
                if sub < 4:
                    self._bad(0x0F00 | op, f"0F BA /{sub} 未实现")
                    return
                bit = self._fetch8()
            else:
                sub = {0xA3: 4, 0xAB: 5, 0xB3: 6, 0xBB: 7}[op]
                bit = self._read_reg(reg, opsize)
            bits = opsize * 8
            if mod == 3:
                bit &= bits - 1
                val = self._read_rm(mod, rm, addr, opsize)
            else:
                addr = (addr + (bit // bits) * opsize) & MASK32
                bit &= bits - 1
                val = self._read_mem_sized(addr, opsize)
            cur = (val >> bit) & 1
            self.flags = (self.flags & ~CF) | (CF if cur else 0)
            if sub == 5:
                val |= 1 << bit
            elif sub == 6:
                val &= ~(1 << bit)
            elif sub == 7:
                val ^= 1 << bit
            if sub != 4:
                if mod == 3:
                    self._write_rm(mod, rm, addr, opsize, val)
                else:
                    self._write_mem_sized(addr, opsize, val)
            return

        # BC/BD bsf/bsr
        if op in (0xBC, 0xBD):
            mod, reg, rm, addr = self._modrm()
            v = self._read_rm(mod, rm, addr, opsize)
            if v == 0:
                self.flags |= ZF
                return
            self.flags &= ~ZF
            idx = (v & -v).bit_length() - 1 if op == 0xBC else v.bit_length() - 1
            self._write_reg(reg, opsize, idx)
            return

        # A4/AC shld/shrd(立即数形式), A5/AD 按 CL
        if op in (0xA4, 0xA5, 0xAC, 0xAD):
            mod, reg, rm, addr = self._modrm()
            cnt = self._fetch8() if op in (0xA4, 0xAC) else self.get_reg8(ECX)
            cnt &= 31
            bits = opsize * 8
            mask = self._mask_of(opsize)
            dst = self._read_rm(mod, rm, addr, opsize)
            src = self._read_reg(reg, opsize)
            if cnt == 0:
                return
            if op in (0xA4, 0xA5):                   # shld: 左移, 从 src 高位补入
                wide = ((dst << bits) | src) & ((1 << (bits * 2)) - 1)
                res = (wide << cnt) >> bits
                cf = (dst >> (bits - cnt)) & 1
            else:                                    # shrd: 右移, 从 src 低位补入
                wide = ((src << bits) | dst) & ((1 << (bits * 2)) - 1)
                res = wide >> cnt
                cf = (dst >> (cnt - 1)) & 1
            res &= mask
            self._write_rm(mod, rm, addr, opsize, res)
            f = EFLAGS_BASE | (self.flags & DF)
            if cf:
                f |= CF
            if res == 0:
                f |= ZF
            if res & self._sign_of(opsize):
                f |= SF
            f |= _PARITY[res & 0xFF]
            self.flags = f
            return

        # B6/B7 movzx, BE/BF movsx
        if op in (0xB6, 0xB7, 0xBE, 0xBF):
            src_size = 1 if op in (0xB6, 0xBE) else 2
            mod, reg, rm, addr = self._modrm()
            v = self._read_rm(mod, rm, addr, src_size)
            if op in (0xBE, 0xBF):
                v = _sx8(v) if src_size == 1 else _sx16(v)
            self._write_reg(reg, opsize, v & self._mask_of(opsize))
            return
        self._bad(0x0F00 | op, f"0F {op:02x} 未实现")
