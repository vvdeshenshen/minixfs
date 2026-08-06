"""i386 用户态平坦地址空间.

Linux 0.11 给每个进程一个 64MB 的逻辑地址空间(fs/exec.c 的 change_ldt 里
data_limit = 0x4000000), 栈顶就在 64MB 处向下增长, 代码从虚址 0 开始。

实现用双区 bytearray 而非 64MB 单块或 4KB 页字典:
    [0, low_end)                        低区: text + data + bss + 堆(随 brk 增长)
        ...空洞(访问抛 SegFault)...
    [stack_low, TASK_SIZE)              高区: 栈(向下增长, 触碰下沿自动扩)
单块 64MB 会让多进程内存爆掉; 页字典则每次访存多一次字典查找与跨页拼接,
而这个年代的进程实际内存不到 1MB, 双区两次范围比较就够。
"""

from __future__ import annotations

import struct

TASK_SIZE = 0x4000000        # 用户空间上限 64MB, 即栈顶
PAGE_SIZE = 4096
MAX_ARG_PAGES = 32           # fs/exec.c: 参数区占栈顶下方 32 页 = 128KB
ARG_AREA = MAX_ARG_PAGES * PAGE_SIZE
BRK_STACK_GAP = 16384        # kernel/sys.c 的 sys_brk 要求 brk < start_stack - 16384

DEFAULT_STACK = 512 * 1024   # 初始栈区大小(含参数区)
STACK_GROW_STEP = 64 * 1024  # 每次自动扩栈的步长

_U16 = struct.Struct("<H")
_U32 = struct.Struct("<I")


class SegFault(Exception):
    """访问未映射地址."""

    def __init__(self, addr: int, size: int, is_write: bool):
        super().__init__(f"{'写' if is_write else '读'}越界: "
                         f"addr={addr:#x} size={size}")
        self.addr = addr
        self.size = size
        self.is_write = is_write


class AddressSpace:
    """单个进程的地址空间."""

    __slots__ = ("low", "low_end", "stack", "stack_low",
                 "brk", "text_end", "start_stack")

    def __init__(self, stack_size: int = DEFAULT_STACK):
        self.low = bytearray()          # 从虚址 0 开始
        self.low_end = 0
        stack_size = (stack_size + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1)
        self.stack = bytearray(stack_size)
        self.stack_low = TASK_SIZE - stack_size
        self.brk = 0
        self.text_end = 0               # 供 CPU 做自修改代码检测
        self.start_stack = TASK_SIZE

    # ---- 装载与增长 ---------------------------------------------------

    def load_program(self, text: bytes, data: bytes, bss: int) -> None:
        """按 a.out ZMAGIC 布局装入: text 在虚址 0, 紧跟 data, 再 bss 清零."""
        self.low = bytearray(text) + bytearray(data) + bytearray(bss)
        self.text_end = len(text)
        self.low_end = len(self.low)
        self.brk = self.low_end

    def set_brk(self, addr: int) -> int:
        """语义照抄 kernel/sys.c 的 sys_brk: 合法则更新, 恒返回当前 brk."""
        if self.text_end <= addr < self.start_stack - BRK_STACK_GAP:
            if addr > self.low_end:
                self.low.extend(bytes(addr - self.low_end))
                self.low_end = addr
            self.brk = addr
        return self.brk

    def grow_stack(self, addr: int) -> bool:
        """栈区向下扩展到能覆盖 addr; 超出允许范围返回 False."""
        if addr >= self.stack_low or addr < self.low_end:
            return False
        need = self.stack_low - addr
        step = max(need, STACK_GROW_STEP)
        step = (step + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1)
        new_low = self.stack_low - step
        if new_low < self.low_end:
            new_low = self.low_end
            step = self.stack_low - new_low
            if step <= 0:
                return False
        self.stack = bytearray(step) + self.stack
        self.stack_low = new_low
        return True

    def clone(self) -> "AddressSpace":
        """fork 用: 直接深拷(这个年代进程才几百 KB, 不值得做 CoW)."""
        new = AddressSpace.__new__(AddressSpace)
        new.low = bytearray(self.low)
        new.low_end = self.low_end
        new.stack = bytearray(self.stack)
        new.stack_low = self.stack_low
        new.brk = self.brk
        new.text_end = self.text_end
        new.start_stack = self.start_stack
        return new

    # ---- 访存 ---------------------------------------------------------

    def read(self, addr: int, n: int) -> bytes:
        if 0 <= addr and addr + n <= self.low_end:
            return bytes(self.low[addr:addr + n])
        if addr >= self.stack_low and addr + n <= TASK_SIZE:
            off = addr - self.stack_low
            return bytes(self.stack[off:off + n])
        raise SegFault(addr, n, False)

    def write(self, addr: int, data: bytes) -> None:
        n = len(data)
        if 0 <= addr and addr + n <= self.low_end:
            self.low[addr:addr + n] = data
            return
        if addr >= self.stack_low and addr + n <= TASK_SIZE:
            off = addr - self.stack_low
            self.stack[off:off + n] = data
            return
        if 0 <= addr < self.stack_low and self.grow_stack(addr):
            self.write(addr, data)
            return
        raise SegFault(addr, n, True)

    def read_u8(self, addr: int) -> int:
        if 0 <= addr < self.low_end:
            return self.low[addr]
        if self.stack_low <= addr < TASK_SIZE:
            return self.stack[addr - self.stack_low]
        raise SegFault(addr, 1, False)

    def read_u16(self, addr: int) -> int:
        return _U16.unpack(self.read(addr, 2))[0]

    def read_u32(self, addr: int) -> int:
        return _U32.unpack(self.read(addr, 4))[0]

    def write_u8(self, addr: int, val: int) -> None:
        val &= 0xFF
        if 0 <= addr < self.low_end:
            self.low[addr] = val
            return
        if self.stack_low <= addr < TASK_SIZE:
            self.stack[addr - self.stack_low] = val
            return
        self.write(addr, bytes((val,)))

    def write_u16(self, addr: int, val: int) -> None:
        self.write(addr, _U16.pack(val & 0xFFFF))

    def write_u32(self, addr: int, val: int) -> None:
        self.write(addr, _U32.pack(val & 0xFFFFFFFF))

    # ---- 字符串辅助(系统调用层取路径名用) -----------------------------

    def read_cstr(self, addr: int, limit: int = 4096) -> bytes:
        out = bytearray()
        while len(out) < limit:
            b = self.read_u8(addr + len(out))
            if b == 0:
                return bytes(out)
            out.append(b)
        raise SegFault(addr, limit, False)
