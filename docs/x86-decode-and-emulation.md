# x86 指令解码与仿真:算法与代码流程

本文详细整理仿真器 CPU 层(`cpu86.py` + `x86mem.py`)是怎样把一段 1991 年的
a.out 机器码逐条解释执行的。只覆盖 **ring-3 用户态**:平坦地址空间、不管段
寄存器、不管分页与特权级;遇到 `int N` 陷入注入的回调(内核层在那里实现系统
调用),遇到除零/非法指令/越界访存抛异常。

> 阅读顺序建议:先看第 1 节的总览与状态,再看第 3 节的"解码一次、执行多次"主线,
> 其余小节是各环节的细节展开。所有引用都标了 `文件:行`(行号随代码演进会漂移,
> 以函数名为准)。性能演进的来龙去脉见 `performance-plan.md`。

---

## 1. 总览:一台寄存器机 + 解码缓存 + 一根执行循环

CPU 被建模成一个对象 `CPU`(cpu86.py:1460),持有:

| 字段 | 含义 |
|---|---|
| `regs[8]` | 8 个 32 位通用寄存器,下标即 ModRM 的 reg 编码:`0=EAX 1=ECX 2=EDX 3=EBX 4=ESP 5=EBP 6=ESI 7=EDI` |
| `eip` | 指令指针 |
| `flags` | EFLAGS(即时计算,但计算代码内联在各 handler 里) |
| `mem` | `AddressSpace`,即这个进程的用户地址空间,**解码缓存也挂在它上面** |
| `on_int` / `on_fault` | 注入的回调:`int N` 与故障时上调内核 |
| `halted` | `hlt` 或无回调的 `int` 置位,主循环据此停 |
| `icount` | 已执行指令数(调度器按它的差值记账) |
| `_insn_start` | 最近一次解码/单步的指令起点(报错兜底用;热循环里不维护) |
| `prof` | 性能剖析器,`None` 时关闭 |

寄存器有两套视图:
- **名字视图**:`cpu.eax` 是 8 个 `property`(`_reg_property`,cpu86.py:240),映射到
  `regs[idx]`,方便测试与内核层按名字读写。早先用 `__getattr__/__setattr__` 钩子实现,
  代价是热循环里每次 `self.eip=`/`self.flags=` 都要过一遍 Python 级判断,实测占总耗时
  约 19%,已改掉。
- **子宽度视图**:`get_reg8/set_reg8`(低字节 AL / 次低字节 AH)、`get_reg16/set_reg16`
  (cpu86.py:1480-1497)。8 位编码 0-3 是 AL/CL/DL/BL,4-7 是 AH/CH/DH/BH。

**核心思想:解码与执行分离。** 一条指令第一次遇到时被解成一个不可变元组 `e`
(handler 函数 + 全部解码期常量),缓存在 `mem.icache[eip]`;此后每次执行到它只做
两件事——`eip += 长度`、`e[0](cpu, e)`。取指、前缀、ModRM、SIB、立即数、跳转目标的
计算都只发生一次。这是纯 Python 解释器能做到的最大一步提速(见第 12 节的数据)。

---

## 2. 内存模型(x86mem.py)

`AddressSpace`(x86mem.py:42)把 64MB 用户空间(`TASK_SIZE=0x4000000`)分成三段:

```
[0, text_end)         低区: text(代码) + data + bss,连续一块
   ...空洞(访问抛 SegFault)...
[stack_low, TASK_SIZE) 高区: 栈,向下增长,触碰下沿自动扩(STACK_GROW_STEP)
```

- **读写接口**:`read_u8/u16/u32`、`write_u8/u16/u32`、`read(addr,n)`、`write(addr,bytes)`。
  u16/u32 用 `struct.Struct.unpack_from/pack_into` **直接读写 bytearray**,不经
  `bytes(切片)` 拷贝(单次 127ns → 33ns)。CPU 取指与访存全走它们。
- **越界即故障**:任何落在空洞或越过边界的访问抛 `SegFault`(x86mem.py:31),
  由 CPU 的故障路径转给内核(→ SIGSEGV)。
- **小端**:`read_u16/u32` 按小端组装;间接寻址、立即数都据此。
- **栈自动扩**:压栈触碰 `stack_low` 下沿会自动向下扩一段,对应真实内核的缺页扩栈。
- **brk 与栈之间留 16KB 保护间隙**(`BRK_STACK_GAP`),与内核 `sys_brk` 一致。
- **解码缓存 `icache`**:`load_program` 时建成 `[None] * text_end`(text 超过 8MB 则不建),
  `clone()`(fork)整份复制,**不与父进程共享**;所有落在 `[0, text_end)` 的写都会调
  `_flush_icache(addr, n)`,就地把 `[addr-15, addr+n)` 的槽位清成 None(一条指令最长
  15 字节,所以往前多清 15 项)。就地切片赋值保持 list 身份,`CPU.run()` 里持有的局部引用
  不会失效。正常程序永不写 text,这一步只为不改变"text 可写"的既有行为。

CPU 对内存的全部依赖就是"给我地址、还我字节"+"给我 eip、还我缓存槽",没有 MMU、
没有 TLB、没有页表。

---

## 3. 主线:解码一次、执行多次

一条指令的生命周期:`run()` → 查 `icache[eip]` → 未命中则 `_decode()` → `e[0](cpu, e)`。

### 3.1 已解码指令元组 `e`

```
e = (fn, length, size, reg, base, index, scale, disp, imm, mod)
     [0]   [1]    [2]  [3]  [4]   [5]    [6]   [7]   [8]  [9]
```

| 字段 | 含义 |
|---|---|
| `fn` | 模块级函数 `fn(cpu, e)`,直接执行这条指令 |
| `length` | 整条指令字节数(含前缀),命中时 `eip += length` |
| `size` | 操作数尺寸 1/2/4 |
| `reg` | ModRM.reg / opcode 内编码的寄存器 / 条件码 / 子操作码 |
| `base` | 寄存器形态:rm 寄存器号;内存形态:基址寄存器号或 None |
| `index`, `scale` | SIB 索引寄存器号(None=无)与比例 0..3 |
| `disp` | 位移(绝对寻址形态已 `& MASK32`,其余为有符号整数) |
| `imm` | 立即数 / **已算好的绝对跳转目标** / rep 前缀 / 其它常量 |
| `mod` | ModRM.mod(3 = 寄存器形态;无 ModRM 的指令填 3) |

`e` 里**没有任何运行期值**(有效地址在执行时才用 `regs` 算),所以可以缓存,也可以
被 fork 出的子进程整份带走。

### 3.2 主循环 `run()`(cpu86.py:1680)

```python
def run(self, max_steps):
    if self.prof is not None: return self._run_profiled(max_steps)   # 剖析版, 结构相同
    if self.halted: return 0
    cache = self.mem.icache; cache_end = len(cache); on_fault = self.on_fault
    done = 0
    try:
        for _ in range(max_steps):
            eip = self.eip
            if eip >= MAGIC_EIP_BASE: raise MagicJump(eip)       # 魔数返回地址(3.6)
            try:
                if eip < cache_end:                              # 在 text 区内
                    e = cache[eip]
                    if e is None:                                # 未命中: 解码并缓存
                        e = self._decode(eip)
                        if self.eip <= cache_end: cache[eip] = e # 整条都在 text 内才缓存
                    else:
                        self.eip = eip + e[1]                    # 命中: 只推 eip
                else:
                    e = self._decode(eip)                        # 栈/堆上的代码: 不缓存
                e[0](self, e)                                    # 执行
            except SegFault as ex:   ... on_fault(self, ex)      # → SIGSEGV
            except DivideError as ex: ... on_fault(self, ex)     # → SIGFPE
            done += 1
    except _Halt:
        done += 1                                                # hlt 那条也算执行了
    finally:
        self.icount += done                                      # 一次性记账
    return done
```

要点:
- **一次跑一个时间片**:调度器每次调 `cpu.run(TIMESLICE)`,跑满 10 万条就返回。
- **`icount` 在 `finally` 里一次性加**:Blocked/Exited/Replaced/MagicJump 都是异常穿出,
  已完成的条数照样计入;调度器用 `icount` 的**差值**记账,所以不能漏。
- **`halted` 不逐条检查**:`hlt`(以及无 `on_int` 时的 `int`)置位后抛私有异常 `_Halt`
  跳出循环,省掉每条一次的属性读。
- **`fn` 执行前 eip 已指向下一条指令**(无论命中还是刚解码)。这是全模块最重要的约定:
  `int 0x80` 阻塞回卷的 `eip -= 2`、反汇编长度对照(`eip - start`)、`_bad` 报错取字节
  都靠它;转移指令则在 `fn` 里改写 eip。
- `step()`(cpu86.py:1774)走同一条缓存路径,供 monitor 单步与测试用;`_run_profiled`
  多一行 `prof.record(eip, mem)`,其余相同。

### 3.3 解码 `_decode(start)`(cpu86.py:1798)

```python
def _decode(self, start):
    op = mem.read_u8(start); eip = start + 1
    if op in _PREFIXES:                              # 0x66 / 段前缀 / lock / rep
        opsize = 4; rep = 0
        while op in _PREFIXES:
            if op == 0x66: opsize = 2
            elif op in (0xF2, 0xF3): rep = op
            op = mem.read_u8(eip); eip += 1          # 段前缀、lock 平坦模型下忽略
        self.eip = eip
        if rep and 串指令: return (_h_string, eip - start, opsize, op, ..., rep, 3)
        if rep and op == 0x90: return (_h_nop, ...)  # f3 90 = pause
        return _DEC[op](self, op, opsize, start)
    self.eip = eip
    return _DEC[op](self, op, 4, start)              # 绝大多数指令无前缀: 直达
```

**分派是 256 项表 `_DEC`**(0F 两字节再查 `_DEC0F`),没有 if 链。每个解码器的签名是
`dec(cpu, op, opsize, start) -> e`:进入时 `cpu.eip` 已越过 opcode 字节,解码器用
`cpu._fetch8/16/32()` 继续啃 ModRM/SIB/disp/imm,返回时 `cpu.eip` 恰好指向下一条,
`length = cpu.eip - start`。未注册的 opcode 落到 `_dec_bad`,产出一个执行时抛
`CpuError` 的 `e`(带 opcode 与机器码字节)。

解码器只有 42 个(按指令族),因为同族指令共用一个解码器、靠 opcode 低位区分。
下表是 `_DEC` 覆盖的 opcode 集(与 Profiler 的 `_OP_CATEGORY` 表一致):

| opcode | 指令族 | 解码器 → handler |
|---|---|---|
| `00-3F`(且 `op&7 < 6`) | ALU 8 族 × 6 形 | `_dec_alu` → 模板 `alu_rm_r / alu_r_rm / alu_rm_imm` |
| `40-4F` | inc/dec reg | `_dec_incdec_r` → 模板 `inc/dec` 的寄存器形态 |
| `50-5F` | push/pop reg | `_h_push_r32/_h_pop_r32`(16 位另有变体) |
| `68/6A` | push imm | `_h_push_imm32/16` |
| `69/6B` | imul r,r/m,imm | `_h_imul3`(胖 handler) |
| `70-7F` | jcc rel8 | 16 个模板 `jcc`,`imm` = 绝对目标 |
| `80/81/83` | ALU r/m, imm | 模板 `alu_rm_imm`,立即数解码期已截断/符号扩展 |
| `84/85` | test | 模板 `test_rm_r` |
| `86/87` | xchg r/m,r | 模板 `xchg` |
| `88-8B` | mov(四个方向) | 模板 `mov_rm_r / mov_r_rm` |
| `8D` | lea | 模板 `lea`(寄存器形态填报错 handler) |
| `8F` | pop r/m | `_h_pop_rm` |
| `90` / `91-97` | nop / xchg eax,r | `_h_nop` / `_h_xchg_eax_r` |
| `98/99`, `9C-9F` | cbw/cwd, pushf/popf, sahf/lahf | 对应 `_h_*` |
| `A0-A3` | mov eax↔moffs | `_h_mov_*_moffs` |
| `A4-AF` | 串指令(无 rep) | `_h_string` → `_string_op(op, size, 0)` |
| `A8/A9` | test al/eax, imm | 模板 `test_rm_imm` 的寄存器形态 |
| `B0-BF` | mov reg, imm | `_h_mov_r8_imm / _h_mov_r32_imm / _h_mov_r16_imm` |
| `C0/C1/D0-D3` | 移位/循环移位 | 模板 `shift`(按 kind × 尺寸 × 形态 × 计数来源) |
| `C2/C3` | ret [imm16] | `_h_ret_n / _h_ret` |
| `C6/C7` | mov r/m, imm | 模板 `mov_rm_imm` |
| `C8/C9` | enter/leave | `_h_enter / _h_leave` |
| `CC/CD` | int3 / int imm8 | `_h_int` → `on_int`(见 3.5) |
| `D7`, `E0-E3` | xlat, loop 族/jecxz | `_h_xlat`, `_h_loop` |
| `E8/E9/EB` | call/jmp rel | `_h_call_rel / _h_jmp`,目标解码期算好 |
| `F4` | hlt | `_h_hlt`(抛 `_Halt`) |
| `F6/F7` | test/not/neg/mul/imul/div/idiv | 模板 `test_rm_imm / not / neg`;乘除 → `_h_muldiv` |
| `F8/F9/FC/FD` | clc/stc/cld/std | `_h_clc` 等 |
| `FE/FF` | inc/dec/call/jmp/push(间接) | 模板 `inc/dec/call_rm/jmp_rm/push_rm` |
| `0F xx` | 两字节 opcode | `_dec_0f` → `_DEC0F`(见 3.4) |

### 3.4 两字节 opcode `_DEC0F`

- `80-8F` jcc rel32 → 同 `70-7F` 的 16 个 `jcc` handler
- `90-9F` setcc r/m8 → 模板 `setcc`
- `AF` imul r, r/m → `_h_imul2`
- `A3/AB/B3/BB/BA` bt/bts/btr/btc → `_h_bt_r`(寄存器位号)/ `_h_bt_i`(立即数位号)
- `BC/BD` bsf/bsr → `_h_bsf`
- `A4/A5/AC/AD` shld/shrd → `_h_shd`
- `B6/B7/BE/BF` movzx/movsx → 模板 `movx`(按符号扩展 × 源尺寸 × 目标尺寸)
- 其它 → `_dec_bad0f`

### 3.5 陷入内核:`int`、故障

- **`int N`**(`CC`=int3 / `CD imm8`):`_h_int` 若 `on_int` 为空则置 `halted` 并抛 `_Halt`,
  否则调 `cpu.on_int(cpu, vec)`。内核在回调里读 `regs[0..3]` 当作调用号与参数,处理完把
  返回值写回 `eax`。**Linux 0.11 的系统调用就是 `int 0x80`**,所以 `int` 是用户态与内核态的
  唯一门。此刻 eip 已在 `CD 80` 之后,阻塞时调度器 `eip -= 2` 回卷即可重做。
- **`SegFault` / `DivideError`**:在 `run()` 的内层 `try` 里被接住,调 `on_fault`,内核转成
  SIGSEGV/SIGFPE。若没有注入回调(纯 CPU 单测),就把异常继续抛出。

### 3.6 魔数返回 `MagicJump`

0.11 **没有 sigreturn 系统调用**,信号返回靠 libc 的 `sa_restorer` 在用户态弹栈。
当 `restorer` 为 0 时,内核压帧时用一个 `MAGIC_EIP_BASE`(0xFFFF0000)之上的假地址当返回
地址;执行流一旦跳到那里,主循环头部的检查抛 `MagicJump`,穿到调度器由 `_sigreturn`
弹出信号帧。

### 3.7 指令长度:解码的副产品,缓存后成为常量

x86 是**可变长度指令集**,1 到 15 字节:

```
[前缀 0..4 字节] [opcode 1..2 字节] [ModRM 0/1] [SIB 0/1] [disp 0/1/4] [imm 0/1/2/4]
```

解码器从不显式查"每个 opcode 多少字节"的长度表——长度是**取指过程的副产品**:
`_fetch8/16/32` 每读一段就把 `eip` 往前推,等一条指令的所有部件都取完,
`cpu.eip - start` 就是长度,存进 `e[1]`。之后每次命中直接 `eip += e[1]`。

显式用到长度的地方:
- **报错**:`_h_bad` 用 `cpu.eip - e[1]` 还原指令起点,连同机器码原文塞进 `CpuError`。
- **阻塞回卷**:`int 0x80` 固定 2 字节,调度器 `eip -= 2`——唯一"硬编码某条指令长度"的地方,
  因为它在 `step()` 之外倒推。
- **反汇编器对照**:`cpu_disasm.py` 独立算长度,`test_cpu_disasm` 用 `step()` 后的
  `eip - start` 逐条对照,所以"fn 执行前 eip 已在末尾"的约定是这项测试的前提。

---

## 4. 寻址:`_modrm_dec` 与四种寻址形态

绝大多数指令的"第二操作数"由 opcode 后的 **ModRM 字节**指定:

```
 7 6 | 5 4 3 | 2 1 0
 mod |  reg  |  rm
```

`_modrm_dec(cpu)`(cpu86.py:950)一次解完 ModRM(+SIB+disp),返回
`(mod, reg, base, index, scale, disp)`:

| mod | rm 的含义 |
|---|---|
| `3` | rm 是寄存器(`base` = rm 寄存器号) |
| `0` | `[寄存器]`,无偏移(特例:rm=5 → disp32 绝对,`base=None`;rm=4 → 走 SIB) |
| `1` | `[寄存器 + disp8]` |
| `2` | `[寄存器 + disp32]` |

SIB(rm==4):`base + index*scale`,`index==4` 表示无索引(`index=None`),
`base==5 且 mod==0` 表示无基址只有 disp32(`base=None`)。

然后 `_mk()`(cpu86.py:996)按解码结果把操作数归入**四种寻址形态**,选对应的 handler 变体:

| form | 形态 | handler 里的有效地址表达式 | 出现频率(gcc 输出) |
|---|---|---|---|
| 0 | 寄存器 | 无(直接 `regs[d]`) | — |
| 1 | `[disp32]` 绝对 | `e[7]`(解码期已 `& MASK32`) | 少 |
| 2 | `[base + disp]` | `(regs[e[4]] + e[7]) & M` | 内存操作数的 ~85% |
| 3 | 含索引的通用 SIB | `(e[7] + (regs[e[5]] << e[6]) + (regs[e[4]] if e[4] is not None else 0)) & M` | ~15% |

按形态生成专用变体,是为了让最常见的 `[ebp-8]`、`[esp+4]`、`[ebx]` 只花一次加法,
不必每次判断"有没有索引、有没有基址"。

罕见指令的"胖 handler"(imul、mul/div、bt 族、shld/shrd、bsf、pop r/m)不分形态,
用 `_ea_of(regs, e)`(cpu86.py:271)算地址(寄存器形态返回 None),再复用旧式的
`cpu._read_rm(mod, rm, addr, size) / _write_rm(...)`(cpu86.py:1573-1617)。

`opsize`(默认 4,遇 0x66 变 2)在**解码期就消化掉**:解码器按它选 handler 变体,
运行期不再有尺寸分支。字节指令(如 `88`、`F6`)把 size 固定成 1。

---

## 5. 模板生成的 handler(cpu86.py:289-580)

ModRM 族指令的数量 = 操作 × 尺寸(1/2/4)× 寻址形态(4)× 方向,手写会有几百个近似
重复的函数。所以它们由**模板生成**:

- 片段构造函数:`_rd_reg/_wr_reg`(按尺寸读写寄存器,8 位要区分 AL/AH 那半)、
  `_rm_rd/_rm_wr`(r/m 操作数,寄存器形态走 `regs[d]`,内存形态走 `mem.read_*/write_*(addr)`)、
  `_setup(form)`(算有效地址)、`_alu_body(op)`、`_f_add/_f_sub/_F_LOGIC`(标志)、
  `_shift_body/_shift_flags`、`_INC_BODY/_DEC_BODY`。
- `_emit(kind, args, form)`(cpu86.py:457)把片段拼成一个 handler 的语句列表,并返回该
  handler 的尺寸;`_gen()`(cpu86.py:531)把占位符 `MASK/SIGN/BITS` 替换成**字面量**、
  拼成 `def h_xxx(cpu, e):` 源码、`compile` + `exec`,并把源码登记进 `linecache`——
  traceback 能显示生成代码的行,`CPU86_DUMP_GEN=1` 还能把生成的源码转储到 stderr。
- **惰性生成**:各族的变体表是 `_LazyForms`(cpu86.py:558,一个带 `__missing__` 的 dict),
  解码器第一次取 `_ALU_RM_R[op, size]` 时才生成并编译该族的 4 个形态。全部 680 多个变体一次
  生成要 150ms 的 import 时间,而一个程序实际只用到一两百个。

生成出来的 `add [ebp-8], eax`(`alu_rm_r`,op=0,size=4,form=2)长这样:

```python
def h_alu_rm_r_0_4_2(cpu, e):
    regs = cpu.regs
    mem = cpu.mem
    addr = (regs[e[4]] + e[7]) & M
    a = mem.read_u32(addr)
    r = e[3]
    b = regs[r]
    res = a + b
    t = res & 0xffffffff
    f = EFLAGS_BASE | (cpu.flags & DF)
    if res > 0xffffffff: f |= CF
    if t == 0: f |= ZF
    if t & 0x80000000: f |= SF
    if (~(a ^ b)) & (a ^ t) & 0x80000000: f |= OF
    if (a & 0xF) + (b & 0xF) > 0xF: f |= AF
    cpu.flags = f | _PARITY[t & 0xFF]
    res = t
    mem.write_u32(addr, res)
```

没有函数调用(访存除外)、没有尺寸分支、没有方法查找。这就是"标志内联"——
惰性标志方案(读时才算)被评估为收益不抵复杂度,见 `performance-plan.md`。

三处把 ModRM 的 **reg 字段**当第二级 opcode 的组指令,现在在解码器里分流:
`_dec_grp_f7`(test/not/neg → 模板;mul/imul/div/idiv → `_h_muldiv` 复用
`_mul_unsigned/_mul_signed/_div_unsigned/_div_signed`,cpu86.py:1836-1949)、
`_dec_grp_ff`(inc/dec/call/jmp/push)、`_dec_shift`(rol/ror/shl/shr/sar;rcl/rcr 未实现,
产出报错 handler)。x86 除法**向零取整**,与 Python 的向下取整不同,故用 `_trunc_divmod`。

---

## 6. 标志位模型

采取**即时计算**:每条影响标志的指令算完结果后,立刻按位重建 EFLAGS,但计算代码
内联在 handler 里(第 5 节),mask/符号位是字面量:

- 逻辑运算(and/or/xor/test):CF=OF=0,按结果置 ZF/SF/PF,AF 未定义置 0。
- 加/减(add/adc/sub/sbb/cmp/neg):完整 CF、ZF、SF、**OF(符号溢出)**、**AF(半进位)**、PF。
  OF 用经典的"符号位一致性"判据(`~(a^b) & (a^res) & sign` / `(a^b) & (a^res) & sign`)。
- inc/dec:走 add/sub 规则,但**保留 CF 不变**(x86 规定),实现是 `f = BASE | (flags & (DF|CF))`。
- 移位:CF/OF 的取法各类不同,逐类精确实现;计数为 0 时**标志不变**(handler 直接 return);
  循环移位只改 CF/OF。
- **PF 查表** `_PARITY`(cpu86.py:58):低 8 位 1 的个数为偶则置位,预生成 256 项表。

CPU 类上仍保留 `_set_add_flags/_set_sub_flags/_set_logic_flags`(cpu86.py:1628-1672),
供串指令 cmps/scas 与胖 handler 复用,语义与内联版逐位相同(差分对照测试保证)。

条件码 `_COND_EXPR`(cpu86.py:437):把 jcc/setcc 的低 4 位翻译成对 EFLAGS 的表达式
(o/no/b/ae/e/ne/be/a/s/ns/p/np/l/ge/le/g),有符号比较用 `SF != OF` 判据
(`((f >> 7) ^ (f >> 11)) & 1`)。16 个 `jcc`/`setcc` handler 各自内联一条表达式,不再有
`_cond` 的 if 链;`CPU._cond(code)` 保留给非热路径。

---

## 7. 串指令与 rep(cpu86.py:1953)

`movs/stos/lods/scas/cmps`(A4-AF),可带 `rep/repe/repne` 前缀。解码期 `_decode` 认出
rep 前缀就直接产出 `_h_string`,执行时调 `_string_op(op, size, rep)`,真正执行在
`_string_op_impl`:

- **方向由 DF 决定**:DF=1 时地址递减(memmove 反向拷贝要用),`delta = ±size`。
- **rep 计数在 ECX**:一条 `rep movs` 在一次执行里把 ECX 个元素全搬完——**它只算一条指令,
  却做了 N 个元素的活**,这是性能上很值得注意的一点(Profiler 的"rep 放大倍数"就是量它)。
- **整块快路径**:正向、无重叠的 `rep movs/stos` 直接一次 `mem.write(...)` 整块搬。
- **repe/repne 提前结束**:cmps/scas 按 ZF 与前缀类型(F3/F2)决定是否中途停。

---

## 8. 栈、调用约定相关

- `push32/pop32`(cpu86.py:1539-1560):ESP 先减 4 再写(压),或先读再加 4(弹)。
  热路径 handler(`_h_push_r32/_h_pop_r32/_h_call_rel/_h_ret`)把这两步内联;`pop esp` 的
  语义是"先动 ESP 再写目标寄存器",`_h_pop_r32` 按此顺序。
- `call`(E8 / FF/2):压 `eip`(此刻已是返回地址)后改 eip;`ret`(C3 / C2 imm16):
  弹回 eip,C2 再把 ESP 加 imm16。
- `enter/leave`(C8/C9):建立/拆除栈帧;`leave` = `mov esp,ebp; pop ebp`。
- `pushf/popf`(9C/9D):EFLAGS 进出栈;`popf` 经 `eflags` setter 过滤保留位。
- `pop [esp+x]`(8F):先按弹出前的 ESP 算地址,再弹,再写。

---

## 9. 快照:fork 与信号帧(cpu86.py:1563)

`snapshot()` / `restore()` 只拷 `regs / eip / flags` 三样。用途:
- **fork**:子进程新建 CPU 后 `restore(parent.snapshot())`,再把子进程 `eax` 置 0。
  地址空间另行 `clone()`(连同解码缓存副本)。**`restore()` 会替换 `regs` 这个 list 对象**,
  所以任何 handler 都不能在解码期绑定 `regs`,只能每次 `cpu.regs`——这是 `e` 里不放
  运行期引用的另一个理由。
- **信号帧**:内核建立/返回信号处理时保存/恢复上下文。

---

## 10. 异常一览:CPU 层怎么把控制权交出去

| 异常 | 抛出点 | 谁接 | 语义 |
|---|---|---|---|
| `SegFault`(x86mem) | 任何越界访存(解码期取指或执行期) | `run()` → `on_fault` | → SIGSEGV |
| `DivideError` | div/idiv 除零或溢出 | `run()` → `on_fault` | → SIGFPE |
| `CpuError` | `_h_bad/_h_lea_reg`:未实现/非法 opcode | 一路抛到仿真器顶层 | 带 eip 与机器码字节 |
| `MagicJump` | 主循环头:eip 落到魔数区 | 调度器 `_sigreturn` | 无 sigreturn 时的信号返回兜底 |
| `_Halt`(私有) | `_h_hlt` / 无 `on_int` 的 `_h_int` | `run()`/`step()` 自己接 | 置 `halted` 后跳出循环 |
| `on_int` 回调内可能抛 | execve 会抛 `Replaced`、阻塞抛 `Blocked` 等 | 调度器 | 见内核层文档 |

x87 浮点**未实现**(镜像 libc 是软浮点):遇到浮点 opcode 抛带 eip 与机器码字节的
`CpuError`——这是刻意策略,不静默跳过。

---

## 11. 一条指令的完整走查(例)

以 `add [ebx+4], eax` 为例,机器码 `01 43 04`,第一次执行:

1. `run()`:`eip < len(icache)` 且 `icache[eip] is None` → `_decode(eip)`。
2. `_decode`:首字节 `0x01` 不是前缀,`self.eip = start+1`,查 `_DEC[0x01]` = `_dec_alu`。
3. `_dec_alu`:`alu = 0`(add),`form = 1`(r/m, r 方向),调 `_modrm_dec`:读 `0x43 = 01 000 011`
   → mod=1、reg=0(EAX)、rm=3(EBX);mod==1 再读 disp8 `0x04`。返回 `(1, 0, 3, None, 0, 4)`。
4. `_mk`:index 为 None、base 非 None → form 2(`[base+disp]`);取 `_ALU_RM_R[0, 4][2]`
   (首次取用触发 `_gen` 生成 4 个形态的 handler),组装
   `e = (h_alu_rm_r_0_4_2, 3, 4, 0, 3, None, 0, 4, 0, 1)`。
5. 整条都在 text 内 → `icache[eip] = e`;此刻 `self.eip` 已是 start+3。
6. `e[0](self, e)`:即第 5 节展示的那段生成代码——算 `addr = (regs[3] + 4) & M`,读、加、
   置标志、写回。
7. `done += 1`;下一轮从 start+3 继续。

第二次执行到同一地址:步骤 2-5 全部跳过,只剩 `self.eip = eip + 3` 与步骤 6。

再看一条控制流 `jne +5`,机器码 `75 05`:解码期 `_dec_jcc8` 取 rel8 并算出**绝对目标**
`(eip_after + 5) & M` 放进 `e[8]`,handler 是 `h_jcc_5`:`f = cpu.flags; if not (f & ZF): cpu.eip = e[8]`。

---

## 12. 设计取舍备忘

- **解码缓存 vs 每次重解码**:早期版本每条指令都重新取字节、走一条 20 来个 `if` 的
  线性分派链,约 0.4 MIPS;分离解码/执行、查表分派、模板内联、解码缓存四步之后约 2.9 MIPS
  (gzip 基准 15.9s → 2.3s,awk 十万次循环 692s → 88s,输出逐字节不变,与旧实现逐条状态
  哈希一致)。数据与每步收益见 `performance-plan.md`。
- **元组 vs 闭包**:缓存项用元组而非绑定了操作数的闭包,是因为 `restore()` 会替换 `regs`
  对象、fork 要整份带走缓存——元组里只有常量,天然安全。
- **模板 exec vs 手写**:形状单一的 ~50 条指令手写(`_h_*`),ModRM 族由模板生成;
  `functools.partial` 被排除(C 层多一次参数拼接,反而比闭包慢)。
- **惰性标志**:评估过"记录操作数、读标志时才算"的方案,收益约 6-15%,却是最容易引入细微
  标志错误的一步(AF/OF 边界、adc 进位反推),目前不做;把标志计算内联进 handler 已拿到其中
  最便宜的一半收益。
- **不做 cmp+jcc 窥孔融合**:会让 `run(1)` 一步跨两条、jcc 地址上的断点命中不到、
  icount/Profiler 少记。
- **不做地址尺寸 16 位寻址**:32 位足够跑这个镜像的用户程序。
- **能不实现就不实现,但不静默**:x87、rcl/rcr、部分 0F 都以 `CpuError`(带 eip 与字节)
  显式报错,而不是当 nop 跳过。
- **热路径纪律**(实测的教训):不给 `CPU` 加 `__setattr__/__getattr__` 钩子;访存用
  `unpack_from/pack_into`;按尺寸取 mask/符号位用字面量或元组 `_MASK/_SIGN`;每条必走的
  代码里不做属性存储、不调方法。任何逐指令开销都会被放大数千万倍。改动 CPU 层前后跑
  `python3 emulator.py hdc-0.11.img /usr/bin/gzip -c /bin/date | md5sum`
  (应为 `d4bc050cbdacd8db08423d8dc7a43313`)并计时。

---

## 附:关键函数索引

| 环节 | 函数 | 位置 |
|---|---|---|
| 主循环 | `CPU.run` / `_run_profiled` / `step` | cpu86.py:1680 / 1729 / 1774 |
| 解码入口(前缀) | `CPU._decode` | cpu86.py:1798 |
| 分派表 | `_DEC` / `_DEC0F` + 42 个 `_dec_*` | cpu86.py:1040 起 |
| ModRM/SIB | `_modrm_dec` / `_mk` / `_E` | cpu86.py:950 / 996 / 1019 |
| 有效地址(胖 handler) | `_ea_of` | cpu86.py:271 |
| 模板片段 | `_rd_reg/_wr_reg/_rm_rd/_rm_wr/_setup` | cpu86.py:289-333 |
| 标志片段 | `_f_add/_f_sub/_F_LOGIC/_alu_body/_INC_BODY/_shift_flags` | cpu86.py:336-435 |
| 生成器 | `_emit` / `_gen` / `_LazyForms` | cpu86.py:457 / 531 / 558 |
| 手写 handler | `_h_*`(47 个) | cpu86.py:583-946 |
| 乘除 | `_mul_unsigned/_mul_signed/_div_unsigned/_div_signed` | cpu86.py:1836 |
| 串指令 | `_string_op` / `_string_op_impl` | cpu86.py:1953 / 1966 |
| 栈 | `push32/pop32/...` | cpu86.py:1539 |
| 快照 | `snapshot/restore` | cpu86.py:1563 |
| 报错 | `_bad` / `_h_bad` | cpu86.py:1825 / 599 |
| 内存与解码缓存 | `AddressSpace`(read/write/扩栈/`icache`/`_flush_icache`) | x86mem.py:42 |
