# x86 指令解码与仿真:算法与代码流程

本文详细整理仿真器 CPU 层(`cpu86.py` + `x86mem.py`)是怎样把一段 1991 年的
a.out 机器码逐条解释执行的。只覆盖 **ring-3 用户态**:平坦地址空间、不管段
寄存器、不管分页与特权级;遇到 `int N` 陷入注入的回调(内核层在那里实现系统
调用),遇到除零/非法指令/越界访存抛异常。

> 阅读顺序建议:先看第 1 节的总览与状态,再看第 3 节的取指-解码-执行主线,
> 其余小节是各环节的细节展开。所有引用都标了 `文件:行`。

---

## 1. 总览:一台寄存器机 + 一根解释循环

CPU 被建模成一个对象 `CPU`(cpu86.py:208),持有:

| 字段 | 含义 |
|---|---|
| `regs[8]` | 8 个 32 位通用寄存器,下标即 ModRM 的 reg 编码:`0=EAX 1=ECX 2=EDX 3=EBX 4=ESP 5=EBP 6=ESI 7=EDI`(cpu86.py:21) |
| `eip` | 指令指针 |
| `flags` | EFLAGS(朴素即时计算,正确性优先) |
| `mem` | `AddressSpace`,即这个进程的用户地址空间 |
| `on_int` / `on_fault` | 注入的回调:`int N` 与 故障 时上调内核 |
| `halted` | `hlt` 或无回调的 `int` 置位,主循环据此停 |
| `icount` | 已执行指令数(调度器按它记账) |
| `_insn_start` | 本条指令的起始 eip(报错与剖析用) |
| `prof` | 性能剖析器,`None` 时关闭(见 `docs` 之外的剖析说明) |

寄存器有两套视图:
- **名字视图**:`cpu.eax` 经 `__getattr__/__setattr__`(cpu86.py:249-260)映射到
  `regs[REG32_NAMES.index(...)]`,方便测试与内核层按名字读写。
- **子宽度视图**:`get_reg8/set_reg8`(低字节 AL / 次低字节 AH)、`get_reg16/
  set_reg16`(cpu86.py:229-247)。8 位编码 0-3 是 AL/CL/DL/BL,4-7 是 AH/CH/DH/BH。

没有解码缓存(cpu86.py 注释明说"本阶段不做解码缓存"):每条指令都从内存重新
取字节、重新解码。主循环因此非常朴实,也非常热——任何逐指令的额外开销都会被
放大到数千万倍(这正是性能剖析要做成两档、默认关的原因)。

---

## 2. 内存模型(x86mem.py)

`AddressSpace`(x86mem.py:42)把 64MB 用户空间(`TASK_SIZE=0x4000000`,x86mem.py:18)
分成三段:

```
[0, text_end)         低区: text(代码) + data + bss,连续一块
   ...空洞(访问抛 SegFault)...
[stack_low, TASK_SIZE) 高区: 栈,向下增长,触碰下沿自动扩(STACK_GROW_STEP)
```

- **读写接口**:`read_u8/u16/u32`、`write_u8/u16/u32`、`read(addr,n)`、`write(addr,bytes)`
  (x86mem.py:107-165)。CPU 取指与访存全走它们。
- **越界即故障**:任何落在空洞或越过边界的访问抛 `SegFault`(x86mem.py:31),
  由 CPU 的故障路径转给内核(→ SIGSEGV)。
- **小端**:`read_u16/u32` 按小端组装;间接寻址、立即数都据此。
- **栈自动扩**:压栈触碰 `stack_low` 下沿会自动向下扩一段(x86mem.py:81),
  对应真实内核的缺页扩栈。
- **brk 与栈之间留 16KB 保护间隙**(`BRK_STACK_GAP`,x86mem.py:22),与内核
  `sys_brk` 一致。

CPU 对内存的全部依赖就是"给我地址、还我字节",没有 MMU、没有 TLB、没有页表。

---

## 3. 取指-解码-执行主线

一条指令的生命周期:`run()` → `step()` → (前缀循环) → `_execute()` → 具体处理。

### 3.1 主循环 `run()`(cpu86.py:542)

```python
def run(self, max_steps):
    if self.prof is not None:            # 剖析开启走插桩版(见 _run_profiled)
        return self._run_profiled(max_steps)
    n = 0
    while n < max_steps and not self.halted:
        try:
            self.step()                  # 执行一条
        except SegFault as e:            # 越界访存
            if self.on_fault is None: raise
            self.on_fault(self, e)       # 上调内核 → SIGSEGV
        except DivideError as e:         # 除零/除法溢出
            if self.on_fault is None: raise
            self.on_fault(self, e)       # 上调内核 → SIGFPE
        n += 1
        self.icount += 1                 # 每条 +1(记账在这里, 不在 step)
    return n
```

要点:
- **一次跑一个时间片**:调度器每次调 `cpu.run(TIMESLICE)`,跑满 10 万条就返回,
  轮到下一个进程(协作式调度,见 kernel 调度文档)。
- **`icount` 在 `run()` 里加**,不在 `step()` 里——即便某条指令走了故障路径,
  也算一条。调度器用 `icount` 的**差值**记账,因为 Blocked/Exited 都是异常路径,
  靠 `run()` 返回值会漏记。
- **`MagicJump` 不在这里接**:它从 `step()` 抛出后一路穿到调度器,用于信号返回
  兜底(见 3.6)。

### 3.2 一条指令 `step()`:前缀循环 + 分派(cpu86.py:585)

```python
def step(self):
    if self.eip >= MAGIC_EIP_BASE:       # 0xFFFF0000 之上是魔数返回地址
        raise MagicJump(self.eip)        # 内核用它兜底信号返回
    self._insn_start = self.eip          # 记本条起点(报错/剖析用)
    opsize = 4                           # 默认 32 位操作数
    rep = 0                              # rep/repne 前缀
    while True:                          # ── 前缀消费循环 ──
        op = self._fetch8()
        if op == 0x66: opsize = 2; continue          # 操作数尺寸前缀 → 16 位
        if op in (0x2E,0x36,0x3E,0x26,0x64,0x65): continue  # 段前缀: 平坦模型忽略
        if op == 0xF0: continue                      # lock: 忽略
        if op in (0xF2,0xF3): rep = op; continue     # rep/repne
        break                            # 第一个非前缀字节 = 真正的 opcode
    if rep and 0xA4 <= op <= 0xAF:       # 带 rep 的串指令走专门路径
        self._string_op(op, opsize, rep); return
    if rep and op == 0x90:               # f3 90 = pause, 当 nop
        return
    self._execute(op, opsize)            # 分派执行
```

**取指** `_fetch8/16/32`(cpu86.py:271-284):从 `mem` 按 eip 读,并把 eip 前进
1/2/4 字节。整个解码就是不断 `_fetch*` 往前啃字节:opcode → (ModRM → SIB → disp)
→ 立即数。eip 走到哪,下一条就从哪开始。

**前缀**只实现了会影响语义的两类:
- `0x66` 操作数尺寸 → `opsize=2`(把 32 位指令变 16 位);
- `0xF2/0xF3` rep/repne(只对串指令有意义)。
- 段前缀、`lock`、地址尺寸前缀在平坦用户态无意义,消费掉即可。

### 3.3 分派 `_execute(op, opsize)`(cpu86.py:618)

**核心数据结构就是一条按 opcode 数值分段的线性 `if / return` 链**——不是查表、
不是字典,而是一串区间判断,每段末尾 `return`。开头缓存了两个局部量
`regs = self.regs`、`mem = self.mem`(cpu86.py:619-620)以省去属性查找。

分段顺序大致按 opcode 从小到大:

| opcode | 指令族 | 处理 |
|---|---|---|
| `00-3F`(且 `op&7 < 6`) | ALU 8 族 × 6 形 | 解出 `alu_op=op>>3`、`form=op&7`,调 `_alu` |
| `40-4F` | inc/dec reg | 直接算,`_set_inc_flags` |
| `50-5F` | push/pop reg | `push32/pop32` |
| `68/6A` | push imm32/imm8 | |
| `69/6B` | imul r,r/m,imm | |
| `70-7F` | jcc rel8 | `_cond(op&0xF)` 决定是否跳 |
| `80/81/83` | ALU r/m, imm | reg 字段选 ALU 子操作 |
| `84/85` | test | |
| `86/87` | xchg r/m,r | |
| `88-8B` | mov(四个方向) | |
| `8D` | lea(只算地址不访存) | |
| `8F` | pop r/m | |
| `90` / `91-97` | nop / xchg eax,r | |
| `98/99` | cbw/cwde、cwd/cdq | 符号扩展 eax |
| `9C/9D` | pushf/popf | |
| `9E/9F` | sahf/lahf | |
| `A0-A3` | mov eax↔moffs(绝对地址) | |
| `A4-AF` | 串指令(无 rep,执行一次) | 转 `_string_op(...,0)` |
| `A8/A9` | test al/eax, imm | |
| `B0-BF` | mov reg, imm | |
| `C2/C3` | ret [imm16] | |
| `C6/C7` | mov r/m, imm | |
| `C8/C9` | enter/leave | |
| `CC/CD` | int3 / int imm8 | 上调 `on_int`(见 3.5) |
| `E0-E3` | loop 族 / jecxz | |
| `E8/E9/EB` | call rel32 / jmp rel32 / jmp rel8 | |
| `F4` | hlt | 置 `halted` |
| `F6/F7` | test/not/neg/mul/imul/div/idiv | 转 `_group_f7` |
| `F8-FD` | clc/stc/cld/std 等标志操作 | |
| `FE/FF` | inc/dec/call/jmp/push(间接) | 转 `_group_ff` |
| `C0/C1/D0-D3` | 移位/循环移位 | 转 `_shift` |
| `0F` | 两字节 opcode | 再取一字节转 `_execute_0f`(见 3.4) |
| 其它 | | `_bad(op)` 抛 `CpuError` |

对 **8 组同构指令**(F6/F7、FE/FF、C0/D0 移位)用 ModRM 的 **reg 字段当 opcode
扩展**,分派到 `_group_f7 / _group_ff / _shift`(见第 5 节)。

### 3.4 两字节 opcode `_execute_0f`(cpu86.py:1357)

`0F` 之后再取一字节,进入 386 扩展指令:
- `80-8F` jcc rel32(近条件跳转)
- `90-9F` setcc r/m8(条件置字节)
- `AF` imul r, r/m
- `A3/AB/B3/BB/BA` 位测试族 bt/bts/btr/btc(寄存器形式与 `BA` 的立即数形式)
- `BC/BD` bsf/bsr(位扫描)
- `A4/A5/AC/AD` shld/shrd(双精度移位)
- `B6/B7/BE/BF` movzx/movsx(零/符号扩展搬运)
- 其它 → `_bad(0x0F00|op)`

### 3.5 陷入内核:`int`、故障(cpu86.py:894, 542)

- **`int N`**(`CC`=int3 / `CD imm8`):取中断号,若 `on_int` 为空则 `halted=True`,
  否则调 `self.on_int(self, vec)`(cpu86.py:894-901)。内核在回调里读
  `eax/ebx/ecx/edx` 当作系统调用号与参数,处理完把返回值写回 `eax`。**注意
  Linux 0.11 的系统调用就是 `int 0x80`**,所以 `int` 是用户态与内核态的唯一门。
- **`SegFault` / `DivideError`**:在 `run()` 的 `try` 里被接住,调 `on_fault`
  (cpu86.py:547-555),内核转成 SIGSEGV/SIGFPE。若没有注入回调(纯 CPU 单测),
  就把异常继续抛出。

### 3.6 魔数返回 `MagicJump`(cpu86.py:585-587, 62)

0.11 **没有 sigreturn 系统调用**,信号返回靠 libc 的 `sa_restorer` 在用户态弹栈。
当 `restorer` 为 0 时,内核压帧时用一个 `MAGIC_EIP_BASE`(0xFFFF0000)之上的假
地址当返回地址;执行流一旦跳到那里,`step()` 抛 `MagicJump`,穿到调度器由
`_sigreturn` 弹出信号帧。这是"没有 sigreturn 也能返回"的兜底机制。

### 3.7 指令长度:可变字节数如何隐式确定

x86 是**可变长度指令集**,一条指令占 **1 到 15 字节**不等。完整编码模板是:

```
[前缀 0..4 字节] [opcode 1..2 字节] [ModRM 0/1] [SIB 0/1] [disp 0/1/4] [imm 0/1/2/4]
   66 F2 F3 …      一字节 或 0F xx    见第 4 节    见第 4 节   随 mod/rm   随指令
```

各部分的字节数怎么定:

| 组成 | 字节数 | 由什么决定 |
|---|---|---|
| 前缀 | 每个 1 字节,可 0 个或多个 | `step()` 前缀循环里每认出一个前缀就多吃 1 字节(0x66/0xF2/0xF3/段/lock) |
| opcode | 单字节;`0F` 打头则 2 字节 | 第一个非前缀字节;若是 `0F` 再取一字节 |
| ModRM | 0 或 1 | 该 opcode 是否带 ModRM(如 `88-8B` 带,`40-4F`、`B8-BF` 不带) |
| SIB | 0 或 1 | 仅当 ModRM 的 `rm==4` 且 mod≠3(cpu86.py:335) |
| 位移 disp | 0 / 1 / 4 | mod==1→1,mod==2→4,`rm==5&&mod==0` 或 SIB 的 `base==5&&mod==0`→4(cpu86.py:343-355) |
| 立即数 imm | 0 / 1 / 2 / 4 | 由 opcode 与 `opsize` 定:`6A`/`80`/`B0-B7` 是 1 字节,`68`/`81`/`B8-BF` 是 4 字节(0x66 前缀下为 2 字节) |

**关键实现取舍:这个解释器从不显式计算指令长度,也没有"每个 opcode 多少字节"
的长度表。** 长度是**取指过程的副产品**——`_fetch8/16/32` 每读一段就把 `eip`
往前推(cpu86.py:271-284),等一条指令的所有部件都取完,`eip` 自然正好落在**下一条
指令的首字节**上。也就是说:

```
本条指令长度 = 执行后的 eip − _insn_start
```

`step()` 一开头记下 `self._insn_start = self.eip`(cpu86.py:590),之后无论走到哪个
分支、吃掉多少 ModRM/SIB/disp/imm,eip 都被 `_fetch*` 精确推进。控制流指令(jmp/
call/ret/jcc)则**直接改写 eip**,于是"下一条"落到跳转目标而非顺序的下一字节。

这个"长度隐式"的设计只有两处需要**显式回看长度**:
- **报错**:`_bad()`(cpu86.py:613)用 `eip − _insn_start` 算出本条已吃的字节数,
  连同机器码原文塞进 `CpuError`,便于定位是哪条指令没实现。
- **阻塞回卷**:系统调用 `int 0x80` 固定 2 字节(`CD 80`),阻塞时调度器把
  `eip -= 2` 回卷以便唤醒后重做——这里是唯一"硬编码某条指令长度"的地方,因为
  它必须在 `step()` 之外(调度器里)倒推,拿不到 `_insn_start`。

长度跨度的直观例子(见第 11 节的完整走查):

| 指令 | 机器码 | 字节数 | 构成 |
|---|---|---|---|
| `nop` | `90` | 1 | 纯 opcode |
| `inc eax` | `40` | 1 | 纯 opcode(寄存器编在 opcode 里) |
| `jne +5` | `75 05` | 2 | opcode + rel8 |
| `mov eax, imm32` | `B8 xx xx xx xx` | 5 | opcode + imm32 |
| `add [ebx+4], eax` | `01 43 04` | 3 | opcode + ModRM + disp8 |
| `mov [ebx+esi*4+0x10], eax` | `89 44 B3 10` | 4 | opcode + ModRM + SIB + disp8 |
| `add dword [0x9000], imm32` | `81 05 00 90 00 00 xx xx xx xx` | 10 | opcode + ModRM + disp32 + imm32 |

理论上限 15 字节(多前缀 + 最长位移 + 最长立即数);真实用户程序极少接近。

---

## 4. 寻址:ModRM 与 SIB(cpu86.py:322)

绝大多数指令的"第二操作数"由 opcode 后的 **ModRM 字节**指定。ModRM 拆成三段:

```
 7 6 | 5 4 3 | 2 1 0
 mod |  reg  |  rm
```

- **reg**(3 位):一个寄存器操作数,或作 opcode 扩展(见 3.3 的组指令);
- **rm + mod**:另一个操作数,可能是寄存器,也可能是内存(R/M = Register/Memory);
- **mod** 决定 rm 怎么解释:

| mod | rm 的含义 |
|---|---|
| `3` | rm 是寄存器(`addr=None`) |
| `0` | `[寄存器]`,无偏移(特例:rm=5 → disp32 绝对;rm=4 → 走 SIB) |
| `1` | `[寄存器 + disp8]` |
| `2` | `[寄存器 + disp32]` |

两个"逃逸"编码:
- **rm==4**:后跟 **SIB 字节**(scale-index-base),算 `base + index*scale`,做数组
  寻址(cpu86.py:335-346);`index==4` 表示无索引,`base==5 且 mod==0` 表示 disp32。
- **rm==5 且 mod==0**:disp32 绝对寻址(cpu86.py:347-348)。

`_modrm()` 返回 `(mod, reg, rm, addr)`,mod==3 时 addr 为 None,否则是算好的有效
地址。随后统一交给 **操作数读写层**:

- `_read_rm/_write_rm`(cpu86.py:360-388):mod==3 走寄存器(按 size 用 8/16/32 视图),
  否则走 `mem.read_*/write_*(addr)`。**这正是 R/M 在"寄存器"与"内存"两种身份间
  切换的地方。**
- `_read_reg/_write_reg`(cpu86.py:390-403):reg 字段那个纯寄存器操作数。

`opsize`(默认 4,遇 0x66 变 2)贯穿始终,决定按 32 位还是 16 位读写与置标志。
字节指令(如 `88`、`F6`)则把 size 固定成 1。

---

## 5. 同构指令组:用 reg 字段当子操作码

三处把 ModRM 的 **reg 字段**当第二级 opcode:

### 5.1 `_group_f7`(cpu86.py:1018)—— F6/F7
`reg` = 0/1 test、2 not、3 neg、4 mul、5 imul、6 div、7 idiv。乘法结果落 EDX:EAX
(`_mul_unsigned/_mul_signed`,cpu86.py:1052-1105),除法从 EDX:EAX 取被除数
(`_div_unsigned/_div_signed`,1107-1160)。除零或商溢出抛 `DivideError`。
x86 除法**向零取整**,与 Python 的向下取整不同,故用 `_trunc_divmod`(1161)手动
调整余数符号。

### 5.2 `_group_ff`(cpu86.py:1171)—— FE/FF
`reg` = 0 inc、1 dec、2 call r/m(间接调用,压返回地址后跳)、4 jmp r/m(间接跳)、
6 push r/m。间接 call/jmp 是编译器实现函数指针、switch 跳表的基础。

### 5.3 `_shift`(cpu86.py:1196)—— C0/C1/D0-D3
`reg` = 0 rol、1 ror、4/6 shl/sal、5 shr、7 sar。移位计数按 x86 语义 `& 31`;
计数为 0 时**标志不变**(cpu86.py:1199)。CF/OF 的取法各不相同,逐类精确实现;
rcl/rcr(带进位循环)未实现,遇到抛 `_bad`。

---

## 6. 标志位模型(cpu86.py:405-473)

采取**朴素即时计算**:每条影响标志的指令算完结果后,立刻按位重建 EFLAGS。
辅助函数:

- `_set_logic_flags`(and/or/xor/test):CF=OF=0,按结果置 ZF/SF/PF,AF 未定义置 0。
- `_set_add_flags` / `_set_sub_flags`:加/减的完整 CF、ZF、SF、**OF(符号溢出)**、
  **AF(半进位)**、PF。OF 用经典的"符号位一致性"判据
  (`~(a^b) & (a^res) & sign` 之类)。
- `_set_inc_flags`:inc/dec 走 add/sub 规则,但**保留 CF 不变**(x86 规定)。
- **PF 查表** `_PARITY`(cpu86.py:40):低 8 位 1 的个数为偶则置位,预生成 256 项表。

`_alu(op, a, b, size)`(cpu86.py:500)是 ALU 总入口:`op` 0-7 对应
add/or/adc/sbb/and/sub/xor/cmp,adc/sbb 读入当前 CF,cmp 只置标志返回 None(不写回)。
所有 00-3F、80/81/83、A8/A9 的算术都汇到这里。

条件码 `_cond(code)`(cpu86.py:477):把 jcc/setcc/loopcc 的低 4 位翻译成对 EFLAGS
的布尔判断(o/no/b/ae/e/ne/be/a/s/ns/p/np/l/ge/le/g),有符号比较用 `SF!=OF` 判据。

---

## 7. 串指令与 rep(cpu86.py:1255)

`movs/stos/lods/scas/cmps`(A4-AF),可带 `rep/repe/repne` 前缀。`_string_op` 是
一层薄包装(顺带做性能剖析的元素计数),真正执行在 `_string_op_impl`(cpu86.py:1268):

- **方向由 DF 决定**:DF=1 时地址递减(memmove 反向拷贝要用),`delta = ±size`。
- **rep 计数在 ECX**:一条 `rep movs` 在一次 `step()` 里把 ECX 个元素全搬完
  ——**它只算一条指令,却做了 N 个元素的活**,这是性能上很值得注意的一点。
- **整块快路径**:正向、无重叠的 `rep movs/stos` 直接一次 `mem.write(...)` 整块搬
  (cpu86.py 里 movs/stos 的 fast path),比逐元素循环快得多。
- **repe/repne 提前结束**:cmps/scas 按 ZF 与前缀类型(F3/F2)决定是否中途停。

---

## 8. 栈、调用约定相关

- `push32/pop32`(cpu86.py:288-297):ESP 先减 4 再写(压),或先读再加 4(弹)。
  16 位版本同理减/加 2。
- `call`(E8 / FF/2):压 `eip`(即返回地址)后改 eip;`ret`(C3 / C2 imm16):
  弹回 eip,C2 再把 ESP 加 imm16(清理调用者压的参数)。
- `enter/leave`(C8/C9):建立/拆除栈帧;`leave` = `mov esp,ebp; pop ebp`。
- `pushf/popf`(9C/9D):EFLAGS 进出栈;`popf` 经 `eflags` setter 过滤保留位。

---

## 9. 快照:fork 与信号帧(cpu86.py:312)

`snapshot()` / `restore()` 只拷 `regs / eip / flags` 三样。用途:
- **fork**:子进程新建 CPU 后 `restore(parent.snapshot())`,再把子进程 `eax` 置 0
  (fork 返回值)。地址空间是另行整块拷贝的(写时不共享)。
- **信号帧**:内核建立/返回信号处理时保存/恢复上下文。

---

## 10. 异常一览:CPU 层怎么把控制权交出去

CPU 用 Python 异常表达"这条指令没法在用户态就地走完":

| 异常 | 抛出点 | 谁接 | 语义 |
|---|---|---|---|
| `SegFault`(x86mem) | 任何越界访存 | `run()` → `on_fault` | → SIGSEGV |
| `DivideError` | div/idiv 除零或溢出 | `run()` → `on_fault` | → SIGFPE |
| `CpuError` | `_bad`:未实现/非法 opcode | 一路抛到仿真器顶层 | 带 eip 与机器码字节,便于定位 |
| `MagicJump` | `step()`:eip 跳到魔数区 | 调度器 `_sigreturn` | 无 sigreturn 时的信号返回兜底 |
| `on_int` 回调内可能抛 | `int` 处理里 execve 会抛 `Replaced` 等 | 调度器 | 见内核层文档 |

x87 浮点**未实现**(镜像 libc 是软浮点):遇到浮点 opcode 抛带 eip 与机器码字节的
`CpuError`——这是刻意策略,不静默跳过。

---

## 11. 一条指令的完整走查(例)

以 `add [ebx+4], eax` 为例,机器码 `01 43 04`:

1. `step()`:无前缀,`opsize=4`,`op = _fetch8() = 0x01`。
2. `_execute(0x01, 4)`:落入 `00-3F` ALU 段(cpu86.py:622)。
   `alu_op = 0x01>>3 = 0`(add),`form = 0x01&7 = 1`(r/m, r 方向)。
3. `_modrm()` 读 `0x43 = 01 000 011`:mod=1、reg=0(EAX)、rm=3(EBX)。
   mod==1 → 再取 disp8 `0x04`,`addr = EBX + 4`。
4. `a = _read_rm(mod=1, rm=3, addr, 4)` → 读内存 `[EBX+4]` 的 32 位值。
5. `res = _alu(0, a, _read_reg(0,4), 4)` → `a + EAX`,`_set_add_flags` 置 CF/ZF/…。
6. `res` 非 None → `_write_rm(1,3,addr,4,res)` 写回内存。
7. 回到 `run()`:`icount += 1`,继续下一条(eip 此刻正指向 `01 43 04` 之后)。

再看一条控制流 `jne +5`,机器码 `75 05`:
1. `op=0x75` 落入 `70-7F`(cpu86.py:721),取 rel8=`0x05`。
2. `_cond(0x75 & 0xF = 0x5)` = "ne/nz" = `not ZF`。ZF=0 则 `eip += 5`(跳),否则顺序执行。

---

## 12. 设计取舍备忘

- **朴素即时标志 vs 惰性标志**:当前正确性优先,每条算完就重建 EFLAGS。若要提速,
  可改为"记住上次算术的操作数,读标志时才算"的惰性方案(代码里 EFLAGS 注释已留伏笔)。
- **线性 if 链 vs 跳转表**:线性链好读、易对照 Intel 手册分段,但每条指令平均要过
  若干个 `if`。因为纯 Python 逐指令开销本就大,这不是主要瓶颈;真要提速应先上
  **解码缓存**(把 eip→已解码指令记下来),而不是把 if 链换成表。
- **不做地址尺寸 16 位寻址**:`_modrm(addr_size_16=...)` 预留了参数但 32 位足够跑
  这个镜像的用户程序。
- **能不实现就不实现,但不静默**:x87、rcl/rcr、部分 0F 都以 `_bad`/`CpuError`
  显式报错(带 eip 与字节),而不是当 nop 跳过——出问题能立刻定位。

---

## 附:关键函数索引

| 环节 | 函数 | 位置 |
|---|---|---|
| 主循环 | `run` / `_run_profiled` | cpu86.py:542 / 564 |
| 一条指令 | `step` | cpu86.py:585 |
| 取指 | `_fetch8/16/32` | cpu86.py:271 |
| 分派 | `_execute` | cpu86.py:618 |
| 两字节 | `_execute_0f` | cpu86.py:1357 |
| ModRM/SIB | `_modrm` | cpu86.py:322 |
| 操作数读写 | `_read_rm/_write_rm/_read_reg/_write_reg` | cpu86.py:360 |
| ALU | `_alu` | cpu86.py:500 |
| 标志 | `_set_logic/add/sub/inc_flags` | cpu86.py:415 |
| 条件码 | `_cond` | cpu86.py:477 |
| F6/F7 组 | `_group_f7`(+ mul/div 系列) | cpu86.py:1018 |
| FE/FF 组 | `_group_ff` | cpu86.py:1171 |
| 移位组 | `_shift` | cpu86.py:1196 |
| 串指令 | `_string_op` / `_string_op_impl` | cpu86.py:1255 / 1268 |
| 栈 | `push32/pop32/...` | cpu86.py:288 |
| 快照 | `snapshot/restore` | cpu86.py:312 |
| 内存 | `AddressSpace`(read/write/扩栈) | x86mem.py:42 |
