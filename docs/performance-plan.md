# 仿真器性能提升方案(纯标准库)

## Context

仿真器(`emulator.py → kernel.py → cpu86.py/x86mem.py`)是纯 Python 标准库写的 i386 用户态
解释器。实测基线约 **0.36–0.41 MIPS**: `gzip -c /bin/date`(650 万条指令)15.9s;
`awk 'BEGIN{for(i=0;i<100000;i++)s+=i}'`(2.5 亿条指令)**692s**。交互 shell 里跑稍重一点的
命令要等十几分钟, 是当前最大的可用性问题。

约束: 不引入外部库(不假设 Cython/numpy/PyPy), 只优化标准库实现; `minixfs.py`/`pager.py`
不动; 现有测试全过; cpu86 层不 import 内核层; `cpu_disasm.py` 镜像解码结构, 其长度对照单测
必须继续成立; 单步调试(`run(1)`)、Profiler、MagicJump、fork 快照语义不变。

本报告基于实测(cProfile + 运行时 monkeypatch 原型)而非猜测。分四个阶段, 每
阶段独立可交付、可回归验证。**四个阶段均已落地**(2026-09-10): gzip 15.87s → 2.29s
(**6.9x**, 约 2.9 MIPS), ls -l 2.0s → 0.47s, awk 十万次循环 692s → 88s(7.8x);
gzip/ls 输出 md5 不变, 与旧实现在 gzip/ls/awk 三种负载上逐条指令的 regs/eip/flags 哈希
完全一致(共约 970 万条)。以下"预估"数字保留作为对照, 实测见第七节。

---

## 一、实测热点(gzip 负载, Python 3.12, cProfile)

| 热点 | 占比 | 原因 |
|---|---|---|
| `CPU.__setattr__`(cpu86.py:255) | **19%**(3400 万次) | 自定义钩子, 每次 `self.eip=`/`self.flags=`/`self._insn_start=` 都做 `name in REG32_NAMES` |
| `_execute` if 链自身 | 15% → 阶段一后 **30%** | 走到 `mov`(8B) 要过 ~20 个判断 ≈200ns; 256 项表查找+调用 22ns |
| `_fetch8/16/32` | 1460 万次调用 | 每字节一次方法调用(~60ns 固定开销) |
| `read_u32` = `bytes(slice)`+`struct.unpack` | 127ns/次 | 两次拷贝; `unpack_from` 直读 bytearray 33ns |
| `_mask_of/_sign_of` 静态方法 | 770 万次 | 应为元组查表 |
| `_modrm` | 370 万次 | 内部再调 `_fetch*` |

**不是瓶颈**: 内核层每时间片(10 万条指令)一次 `select` + 三次进程表扫描 + 两次
`perf_counter`, 可忽略; `rep movs/stos` 已有整块快路径。`--profile` 逐指令插桩使速度从 0.41
降到 0.36 M/s, 与"默认关"的设计一致。

## 二、原型验证(monkeypatch; gzip 输出 md5 一致, 423 个测试全过)

| 步骤 | 耗时 | 累计提速 |
|---|---|---|
| 基线 | 15.87s | 1.00x |
| E1 去 `__setattr__/__getattr__` 钩子, 改 8 个 property | 9.15s | **1.74x** |
| E2 + `read/write_u16/u32` 用 `unpack_from/pack_into` 免拷贝 | 8.07s | 1.97x |
| E3 + 内联取指/ModRM、`_MASK/_SIGN` 元组、`_alu` 按频率重排、`_read_rm` 先判 size==4 | 6.44s | **2.46x** |

---

## 三、方案

### 阶段一: 微优化(已验证 2.46x; 半天; 零结构风险)

改动只在 `cpu86.py` 与 `x86mem.py`, 语义不变。

1. 删 `CPU.__getattr__/__setattr__`(cpu86.py:249-259), 改 8 个 `property`(setter `& MASK32`)。
   全仓库仅 `test_cpu86.py` 3 处按名字访问, 内核层一律 `cpu.regs[i]`, property 即兼容。
2. `x86mem.py`: `read_u16/u32` 用 `_U16/_U32.unpack_from(self.low, addr)`, `write_u16/u32` 用
   `pack_into`; 保留低区/栈区两次范围比较, 越界仍 `SegFault`, 写越界仍走 `self.write()` 扩栈。
   `read()/write()` 整块接口保留给串指令与内核。
3. `step()`: 首字节直接 `mem.low[eip]`(text 必在低区), 非前缀字节直接 `_execute(op, 4)`;
   前缀用 `frozenset` 判断, 命中才进循环(保留 `f3 90` pause 特例)。
4. `_modrm()` 内联取指: 局部 `eip/mem/regs`, 末尾写回一次 `self.eip`; 符号扩展内联。
5. `_mask_of/_sign_of` → 模块级元组 `_MASK=(0,0xFF,0xFFFF,0,0xFFFFFFFF)`、`_SIGN`;
   `_set_*_flags` 用之; `_alu` 按频率排(add/sub/cmp/and/or/xor/adc/sbb)。
6. `_read_rm/_write_rm/_read_reg/_write_reg` 先判 `size == 4`。

### 阶段二: 解码/执行分离 + 查表分派(预估 6.4s → ~4.0s)

**核心决定**: 解码器返回不可变元组 `e`, 执行器是模块级平铺函数 `h(cpu, e)`。这样阶段三只需
加一行 `cache[eip] = e`, 不必二次重写。

```python
# e 的固定布局(9 元组):
#  e[0] fn  e[1] length(含前缀)  e[2] size  e[3] reg/条件码/子操作码
#  e[4] base(mod==3 时为 rm)  e[5] index  e[6] scale  e[7] disp(已符号扩展)  e[8] imm/绝对跳转目标/rep 字节
def step(self):
    eip = self.eip
    if eip >= MAGIC_EIP_BASE: raise MagicJump(eip)
    self._insn_start = eip
    e = self._decode(eip)      # 内部把 self.eip 推到指令末尾(执行 handler 之前!)
    e[0](self, e)
```

- **分派表** `_DEC[256]`/`_DEC0F[256]`, 用注册装饰器 `@_op(*ops, cat=CAT_xxx)` **同时**填解码表与
  Profiler 的 `_OP_CATEGORY`, 取代现在"边界照抄 `_execute`"的隐式约定(注意 A8/A9 归 CAT_ALU
  的覆盖优先级)。未注册项填 `_dec_bad`(抛 `CpuError`, 字节从 `_insn_start` 读)。
- **opsize 在解码期消化**: 32 位选专用 handler; `0x66` 路径选带 `size` 字段的通用变体(占比 <3%),
  解码函数天然复用。8 位形式固定 size=1。
- **ModRM** 统一 `_modrm_dec(cpu) → (mod, reg, base, index, scale, disp)`, 按三种寻址形态选变体:
  寄存器 / `[base+disp]`(gcc 输出中 ~85% 的内存操作数, 内联 `(regs[e[4]]+e[7])&M`)/ 通用 SIB。
- **handler 生成方式**: 形状单一的 ~40 条(push/pop/jcc/mov imm/ret/call/jmp/leave/inc-dec reg/int/
  hlt/clc…)手写闭包; **ModRM 族**(00-3F ALU、80/81/83、84/85、88-8B、C6/C7、F6/F7、FE/FF、
  移位、movzx/movsx、setcc、0F AF)用**模板字符串 + `exec`** 生成 3 寻址 × 3 尺寸 × N 子操作变体,
  `mask/sign` 变字面量, 标志计算函数体内联(省调用 + `_mask_of/_sign_of` ≈120ns/条)。用
  `linecache` 注册生成源码让 traceback 可读; 环境变量 `CPU86_DUMP_GEN=1` 转储全部生成代码供 review。
  不用 `functools.partial`(C 层多一次 tuple 拼参, 反而慢)。
- **高频专用快路径**(解码期选定, 执行期零分支): `89/8B` mod=3 → `regs[e[4]] = regs[e[3]]`;
  `89/8B [base+disp]`; `50+r/58+r` 内联 push/pop; `B8+r`; `83 /op imm8` mod=3(`add esp,8`/
  `cmp eax,0`); jcc 按 16 个条件码各生成一个 handler, 条件表达式内联, `e[8]` 存**绝对目标**;
  `E8/E9/EB/C3/C9`; `40-4F`; `85` mod=3(`test eax,eax`); `CD 80` → `cpu.on_int(cpu, e[8])`。
- **罕见指令**(enter/xlat/loop/bt 族/shld/bsf/mul/div/pushf/popf…)走"胖 handler": 解码函数把
  mod/reg/rm 塞进 e, handler 复用现有 `_group_f7/_shift/_execute_0f` 逻辑(只改签名), 已测代码保留,
  重写面控制在约 35% 行数。串指令 → 现有 `_string_op(op, size, rep)`。
- `cpu_disasm.py` 代码不改, docstring "镜像 `_execute`" 改为 "镜像 `_DEC` 表与 `_modrm_dec`";
  `docs/x86-decode-and-emulation.md` §12 与附表同步。

### 阶段三: 解码缓存(预估 ~4.0s → ~2.7s)

- **缓存项就是 `e`**(不含运行期值; 有效地址执行期算)。**不缓存闭包**——`restore()` 会替换
  `self.regs` 对象, 闭包若绑定 `regs` 即出错。
- **容器用 `list` 而非 dict**: `icache = [None] * text_end`, 按 eip 下标索引(~20ns 免哈希),
  `eip < text_end` 同时就是"在 text 内"的判断。text 30–400KB → 每进程 0.25–3MB, 可接受;
  `text_end > 4MB` 时退化为不缓存。
- **挂在 `AddressSpace`**(加 `__slots__` 项 `icache`; `__init__`/`load_program` 初始化;
  **`clone()` 里必须赋 `new.icache = [None] * text_end`**, 不共享——fork 后子进程多半立刻 execve,
  否则重解码一遍只花数十 ms, 不值得引入跨进程失效问题)。
- **失效**: `write/write_u8/u16/u32` 加 `if addr < self.text_end: 就地清 icache[addr-15:addr+n]`
  (就地赋值保持对象身份, `run()` 里的局部引用不失效)。正常程序永不触发, 代价一次比较。
- **不缓存**: `start >= text_end`(栈/堆上的代码, 含 `text_end==0` 的测试 FakeCPU); 跨 `text_end` 的
  指令; 解码期即抛 `CpuError` 的指令(异常在写入前抛出)。
- **命中路径**(`step()`/`run()`/`_run_profiled()` 共用一段, 保证 `run(1)`、断点、反汇编长度对照、
  `_insn_start`/`_bad` 报错字节全部一致):

```python
if eip < text_end and (e := cache[eip]) is not None:
    self.eip = eip + e[1]          # 先推 eip 再执行: 反汇编长度对照 & Blocked 的 eip -= 2 都依赖它
else:
    e = self._decode(eip)
    if self.eip <= text_end: cache[eip] = e
e[0](self, e)
```

- 收益依据: 阶段一后每条 ≈990ns, 其中解码/分派(2.5 次取指 + `_modrm` + if 链)≈650ns; 命中后
  换成 `cache[eip]` + 加法 + 一次 handler 调用 ≈110ns。gzip/awk 紧循环命中率 >99.9%。

### 阶段四: 主循环收尾(预估 ~2.7s → ~2.5s)

- `while n < max_steps and not self.halted` → `for _ in range(max_steps)`, `halted` 检查后置
  `if self.halted: break`。
- `icount` 改为 `finally: self.icount += done` 一次性加。语义与现在一致: Blocked/Exited/Replaced/
  MagicJump 穿出时已完成的条数计入, 正在执行的那条不算(内核 `max(…,1)` 兜底不变);
  `Replaced` 时内核局部变量仍是旧 CPU, 差值取的正是它。`run(1)` 返回后 icount 已 +1。
- 内层 `try/except` 在 3.12 零成本, 保留; MagicJump 检查留循环头(测试直接置 eip=MAGIC)。

### 可选(仅在阶段三后 cProfile 显示标志计算仍 ≥10% 时做): 惰性标志

- 状态 `_fl/_lk/_la/_lb/_lr/_lm` 替代 `self.flags`; `flags`/`eflags` 变 property(getter 物化),
  `snapshot()` 物化、`restore()` 走 setter, **kernel.py 零改动**(内核只经 `cpu.eflags` 与快照碰
  标志)。DF 只住 `_fl`; inc/dec 记录前用 `_cf()` 取旧 CF; shift/rol/bt/bsf/sahf 先物化再改位。
- jcc 快路: K_SUB 记录下 `e/ne` 直接 `t==0`、`l/ge` 直接有符号比较, 不物化。
- 净收益预估 6–8%(阶段一基数)/ 12–15%(阶段三基数); 是全方案里最易引入细微标志错误的一步
  (AF/OF 边界、adc 进位反推), 故排最后、按需做。因为 `flags` 是 property, 漏改的读写点仍正确
  只是慢, 可增量转换。
- **不做 cmp+jcc 窥孔融合**: 会让 `run(1)` 一步跨两条、jcc 地址断点命中不到、icount/Profiler 少记。

---

## 四、耦合坑清单(实施前必读)

| 位置 | 坑 | 对策 |
|---|---|---|
| `test_cpu86.py` 多处 `cpu.flags` 直读、`snap["eip"]` | `flags` 须保持可读属性; snapshot 键名 `regs/eip/flags` 不能改 | property + 物化 |
| `test_cpu_disasm.py` `_exec_len` 用 `step()` 后 `eip - start` 当长度, 即使执行抛异常 | 新 step 必须**先推 eip 再执行 handler** | 见阶段二/三命中路径 |
| `kernel.py:1229` `cpu.eip -= 2` | Blocked 回卷依赖 `int 0x80` 两字节且 eip 已越过 | 同上; `int` 不做前缀感知 |
| `kernel.py:1237` icount 差值记账 | Blocked/Exited/Replaced 异常穿出 | icount 一次性加放 `finally` |
| `kernel.py:1268` `cpu.run(1)`; `test_kernel.py:1431/1459` | 单步后 icount==1, 断点按 `cpu.eip` 判 | 单步走同一缓存路径 |
| `cpu86.py:315 restore()` 替换 `regs` list 对象 | handler/闭包不得在解码期绑定 `regs`/`mem` | 每次 `cpu.regs` |
| `x86mem.py __slots__` + `clone()` 用 `__new__` 手工赋槽 | 新增 `icache` 槽 clone 必须同步赋 | 见阶段三 |
| `test_kernel.py:66 FakeCPU` 只有 `regs/eip/eflags/icount/halted/mem` | 内核层只能依赖这几个名字 | 新字段仅 cpu86 内部用 |
| `_build_op_category` 与 `cpu_disasm.py` 两处"镜像 `_execute`" | 隐式结构约定 | 注册装饰器统一生成; disasm 改注释 |
| `test_cpu86.py:1537` `plain.flags == prof.flags` | 剖析/非剖析路径标志逐位一致 | 两条路径共用命中代码 |

## 五、实施顺序、验证与预期

每步固定三项验证: (a) `python3 -m unittest test_cpu86 test_kernel test_kmonitor test_cpu_disasm test_ktty test_kvfs test_minixfs`;
(b) `python3 emulator.py hdc-0.11.img /usr/bin/gzip -c /bin/date | md5sum` = `d4bc050cbdacd8db08423d8dc7a43313`(20131 字节), 记 wall time;
(c) awk 十万次循环基准(基线 692s)。

强烈建议在 S1 前写一个**差分对照脚本**(纯 stdlib, 放 `tools/` 或测试目录): 复制当前 `cpu86.py`
为参考实现, 两个 CPU 对同一 AddressSpace 快照锁步各跑一条, 逐条比对 `regs/eip/flags`, 跑 gzip
前 200 万条。它抓解码/标志回归的能力远超单测。

| 步 | 内容 | 验证重点 | gzip 预期 |
|---|---|---|---|
| S0 | 阶段一落地 | 全测 + md5 | **6.5s(实测)** |
| S1-S4 | 解码/执行分离 + `_DEC/_DEC0F` 表 + 模板生成(惰性) + `icache` + for-range/finally icount/`_Halt` | 全测; gzip/ls md5; 差分对照 970 万条 | **2.29s(实测)** |
| S5(可选) | 惰性标志 | 差分对照逐位; DF/移位零计数/信号帧测试 | 未做 |

## 七、实测结果(2026-09-10, Python 3.12)

| 负载 | 基线 | 阶段一 | 全部落地 | 提速 |
|---|---|---|---|---|
| gzip -c /bin/date(654 万条) | 15.87s | 6.50s | **2.29s** | 6.9x |
| ls -l /usr/bin | 2.00s | 0.87s | 0.47s | 4.3x |
| awk 一万次循环(2500 万条) | 26.3s(推算 69s 基线) | 26.3s | 9.2s | — |
| awk 十万次循环(2.5 亿条) | 692s | — | **88s** | 7.8x |

与设计的差异:
- 模板生成改为**按族惰性编译**(`_LazyForms.__missing__`): 一次生成全部 682 个变体要 150ms
  import 时间, 而一个程序只用到一两百个。热身后 `import cpu86` 约 3ms。
- 寻址形态分四种(寄存器 / `[disp32]` / `[base+disp]` / 通用 SIB), 通用 SIB 的有效地址内联
  为一个表达式, 不再调 `_ea()`。
- `_OP_CATEGORY` 表保持独立构造(与 `_DEC` 覆盖集一致), 没有引入注册装饰器: 两张表
  改动频率都极低, 装饰器带来的耦合不值。
- 热循环不再每条存 `_insn_start`; 报错 handler 用 `cpu.eip - e[1]` 还原起点。
- 全部落地后 cProfile: `run()` 循环自身约 35%, 其余分散在几十个生成 handler 与访存函数里,
  再没有单点热点; 每条指令约 350ns, 其中调度(取缓存、推 eip、调用 fn)约 100ns 是纯解释器
  固定成本。下一档提速只能靠惰性标志(预估 10-15%)或进一步减少访存函数调用, 收益递减。

验证方法(可复用): 差分对照脚本把旧实现另存为 `cpu86_ref.py/x86mem_ref.py`, 以模块名
`cpu86/x86mem` 注入 `sys.modules` 后跑同一负载, 把每条指令后的 `hash((eip, flags, *regs))`
存成 `array('q')`, 最后逐项比对首个分歧位置。注意要把 `time.time` 固定成常数, 否则
`time()` 系统调用的返回值会造成假分歧(ls 第 18 条就是它)。

## 六、不做的事

- 多进程/多线程并行: 内核状态共享且受 GIL 限制, 不可行。
- 除 `rep movs/stos` 外的指令"向量化": 没有 numpy, 无收益。
- `minixfs.py`/`pager.py`/内核调度循环: 不在热路径。
- 改用 JIT/代码生成到 C: 违反"纯标准库"约束。


---

## 八、第二轮评估: 还能再快多少(2026-09-10)

四个阶段落地后重新剖析与做原型实验, 目的是回答"继续投入是否值得"。基线为当前实现
gzip 约 1.95s(654 万条, 约 300ns/条; 数字随机器负载在 1.9–2.3s 间波动, 下面的对比都在
串行、无并发干扰下取两次最小值)。

### 8.1 每条指令的时间去哪了

| 组成 | 约 ns/条 | 说明 |
|---|---|---|
| 主循环骨架(range 迭代、读 eip、魔数比较、查缓存、推 eip、调用 fn、计数) | 150–170 | 纯解释器固定成本, 微基准空 handler 骨架 248ns 含全局量查找, 实际略低 |
| handler 本体(平均) | 130–150 | 见下行拆分 |
| ├ ALU 指令(37.7%)的标志计算 | ~180/条 ALU | `add r,r` 含标志 274ns, 不算标志 67ns, 只记录操作数(惰性) 92ns |
| ├ 访存调用 `mem.read_u32/write_u32`(约 35% 指令) | ~140/次 | 方法调用 60 + 两次范围比较 + unpack_from 40 |
| ├ jcc(分支 24.2%) | ~34 | 已是最简形式 |

指令类别分布(gzip, Profiler): ALU 37.7%, MOV 27.3%, 分支 24.2%, 栈 7.3%, 乘除 1.0%,
串 0.1%, 其它 2.3%。GC 影响可忽略(整个 gzip 只触发 10 次 gen0 回收, `gc.disable` 仅 1.02x)。
I/O 型负载(`ls -l /usr/bin`)里内核层/文件系统只占 2.5%(18ms/733ms), 仍是 CPU 解释主导。
启动开销 0.2s 几乎全是 Python 解释器启动与 import, 打开镜像 + 装载 + 运行 date 本身 < 10ms。

### 8.2 候选项实测/估算

| 候选 | 方法 | 结果 | 结论 |
|---|---|---|---|
| **基本块执行**(一次取出直到分支的整串 e, 内层紧循环只做 `eip=常量; fn()`) | monkeypatch 原型, gzip 实测 | **1.06x**; 块平均 5.1 条、中位数 4 条 | 分支占 24%, 块太短, 每块的字典查找与解包吃掉收益; 微基准里 8 条长块骨架 74ns 的美好数字在真实代码上不成立。**放弃** |
| 访存内联(模板里先查低区再 unpack_from) | monkeypatch 模板片段, gzip 实测 | 0.99x | gzip 的热访存在**栈区**, 低区快路径反而多一次比较。**放弃** |
| 平坦 64MB 地址空间 + 无检查访存 | 微基准 | `bytearray(64MB)` 立即 memset: 分配 102ms、常驻 64MB, fork 不可承受; 匿名 `mmap` 懒零页可行(分配 0.05ms、常驻 0、按已用范围克隆 4ms), 但 mmap 上 `unpack_from` 约 60–130ns, 不比现在的 bytearray 快 | 收益估 5–8%, 还会失去空洞区的 SegFault 保真(除非保留两次边界比较, 收益再减半)。**不值** |
| 主循环: 用 `for i in range()` 下标代替 `done += 1` | 原型实测 | 0.998x | 无收益 |
| 主循环: 魔数比较移出快路径(只在解码慢路径/转移指令里查) | 原型实测 | **1.05–1.07x** | 便宜, 但要保证所有能改 eip 的 handler(ret/jmp/call r/m/sigreturn 路径)都覆盖; 现有 `test_magic_jump` 直接置 eip 后 run, 需改为经解码慢路径触发。**可做, 小收益** |
| **惰性标志**(ALU 只记录操作数, 读标志时物化; cmp/test+jcc 直接比较) | 微基准 + 类别加权估算 | 每条 ALU 省 (274−92)=~180ns, 乘 37.7% 的 ALU 占比, 再乘"标志未被读"的比例(估 50–60%), 减去 jcc 物化成本 | 估 **8–12%**。是剩余候选里最大的一项, 但也是最容易引入细微错误的一项(AF/OF 边界、adc/sbb 进位反推、inc/dec 保 CF、移位/rol 部分位、pushf/lahf/信号帧物化); 需要差分对照逐位验证 |
| 减少 handler 内的属性访问(`cpu.regs`/`cpu.flags`/`cpu.mem` 各 ~15ns) | 分析 | 每 handler 2–3 次, 约 30–45ns/条 | 无法消除: `restore()` 会换 regs 对象, e 里不能绑定; 把 regs/flags 合并成一个 list(flags 放 regs[8])可省一次属性读, 估 3–5%, 但要改全部标志代码 |
| 更新 Python 版本 | 环境检查 | 本机只有 3.12.3, 无 3.13/3.14 | 3.13 默认无 JIT; 3.14 实验性 JIT 对这种"大量小函数 + 元组索引"的负载收益未验证。不在"只改代码"范围内 |
| 多进程/多线程并行 | 分析 | 内核状态共享 + GIL | 不可行 |

### 8.3 结论与建议

- 当前约 300ns/条里, 约一半是纯解释器调度成本, 已无法在不改变"逐条调用 Python 函数"这一
  模型的前提下再压; 而改变模型的两条路(基本块、平坦内存)实测/估算收益都在 5–8% 以内。
- **剩余可做且值得的只有两项**: ① 魔数检查移出快路径(+5–7%, 半天); ② 惰性标志
  (+8–12%, 两三天, 需差分对照)。两项叠加约 1.15x, gzip 从 1.95s 到约 1.7s, 约 3.3–3.5 MIPS。
- 再往上要靠 C 扩展/Cython/PyPy 这类非标准库手段(PyPy 对这类解释器通常 5–20x), 与本项目
  "纯标准库"约束冲突, 不在本报告范围内。
- 建议: 性能工作到此收尾。只有在出现"某个具体负载明显偏慢"的实际需求时, 再按 8.2 的表
  决定是否做惰性标志; 日常改动继续用 gzip md5 + 计时和差分对照守住现有水平。
