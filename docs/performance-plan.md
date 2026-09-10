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
阶段独立可交付、可回归验证。**阶段一已落地**(提交于 2026-09-10, gzip 15.87s → 6.50s, 2.44x); 阶段二至四为设计与预估。

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
| S0 | 阶段一落地(**已完成**) | 全测 + md5 | **6.5s(实测)** |
| S1 | `_modrm_dec` + `e` 元组 + `_DEC/_DEC0F` 注册表 + 闭包 handler + 胖 handler; `_OP_CATEGORY` 改由注册生成 | 反汇编长度对照; TestProfiler 类别数; 新增 `_dec_bad ⇒ CAT_OTHER` 断言 | ~5.0s |
| S2 | 模板 exec 生成 ModRM 族三寻址×三尺寸变体, 标志内联, 16 个 jcc handler | 差分对照 200 万条; 标志测试 | ~4.0s |
| S3 | `icache`(x86mem 槽/初始化/clone/写失效) + 命中路径 | `run(1)`/断点/fork 子进程/`CpuError` 报错字节; 新增"写 text 后再执行拿到新指令"测试 | ~2.7s |
| S4 | for-range + finally icount + halted 后置 | icount/预算测试、内核记账、kmonitor 阈值 | ~2.5s |
| S5(可选) | 惰性标志 | 差分对照逐位; DF/移位零计数/信号帧测试 | ~2.2s |

必做部分累计 **15.87s → ~2.5s(≈6x, ≈2.6 MIPS)**, awk 692s → 约 2 分钟。其中阶段一的 2.46x 是实测,
其余为按微基准推算的预估, 每步落地后以实测为准并据此决定是否继续。

## 六、不做的事

- 多进程/多线程并行: 内核状态共享且受 GIL 限制, 不可行。
- 除 `rep movs/stos` 外的指令"向量化": 没有 numpy, 无收益。
- `minixfs.py`/`pager.py`/内核调度循环: 不在热路径。
- 改用 JIT/代码生成到 C: 违反"纯标准库"约束。
