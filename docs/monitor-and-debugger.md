# monitor 与单步调试器:算法与代码流程

本文整理仿真器的 **monitor 控制台**(`kmonitor.py`)与**只读反汇编器**
(`cpu_disasm.py`)是怎样协作出一套 qemu 风格的运行时观察面板 + gdb 风格的
单步调试器的。monitor 本身只做输入解析、状态读取与排版,**不执行任何指令**;
真正的逐指令推进、断点判定住在调度器 `kernel.py`(`_run_debug_slice` 等),
反汇编则完全独立于执行器另写一遍解码。三者靠内核上的几个标志位(`monitor_pending`
/ `step_request` / `breakpoints` / `debug_stop`)乒乓联动。

> 阅读顺序建议:先看第 1 节 monitor 怎么被唤入与退出,再看第 2 节命令分派,
> 观察类命令(3-5 节)可跳读,单步调试(6 节)是重点,反汇编器(7 节)独立成篇。
> 所有引用都标了 `文件:行`。

---

## 1. monitor 架构:可注入 + 被标志位唤入

`Monitor`(kmonitor.py:127)持有内核引用 `self.k`,以及两个**可注入**的 I/O 钩子
`read_line` / `write`(kmonitor.py:130-137)。与 `pager.py` 同一套哲学:

- `out(text)`(kmonitor.py:141):有注入的 `_write` 就用它,否则 `print`。
- `read_line(prompt)`(kmonitor.py:147):有注入的 `_read_line` 就用它,否则
  `input()`;EOF/Ctrl-C 退化成 `"cont"`(便于脚本化输入喂完就自动离开)。

注入的意义:单测里 `Monitor(k, read_line=脚本, write=StringIO.write)` 就能把整段
交互跑完,不占宿主终端。

### 1.1 唤入:`monitor_pending` 乒乓

monitor 不是主动轮询键盘的,而是被调度器"唤入"的:

1. 交互时宿主终端处 raw 模式,用户按 **Ctrl-A c**,转义键处理落到
   `Kernel.on_escape`(kernel.py:1116),`b"c"` 分支只做一件事:
   `self.monitor_pending = True`(kernel.py:1125)。
2. 调度器主循环每轮开头检查这个标志(kernel.py:1172):置位则清零并调
   `self.monitor.interact()`,阻塞在 monitor 里直到用户离开。

`monitor_pending` 是单向的"请进来"信号——谁都能置位(转义键、`_debug_break`),
调度器统一在**下一轮循环顶部**响应。

### 1.2 REPL:`interact()`(kmonitor.py:157)

```
suspend 宿主终端 (raw → 常规, 好让 input() 能行编辑)
if debug_stop 非空:  打印停因 + 现场, 清空 debug_stop   (调试停下时进入, 抑制 banner)
else:                打印 "已进入 monitor" banner       (用户主动 Ctrl-A c 进入)
while True:
    line = read_line()
    if dispatch(line.strip()):  break     # dispatch 返回 True = 该离开
finally: resume 宿主终端 (常规 → raw)
```

要点:进入时若 `k.debug_stop` 有值(说明是断点/单步停下来的,不是用户敲 Ctrl-A c),
走 `_print_debug_stop` 展示停因与反汇编现场,并**不打**"已进入 monitor"的欢迎语
(kmonitor.py:163-168)。`suspend`/`resume` 让 monitor 期间宿主终端回到常规行模式,
离开时再切回 raw(kmonitor.py:159-180)。

---

## 2. 命令分派与 info 子分派

### 2.1 `dispatch(line)`(kmonitor.py:182)→ bool

一条命令的执行入口,**返回 True 表示该离开 monitor**(cont/quit/si/until 会返回 True)。
分派前有两个 gdb 味道的细节:

- **空行重复上一条**(kmonitor.py:187-190):`line` 为空则取 `self._last_cmd`;
  连按回车即可反复 `si` 单步。
- **离开类命令不记为"上一条"**(kmonitor.py:194):`cont`/`quit` 不写入
  `_last_cmd`,免得回车重进 monitor 后又误触发离开。

其后是一串 `if cmd in (...)` 线性分派(kmonitor.py:196-241):`info`、`ps`、`regs`、
`kill`、`trace`、`prof`,以及单步调试族 `si/disas/x/break/until/layout`,末尾
未知命令回一句提示。`x` 特判 `cmd.startswith("x/")`,把 `x/8xw` 这种粘连写法拆开
(kmonitor.py:229-230)。

### 2.2 `cmd_info(args)`(kmonitor.py:245)——handlers dict

info 的二级分派用一张 `handlers` 字典(kmonitor.py:252-270),各视图一句话概括:

| 子命令 | 视图 | 一句话 |
|---|---|---|
| `procs` / `ps` | `info_procs` | 进程表:pid/父/组/状态/已执行指令/等待对象/程序名 |
| `mem` | `info_mem` | 各进程 代码+数据+堆 / brk / 栈 / 合计 用量 |
| `fs` | `info_fs` | 覆盖层(CoW 改动明细)+ 底层镜像 inode/zone 使用率 |
| `syscalls` | `info_syscalls` | 系统调用次数排行 + 最近 10 条轨迹 |
| `trace [n]` | `show_trace` | 翻看轨迹环形缓冲最近 n 条 |
| `cpu [pid]` / `regs` | `info_cpu` | 寄存器、EFLAGS、eip 处字节、剖析开关 |
| `fds [pid]` | `info_fds` | 文件描述符表(inode/管道/终端、pos/flags/refs/cloexec) |
| `tty` | `info_tty` | 终端尺寸、行规程标志、前台进程组、c_cc |
| `profile [pid]` | `info_profile` | 按进程性能概览 / 单进程明细 |
| `console` | `info_console` | 最近的控制台输出(`console_tail`) |

未知子命令回一句 `未知的 info 项`(kmonitor.py:272-274)。

---

## 3. 排版:按显示列数对齐(中文双宽)

monitor 的每张表都过 `table()`(kmonitor.py:109),它**不能**用 Python 的
`f"{s:<5}"`——那是按**字符数**补齐的,而中文/东亚宽字符一个字要占**两个显示列**,
表头"状态"(2 字符 / 4 列)会少补 2 列,整张表跟着错位。故有一组按显示列数
算的原语:

| 函数 | 位置 | 作用 |
|---|---|---|
| `dwidth(s)` | kmonitor.py:90 | 字符串的**显示列数**:宽字符(`east_asian_width in "WF"`)记 2,其余记 1 |
| `ljust/rjust(s,n)` | kmonitor.py:99/104 | 按 `dwidth` 而非 `len` 补空格 |
| `table(headers,rows,aligns)` | kmonitor.py:109 | 各列宽 = 表头与各行 `dwidth` 的最大值;逐行按 `aligns`(`l`/`r`)对齐,`rstrip` 收尾 |
| `fmt_bytes(n)` | kmonitor.py:81 | 字节数转 `B`/`KB`/`MB` 人类可读 |

调用方只管给 `(headers, rows, aligns)`,拿回一串已对齐好的行逐条 `out`。这条规矩
一破,含中文的表(几乎全部)就散架——是这个子系统最容易再踩的坑。

---

## 4. 系统调用轨迹

轨迹是**常开的一份环形缓冲** `k.recent_syscalls`(kernel.py:186,`deque(maxlen=...)`),
每次系统调用返回时追加一条 `(pid, nr, a, b, c, ret)`(kernel.py:270)。容量默认
`TRACE_DEFAULT=200`(kernel.py:28),`trace on` 放大到 `TRACE_VERBOSE=5000`
(kernel.py:29),都走 `set_trace_capacity`(kernel.py:273)重建 deque——**轨迹始终在记,
on/off 只改历史长度**,不存在"关掉轨迹"。

monitor 侧:

- `show_trace(n)`(kmonitor.py:380):取尾部 n 条,`syscall_name` 把调用号翻成名字
  (反查 `ksyscall` 里的 `NR_*` 常量,kmonitor.py:402),`_fmt_ret` 把 `-2` 标成
  `-2(ENOENT)`(kmonitor.py:395,查 `ERRNO_NAMES`)。
- `info_syscalls`(kmonitor.py:363):先按 `k.syscall_counts` 排一张次数榜(前 20),
  再 `show_trace(10)`,末尾报缓冲占用。
- `cmd_trace`(kmonitor.py:529):`show/on/off` 三个子命令的解析。

---

## 5. 性能剖析视图:按进程(活 + 历史)

剖析分**两档**且**按进程**归口(见 CLAUDE.md):

- **常开档**:每进程的 `utime`(指令数)、`wall`(墙钟)、`syscall_counts`
  始终在累计,开销可忽略。
- **可选档**:指令混合/热点(`Profiler`,见下)默认关,`prof on` 才插桩,因为
  cpu86 是纯 Python 解释器,逐指令插桩会拖慢仿真。`cmd_prof`(kmonitor.py:572)
  经 `k.set_profiling`(kernel.py:292)开关。

进程**死后进 `proc_history`**(kernel.py:191,一个 `deque`),所以历史进程的性能
也查得到。`_perf_entries()`(kmonitor.py:598)把**活进程**(跳过内核任务)与
`proc_history` 里的**死进程**揉成同一串条目字典,是两个 profile 视图的共同数据源。

### 5.1 `Profiler`(cpu86.py:155)

`prof on` 时每条指令采样一次(`_run_profiled`,cpu86.py:564),记入:

| 字段 | 含义 |
|---|---|
| `insns` | 采样到的指令总数 |
| `cat_counts[8]` | 各类别计数,类别名 `CAT_NAMES`(cpu86.py:76):ALU/MOV/栈/分支/串/乘除/标志/其他 |
| `hot{bucket→n}` | 热点:eip 右移 `bucket_shift`(默认 6,即每桶 64B)分桶计数 |
| `rep_elems` | rep/串指令搬运的元素总数(算 rep 放大倍数用) |

### 5.2 两个视图

- **概览** `info_profile()`(kmonitor.py:619):按指令数降序,一行一进程,列出
  状态(活进程用中文态名,死进程标 `退N` 退出码)、指令数、仿真 ms、M/s 速度、
  系统调用数、**主类别**(`cat_counts` 占比最高的一类)。
- **单进程明细** `_info_profile_one(pid)`(kmonitor.py:652)+ `_render_prof_detail`
  (kmonitor.py:694):系统调用分布(前 15)+ 指令分布(按类别占比)+ 热点地址区间
  (前 10)+ **派生指标**——访存指令占比(`_CAT_MEMORY`=MOV+栈+串,cpu86.py:79)、
  控制流密度(分支占比)、平均基本块长(总数/分支)、rep 放大倍数(`rep_elems/串指令数`)。
- `dump_profile()`(kmonitor.py:683):`--profile` 退出时的完整转储,概览 + 每进程明细。

---

## 6. gdb 风格单步调试

这是本子系统的核心。命令都在 monitor 侧解析,但**逐指令推进在调度器**,两边靠
`monitor_pending` 乒乓。

### 6.1 目标进程与命令一览

`_debug_proc()`(kmonitor.py:736):调试目标 = `debug_target_pid`(`--debug` 锁定)
优先,否则当前有 CPU 的进程。命令:

| 命令 | 处理 | 返回 monitor? | 作用 |
|---|---|---|---|
| `si`/`stepi [n]` | `cmd_step`(823) | **是** | 置 `step_request=n`,离开让调度器逐条跑 |
| `disas [addr] [n]` | `cmd_disas`(843) | 否 | 反汇编 n 条(默认 eip 起 8 条) |
| `x /NFU addr` | `cmd_x`(867) | 否 | 检查内存,`i` 格式即反汇编 |
| `break <addr>` | `cmd_break`(927) | 否 | 增删/列出永久断点 `k.breakpoints` |
| `until <addr>` | `cmd_until`(952) | **是** | 加一次性断点 `k.temp_breakpoints` 并跑过去 |
| `layout [on/off]` | `cmd_layout`(773) | 否 | 三栏视图开关 |
| `info console` | `info_console`(963) | 否 | `console_tail` 里的最近输出 |
| (空行) | — | — | 重复上一条(连按回车反复 si) |
| `cont` | dispatch(196) | **是** | 离开,断点仍会命中 |

### 6.2 乒乓机制(`si` 一次单步的完整走查)

前提:已在 monitor 里(比如刚断点停下)。用户敲 `si`:

1. **monitor 侧** `cmd_step`(kmonitor.py:823):检查目标进程可运行,置
   `k.step_request = n`(默认 1),`return True` → `interact` 的 `dispatch` 收到 True
   跳出循环,`interact` 返回 → 调度器主循环从 `monitor.interact()` 处继续往下。
2. **调度器侧**:主循环转到 `_pick` 挑中该进程,因 `step_request` 非空走
   `_run_debug_slice`(kernel.py:1204/1257)。`budget = 1`(因 `step_request` 真),
   循环里 `cpu.run(1)` **执行 eip 处一条**(kernel.py:1268)——注意是 `cpu.run(1)`
   不是 `cpu.step()`:走 `run` 才有 `icount` 记账与故障/`MagicJump` 的异常臂。
3. 执行完 `step_request -= 1` → 归零 → `_debug_break(("step", pid))`(kernel.py:1272)。
   `_debug_break`(kernel.py:1251)做三件事:`step_request=0`、`debug_stop=停因元组`、
   `monitor_pending=True`。
4. **回到主循环顶部**:`monitor_pending` 置着(kernel.py:1172),清零并再入
   `interact()`。这回 `debug_stop` 非空,走 `_print_debug_stop`(kmonitor.py:751)
   打印 `[单步] pid N` + 当前指令反汇编 + 寄存器行,**并抑制欢迎语**,然后清空
   `debug_stop`。用户又回到 `(minix)` 提示符——一次乒乓闭合。

连按回车 = 重复 `si`,即反复乒乓单步。

### 6.3 断点:执行后检查

`_run_debug_slice`(kernel.py:1257)在 `cpu.run(1)` **之后**才查 `cpu.eip in breakpoints`
(kernel.py:1275-1281)。这带来 gdb 语义:

- 停下时 `eip == X`,而 **X 那条尚未执行**;
- 从断点 `cont` 继续时,先执行 X 再进入下一轮检查,所以**不会立刻重命中同一断点**,
  天然避免死循环。

`until` 是一次性断点:命中即 `discard` 后停(kernel.py:1275-1277)。异常路径
(`Exited`/`Blocked`/`Replaced`/`MagicJump`)由 `cpu.run(1)` 抛出,穿回 `run()` 的
异常臂,那里若 `_debug_active()` 也各自 `_debug_break`(kernel.py:1209-1233),
于是"进程退出/阻塞/execve/信号返回"也能停进 monitor 报因。

快慢两条路:无任何断点且不在单步时,调度器走 `cpu.run(TIMESLICE)` 快路径,
一字节不改开销(kernel.py:1203-1206);一旦有断点或 `step_request` 才切到逐指令的
慢路径。

### 6.4 停下时的现场:`_print_debug_stop` 与 layout

- 默认(layout 关):`_print_debug_stop`(kmonitor.py:751)打一行停因 + `_cur_insn`
  (当前 eip 的一条反汇编)+ `_regline`(8 个寄存器)。
- **layout 开**(`cmd_layout`,kmonitor.py:773):停下时改渲染 `_render_layout`
  (kmonitor.py:795)的**三栏**——反汇编窗口(eip 起 8 条,`→` 标当前行)、寄存器 +
  EFLAGS 标志字母、栈顶 6 个 u32(首行标 `<- esp`)。

### 6.5 地址解析:`_parse_addr`(kmonitor.py:978)

`break`/`until`/`disas`/`x` 的地址参数都过它,认三种写法:

- `$eip` / `eip` / `pc` → 当前 eip;
- `$eax`..`edi` / 裸寄存器名 → 该寄存器值(查 `cpu86.REG32_NAMES`);
- 其余交给 `int(tok, 0)`,吃 `0x..`(十六进制)与十进制,`& 0xFFFFFFFF`。

失败打印 `无效地址` 返回 `None`,调用方据此中止。

`cmd_x`(kmonitor.py:867)另解析 gdb 的 `/NFU` 规格:N 个单位,格式
`x`(十六进制)/`d`(有符号)/`u`(无符号)/`c`(字符)/`i`(反汇编),
单位 `b`/`h`/`w`(1/2/4 字节);`_last_addr` 记住续址,便于连续 `x`。

---

## 7. 只读反汇编器 `cpu_disasm.py`

**只解码、绝不执行、绝不碰 CPU 状态**。给定内存对象与地址,逐字节游走还原出
一条指令的 `(长度, 文本, 原始字节)`。它是执行器 `_execute`/`_execute_0f`/`_modrm`
的**镜像重写**——覆盖的 opcode 集就是 cpu86 实际实现的那套,其余(cpu86 本就
`_bad` 拒绝的)回退成 `.byte 0xNN`。

### 7.1 长度正确性第一

多条反汇编靠**上一条的长度**定位下一条地址(`disasm_range`,cpu_disasm.py:172),
一条长度算错则后面全错位。故 `disasm_one` 的长度必须与 cpu86 执行同一条指令时
eip 前进的字节数**逐字节一致**(有单测拿执行器做长度对照)。长度和 cpu86 一样是
**取指游走的副产品**,不查"每 opcode 多少字节"的长度表。

### 7.2 `_Reader`(cpu_disasm.py:41)——按字节前进的只读游标

`u8/u16/u32/s8/s32` 每读一段就把 `pos` 前进,`length`(cpu_disasm.py:75)= `pos-start`。
读越界抛内部 `_Bad`(cpu_disasm.py:37),不改任何状态。整个解码就是不断 `u*` 往前啃:
opcode →(ModRM → SIB → disp)→ 立即数,`length` 自然落在下一条首字节的偏移上。

### 7.3 解码主线

- `_decode(r)`(cpu_disasm.py:200):镜像 `CPU.step` 的**前缀循环**——`0x66` 置
  `opsize=2`,段/lock 前缀忽略,`0xF2/0xF3` 记 rep;带 rep 的串指令走 `_string`,
  `f3 90` 认 `pause`,否则 `_one`。
- `_one(r, op, opsize)`(cpu_disasm.py:233):一条与 `_execute` 同构的线性
  `if` 链,按 opcode 分段还原 Intel 语法文本;`0x0F` 转 `_one_0f`(cpu_disasm.py:479)。
- `_modrm(r, size)`(cpu_disasm.py:103):与 cpu86 的 `_modrm` 同样处理 SIB
  (`rm==4`)与 disp32 绝对(`rm==5 && mod==0`),但**只拼字符串**如
  `[eax+ecx*4+0x10]`,不算有效地址。内存操作数尺寸不由寄存器隐含时,`_ptr`
  (cpu_disasm.py:96)补 `dword/word/byte` 前缀。
- `disasm_one`(cpu_disasm.py:155):`_decode` 抛 `_Bad` 时回退 `.byte 0xNN`
  (长度 1),**绝不抛异常**,以便多条反汇编重新对齐。

### 7.4 一条指令的字节游走(例)

反汇编 `mov eax, [ebx+4]`,机器码 `8B 43 04`:

1. `disasm_one` 建 `_Reader(mem, addr)`,调 `_decode`。
2. `_decode`:`op = u8() = 0x8B`,非前缀,`opsize=4` → `_one(r, 0x8B, 4)`。
3. `_one` 落到 `op == 0x8B` 分支(cpu_disasm.py:316):调 `_modrm(r, 4)`。
4. `_modrm`:`b = u8() = 0x43 = 01 000 011` → mod=1、reg=0、rm=3。
   rm≠4、非(rm=5&&mod=0)→ `base=3`(ebx);mod==1 → `disp = s8() = 0x04`。
   拼出 `[ebx+0x4]`,返回 `(1, 0, 3, "[ebx+0x4]")`。
5. `_one` 拼 `f"mov {_reg(0,4)}, {_ptr(4,'[ebx+0x4]')}"` = `mov eax, dword [ebx+0x4]`。
6. 此刻 `r.pos` 已前进 3 字节 → `length = 3`,原始字节 `8b 43 04`。

monitor 的 `_cur_insn`(kmonitor.py:747)、`cmd_disas`、`_render_layout`、`x/i`
全靠这对 `disasm_one`/`disasm_range` 出文本。

---

## 8. 一次完整的调试会话走查

用户在跑着的程序上按 **Ctrl-A c**,设个断点,跑到,再单步一条:

1. `Ctrl-A c` → `on_escape`(kernel.py:1116)置 `monitor_pending`。
2. 调度器下一轮顶部(kernel.py:1172)清标志,入 `interact`。`debug_stop` 空,
   打欢迎语,进 `(minix)` 提示符。
3. `break 0x1234` → `cmd_break`(kmonitor.py:927)→ `_parse_addr` 得 0x1234 →
   `k.breakpoints.add(0x1234)`。
4. `cont` → dispatch 返回 True → 离开 monitor。
5. 调度器:`breakpoints` 非空 → 走 `_run_debug_slice`(kernel.py:1204),`budget=TIMESLICE`,
   逐条 `cpu.run(1)`,每条后查 `eip in breakpoints`。
6. 某条执行后 `eip == 0x1234` → `_debug_break(("break", pid, 0x1234))`
   (kernel.py:1280):`debug_stop` 记停因,`monitor_pending=True`,返回。
7. 主循环顶部再入 `interact`:`debug_stop` 非空 → `_print_debug_stop` 打
   `[命中断点 0x1234] pid N` + 当前指令(**尚未执行**)+ 寄存器,清 `debug_stop`,
   抑制欢迎语。
8. `si` → `cmd_step` 置 `step_request=1` 离开 → `_run_debug_slice` `budget=1` →
   `cpu.run(1)` 执行 0x1234 那条 → `step_request` 归零 → `_debug_break(("step",...))` →
   再入 monitor 打 `[单步] pid N` + 新现场。
9. `cont` → 从 0x1234 之后继续;因断点是**执行后**检查,不会立刻在 0x1234 重命中。

---

## 9. 设计取舍

- **反汇编另写一遍,不复用执行器**:`cpu_disasm` 独立解码,好处是"只读、不碰
  状态、能对任意地址反汇编",代价是解码逻辑写两份、必须**与 cpu86 同步**。用
  长度对照单测(执行器交叉校验)兜住这个风险。若把执行器改造成"解码/执行分离"
  能省一份,但会侵入那条极热的解释循环,得不偿失。
- **断点执行后检查 vs 执行前检查**:执行后检查天然实现"从断点 cont 不重命中",
  且停在 `eip==X 未执行` 符合 gdb 直觉;代价是断点必须走逐指令慢路径。
- **monitor 不自己跑指令,靠标志位乒乓**:让"推进指令"这件事只有调度器一个
  入口(记账、故障、`MagicJump`、`Blocked` 回卷都在那),monitor 保持纯观察者。
  代价是"单步一条"要绕一圈调度循环,但正确性远比省这一圈重要。
- **轨迹/常开统计常开,指令混合可选**:环形缓冲与每进程计数开销可忽略,故常开;
  逐指令插桩的指令混合默认关,`prof on` 才付代价——两档的边界就是"值不值得拖慢
  那条纯 Python 热循环"。
- **排版一律走 `dwidth`**:宁可多一层显示列数计算,也不用 `str.ljust`——中文双宽
  一破整表就散,这是硬约束不是优化。
- **未知 opcode 回退 `.byte` 而非报错**:反汇编要能在任意字节流上"尽量往下走",
  与执行器"遇未实现就 `_bad` 硬停"的策略刻意相反——观察工具的健壮性优先。

---

## 附:关键函数索引

| 环节 | 函数 | 位置 |
|---|---|---|
| 唤入标志 | `on_escape`(置 `monitor_pending`) | kernel.py:1116 |
| 调度器响应唤入 | `run` 循环顶部检查 | kernel.py:1172 |
| REPL | `Monitor.interact` | kmonitor.py:157 |
| 命令分派 | `dispatch` | kmonitor.py:182 |
| info 子分派 | `cmd_info`(handlers dict) | kmonitor.py:245 |
| 排版 | `table`/`dwidth`/`ljust`/`rjust`/`fmt_bytes` | kmonitor.py:109/90/99/104/81 |
| 轨迹显示 | `show_trace`/`info_syscalls` | kmonitor.py:380/363 |
| 轨迹缓冲 | `recent_syscalls`/`set_trace_capacity` | kernel.py:186/273 |
| 性能条目源 | `_perf_entries` | kmonitor.py:598 |
| 性能视图 | `info_profile`/`_info_profile_one`/`_render_prof_detail` | kmonitor.py:619/652/694 |
| 剖析器 | `Profiler` | cpu86.py:155 |
| 单步命令 | `cmd_step` | kmonitor.py:823 |
| 逐指令时间片 | `_run_debug_slice` | kernel.py:1257 |
| 请求进 monitor | `_debug_break` | kernel.py:1251 |
| 停下现场 | `_print_debug_stop`/`_render_layout` | kmonitor.py:751/795 |
| 反汇编命令 | `cmd_disas`/`cmd_x` | kmonitor.py:843/867 |
| 断点命令 | `cmd_break`/`cmd_until` | kmonitor.py:927/952 |
| 地址解析 | `_parse_addr` | kmonitor.py:978 |
| 反汇编入口 | `disasm_one`/`disasm_range` | cpu_disasm.py:155/172 |
| 只读游标 | `_Reader` | cpu_disasm.py:41 |
| 解码主线 | `_decode`/`_one`/`_one_0f`/`_modrm` | cpu_disasm.py:200/233/479/103 |
</content>
</invoke>
