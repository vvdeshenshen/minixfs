# 内核:进程、调度与信号的算法与代码流程

本文整理仿真器内核层(`kernel.py`)的进程模型、协作式调度器、进程生命周期、
阻塞/唤醒与信号机制是怎样运转的。CPU 层(`cpu86.py`)只管把一段机器码逐条
跑完并在 `int 0x80`/故障时回调上来;**内核层负责的是"多个进程怎么轮流用这一台
CPU、怎么睡下去又被唤醒、怎么把信号送到用户栈上"**。所有引用都标了 `文件:行`。

> 阅读顺序:先看第 1 节的进程模型与两张进程表,再看第 2 节的调度主循环
> `run()`(全篇的骨架),其余小节是被它每轮调用的各个环节(生命周期、
> 阻塞唤醒、信号、init 状态机)的展开。第 8 节是一条完整走查。

与 CPU 层的契约(kernel.py:3-9):`cpu.run(N)` 执行至多 N 条指令;
`regs[0..7]` = `eax ecx edx ebx esp ebp esi edi`;`on_int(cpu,vec)` 是
`int 0x80` 的陷入口;`on_fault(cpu,exc)` 把除零/越界转成信号。系统调用返回值
写回 `eax`,其余寄存器由内核 `system_call.s` 保证保留。

---

## 1. 进程模型:两张表 + 一个 task_struct

### 1.1 `class Process`(kernel.py:74)

字段照内核 `task_struct` 逐一对应(kernel.py:77-108):

| 字段 | 含义 |
|---|---|
| `pid` / `ppid` | 进程号 / 父进程号 |
| `pgrp` / `session` / `leader` | 进程组、会话、会话首进程标志(`setsid`) |
| `state` | `RUNNING / SLEEPING / ZOMBIE / STOPPED`(kernel.py:37) |
| `mem` | `AddressSpace`,这个进程的 64MB 用户地址空间 |
| `cpu` | 这个进程的 `CPU`;**内核任务(init)为 `None`** |
| `fds[20]` | 文件描述符表,每格是 `OpenFile` 或 `None`(`NR_OPEN=20`,kernel.py:32) |
| `close_on_exec` | 位掩码:哪些 fd 在 execve 时关闭 |
| `cwd` / `root` | 当前目录 / 根目录(都是 `VInode`,进程里不留字符串路径) |
| `umask` / `uid,euid,suid` / `gid,egid,sgid` | 权限相关 |
| `signal` / `blocked` | 待决信号位图 / 屏蔽位图 |
| `sigactions[33]` | 每信号的 `(handler, mask, flags, restorer)` 四元组 |
| `wait_channel` | 睡在哪个等待条件上(见第 4 节),`None`=未睡 |
| `alarm_at` | `alarm()` 的到期 jiffies,0=无 |
| `utime` / `stime` / `cutime` / `cstime` | 用户态/内核态指令记账,及已回收子进程的累计 |
| `restart_syscall` | 阻塞回卷标志:被信号打断唤醒时要不要吞掉重做(见 4.3) |
| `sigframes` | 每层信号帧"是否含 blocked 字段"的栈(供 `_sigreturn` 弹帧) |
| `kernel_task` | `True`=内核任务(init),不占用户态 CPU |
| `wall` / `syscall_counts` / `prof` | 按进程的墙钟秒数 / 各系统调用次数 / 指令剖析器(死后进历史) |

两个辅助:`alloc_fd(start)` 找第一个空 fd 格(kernel.py:114),`get_file(fd)`
带边界检查取 `OpenFile`(kernel.py:120)。

`OpenFile`(kernel.py:54)是 POSIX 的 *open file description*:fork/dup 让多个
fd **共享同一个** `OpenFile`,故共享读写位置 `pos` 与访问标志 `flags`;`refs`
是指向它的描述符数。`sh > file` 的重定向语义正建立在这份共享上。

### 1.2 两张进程表:`procs` 与 `runq`

- `procs: Dict[pid→Process]`(kernel.py:166)—— 全部活着的进程(含僵尸,回收前
  仍在表里),`next_pid` 单调递增发号。
- `runq: List[pid]`(kernel.py:174)—— **可运行队列**,一个 FIFO 的 pid 列表,
  调度器 `_pick` 从头轮转。睡眠/停止时从 `runq` 摘除,唤醒时重新 append。
- `current`(kernel.py:172)—— 当前正在(或刚刚)运行的进程。

### 1.3 进程状态(kernel.py:37)

```
RUNNING  可运行, 在 runq 里         SLEEPING  阻塞在某等待条件, 已摘出 runq
ZOMBIE   已 exit, 等父进程 wait     STOPPED   收到停止信号(SIGSTOP 等), 已摘出 runq
```

状态迁移都在内核层完成:`Blocked` 异常 → `SLEEPING`;`_wake` → `RUNNING`;
`sys_exit`/信号默认动作 → `ZOMBIE`;`_reap` → 从 `procs` 删除。

### 1.4 已死进程的性能快照 `ProcPerf`(kernel.py:126)

进程被 `_reap` 回收时,从 `Process` 拷一份不可变快照(pid/name/icount/wall/
syscalls/prof/exit_code)进 `proc_history` 环形缓冲(容量 `PERF_HISTORY=200`),
供 monitor 事后回看"镜像里哪个二进制跑了多少指令、什么指令分布"。`icount`
取的是 `utime`(累计用户态指令数,跨 execve 累加,kernel.py:137)。

---

## 2. 调度器 `run()`:协作式 + 指令预算(kernel.py:1163)

整台仿真机只有一根解释循环。调度是**协作式**的:每个进程一次只跑一个时间片
`TIMESLICE=100_000` 条指令(kernel.py:34,约折 10ms),跑满就交还控制权,
轮到下一个。进程之间不抢占——只在时间片边界、阻塞、退出时切换。

### 2.1 每轮的固定动作序

```python
while total < max_instructions:
    if self.quit_requested: return ...          # Ctrl-A x 退出
    if self.monitor_pending: monitor.interact() # Ctrl-A c 进 monitor
    self._pump_tty()          # 把宿主键盘输入喂进行规程
    self._check_alarms()      # 到期的 alarm() -> post_signal(SIGALRM)
    self._wake_waiters()      # 复查所有睡眠进程的等待条件(第 4 节)
    self._deliver_pending()   # 在指令边界投递待决信号(第 5 节)
    if self._init_state != "done": self._init_step()   # 内建 init 状态机(第 6 节)
    p = self._pick()          # 轮转挑一个 RUNNING 且非内核任务的进程
    if p is None: ... 空闲处理 ...
    ...跑一个时间片, 异常驱动的控制流...
```

顺序有讲究:**`_wake_waiters` 每轮都要跑**,否则管道两端互等会永久卡死
(kernel.py:1180 注释)。`_deliver_pending` 紧随其后,让本轮刚投递的信号在下面
挑中运行前就已改好 eip/栈。

### 2.2 挑选 `_pick`(kernel.py:1150)

轮转:从 `runq` 头 pop 一个 pid,若进程已不在或是僵尸就跳过,否则把它 append
回队尾(实现 round-robin),第一个 `state==RUNNING 且非 kernel_task` 的即选中。
内核任务(init)永远不会被 `_pick` 选中运行用户态——它只在 `_init_step` 里推进。

### 2.3 跑一个时间片:异常驱动的控制流(kernel.py:1198-1233)

选中 `p` 后,记下 `before = cpu.icount` 与 `t0`,然后:

```python
if 有断点 or 正在单步:  self._run_debug_slice(p, cpu)   # 逐指令(第 7 节)
else:                   cpu.run(TIMESLICE)              # 快路径, 一字节不改
```

`cpu.run()` 正常返回(跑满时间片)就直接进下一轮;若中途有事,CPU 层/系统调用
以 **Python 异常**穿透 `cpu.run()` 抛回这里,每种异常一条语义:

| 异常 | 抛出处 | 处理臂(kernel.py) | 语义 |
|---|---|---|---|
| `cpu.halted`(非异常) | `hlt` 指令 | 1207:`_exit_process(p,0)` | 程序 hlt = 正常退出 |
| `Exited(code)` | `sys_exit` / `_on_fault` | 1211:`_exit_process(p,code)` | exit 或段错误/除零转的退出码;若 `ppid==0` 直接返回 code 结束整机 |
| `Replaced` | `sys_execve` | 1217:什么都不做 | 新 CPU 已装好,下轮继续跑它 |
| `MagicJump` | `step()` 跳到魔数区 | 1221:`_sigreturn(p)` | 无 restorer 时的信号返回兜底(第 5 节) |
| `Blocked(channel)` | 各阻塞型系统调用 | 1225:置 `SLEEPING` | 见下 |

`Blocked` 臂(kernel.py:1225-1233)做四件事:`state=SLEEPING`;记下
`wait_channel=e.channel`;置 `restart_syscall=True`;**`cpu.eip -= 2` 回卷**——
`int 0x80` 是 `CD 80` 两字节,回卷到指令首字节,这样唤醒后会重新执行同一条
`int 0x80` 把系统调用**重做一遍**(读到数据/写进空位)。最后把 pid 从 `runq` 摘除。

### 2.4 记账:为什么用 `icount` 差值而不是返回值(kernel.py:1234-1241)

`finally` 里:`n = max(cpu.icount - before, 1)`,把 `n` 累进 `total`(预算)、
`p.utime`(进程记账)、`p.wall`(墙钟)、`jiffies`(时钟)。

**关键取舍**:`cpu.run()` 的返回值只在跑满时间片时才准;`Exited/Replaced/Blocked`
都是**异常路径**,从 `run()` 里抛出时返回值根本没返回。若靠返回值记账,阻塞/退出
的那批指令会漏记,`total` 永远追不上 `max_instructions` → 死循环。改用
`cpu.icount`(CPU 每执行一条就自增)的**前后差值**,无论走正常还是异常路径都记得准。

### 2.5 空闲:阻塞在终端而不是忙转(kernel.py:1185-1196)

`_pick` 返回 `None`(无可运行进程)时:若还有非僵尸的用户进程活着(都在睡),
就 `terminal.pump(0.02)` **阻塞式**等 20ms 输入并喂给行规程,`jiffies += 2`,
`idle += 1`。这样"所有进程都睡在等键盘"时不会 100% 占 CPU 空转。连续空转
超过 20000 轮(全员永久睡眠、又无输入可来)就跳出收场。若连用户进程都没了
且 init 已 `done`,直接 break 结束。

---

## 3. 进程生命周期

### 3.1 创建:`_new_process`(kernel.py:201)

发一个新 pid,建 `Process(pid, AddressSpace())`,`cwd/root` 指向 fs 根,登记进
`procs`。这是 `boot`/`fork`/`_spawn` 的公共底座。

- `boot(path)`(kernel.py:210):装单个程序——`resolve_exec` → `load_aout`(装
  a.out 正文/数据/bss) → `setup_stack`(压 argv/envp,返回初始 ESP) → 建 CPU、
  设 `eip=entry`、`regs[4]=esp`、接标准 fd。
- `_setup_std_fds`(kernel.py:228):把终端对象直接塞进 fd 0/1/2(等价于内核
  init 的 `open("/dev/tty0")+dup(0)+dup(0)`),`fd1/fd2` 共享一个 `OpenFile`
  故 `refs=2`。

### 3.2 fork(kernel.py:777)

整块拷贝地址空间 + 快照 CPU:

1. `child = Process(next_pid, p.mem.clone())` —— 地址空间**整块深拷贝**(写时不共享)。
2. 逐字段继承 ppid/pgrp/session/umask/uid.../blocked/sigactions/close_on_exec/name。
3. **fd 表逐项复制但指向同一 `OpenFile`**(kernel.py:794-797):`_acquire_fd` 让
   `refs+1`,于是父子共享文件位置——重定向语义的根基。
4. `child.cpu.restore(p.cpu.snapshot())` 复制寄存器/eip/flags,再
   `child.cpu.regs[0] = 0` —— **子进程 fork 返回 0**,父进程返回 child.pid。
5. 登记进 `procs`,**append 进 `runq`**(子进程立即可运行)。

### 3.3 execve(kernel.py:751)

换地址空间与 CPU,但**保留同一个 `Process`**(pid/ppid/fd 不变):

1. 读出 argv/envp,`resolve_exec` 解析(处理 `#!` 脚本),`load_aout` 装进
   **全新** `AddressSpace`,`setup_stack` 压栈。
2. 把 `p.mem/p.cpu` 换成新的,设 `eip=entry`、`regs[4]=esp`。
3. 关掉带 `close_on_exec` 位的 fd;清 `close_on_exec`。
4. 信号处置复位:`SIG_DFL`,但 `SIG_IGN`(handler==1)保留(kernel.py:769)。
5. **`raise Replaced()`**(kernel.py:773)—— 旧的 `cpu.run()` 循环还在 Python 栈上,
   且它持有的是**已失效的旧内存**,必须用异常打断它,回到调度器下轮跑新 CPU。

### 3.4 waitpid(kernel.py:805)

按 pid 语义(`>0` 指定子、`0` 同组、`-1` 任意、`<-1` 指定组)在**子进程**里找匹配:
无子返回 `-ECHILD`;有僵尸子则写回 `exit_code`、把子的 `utime/stime` 累进
`cutime/cstime`、`_reap` 回收、返回子 pid;`WNOHANG` 且无僵尸返回 0;否则
`raise Blocked(("wait", pid))` 睡下。

### 3.5 退出 `_exit_process`(kernel.py:840)

`state=ZOMBIE`,记 `exit_code`;释放全部 fd(`_release_file`)与地址空间;
**孤儿过继给 init**(把所有 `ppid==本pid` 的子改成 `ppid=1`,kernel.py:848);
从 `runq` 摘除;给父进程 `post_signal(SIGCHLD)`,若父正睡在 `"wait"` 上就唤醒它;
若 `ppid==0`(init 自己退出)则设 `exit_status` 结束整机。

注意:`_exit_process` 只把进程变成僵尸,**并不从 `procs` 删除**——要等父进程
`waitpid` 或 init 收尸时 `_reap`(kernel.py:835)才真正移除,并顺手把 `ProcPerf`
存进 `proc_history`。

---

## 4. 阻塞与唤醒

### 4.1 `wait_channel` 的几种(阻塞源)

系统调用发现"现在做不下去"时抛 `Blocked(channel)`,`channel` 记在
`p.wait_channel`,供 `_wake_waiters` 复查条件:

| channel | 抛出处 | 唤醒条件(`_wake_waiters`,kernel.py:1304) |
|---|---|---|
| `("piperead", pipe)` | `sys_read` 空管道(kernel.py:689) | 有数据可读,或写端全关(EOF) |
| `("pipewrite", pipe)` | `sys_write` 满管道(kernel.py:715) | 有空位,或读端全关(该收 SIGPIPE) |
| `("wait", pid)` | `sys_waitpid` 无僵尸子(kernel.py:833) | 有子进程变僵尸 |
| `terminal`(对象本身) | `sys_read` 终端无输入(kernel.py:696) | 终端 `ready` 或 `eof_pending` |
| `("pause", pid)` | `sys_pause`(kernel.py:969) | 只能被信号打断(第 5 节),`_wake_waiters` 不管它 |

管道读/写"端全关"的判断依赖**按描述符计数**的 `readers/writers`
(`_acquire_fd`/`_release_file`,kernel.py:863/873):每多/少一个指向管道的
**描述符**就 ±1,不能等 `OpenFile.refs` 归零——否则 fork 后写端永远关不掉,
读端永远等不到 EOF,流水线死锁。

### 4.2 `_wake_waiters` 每轮复查(kernel.py:1304)

调度循环每轮遍历所有 `SLEEPING` 进程,按 `wait_channel` 的类型检查条件是否
已满足,满足就 `_wake(q)`。这是一种**轮询式**唤醒:不做精细的等待队列,而是
每轮 O(进程数) 地复查——进程少,足够。

### 4.3 `_wake`:普通唤醒 vs 被信号打断(kernel.py:924)

```python
def _wake(self, p, interrupted=False):
    if p.state != SLEEPING: return
    p.state = RUNNING
    p.wait_channel = None
    if interrupted and p.restart_syscall:   # 被信号打断的唤醒
        p.cpu.eip += 2                       # 把 eip 推回 int 0x80 之后
        p.cpu.regs[0] = -EINTR               # 系统调用返回 -EINTR
        p.restart_syscall = False
    if p.pid not in self.runq: self.runq.append(p.pid)
```

两条唤醒路径的差别全在这里,对应阻塞时 `eip -= 2` 的回卷(2.3):

- **条件满足的正常唤醒**(`interrupted=False`,来自 `_wake_waiters`):eip 停在
  回卷后的位置,唤醒后**重新执行** `int 0x80` 把系统调用重做——这次能读到数据。
- **被信号打断的唤醒**(`interrupted=True`,来自 `post_signal`):把 `eip += 2`
  推回到 `int 0x80` **之后**(不重做),并让 `eax = -EINTR`。这样用户态看到的是
  "系统调用被信号中断"。

**这里是最容易踩的坑**(CLAUDE.md 已记回归):若不把 eip 推回,回卷留下的
`int 0x80` 会在信号处理后被重新执行,而此刻 `eax` 里是 `-EINTR`(一个大负数),
会被当成**系统调用号**去分派——彻底跑飞。

---

## 5. 信号

### 5.1 投递路径概览

```
产生: sys_kill / _check_alarms(SIGALRM) / _exit_process(SIGCHLD) / _on_fault(SIGSEGV,SIGFPE)
         │  post_signal: 置 p.signal 位, 若能递达且在睡 -> _wake(interrupted=True)
         ▼
边界投递: 调度每轮 _deliver_pending -> 取最低位待决信号 -> _take_signal
         ▼
分派: SIG_IGN 丢弃 / SIG_DFL(忽略|停止|终止) / 有 handler -> _build_signal_frame 压栈跳过去
         ▼
返回: libc sa_restorer 用户态弹栈; restorer==0 时跳魔数 -> MagicJump -> _sigreturn 弹帧
```

### 5.2 `post_signal`(kernel.py:908)

置 `p.signal |= 1<<(sig-1)`。若进程没在睡、或该信号被 `blocked`,就只置位不唤醒。
否则**只有真会被递达的信号才打断睡眠**:handler 为 `SIG_IGN`(1)不唤醒;handler
为 `SIG_DFL`(0) 且属于"默认忽略"集(`SIGCHLD/SIGCONT`)也不唤醒——**否则 waitpid
会拿到 `-EINTR`,bash 把它当调用号重跑 `int 0x80`**。其余才 `_wake(interrupted=True)`。

### 5.3 `_deliver_pending` 与 `_take_signal`(kernel.py:1327 / 1339)

`_deliver_pending` 在每轮的指令边界(等价于内核 `ret_from_sys_call` 的时机)
遍历进程,取 `pend = signal & ~blocked` 的**最低位**(`(pend&-pend).bit_length()`,
等价汇编 `bsfl`),清位后交 `_take_signal`:

- `SIG_IGN` → 丢弃。
- `SIG_DFL` → 默认忽略集丢弃;停止信号集置 `STOPPED` 并摘出 runq;否则
  `_exit_process(q, sig)`(默认动作是终止,退出码即信号号)。
- 有用户 handler → `_build_signal_frame`。

### 5.4 信号帧 `_build_signal_frame`(kernel.py:1359)

布局照内核 `kernel/signal.c` 的 `do_signal`,在用户栈上**从高到低**压 7 或 8 个长字:

```
高地址  old_eip            <- 处理完 ret 回到这
        eflags
        edx
        ecx
        eax
        [blocked]          <- 仅当 !SA_NOMASK 时有(压 8 个); SA_NOMASK 时省略(7 个)
        signr              <- 传给 handler 的参数
低地址  sa_restorer  (=restorer, 或 restorer==0 时用 MAGIC_SIGRETURN)  <- ESP 最终指这
```

然后 `eip = handler`、`blocked |= mask`(处理期间自动屏蔽)、`SA_ONESHOT` 则复位为
`SIG_DFL`。**帧里有没有 `blocked` 无法从栈上看出**(取决于当初的 `SA_NOMASK`),
所以压帧时把这个布尔记进 `p.sigframes`(kernel.py:1386),`_sigreturn` 据此弹帧。
若进程原本在睡,先转 `RUNNING` 并回 runq。

Linux 0.11 **没有 sigreturn 系统调用**:handler 执行完 `ret` 会弹掉栈顶的
`sa_restorer` 地址跳过去,由 libc 提供的 restorer 在用户态把上面那些长字弹回
寄存器再回到 `old_eip`。所以 `sys_signal` 是**三参**的(见下)。

### 5.5 兜底返回 `_sigreturn`(kernel.py:1283)

只有 `restorer==0` 才会用到:压帧时用了 `MAGIC_SIGRETURN=0xFFFF0000`(kernel.py:51)
当返回地址,handler 的 `ret` 跳到这个魔数地址,`step()` 抛 `MagicJump` 穿到调度器
`_sigreturn`。它按压帧的逆序弹栈:`signr`、(据 `sigframes.pop()` 决定的)`blocked`、
`eax`、`ecx`、`edx`、`eflags`、`old_eip`,把上下文恢复到信号发生前。

### 5.6 三个系统调用

- `sys_signal(sig, handler, restorer)`(kernel.py:1394):**三参**,`edx=restorer`。
  装 `(handler, 0, SA_ONESHOT|SA_NOMASK, restorer)`——0.11 的 signal 是一次性
  且不屏蔽的。返回旧 handler。
- `sys_sigaction(sig, newp, oldp)`(kernel.py:1402):读写完整四元组
  `(handler, mask, flags, restorer)`。
- `sys_kill(pid, sig)`(kernel.py:941):按 pid 符号选目标集(`>0` 单进程、`0`
  本组、`-1` 除 init 外全体、`<-1` 指定组),`sig==0` 只探测存在性,否则逐个
  `post_signal`。
- 相关:`sys_pause`(kernel.py:969)睡到有信号;`sys_alarm`(kernel.py:987)设
  `alarm_at`,由 `_check_alarms` 到点投 SIGALRM;`sys_sgetmask/ssetmask`
  (kernel.py:961/964)读写 `blocked`(不许屏蔽 SIGKILL)。

---

## 6. 内建 init:一个内核任务状态机

Linux 0.11 的 init **不是磁盘上的程序**,而是内核 `init/main.c` 的 `init()`
函数在用户态执行(镜像里的 `/bin/init` 是后来某软件包的产物,不在引导链上)。
仿真器把它实现成一个**内核任务**:`kernel_task=True`、`cpu=None`,不占用户态
CPU,由调度器每轮调 `_init_step` 按状态机推进。

- `boot_init`(kernel.py:994):建 pid 1,`ppid=0`、`name="init"`、接标准 fd
  (等价 `open("/dev/tty0")+dup(0)+dup(0)`),置初态 `_init_state="rc"`。
- `_spawn`(kernel.py:1033):替 init 起子进程 = `fork+重定向+execve` 的合并版:
  新建进程、`resolve_exec`+`load_aout`+`setup_stack`、接标准 fd,`new_session`
  时自成会话并把终端的 session/pgrp 指过去,`stdin_from` 时把 fd0 换成脚本文件
  (init 跑 rc 是 `close(0)` 后 `open("/etc/rc")`)。append 进 runq。
- `_init_step`(kernel.py:1065)的状态机:

| 状态 | 动作 | 迁移 |
|---|---|---|
| `rc` | `_spawn(/bin/sh, stdin=/etc/rc)` 跑开机脚本 | → `wait_rc`(无 /etc/rc 则直接 → `shell`) |
| `wait_rc` | 等 rc 子进程变僵尸 → `_reap` | → `shell` |
| `shell` | `_spawn(-/bin/sh, new_session)` 起 login shell(前导 `-` 让 bash 读 /etc/profile) | → `wait_shell` |
| `wait_shell` | 等 shell 死 → 打印 `child N died with code XXXX`,`sync` | 控制台还活着 → `shell`(无限重启);否则 → `done` |

`_console_alive`(kernel.py:1102):交互终端**永远算活着**(真机控制台不会 EOF,
故 init 无限重启 shell 是对的);但输入是管道/脚本时,耗尽后算死,`wait_shell`
→ `done` 就地收场,避免空转。

---

## 7. 单步调试:慢路径,快路径不受影响(kernel.py:1257)

有断点、正在单步、或 `--debug` 锁了目标时(`_debug_active`,kernel.py:1246),
时间片走 `_run_debug_slice` 而非 `cpu.run(TIMESLICE)`:逐条 `cpu.run(1)`,每条后
检查步数用尽 / 命中 `temp_breakpoints`(until 一次性) / 命中 `breakpoints`,命中即
`_debug_break`(记停因、请求进 monitor)。断点**执行后**检查(gdb 语义:停时
eip==X 且 X 尚未执行;从断点 cont 时先执行 X 再查,天然不重复命中)。所有这些
状态默认全空,**调度器快路径一字节不改**——不调试时零开销。

---

## 8. 一条完整走查:阻塞 read → 输入唤醒(含 eip 回卷)

设 shell 执行到 `int 0x80`(机器码 `CD 80`,设在 eip=0x1050),`eax=3`(read)、
`ebx=0`(fd0=终端)、此刻终端无输入。

1. **陷入**:CPU 执行 `int 0x80` → `on_int(cpu, 0x80)`(kernel.py:245)。读
   `nr=3,a=0(fd),b=buf,c=count`,`dispatch` 进 `sys_read`。此刻 CPU 内部 eip
   已前进到 `0x1052`(`CD 80` 之后)。
2. **阻塞**:`sys_read` 走到终端分支,`obj.read(count)` 返回 `None`(无输入)→
   `raise Blocked(terminal)`(kernel.py:696)。异常穿透 `cpu.run()` 抛回调度器。
3. **睡下 + 回卷**:`Blocked` 臂(kernel.py:1225)置 `state=SLEEPING`、
   `wait_channel=terminal`、`restart_syscall=True`,**`cpu.eip -= 2` 回到 0x1050**,
   把 pid 摘出 `runq`。`finally` 用 `icount` 差值把这段指令记进账。
4. **空闲等待**:`_pick` 再无可运行进程(shell 睡了),调度器
   `terminal.pump(0.02)` 阻塞等 20ms 键盘输入。
5. **输入到达**:用户敲了一行回车。某轮 `_pump_tty` 把它喂进行规程,终端
   `ready` 置真。
6. **条件唤醒**:同轮 `_wake_waiters`(kernel.py:1322)发现 `wait_channel is
   terminal` 且 `terminal.ready`,调 `_wake(q)`(**`interrupted=False`**):
   `state=RUNNING`、`wait_channel=None`、eip 保持在回卷后的 **0x1050**、重回 runq。
7. **重做系统调用**:下轮 `_pick` 选中 shell,`cpu.run()` 从 0x1050 **重新执行**
   `int 0x80` → 再次 `sys_read`,这次终端有数据,返回读到的字节数写回 `eax`,
   eip 正常前进到 0x1052,read 完成。

**对照**:若第 5 步来的不是输入而是 `SIGINT`(Ctrl-C),则走 `post_signal`
→ `_wake(interrupted=True)`(kernel.py:924):eip **`+= 2` 推回 0x1052**、
`eax=-EINTR`。read **不重做**,用户态 read 返回 `-EINTR`,随后
`_deliver_pending` 在指令边界把 SIGINT 递给 handler 或按默认动作终止。这正是
回卷(阻塞)与推回(打断)两条路径的分水岭。

---

## 9. 设计取舍

- **协作式 + 固定时间片 vs 抢占**:没有真正的定时器中断,靠"每进程跑满
  `TIMESLICE` 条就交还"近似分时。实现极简,代价是一个死循环不做系统调用的进程
  会独占一个完整时间片才被换下——对跑老程序的仿真足够。
- **`icount` 差值记账 vs `run()` 返回值**:必须用差值,因为退出/替换/阻塞都是
  异常路径,返回值拿不到,漏记会让预算永远到不了而卡死(2.4)。
- **轮询式唤醒 vs 精确等待队列**:`_wake_waiters` 每轮 O(N) 复查所有睡眠进程的
  条件,不维护 per-资源 等待队列。进程数少时最省心;规模大才需要精确队列。
- **阻塞回卷 + 唤醒推回**:用"eip 回卷 2 字节 + 唤醒时按 `interrupted` 决定推不推
  回"这一对操作,统一表达了"条件满足则重做、被信号打断则返回 `-EINTR`"两种
  语义,而不必给系统调用留可重入的中间状态。唯一硬编码的指令长度(`CD 80`=2)
  就在这里,因为它必须在 `step()` 之外倒推(拿不到 `_insn_start`)。
- **管道计数按描述符而非 OpenFile.refs**:fork 让父子共享同一 `OpenFile`,若等
  `refs` 归零才算"端关闭",写端永远关不掉、读端永远等不到 EOF → 流水线死锁。
  故 `readers/writers` 随**每个描述符**的增减而 ±1。
- **execve 抛 `Replaced` 而非就地返回**:旧 `cpu.run()` 循环持有已失效的旧内存,
  必须用异常打断它,不能让它继续执行哪怕一条。
- **init 做成内核任务而非跑 /bin/init**:忠于 0.11 引导链(init 是内核函数),
  且省掉为它单独仿真一段用户态代码;状态机把 `fork/wait/execve` 的控制流搬到
  Python 层,`kernel_task` 使它对 `_pick` 隐形。
- **信号默认忽略集不打断睡眠**:`SIGCHLD/SIGCONT` 若唤醒 `waitpid` 会让它拿到
  `-EINTR`,而 bash 会把返回的负值当调用号重跑——所以只有真会被递达的信号才
  `_wake(interrupted=True)`。
- **调试慢路径与快路径分离**:断点/单步逻辑全塞进 `_run_debug_slice`,不调试时
  `run()` 直接 `cpu.run(TIMESLICE)`,逐指令检查的开销一点不沾快路径。

---

## 附:关键函数索引

| 环节 | 函数 | 位置 |
|---|---|---|
| 进程对象 | `class Process` | kernel.py:74 |
| open file description | `class OpenFile` | kernel.py:54 |
| 死进程快照 | `class ProcPerf` | kernel.py:126 |
| 调度主循环 | `run` | kernel.py:1163 |
| 轮转挑选 | `_pick` | kernel.py:1150 |
| 每轮维护 | `_pump_tty/_check_alarms/_wake_waiters/_deliver_pending` | kernel.py:1140/1144/1304/1327 |
| 进程创建 | `_new_process` / `boot` | kernel.py:201 / 210 |
| 标准 fd | `_setup_std_fds` | kernel.py:228 |
| CPU 工厂 | `_make_cpu` | kernel.py:279 |
| int 陷入 | `_on_int` | kernel.py:245 |
| 故障转信号 | `_on_fault` | kernel.py:314 |
| fork | `sys_fork` | kernel.py:777 |
| execve | `sys_execve` | kernel.py:751 |
| waitpid | `sys_waitpid` | kernel.py:805 |
| 退出/回收 | `_exit_process` / `_reap` | kernel.py:840 / 835 |
| fd 引用计数 | `_acquire_fd` / `_release_file` | kernel.py:863 / 873 |
| 管道 | `sys_pipe` | kernel.py:888 |
| 唤醒 | `_wake` | kernel.py:924 |
| 复查等待条件 | `_wake_waiters` | kernel.py:1304 |
| 产生信号 | `post_signal` / `sys_kill` | kernel.py:908 / 941 |
| 边界投递 | `_deliver_pending` / `_take_signal` | kernel.py:1327 / 1339 |
| 建信号帧 | `_build_signal_frame` | kernel.py:1359 |
| 信号返回兜底 | `_sigreturn` | kernel.py:1283 |
| signal/sigaction | `sys_signal` / `sys_sigaction` | kernel.py:1394 / 1402 |
| pause/alarm | `sys_pause` / `sys_alarm` / `_check_alarms` | kernel.py:969 / 987 / 1144 |
| 内建 init | `boot_init` / `_spawn` / `_init_step` | kernel.py:994 / 1033 / 1065 |
| 控制台存活 | `_console_alive` | kernel.py:1102 |
| 单步调试 | `_run_debug_slice` / `_debug_break` | kernel.py:1257 / 1251 |
| 剖析开关 | `set_profiling` / `reset_profiling` | kernel.py:292 / 308 |
