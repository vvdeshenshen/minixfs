# 仿真器总览:从命令行到跑起 1991 年的 a.out

本文是仿真器的**地图**:它怎样分层、依赖朝哪个方向、一条命令行如何最终把一个
1991 年的 a.out 二进制在纯 Python 的 ring-3 环境里跑起来。细节各有专文
(CPU 解码见 `docs/x86-decode-and-emulation.md`,调度与系统调用见内核层文档);
这里只把各层的职责、粘合点与引导链讲清楚。

> 阅读顺序建议:先看第 1 节的分层与依赖方向,再看第 3 节的引导链与第 6 节的
> 顶层运行循环——这两处是"谁调谁"的骨架。其余小节是命令行契约、终端 I/O 与
> 端到端追踪的展开。所有引用都标了 `文件:行`。

---

## 1. 分层与依赖方向(严格单向)

整套仿真器共用只读解析库 `minixfs.py`,依赖方向**严格单向**,越往下越不知道
上层的存在。CPU 层甚至不 import 内核与 minixfs:

```
emulator.py                     命令行、宿主终端、顶层循环入口
   │
   ▼
kernel.py                       内核门面: 进程/fd/信号/调度
   │  (import: kvfs, cpu86, kexec, ksyscall, x86mem —— kernel.py:18-26)
   ├──► ksyscall.py             87 项系统调用分派表(照镜像 include/linux/sys.h)
   ├──► kexec.py                a.out ZMAGIC 装载 + 初始栈构造
   ├──► kvfs.py                 覆盖式虚拟文件层(inode 级 copy-on-write)
   ├──► ktty.py                 终端 + 行规程 + 宿主终端后端
   ├──► kmonitor.py             qemu 风格 monitor 控制台(内核之外, 反向读内核)
   │
   ▼
minixfs.py                      只读 Minix v1 解析库(不做任何输出)

cpu86.py ──► x86mem.py          CPU 层: 指令解释 + 平坦地址空间
                                (不 import 内核, 也不 import minixfs)
```

各模块一行职责:

| 模块 | 职责 | 关键类型 |
|---|---|---|
| `emulator.py` | 命令行解析、搭链、宿主终端、把 `k.run()` 跑起来 | `build_kernel`、`main` |
| `kernel.py` | 进程表、文件描述符、信号、调度循环、内建 init | `Kernel`、`Process` |
| `ksyscall.py` | int 0x80 的调用号→实现分派(eax/ebx/ecx/edx→eax) | `SyscallTable` |
| `kexec.py` | 把 a.out 装进地址空间、构造 argv/envp 初始栈 | `load_aout`、`setup_stack` |
| `kvfs.py` | 只读镜像上叠一层可写视图,镜像本身永不改 | `OverlayFS`、`VInode`、`Pipe` |
| `ktty.py` | 行规程(ICANON/回显/信号)+ 分平台的宿主 I/O | `TTY`、`HostTerminal` |
| `kmonitor.py` | 运行时检视与单步调试控制台 | `Monitor` |
| `cpu86.py` | i386 用户态指令解释器,`int N`/故障上调回调 | `CPU`、`Profiler` |
| `x86mem.py` | 64MB 双区平坦地址空间,越界抛 `SegFault` | `AddressSpace` |
| `minixfs.py` | Minix v1 块/inode/目录/文件解析,MBR 探测 | `MinixFS` |

**约束:`minixfs.py` 与 `pager.py` 不被仿真器修改。** 它们是浏览器
(`minix_shell.py`)与仿真器共用的只读底座;仿真器需要"可写"时,是在 `kvfs.py`
里叠覆盖层,而不是去改镜像或解析库。CPU 层(`cpu86.py`/`x86mem.py`)与内核层
之间只有回调契约(`on_int`/`on_fault`),没有 import 依赖——这样 CPU 能脱离
内核单测。

---

## 2. 用户态仿真模型:只有 ring-3 与一扇门

仿真器**只仿真用户态**。被仿真进程看到的是一台平坦的 i386:

- **一个 64MB 平坦地址空间**,代码从虚址 0 起,栈顶在 64MB 处向下长
  (`AddressSpace`,x86mem.py)。**没有 MMU、没有分页、没有 GDT/LDT、没有段
  寄存器语义、没有特权级切换**——段前缀在解码时直接被消费掉。
- **用户态与内核态之间只有一扇门:`int 0x80`**。CPU 执行到它时调用注入的
  `on_int` 回调(kernel.py:245),内核读 `eax`(调用号)与 `ebx/ecx/edx`(参数),
  在 Python 里实现该系统调用,把返回值写回 `eax`。这就是全部的"陷入内核"。
- **故障也走回调**:越界访存抛 `SegFault`、除零抛 `DivideError`,被 CPU 的
  `on_fault` 接住转成 SIGSEGV/SIGFPE。
- **内核本身不是被仿真的机器码**,而是 Python 函数。进程/调度/文件/信号全在
  Python 层用普通对象表达;唯有用户程序的每一条 x86 指令是真的被逐条解释执行的。

也就是说:内核层扮演"Linux 0.11 内核",CPU 层扮演"i386 芯片的用户态半边",
两者靠 `int 0x80` 与两个故障回调对接。

---

## 3. 引导链:init 是内核函数,不是 /bin/init

**Linux 0.11 的 init 不是磁盘上的程序**,而是内核 `init/main.c` 里的 `init()`
函数在用户态执行(镜像里确实有个 `/bin/init`,那是后来某软件包的产物,**不在
0.11 引导链上**,别拿它当入口)。内核原文的引导链(boot_init 的 docstring
逐字抄了它,kernel.py:994-1016)是:

```c
open("/dev/tty0", O_RDWR, 0); dup(0); dup(0);   // fd 0/1/2 都接控制台
if (!(pid = fork())) {                          // 子进程跑 /etc/rc
    close(0); if (open("/etc/rc", O_RDONLY, 0)) _exit(1);
    execve("/bin/sh", argv_rc, envp_rc);        // argv_rc = {"/bin/sh"}
}
while (pid != wait(&i));                         // 等 rc 跑完
while (1) {                                      // 之后无限起登录 shell
    if (!(pid = fork())) {
        close(0);close(1);close(2); setsid();
        open("/dev/tty0",...); dup(0); dup(0);
        _exit(execve("/bin/sh", argv, envp));    // argv = {"-/bin/sh"}
    }
    while (1) if (pid == wait(&i)) break;
    printf("child %d died with code %04x", pid, i);
}
```

`argv = {"-/bin/sh"}` 的**前导 `-` 使它成为 login shell**(bash 因此读
`/etc/profile`)。

### 3.1 实现为内核任务状态机

这条 `init()` 被实现成 **Python 层的内核任务**,不占用户态 CPU:

- `Kernel.boot_init()`(kernel.py:994)建立 pid 1,`p.cpu = None`、
  `p.kernel_task = True`(Process 上的标志,kernel.py:104),它没有被解释的机器码。
- 之后由调度循环每轮调 `_init_step()`(kernel.py:1065)按状态机推进:
  `rc → wait_rc → shell → wait_shell → …`。`_spawn()`(kernel.py:1033)相当于
  "fork + 重定向 + execve",替 init 起真正的用户态子进程(sh 有 CPU、有机器码)。

| 状态 | 动作 | 下一状态 |
|---|---|---|
| `rc` | `_spawn("/bin/sh", stdin_from="/etc/rc")`;无 rc 则跳过 | `wait_rc` / `shell` |
| `wait_rc` | 等 rc 子进程变 ZOMBIE 并 `_reap` | `shell` |
| `shell` | `_spawn("-/bin/sh", new_session=True)` 起 login shell | `wait_shell` |
| `wait_shell` | 收尸并打印 `child N died with code XXXX`,再重启 | `shell` / `done` |

**收场的差别**:真机控制台不会 EOF,所以 init 无限重启 shell 是对的;但当输入是
管道/脚本(`printf ... | emulator.py`)时,输入耗尽后再重启只会空转,于是
`_console_alive()`(kernel.py:1102)判死后转入 `done` 就地收场,让 `run()` 能退出。

`emulator.py` 里:命令行**没给程序名**时走 `k.boot_init()`(emulator.py:143),
**给了程序名**时走 `k.boot(program, argv)`(emulator.py:145,kernel.py:210)只装
单个程序,跳过整条引导链。

---

## 4. 命令行契约:选项必须写在程序名之前

用法形态是 `emulator.py [选项] 镜像 [程序 [程序参数...]]`。**程序名之后的一切
都原样透传给被仿真程序**,好让 `ls -l` 的 `-l` 不被仿真器吃掉。

这靠 `split_argv()`(emulator.py:51)手工切分,而**不是** argparse 的
`nargs=REMAINDER`:后者会把本该落到 `program` 的位置参数也吞进 args,于是
`--trace /bin/date` 会退化成 program=None、args=['/bin/date'],结果跑的是引导链
而不是 date。切分规则:从左到右,`-` 开头的当仿真器选项(值型选项见
`VALUE_OPTS`,emulator.py:47,要连值一起带走),第一个非选项是镜像,**镜像之后的
第一个非选项及其后全部**归 tail 透传。

主要选项(`main` 里 argparse 解析 head 部分,emulator.py:88-119):

| 选项 | 作用 |
|---|---|
| `--offset N` | 文件系统起始字节偏移(不给则 MBR 自动探测) |
| `--trace` | 放大轨迹缓冲(`TRACE_VERBOSE`),退出时把系统调用轨迹转储到 stderr(emulator.py:123,163) |
| `--profile` | 开 CPU 指令混合剖析(拖慢),退出时把统计转储到 stderr;须在 boot 前开好,新建 CPU 才挂得上剖析器(emulator.py:125,167) |
| `--monitor` | 启动后先停进 monitor 控制台(设 `monitor_pending`) |
| `--debug` | 单步调试:执行第 0 条前停进 monitor,并锁定 `debug_target_pid`(emulator.py:147,154) |
| `--escape CHAR` | monitor 转义键(默认 `a`=Ctrl-A;`none` 关闭),`ord(upper)&0x1F` 折成控制码(emulator.py:113-119) |
| `--max-insns N` | 指令数上限,防跑飞 |
| `--save-overlay` / `--load-overlay` | 退出时导出 / 启动时加载覆盖层改动(pickle) |

---

## 5. 搭链:build_kernel 把五样东西串起来

`build_kernel()`(emulator.py:25)按 **镜像 → 覆盖层 → 终端 → 内核 → monitor**
的顺序搭好整条链:

1. `OverlayFS(MinixFS.open(image))`——只读镜像外叠一层可写视图。
2. 终端后端:交互用 `HostTerminal`,脚本化(stdin 是管道)用 `ScriptedTerminal`。
3. `Kernel(fs)`——建内核门面。
4. `TTY(term, escape, on_escape=k.on_escape)`——**TTY 必须在 Kernel 之后建**,
   因为转义键回调要指向内核的 `on_escape`,建好再回填 `k.terminal = tty`。
5. `k.monitor = Monitor(k)`——monitor 反向持有内核引用做检视。

注意 build_kernel 的注释点明:覆盖层里**不预置任何文件**,init 打开的
`/dev/tty0` 是镜像里真实存在的设备节点(早先为错误的 `/bin/init` 引导路径合成过
`/dev/console`、`/etc/utmp`,已随死代码一并删除)。

---

## 6. 顶层运行循环:把 CPU / 内核 / 终端粘起来

`main` 最后调 `k.run(a.max_insns)`(emulator.py:158),控制权交给内核的调度循环
`Kernel.run()`(kernel.py:1163)。这个循环是**协作式调度 + 指令预算**,每一轮
(概览,细节见内核调度文档):

1. 若 `quit_requested`(Ctrl-A x)则返回退出码;若 `monitor_pending`
   (Ctrl-A c / --monitor / --debug)则先 `monitor.interact()`(kernel.py:1172)。
2. `_pump_tty()` 抽宿主输入喂给行规程、`_check_alarms()`、`_wake_waiters()`、
   `_deliver_pending()` 派发信号。
3. `_init_step()` 推进内建 init 状态机(kernel.py:1183)。
4. `_pick()`(kernel.py:1150)轮转挑一个可运行的**用户态**进程(跳过 init 这种
   `kernel_task`)。挑不到就 `terminal.pump(0.02)` 阻塞等输入,全员永久睡眠且
   无输入可来时退出。
5. 给选中进程跑一个时间片:快路径 `cpu.run(TIMESLICE)`(kernel.py:1206,
   TIMESLICE=100000 条,kernel.py:34);有断点/单步则走逐指令的 `_run_debug_slice`。
6. 按 CPU 抛出的异常分流:`Exited`→收尸、`Replaced`(execve 换了 CPU)→下轮继续、
   `MagicJump`→`_sigreturn` 弹信号帧、`Blocked`→睡眠且 **`eip -= 2` 回卷**
   (`int 0x80` 是 `CD 80` 两字节,唤醒后重做,kernel.py:1229)。
7. **记账用 `cpu.icount` 的差值**(kernel.py:1237):Blocked/Exited 都走异常路径,
   靠 `run()` 的返回值会漏记而使 `max_instructions` 永远到不了。

CPU 与内核的粘合点就是 `_make_cpu()`(kernel.py:279)注入的 `on_int`/`on_fault`
两个回调:CPU 只管解释指令,一遇到门或故障就上调 Python 内核。

---

## 7. 终端 I/O:分平台的三条路

宿主终端是被仿真进程与真实键盘/屏幕之间的桥,`HostTerminal`(ktty.py:203)按平台
分三条输入路(因为 `select` 在 Windows 上只对 socket 有效,拿控制台句柄会直接失败):

| 平台/场景 | 输入后端 | 出处 |
|---|---|---|
| POSIX 交互/管道 | stdin 设 **raw + select** 轮询 | `_enter_raw`(ktty.py:240) |
| Windows 交互 | `msvcrt.kbhit/getch` 逐键读 | ktty.py:330 |
| Windows 管道 | **后台线程**读进队列 | `_start_reader_thread`(ktty.py:268) |

其余要点:

- **输出一律写 `stdout.buffer`(二进制)**(ktty.py:369),否则 Windows 的文本层
  会把 `\n` 再变 `\r\n`,与行规程的 ONLCR 展开(ktty.py:543)撞车成 `\r\r\n`。
- **退出途径只有转义键 Ctrl-A x**。交互时宿主终端是 raw 模式,Ctrl-C 会作为字节
  0x03 进行规程转成 SIGINT 发给**被仿真进程**,宿主永远收不到信号。转义键在
  `TTY._strip_escapes`(ktty.py:434)里于行规程**之前**拦截——这样即便被仿真
  程序关掉 ICANON/ISIG(bash 就会),Ctrl-A c/x/? 仍然有效。命中后调
  `Kernel.on_escape`(kernel.py:1116):`x`→请求退出、`c`→进 monitor、`?`→帮助。
- 退出时 `main` 的 `finally` 里 `term.restore()`(emulator.py:162)把宿主终端复原,
  再按需转储 trace/profile。

---

## 8. 端到端启动追踪(例)

**A. 完整引导** `python3 emulator.py hdc-0.11.img`:

1. `split_argv` 把 `hdc-0.11.img` 认成镜像,tail 为空 → `program=None`。
2. `build_kernel` 搭链:OverlayFS(镜像)→ HostTerminal(交互 tty,进 raw)→
   Kernel → TTY(挂 on_escape)→ Monitor。打印 monitor 提示行。
3. 无程序名 → `k.boot_init()`:建 pid 1(kernel_task,无 CPU),
   `_setup_std_fds` 把 fd 0/1/2 接上 `/dev/tty0`。
4. `k.run()`:每轮 `_init_step` 推进——先 spawn `/bin/sh < /etc/rc`(有 CPU 的真
   用户进程),等它收尸;再 spawn `-/bin/sh` 登录 shell,建新会话。
5. 调度循环挑到 sh,`cpu.run(TIMESLICE)` 逐条解释它的机器码;sh 读键盘、
   `int 0x80` 陷入内核跑 read/write/fork/execve……直至 Ctrl-A x 触发
   `on_escape` 置 `quit_requested`,`run()` 返回,`finally` 复原终端。

**B. 单个程序** `python3 emulator.py hdc-0.11.img /bin/date`:

1. tail=`['/bin/date']` → `program='/bin/date'`,`prog_args=[]`。
2. `k.boot('/bin/date', [b'/bin/date'])`:`resolve_exec` 解析路径、
   `load_aout` 装 ZMAGIC 到虚址 0、`setup_stack` 铺 argv/envp 初始栈、
   `_make_cpu` 建 CPU 并置 eip=entry、esp=栈顶,**跳过整条引导链**。
3. `k.run()` 直接调度这个进程跑到 `exit`,`ppid==0` 的进程退出时 `run()` 返回其
   退出码,`main` 折成进程退出码 `(code>>8)&0xFF`。

**C. 脚本化** `printf 'echo hi\n' | emulator.py hdc-0.11.img`:stdin 非 tty →
`ScriptedTerminal`,输入耗尽后 `_console_alive()` 判死,init 状态机转 `done`,
调度循环自然退出。

---

## 设计取舍

- **init 做成内核任务而非跑用户态 /bin/sh 当 init**:Linux 0.11 的 init 本就是
  内核 `init()` 在用户态跑,没有对应的磁盘程序。做成不占 CPU 的 Python 状态机,
  既忠于原文,又省掉"用解释器跑一段其实是内核逻辑的机器码"的开销;镜像里的
  `/bin/init` 是无关软件包,刻意不碰。
- **手写 split_argv 而非 argparse.REMAINDER**:REMAINDER 会吞掉 program 位置参数,
  导致 `--trace /bin/date` 跑成引导链。手工切分虽朴素,但"程序名之后原样透传"
  的契约(让 `ls -l` 的 `-l` 归被仿真程序)只有这样才守得住。
- **可写性放在覆盖层,不碰只读底座**:`minixfs.py`/`pager.py` 与浏览器共用,仿真器
  一切写操作叠在 `kvfs.OverlayFS`(inode 级 copy-on-write),镜像文件与解析库
  零改动。selecting inode 级而非路径级覆盖是为了让硬链接/unlink-after-open/
  opendir 原始 dirent 都成立(见 kvfs.py 头注)。
- **CPU 层零内核依赖,只留回调**:`cpu86.py` 不 import `kernel`/`minixfs`,内核靠
  注入 `on_int`/`on_fault` 接管陷入与故障。代价是"陷入内核"要多一层 Python 调用,
  换来的是 CPU 能脱离内核单测、依赖图无环。
- **终端 I/O 三条路而非一套 select**:一套 POSIX select 在 Windows 控制台上直接失效
  (敲键没反应)。分平台虽啰嗦,但这是让 Windows 交互与管道都能工作的唯一办法。
- **退出只认转义键**:raw 模式下宿主收不到 Ctrl-C(它归被仿真进程),所以仿 qemu
  用 Ctrl-A x,并在行规程之前拦截,保证 bash 关掉 ISIG 后仍能退出。

---

## 关键函数索引

| 环节 | 函数 / 位置 |
|---|---|
| 搭链 | `build_kernel` — emulator.py:25 |
| 命令行切分 | `split_argv` / `VALUE_OPTS` — emulator.py:51 / 47 |
| 主入口 | `main`(argparse + boot 分流 + finally 转储) — emulator.py:81 |
| 引导链(内核任务) | `boot_init` / `_init_step` / `_spawn` — kernel.py:994 / 1065 / 1033 |
| 收场判定 | `_console_alive` — kernel.py:1102 |
| 单程序装载 | `boot` — kernel.py:210 |
| 调度循环 | `run`(协作式 + icount 记账) — kernel.py:1163 |
| 挑进程 | `_pick` — kernel.py:1150 |
| CPU 工厂 / 回调 | `_make_cpu` / `_on_int` / `_on_fault` — kernel.py:279 / 245 |
| 转义键处理 | `on_escape` — kernel.py:1116 |
| 标准 fd | `_setup_std_fds` — kernel.py:228 |
| 宿主终端 | `HostTerminal`(raw/msvcrt/线程) — ktty.py:203 |
| 二进制输出 | `HostTerminal.write_out` — ktty.py:369 |
| 转义键拦截 | `TTY._strip_escapes` — ktty.py:434 |
| CPU 主循环 | `CPU.run` — cpu86.py:542 |
| 地址空间 | `AddressSpace` — x86mem.py:42 |
