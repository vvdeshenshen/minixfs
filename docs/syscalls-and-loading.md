# 系统调用与可执行装载:算法与代码流程

本文整理仿真器的**内核门**是怎么工作的:用户程序执行 `int 0x80` 后,控制权
怎样从 CPU 层交到内核层、参数怎么取、号怎么分派、返回值怎么写回;以及一个
a.out 程序从磁盘上的 inode 变成一块可执行的 64MB 地址空间、一根摆好初始栈的
执行流的全过程。两个主角文件是 **ksyscall.py**(调用号表 + 分派 + struct stat
打包)与 **kexec.py**(a.out 装载器 + 初始栈构造),具体每个系统调用的实现体
都是 `kernel.py` 里的 `Kernel.sys_*` 方法。

> ABI 细节一律从镜像内部的内核 C 源码(`/usr/src/linux`)与 `/usr/include`
> 查证,不凭记忆:调用表、初始栈布局、brk 语义、信号帧长字数、struct stat
> 字段宽度都据此确定。下文所有引用都标了 `文件:行`。

> 阅读顺序建议:先看第 1 节 int 0x80 的门,再看第 2 节分派表,第 3 节各调用族
> 是细节展开;第 4 节起是可执行装载。第 8、9 节是两条完整走查。

---

## 1. int 0x80:用户态与内核态的唯一门

Linux 0.11 的系统调用就是软中断 `int 0x80`。CPU 层执行到 `CD 80` 时,若注入了
`on_int` 回调就上调内核(cpu86.py 的 `int` 处理),否则 `halted`。内核挂进去的
回调是 `Kernel._on_int`(kernel.py:245):

```python
def _on_int(self, cpu, vec):
    if vec != 0x80:
        return
    p = self.current
    regs = cpu.regs
    nr, a, b, c = regs[0], regs[3], regs[1], regs[2]   # eax, ebx, ecx, edx
    try:
        ret = self.syscalls.dispatch(p, nr, a, b, c)
    except FsError as e:   ret = -e.errno
    except ExecError as e: ret = -e.errno
    except SegFault:       ret = -kvfs.EFAULT
    self._on_int_stats(p, nr, a, b, c, ret)
    regs[0] = ret & 0xFFFFFFFF
```

**ABI 约定**(ksyscall.py:1-8 的模块注释,照镜像内核):

| 寄存器 | 角色 |
|---|---|
| `eax` | 系统调用号(`regs[0]`) |
| `ebx` | 第一参(`regs[3]`) |
| `ecx` | 第二参(`regs[1]`) |
| `edx` | 第三参(`regs[2]`) |
| `eax`(返回) | 返回值:`>=0` 成功,负值即 `-errno`,`& 0xFFFFFFFF` 后写回 |

注意通用寄存器下标不是 x86 的编码顺序:`regs[0]=EAX regs[1]=ECX regs[2]=EDX
regs[3]=EBX`(cpu86.py 的 `REG32_NAMES`),所以 `_on_int` 里取 `ebx` 是 `regs[3]`。
0.11 的系统调用最多三个寄存器参数;更多参数的调用(如 `select`)靠一个指向参数
块的指针传,这个镜像的 libc 没走到需要第四第五参的路径。

**错误的统一收口**:内核层用 Python 异常表达失败——`FsError`(文件系统)与
`ExecError`(装载)都带 `errno` 字段,在 `_on_int` 里被翻成 `-errno`;访存越界的
`SegFault` 翻成 `-EFAULT`(kernel.py:253-258)。于是各 `sys_*` 方法既能 `return
-EINVAL` 这样直接返回负值,也能 `raise FsError(ENOENT)`,两条路都汇到 `eax`。

**轨迹与统计**:返回前 `_on_int_stats`(kernel.py:262)把 `(pid, nr, a, b, c, ret)`
压进 `recent_syscalls` 环形缓冲、给 `syscall_counts` 与进程自己的计数各加一。
系统调用相对指令数极稀疏(几千 vs 几百万),所以统计常开,不必等 `--trace`;
容量由 `set_trace_capacity`(kernel.py:273)调。

**87 项调用表从镜像查证**:调用号照镜像内核 `include/linux/sys.h` 的
`sys_call_table` 顺序,`NR_SETUP..NR_USELIB` 共 87 个(ksyscall.py:17-35),
`NR_SYSCALLS = 87`。这个镜像的内核是打过补丁的后期版本,比经典 0.11 的 72 个多
出 `sigsuspend/setrlimit/getrlimit/lstat/readlink` 等,而镜像里的 libc 正好用到
它们(bash 的 `ulimit` 用 75/76,`ls -l` 用 84/85)。

---

## 2. 分派:SyscallTable(ksyscall.py:69)

`SyscallTable` 只做一件事:把调用号映射到一个 `Kernel.sys_*` 绑定方法。构造时
`_register`(ksyscall.py:77)一次性填好 `handlers` 字典,分三批(进程与文件、
多进程与管道、信号与会话)注册。分派逻辑极短(ksyscall.py:154):

```python
def dispatch(self, proc, nr, a, b, c):
    if nr >= NR_SYSCALLS:          # 越界 -> 内核 bad_sys_call
        return -ENOSYS
    fn = self.handlers.get(nr)
    if fn is None:                 # 号合法但本仿真器未实现
        return -ENOSYS
    return fn(proc, a, b, c)
```

要点:

- **两种 ENOSYS**:号 `>= 87` 是内核层面的非法调用;号合法但没进 `handlers`
  (如 `ptrace/acct/uselib`)也返回 `-ENOSYS`。二者对用户程序表现一致。
- **别名**:`NR_LSTAT` 直接指向 `k.sys_stat`(ksyscall.py:126)——minix v1 没有
  符号链接,`lstat` 等价 `stat`。`NR_DUP2` 在字典里出现两次(63、139),后者覆盖
  前者,值相同,无害。
- **阻塞不是返回值,而是异常**:处理函数若发现调用无法立即完成(管道空、等子进程、
  `pause`),抛 `Blocked(channel)`(ksyscall.py:58)。它不经过 `dispatch` 的返回
  路径,而是穿过 `_on_int`(不被那里的 `except` 捕获)一路抛到调度器,由调度器
  让进程睡在 `channel` 上,并把 `eip -= 2` 回卷(`CD 80` 两字节),唤醒后整条系统
  调用**重做**(kernel.py:1225-1229)。这就是为什么阻塞型调用的处理函数必须写成
  可重入的——它可能被完整地跑第二遍。
- **execve 也走异常**:`sys_execve` 成功时抛 `Replaced`(见第 3.1、9 节),因为它
  换掉了进程的 CPU 与内存,旧的 `cpu.run()` 循环必须被打断。

---

## 3. 关键系统调用族的实现要点

处理体都在 `kernel.py`。这里只讲**算法上值得注意**的地方,琐碎的置字段略过。

### 3.1 进程族

| 调用 | 实现 | 要点 |
|---|---|---|
| `fork` (2) | kernel.py:777 | 克隆地址空间(`mem.clone()`,写时不共享),复制 fd 表**但指向同一 `OpenFile`**(共享文件位置,是 `sh > file` 重定向的根基),新 CPU `restore(parent.snapshot())` 后把子进程 `eax` 置 0;返回子 pid |
| `execve` (11) | kernel.py:751 | 见第 4-7 节;成功抛 `Replaced` |
| `waitpid` (7) | kernel.py:805 | 按 `pid` 的正/零/负选候选子进程;有僵尸则写回状态字、累计 cutime/cstime、回收;`WNOHANG` 返回 0;否则 `raise Blocked(("wait", pid))` |
| `exit` (1) | kernel.py:341 | `raise Exited((code & 0xFF) << 8)`,由调度器落实为僵尸 |
| `getpid/getppid/getuid...` | kernel.py:344+ | 直接读进程字段 |
| `brk` (45) | kernel.py:479 | **恒返回当前 brk,从不返回 -errno** |

**brk 的语义**照镜像 `kernel/sys.c`(kernel.py:479 → x86mem.py:67 `set_brk`):
参数是想要的新 brk 地址,合法(落在 `[text_end, start_stack - 16384)` 之间,
即与栈保留 16KB 保护间隙 `BRK_STACK_GAP`)则更新并按需向上扩展 bss 区,**无论
成败都返回更新后的当前 brk**。libc 的 `sbrk` 靠"调用后比较返回值和期望值"判断
成败,内核自己不报错。

### 3.2 文件族

| 调用 | 实现 | 要点 |
|---|---|---|
| `open` (5) | kernel.py:579 | 路径 walk;`O_CREAT` 处理 ENOENT;`O_EXCL`、`O_TRUNC`、`O_APPEND`;设备节点转 `_open_device` 按 (major,minor) 分派(不检查 b/c 类型,因镜像 `/dev/null` 被误建为块设备) |
| `read` (3) | kernel.py:676 | VInode 走 `fs.read`;Pipe 空则 `Blocked(("piperead",obj))`;终端无数据则 `Blocked(obj)`;`/dev/null` 恒返回 0(EOF) |
| `write` (4) | kernel.py:700 | 对称:VInode/Pipe(满则 `Blocked`)/NullDevice(吞掉)/终端 |
| `lseek` (19) | kernel.py:721 | 仅 VInode(否则 `-ESPIPE`);offset 按有符号解释;SET/CUR/END |
| `stat/lstat` (18/84) | kernel.py:528 | walk 后 `_write_stat` |
| `fstat` (28) | kernel.py:531 | fd 指向 VInode 则真 stat,管道/终端造假 stat 让 stdio 的 `isatty`/缓冲判断能过 |
| `readlink` (85) | kernel.py:541 | 恒 `-EINVAL`(minix v1 无符号链接) |
| `dup/dup2` (41/63) | kernel.py:631/638 | `_acquire_fd` 增描述符计数;dup2 先关旧 newfd |
| `pipe` (42) | kernel.py:888 | 建 `Pipe`,分配读/写两个 fd |
| `ioctl` (54) | kernel.py:742 | 仅终端对象转 `terminal.ioctl`(termios/窗口尺寸),否则 `-ENOTTY`(`isatty` 靠它判断) |
| `fcntl` (55) | kernel.py:651 | F_DUPFD / F_GETFD / F_SETFD(close-on-exec 位)/ F_GETFL / F_SETFL |

**struct stat 逐字段拷 32 位**:打包格式 `STAT_FMT`(ksyscall.py:43)是 32 字节,
字段宽度取自镜像 `/usr/include/sys/types.h`——`dev_t/ino_t/umode_t/uid_t` 是 u16,
`nlink_t/gid_t` 是 u8,`off_t/time_t` 是 32 位。`pack_stat`(ksyscall.py:46)把
size 与三个时间字段**按无符号截断**打包,因为内核 `cp_stat` 是 `put_fs_long` 逐
字段原样拷 32 位、由程序自己解释符号;镜像里 `/etc/mtab` 的 mtime 就超出了有符号
i32 范围,只有按无符号打包才与真机一致(与内核 `cp_stat` 逐字段拷 32 位吻合)。

### 3.3 信号族

0.11 **没有 sigreturn 系统调用**,这决定了信号的实现形状。

- `signal` (48) 是**三参**(kernel.py:1394):`ebx=signum, ecx=handler,
  edx=restorer`。0.11 的 `signal` 语义是 `SA_ONESHOT | SA_NOMASK`,存进
  `sigactions[sig]` 并返回旧 handler。**edx 是 sa_restorer**——libc 提供的用户态
  弹栈桩,信号处理返回时靠它恢复上下文。
- `sigaction` (67) 读/写四个长字 `(handler, mask, flags, restorer)`(kernel.py:1402)。
- `kill` (37) 按 pid 正/零/负选目标,`post_signal` 投递(kernel.py:941)。
- `alarm` (27) 换算 jiffies,返回上次剩余秒数(kernel.py:987)。
- `pause` (29) 直接 `raise Blocked(("pause", pid))`(kernel.py:969)。

**信号帧的构造**在 `_build_signal_frame`(kernel.py:1359),布局照内核
`kernel/signal.c` 的 `do_signal`:在用户栈上从高到低压 **7 或 8 个长字**——
`SA_NOMASK` 时 7 个,否则多压一个旧 blocked 掩码。压栈顺序(先压的在高地址):

```
old_eip, eflags, edx, ecx, eax, [blocked,] signr, sa_restorer   ← esp 指向 restorer
```

然后把 `eip` 改成 handler。handler `ret` 时弹到 `sa_restorer`,由它在用户态弹掉
其余字并跳回 `old_eip`。**当 restorer 为 0** 时,压的是 `MAGIC_SIGRETURN`
(`0xFFFF0000`,kernel.py:51、1388);执行流跳到那个魔数地址会让 `step()` 抛
`MagicJump`,由调度器 `_sigreturn`(kernel.py:1283)手工弹帧兜底。帧里有没有
blocked 无法从栈上看出,所以压帧时把这个布尔记在 `p.sigframes` 里(kernel.py:1386)。

### 3.4 时间及其它

| 调用 | 实现 | 要点 |
|---|---|---|
| `time` (13) | kernel.py:415 | `int(time.time()) + time_offset`,可选写回 `*tloc` |
| `stime` (25) | kernel.py:421 | 仅 root;调 `time_offset` |
| `gettimeofday` (78) | kernel.py:427 | 秒 + 微秒 |
| `times` (43) | kernel.py:437 | 写 utime/stime/cutime/cstime,返回 jiffies |
| `uname` (59) | kernel.py:443 | 写 `UTSNAME_FIELDS`(每字段 9 字节) |
| `getrlimit` (76) | kernel.py:468 | 恒填 `0x7FFFFFFF`(无限),返回 0 |
| `setrlimit` (75) | kernel.py:474 | 空实现返回 0 |
| `ulimit` (58) | kernel.py:465 | `-ENOSYS`(bash 探测后退回 getrlimit) |

---

## 4. 可执行装载总览(kexec.py)

`execve` 要把磁盘上的一个 a.out 文件变成"能从 entry 跑起来的地址空间 + 摆好的
初始栈",分四步,每步一个函数:

```
resolve_exec  路径解析 + #! 脚本重写 argv        → (VInode, argv)
load_aout     校验 a.out 头, text/data 装入内存, bss 补零   → (entry, brk)
setup_stack   照 create_tables 摆 argc/argv/envp/字符串区   → esp
(kernel)      eip=entry, esp, 复位 fd/信号, raise Replaced
```

格式与布局全部照镜像里的内核源码 `fs/exec.c`(kexec.py 模块注释)。

---

## 5. a.out 头与 load_aout(kexec.py:38, 81)

`AoutHeader`(kexec.py:38)解析头 32 字节的 8 个小端 u32:
`magic, text, data, bss, syms, entry, trsize, drsize`。`validate`(kexec.py:50)
照内核 `do_execve` 的校验:

- `magic` 必须是 **ZMAGIC**(`0o413`),否则 `ENOEXEC`——这个镜像只跑 ZMAGIC 分页
  可执行文件,OMAGIC/NMAGIC/QMAGIC 只有常量、不接受。
- `trsize == drsize == 0`,带重定位信息拒绝。
- `text + data + bss <= 0x3000000`(48MB 上限 `MAX_TOTAL`)。
- 文件长度 `>= text + data + syms + N_TXTOFF`。

`load_aout`(kexec.py:81)的装载算法:

1. 校验 VInode 是普通文件且有执行权限位(`mode & 0o111`),否则 `EACCES`。
2. 从文件偏移 **`N_TXTOFF = 1024`**(`= BLOCK_SIZE`,ZMAGIC 的代码起始)读
   `text + data` 字节;读不满则补零(kexec.py:90)。
3. `mem.load_program(text, data, bss)`(x86mem.py:60):`text` 装到虚址 0,紧跟
   `data`,再 `bss` 个零字节;`text_end = len(text)`,`brk = text+data+bss`。
4. 返回 `(entry, brk)`。

于是低区内存布局是 `[0, text_end) text` + `[text_end, ...) data` + `bss`,连续
一块,brk 落在末尾——与真实内核的 ZMAGIC 布局一致。

---

## 6. 路径解析与 shebang(kexec.py:66, 148)

`resolve_exec`(kexec.py:148)先 `fs.walk` 定位文件、确认是普通文件,再读前 128
字节交给 `parse_shebang`(kexec.py:66):

- 不以 `#!` 开头 → 返回原 `(VInode, argv)`,直接去装载。
- 是脚本 → 解出 `(解释器, 可选单参)`,把 argv **重组**为
  `[interp, arg?, script_path, *argv[1:]]`,然后**递归**用解释器路径再
  `resolve_exec`(处理解释器本身也是脚本的情况),`depth > 4` 抛 `ENOEXEC` 防死循环。

例:执行 `foo.sh a b`,`foo.sh` 首行 `#!/bin/sh`,重组后实际装载 `/bin/sh`,
argv 变成 `["/bin/sh", "foo.sh", "a", "b"]`——这正是内核 `sh_bang/restart_interp`
的行为。

---

## 7. 初始栈:setup_stack 与 create_tables 布局(kexec.py:96)

`setup_stack`(kexec.py:96)照内核 `fs/exec.c` 的 `create_tables` 摆栈。从栈顶
`TASK_SIZE`(`0x4000000`,64MB,x86mem.py:18)向下:

1. 先把 **env 与 arg 的字符串**逐个拷到高地址区(内核先 env 后 arg,自顶向下),
   记下每个串的地址;参数区总长超过 `ARG_AREA` 抛 `E2BIG`(kexec.py:105-107)。
2. 指针 `p` 4 字节对齐(`& 0xFFFFFFFC`)。
3. 依次向下留出 **envp 指针数组(带结尾 NULL)**、**argv 指针数组(带结尾 NULL)**
   的空间,记下两个数组的基址。
4. 再向下压三个字:`envp` 基址、`argv` 基址、`argc`。**esp 最终指向 argc**。
5. 回填两个指针数组:每个槽写对应字符串地址,末槽写 0。
6. `mem.start_stack = sp & 0xFFFFF000`,返回 `sp`。

栈从高到低的最终形貌:

```
TASK_SIZE ─┐
           │  env 字符串区 …\0
           │  arg 字符串区 …\0
           │  (对齐填充)
           │  envp[]: e0 e1 … NULL
           │  argv[]: a0 a1 … NULL
           │  envp_base  ┐
           │  argv_base  ├─ 三个字
esp ─────► │  argc       ┘
```

这个布局已被 `/bin/date` 入口的 `mov eax,[esp+8]`(取 envp)佐证
(kexec.py:103 注释):`[esp]=argc, [esp+4]=argv, [esp+8]=envp`,C 运行时据此
接 `main(argc, argv, envp)`。

内核把这套值装进进程后(kernel.py:751 的 `sys_execve`):`p.mem = 新 mem`、
`p.cpu = _make_cpu(...)`、`cpu.eip = entry`、`cpu.regs[4] = esp`(ESP),复位
close-on-exec 的 fd 与信号处置(SIG_IGN 保留,其余复位 SIG_DFL),清空 `sigframes`,
最后 `raise Replaced()`。

---

## 8. 走查一:write(1, buf, n)

用户程序要打印一行,libc 生成 `int 0x80`,`eax=4(write) ebx=1(fd) ecx=buf edx=n`:

1. CPU 执行 `CD 80`,调 `on_int(cpu, 0x80)` → `Kernel._on_int`(kernel.py:245)。
2. `_on_int` 取 `nr=regs[0]=4, a=regs[3]=1, b=regs[1]=buf, c=regs[2]=n`。
3. `syscalls.dispatch(p, 4, 1, buf, n)`(ksyscall.py:154):`4 < 87`,查表得
   `k.sys_write`,调 `sys_write(p, 1, buf, n)`。
4. `sys_write`(kernel.py:700):`f = p.get_file(1)`;`data = p.mem.read(buf, n)`
   从用户内存把 n 字节读出来;`f.obj` 是终端对象 → `return obj.write(data)`,
   返回实际写出的字节数 `n`。
5. 回到 `_on_int`:`ret = n`(非负,成功);`_on_int_stats` 记一笔轨迹;
   `regs[0] = n & 0xFFFFFFFF`——返回值写回 eax。
6. CPU 继续下一条指令,libc 看到 `eax = n`,`write` 返回 n。

若 fd 是写满的管道,第 4 步 `obj.write` 返回 None → `raise Blocked(("pipewrite",
obj))`;异常穿过 `_on_int` 到调度器(kernel.py:1225),进程睡下、`eip -= 2` 回卷,
读端腾出空间后唤醒,**整条 write 重做**。

## 9. 走查二:execve("/bin/sh", argv, envp)

1. `int 0x80`,`eax=11 ebx=路径 ecx=argv指针 edx=envp指针` → `_on_int` →
   `dispatch` → `sys_execve(p, path, argvp, envpp)`(kernel.py:751)。
2. `_cstr` 读出路径字符串;`_read_ptr_array` 把 `char*[]` 读成 `list[bytes]`。
3. `resolve_exec`(kexec.py:148):walk 到 `/bin/sh`,读头 128 字节,`parse_shebang`
   返回 None(是真二进制),得到 `(VInode, argv)`。
4. 新建一个空 `AddressSpace()`;`load_aout`(kexec.py:81):校验 ZMAGIC 头、从偏移
   1024 读 text+data 装入、bss 补零,返回 `(entry, brk)`。
5. `setup_stack`(kexec.py:96):按 `create_tables` 摆 argv/envp/字符串区,返回 esp。
6. 装进进程:`p.mem = mem`、`p.cpu = _make_cpu(mem, p)`、`cpu.eip = entry`、
   `cpu.regs[4] = esp`;关掉 close-on-exec 的 fd,信号处置复位,`sigframes.clear()`。
7. `raise Replaced()`(kernel.py:773)。这个异常穿过 `_on_int`,一路到调度器
   (kernel.py:1217)。**为什么必须抛异常**:此刻旧 `cpu.run()` 的 Python 调用栈还在
   `_on_int` 下面,而旧 CPU 持有的是**已经被替换掉的失效内存**;不抛异常就会返回到
   旧循环继续用旧 mem 取指。`Replaced` 打断它,调度器下一轮直接跑新 CPU。
8. 下一时间片,调度器 `cpu.run()` 从新 `entry` 开始执行 `/bin/sh` 的第一条指令,
   栈上 argc/argv/envp 已就位。

---

## 设计取舍

- **异常表达非局部控制流**:`Blocked`(睡眠)、`Replaced`(execve 换心)、`Exited`
  (退出)都用 Python 异常穿过 `_on_int` 抛到调度器,而不是靠返回值层层上报。好处
  是各 `sys_*` 处理体写起来是直线代码,坏处是必须记住"哪些异常不能被 `_on_int` 的
  `except` 吃掉"——那里只捕获 `FsError/ExecError/SegFault` 这三类**能翻成 errno**的,
  控制流异常一律放行。
- **阻塞 = 回卷重做,而非续跑**:睡眠的系统调用被完整地跑第二遍(`eip -= 2`),
  所以处理体必须可重入(不能在抛 `Blocked` 前留下副作用)。代价是重算一遍参数,
  换来的是不用在内核里保存"调用进行到一半"的续点状态,和真实 0.11 的 `int 0x80`
  重启语义一致。
- **stat 逐字段拷 32 位、按无符号打包**:不追求 POSIX 的 struct stat 语义,而是
  照内核 `cp_stat` 原样拷 32 位、由用户程序解释符号——这样才能容下镜像里 mtime
  超 i32 的 `/etc/mtab`,与真机字节级一致。
- **只认 ZMAGIC**:OMAGIC/NMAGIC/QMAGIC 只留常量不实现,遇到就 `ENOEXEC`。这个
  镜像的可执行文件全是 ZMAGIC,不为用不到的格式增加分支。
- **shebang 递归解析,深度设限**:`resolve_exec` 递归处理"解释器又是脚本",靠
  `depth > 4` 防环,而不是维护一个显式的解释器链栈——简单且够用。
- **ENOSYS 分两种但对用户一致**:号越界与"号合法但没实现"都返回 `-ENOSYS`,
  实现上是两条分支(越界 vs 字典 miss),对用户程序无差别,便于逐步补齐调用表而不
  改变对外行为。

---

## 附:关键函数索引

| 环节 | 函数 | 位置 |
|---|---|---|
| int 0x80 回调 | `Kernel._on_int` | kernel.py:245 |
| 轨迹/统计 | `_on_int_stats` / `set_trace_capacity` | kernel.py:262 / 273 |
| 分派表 | `SyscallTable._register` / `dispatch` | ksyscall.py:77 / 154 |
| 调用号常量 | `NR_*` / `NR_SYSCALLS` | ksyscall.py:17-35 |
| struct stat | `STAT_FMT` / `pack_stat` | ksyscall.py:43 / 46 |
| 阻塞异常 | `Blocked` | ksyscall.py:58 |
| fork | `sys_fork` | kernel.py:777 |
| execve | `sys_execve`(抛 `Replaced`) | kernel.py:751 / 156 |
| waitpid | `sys_waitpid` | kernel.py:805 |
| brk | `sys_brk` / `AddressSpace.set_brk` | kernel.py:479 / x86mem.py:67 |
| read/write | `sys_read` / `sys_write` | kernel.py:676 / 700 |
| stat 写回 | `_write_stat` | kernel.py:524 |
| 信号注册 | `sys_signal` / `sys_sigaction` | kernel.py:1394 / 1402 |
| 信号帧 | `_build_signal_frame` / `_sigreturn` | kernel.py:1359 / 1283 |
| a.out 头 | `AoutHeader` / `validate` | kexec.py:38 / 50 |
| shebang | `parse_shebang` | kexec.py:66 |
| 装载 | `load_aout` / `AddressSpace.load_program` | kexec.py:81 / x86mem.py:60 |
| 初始栈 | `setup_stack` | kexec.py:96 |
| 路径+脚本解析 | `resolve_exec` | kexec.py:148 |
| 调度器异常臂 | `Kernel.run`(Exited/Replaced/MagicJump/Blocked) | kernel.py:1211-1233 |
