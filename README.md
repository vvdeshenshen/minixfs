# minixfs — Minix v1 文件系统浏览器 + Linux 0.11 仿真器

两个工具, 共用同一个只读解析库:

1. **`minix_shell.py`** — Minix v1 文件系统浏览器(cd/ls/stat/inode/info/file/dump/
   less/checkfs)
2. **`emulator.py`** — Linux 0.11 用户态仿真器, **真正运行镜像里 1991 年的 a.out
   二进制**: 纯 Python 解释 i386 指令, 在 `int 0x80` 处实现 Linux 0.11 系统调用,
   带终端行规程与写入覆盖层(镜像永不被改动)。

```bash
# 完整引导: 内核 init() -> /etc/rc -> login shell
python3 emulator.py hdc-0.11.img
```
```
 Ok.                                   <- /etc/rc 跑完
[/usr/root]# echo hello                <- login shell(PS1 来自 /etc/profile)
hello
[/usr/root]# exit
logout
child 4 died with code 0000            <- init 的 while(1) 汇报, 同 main.c
```
```bash
# 直接跑单个程序(跳过引导)
python3 emulator.py hdc-0.11.img /bin/date
python3 emulator.py hdc-0.11.img /usr/bin/ls -l /etc

# 非交互(可脚本化)
printf 'echo hi | cat\nexit\n' | python3 emulator.py hdc-0.11.img
```
实测可用: 完整引导链、交互式 bash(回显/退格/管道/重定向)、`date`、`cat`、`ls -l`、
`head`、`basename`、`id`、shell 内建与 for 循环、`#!` 脚本。仿真器细节见下方
[Linux 0.11 仿真器](#linux-011-仿真器)一节。

### monitor 控制台

仿 qemu 的 `Ctrl-A` 前缀。**这也是退出仿真器的方式** —— 交互时宿主终端处于 raw
模式, `Ctrl-C` 会作为字节交给被仿真进程, 宿主收不到信号。

| 按键 | 作用 |
|------|------|
| `Ctrl-A c` | 进入 monitor 控制台 |
| `Ctrl-A x` | 退出仿真器 |
| `Ctrl-A a` | 给被仿真程序发一个真正的 `Ctrl-A` |
| `Ctrl-A ?` | 按键帮助 |

monitor 里可以查看仿真器内部状态:

```
(minix) ps
  PID  PPID  PGRP 状态             指令数  等待             程序
    1     0     1 睡眠         208,878  TTY            /bin/sh
(minix) info mem
    1              329.0KB    0x52400    512.0KB    841.0KB /bin/sh
(minix) info cpu
  eax=0x00000003  ...  eip=0x00039a42  eflags=0x0202 [-]
  eip 处字节: cd 80 85 c0 7d 0c f7 d8        <- int 0x80 + errno 处理
```

| 命令 | 说明 |
|------|------|
| `info procs` / `ps` | 进程表: pid/父/进程组/状态/已执行指令数/等待对象 |
| `info mem` | 各进程的代码+数据+堆、brk、栈与合计 |
| `info fs` | 覆盖层改动明细(**逐条列出路径**、变化类型、inode、大小)与底层镜像统计 |
| `info syscalls` | 系统调用次数排名 + 最近 10 次调用(常开, 不需要 `--trace`) |
| `info trace [n]` / `trace show [n]` | 翻看轨迹缓冲里最近 n 条调用(默认 30), 负返回值标出 errno 名 |
| `info cpu [pid]` / `regs` | 寄存器、标志位、eip 处的机器码字节 |
| `info fds [pid]` | 文件描述符表(inode/管道/终端、位置、引用数) |
| `info tty` | 终端与行规程状态、前台进程组、待读字节 |
| `kill <pid> [信号]` | 给被仿真进程发信号 |
| `trace on [容量]` | 放大轨迹缓冲以留更长历史(默认 5000 条) |
| `trace off` | 缩回默认容量(轨迹**始终在记**, 只是历史更短) |
| `cont` / `quit` | 继续仿真 / 停止仿真并退出 |

`info fs` 会把改动逐条列出来:

```
(minix) info fs
  被改动的文件 5 个, 被改动的目录 4 个, 新建 5 个, 已删除 1 个
  改动明细(10 项):
    变化        inode   大小  路径
    改过的目录     75   272B  /etc
    改过的文件     76    57B  /etc/rc
    已删除         79    11B  /etc/mtab
    新建        20670  2.9KB  /tmp/newfile
```

`--monitor` 可在启动后先进入 monitor; `--escape none` 关掉转义键(此时只能从
另一个终端 kill); `--trace` 放大轨迹缓冲并在退出时转储到 stderr。

**注意选项位置**: 程序名之后的一切都原样透传给被仿真程序(好让 `ls -l` 的 `-l`
不被吃掉), 所以仿真器自己的选项要写在程序名**之前**:
`emulator.py 镜像 --trace /bin/date`, 不是 `emulator.py 镜像 /bin/date --trace`。

---

## 文件系统浏览器

用 Python(纯标准库, 无外部依赖)实现的 Minix v1 文件系统解析库与交互式
浏览 shell, 可直接浏览 Linux 0.11 时代的真实磁盘镜像。仓库自带
`hdc-0.11.img`: 一个 63MB 的 Linux 0.11 硬盘镜像(带 MBR 分区表,
Minix 分区位于字节偏移 1024, magic 0x137F, 文件名上限 14 字符)。

## 快速开始

```bash
python3 minix_shell.py hdc-0.11.img
```

```
已加载 hdc-0.11.img (偏移 1024): 20666 inodes, 62000 zones, 文件名上限 14 字符
minix:/$ ls -l /bin
minix:/$ less /etc/rc
```

## 子命令

| 命令 | 说明 |
|------|------|
| `cd [路径]` / `pwd` | 切换/显示当前目录, 支持相对路径与 `..` |
| `ls [-l] [路径]...` | 列目录; `-l` 显示权限/链接数/属主/大小/时间, 设备节点显示主次设备号 |
| `stat [路径]...` | 文件元数据; **无参数**时显示全盘统计(inode/zone 用量与使用率) |
| `inode <编号>` | 按编号显示 inode 原始字段(mode/uid/gid/size/mtime/zone 指针) |
| `info <编号>` | inode 详情 + 遍历目录树列出引用它的全部目录项(可发现硬链接) |
| `file <路径>...` | 判定文件类型: 目录/设备/a.out 可执行/`#!` 脚本/gzip/文本/二进制 |
| `dump <路径> [偏移 [长度]]` | hexdump -C 风格十六进制转储 |
| `less <路径>` | 满屏分页查看; `j/k` 行, `f/b/n/p` 屏, `d/u` 半屏, `g/G` 首尾, `q` 退出, 支持方向键/PgUp/PgDn |
| `checkfs` | 全盘一致性检查(fsck): size 与数据块数、inode/zone 位图标记、重复引用、孤儿 inode 与丢失块 |

## 代码结构

```
minixfs.py       解析库(只读): 超级块/inode/目录/文件读取(直接块+一级/二级间接
                 块, 空洞补零)、MBR 分区自动探测、位图查询、check_fs 一致性检查
minix_shell.py   浏览器: 基于 cmd.Cmd 的交互层, 只做参数解析与格式化
pager.py         less 风格分页器, 终端尺寸/按键/输出均可注入

emulator.py      仿真器入口
cpu86.py         i386 用户态指令解释器
cpu_disasm.py    只读 Intel 反汇编器(单步调试用)
x86mem.py        双区平坦地址空间
kvfs.py          写入覆盖层(COW)、管道、设备表
kexec.py         a.out ZMAGIC 加载器与初始栈
ksyscall.py      系统调用表与常量
kernel.py        进程/fd/信号/调度
ktty.py          终端行规程与 termios
kmonitor.py      qemu 风格 monitor(含 gdb 风格单步调试)

test_*.py        636 个单元测试
```

单步调试(gdb 风格):

```bash
# 执行第 0 条前先停进 monitor, 然后 si 单步 / disas 反汇编 / x 查内存 / break 断点
python3 emulator.py hdc-0.11.img --debug /bin/date
# monitor 里也随时可用: si、disas [addr] [n]、x/NFU addr、break <addr>、until <addr>、
#                        info console(控制台输出)
```

深入文档(算法与代码流程, 见 [docs/](docs/)):

- [docs/emulator-overview.md](docs/emulator-overview.md) —— 仿真器总体架构与引导链(先读这篇)
- [docs/x86-decode-and-emulation.md](docs/x86-decode-and-emulation.md) —— CPU 指令解码与仿真
- [docs/kernel-process-and-scheduler.md](docs/kernel-process-and-scheduler.md) —— 进程/调度器/信号
- [docs/syscalls-and-loading.md](docs/syscalls-and-loading.md) —— 系统调用与 a.out 装载
- [docs/vfs-overlay-pipes-devices.md](docs/vfs-overlay-pipes-devices.md) —— 写时复制 VFS/管道/设备
- [docs/terminal-and-line-discipline.md](docs/terminal-and-line-discipline.md) —— 终端与行规程
- [docs/monitor-and-debugger.md](docs/monitor-and-debugger.md) —— monitor 与单步调试器
- [docs/minixfs-and-browser.md](docs/minixfs-and-browser.md) —— Minix v1 解析库与浏览器

## 测试

```bash
python3 -m unittest test_minixfs test_cpu86 test_kvfs test_kernel test_ktty
```

测试在内存中程序化构造迷你 minix 镜像(含子目录、设备节点、跨间接块
大文件、稀疏文件), 不依赖真实镜像; `hdc-0.11.img` 存在时会额外运行
集成测试。checkfs 测试通过直接篡改镜像字节注入十余种损坏场景。

## Linux 0.11 仿真器

**用户态仿真**: 只解释 ring-3 用户代码, 在 `int 0x80` 处陷出到 Python 实现的内核层,
不模拟 MMU/分页/GDT/中断/端口 I/O。镜像里的程序看不到硬件, 与外界的唯一通道就是
系统调用, 所以只要 ABI 一致, 程序无法区分下面是真内核还是 Python。

| 模块 | 职责 |
|------|------|
| `cpu86.py` | i386 解释器: ModRM/SIB 完整寻址、ALU 与 EFLAGS、乘除、移位、字符串指令(含 rep 与 DF 反向)、setcc/movzx/movsx、位操作、0x66 前缀 |
| `x86mem.py` | 双区平坦地址空间(低区 text+data+bss+堆, 高区栈自动增长), 空洞访问抛 SegFault |
| `kvfs.py` | inode 级写入覆盖层(COW), **镜像文件永不被修改**; 管道; 设备表 |
| `kexec.py` | a.out ZMAGIC 加载器 + `#!` shebang + 初始栈构造 |
| `ksyscall.py` / `kernel.py` | 系统调用表与实现、进程/fd 表、fork/execve/waitpid、信号、调度器、**内建 init** |
| `ktty.py` | 终端行规程(回显/退格/^C/^D)、termios ioctl、宿主终端与脚本化终端 |

### ABI 全部从镜像内部查证

镜像里带着 **`/usr/src/linux` 的内核 C 源码**与完整 `/usr/include`, 所以所有细节都是
读原文确认的, 而非凭记忆:

- 初始栈布局取自 `fs/exec.c` 的 `create_tables`: `[esp]=argc, +4=argv, +8=envp`
  (交叉验证: `/bin/date` 首条指令正是 `mov eax,[esp+8]` 取 envp)
- 用户地址空间 `0..0x4000000`(64MB), 栈顶 64MB, 参数区 128KB —— 来自 `change_ldt`
- `brk` **恒返回当前 brk**(不是 0 也不是 -errno) —— 来自 `kernel/sys.c`
- 信号帧 7/8 个长字 `restorer, signr, [blocked], eax, ecx, edx, eflags, old_eip`
  —— 来自 `kernel/signal.c` 的 `do_signal`; 0.11 **没有 sigreturn 系统调用**,
  返回靠 libc 的 restorer 在用户态弹栈
- 调用表 **87 项**: 这个镜像的内核是打过补丁的后期版本, 比经典 0.11 的 72 个多出
  `lstat/readlink/getrlimit` 等 —— 而镜像里的 libc 正好用到它们
- termios ioctl 码与结构布局来自内核 `include/termios.h`

### 已知限制

- **性能**: 纯 Python 解释, 约 0.4M 条指令/秒。`date` 不到 1 秒, bash 启动数秒,
  完整引导到登录 shell 要一两分钟。用 `pypy3` 运行可获数量级加速(零代码改动)。
- **平台**: Linux/macOS 与 Windows 都可用。Windows 下终端输入走 `msvcrt`
  (`select` 在 Windows 上只能用于 socket, 对控制台句柄无效), 管道输入走后台读取
  线程; 退格键 BS(0x08) 会翻译成 Unix 终端的 DEL(0x7F), 方向键等特殊键翻译成
  ANSI 转义序列, 并自动打开控制台的 VT 处理。
- **x87 浮点未实现**: 镜像 libc 是软浮点编译的(`fp.o`/`fp-interf.o`), 且 0.11 内核的
  `math_emulate` 本身就只是个发 SIGFPE 的桩, 故暂不需要。遇到 x87 指令会抛出带
  eip 与机器码字节的 `CpuError`。
- **引导链已实现且照内核原文**: Linux 0.11 的 init **不是磁盘上的程序**, 而是内核
  `init/main.c` 里的 `init()` 函数在用户态执行 —— 它 open `/dev/tty0`、fork 一个
  `sh` 以 `/etc/rc` 为 stdin 跑启动脚本, 然后在 `while(1)` 里反复以
  `argv[0] = "-/bin/sh"`(前导 `-` 使其成为 login shell, 会读 `/etc/profile`)起登录
  shell 并汇报子进程死亡。仿真器把这段逻辑实现为 Python 层的内核任务(`boot_init`)。
  镜像里那个 `/bin/init` 是后来某个软件包的东西, 不在 0.11 引导链上, 它要的
  `/etc/inittab` 这个镜像里也没有。

## 实现笔记(文件系统)

- 位图为字节顺序 + 字节内 LSB 在前的位序(与 x86 位指令一致), 位 0 保留。
- Minix v1 inode 仅 32 字节, 只有一个时间戳(mtime); 设备号存于 zones[0]。
- 老 mkfs 位图尾部填充存在差一问题, 对真实镜像跑 `checkfs` 会如实报告
  最后一个 inode "位图已分配但内容全零", 属于历史现象而非损坏。
- 镜像里 `/dev/null` 被误建成了**块**设备(应为字符设备), 故设备分派按
  (major, minor) 匹配而不检查 b/c 类型; `/dev/console` 与 `/etc/inittab` 干脆不存在。
