# 终端与行规程:算法与代码流程

本文整理仿真器终端层(`ktty.py`)是怎样在**宿主真实终端**与**被仿真的 Linux 0.11
用户程序**之间当一根 tty 的:一边把宿主敲进来的字节做行编辑、回显、信号翻译,
攒成"行"交给程序 `read`;另一边把程序写出的字节做 OPOST/ONLCR 展开再吐给宿主。
中间还要拦住 `Ctrl-A x` 之类的转义键,并把 termios/窗口大小/前台进程组这些
`ioctl` 伺候好。只覆盖**一根受控终端**(镜像无 `/dev/console`、无多虚拟终端)。

> 阅读顺序:先看第 1 节的分层与三个对象,再看第 3 节输入侧的 feed/pump 主线
> (行规程的心脏),其余小节是各环节展开。所有引用都标了 `文件:行`。

---

## 1. 分层:一根逻辑行规程 + 一个可注入后端

沿用 `pager.py` 的"逻辑与 I/O 分离、后端可注入"哲学(ktty.py:3-8),终端拆成
三个对象,依赖单向:

```
TTY(行规程, 纯逻辑, 可测)  ──持有──▶  Terminal 后端(可注入)
                                        ├─ HostTerminal      宿主 stdin/stdout(分平台)
                                        └─ ScriptedTerminal  测试用(预置输入/捕获输出)
```

| 对象 | 职责 | 位置 |
|---|---|---|
| `Termios` | termios 状态(iflag/oflag/cflag/lflag/c_cc)与其 struct 打包/解包 | ktty.py:76 |
| `TTY` | 行规程本体:回显、行编辑、信号字符、缓冲、`read`/`write`、`ioctl` | ktty.py:387 |
| `HostTerminal` | 宿主终端后端:raw 模式、按平台读键、二进制写出 | ktty.py:203 |
| `ScriptedTerminal` | 测试后端:`pending` 队列供输入,`out` 收集输出 | ktty.py:110 |

内核只持有一个 `TTY` 实例(`k.terminal`),进程 0/1/2 号 fd 都是包着它的
`OpenFile`(kernel.py:236-237)。装配在 `build_kernel`:先建后端,再
`TTY(term, escape=..., on_escape=k.on_escape)`,回填 `k.terminal`(emulator.py:35-41)。

**后端接口**(TTY 只依赖这几个方法,故 Scripted 与 Host 可互换):
`poll_input()`(非阻塞取字节)、`wait_input(timeout)`(阻塞取字节)、
`write_out(bytes)`、`size()→(rows,cols)`、`is_tty()`、`restore/suspend/resume`,
外加可选属性 `at_eof`。

---

## 2. Termios 模型(ktty.py:19-107)

### 2.1 四个标志字 + c_cc

termios 是"四组开关位 + 一张控制字符表"。默认值在 `Termios.__init__`
(ktty.py:77-83),照抄内核 `INIT_C_CC` 与初始 termios:

| 组 | 默认位 | 本层真正用到的位与语义 |
|---|---|---|
| `iflag` 输入 | `ICRNL BRKINT IXON` | **ICRNL**:输入 CR(13)→LF(10)(ktty.py:460) |
| `oflag` 输出 | `OPOST ONLCR` | **OPOST+ONLCR**:输出 `\n`→`\r\n`(ktty.py:543) |
| `cflag` 控制 | `CS8 CREAD B9600` | 纯占位,本层不据此改行为(无真串口) |
| `lflag` 本地 | `ISIG ICANON ECHO ECHOE ECHOK ECHOCTL ECHOKE` | 见下 |

`lflag` 各位的作用(ktty.py:37-39 定义,`_feed_cooked`/`_echo` 消费):

| 位 | 值 | 作用 |
|---|---|---|
| `ISIG` | 0o1 | 认 VINTR/VQUIT/VSUSP 三个信号字符,翻成信号(ktty.py:462) |
| `ICANON` | 0o2 | 规范模式:攒行、行编辑;关掉则字符一到即可读(ktty.py:457,477) |
| `ECHO` | 0o10 | 回显开关(ktty.py:507) |
| `ECHOE` | 0o20 | VERASE 用退格擦除法 `\b \b` 回显(ktty.py:484) |
| `ECHOCTL` | 0o1000 | 控制字符回显成 `^X`(ktty.py:511) |

### 2.2 c_cc:控制字符表(ktty.py:41-73)

`NCCS=17`,下标名 `VINTR/VQUIT/VERASE/VKILL/VEOF/VTIME/VMIN/...`(ktty.py:43-44)。
`default_cc()` 填内核默认:`VINTR=^C(3)`、`VQUIT=^\(28)`、`VERASE=DEL(127)`、
`VKILL=^U(21)`、`VEOF=^D(4)`、`VSUSP=^Z(26)` 等。注意 **VERASE 默认是 DEL(127)
不是退格 BS(8)**——这正是 Windows 后端要 `translate_windows_key` 把 BS 翻成 DEL
的原因(见第 6 节)。

### 2.3 struct 布局(从镜像 include/termios.h 查证)

ioctl 请求码(ktty.py:20-28)与两种 struct 布局都取自镜像内核头文件:

- `TERMIOS_FMT = "<4LB17s"`(ktty.py:50):4 个 u32 标志字 + `c_line`(u8)+
  `c_cc[17]` = 34 字节,给 `TCGETS/TCSETS` 族用。
- `TERMIO_FMT = "<4HB8s"`(ktty.py:51):老 SysV `struct termio`,4 个 **u16** +
  `c_line` + `c_cc[8]`,给 `TCGETA/TCSETA` 族用。升格回 termios 时**只覆盖低 16 位
  与前 8 个 c_cc**,与内核一致(ktty.py:100-107)。
- `WINSIZE_FMT = "<4H"`(ktty.py:52):`ws_row/ws_col/ws_xpixel/ws_ypixel`。

---

## 3. 输入侧:pump / feed / 行规程主线

一个字节从宿主到程序 `read` 的完整链路:

```
宿主键盘 ─▶ 后端 poll/wait_input ─▶ TTY.pump ─▶ TTY.feed
                                                   │
                              _strip_escapes(拦转义键, 在行规程之前)
                                                   ▼
                                            _feed_cooked(行规程)
                       ┌───────────── canon? ─────────────┐
                    非规范(raw)                          规范(canon)
                  字节直入 self.ready                ICRNL→ISIG→行编辑→攒行
                                                   提交时整行倒进 self.ready
                                                   ▼
                                     程序 sys_read ─▶ TTY.read 从 ready 取
```

### 3.1 `pump(timeout)`:抽宿主输入(ktty.py:413)

```python
def pump(self, timeout=0.0):
    data = self.term.wait_input(timeout) if timeout > 0 else self.term.poll_input()
    if data:
        self.feed(data)
    elif getattr(self.term, "at_eof", False) and not self.ready:
        self.eof_pending = True
```

`timeout>0` 时**阻塞等**(调度器发现全员睡眠时用,kernel.py:1191 传 0.02),
否则非阻塞轮询。**读到的字节必须交给 `feed`**——注释特别记了个坑:早期版本
在空闲分支里直接 `term.wait_input()` 把输入读走丢弃,交互模式下敲键毫无反应
(ktty.py:414-419)。管道读到 EOF 且 `ready` 已空时置 `eof_pending`。

### 3.2 `feed`:先拦转义键,再进行规程(ktty.py:427)

```python
def feed(self, data):
    if self.on_escape is not None:
        data = self._strip_escapes(data)   # 抽掉 Ctrl-A 序列
        if not data:
            return
    self._feed_cooked(data)
```

**转义键在行规程之前拦截**,这是刻意的(见第 5 节):即便被仿真程序把 termios
的 ICANON/ISIG 全关了(bash/readline 就会),`Ctrl-A x` 也照样能退出。

### 3.3 `_feed_cooked`:规范/非规范处理(ktty.py:455)

逐字节走一条固定优先级的判定链(顺序即优先级):

1. **ICRNL**:`iflag & ICRNL` 且字节是 CR(13)→ 就地改成 LF(10)(ktty.py:460)。
2. **ISIG**(三个信号字符,ktty.py:462-476):
   - `VINTR`(^C):回显 `^C` → **清空输入缓冲** `_flush_input` → `post_signal(pgrp,
     SIGINT)`,发给**前台进程组**;
   - `VQUIT`(^\):同上,发 SIGQUIT;
   - `VSUSP`(^Z):回显 → 发 SIGTSTP(不清缓冲)。
3. **非规范**(`not ICANON`,ktty.py:477-480):字节**直接进 `self.ready`** 并回显,
   一到就可读(VMIN=1 语义的近似)。bash 关掉 ICANON 后走这条。
4. **规范模式行编辑**:
   - `VERASE`(退格,ktty.py:481):`line` 非空则弹一字节,`ECHOE` 时写 `\b \b`
     (退一格、盖空格、再退一格)把屏幕上那个字符擦掉;
   - `VKILL`(^U,ktty.py:487):擦掉整行(逐字符 `\b \b`)并清 `line`;
   - `VEOF`(^D,ktty.py:492):`line` 有内容就把当前(未回车的)行提交进 `ready`
     (于是 `read` 返回不足一行的数据);`line` 空则置 `eof_pending`(程序 read 得 0);
   - 普通字符(ktty.py:499-503):回显、追加进 `line`;若是 `\n`(或配了 VEOL 且命中),
     把整行 `line` 倒进 `ready` 并清空 `line`——**这一步就是"行提交"**。

### 3.4 回显 `_echo` / `_echo_ctl`(ktty.py:505-518)

`ECHO` 关就不回显。`\n` 原样回显;控制字符(<32)在 `ECHOCTL` 下回显成
`^` + `(ch+64)`(如 ^C);其余原样。`_echo_ctl` 专给信号字符用,要求 `ECHO` 与
`ECHOCTL` 同时置位才回显 `^X`。

### 3.5 三个缓冲与 `read` 的阻塞语义(ktty.py:397-399, 525)

| 缓冲 | 含义 |
|---|---|
| `self.line` | 正在编辑、尚未提交的当前行 |
| `self.ready` | 已提交、待 `read` 取走的字节 |
| `self.eof_pending` | 收到 EOF(^D 空行 / 管道读完),下次 read 应返回 `b""` |

```python
def read(self, n):
    self.pump()                      # 先抽一把宿主输入
    if self.ready:
        out = bytes(self.ready[:n]); del self.ready[:n]; return out
    if self.eof_pending:
        self.eof_pending = False; return b""
    return None                      # 无数据 → 调用方应阻塞
```

**三态返回**:有数据返回字节;EOF 返回 `b""`;**无数据返回 `None`**。内核
`sys_read` 见 `None` 就 `raise Blocked(obj)`,让进程睡在以 tty 对象为
`wait_channel` 的通道上(kernel.py:694-696)。调度器 `_wake_waiters` 里,当
`ch is self.terminal` 且 `terminal.ready or terminal.eof_pending` 为真才唤醒它
(kernel.py:1322-1325)——这就是"敲了回车,睡着的 read 醒过来"的闭环。

---

## 4. 输出侧:write 与 OPOST/ONLCR、console_tail(ktty.py:539)

```python
def write(self, data):
    t = self.termios
    out = data
    if t.oflag & OPOST and t.oflag & ONLCR and self.term.is_tty():
        out = data.replace(b"\n", b"\r\n")   # 仅 tty 才展开
    self.term.write_out(out)
    self.console_tail.extend(data)           # 留存"逻辑"输出(ONLCR 展开前)
    return len(data)
```

要点:

- **ONLCR 只在真 tty 上展开**:程序只写 `\n`,终端需要 `\r\n` 才能回到行首。
  `is_tty()` 假(管道/文件)时不展开,免得把 LF 污染成 CRLF。
- **返回值是程序请求的字节数**,不是展开后的字节数(ktty.py:540)——否则
  `write()` 返回值会比 count 大,程序会以为写多了。
- **`console_tail`**:`maxlen=8192` 的环形字节缓冲(ktty.py:406),存**展开前**的
  逻辑输出,供 monitor 的 `info console` 回看最近输出。存展开前是对的:回看时不该
  夹带 `\r`。

---

## 5. 转义键:Ctrl-A 前缀状态机(ktty.py:434, kernel.py:1116)

仿 qemu 的 `Ctrl-A` 前缀。默认转义键是 `Ctrl-A`(0x01),由 `--escape` 配
(emulator.py:109-116,`'a'→ord('A')&0x1F=0x01`;传 `none` 则 `on_escape=None`
关掉整个机制,emulator.py:130-131)。

`_strip_escapes` 是个两状态机(ktty.py:434-453):

```
初始态 ── 见到 escape(Ctrl-A) ──▶ armed 态(吞掉这个字节, 不透传)
armed 态 ── 下一个字节 X ──▶ 回初始态, 按 X 分派:
    X ∈ {escape, 'a', 'A'}  → 透传一个"真正的" Ctrl-A 给被仿真程序
    其它 X                  → 调 on_escape(X)(命令), 不透传
非 escape 字节 → 原样透传给行规程
```

命令语义在内核 `on_escape`(kernel.py:1116-1127),与 `ESCAPE_HELP`
(kmonitor.py:40-45)一致:

| 键 | 语义 | 实现 |
|---|---|---|
| `Ctrl-A c` | 进 monitor 控制台 | `self.monitor_pending = True` |
| `Ctrl-A x` | 退出仿真器 | `self.quit_requested = True` + 打印"仿真器退出。" |
| `Ctrl-A a` | 发一个真正的 Ctrl-A 给程序 | `_strip_escapes` 直接透传,不进 on_escape |
| `Ctrl-A ?`(或 `h`) | 打印这份帮助 | `_write_console(ESCAPE_HELP)` |

**为什么在行规程之前拦**:这是唯一的退出途径。交互时宿主终端是 raw 模式,
`Ctrl-C` 会作为字节 0x03 走行规程转成 SIGINT 发给被仿真进程,宿主永远收不到
信号;而 bash 又会关掉 ICANON/ISIG。若转义键走行规程,bash 一关 ISIG 它就失效。
放在行规程之前,`Ctrl-A x` 才永远有效(ktty.py:400-401)。

---

## 6. 平台后端:HostTerminal 的三条路(ktty.py:203)

`select` 在 Windows 上只对 socket 有效,拿控制台句柄调会直接失败——早期版本
因此在 Windows 下敲键完全没反应。所以输入按平台分三条路(ktty.py:230-236,306-357):

| 场景 | 读法 | 位置 |
|---|---|---|
| POSIX 交互/管道 | stdin 设 raw + `select.select` 轮询 + `os.read` | `_read_posix` ktty.py:312 |
| Windows 交互控制台 | `msvcrt.kbhit()`/`getch()` 逐键读(getch 不回显,正好交给行规程) | `_read_windows_console` ktty.py:329 |
| Windows 管道 | 后台线程 `stream.read(1)` 塞进 `_thread_buf`,读侧 drain | `_read_thread` ktty.py:347 |

统一入口 `_read(timeout)` 按 `IS_WINDOWS` 与 `_is_tty` 分派(ktty.py:306-310),
`poll_input=_read(0)`、`wait_input=_read(timeout)`。

其余平台细节:

- **raw 模式**:POSIX 交互时 `_enter_raw` 用 `tty.setraw` 并存旧 termios
  (ktty.py:240-248);`restore` 用 `TCSADRAIN` 复原(ktty.py:250)。
- **suspend/resume**:进 monitor 前 `suspend` 暂时恢复宿主常规模式(monitor 要用
  `input()` 读整行),退出 monitor 后 `resume` 回 raw(ktty.py:256-264)。
- **`translate_windows_key`**(ktty.py:172):Windows 退格是 **BS(0x08)** 而非
  **DEL(0x7F)**,必须翻成 DEL,否则行规程的 VERASE(默认 127)认不出来,退格失效;
  特殊键 `0x00/0xE0` 前缀 + 扫描码翻成 ANSI 序列(`_WIN_SCANCODE_TO_ANSI`,
  ktty.py:158-169),bash/readline 才认得方向键;`Ctrl-C` 等原样透传交给 ISIG。
- **输出写二进制**:`write_out` 优先写 `stdout.buffer`(二进制)(ktty.py:369-376),
  否则 Windows 文本层会把 `\n` 再变 `\r\n`,与 ONLCR 撞车成 `\r\r\n`。
- **`at_eof`**:交互控制台**永不 EOF**(真机上控制台也不会),只有管道/文件读完
  才 EOF(ktty.py:359-367)。
- **窗口大小**:`size()` 用 `shutil.get_terminal_size((80,24))`(ktty.py:378)。
- **`ScriptedTerminal`**(ktty.py:110):`pending` 队列供 `poll_input` 逐块弹出,
  `out` 收集输出,`text`/`text_utf8` 两种视图看输出(内核中文消息是 UTF-8)。
  非交互时 `TTY.__init__` 会关回显免得污染输出(ktty.py:407-409)。

---

## 7. ioctl(ktty.py:551)

内核 `sys_ioctl` 见 fd 指向 tty 就转 `terminal.ioctl(p, cmd, argp)`(kernel.py:745-746)。
`argp` 是用户空间指针,数据经 `proc.mem` 读写:

| 请求 | 行为 |
|---|---|
| `TCGETS` | 把 termios 打包写回 `argp`(ktty.py:553-555) |
| `TCSETS/W/F` | 从 `argp` 解包覆盖 termios;`TCSETSF` 顺带 `_flush_input`(ktty.py:556-560) |
| `TCGETA` | 打包**老 termio**(u16)写回(ktty.py:561-563) |
| `TCSETA/W/F` | 解包老 termio,只覆盖低 16 位与前 8 c_cc;`TCSETAF` 清缓冲(ktty.py:564-568) |
| `TIOCGWINSZ` | 后端 `size()` → 打包 winsize 写回(ktty.py:569-572) |
| `TIOCGPGRP/TIOCSPGRP` | 读/写前台进程组 `self.pgrp`(ktty.py:575-580) |
| `TIOCSCTTY` | 认本进程的会话与进程组为控制终端(ktty.py:581-584) |
| `TIOCINQ/FIONREAD` | `pump` 后返回 `ready` 里可读字节数(ktty.py:585-588) |
| `TCFLSH/TCSBRK/TCXONC` | `TCFLSH` 清输入缓冲,其余当 no-op 返 0(ktty.py:589-592) |
| 其它 | 返回 `-22`(EINVAL)(ktty.py:593) |

**前台进程组 `pgrp`**:VINTR/VQUIT/VSUSP 的信号都投给它(`post_signal(self.pgrp, sig)`);
`TIOCSCTTY` 时从进程取 `session`/`pgrp`;新会话建立时内核也会回填(kernel.py:1058-1060)。
这就是"信号只打前台作业"的基础。

---

## 8. 一条输入的完整走查(例)

### 8.1 交互式敲 `ls<回车>`,程序 read 到 `"ls\n"`

前提:规范模式(ICANON|ECHO|ECHOE 都开),`on_escape` 已装。

1. 敲 `l`:宿主 raw 读到 `b"l"` → `pump` → `feed`。`_strip_escapes` 非 escape、
   原样透传 → `_feed_cooked`:非信号、canon、普通字符 → `_echo(b"l")` 回显 `l`、
   `line=b"l"`。
2. 敲 `s`:同理,回显 `s`、`line=b"ls"`。
3. 敲**退格**(误敲一下,宿主发 DEL 0x7F;Windows 下 BS 已被翻成 DEL):命中
   `VERASE` → `line` 弹掉 `s`、`ECHOE` 写 `\b \b` 把屏幕上的 `s` 擦掉,`line=b"l"`。
4. 重敲 `s`:回显、`line=b"ls"`。
5. 敲**回车**:宿主 raw 发 CR(13)→ `ICRNL` 就地改成 LF(10)→ 普通字符路径:
   `_echo(b"\n")` 回显换行、`line=b"ls\n"`;字节是 `\n` → **行提交**:
   `ready.extend(b"ls\n")`、`line` 清空。
6. 此刻若程序早已 `sys_read` 睡在 tty 通道上:调度器 `_wake_waiters` 发现
   `terminal.ready` 非空,唤醒它;`TTY.read(n)` 从 `ready` 取走 `b"ls\n"` 返回。
   程序拿到完整一行。

### 8.2 敲 `Ctrl-C` → 前台进程组收 SIGINT

1. 宿主 raw 读到 `b"\x03"` → `feed` → `_strip_escapes`:0x03 不是 escape,透传。
2. `_feed_cooked`:`ISIG` 开,`0x03 == cc[VINTR]` → `_echo_ctl` 回显 `^C` →
   `_flush_input` 清 `line`+`ready`(NOFLSH 未置)→ `post_signal(self.pgrp, SIGINT)`。
3. 信号投给**前台进程组**里每个进程(内核置 pending 位),在指令边界
   `_deliver_pending` 投递(kernel.py:1327-1337),默认动作终止,于是前台程序被
   `Ctrl-C` 打断。**宿主自己收不到 SIGINT**——它在 raw 模式,0x03 只是普通字节,
   这也是为什么退出只能靠 `Ctrl-A x`。

---

## 9. 设计取舍备忘

- **行规程在逻辑层、I/O 在后端**:`TTY` 不碰真实 fd,全部输入经后端的
  `poll/wait_input`、输出经 `write_out`。于是同一套行编辑/回显逻辑既能跑在宿主
  终端上,也能在测试里用 `ScriptedTerminal` 注入按键、断言输出,无需真 tty。
- **转义键在行规程之前拦**:唯一可靠的退出/进 monitor 路径。放在
  `_feed_cooked` 之前,不受被仿真程序 termios 设置影响(bash 关 ISIG 也拦得住)。
  代价是被仿真程序永远收不到裸 `Ctrl-A`,除非显式 `Ctrl-A a` 透传。
- **VMIN/VTIME 只做近似**:非规范模式当作 VMIN=1(一字节即可读),没实现
  VTIME 定时器与 VMIN>1 的成批语义——够这个镜像的 bash/readline 用。
- **cflag 是占位**:没有真串口,波特率/字长/CREAD 只存不用。
- **ONLCR 只在 tty 展开、console_tail 存展开前**:两处都为了"逻辑字节 vs 屏幕
  字节"分家——程序看到的是 `\n`,屏幕要的是 `\r\n`,回看缓冲要的又是 `\n`。
- **平台差异集中在 HostTerminal**:`select`/`msvcrt`/后台线程三条路、BS↔DEL 翻译、
  二进制写出,全封在后端;`TTY` 与内核对平台一无所知。
- **返回 `None` 表示"该阻塞"**:把"无数据"与"EOF(b\"\")"分开,让内核决定是
  `Blocked` 还是返回 0,行规程自己不管调度。

---

## 附:关键函数索引

| 环节 | 函数/常量 | 位置 |
|---|---|---|
| ioctl 请求码 | `TCGETS...TIOCINQ` | ktty.py:20 |
| 标志位定义 | `ICRNL/OPOST/ONLCR/ISIG/ICANON/ECHO...` | ktty.py:30 |
| c_cc 下标与默认 | `VINTR...` / `default_cc` | ktty.py:43 / 55 |
| struct 布局 | `TERMIOS_FMT/TERMIO_FMT/WINSIZE_FMT` | ktty.py:50 |
| termios 打包/解包 | `Termios.pack/unpack/pack_old/unpack_old` | ktty.py:85 |
| 抽宿主输入 | `TTY.pump` | ktty.py:413 |
| 拦转义键 | `TTY.feed` / `_strip_escapes` | ktty.py:427 / 434 |
| 行规程主体 | `TTY._feed_cooked` | ktty.py:455 |
| 回显 | `_echo` / `_echo_ctl` | ktty.py:505 / 516 |
| 清缓冲 | `_flush_input` | ktty.py:520 |
| 读(三态) | `TTY.read` | ktty.py:525 |
| 写(ONLCR/console_tail) | `TTY.write` | ktty.py:539 |
| ioctl 分派 | `TTY.ioctl` | ktty.py:551 |
| Windows 键翻译 | `translate_windows_key` / `_WIN_SCANCODE_TO_ANSI` | ktty.py:172 / 158 |
| 宿主后端 | `HostTerminal` | ktty.py:203 |
| raw 模式 | `_enter_raw/restore/suspend/resume` | ktty.py:240 |
| 分平台读 | `_read/_read_posix/_read_windows_console/_read_thread` | ktty.py:306 |
| 二进制写出 | `HostTerminal.write_out` | ktty.py:369 |
| 测试后端 | `ScriptedTerminal` | ktty.py:110 |
| 转义键命令语义 | `Kernel.on_escape` | kernel.py:1116 |
| 终端 read 阻塞 | `sys_read` 的 `Blocked(obj)` | kernel.py:694 |
| 唤醒 tty 等待者 | `_wake_waiters`(`ch is self.terminal`) | kernel.py:1322 |
| 装配 tty | `build_kernel` | emulator.py:35 |
