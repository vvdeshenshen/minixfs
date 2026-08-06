# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## 项目概述

用 Python 实现的 Minix v1 文件系统(Linux 0.11 时代)只读浏览器。
`hdc-0.11.img` 是带 MBR 分区表的真实 Linux 0.11 磁盘镜像(63MB, 已入库),
Minix 分区从字节偏移 1024 开始, magic 0x137F(文件名 14 字符)。

## 常用命令

```bash
# 全部测试(无需真实镜像; 镜像存在时会多跑几个集成测试)
python3 -m unittest test_minixfs test_cpu86 test_kvfs test_kernel test_ktty

# 单个测试类 / 单个测试
python3 -m unittest test_minixfs.TestCheckFs
python3 -m unittest test_minixfs.TestFileRead.test_sparse_file_reads_zeros

# 交互式运行(子命令: cd/ls/pwd/stat/inode/info/file/dump/less/checkfs)
python3 minix_shell.py hdc-0.11.img

# 非交互验证(stdout 非 TTY 时 less 退化为直接输出)
printf 'ls -l /bin\nexit\n' | python3 minix_shell.py hdc-0.11.img

# 仿真器: 交互式 bash / 单个程序 / 可脚本化
python3 emulator.py hdc-0.11.img
python3 emulator.py hdc-0.11.img /bin/date
printf 'echo hi | cat\nexit\n' | python3 emulator.py hdc-0.11.img
python3 emulator.py hdc-0.11.img /bin/sh --trace     # 打印系统调用轨迹
```

无外部依赖, 仅标准库; 无 lint 配置。

## 架构

两套工具共用只读解析库, 依赖方向严格单向, **minixfs.py 与 pager.py 不被仿真器修改**:
```
minix_shell.py → minixfs.py + pager.py            浏览器
emulator.py → kernel.py → {ksyscall, kexec, kproc 相关, kvfs, ktty} → minixfs.py
cpu86.py → x86mem.py                              CPU 层不 import minixfs 与内核层
```

- **minixfs.py** — 解析库, 不做任何输出。`MinixFS` 提供块/inode/目录/
  文件读取(直接块 + 一级/二级间接块, zone 0 视为空洞补零)、MBR 分区
  自动探测(`find_minix_partition_offset`)、位图查询(`inode_allocated`/
  `zone_allocated`/`fs_stats`)。`check_fs()` 是 fsck: 遍历目录树,
  返回结构化 `FsckReport`, 检查 size/块数一致、inode 与 zone 的位图
  标记、重复引用、孤儿与丢失块。
- **minix_shell.py** — 基于 `cmd.Cmd` 的交互层, 只负责参数解析与格式化。
  `MinixError` 统一在 `onecmd()` 里捕获。当前目录状态是 `cwd`(Inode) +
  `cwd_path`(显示用规范化字符串)两份。
- **pager.py** — 独立的 less 风格分页器。`Pager` 的终端尺寸/按键读取/
  写出全部可注入; `read_key` 为 None 时非交互直接输出。tty 按键经
  `_decode_key` 把方向键等 ESC 序列翻译成 j/k/f/b。

## 测试设计

`test_minixfs.py` 的核心是 `build_image()`: 在内存中程序化构造一个
32 块的迷你 minix v1 镜像(含子目录、设备节点、跨一级间接块的大文件、
落在二级间接区的全空洞稀疏文件), 所有单测都跑在它上面。
`TestCheckFs` 通过直接改镜像字节注入损坏(fixture 布局常量见该类顶部);
注意 fixture 中 sparse.bin(inode 7) 的空洞是 checkfs 的**预期**报告,
相关断言需先排除它。shell 测试向 `MinixShell(stdout=StringIO)` 注入
输出流, 分页测试用脚本化按键序列注入 `Pager(read_key=...)`。

## 仿真器(改代码前必读)

- **ABI 一律从镜像内部查证, 不要凭记忆**: 镜像带着 `/usr/src/linux` 的内核 C 源码
  (`fs/` 18 个 .c, `kernel/` 10 个 .c)与完整 `/usr/include`。查法:
  `fs.read_file(fs.resolve('/usr/src/linux/fs/exec.c'))`。已据此确认: 初始栈布局
  (`create_tables`)、64MB 地址空间(`change_ldt`)、`brk` 恒返回当前值(`sys.c`)、
  信号帧 7/8 长字(`signal.c` 的 `do_signal`)、87 项调用表(`include/linux/sys.h`)、
  termios 码(`include/termios.h`)。
- **这个镜像的内核是打过补丁的后期版本**, 87 个调用(不是经典 0.11 的 72 个),
  镜像 libc 确实用到 `lstat/readlink/getrlimit` 等超出部分。
- 0.11 **没有 sigreturn 系统调用**: 信号返回靠 libc 的 `sa_restorer` 在用户态弹栈,
  所以 `signal(48)` 是三参(edx=restorer)。restorer 为 0 时走 `MAGIC_SIGRETURN` 兜底。
- 三个容易再踩的坑(都已有回归测试):
  ① 被信号唤醒时必须把 eip 推回(不重做系统调用), 否则 eax 里的 `-EINTR` 会被当成
     调用号; 且默认动作为忽略的信号不能打断 waitpid。
  ② 调度器的指令记账要用 `cpu.icount` 差值 —— Blocked/Exited 都走异常路径,
     靠 `run()` 返回值会漏记而死循环。
  ③ 管道读写端计数按**描述符**增减(`_acquire_fd`), 不能等 OpenFile 的 refs 归零,
     否则 fork 后写端永远关不掉, 流水线死锁。
- `execve` 必须抛 `Replaced` 打断旧 `cpu.run()` 循环(旧 CPU 持有已失效的内存)。
- x87 未实现(镜像 libc 是软浮点), 遇到就抛带 eip 与机器码字节的 `CpuError` —— 这是
  刻意的策略, 别改成静默跳过。
- 镜像自身的坑: 无 `/dev/console`、无 `/etc/inittab`、`/dev/null` 被误建为块设备
  (故设备分派不检查 b/c 类型)、`/etc/mtab` 的 mtime 超出有符号 i32(故 stat 按无符号
  打包, 与内核 `cp_stat` 逐字段拷 32 位一致)。

## 领域细节(改代码前必读)

- 位图位序: 字节顺序 + 字节内 LSB 在前; 位 0 保留恒为 1。
  inode 位图第 n 位 ↔ inode n; zone 位图第 n 位 ↔ zone
  `firstdatazone + n - 1`。老 mkfs 的尾部填充从第 ninodes 位就开始
  (差一), 所以真实镜像 checkfs 恒报最后一个 inode "内容全零"——这
  是已知现象, 不是回归。
- inode 32 字节, 只有一个时间戳(mtime); 设备号存 zones[0]
  (major<<8|minor); 间接块是 512 个小端 u16 zone 号。
- 有效统计范围: inode 1..ninodes, 数据 zone 共 nzones-firstdatazone
  个; 位图统计必须跳过保留位与尾部填充位, 否则使用率虚高。

## 约定

- 提交信息、注释、用户可见输出均为中文; 按功能拆分提交(feat: 前缀)。
- 镜像 hdc-0.11.img 已入库, 但测试不依赖它, 缺失时集成测试自动跳过;
  修改代码时不要改动镜像内容。
