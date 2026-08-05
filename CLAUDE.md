# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## 项目概述

用 Python 实现的 Minix v1 文件系统(Linux 0.11 时代)只读浏览器。
`hdc-0.11.img` 是带 MBR 分区表的真实 Linux 0.11 磁盘镜像(63MB, 已入库),
Minix 分区从字节偏移 1024 开始, magic 0x137F(文件名 14 字符)。

## 常用命令

```bash
# 全部测试(无需真实镜像; 镜像存在时会多跑几个集成测试)
python3 -m unittest test_minixfs

# 单个测试类 / 单个测试
python3 -m unittest test_minixfs.TestCheckFs
python3 -m unittest test_minixfs.TestFileRead.test_sparse_file_reads_zeros

# 交互式运行(子命令: cd/ls/pwd/stat/inode/info/file/dump/less/checkfs)
python3 minix_shell.py hdc-0.11.img

# 非交互验证(stdout 非 TTY 时 less 退化为直接输出)
printf 'ls -l /bin\nexit\n' | python3 minix_shell.py hdc-0.11.img
```

无外部依赖, 仅标准库; 无 lint 配置。

## 架构

三层结构, 依赖方向单一: `minix_shell.py` → `minixfs.py` + `pager.py`。

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
