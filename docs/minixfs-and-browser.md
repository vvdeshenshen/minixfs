# Minix v1 文件系统解析与只读浏览器:布局、算法与代码流程

本文整理只读那一半工具:解析库 `minixfs.py` 怎样把一块 Minix v1(Linux 0.11
时代)磁盘镜像的字节还原成超级块 / inode / 目录树 / 文件内容, 以及
`minix_shell.py`(交互 shell)与 `pager.py`(less 分页器)如何在其上做参数解析、
格式化与翻页。三者依赖严格单向:`minix_shell.py → minixfs.py + pager.py`,
解析库**只解析、不输出**, 所有终端交互都压在 shell 与 pager 里。

> 阅读顺序建议:先看第 1 节的盘上布局与两个魔数常量, 再看第 2-4 节的
> 超级块 / inode / zone 映射(读一个文件的主线), 第 5 节位图, 第 6 节
> checkfs, 最后第 7-8 节的 shell 与 pager。所有引用都标了 `文件:行`。

---

## 1. 盘上布局与入口探测

Minix v1 块大小恒为 1024 字节(`BLOCK_SIZE`,minixfs.py:23)。一块文件系统按块
排布(minixfs.py:3-13 的模块 docstring 就是这张图):

```
块 0            引导块(不属于文件系统内容)
块 1            超级块
块 2 ..         inode 位图  (s_imap_blocks 块)
..              zone  位图  (s_zmap_blocks 块)
..              inode 表    (每块 32 个 inode, 每个 32 字节)
s_firstdatazone 数据区
```

**这个镜像不是裸文件系统, 而是带 MBR 分区表的整盘**:`hdc-0.11.img` 的 Minix
分区从**字节偏移 1024** 开始(即分区第 1 扇区之后就是该分区的引导块)。所有
块号在解析时都要加上这个分区起始偏移 `self.offset`。

两个 magic 决定文件名长度(minixfs.py:28-29):

| magic | 常量 | 目录项文件名 | 目录项大小 |
|---|---|---|---|
| `0x137F` | `MINIX_MAGIC_14` | 14 字节 | 2 + 14 = 16 |
| `0x138F` | `MINIX_MAGIC_30` | 30 字节 | 2 + 30 = 32 |

`hdc-0.11.img` 用的是 `0x137F`(14 字符名)。magic 之外的变体(30 字符名)也
支持, `name_len` / `dirent_size` 随之而变(minixfs.py:63-69)。

### 1.1 起始偏移自动探测 `find_minix_partition_offset`(minixfs.py:168)

打开镜像时若不显式给 `offset`,`MinixFS.__init__`(minixfs.py:207-210)调它来找
文件系统起点。算法:

1. **先赌偏移 0**——`has_magic(0)` 去偏移 0 的**块 1** 读超级块, 看第 16 字节起的
   u16 是否是两个 magic 之一(minixfs.py:174-182)。裸文件系统镜像直接命中。
2. 不中则读 MBR(第 0 扇区 512 字节), 校验尾部 `0x55AA` 签名(minixfs.py:186-187)。
3. 遍历 4 个分区表项, 取分区类型 `ptype`(entry[4])与起始 LBA(entry[8..11],
   小端 u32)。**老式 Minix 分区类型 `0x80/0x81` 排前面优先试**(minixfs.py:193-196)。
4. 对每个候选分区, `has_magic(start_lba * 512)` 去它的块 1 验 magic, 命中即返回
   该字节偏移(minixfs.py:196-199)。
5. 全落空抛 `MinixError`。

`hdc-0.11.img` 走的是第 2-4 步:MBR 里的 Minix 分区起始 LBA 为 2 扇区,
`2 * 512 = 1024`, 于是 `self.offset = 1024`。

---

## 2. 超级块 `SuperBlock`(minixfs.py:42)

从块 1 头部按 `"<HHHHHHIH"` 一次解出 8 个字段(minixfs.py:53-61):

| 字段 | 类型 | 含义 |
|---|---|---|
| `ninodes` | u16 | inode 总数 |
| `nzones` | u16 | zone 总数 |
| `imap_blocks` | u16 | inode 位图占用块数 |
| `zmap_blocks` | u16 | zone 位图占用块数 |
| `firstdatazone` | u16 | 第一个数据 zone 号 |
| `log_zone_size` | u16 | zone 大小 = `1024 << log_zone_size` |
| `max_size` | u32 | 单文件最大字节数 |
| `magic` | u16 | `0x137F` / `0x138F` |

解析时**两处硬约束**(minixfs.py:57-60):magic 必须是已知两值之一, 且
`log_zone_size` 必须为 0(即 zone 恒等于块, 1024 字节)——非 0 直接抛错, 本库
不支持多块 zone。

三个派生属性省去到处重算:
- `name_len` / `dirent_size`(minixfs.py:63-69):由 magic 决定, 见上表。
- `inode_table_block = 2 + imap_blocks + zmap_blocks`(minixfs.py:72-73):inode 表
  紧跟在两张位图之后, 这是从 inode 号定位盘上位置的关键锚点。

---

## 3. inode:32 字节, 只有一个时间戳(minixfs.py:76)

Minix v1 的 inode 是 **32 字节定长**, 按 `"<HHIIBB9H"` 解(minixfs.py:87-92):

| 偏移 | 字段 | 说明 |
|---|---|---|
| 0 (H) | `mode` | 类型位 + 权限位(`S_IFMT` 取类型) |
| 2 (H) | `uid` | 属主 |
| 4 (I) | `size` | 文件字节数 |
| 8 (I) | `mtime` | **唯一的时间戳**(v1 没有 atime/ctime) |
| 12 (B) | `gid` | 属组 |
| 13 (B) | `nlinks` | 硬链接数 |
| 14 (9×H) | `zones[0..8]` | 9 个 zone 指针 |

9 个 zone 指针的含义:**前 7 个是直接块**,`zones[7]` 是一级间接块,`zones[8]`
是二级间接块(见第 4 节)。

**设备节点没有数据块**:字符/块设备把设备号塞在 `zones[0]`,`devno` 属性把它拆成
`(major, minor) = (zones[0] >> 8, zones[0] & 0xFF)`(minixfs.py:122-125)。

一批 `is_*` 属性(minixfs.py:94-121)包装 `stat` 模块的 `S_ISDIR/S_ISREG/…` 做
类型判定;`type_name`(minixfs.py:127-141)给出 `file` 命令用的英文类型名;
`mode_string()`(minixfs.py:143-162)拼 `ls -l` 风格的 `drwxr-xr-x` 串, 并处理
setuid/setgid/sticky 三个特殊位;`mtime_string()`(minixfs.py:164-165)把 mtime
格式化成本地时间。

`get_inode(num)`(minixfs.py:238-244)从 inode 号定位:先边界检查 `1..ninodes`,
再算 `block = inode_table_block + (num-1)//32`、`off = ((num-1)%32)*32`, 读出那
32 字节交给 `Inode.parse`。**inode 从 1 开始编号**(`ROOT_INODE = 1`,minixfs.py:31)。

---

## 4. zone 映射与文件读取

### 4.1 块 0 即空洞(minixfs.py:227)

`read_block(block)`(minixfs.py:227-234)是所有盘访问的唯一出口:
- **`block == 0` 直接返回 1024 个零字节**(minixfs.py:228-229)——zone 号 0 是
  Minix 表达"空洞"的方式, 稀疏文件里没落盘的块 zone 号就是 0。
- 否则 `seek(offset + block*1024)` 读一块;读到镜像尾部不足一块时补零填满
  (minixfs.py:230-233)。

### 4.2 文件内块号 → zone 号 `zone_at`(minixfs.py:300)

给定 inode 与"文件内第 index 块", 返回其 zone 号(0 即空洞), 分三段:

```
index < 7                              直接块:   return zones[index]
7 <= index < 7+512                     一级间接: zones[7] 指向的块里第 (index-7) 个 u16
7+512 <= index < 7+512+512*512         二级间接: zones[8] → 512 个一级间接块 → 各 512 个 zone
```

- 一级间接(minixfs.py:305-309):`zones[7]` 若为 0 则整段是空洞返回 0;否则读该
  间接块, 按 `index*2` 偏移取一个**小端 u16 zone 号**。间接块里就是 `ZONES_PER_BLOCK
  = 512` 个 u16(minixfs.py:26)。
- 二级间接(minixfs.py:310-320):`zones[8]` → 用 `index // 512` 选一级间接块,
  再用 `index % 512` 在其中选 zone;**任一级为 0 都是空洞**, 逐级短路返回 0。
- 超过 `7 + 512 + 512*512` 抛 `MinixError`(minixfs.py:321)——v1 的文件大小上限。

**注意每一步都不检查 zone 位图**, 也不校验 zone 号合法性:`zone_at` 只做映射,
拿到 0 就当空洞、拿到号就交给 `read_block`。一致性校验是 checkfs 的活(第 6 节)。

### 4.3 `read_file`(minixfs.py:328)与 `iter_blocks`(minixfs.py:323)

`read_file(inode, offset, length)` 支持任意 `offset/length` 的部分读:
1. 类型闸门:只有目录 / 普通文件 / 符号链接可读内容, 别的抛错(minixfs.py:330-333)。
2. 按 `inode.size` 夹取真实读取区间 `[offset, end)`(minixfs.py:334-338)——**读取
   永不越过 size**, 即便盘上多分配了块。
3. 从 `offset` 所在块起, 逐块 `zone_at → read_block`, 每块按需切首尾片段拼接
   (minixfs.py:339-347)。空洞块经 `read_block(0)` 天然补零。

`iter_blocks`(minixfs.py:323-326)是按 `ceil(size/1024)` 逐块产出的迭代器版本。

---

## 5. 位图语义:字节序 + 字节内 LSB 在前, 位 0 保留

两张位图(inode 位图、zone 位图)的位序**必须字节顺序 + 字节内低位在前**, 且
**位 0 永远保留为 1**(占位, 从不对应真实对象)。

- **inode 位图第 n 位 ↔ inode n**(直接映射)。`inode_allocated(num)`
  (minixfs.py:250-256):块内偏移 `2 + num//(1024*8)`, 字节 `(num%(1024*8))//8`,
  位 `num % 8`。
- **zone 位图第 n 位(n≥1) ↔ 数据 zone `firstdatazone + n - 1`**(有偏移!)。
  `zone_allocated(zone)`(minixfs.py:289-296):先 `bit = zone - firstdatazone + 1`
  换算, 再按同样方式取位。数据 zone 总数 = `nzones - firstdatazone`。

`_count_bitmap(start, nblocks, nbits)`(minixfs.py:260-270)统计**第 1..nbits 位**
里置位的个数——**从 1 起, 跳过位 0**, 且不数 `nbits` 之后的尾部填充位(老 mkfs
把范围外的位全填 1)。`fs_stats`(minixfs.py:272-287)据此汇总:

```python
used_inodes = _count_bitmap(2, imap_blocks, ninodes)               # 位 1..ninodes
used_zones  = _count_bitmap(2+imap_blocks, zmap_blocks, nzones-firstdatazone)
```

> 差一坑(CLAUDE.md 已记):老 mkfs 的尾部填充**从第 ninodes 位就开始**(而非
> ninodes+1), 所以真实镜像里最后一个 inode 恒被标为已分配却内容全零——checkfs
> 会把它报成"位图泄漏", 这是**已知现象不是回归**(见 6.4)。

---

## 6. checkfs:一趟目录树遍历式 fsck(minixfs.py:436)

`check_fs(fs)` 返回结构化的 `FsckReport`(minixfs.py:425, 含 `problems` 列表 +
`inodes_checked` + `zones_checked`, `clean` 属性即"无问题"), 每条问题是
`FsckProblem(path, inode, message)`(minixfs.py:413)。它一趟遍历同时做四类检查。

### 6.1 准备:位图整体入内存(minixfs.py:452-461)

两张位图各自 `b"".join` 整块读进内存, 用闭包 `ibit(num)` / `zbit(zone)` 按位查,
避免逐位读盘。`zbit` 内含与 `zone_allocated` 相同的 `firstdatazone` 偏移换算。

### 6.2 枚举一个 inode 的全部 zone `collect_zones`(minixfs.py:463)

返回 `(data, meta)`:`data` 是 `[(文件内块索引, zone)]`(直接 + 一级间接下的
+ 二级间接下的实际数据块),`meta` 是间接块**自身**的 `[(描述, zone)]`。关键点:
- 直接块(minixfs.py:474-476)、一级间接(minixfs.py:477-484)、二级间接
  (minixfs.py:485-500)逐级展开;二级间接的文件内块索引基址是
  `7 + 512 + j*512`(minixfs.py:495)。
- **越界的间接块不再向下展开**(minixfs.py:472 的 `valid(z)` 守卫)——一个非法
  的间接块 zone 号不该被拿去 `read_block` 当指针数组读。

### 6.3 单 inode 检查 `check_inode`(minixfs.py:507)

设备 / FIFO 跳过(zones[0] 是设备号无数据块,minixfs.py:509-510)。对每个
data/meta zone:
1. **合法性**:落在 `firstdatazone..nzones-1` 之外报"zone 号非法"(minixfs.py:515-520)。
2. **位图标记**:`zbit(zone)` 为假报"未在 zone 位图中标记为已用"(minixfs.py:521-523)。
3. **重复引用**:`zone_owner` 字典记录每个 zone 的首个属主, 再次出现即报与谁
   "重复引用"(minixfs.py:524-530)。
4. **size 一致性**(minixfs.py:532-541):`expected = ceil(size/1024)`。若实际
   data 块数 ≠ expected, 或有块索引 `>= expected`(越过文件末尾), 就报不一致,
   并区分"越过末尾"与"存在空洞"两种措辞。
5. 目录额外查 size 是否是 `dirent_size` 的整数倍(minixfs.py:543-546)。

### 6.4 遍历 + 反向检查(minixfs.py:548-606)

从根 inode 起用栈做深度遍历(minixfs.py:548-583):每个目录项检查 inode 号是否
越界、`referenced` 记录首次引用路径、目录入栈递归、非目录当场做 `ibit` 位图检查
与类型检查再 `check_inode`;`checked` 集合防重复处理(硬链接/环)。

遍历完做两个**全局反向检查**:
- **孤儿 inode**(minixfs.py:585-598):位图标为已分配却没被任何目录引用。再分
  两种——有内容的是真孤儿, 全零的是"位图泄漏"(并提示这多半就是 5 节说的最后
  一个 inode 的差一填充)。
- **丢失块**(minixfs.py:599-606):zone 位图标为已用却没被任何 inode 引用。

### 6.5 走查:checkfs 如何发现一处位图不一致

设某普通文件 inode 9 的 `zones = [41, 0, …]`(仅一个直接块), 而 zone 位图里
第 `41 - firstdatazone + 1` 位是 0(该块被引用却没标记):

1. 遍历到 inode 9, 非目录, `ibit(9)` 通过, 进 `check_inode("/path/f", 9)`。
2. `collect_zones` 得 `data = [(0, 41)]`,`meta = []`。
3. 对 `(0, 41)`:`41` 在合法范围, 但 `zbit(41)` 为假 → 追加
   `FsckProblem("/path/f", 9, "数据块[0] zone 41 未在 zone 位图中标记为已用")`。
4. `zone_owner[41] = ("/path/f", 9)`。size 若与 1 块一致则不再报别的。
5. shell 侧 `do_checkfs`(minix_shell.py:232)逐条 `str(p)` 打印, 末尾汇报
   "N 个 inode / M 个已引用 zone / K 个问题"。

---

## 7. 交互 shell `minix_shell.py`

基于 `cmd.Cmd`(minix_shell.py:34)。定位:**只做参数解析与格式化**, 所有真正的
盘上操作都下沉到 `minixfs`。

### 7.1 状态:两份当前目录(minix_shell.py:37-44)

当前目录**同时存两份**:
- `self.cwd` 是 `Inode` —— 实际用于解析相对路径(`_resolve` → `fs.resolve(path,
  cwd=self.cwd)`,minix_shell.py:54-55)。
- `self.cwd_path` 是**规范化字符串**, 仅供 `pwd` 与提示符显示。

`do_cd`(minix_shell.py:87-97)切目录时:先 `_resolve` 拿到 inode 并确认是目录,
更新 `self.cwd`;再用纯字符串函数 `normalize_path`(minix_shell.py:18-31, 处理
`.`/`..`/多斜杠)更新 `self.cwd_path`。两者各算各的, 谁也不依赖谁。

### 7.2 错误统一在 `onecmd` 收口(minix_shell.py:60-65)

`onecmd` 包一层 `try`, 把任何 `MinixError`(路径不存在、越界、类型不符…)统一
转成 `错误: …` 打印, **不让异常冒泡打断 shell**。各 `do_*` 因此可以放心地
`_resolve` 而不必各自 try。

### 7.3 各子命令职责

| 命令 | 位置 | 职责 |
|---|---|---|
| `pwd` | do_pwd (83) | 打印 `cwd_path` |
| `cd [路径]` | do_cd (87) | 切目录, 无参回根;更新两份 cwd |
| `ls [-l] [路径]…` | do_ls (109) | 列目录/文件;`-l` 用 `_format_long`(99) 拼权限/链接/属主/大小/时间, 设备显示 `major,minor` |
| `stat [路径]…` | do_stat (168) | 无参时打印 `_print_fs_stats`(152) 全盘统计;有参逐个 `_print_inode_info`(136) |
| `inode <编号>` | do_inode (204) | 按号打印原始 inode(`_print_inode_raw`,191, 含 zones/间接块) |
| `info <编号>` | do_info (210) | 原始 inode + `find_references` 列出全部引用它的目录项, 并核对 nlinks 是否与实际引用数一致 |
| `checkfs` | do_checkfs (232) | 跑 `check_fs` 打印全部问题 + 汇总 |
| `file <路径>…` | do_file (274) | `_classify`(249) 判类型:a.out 魔数(407/410/413/314)、`#!` 脚本、gzip/compress 魔数、文本启发式(无 NUL 且可打印占比 > 95%) |
| `dump <路径> [偏移 [长度]]` | do_dump (283) | 十六进制转储, 8 字节分组 + ASCII 侧栏 |
| `less <路径>` | do_less (307) | 读文件全文交给 `Pager` 分页 |
| `exit`/`quit`/`q`/`EOF` | do_exit (74) | 退出 |

`do_inode` / `do_info` 的编号解析走 `_parse_inode_arg`(minix_shell.py:179-189,
支持 `0x`/八进制前缀, 用 `int(s, 0)`)。

`do_less`(minix_shell.py:307-324)的交互判定值得一看:只有当 `pager_opts` 没被
测试注入、**且 stdin 与 stdout 都是 TTY** 时, 才挂上真实的 `read_key_tty` 与
ANSI 输出;否则 `read_key` 留 None, Pager 退化为直接吐全文(见第 8 节)。这就是
CLAUDE.md 里"stdout 非 TTY 时 less 退化为直接输出"的落点。

---

## 8. 分页器 `pager.py`

独立的 less 风格分页器, 与文件系统完全无关。**终端尺寸 / 按键读取 / 写出全部
可注入**(minix_shell.py 与单测据此注入 StringIO 与脚本化按键)。

### 8.1 交互 vs 非交互(pager.py:110)

`run()`(pager.py:110-153)三条路:
1. 空内容直接返回。
2. **`read_key is None` → 非交互**, 逐行 `write` 全部内容后返回(pager.py:113-116)
   —— 输出被重定向 / 非 TTY 时就走这条。
3. 内容**一屏放得下**(`len(lines) <= height`)也直接全吐, 不进交互(类似
   `less -F`,pager.py:117-121)。
4. 否则进交互循环:`_draw(top)` 画一屏 + 反显状态栏, `read_key()` 读键跳转。

`top` 是当前顶行, `max_top = len(lines) - height` 夹住下界, `half` 是半屏步长。

### 8.2 按键与 ESC 序列翻译(pager.py:19)

交互循环认这些键(pager.py:132-150):`j`/回车 下一行、`k` 上一行、`f`/空格/`n`
下一屏、`b`/`p` 上一屏、`d` 半屏下、`u` 半屏上、`g`/`G` 首尾、`q`/`Q` 退出。

方向键与翻页键是多字节 ESC 序列, 由 `_decode_key`(pager.py:19-43)在读键处
**翻译成等价字母键**再喂给循环:`ESC [ A/B` → `k`/`j`(↑/↓),`ESC [ 5~`/`6~` →
`b`/`f`(PgUp/PgDn),其它 ESC 序列一律当 `q`;`Ctrl-C`/EOF → `q`,`Ctrl-D`/`Ctrl-U`
→ `d`/`u`。循环本身因此只需处理单字母, 方向键逻辑不散落在主循环里。

`read_key_tty`(pager.py:46-59)是 POSIX 上的真实实现:把终端切 cbreak, 用
`_decode_key(lambda: sys.stdin.read(1))` 读一个键, `finally` 恢复终端设置。

### 8.3 绘制(pager.py:95)

`_draw`(pager.py:95-106):ANSI 模式先 `\x1b[2J\x1b[H` 清屏归位, 逐行按 `width`
截断输出, 末尾用 `\x1b[7m…\x1b[0m` 反显状态栏(不换行)并 flush;非 ANSI 模式
只在末尾多打一行状态。`_status`(pager.py:86-93)拼 `名字 top-end/total 行 (pct%)`,
到底加 `(END)`。

---

## 9. 一条完整走查:`less /path/big`(读一个跨一级间接块的文件)

设 `/path/big` 是普通文件, `size = 9000` 字节(占 `ceil(9000/1024) = 9` 块), 前
7 块是直接块, 第 8/9 块落在一级间接。

1. shell:`do_less`(minix_shell.py:307)`_resolve("/path/big")` → `fs.resolve`
   (minixfs.py:394)从 `cwd` 或根逐段 `dir_lookup`(minixfs.py:366)得到 inode。
2. `fs.read_file(inode)`(minixfs.py:328), `length=None` → 读满 size=9000。
3. 循环第 0..6 块:`zone_at(inode, i)` 走 `index < 7` 分支直接取 `zones[i]`
   (minixfs.py:302-303), `read_block` 各读一块。
4. 第 7 块:`zone_at(inode, 7)` → `index-7 = 0 < 512`, 读 `zones[7]` 指向的一级
   间接块, 取其第 0 个 u16 当 zone 号(minixfs.py:305-309), 再 `read_block`。
5. 第 8 块:同理取一级间接块第 1 个 u16。若某块 zone 号为 0, `read_block(0)` 返回
   零填充(空洞)。
6. 拼接的字节夹到 `end = min(9000, …)`, **最后一块只取前 9000 - 8*1024 = 808 字节**
   (minixfs.py:336, 344)。
7. 回 shell:`.decode("latin-1").splitlines()` 交给 `Pager`(minix_shell.py:314-324)。
   非 TTY(如管道)时 `read_key` 为 None, Pager 直接吐全文;TTY 下进交互翻页。

---

## 10. 设计取舍

- **解析库零输出**:`minixfs.py` 只返回数据结构(`Inode`/`SuperBlock`/`FsckReport`),
  从不 print。格式化、分页、报错文案全在 shell/pager。好处是解析库能被仿真器
  (`emulator.py → kernel → kvfs`)复用而不拖进任何终端逻辑。
- **zone_at 只映射不校验**:读路径故意不查位图、不验 zone 合法性——只认 0=空洞。
  一致性交给独立的 `check_fs`。读一个"坏"文件不会崩, 只会读到零或错块;要诊断
  才跑 checkfs。
- **checkfs 一趟遍历 + 反向扫描**:正向遍历目录树收集"谁引用了什么"(`zone_owner`/
  `referenced`), 再反向扫位图找孤儿/丢失。比"每个 inode 独立全盘扫"省 IO, 代价
  是要用 `checked`/`seen` 集合防环与防重。
- **当前目录存两份**:`cwd`(Inode, 真解析用)与 `cwd_path`(字符串, 只显示用)。
  不试图从 inode 反推路径(硬链接下路径不唯一), 显示路径靠纯字符串规范化维护。
- **差一填充不当错**:老 mkfs 的位图尾部差一是镜像固有现象, checkfs **照报但
  措辞点明**"多半是老 mkfs 填充的差一", 既不隐瞒也不误导为损坏。
- **pager 全可注入**:`write/read_key/height/width/use_ansi` 都能注入, 使得非
  交互退化、单元测试(脚本化按键 + StringIO)、真实 TTY 三态共用一套主循环。
- **只读**:全库无任何写盘路径, 打开镜像也是 `"rb"`(minixfs.py:214)。浏览器的
  定位就是"看", 不改镜像内容。

---

## 附:关键函数索引

| 环节 | 函数 | 位置 |
|---|---|---|
| 起始偏移探测 | `find_minix_partition_offset` | minixfs.py:168 |
| 超级块解析 | `SuperBlock.parse` | minixfs.py:53 |
| inode 解析 | `Inode.parse` / `Inode.devno` | minixfs.py:89 / 122 |
| 权限串 | `Inode.mode_string` | minixfs.py:143 |
| 底层块读(块0=空洞) | `MinixFS.read_block` | minixfs.py:227 |
| 取 inode | `MinixFS.get_inode` | minixfs.py:238 |
| 文件内块→zone | `MinixFS.zone_at` | minixfs.py:300 |
| 文件读取 | `MinixFS.read_file` / `iter_blocks` | minixfs.py:328 / 323 |
| 目录读取/查找 | `read_dir` / `dir_lookup` / `resolve` | minixfs.py:351 / 366 / 394 |
| 引用反查 | `find_references` | minixfs.py:372 |
| 位图查询 | `inode_allocated` / `zone_allocated` | minixfs.py:250 / 289 |
| 位图统计 | `_count_bitmap` / `fs_stats` | minixfs.py:260 / 272 |
| fsck 主体 | `check_fs` | minixfs.py:436 |
| fsck 枚举 zone | `collect_zones` | minixfs.py:463 |
| fsck 单 inode | `check_inode` | minixfs.py:507 |
| shell 主类 | `MinixShell` | minix_shell.py:34 |
| 路径规范化 | `normalize_path` | minix_shell.py:18 |
| 错误收口 | `MinixShell.onecmd` | minix_shell.py:60 |
| ls -l 格式化 | `_format_long` | minix_shell.py:99 |
| 全盘统计 | `_print_fs_stats` | minix_shell.py:152 |
| file 类型判定 | `_classify` | minix_shell.py:249 |
| less 交互判定 | `do_less` | minix_shell.py:307 |
| 分页主循环 | `Pager.run` | pager.py:110 |
| 绘制 | `Pager._draw` / `_status` | pager.py:95 / 86 |
| 按键翻译 | `_decode_key` / `read_key_tty` | pager.py:19 / 46 |
