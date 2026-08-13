# 可写虚拟文件层:覆盖式 COW、管道与设备表

本文整理仿真器文件系统层(`kvfs.py`,由 `kernel.py` 的系统调用驱动)是怎样
在**只读**的 `minixfs.MinixFS` 之上叠一层可写视图的:读未改动的内容直接透传
底层镜像,首次写入才把文件/目录整块复制进内存(copy-on-write),**镜像文件本身
永不被写**。同一层里还实现了匿名管道与 `/dev` 设备分派。

> 阅读顺序:先看第 1 节的分层与 VInode,再看第 2 节的 COW 主线,第 3 节的
> 文件对象/描述符,第 4 节的管道,第 5 节的设备表。所有引用都标了 `文件:行`。

---

## 1. 分层:只读底层 + 内存覆盖层

```
minixfs.MinixFS   只读解析: get_inode / read_file / read_dir / resolve —— 永不写
      ▲ 透传未改动的内容
kvfs.OverlayFS    可写覆盖: VInode 缓存 + COW + 目录项操作 + 管道 + 导出导入
      ▲ 系统调用
kernel.Kernel     sys_open/read/write/fork/pipe … 把 VInode/Pipe 包进 OpenFile
```

依赖严格单向:`kvfs.py` import `minixfs`(kvfs.py:22),反过来不成立。底层
`MinixFS` 只提供"给我 inode 号/目录 inode,还我字节/目录项"(`get_inode`
minixfs.py:238、`read_file` minixfs.py:328、`read_dir` minixfs.py:351),
不知道覆盖层的存在。

### 1.1 为什么选 inode 级而非路径级覆盖(kvfs.py:7-13)

覆盖单位是 **inode**(`dict[int] -> VInode`),不是 `dict[path] -> bytes`。
路径级有四个破绽,注释里点明:

| 破绽 | 后果 |
|---|---|
| 硬链接 / rename | 镜像里 `/bin/sh` 与 `/bin/bash` 是同一 inode,路径级会分裂成两份 |
| 打开后 unlink | shell 重定向的临时文件"删了还能读"会失效 |
| opendir 读原始 dirent | 0.11 直接 `read` 目录 fd 拿 16 字节一条的 dirent,路径级没有 inode 号可填 |
| chroot / `..` | 只能靠字符串规范化,易错 |

### 1.2 VInode:一个可能"还在底层"的 inode(kvfs.py:57)

`VInode`(`__slots__`,kvfs.py:60)是覆盖层的核心对象。两个字段编码"改没改过":

| 字段 | 含义 |
|---|---|
| `data` | `bytearray` 文件内容;**`None` = 还没 COW,内容仍在底层镜像** |
| `entries` | `dict[name -> ino]` 目录项;**`None` = 还没 COW,目录仍读底层** |
| `base` | 对应的底层 `minixfs.Inode`;**`None` = 覆盖层新建、底层无此 inode** |
| `mode/uid/gid/nlinks/mtime/rdev` | 元数据,`from_base` 时从底层拷来,之后就地改 |
| `open_refs` | 有几个打开描述符指向它(决定 unlink 后能否立即丢弃) |
| `deleted` | nlinks 与 open_refs 都归零后置位 |

`size`(kvfs.py:86)是**计算属性**:COW 过的文件按 `len(data)`,COW 过的目录按
`len(entries)*16`,否则退回底层的 `_size`。`from_base`(kvfs.py:80)从底层
`Inode` 包一个 VInode,设备节点顺手把 `zones[0]` 解成 `rdev`。

`OverlayFS`(kvfs.py:163)持有 `vnodes: Dict[int, VInode]` 缓存,`get(ino)`
(kvfs.py:179)是**唯一取 VInode 的入口**:命中缓存直接返回(保证同一 inode
全程是同一个 Python 对象,硬链接才共享改动),否则从底层包一个存进缓存。
新 inode 号从 `base.sb.ninodes + 1` 起递增(kvfs.py:174),与镜像原有 inode
号不冲突,`_new_inode`(kvfs.py:190)分配,越过 u16 上限抛 `ENOSPC`。

---

## 2. 写时复制(COW)主线

### 2.1 两把 COW 钥匙:`_cow_file` 与 `_cow_dir`

一切写操作在动手前先调其一,把底层内容"拉进"内存:

- **`_cow_file(v)`**(kvfs.py:204):`v.data is None` 时,用
  `base.read_file(v.base)` 把整个文件读成 `bytearray`(新建文件则空);之后
  `v.data` 非 None,再写就地改。返回 `v.data`。
- **`_cow_dir(v)`**(kvfs.py:213):`v.entries is None` 时,用 `base.read_dir`
  把目录项(含 `.` 与 `..`)读成 `dict`;之后目录项都在内存里增删。返回
  `v.entries`。

COW 是**惰性且一次性**的:只在首次写触发,第二次写命中已在内存的副本。读路径
永远不触发 COW —— `read`(kvfs.py:305)优先看 `v.data`,没有就透传
`base.read_file`;`readdir_raw`(kvfs.py:235)优先按内存 `entries` 重新打包
16 字节 dirent,没有就透传底层原始字节。

### 2.2 内容读写落到覆盖层

| 操作 | 函数 | 落点 |
|---|---|---|
| `write(v,off,data)` | kvfs.py:315 | `_cow_file` 后就地改 `data`;`off > len` 先补零空洞 |
| `truncate(v,size)` | kvfs.py:325 | `_cow_file` 后 `del data[size:]` 或补零到 size |
| `read(v,off,len)` | kvfs.py:305 | 目录→打包 dirent;有 `data`→切片;否则透传底层 |

写目录直接 `EISDIR`(kvfs.py:317)。每次写更新 `v.mtime`。

### 2.3 目录项操作:全部经 `_link_entry` / `_unlink_entry`

增删名字这两把内部小工具是所有目录级操作的公共底座,它们各自先 `_cow_dir`:

- **`_link_entry(parent,name,v)`**(kvfs.py:341):`_cow_dir(parent)` 后
  `entries[name]=v.ino`,`v.nlinks += 1`。
- **`_unlink_entry(parent,name)`**(kvfs.py:347):删名字,`v.nlinks -= 1`;
  若 `nlinks==0 且 open_refs==0` 则 `v.deleted=True`,**否则等 close 再丢**
  (打开着的文件删掉还能读的语义)。删前调 `_remember` 记下 `(父ino,名字)`。

上层命令都是这两块的组合:

| 命令 | 函数 | 要点 |
|---|---|---|
| `create` | kvfs.py:361 | 新建 regular;已存在 `EEXIST` |
| `mknod` | kvfs.py:371 | 设备/FIFO 不给 `data`,其余给空 `data` |
| `mkdir` | kvfs.py:383 | 新目录**自带 `.` 与 `..`**,给父目录 nlinks +1 |
| `rmdir` | kvfs.py:400 | 非空(除 `.`/`..`)`ENOTEMPTY`;父 nlinks -1 |
| `unlink` | kvfs.py:415 | 目录用 rmdir → `EISDIR` |
| `link` | kvfs.py:424 | 硬链接;禁止对目录建链 `EPERM` |
| `rename` | kvfs.py:433 | 目标存在则先删;跨目录移动目录时改子目录 `..` 与两边 nlinks |

`walk_parent`(kvfs.py:282)把 `路径` 拆成 `(父目录 VInode, 末段名)` 供上述
带路径的操作用,并在此做 minix v1 的 14 字节文件名截断(kvfs.py:299)。

### 2.4 元数据与 stat

`chmod`(kvfs.py:458)只换权限位、保留类型位;`chown`(kvfs.py:461)用
`0xFFFF` 表示"不改";`stat_tuple`(kvfs.py:470)打包 `struct stat` 字段 ——
**Minix v1 磁盘 inode 只有一个 mtime,所以 atime/mtime/ctime 同值**,根设备号
恒为 `ROOT_DEV=0x0301`(/dev/hd1)。

### 2.5 符号链接:本文件系统没有

`minixfs.Inode` 有 `is_symlink`(minixfs.py:119),但 **Minix v1 实际不用符号
链接**:`walk`(kvfs.py:260)从不解引用,内核 `sys_readlink` 直接返回 `-EINVAL`
(kernel.py:541)、`sys_symlink` 返回 `-EPERM`(kernel.py:544)。也因此没有独立
的 lstat —— `sys_stat`(kernel.py:528)与 fstat 就够了,不存在"跟随/不跟随"的
分歧。

### 2.6 路径解析 `walk`(kvfs.py:260)

逻辑与 `minixfs.resolve` 一致,但走覆盖层 `lookup`(kvfs.py:247,优先查内存
`entries`,否则遍历底层 `read_dir`)并支持 chroot:

- 起点:绝对路径或无 cwd → `root`,否则 cwd;
- 逐段跳过 `""` 与 `.`;非目录中查找抛 `ENOTDIR`;查不到抛 `ENOENT`;
- **chroot 边界**:在 `cur.ino == root.ino` 时遇 `..` 原地不动(kvfs.py:274),
  越根被挡住。

---

## 3. 文件对象与描述符(kernel.py)

覆盖层给出 `VInode` / `Pipe` / 设备对象,内核用两层把它们接到进程 fd 表:

```
Process.fds[fd]  ──► OpenFile(obj, flags, pos, refs)  ──► VInode | Pipe | 终端 | NullDevice
   每进程一份          open file description(可被多 fd 共享)      底层对象
```

**`OpenFile`**(kernel.py:54)= `obj + flags + pos + refs`,即 POSIX 的
"打开文件描述"。关键点:**fork/dup 共享同一个 OpenFile,故共享读写位置 `pos`**
(kernel.py:55)。`readable/writable`(kernel.py:65-71)按 `flags & O_ACCMODE`
判。`sys_open`(kernel.py:579)分配 fd、建 OpenFile;若目标是 VInode 就
`open_refs += 1`,`O_APPEND` 时 `pos` 置到文件尾。

读写按 `obj` 类型分派(**sys_read** kernel.py:676 / **sys_write** kernel.py:700):

| obj 类型 | 读 | 写 |
|---|---|---|
| `VInode` | `fs.read`,推进 `f.pos` | `fs.write`(O_APPEND 先跳尾),推进 `f.pos` |
| `Pipe` | `obj.read`;`None` → `Blocked(("piperead",obj))` | `obj.write`;`None` → `Blocked(("pipewrite",obj))` |
| `NullDevice` | 恒 0(EOF) | 恒吞掉 count 字节 |
| 终端 | `obj.read`;`None` → `Blocked(obj)` | `obj.write` |

fork 时 fd 表**逐项复制但指向同一 OpenFile**(kernel.py:794-797),这正是
`sh > file` 重定向、父子共享偏移的根基。

---

## 4. 管道(kvfs.py:127)

`Pipe` 是"一页环形缓冲",语义照内核 `fs/pipe.c`:`buf` 是 `bytearray`,
`readers`/`writers` 是打开的读/写端计数。`PIPE_SIZE=4096`,满在 4095
(`space = 4096-1-len`,kvfs.py:135)。

### 4.1 阻塞、EOF、EPIPE 全在 read/write 的返回值里编码

- **`Pipe.read(n)`**(kvfs.py:139):有数据 → 返回并从缓冲头删掉;无数据但
  `writers>0` → 返回 `None`(**调用方应阻塞**);无数据且 `writers==0` → 返回
  `b""`(**写端全关 = EOF**)。
- **`Pipe.write(data)`**(kvfs.py:149):`readers==0` → 抛 `FsError(EPIPE)`
  (**读端全关**);缓冲满(`space<=0`)→ 返回 `None`(**调用方应阻塞**);否则
  写入至多 `space` 字节,返回实际写入数(部分写)。

内核把这三态翻成动作:`None`→抛 `Blocked` 把进程挂到 `wait_channel`;`b""`→
读到 0 字节(EOF);`EPIPE`→ 变 `-EPIPE` 返回(通常再触发 SIGPIPE)。

### 4.2 读写端为何按**描述符**计数,而非 OpenFile.refs

这是整个子系统最易踩的坑(CLAUDE.md 亦列为回归点)。`sys_pipe`(kernel.py:888)
建管道时 `readers=writers=1`。计数的增减挂在 fd 的获取/释放上,而不是 OpenFile
的引用计数:

- **`_acquire_fd(f)`**(kernel.py:863):`f.refs += 1`;若 `f.obj` 是 Pipe,
  按 `f` 的读/写能力给 `readers`/`writers` **各 +1**。fork/dup/dup2 都走它。
- **`_release_file(f)`**(kernel.py:873):Pipe 情形**每关一个描述符就减一次**,
  `max(...-1,0)`;VInode 情形才等 `refs<=0` 再减 `open_refs`。

为什么必须按描述符:fork 出来的父子描述符**共享同一个 OpenFile**(refs 不归零),
若按 refs 判,`ls | cat` 里 `ls` 那侧 fork 后的写端永远关不掉,`cat` 就永远等不到
EOF —— **流水线死锁**。按描述符计数,每个进程关掉自己那份写端 fd 都实打实减 1,
最后一个写端 close 时 `writers` 才归 0,读端才见 EOF。

### 4.3 与调度器 `wait_channel` 的配合(kernel.py:1304)

`wait_channel` 存 `("piperead"/"pipewrite", pipe)` 元组。`_wake_waiters`
逐个检查睡眠进程:

- `piperead`:`pipe.buf` 非空**或** `writers==0`(有数据 or EOF)→ 唤醒;
- `pipewrite`:`pipe.space>0`**或** `readers==0`(有空位 or 该收 EPIPE)→ 唤醒。

唤醒后进程重做被回卷的 `int 0x80`,再次调 `Pipe.read/write`,这次拿到数据/
空位/EOF/EPIPE。

---

## 5. 设备表(kernel.py:606)

`/dev` 下的设备节点在覆盖层里就是普通 VInode,只是 `rdev` 记着
`(major<<8)|minor`(`devno`,kvfs.py:119)。`sys_open` 发现 `v.is_device`
(kvfs.py:111,字符或块)时改调 `_open_device` 把 VInode 换成实际设备对象:

| major, minor | 设备 | 返回的 obj |
|---|---|---|
| major ∈ {4,5} | `/dev/tty*`、`/dev/console` 类 | 宿主终端(无终端时退回 VInode) |
| (1,3) | `/dev/null` | `NullDevice()`(kernel.py:1415) |
| major == 3 | 硬盘 `/dev/hd*` | 拒绝:`EPERM`(不许直接访问块设备) |
| 其它 | | `ENXIO` |

### 5.1 为什么**不检查** b/c 类型(kernel.py:609)

真机上字符设备与块设备走不同分派,但**这个镜像里 `/dev/null` 被误建成了块
设备**(S_IFBLK)。若严格按 b/c 分派,`echo … > /dev/null`、shell 里大量
`2>/dev/null` 会全部失败。所以 `_open_device` 只看 `(major,minor)`,不看
S_ISCHR/S_ISBLK —— 这是对镜像瑕疵的**刻意**让步(CLAUDE.md 记录:无
`/dev/console`、`/dev/null` 被误建为块设备)。

`NullDevice`(kernel.py:1415)读恒返回 `b""`(EOF)、写恒吞下并报告全部写完。
`sys_read`/`sys_write` 对它有快路径(kernel.py:692、717),不进 VInode/Pipe 分支。

---

## 6. 统计与导入导出

覆盖层向 monitor 和 CLI 暴露"改了什么":

- **`overlay_stats()`**(kvfs.py:544):遍历 `vnodes`,数 `cow_files`(有
  `data`)、`cow_dirs`(有 `entries`)、`new_inodes`(`base is None`)、
  `deleted`、内存字节数、`next_ino`、`tracked` —— 供 `info fs`。
- **`changed_paths()`**(kvfs.py:492):先 `_changed_inodes`(kvfs.py:478,把
  每个动过的 inode 归类"新建/改过的文件/改过的目录/已删除"),再从根 DFS 遍历
  目录树反查当前真实路径;**已从目录树消失的项**(删掉的、改名走的)用 `names`
  里记的 `(父ino,名字)` 兜底拼路径(`_remember`,kvfs.py:337)。返回
  `[(路径,类型,ino,大小)]`。
- **`export_changes()`** / **`import_changes()`**(kvfs.py:565 / 582):把动过的
  VInode 序列化成 dict(含 data/entries/元数据/deleted/from_base),
  `--save-overlay` 用 pickle 落盘(emulator.py:172),`--load-overlay` 载回
  (emulator.py:137)。`from_base` 标志决定重建时是包底层 inode 还是造纯新
  inode;完全没动过的透传项(`data`/`entries` 皆 None 且非 deleted)被跳过,
  只存增量。

---

## 7. 一条命令的完整走查:`echo hi > file`

shell 执行 `echo hi > file` 时,`open("file", O_CREAT|O_WRONLY|O_TRUNC, 0666)`
→ 写 `"hi\n"` → close。逐步:

1. **open**(kernel.py:579):`_walk("file")` 抛 `ENOENT`,但带 `O_CREAT`,转
   `fs.create("file", 0666 & ~umask, cwd, root)`(kvfs.py:361)。
2. **create → walk_parent**(kvfs.py:282):解析出父目录(设为 cwd 的 VInode)与
   末段名 `"file"`。`lookup` 确认不存在。
3. **建新 inode**:`_new_inode`(kvfs.py:190)分配 `ino = ninodes+1`,`data=b""`。
4. **落覆盖层根目录**:`_link_entry(parent,"file",v)`(kvfs.py:341)先
   **`_cow_dir(parent)`** —— 这是父目录的首次修改,把它的目录项(含 `.`/`..`
   与原有全部条目)从底层 `read_dir` 拷进 `parent.entries`,然后加
   `entries["file"]=ino`,`v.nlinks=1`。父目录自此"改过的目录"。
5. **回 open**:目标非设备、非目录,`O_TRUNC` 对空新文件无实质动作;建
   `OpenFile(v, O_WRONLY|…)`,`v.open_refs=1`,装进 fd 表返回 fd。
6. **write**(kernel.py:700):obj 是 VInode → `fs.write(v, 0, b"hi\n")`
   (kvfs.py:315)先 **`_cow_file(v)`**(此处 `data` 已是空 `bytearray`,无底层
   可拷),就地写入,`v.mtime` 更新,`f.pos` 推到 3,返回 3。
7. **close**(kernel.py:625):`_release_file`,VInode 情形 `open_refs` 减到 0。

结果:底层镜像一字节没改;覆盖层多了一个新 VInode(`base=None`,`data=b"hi\n"`)
和一个"改过的目录"根。`changed_paths()` 此后会列出 `/file 新建`;`--save-overlay`
会把这两个 inode 存下来。

## 8. 一条流水线的读写端账本:`ls | cat`

shell 建管道跑 `ls | cat`,重点看 `writers` 怎么归零到让 `cat` 见 EOF:

1. **pipe()**(kernel.py:888):建 Pipe,`readers=writers=1`,rfd/wfd 两个
   OpenFile 进 shell 的 fd 表。
2. **fork ls**(kernel.py:777):子进程 fd 表逐项 `_acquire_fd`(kernel.py:863),
   Pipe 的 rfd 令 `readers→2`、wfd 令 `writers→2`。
3. **fork cat**:同理 `readers→3`、`writers→3`。
4. **shell close 两端**:`readers→2`、`writers→2`。
5. **ls**:`dup2(wfd,1)` 令 `writers→3`,随后关掉自己的 rfd(`readers→2`)与
   原 wfd(`writers→2`);写完退出,close 剩下的写端 → `writers→1`。
6. **cat**:`dup2(rfd,0)`,关掉自己的写端 → `writers→0`(仅剩 ls 那份已随退出
   关闭)。此后 `cat` 的 `read` 命中 `Pipe.read` 的 `writers==0` 分支返回
   `b""` —— **EOF**,`cat` 收尾退出。

每一步的增减都落在**描述符**上(第 4.2 节),而非 OpenFile.refs;fork 出来的
写端描述符被各自 close 后 `writers` 才真正归零,`cat` 才不会永远阻塞。

---

## 9. 设计取舍

- **inode 级 vs 路径级覆盖**:选 inode 级(kvfs.py:7)保住硬链接、打开后 unlink、
  原始 dirent、chroot 四类语义;代价是要维护 `vnodes` 缓存与 `next_ino` 分配。
- **惰性一次性 COW vs 预拷贝**:只在首次写触发 `_cow_file`/`_cow_dir`,读永远
  透传底层。绝大多数进程只读镜像,内存占用只随真正改动增长。
- **三态编码(数据/None/EOF)vs 抛异常**:`Pipe.read/write` 用返回值区分
  "有货/该阻塞/EOF-EPIPE",把阻塞决策留给内核的 `Blocked` + `wait_channel`,
  管道对象本身无进程概念,好测。
- **读写端按描述符计数 vs 按 OpenFile.refs**:必须按描述符(kernel.py:867),
  否则 fork 后共享 OpenFile 使写端关不掉、流水线死锁 —— 有回归测试守着。
- **设备不检查 b/c 类型**:对镜像把 `/dev/null` 误建为块设备的瑕疵让步
  (kernel.py:609),按 `(major,minor)` 分派,牺牲严格性换可用性。
- **只读底层零改动**:`minixfs.py` 全程不被覆盖层修改,镜像文件永不写 —— 所有
  可写状态都在内存 VInode 里,可整体 pickle 导出/导入。

---

## 附:关键函数索引

| 环节 | 函数 | 位置 |
|---|---|---|
| 虚拟 inode | `VInode` / `from_base` / `size` | kvfs.py:57 / 80 / 86 |
| 覆盖层 | `OverlayFS` / `get` / `_new_inode` | kvfs.py:163 / 179 / 190 |
| COW | `_cow_file` / `_cow_dir` | kvfs.py:204 / 213 |
| 目录读取 | `list_dir` / `readdir_raw` / `lookup` | kvfs.py:227 / 235 / 247 |
| 路径解析 | `walk` / `walk_parent` | kvfs.py:260 / 282 |
| 内容读写 | `read` / `write` / `truncate` | kvfs.py:305 / 315 / 325 |
| 目录项底座 | `_link_entry` / `_unlink_entry` | kvfs.py:341 / 347 |
| 目录命令 | `create` / `mknod` / `mkdir` / `rmdir` / `unlink` / `link` / `rename` | kvfs.py:361 / 371 / 383 / 400 / 415 / 424 / 433 |
| 元数据 | `chmod` / `chown` / `stat_tuple` | kvfs.py:458 / 461 / 470 |
| 统计导出 | `changed_paths` / `overlay_stats` / `export_changes` / `import_changes` | kvfs.py:492 / 544 / 565 / 582 |
| 管道对象 | `Pipe.read` / `Pipe.write` | kvfs.py:139 / 149 |
| 打开文件描述 | `OpenFile` | kernel.py:54 |
| 打开/分派 | `sys_open` / `_open_device` | kernel.py:579 / 606 |
| 读写分派 | `sys_read` / `sys_write` | kernel.py:676 / 700 |
| 描述符计数 | `_acquire_fd` / `_release_file` | kernel.py:863 / 873 |
| 建管道 | `sys_pipe` | kernel.py:888 |
| 唤醒 | `_wake_waiters` | kernel.py:1304 |
| 空设备 | `NullDevice` | kernel.py:1415 |
