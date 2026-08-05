# minixfs — Minix v1 文件系统只读浏览器

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
minixfs.py       解析库: 超级块/inode/目录/文件读取(直接块+一级/二级间接块,
                 空洞补零)、MBR 分区自动探测、位图查询、check_fs 一致性检查
minix_shell.py   基于 cmd.Cmd 的交互层, 只做参数解析与格式化
pager.py         less 风格分页器, 终端尺寸/按键/输出均可注入
test_minixfs.py  单元测试
```

## 测试

```bash
python3 -m unittest test_minixfs
```

测试在内存中程序化构造迷你 minix 镜像(含子目录、设备节点、跨间接块
大文件、稀疏文件), 不依赖真实镜像; `hdc-0.11.img` 存在时会额外运行
集成测试。checkfs 测试通过直接篡改镜像字节注入十余种损坏场景。

## 实现笔记

- 位图为字节顺序 + 字节内 LSB 在前的位序(与 x86 位指令一致), 位 0 保留。
- Minix v1 inode 仅 32 字节, 只有一个时间戳(mtime); 设备号存于 zones[0]。
- 老 mkfs 位图尾部填充存在差一问题, 对真实镜像跑 `checkfs` 会如实报告
  最后一个 inode "位图已分配但内容全零", 属于历史现象而非损坏。
