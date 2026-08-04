"""Minix v1 文件系统只读解析库(Linux 0.11 时代的 minix fs).

磁盘布局(块大小 1024 字节):
    块 0            引导块
    块 1            超级块
    块 2 ..         inode 位图 (s_imap_blocks 块)
    ..              zone 位图 (s_zmap_blocks 块)
    ..              inode 表 (每块 32 个 inode, 每个 32 字节)
    s_firstdatazone 数据区

inode 的 9 个 zone 指针: 前 7 个直接块, zone[7] 一级间接块,
zone[8] 二级间接块; 间接块内是 512 个 16 位 zone 号.
"""

from __future__ import annotations

import stat as _stat
import struct
import time
from dataclasses import dataclass
from typing import BinaryIO, Iterator, List, Optional, Tuple

BLOCK_SIZE = 1024
INODE_SIZE = 32
INODES_PER_BLOCK = BLOCK_SIZE // INODE_SIZE
ZONES_PER_BLOCK = BLOCK_SIZE // 2  # 512 个 16 位 zone 号

MINIX_MAGIC_14 = 0x137F  # 文件名 14 字节
MINIX_MAGIC_30 = 0x138F  # 文件名 30 字节

ROOT_INODE = 1

SECTOR_SIZE = 512
MBR_PART_TABLE_OFFSET = 0x1BE
MBR_SIGNATURE_OFFSET = 0x1FE


class MinixError(Exception):
    """Minix 文件系统解析错误."""


@dataclass
class SuperBlock:
    ninodes: int          # inode 总数
    nzones: int           # zone 总数
    imap_blocks: int      # inode 位图占用块数
    zmap_blocks: int      # zone 位图占用块数
    firstdatazone: int    # 第一个数据 zone 号
    log_zone_size: int    # zone 大小 = 1024 << log_zone_size
    max_size: int         # 单文件最大字节数
    magic: int

    @classmethod
    def parse(cls, raw: bytes) -> "SuperBlock":
        fields = struct.unpack_from("<HHHHHHIH", raw, 0)
        sb = cls(*fields)
        if sb.magic not in (MINIX_MAGIC_14, MINIX_MAGIC_30):
            raise MinixError(f"超级块 magic 无效: {sb.magic:#06x}")
        if sb.log_zone_size != 0:
            raise MinixError("仅支持 log_zone_size == 0 的镜像")
        return sb

    @property
    def name_len(self) -> int:
        return 14 if self.magic == MINIX_MAGIC_14 else 30

    @property
    def dirent_size(self) -> int:
        return 2 + self.name_len

    @property
    def inode_table_block(self) -> int:
        return 2 + self.imap_blocks + self.zmap_blocks


@dataclass
class Inode:
    num: int
    mode: int      # 类型 + 权限位
    uid: int
    size: int
    mtime: int     # minix v1 只有一个时间戳
    gid: int
    nlinks: int
    zones: Tuple[int, ...]  # 9 个 zone 指针

    STRUCT = struct.Struct("<HHIIBB9H")

    @classmethod
    def parse(cls, num: int, raw: bytes) -> "Inode":
        mode, uid, size, mtime, gid, nlinks, *zones = cls.STRUCT.unpack(raw)
        return cls(num, mode, uid, size, mtime, gid, nlinks, tuple(zones))

    @property
    def is_dir(self) -> bool:
        return _stat.S_ISDIR(self.mode)

    @property
    def is_regular(self) -> bool:
        return _stat.S_ISREG(self.mode)

    @property
    def is_chardev(self) -> bool:
        return _stat.S_ISCHR(self.mode)

    @property
    def is_blockdev(self) -> bool:
        return _stat.S_ISBLK(self.mode)

    @property
    def is_device(self) -> bool:
        return self.is_chardev or self.is_blockdev

    @property
    def is_fifo(self) -> bool:
        return _stat.S_ISFIFO(self.mode)

    @property
    def is_symlink(self) -> bool:
        return _stat.S_ISLNK(self.mode)

    @property
    def devno(self) -> Tuple[int, int]:
        """设备节点的 (major, minor), 存放在 zone[0]."""
        return self.zones[0] >> 8, self.zones[0] & 0xFF

    @property
    def type_name(self) -> str:
        if self.is_dir:
            return "directory"
        if self.is_regular:
            return "regular file"
        if self.is_chardev:
            return "character special file"
        if self.is_blockdev:
            return "block special file"
        if self.is_fifo:
            return "fifo"
        if self.is_symlink:
            return "symbolic link"
        return "unknown"

    def mode_string(self) -> str:
        """ls -l 风格的权限串, 如 drwxr-xr-x."""
        type_chars = {
            _stat.S_IFDIR: "d", _stat.S_IFCHR: "c", _stat.S_IFBLK: "b",
            _stat.S_IFREG: "-", _stat.S_IFIFO: "p", _stat.S_IFLNK: "l",
        }
        out = [type_chars.get(_stat.S_IFMT(self.mode), "?")]
        for shift, (r, w, x) in ((6, "rwx"), (3, "rwx"), (0, "rwx")):
            bits = self.mode >> shift
            out.append(r if bits & 4 else "-")
            out.append(w if bits & 2 else "-")
            out.append(x if bits & 1 else "-")
        # setuid/setgid/sticky
        if self.mode & _stat.S_ISUID:
            out[3] = "s" if out[3] == "x" else "S"
        if self.mode & _stat.S_ISGID:
            out[6] = "s" if out[6] == "x" else "S"
        if self.mode & _stat.S_ISVTX:
            out[9] = "t" if out[9] == "x" else "T"
        return "".join(out)

    def mtime_string(self) -> str:
        return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(self.mtime))


def find_minix_partition_offset(fp: BinaryIO) -> int:
    """确定文件系统起始字节偏移.

    先尝试偏移 0(裸文件系统镜像); 失败则解析 MBR 分区表,
    依次尝试各分区起始位置, 优先 Minix 分区类型(0x80/0x81).
    """
    def has_magic(offset: int) -> bool:
        fp.seek(offset + BLOCK_SIZE)
        raw = fp.read(BLOCK_SIZE)
        if len(raw) < 18:
            return False
        magic = struct.unpack_from("<H", raw, 16)[0]
        return magic in (MINIX_MAGIC_14, MINIX_MAGIC_30)

    if has_magic(0):
        return 0

    fp.seek(0)
    mbr = fp.read(SECTOR_SIZE)
    if len(mbr) == SECTOR_SIZE and mbr[MBR_SIGNATURE_OFFSET:MBR_SIGNATURE_OFFSET + 2] == b"\x55\xaa":
        candidates = []
        for i in range(4):
            entry = mbr[MBR_PART_TABLE_OFFSET + i * 16: MBR_PART_TABLE_OFFSET + (i + 1) * 16]
            ptype = entry[4]
            start_lba = struct.unpack_from("<I", entry, 8)[0]
            if ptype != 0 and start_lba != 0:
                # 0x80/0x81 是老式 Minix 分区类型, 排前面
                candidates.append((0 if ptype in (0x80, 0x81) else 1, start_lba))
        for _, start_lba in sorted(candidates):
            offset = start_lba * SECTOR_SIZE
            if has_magic(offset):
                return offset

    raise MinixError("未找到 Minix v1 文件系统(偏移 0 及 MBR 各分区均无有效 magic)")


class MinixFS:
    """Minix v1 文件系统的只读访问."""

    def __init__(self, fp: BinaryIO, offset: Optional[int] = None):
        self.fp = fp
        self.offset = find_minix_partition_offset(fp) if offset is None else offset
        self.sb = SuperBlock.parse(self.read_block(1))

    @classmethod
    def open(cls, path: str, offset: Optional[int] = None) -> "MinixFS":
        return cls(open(path, "rb"), offset)

    def close(self) -> None:
        self.fp.close()

    def __enter__(self) -> "MinixFS":
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    # ---- 底层块访问 -------------------------------------------------

    def read_block(self, block: int) -> bytes:
        if block == 0:
            return b"\x00" * BLOCK_SIZE  # 空洞
        self.fp.seek(self.offset + block * BLOCK_SIZE)
        data = self.fp.read(BLOCK_SIZE)
        if len(data) < BLOCK_SIZE:
            data += b"\x00" * (BLOCK_SIZE - len(data))
        return data

    # ---- inode ------------------------------------------------------

    def get_inode(self, num: int) -> Inode:
        if not 1 <= num <= self.sb.ninodes:
            raise MinixError(f"inode 号越界: {num} (有效范围 1..{self.sb.ninodes})")
        block = self.sb.inode_table_block + (num - 1) // INODES_PER_BLOCK
        off = ((num - 1) % INODES_PER_BLOCK) * INODE_SIZE
        raw = self.read_block(block)[off:off + INODE_SIZE]
        return Inode.parse(num, raw)

    @property
    def root(self) -> Inode:
        return self.get_inode(ROOT_INODE)

    def inode_allocated(self, num: int) -> bool:
        """查 inode 位图判断该 inode 是否已分配."""
        if not 1 <= num <= self.sb.ninodes:
            raise MinixError(f"inode 号越界: {num} (有效范围 1..{self.sb.ninodes})")
        bmap = self.read_block(2 + num // (BLOCK_SIZE * 8))
        byte = bmap[(num % (BLOCK_SIZE * 8)) // 8]
        return bool(byte & (1 << (num % 8)))

    # ---- 位图统计 -----------------------------------------------------

    def _count_bitmap(self, start_block: int, nblocks: int, nbits: int) -> int:
        """统计位图中第 1..nbits 位里已置位的个数.

        位 0 保留(恒为 1), 有效范围之后的填充位(mkfs 置 1)不计入.
        """
        data = b"".join(self.read_block(start_block + i) for i in range(nblocks))
        count = 0
        for i in range(1, nbits + 1):
            if data[i >> 3] & (1 << (i & 7)):
                count += 1
        return count

    def fs_stats(self) -> dict:
        """整个文件系统的使用统计.

        inode 位图第 i 位对应 inode i;
        zone 位图第 i 位(i>=1)对应 zone firstdatazone + i - 1,
        数据 zone 总数 = nzones - firstdatazone.
        """
        sb = self.sb
        total_zones = sb.nzones - sb.firstdatazone
        return {
            "total_inodes": sb.ninodes,
            "used_inodes": self._count_bitmap(2, sb.imap_blocks, sb.ninodes),
            "total_zones": total_zones,
            "used_zones": self._count_bitmap(2 + sb.imap_blocks,
                                             sb.zmap_blocks, total_zones),
        }

    def zone_allocated(self, zone: int) -> bool:
        """查 zone 位图判断该数据 zone 是否已分配."""
        if not self.sb.firstdatazone <= zone < self.sb.nzones:
            raise MinixError(f"zone 号越界: {zone}")
        bit = zone - self.sb.firstdatazone + 1
        bmap = self.read_block(2 + self.sb.imap_blocks + bit // (BLOCK_SIZE * 8))
        byte = bmap[(bit % (BLOCK_SIZE * 8)) // 8]
        return bool(byte & (1 << (bit % 8)))

    # ---- 数据 zone 映射与文件读取 ------------------------------------

    def zone_at(self, inode: Inode, index: int) -> int:
        """文件内第 index 个块对应的 zone 号, 0 表示空洞."""
        if index < 7:
            return inode.zones[index]
        index -= 7
        if index < ZONES_PER_BLOCK:
            ind = inode.zones[7]
            if ind == 0:
                return 0
            return struct.unpack_from("<H", self.read_block(ind), index * 2)[0]
        index -= ZONES_PER_BLOCK
        if index < ZONES_PER_BLOCK * ZONES_PER_BLOCK:
            dbl = inode.zones[8]
            if dbl == 0:
                return 0
            ind = struct.unpack_from("<H", self.read_block(dbl),
                                     (index // ZONES_PER_BLOCK) * 2)[0]
            if ind == 0:
                return 0
            return struct.unpack_from("<H", self.read_block(ind),
                                      (index % ZONES_PER_BLOCK) * 2)[0]
        raise MinixError(f"块索引超出 minix v1 上限: {index}")

    def iter_blocks(self, inode: Inode) -> Iterator[bytes]:
        nblocks = (inode.size + BLOCK_SIZE - 1) // BLOCK_SIZE
        for i in range(nblocks):
            yield self.read_block(self.zone_at(inode, i))

    def read_file(self, inode: Inode, offset: int = 0, length: Optional[int] = None) -> bytes:
        """读取文件内容, 空洞按 0 填充."""
        if inode.is_dir or inode.is_regular or inode.is_symlink:
            pass
        else:
            raise MinixError(f"inode {inode.num} 不是可读取内容的类型 ({inode.type_name})")
        if length is None:
            length = inode.size - offset
        end = min(inode.size, offset + max(length, 0))
        if offset >= end:
            return b""
        chunks = []
        block = offset // BLOCK_SIZE
        pos = block * BLOCK_SIZE
        while pos < end:
            data = self.read_block(self.zone_at(inode, block))
            chunks.append(data[max(offset - pos, 0):end - pos])
            block += 1
            pos += BLOCK_SIZE
        return b"".join(chunks)

    # ---- 目录 --------------------------------------------------------

    def read_dir(self, inode: Inode) -> List[Tuple[int, str]]:
        """返回目录项列表 [(inode_num, name), ...], 跳过已删除项."""
        if not inode.is_dir:
            raise MinixError(f"inode {inode.num} 不是目录")
        raw = self.read_file(inode)
        entries = []
        esize = self.sb.dirent_size
        for off in range(0, len(raw) - esize + 1, esize):
            ino = struct.unpack_from("<H", raw, off)[0]
            if ino == 0:
                continue
            name = raw[off + 2:off + esize].split(b"\x00", 1)[0]
            entries.append((ino, name.decode("latin-1")))
        return entries

    def dir_lookup(self, dir_inode: Inode, name: str) -> Optional[Inode]:
        for ino, ename in self.read_dir(dir_inode):
            if ename == name:
                return self.get_inode(ino)
        return None

    def resolve(self, path: str, cwd: Optional[Inode] = None) -> Inode:
        """把路径解析为 inode. 绝对路径从根开始, 相对路径从 cwd 开始."""
        cur = self.root if (cwd is None or path.startswith("/")) else cwd
        for part in path.split("/"):
            if part in ("", "."):
                continue
            if not cur.is_dir:
                raise MinixError(f"不是目录: 无法在其中查找 '{part}'")
            nxt = self.dir_lookup(cur, part)
            if nxt is None:
                raise MinixError(f"路径不存在: '{part}'")
            cur = nxt
        return cur


# ---------------------------------------------------------------------------
# 文件系统一致性检查 (fsck)
# ---------------------------------------------------------------------------

@dataclass
class FsckProblem:
    path: str      # 首次发现该 inode 的路径; 全局性问题为 "-"
    inode: int     # 相关 inode 号; 全局性问题为 0
    message: str

    def __str__(self) -> str:
        if self.inode:
            return f"{self.path} (inode {self.inode}): {self.message}"
        return self.message


@dataclass
class FsckReport:
    problems: List[FsckProblem]
    inodes_checked: int
    zones_checked: int

    @property
    def clean(self) -> bool:
        return not self.problems


def check_fs(fs: MinixFS) -> FsckReport:
    """遍历全部目录与文件, 做一致性检查.

    检查项:
      1. 每个 inode 的 size 与实际引用的数据块个数是否一致
         (含越过文件末尾的数据块与空洞);
      2. 目录树中引用的 inode 是否都在 inode 位图中标记为已分配,
         以及位图已分配却未被任何目录引用的孤儿 inode;
      3. 每个数据块/间接块的 zone 号是否合法, 是否都在 zone 位图中
         标记为已用, 是否被多个文件重复引用, 以及位图已用却未被
         任何 inode 引用的丢失块.
    """
    sb = fs.sb
    problems: List[FsckProblem] = []

    # 位图整体读入内存, 避免逐位读盘
    imap = b"".join(fs.read_block(2 + i) for i in range(sb.imap_blocks))
    zmap = b"".join(fs.read_block(2 + sb.imap_blocks + i)
                    for i in range(sb.zmap_blocks))

    def ibit(num: int) -> bool:
        return bool(imap[num >> 3] & (1 << (num & 7)))

    def zbit(zone: int) -> bool:
        bit = zone - sb.firstdatazone + 1
        return bool(zmap[bit >> 3] & (1 << (bit & 7)))

    def collect_zones(inode: Inode):
        """枚举 inode 引用的所有 zone.

        返回 (data, meta): data 是 [(文件内块索引, zone)], meta 是
        [(描述, zone)] 的间接块自身. 越界的间接块不再向下展开.
        """
        data, meta = [], []

        def valid(z):
            return sb.firstdatazone <= z < sb.nzones

        for i in range(7):
            if inode.zones[i]:
                data.append((i, inode.zones[i]))
        ind = inode.zones[7]
        if ind:
            meta.append(("一级间接块", ind))
            if valid(ind):
                for j, z in enumerate(struct.unpack(f"<{ZONES_PER_BLOCK}H",
                                                    fs.read_block(ind))):
                    if z:
                        data.append((7 + j, z))
        dbl = inode.zones[8]
        if dbl:
            meta.append(("二级间接块", dbl))
            if valid(dbl):
                for j, z in enumerate(struct.unpack(f"<{ZONES_PER_BLOCK}H",
                                                    fs.read_block(dbl))):
                    if not z:
                        continue
                    meta.append((f"二级间接的下级块[{j}]", z))
                    if valid(z):
                        base = 7 + ZONES_PER_BLOCK + j * ZONES_PER_BLOCK
                        for k, z2 in enumerate(
                                struct.unpack(f"<{ZONES_PER_BLOCK}H",
                                              fs.read_block(z))):
                            if z2:
                                data.append((base + k, z2))
        return data, meta

    zone_owner = {}          # zone -> (path, inode_num)
    referenced = {}          # inode_num -> 首次引用路径
    checked = set()          # 已做过内容检查的 inode

    def check_inode(path: str, inode: Inode) -> None:
        """对单个 inode 做 zone 合法性 / 位图 / size 一致性检查."""
        if inode.is_device or inode.is_fifo:
            return  # zones[0] 是设备号, 无数据块
        data, meta = collect_zones(inode)

        for desc, zone, is_meta in ([(f"数据块[{i}]", z, False) for i, z in data]
                                    + [(d, z, True) for d, z in meta]):
            if not sb.firstdatazone <= zone < sb.nzones:
                problems.append(FsckProblem(
                    path, inode.num,
                    f"{desc} zone 号非法: {zone} (有效范围 "
                    f"{sb.firstdatazone}..{sb.nzones - 1})"))
                continue
            if not zbit(zone):
                problems.append(FsckProblem(
                    path, inode.num, f"{desc} zone {zone} 未在 zone 位图中标记为已用"))
            if zone in zone_owner:
                opath, oino = zone_owner[zone]
                problems.append(FsckProblem(
                    path, inode.num,
                    f"{desc} zone {zone} 与 {opath} (inode {oino}) 重复引用"))
            else:
                zone_owner[zone] = (path, inode.num)

        expected = (inode.size + BLOCK_SIZE - 1) // BLOCK_SIZE
        beyond = [i for i, _ in data if i >= expected]
        if len(data) != expected or beyond:
            msg = (f"size 与数据块数不一致: size={inode.size} 应占 "
                   f"{expected} 块, 实际引用 {len(data)} 块")
            if beyond:
                msg += f", 其中 {len(beyond)} 块越过文件末尾"
            elif len(data) < expected:
                msg += f" (存在 {expected - len(data)} 个空洞)"
            problems.append(FsckProblem(path, inode.num, msg))

        if inode.is_dir and inode.size % sb.dirent_size:
            problems.append(FsckProblem(
                path, inode.num,
                f"目录 size {inode.size} 不是目录项大小 {sb.dirent_size} 的整数倍"))

    # ---- 从根开始遍历目录树 ----
    stack = [("/", ROOT_INODE)]
    referenced[ROOT_INODE] = "/"
    while stack:
        dpath, dnum = stack.pop()
        dnode = fs.get_inode(dnum)
        if dnum not in checked:
            checked.add(dnum)
            if not ibit(dnum):
                problems.append(FsckProblem(
                    dpath, dnum, "inode 未在 inode 位图中标记为已分配"))
            check_inode(dpath, dnode)
        for ino, name in fs.read_dir(dnode):
            epath = (dpath.rstrip("/") + "/" + name) if name not in (".", "..") \
                else dpath
            if not 1 <= ino <= sb.ninodes:
                problems.append(FsckProblem(
                    epath, ino, f"目录项 '{name}' 的 inode 号越界"))
                continue
            referenced.setdefault(ino, epath)
            if name in (".", ".."):
                continue
            child = fs.get_inode(ino)
            if child.is_dir:
                if ino not in checked:
                    stack.append((epath, ino))
            elif ino not in checked:
                checked.add(ino)
                if not ibit(ino):
                    problems.append(FsckProblem(
                        epath, ino, "inode 未在 inode 位图中标记为已分配"))
                if not (child.is_regular or child.is_device or child.is_fifo
                        or child.is_symlink):
                    problems.append(FsckProblem(
                        epath, ino, f"未知的文件类型 mode={child.mode:#06x}"))
                check_inode(epath, child)

    # ---- 全局反向检查: 孤儿 inode 与丢失 zone ----
    for i in range(1, sb.ninodes + 1):
        if ibit(i) and i not in referenced:
            node = fs.get_inode(i)
            if node.mode or node.nlinks or node.size:
                problems.append(FsckProblem(
                    "-", i, f"inode 在位图中已分配但未被任何目录引用"
                            f"(孤儿 inode, mode={node.mode:#06x}, "
                            f"size={node.size}, nlinks={node.nlinks})"))
            else:
                problems.append(FsckProblem(
                    "-", i, "inode 在位图中已分配但内容全零"
                            "(位图泄漏; 若为最后一个 inode, 多半是老 mkfs "
                            "位图填充的差一问题)"))
    lost = [z for z in range(sb.firstdatazone, sb.nzones)
            if zbit(z) and z not in zone_owner]
    if lost:
        head = ", ".join(map(str, lost[:10]))
        more = f" 等共 {len(lost)} 个" if len(lost) > 10 else ""
        problems.append(FsckProblem(
            "-", 0, f"{len(lost)} 个 zone 在位图中已用但未被任何 inode 引用"
                    f"(丢失块): {head}{more}"))

    return FsckReport(problems, len(checked), len(zone_owner))
