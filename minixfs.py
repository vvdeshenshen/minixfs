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
