"""覆盖式虚拟文件层.

把只读的 minixfs.MinixFS 包起来, 在内存里叠加一层可写视图:
读未改动的内容直接透传底层镜像, 首次写入时把整个文件/目录复制到内存
(copy-on-write)。**镜像文件本身永不被修改**。

选 inode 级而非路径级(`dict[path] -> bytes`)覆盖, 因为路径级有四个破绽:
① 硬链接与 rename 语义破碎(镜像里 /bin/sh 与 /bin/bash 正是同一 inode);
② 已打开再 unlink 的文件会失效(shell 重定向临时文件要用);
③ Linux 0.11 的 opendir 直接 read 目录 fd 拿原始 dirent 字节, 路径级
   没有 inode 号可填;
④ chroot 与 `..` 只能靠字符串规范化, 易错。
"""

from __future__ import annotations

import stat as _stat
import struct
import time
from typing import Dict, List, Optional, Tuple

from minixfs import BLOCK_SIZE, Inode, MinixError, MinixFS

# errno(取自镜像 /usr/include/errno.h)
EPERM, ENOENT, ESRCH, EINTR, EIO, ENXIO, E2BIG, ENOEXEC, EBADF, ECHILD = range(1, 11)
EAGAIN, ENOMEM, EACCES, EFAULT, ENOTBLK, EBUSY, EEXIST, EXDEV, ENODEV = range(11, 20)
ENOTDIR, EISDIR, EINVAL, ENFILE, EMFILE, ENOTTY, ETXTBSY, EFBIG = range(20, 28)
ENOSPC, ESPIPE, EROFS, EMLINK, EPIPE = range(28, 33)
ERANGE = 34
ENOSYS = 38
ENOTEMPTY = 39

# open 标志(取自镜像 /usr/include/fcntl.h)
O_RDONLY, O_WRONLY, O_RDWR = 0, 1, 2
O_ACCMODE = 3
O_CREAT = 0o100
O_EXCL = 0o200
O_NOCTTY = 0o400
O_TRUNC = 0o1000
O_APPEND = 0o2000
O_NONBLOCK = 0o4000

PIPE_SIZE = 4096          # 内核 include/linux/fs.h: 管道一页, 满在 4095
NAME_LEN = 14             # magic 0x137F 的目录项名长
DIRENT_SIZE = 16
ROOT_DEV = 0x0301         # /dev/hd1, /etc/mtab 里的根设备


class FsError(Exception):
    """带 errno 的文件系统错误, 系统调用层转成 -errno 返回."""

    def __init__(self, errno: int, msg: str = ""):
        super().__init__(msg or f"errno={errno}")
        self.errno = errno


class VInode:
    """虚拟 inode: 未改动时透传底层, 改动后内容在内存里."""

    __slots__ = ("ino", "mode", "uid", "gid", "nlinks", "mtime", "rdev",
                 "_size", "data", "entries", "base", "open_refs", "deleted")

    def __init__(self, ino: int, mode: int, uid: int = 0, gid: int = 0,
                 nlinks: int = 1, mtime: int = 0, rdev: int = 0,
                 size: int = 0, base: Optional[Inode] = None):
        self.ino = ino
        self.mode = mode
        self.uid = uid
        self.gid = gid
        self.nlinks = nlinks
        self.mtime = mtime
        self.rdev = rdev
        self._size = size
        self.data: Optional[bytearray] = None      # None = 内容还在底层镜像
        self.entries: Optional[Dict[str, int]] = None   # 目录项, None = 未 COW
        self.base = base
        self.open_refs = 0
        self.deleted = False

    @classmethod
    def from_base(cls, inode: Inode) -> "VInode":
        rdev = inode.zones[0] if inode.is_device else 0
        return cls(inode.num, inode.mode, inode.uid, inode.gid, inode.nlinks,
                   inode.mtime, rdev, inode.size, base=inode)

    @property
    def size(self) -> int:
        if self.data is not None:
            return len(self.data)
        if self.entries is not None:
            return len(self.entries) * DIRENT_SIZE
        return self._size

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
    def devno(self) -> Tuple[int, int]:
        return self.rdev >> 8, self.rdev & 0xFF

    def __repr__(self) -> str:
        kind = "d" if self.is_dir else ("c" if self.is_chardev else "-")
        return f"<VInode {self.ino} {kind} mode={self.mode:#o} size={self.size}>"


class Pipe:
    """管道: 一页环形缓冲, 语义照内核 fs/pipe.c."""

    def __init__(self):
        self.buf = bytearray()
        self.readers = 0
        self.writers = 0

    @property
    def space(self) -> int:
        return PIPE_SIZE - 1 - len(self.buf)

    def read(self, n: int) -> Optional[bytes]:
        """返回数据; 无数据但还有写端时返回 None(调用方应阻塞)."""
        if self.buf:
            out = bytes(self.buf[:n])
            del self.buf[:n]
            return out
        if self.writers == 0:
            return b""                 # 写端全关 -> EOF
        return None

    def write(self, data: bytes) -> Optional[int]:
        """返回写入字节数; 缓冲满时返回 None(调用方应阻塞)."""
        if self.readers == 0:
            raise FsError(EPIPE, "管道读端已全部关闭")
        if not data:
            return 0
        room = self.space
        if room <= 0:
            return None
        chunk = data[:room]
        self.buf.extend(chunk)
        return len(chunk)


class OverlayFS:
    """只读 MinixFS 之上的可写覆盖层."""

    def __init__(self, base: MinixFS):
        self.base = base
        self.vnodes: Dict[int, VInode] = {}
        self.next_ino = base.sb.ninodes + 1        # 新 inode 从镜像上限之后取
        self.root = self.get(1)

    # ---- inode 取用 ---------------------------------------------------

    def get(self, ino: int) -> VInode:
        """取 VInode: 已在覆盖层则返回它, 否则从底层镜像包装一个."""
        v = self.vnodes.get(ino)
        if v is not None:
            return v
        if not 1 <= ino <= self.base.sb.ninodes:
            raise FsError(ENOENT, f"inode 号越界: {ino}")
        v = VInode.from_base(self.base.get_inode(ino))
        self.vnodes[ino] = v
        return v

    def _new_inode(self, mode: int, uid: int = 0, gid: int = 0,
                   rdev: int = 0) -> VInode:
        ino = self.next_ino
        self.next_ino += 1
        if ino > 0xFFFF:
            raise FsError(ENOSPC, "inode 号耗尽(u16 上限)")
        v = VInode(ino, mode, uid, gid, nlinks=0, mtime=int(time.time()),
                   rdev=rdev)
        v.data = bytearray()
        self.vnodes[ino] = v
        return v

    # ---- COW ----------------------------------------------------------

    def _cow_file(self, v: VInode) -> bytearray:
        """首次写入时把整个文件复制进内存."""
        if v.data is None:
            if v.base is not None:
                v.data = bytearray(self.base.read_file(v.base))
            else:
                v.data = bytearray()
        return v.data

    def _cow_dir(self, v: VInode) -> Dict[str, int]:
        """首次修改目录时把目录项复制进内存(含 . 与 ..)."""
        if v.entries is None:
            if not v.is_dir:
                raise FsError(ENOTDIR, f"inode {v.ino} 不是目录")
            if v.base is not None:
                v.entries = {name: ino
                             for ino, name in self.base.read_dir(v.base)}
            else:
                v.entries = {}
        return v.entries

    # ---- 目录读取与查找 -------------------------------------------------

    def list_dir(self, v: VInode) -> List[Tuple[int, str]]:
        """目录项 [(ino, name)], 含 . 与 .."""
        if not v.is_dir:
            raise FsError(ENOTDIR, f"inode {v.ino} 不是目录")
        if v.entries is not None:
            return [(ino, name) for name, ino in v.entries.items()]
        return self.base.read_dir(v.base)

    def readdir_raw(self, v: VInode) -> bytes:
        """原始 dirent 字节 —— 0.11 的 opendir 直接 read 目录 fd 拿这个."""
        if not v.is_dir:
            raise FsError(ENOTDIR, f"inode {v.ino} 不是目录")
        if v.entries is None:
            return self.base.read_file(v.base)
        out = bytearray()
        for name, ino in v.entries.items():
            out += struct.pack("<H", ino & 0xFFFF)
            out += name.encode("latin-1")[:NAME_LEN].ljust(NAME_LEN, b"\x00")
        return bytes(out)

    def lookup(self, dirv: VInode, name: str) -> Optional[VInode]:
        if not dirv.is_dir:
            raise FsError(ENOTDIR, f"inode {dirv.ino} 不是目录")
        if dirv.entries is not None:
            ino = dirv.entries.get(name)
            return self.get(ino) if ino is not None else None
        for ino, ename in self.base.read_dir(dirv.base):
            if ename == name:
                return self.get(ino)
        return None

    # ---- 路径解析 -----------------------------------------------------

    def walk(self, path: str, cwd: Optional[VInode] = None,
             root: Optional[VInode] = None) -> VInode:
        """解析路径为 VInode.

        逻辑与 minixfs.resolve 一致, 但走覆盖层查找并支持 chroot:
        到达 root 时 `..` 不再向上。
        """
        root = root or self.root
        cur = root if (cwd is None or path.startswith("/")) else cwd
        for part in path.split("/"):
            if part in ("", "."):
                continue
            if not cur.is_dir:
                raise FsError(ENOTDIR, f"不是目录: 无法在其中查找 '{part}'")
            if part == ".." and cur.ino == root.ino:
                continue                       # chroot 边界: 越根被挡住
            nxt = self.lookup(cur, part)
            if nxt is None:
                raise FsError(ENOENT, f"路径不存在: '{part}'")
            cur = nxt
        return cur

    def walk_parent(self, path: str, cwd: Optional[VInode] = None,
                    root: Optional[VInode] = None) -> Tuple[VInode, str]:
        """解析到父目录, 返回 (父目录, 末段名). 用于 create/unlink/mkdir."""
        norm = path.rstrip("/")
        if not norm:
            raise FsError(EBUSY, "不能操作根目录本身")
        idx = norm.rfind("/")
        if idx < 0:
            parent = cwd or self.root
            name = norm
        else:
            parent = self.walk(norm[:idx] or "/", cwd, root)
            name = norm[idx + 1:]
        if not parent.is_dir:
            raise FsError(ENOTDIR, "父路径不是目录")
        if not name or name in (".", ".."):
            raise FsError(EINVAL, f"无效的名字: '{name}'")
        if len(name.encode("latin-1")) > NAME_LEN:
            name = name[:NAME_LEN]             # minix v1 名字截断
        return parent, name

    # ---- 文件内容读写 -------------------------------------------------

    def read(self, v: VInode, offset: int, length: int) -> bytes:
        if v.is_dir:
            raw = self.readdir_raw(v)
            return raw[offset:offset + length]
        if v.data is not None:
            return bytes(v.data[offset:offset + length])
        if v.base is None:
            return b""
        return self.base.read_file(v.base, offset, length)

    def write(self, v: VInode, offset: int, data: bytes) -> int:
        if v.is_dir:
            raise FsError(EISDIR, "不能写目录")
        buf = self._cow_file(v)
        if offset > len(buf):
            buf.extend(bytes(offset - len(buf)))      # 空洞补零
        buf[offset:offset + len(data)] = data
        v.mtime = int(time.time())
        return len(data)

    def truncate(self, v: VInode, size: int) -> None:
        if v.is_dir:
            raise FsError(EISDIR, "不能截断目录")
        buf = self._cow_file(v)
        if size < len(buf):
            del buf[size:]
        else:
            buf.extend(bytes(size - len(buf)))
        v.mtime = int(time.time())

    # ---- 目录项操作 ---------------------------------------------------

    def _link_entry(self, parent: VInode, name: str, v: VInode) -> None:
        entries = self._cow_dir(parent)
        entries[name] = v.ino
        v.nlinks += 1
        parent.mtime = int(time.time())

    def _unlink_entry(self, parent: VInode, name: str) -> VInode:
        entries = self._cow_dir(parent)
        ino = entries.get(name)
        if ino is None:
            raise FsError(ENOENT, f"'{name}' 不存在")
        v = self.get(ino)
        del entries[name]
        v.nlinks = max(v.nlinks - 1, 0)
        parent.mtime = int(time.time())
        if v.nlinks == 0 and v.open_refs == 0:
            v.deleted = True                # 已打开的话等 close 时才真正丢弃
        return v

    def create(self, path: str, mode: int, cwd=None, root=None,
               uid: int = 0, gid: int = 0) -> VInode:
        parent, name = self.walk_parent(path, cwd, root)
        if self.lookup(parent, name) is not None:
            raise FsError(EEXIST, f"'{name}' 已存在")
        v = self._new_inode((mode & 0o7777) | _stat.S_IFREG, uid, gid)
        self._link_entry(parent, name, v)
        return v

    def mknod(self, path: str, mode: int, rdev: int, cwd=None, root=None,
              uid: int = 0, gid: int = 0) -> VInode:
        parent, name = self.walk_parent(path, cwd, root)
        if self.lookup(parent, name) is not None:
            raise FsError(EEXIST, f"'{name}' 已存在")
        v = self._new_inode(mode, uid, gid, rdev=rdev)
        if not (v.is_device or v.is_fifo):
            v.data = bytearray()
        self._link_entry(parent, name, v)
        return v

    def mkdir(self, path: str, mode: int, cwd=None, root=None,
              uid: int = 0, gid: int = 0) -> VInode:
        parent, name = self.walk_parent(path, cwd, root)
        if self.lookup(parent, name) is not None:
            raise FsError(EEXIST, f"'{name}' 已存在")
        v = self._new_inode((mode & 0o7777) | _stat.S_IFDIR, uid, gid)
        v.data = None
        v.entries = {}
        # 新目录必须自带 . 与 .. , 否则相对路径解析走不通
        v.entries["."] = v.ino
        v.nlinks += 1
        v.entries[".."] = parent.ino
        parent.nlinks += 1
        self._link_entry(parent, name, v)
        return v

    def rmdir(self, path: str, cwd=None, root=None) -> None:
        parent, name = self.walk_parent(path, cwd, root)
        v = self.lookup(parent, name)
        if v is None:
            raise FsError(ENOENT, f"'{name}' 不存在")
        if not v.is_dir:
            raise FsError(ENOTDIR, f"'{name}' 不是目录")
        entries = self._cow_dir(v)
        if set(entries) - {".", ".."}:
            raise FsError(ENOTEMPTY, f"目录 '{name}' 非空")
        self._unlink_entry(parent, name)
        parent.nlinks = max(parent.nlinks - 1, 0)   # 子目录的 .. 消失
        v.nlinks = 0
        v.deleted = True

    def unlink(self, path: str, cwd=None, root=None) -> None:
        parent, name = self.walk_parent(path, cwd, root)
        v = self.lookup(parent, name)
        if v is None:
            raise FsError(ENOENT, f"'{name}' 不存在")
        if v.is_dir:
            raise FsError(EISDIR, f"'{name}' 是目录, 用 rmdir")
        self._unlink_entry(parent, name)

    def link(self, oldpath: str, newpath: str, cwd=None, root=None) -> None:
        v = self.walk(oldpath, cwd, root)
        if v.is_dir:
            raise FsError(EPERM, "不允许对目录建硬链接")
        parent, name = self.walk_parent(newpath, cwd, root)
        if self.lookup(parent, name) is not None:
            raise FsError(EEXIST, f"'{name}' 已存在")
        self._link_entry(parent, name, v)

    def rename(self, oldpath: str, newpath: str, cwd=None, root=None) -> None:
        oldparent, oldname = self.walk_parent(oldpath, cwd, root)
        v = self.lookup(oldparent, oldname)
        if v is None:
            raise FsError(ENOENT, f"'{oldname}' 不存在")
        newparent, newname = self.walk_parent(newpath, cwd, root)
        existing = self.lookup(newparent, newname)
        if existing is not None:
            if existing.ino == v.ino:
                return                       # 同一 inode, 无操作
            if existing.is_dir:
                self.rmdir(newpath, cwd, root)
            else:
                self._unlink_entry(newparent, newname)
        self._link_entry(newparent, newname, v)
        self._unlink_entry(oldparent, oldname)
        if v.is_dir and oldparent.ino != newparent.ino:
            # 子目录的 .. 要跟着改
            ents = self._cow_dir(v)
            ents[".."] = newparent.ino
            newparent.nlinks += 1
            oldparent.nlinks = max(oldparent.nlinks - 1, 0)

    # ---- 元数据 -------------------------------------------------------

    def chmod(self, v: VInode, mode: int) -> None:
        v.mode = (v.mode & ~0o7777) | (mode & 0o7777)

    def chown(self, v: VInode, uid: int, gid: int) -> None:
        if uid != 0xFFFF:
            v.uid = uid
        if gid != 0xFFFF:
            v.gid = gid

    def utime(self, v: VInode, mtime: int) -> None:
        v.mtime = mtime

    def stat_tuple(self, v: VInode) -> tuple:
        """打包 struct stat 用的字段.

        Minix v1 磁盘 inode 只有一个 mtime, 所以 atime/mtime/ctime 同值。
        """
        return (ROOT_DEV, v.ino, v.mode, v.nlinks, v.uid, v.gid,
                v.rdev, v.size, v.mtime, v.mtime, v.mtime)

    def overlay_stats(self) -> dict:
        """覆盖层用量统计, 供 monitor 的 `info fs` 用."""
        cow_files = cow_dirs = new_inodes = deleted = nbytes = 0
        for v in self.vnodes.values():
            if v.base is None:
                new_inodes += 1
            if v.deleted:
                deleted += 1
            if v.data is not None:
                cow_files += 1
                nbytes += len(v.data)
            if v.entries is not None:
                cow_dirs += 1
                nbytes += len(v.entries) * DIRENT_SIZE
        return {"cow_files": cow_files, "cow_dirs": cow_dirs,
                "new_inodes": new_inodes, "deleted": deleted,
                "bytes": nbytes, "next_ino": self.next_ino,
                "tracked": len(self.vnodes)}

    # ---- 覆盖层导出/导入(--save-overlay) -------------------------------

    def export_changes(self) -> dict:
        """导出被改动的 inode, 供 --save-overlay 持久化."""
        out = {}
        for ino, v in self.vnodes.items():
            if v.data is None and v.entries is None and not v.deleted \
                    and v.base is not None:
                continue                     # 完全没动过
            out[ino] = {
                "mode": v.mode, "uid": v.uid, "gid": v.gid,
                "nlinks": v.nlinks, "mtime": v.mtime, "rdev": v.rdev,
                "deleted": v.deleted,
                "data": bytes(v.data) if v.data is not None else None,
                "entries": dict(v.entries) if v.entries is not None else None,
                "from_base": v.base is not None,
            }
        return {"next_ino": self.next_ino, "vnodes": out}

    def import_changes(self, blob: dict) -> None:
        self.next_ino = max(self.next_ino, blob.get("next_ino", self.next_ino))
        for ino, rec in blob.get("vnodes", {}).items():
            ino = int(ino)
            if rec.get("from_base") and 1 <= ino <= self.base.sb.ninodes:
                v = self.get(ino)
            else:
                v = VInode(ino, rec["mode"])
                self.vnodes[ino] = v
            v.mode = rec["mode"]
            v.uid = rec["uid"]
            v.gid = rec["gid"]
            v.nlinks = rec["nlinks"]
            v.mtime = rec["mtime"]
            v.rdev = rec["rdev"]
            v.deleted = rec["deleted"]
            v.data = bytearray(rec["data"]) if rec["data"] is not None else None
            v.entries = dict(rec["entries"]) if rec["entries"] is not None else None
        self.root = self.get(1)
