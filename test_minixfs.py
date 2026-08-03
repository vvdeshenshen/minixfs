"""minixfs 库与 minix shell 的单元测试.

测试用镜像由 build_image() 在内存中程序化构造, 无需外部文件;
若工作目录下存在 hdc-0.11.img, 额外跑真实镜像的集成测试.
"""

import io
import os
import struct
import unittest

import minixfs
from minixfs import BLOCK_SIZE, MinixError, MinixFS

IMG_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "hdc-0.11.img")


# ---------------------------------------------------------------------------
# 测试镜像构造
# ---------------------------------------------------------------------------

def _pack_inode(mode, uid, size, mtime, gid, nlinks, zones):
    zones = list(zones) + [0] * (9 - len(zones))
    return struct.pack("<HHIIBB9H", mode, uid, size, mtime, gid, nlinks, *zones)


def _dirent(ino, name):
    return struct.pack("<H", ino) + name.encode().ljust(14, b"\x00")


def build_image():
    """构造迷你 minix v1 镜像.

    布局: 块0 引导 | 块1 超级块 | 块2 inode位图 | 块3 zone位图 |
          块4 inode表 | 块5起 数据区

    内容:
      /            inode 1, 目录
      /hello.txt   inode 2, "Hello, Minix!\n"
      /sub         inode 3, 目录
      /tty         inode 4, 字符设备 4,0
      /big.bin     inode 5, 10 块, 覆盖一级间接块
      /sub/note.txt inode 6
      /sparse.bin  inode 7, 全空洞稀疏文件, 大小落在二级间接区
    """
    nzones = 32
    img = bytearray(nzones * BLOCK_SIZE)

    # 超级块: ninodes=32, imap=1, zmap=1, firstdatazone=5
    struct.pack_into("<HHHHHHIH", img, BLOCK_SIZE,
                     32, nzones, 1, 1, 5, 0, 268966912, minixfs.MINIX_MAGIC_14)

    # inode 位图: inode 0(保留) 和 1..7 已分配
    img[2 * BLOCK_SIZE] = 0xFF

    mtime = 946684800  # 2000-01-01 00:00:00 UTC
    inodes = {
        1: _pack_inode(0o040755, 0, 5 * 16, mtime, 0, 3, [5]),
        2: _pack_inode(0o100644, 10, 14, mtime, 20, 1, [7]),
        3: _pack_inode(0o040700, 0, 3 * 16, mtime, 0, 2, [6]),
        4: _pack_inode(0o020666, 0, 0, mtime, 0, 1, [4 << 8 | 0]),
        5: _pack_inode(0o100755, 0, 10 * BLOCK_SIZE, mtime, 0, 1,
                       [8, 9, 10, 11, 12, 13, 14, 15, 0]),
        6: _pack_inode(0o100600, 1, 6, mtime, 1, 1, [19]),
        # 大小 = 8MB, 数据全在空洞里(zone 指针全 0), 尾块落在二级间接区
        7: _pack_inode(0o100644, 0, 8 * 1024 * 1024, mtime, 0, 1, []),
    }
    for num, raw in inodes.items():
        img[4 * BLOCK_SIZE + (num - 1) * 32: 4 * BLOCK_SIZE + num * 32] = raw

    # 根目录(zone 5)
    root = (_dirent(1, ".") + _dirent(1, "..") + _dirent(2, "hello.txt") +
            _dirent(3, "sub") + _dirent(4, "tty") + _dirent(5, "big.bin") +
            _dirent(7, "sparse.bin"))
    # 根目录 size 写的是 5*16, 故意只覆盖前 5 项之外再补两项 -> 修正 size
    inodes[1] = _pack_inode(0o040755, 0, len(root), mtime, 0, 3, [5])
    img[4 * BLOCK_SIZE: 4 * BLOCK_SIZE + 32] = inodes[1]
    img[5 * BLOCK_SIZE: 5 * BLOCK_SIZE + len(root)] = root

    # /sub 目录(zone 6)
    sub = _dirent(3, ".") + _dirent(1, "..") + _dirent(6, "note.txt")
    img[6 * BLOCK_SIZE: 6 * BLOCK_SIZE + len(sub)] = sub

    # /hello.txt (zone 7)
    img[7 * BLOCK_SIZE: 7 * BLOCK_SIZE + 14] = b"Hello, Minix!\n"

    # /big.bin: 直接块 zone 8..14, 间接块 zone 15 -> 指向 zone 16,17,18
    for i in range(7):
        img[(8 + i) * BLOCK_SIZE:(9 + i) * BLOCK_SIZE] = bytes([i]) * BLOCK_SIZE
    struct.pack_into("<HHH", img, 15 * BLOCK_SIZE, 16, 17, 18)
    for i in range(3):
        img[(16 + i) * BLOCK_SIZE:(17 + i) * BLOCK_SIZE] = bytes([7 + i]) * BLOCK_SIZE

    # /sub/note.txt (zone 19)
    img[19 * BLOCK_SIZE: 19 * BLOCK_SIZE + 6] = b"notes\n"

    return bytes(img)


def build_mbr_image(fs_image, start_sector=2):
    """把裸文件系统镜像包进带 MBR 分区表的磁盘镜像."""
    mbr = bytearray(start_sector * 512)
    # 分区 1: 类型 0x81(minix), 起始扇区 start_sector
    struct.pack_into("<I", mbr, 0x1BE + 8, start_sector)
    mbr[0x1BE + 4] = 0x81
    mbr[0x1FE:0x200] = b"\x55\xaa"
    return bytes(mbr) + fs_image


def open_test_fs(**kwargs):
    return MinixFS(io.BytesIO(build_image()), **kwargs)


# ---------------------------------------------------------------------------
# 核心库测试
# ---------------------------------------------------------------------------

class TestSuperBlock(unittest.TestCase):
    def test_parse(self):
        fs = open_test_fs()
        self.assertEqual(fs.sb.magic, minixfs.MINIX_MAGIC_14)
        self.assertEqual(fs.sb.ninodes, 32)
        self.assertEqual(fs.sb.firstdatazone, 5)
        self.assertEqual(fs.sb.name_len, 14)
        self.assertEqual(fs.sb.dirent_size, 16)
        self.assertEqual(fs.sb.inode_table_block, 4)

    def test_bad_magic(self):
        img = bytearray(build_image())
        img[BLOCK_SIZE + 16] = 0
        with self.assertRaises(MinixError):
            MinixFS(io.BytesIO(bytes(img)), offset=0)


class TestPartitionDetection(unittest.TestCase):
    def test_raw_image_offset_zero(self):
        self.assertEqual(open_test_fs().offset, 0)

    def test_mbr_partition_autodetect(self):
        disk = build_mbr_image(build_image(), start_sector=2)
        fs = MinixFS(io.BytesIO(disk))
        self.assertEqual(fs.offset, 1024)
        self.assertEqual(fs.sb.ninodes, 32)

    def test_no_filesystem(self):
        with self.assertRaises(MinixError):
            MinixFS(io.BytesIO(b"\x00" * 4096))


class TestInode(unittest.TestCase):
    def setUp(self):
        self.fs = open_test_fs()

    def test_root_inode(self):
        root = self.fs.root
        self.assertEqual(root.num, 1)
        self.assertTrue(root.is_dir)
        self.assertEqual(root.mode & 0o777, 0o755)
        self.assertEqual(root.nlinks, 3)
        self.assertEqual(root.mode_string(), "drwxr-xr-x")

    def test_regular_file_inode(self):
        ino = self.fs.get_inode(2)
        self.assertTrue(ino.is_regular)
        self.assertEqual(ino.size, 14)
        self.assertEqual(ino.uid, 10)
        self.assertEqual(ino.gid, 20)
        self.assertEqual(ino.mode_string(), "-rw-r--r--")
        self.assertEqual(ino.type_name, "regular file")

    def test_device_inode(self):
        tty = self.fs.get_inode(4)
        self.assertTrue(tty.is_chardev)
        self.assertEqual(tty.devno, (4, 0))
        self.assertEqual(tty.mode_string(), "crw-rw-rw-")

    def test_inode_out_of_range(self):
        with self.assertRaises(MinixError):
            self.fs.get_inode(0)
        with self.assertRaises(MinixError):
            self.fs.get_inode(33)

    def test_inode_allocated(self):
        self.assertTrue(self.fs.inode_allocated(1))
        self.assertTrue(self.fs.inode_allocated(7))
        self.assertFalse(self.fs.inode_allocated(8))


class TestDirectory(unittest.TestCase):
    def setUp(self):
        self.fs = open_test_fs()

    def test_read_root_dir(self):
        names = [name for _, name in self.fs.read_dir(self.fs.root)]
        self.assertEqual(names, [".", "..", "hello.txt", "sub", "tty",
                                 "big.bin", "sparse.bin"])

    def test_read_dir_on_file_fails(self):
        with self.assertRaises(MinixError):
            self.fs.read_dir(self.fs.get_inode(2))

    def test_resolve_absolute(self):
        self.assertEqual(self.fs.resolve("/sub/note.txt").num, 6)
        self.assertEqual(self.fs.resolve("/").num, 1)

    def test_resolve_relative_and_dots(self):
        sub = self.fs.resolve("/sub")
        self.assertEqual(self.fs.resolve("note.txt", cwd=sub).num, 6)
        self.assertEqual(self.fs.resolve("../hello.txt", cwd=sub).num, 2)
        self.assertEqual(self.fs.resolve("./../sub/.", cwd=sub).num, 3)
        self.assertEqual(self.fs.resolve("..", cwd=self.fs.root).num, 1)

    def test_resolve_missing(self):
        with self.assertRaises(MinixError):
            self.fs.resolve("/no/such/file")

    def test_resolve_through_non_dir(self):
        with self.assertRaises(MinixError):
            self.fs.resolve("/hello.txt/x")


class TestFileRead(unittest.TestCase):
    def setUp(self):
        self.fs = open_test_fs()

    def test_read_small_file(self):
        ino = self.fs.resolve("/hello.txt")
        self.assertEqual(self.fs.read_file(ino), b"Hello, Minix!\n")

    def test_read_with_offset_and_length(self):
        ino = self.fs.resolve("/hello.txt")
        self.assertEqual(self.fs.read_file(ino, 7, 5), b"Minix")
        self.assertEqual(self.fs.read_file(ino, 7), b"Minix!\n")
        self.assertEqual(self.fs.read_file(ino, 100, 5), b"")

    def test_read_big_file_indirect(self):
        ino = self.fs.resolve("/big.bin")
        data = self.fs.read_file(ino)
        self.assertEqual(len(data), 10 * BLOCK_SIZE)
        for i in range(10):
            block = data[i * BLOCK_SIZE:(i + 1) * BLOCK_SIZE]
            self.assertEqual(block, bytes([i]) * BLOCK_SIZE,
                             f"块 {i} 内容不符")

    def test_read_across_direct_indirect_boundary(self):
        ino = self.fs.resolve("/big.bin")
        data = self.fs.read_file(ino, 7 * BLOCK_SIZE - 2, 4)
        self.assertEqual(data, bytes([6, 6, 7, 7]))

    def test_sparse_file_reads_zeros(self):
        ino = self.fs.resolve("/sparse.bin")
        self.assertEqual(ino.size, 8 * 1024 * 1024)
        # 直接块区
        self.assertEqual(self.fs.read_file(ino, 0, 16), b"\x00" * 16)
        # 一级间接区
        self.assertEqual(self.fs.read_file(ino, 100 * BLOCK_SIZE, 16), b"\x00" * 16)
        # 二级间接区 (>= (7+512)*1024)
        self.assertEqual(self.fs.read_file(ino, 600 * BLOCK_SIZE, 16), b"\x00" * 16)

    def test_read_device_fails(self):
        with self.assertRaises(MinixError):
            self.fs.read_file(self.fs.resolve("/tty"))

    def test_zone_at_boundaries(self):
        ino = self.fs.resolve("/big.bin")
        self.assertEqual(self.fs.zone_at(ino, 0), 8)
        self.assertEqual(self.fs.zone_at(ino, 6), 14)
        self.assertEqual(self.fs.zone_at(ino, 7), 16)   # 间接块第一项
        self.assertEqual(self.fs.zone_at(ino, 9), 18)
        self.assertEqual(self.fs.zone_at(ino, 10), 0)   # 未分配 -> 空洞


# ---------------------------------------------------------------------------
# shell 测试
# ---------------------------------------------------------------------------

class ShellTestCase(unittest.TestCase):
    def setUp(self):
        import minix_shell
        self.fs = open_test_fs()
        self.out = io.StringIO()
        self.shell = minix_shell.MinixShell(self.fs, stdout=self.out)

    def run_cmd(self, line):
        """执行一条命令并返回其输出."""
        self.out.seek(0)
        self.out.truncate()
        self.shell.onecmd(line)
        return self.out.getvalue()


class TestShellNavigation(ShellTestCase):
    def test_pwd_initial(self):
        self.assertEqual(self.run_cmd("pwd"), "/\n")

    def test_cd_and_pwd(self):
        self.run_cmd("cd sub")
        self.assertEqual(self.shell.cwd.num, 3)
        self.assertEqual(self.run_cmd("pwd"), "/sub\n")
        self.assertEqual(self.shell.prompt, "minix:/sub$ ")
        self.run_cmd("cd ..")
        self.assertEqual(self.run_cmd("pwd"), "/\n")

    def test_cd_absolute_and_bare(self):
        self.run_cmd("cd /sub")
        self.run_cmd("cd")
        self.assertEqual(self.run_cmd("pwd"), "/\n")

    def test_cd_to_file_rejected(self):
        out = self.run_cmd("cd hello.txt")
        self.assertIn("不是目录", out)
        self.assertEqual(self.shell.cwd.num, 1)

    def test_cd_missing(self):
        out = self.run_cmd("cd nowhere")
        self.assertIn("错误", out)

    def test_ls_plain(self):
        out = self.run_cmd("ls")
        self.assertIn("hello.txt", out)
        self.assertIn("sub", out)
        self.assertNotIn("..", out.split())

    def test_ls_long(self):
        out = self.run_cmd("ls -l")
        self.assertIn("-rw-r--r--", out)
        self.assertIn("hello.txt", out)
        self.assertIn("14", out)  # hello.txt 大小
        # 设备节点显示主/次设备号
        tty_line = [l for l in out.splitlines() if l.endswith("tty")][0]
        self.assertTrue(tty_line.startswith("crw-rw-rw-"))
        self.assertIn("4,", tty_line)

    def test_ls_path_argument(self):
        out = self.run_cmd("ls /sub")
        self.assertIn("note.txt", out)

    def test_ls_single_file(self):
        self.assertEqual(self.run_cmd("ls hello.txt"), "hello.txt\n")

    def test_unknown_command(self):
        self.assertIn("未知命令", self.run_cmd("bogus"))

    def test_normalize_path(self):
        import minix_shell
        np = minix_shell.normalize_path
        self.assertEqual(np("/", "sub"), "/sub")
        self.assertEqual(np("/sub", ".."), "/")
        self.assertEqual(np("/sub", "../sub/./x"), "/sub/x")
        self.assertEqual(np("/", "/a/b/../c"), "/a/c")
        self.assertEqual(np("/a", "/"), "/")


@unittest.skipUnless(os.path.exists(IMG_PATH), "真实镜像 hdc-0.11.img 不存在")
class TestRealImage(unittest.TestCase):
    """针对仓库中 Linux 0.11 真实镜像的集成测试."""

    @classmethod
    def setUpClass(cls):
        cls.fs = MinixFS.open(IMG_PATH)

    @classmethod
    def tearDownClass(cls):
        cls.fs.close()

    def test_superblock(self):
        self.assertEqual(self.fs.offset, 1024)
        self.assertEqual(self.fs.sb.magic, minixfs.MINIX_MAGIC_14)

    def test_root_listing(self):
        names = {name for _, name in self.fs.read_dir(self.fs.root)}
        self.assertIn(".", names)
        self.assertIn("..", names)
        self.assertGreater(len(names), 2)


if __name__ == "__main__":
    unittest.main()
