"""kvfs 覆盖层测试.

复用 test_minixfs.build_image() 的迷你镜像做 fixture, 不依赖真实镜像。
最重要的一条防线是 test_image_bytes_never_change: 任何写操作之后,
底层镜像字节必须一字不变。
"""

import io
import unittest

import kvfs
from kvfs import (EEXIST, EISDIR, ENOENT, ENOTDIR, ENOTEMPTY, FsError,
                  OverlayFS, Pipe, VInode)
from minixfs import MinixFS
from test_minixfs import build_image


class OverlayTestCase(unittest.TestCase):
    def setUp(self):
        self.raw = build_image()
        self.fs = MinixFS(io.BytesIO(self.raw), offset=0)
        self.ov = OverlayFS(self.fs)

    def assertImageUnchanged(self):
        """底层镜像字节必须一字不变 —— 覆盖层的根本约定."""
        self.fs.fp.seek(0)
        self.assertEqual(self.fs.fp.read(), self.raw,
                         "底层镜像被修改了! 覆盖层必须只在内存里改动")


# ---------------------------------------------------------------------------
# 透传读取
# ---------------------------------------------------------------------------

class TestPassthroughRead(OverlayTestCase):
    def test_root_and_lookup(self):
        self.assertEqual(self.ov.root.ino, 1)
        self.assertTrue(self.ov.root.is_dir)
        v = self.ov.lookup(self.ov.root, "hello.txt")
        self.assertEqual(v.ino, 2)

    def test_read_matches_base(self):
        v = self.ov.walk("/hello.txt")
        self.assertEqual(self.ov.read(v, 0, 100), b"Hello, Minix!\n")
        self.assertEqual(self.ov.read(v, 7, 5), b"Minix")

    def test_read_big_file_through_indirect_blocks(self):
        v = self.ov.walk("/big.bin")
        data = self.ov.read(v, 0, 10 * 1024)
        self.assertEqual(len(data), 10 * 1024)
        for i in range(10):
            self.assertEqual(data[i * 1024:(i + 1) * 1024], bytes([i]) * 1024)

    def test_list_dir_passthrough(self):
        names = {n for _, n in self.ov.list_dir(self.ov.root)}
        self.assertIn("hello.txt", names)
        self.assertIn(".", names)
        self.assertIn("..", names)

    def test_readdir_raw_passthrough_is_base_bytes(self):
        raw = self.ov.readdir_raw(self.ov.root)
        self.assertEqual(raw, self.fs.read_file(self.fs.root))

    def test_walk_absolute_and_relative(self):
        sub = self.ov.walk("/sub")
        self.assertEqual(self.ov.walk("note.txt", cwd=sub).ino, 6)
        self.assertEqual(self.ov.walk("../hello.txt", cwd=sub).ino, 2)
        self.assertEqual(self.ov.walk("/").ino, 1)

    def test_walk_missing_raises_enoent(self):
        with self.assertRaises(FsError) as ctx:
            self.ov.walk("/nope")
        self.assertEqual(ctx.exception.errno, ENOENT)

    def test_walk_through_file_raises_enotdir(self):
        with self.assertRaises(FsError) as ctx:
            self.ov.walk("/hello.txt/x")
        self.assertEqual(ctx.exception.errno, ENOTDIR)

    def test_device_node_fields(self):
        v = self.ov.walk("/tty")
        self.assertTrue(v.is_chardev)
        self.assertEqual(v.devno, (4, 0))

    def test_same_inode_returned_for_same_path(self):
        a = self.ov.walk("/hello.txt")
        b = self.ov.walk("/hello.txt")
        self.assertIs(a, b)          # 同一 VInode 对象, 改动才能被看见


# ---------------------------------------------------------------------------
# COW 写入
# ---------------------------------------------------------------------------

class TestCopyOnWrite(OverlayTestCase):
    def test_write_then_read_back(self):
        v = self.ov.walk("/hello.txt")
        self.ov.write(v, 0, b"HELLO")
        self.assertEqual(self.ov.read(v, 0, 100), b"HELLO, Minix!\n")
        self.assertImageUnchanged()

    def test_image_bytes_never_change(self):
        """一串写操作之后镜像仍应一字不变."""
        v = self.ov.walk("/hello.txt")
        self.ov.write(v, 0, b"xxxx")
        self.ov.truncate(v, 4)
        self.ov.create("/newfile", 0o644)
        self.ov.mkdir("/newdir", 0o755)
        self.ov.unlink("/hello.txt")
        self.ov.rename("/big.bin", "/renamed.bin")
        big = self.ov.walk("/renamed.bin")
        self.ov.write(big, 0, b"clobber")
        self.assertImageUnchanged()

    def test_base_read_still_original_after_overlay_write(self):
        v = self.ov.walk("/hello.txt")
        self.ov.write(v, 0, b"ZZZZZ")
        # 直接用底层 MinixFS 读, 应该还是原文
        self.assertEqual(self.fs.read_file(self.fs.get_inode(2)),
                         b"Hello, Minix!\n")

    def test_write_extends_file(self):
        v = self.ov.walk("/hello.txt")
        self.ov.write(v, 14, b"more")
        self.assertEqual(v.size, 18)
        self.assertEqual(self.ov.read(v, 0, 100), b"Hello, Minix!\nmore")

    def test_write_past_end_zero_fills(self):
        v = self.ov.walk("/hello.txt")
        self.ov.write(v, 20, b"X")
        self.assertEqual(self.ov.read(v, 14, 6), bytes(6))
        self.assertEqual(v.size, 21)

    def test_truncate_shrink_and_grow(self):
        v = self.ov.walk("/hello.txt")
        self.ov.truncate(v, 5)
        self.assertEqual(self.ov.read(v, 0, 99), b"Hello")
        self.ov.truncate(v, 8)
        self.assertEqual(self.ov.read(v, 0, 99), b"Hello" + bytes(3))

    def test_cow_of_big_file_preserves_content(self):
        v = self.ov.walk("/big.bin")
        self.ov.write(v, 5000, b"XYZ")
        data = self.ov.read(v, 0, 10 * 1024)
        self.assertEqual(data[5000:5003], b"XYZ")
        self.assertEqual(data[:1024], bytes(1024))     # 第 0 块原样
        self.assertEqual(len(data), 10 * 1024)

    def test_sparse_file_read_is_zeros(self):
        v = self.ov.walk("/sparse.bin")
        self.assertEqual(self.ov.read(v, 0, 16), bytes(16))
        self.assertEqual(self.ov.read(v, 600 * 1024, 16), bytes(16))

    def test_write_to_dir_raises_eisdir(self):
        with self.assertRaises(FsError) as ctx:
            self.ov.write(self.ov.root, 0, b"x")
        self.assertEqual(ctx.exception.errno, EISDIR)


# ---------------------------------------------------------------------------
# 目录项操作
# ---------------------------------------------------------------------------

class TestDirectoryOps(OverlayTestCase):
    def test_create_new_file(self):
        v = self.ov.create("/brand-new", 0o644)
        self.assertGreater(v.ino, self.fs.sb.ninodes)   # 新号在镜像上限之外
        self.assertEqual(v.nlinks, 1)
        self.assertIs(self.ov.walk("/brand-new"), v)
        self.ov.write(v, 0, b"data")
        self.assertEqual(self.ov.read(v, 0, 9), b"data")
        self.assertImageUnchanged()

    def test_create_existing_raises_eexist(self):
        with self.assertRaises(FsError) as ctx:
            self.ov.create("/hello.txt", 0o644)
        self.assertEqual(ctx.exception.errno, EEXIST)

    def test_create_in_subdir(self):
        v = self.ov.create("/sub/added", 0o600)
        self.assertIs(self.ov.walk("/sub/added"), v)
        names = {n for _, n in self.ov.list_dir(self.ov.walk("/sub"))}
        self.assertEqual(names, {".", "..", "note.txt", "added"})

    def test_mkdir_has_dot_and_dotdot(self):
        d = self.ov.mkdir("/newdir", 0o755)
        names = {n for _, n in self.ov.list_dir(d)}
        self.assertEqual(names, {".", ".."})
        # .. 必须指回父目录, 否则相对路径走不通
        self.assertEqual(self.ov.walk("/newdir/..").ino, 1)
        self.assertEqual(self.ov.walk("/newdir/.").ino, d.ino)

    def test_mkdir_nested_then_file(self):
        self.ov.mkdir("/a", 0o755)
        self.ov.mkdir("/a/b", 0o755)
        v = self.ov.create("/a/b/c.txt", 0o644)
        self.ov.write(v, 0, b"deep")
        self.assertEqual(self.ov.read(self.ov.walk("/a/b/c.txt"), 0, 9), b"deep")
        self.assertEqual(self.ov.walk("/a/b/..").ino, self.ov.walk("/a").ino)

    def test_unlink_removes_entry(self):
        self.ov.unlink("/hello.txt")
        with self.assertRaises(FsError):
            self.ov.walk("/hello.txt")
        names = {n for _, n in self.ov.list_dir(self.ov.root)}
        self.assertNotIn("hello.txt", names)
        self.assertImageUnchanged()

    def test_unlink_dir_raises_eisdir(self):
        with self.assertRaises(FsError) as ctx:
            self.ov.unlink("/sub")
        self.assertEqual(ctx.exception.errno, EISDIR)

    def test_rmdir_empty_only(self):
        with self.assertRaises(FsError) as ctx:
            self.ov.rmdir("/sub")
        self.assertEqual(ctx.exception.errno, ENOTEMPTY)
        self.ov.unlink("/sub/note.txt")
        self.ov.rmdir("/sub")
        with self.assertRaises(FsError):
            self.ov.walk("/sub")

    def test_rmdir_on_file_raises_enotdir(self):
        with self.assertRaises(FsError) as ctx:
            self.ov.rmdir("/hello.txt")
        self.assertEqual(ctx.exception.errno, ENOTDIR)

    def test_hard_link_shares_inode(self):
        self.ov.link("/hello.txt", "/hello2.txt")
        a = self.ov.walk("/hello.txt")
        b = self.ov.walk("/hello2.txt")
        self.assertIs(a, b)
        self.assertEqual(a.nlinks, 2)
        # 通过一个名字写, 另一个名字看得到
        self.ov.write(a, 0, b"J")
        self.assertEqual(self.ov.read(b, 0, 5), b"Jello")

    def test_unlink_one_link_keeps_other(self):
        self.ov.link("/hello.txt", "/hello2.txt")
        self.ov.unlink("/hello.txt")
        v = self.ov.walk("/hello2.txt")
        self.assertEqual(self.ov.read(v, 0, 99), b"Hello, Minix!\n")

    def test_link_dir_raises_eperm(self):
        with self.assertRaises(FsError) as ctx:
            self.ov.link("/sub", "/sub2")
        self.assertEqual(ctx.exception.errno, kvfs.EPERM)

    def test_rename_within_dir(self):
        self.ov.rename("/hello.txt", "/greeting.txt")
        self.assertEqual(self.ov.read(self.ov.walk("/greeting.txt"), 0, 99),
                         b"Hello, Minix!\n")
        with self.assertRaises(FsError):
            self.ov.walk("/hello.txt")

    def test_rename_across_dirs(self):
        self.ov.rename("/hello.txt", "/sub/moved.txt")
        self.assertEqual(self.ov.read(self.ov.walk("/sub/moved.txt"), 0, 99),
                         b"Hello, Minix!\n")
        with self.assertRaises(FsError):
            self.ov.walk("/hello.txt")

    def test_rename_over_existing_file(self):
        self.ov.create("/target", 0o644)
        self.ov.rename("/hello.txt", "/target")
        self.assertEqual(self.ov.read(self.ov.walk("/target"), 0, 99),
                         b"Hello, Minix!\n")

    def test_rename_dir_fixes_dotdot(self):
        self.ov.mkdir("/d1", 0o755)
        self.ov.mkdir("/d1/inner", 0o755)
        self.ov.rename("/d1/inner", "/moved")
        self.assertEqual(self.ov.walk("/moved/..").ino, 1)   # .. 现在指向根

    def test_mknod_device(self):
        v = self.ov.mknod("/dev-null", 0o020666, (1 << 8) | 3)
        self.assertTrue(v.is_chardev)
        self.assertEqual(v.devno, (1, 3))

    def test_name_longer_than_14_is_truncated(self):
        long_name = "a" * 20
        self.ov.create("/" + long_name, 0o644)
        names = {n for _, n in self.ov.list_dir(self.ov.root)}
        self.assertIn("a" * 14, names)
        self.assertNotIn(long_name, names)

    def test_readdir_raw_synthesized_is_parseable(self):
        """合成的 dirent 字节能被现有 minixfs 的解析逻辑反解."""
        import struct
        self.ov.create("/zzz", 0o644)
        raw = self.ov.readdir_raw(self.ov.root)
        self.assertEqual(len(raw) % 16, 0)
        parsed = []
        for off in range(0, len(raw), 16):
            ino = struct.unpack_from("<H", raw, off)[0]
            if ino == 0:
                continue
            name = raw[off + 2:off + 16].split(b"\x00", 1)[0].decode("latin-1")
            parsed.append((ino, name))
        self.assertIn("zzz", [n for _, n in parsed])
        self.assertEqual(dict((n, i) for i, n in parsed),
                         dict((n, i) for i, n in self.ov.list_dir(self.ov.root)))


# ---------------------------------------------------------------------------
# 已打开文件与删除
# ---------------------------------------------------------------------------

class TestOpenAndDelete(OverlayTestCase):
    def test_open_file_survives_unlink(self):
        """shell 的临时文件依赖这个: unlink 之后仍可通过已有引用读写."""
        v = self.ov.walk("/hello.txt")
        v.open_refs += 1
        self.ov.unlink("/hello.txt")
        self.assertFalse(v.deleted)                 # 还有打开引用, 未真正丢弃
        self.ov.write(v, 0, b"still")
        self.assertEqual(self.ov.read(v, 0, 5), b"still")

    def test_unlink_without_open_marks_deleted(self):
        v = self.ov.walk("/hello.txt")
        self.ov.unlink("/hello.txt")
        self.assertTrue(v.deleted)
        self.assertEqual(v.nlinks, 0)

    def test_nlinks_bookkeeping(self):
        v = self.ov.walk("/hello.txt")
        start = v.nlinks
        self.ov.link("/hello.txt", "/l2")
        self.assertEqual(v.nlinks, start + 1)
        self.ov.unlink("/l2")
        self.assertEqual(v.nlinks, start)


# ---------------------------------------------------------------------------
# chroot
# ---------------------------------------------------------------------------

class TestChroot(OverlayTestCase):
    def test_dotdot_blocked_at_root(self):
        sub = self.ov.walk("/sub")
        # 以 /sub 为根: .. 不能逃出去
        self.assertEqual(self.ov.walk("/..", root=sub).ino, sub.ino)
        self.assertEqual(self.ov.walk("/../..", root=sub).ino, sub.ino)

    def test_paths_resolve_relative_to_new_root(self):
        sub = self.ov.walk("/sub")
        self.assertEqual(self.ov.walk("/note.txt", root=sub).ino, 6)
        with self.assertRaises(FsError):
            self.ov.walk("/hello.txt", root=sub)     # 新根之外看不到

    def test_absolute_path_uses_root_not_cwd(self):
        sub = self.ov.walk("/sub")
        self.assertEqual(self.ov.walk("/", cwd=sub).ino, 1)


# ---------------------------------------------------------------------------
# 元数据
# ---------------------------------------------------------------------------

class TestMetadata(OverlayTestCase):
    def test_chmod_keeps_type_bits(self):
        v = self.ov.walk("/hello.txt")
        self.ov.chmod(v, 0o600)
        self.assertEqual(v.mode & 0o7777, 0o600)
        self.assertTrue(v.is_regular)

    def test_chown(self):
        v = self.ov.walk("/hello.txt")
        self.ov.chown(v, 5, 6)
        self.assertEqual((v.uid, v.gid), (5, 6))
        self.ov.chown(v, 0xFFFF, 9)          # 0xFFFF 表示不改
        self.assertEqual((v.uid, v.gid), (5, 9))

    def test_stat_tuple_layout(self):
        v = self.ov.walk("/hello.txt")
        st = self.ov.stat_tuple(v)
        self.assertEqual(len(st), 11)
        dev, ino, mode, nlink, uid, gid, rdev, size, at, mt, ct = st
        self.assertEqual(dev, kvfs.ROOT_DEV)
        self.assertEqual(ino, 2)
        self.assertEqual(size, 14)
        self.assertEqual(uid, 10)
        self.assertEqual(gid, 20)
        # minix v1 只有一个时间戳, 三个时间字段同值
        self.assertEqual((at, mt, ct), (v.mtime, v.mtime, v.mtime))

    def test_stat_of_device_has_rdev(self):
        st = self.ov.stat_tuple(self.ov.walk("/tty"))
        self.assertEqual(st[6], (4 << 8) | 0)

    def test_size_reflects_overlay_writes(self):
        v = self.ov.walk("/hello.txt")
        self.ov.write(v, 0, b"x" * 100)
        self.assertEqual(self.ov.stat_tuple(v)[7], 100)


# ---------------------------------------------------------------------------
# 管道
# ---------------------------------------------------------------------------

class TestPipe(unittest.TestCase):
    def setUp(self):
        self.p = Pipe()
        self.p.readers = 1
        self.p.writers = 1

    def test_write_then_read(self):
        self.assertEqual(self.p.write(b"hello"), 5)
        self.assertEqual(self.p.read(10), b"hello")

    def test_partial_read(self):
        self.p.write(b"abcdef")
        self.assertEqual(self.p.read(3), b"abc")
        self.assertEqual(self.p.read(3), b"def")

    def test_read_empty_with_writer_blocks(self):
        self.assertIsNone(self.p.read(10))       # None = 调用方该阻塞

    def test_read_empty_without_writer_is_eof(self):
        self.p.writers = 0
        self.assertEqual(self.p.read(10), b"")

    def test_write_full_blocks(self):
        self.assertEqual(self.p.write(b"x" * 5000), kvfs.PIPE_SIZE - 1)
        self.assertIsNone(self.p.write(b"more"))

    def test_capacity_is_one_page_minus_one(self):
        self.p.write(b"x" * 10000)
        self.assertEqual(len(self.p.buf), kvfs.PIPE_SIZE - 1)

    def test_write_without_reader_raises_epipe(self):
        self.p.readers = 0
        with self.assertRaises(FsError) as ctx:
            self.p.write(b"x")
        self.assertEqual(ctx.exception.errno, kvfs.EPIPE)

    def test_write_empty_is_zero(self):
        self.assertEqual(self.p.write(b""), 0)


# ---------------------------------------------------------------------------
# 覆盖层导出/导入
# ---------------------------------------------------------------------------

class TestOverlayPersistence(OverlayTestCase):
    def test_export_only_includes_changes(self):
        self.ov.walk("/hello.txt")            # 只读, 不该被导出
        blob = self.ov.export_changes()
        self.assertEqual(blob["vnodes"], {})

    def test_roundtrip_preserves_writes(self):
        v = self.ov.walk("/hello.txt")
        self.ov.write(v, 0, b"SAVED")
        self.ov.create("/added", 0o644)
        self.ov.write(self.ov.walk("/added"), 0, b"new file")
        blob = self.ov.export_changes()

        fresh = OverlayFS(MinixFS(io.BytesIO(self.raw), offset=0))
        fresh.import_changes(blob)
        self.assertEqual(fresh.read(fresh.walk("/hello.txt"), 0, 99),
                         b"SAVED, Minix!\n")
        self.assertEqual(fresh.read(fresh.walk("/added"), 0, 99), b"new file")

    def test_roundtrip_preserves_deletions(self):
        self.ov.unlink("/hello.txt")
        blob = self.ov.export_changes()
        fresh = OverlayFS(MinixFS(io.BytesIO(self.raw), offset=0))
        fresh.import_changes(blob)
        with self.assertRaises(FsError):
            fresh.walk("/hello.txt")


@unittest.skipUnless(__import__("os").path.exists(
    __import__("os").path.join(__import__("os").path.dirname(
        __import__("os").path.abspath(__file__)), "hdc-0.11.img")),
    "真实镜像 hdc-0.11.img 不存在")
class TestRealImageOverlay(unittest.TestCase):
    """真实 Linux 0.11 镜像上的覆盖层集成测试."""

    IMG = __import__("os").path.join(__import__("os").path.dirname(
        __import__("os").path.abspath(__file__)), "hdc-0.11.img")

    def setUp(self):
        self.fs = MinixFS.open(self.IMG)
        self.ov = OverlayFS(self.fs)

    def tearDown(self):
        self.fs.close()

    def test_sh_and_bash_are_same_inode(self):
        """路径级覆盖层做不到这点, inode 级才对."""
        sh = self.ov.walk("/bin/sh")
        bash = self.ov.walk("/bin/bash")
        self.assertIs(sh, bash)
        self.assertEqual(sh.ino, 6)
        self.assertEqual(sh.nlinks, 2)

    def test_read_etc_rc(self):
        data = self.ov.read(self.ov.walk("/etc/rc"), 0, 100)
        self.assertIn(b"/etc/update", data)

    def test_mknod_device_in_overlay(self):
        """覆盖层能新建设备节点(镜像里没有 /dev/console 就临时造一个来测)."""
        with self.assertRaises(FsError):
            self.ov.walk("/dev/console")
        v = self.ov.mknod("/dev/console", 0o020600, (5 << 8) | 0)
        self.assertEqual(v.devno, (5, 0))
        self.assertIs(self.ov.walk("/dev/console"), v)

    def test_image_file_not_modified(self):
        import hashlib

        def digest():
            h = hashlib.md5()
            with open(self.IMG, "rb") as f:
                for chunk in iter(lambda: f.read(1 << 20), b""):
                    h.update(chunk)
            return h.hexdigest()

        before = digest()
        self.ov.write(self.ov.walk("/etc/rc"), 0, b"# clobbered\n")
        self.ov.create("/tmp/scratch", 0o644)
        self.ov.unlink("/etc/mtab")
        self.assertEqual(digest(), before, "真实镜像文件被改动了!")


if __name__ == "__main__":
    unittest.main()
