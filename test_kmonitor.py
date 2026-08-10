"""monitor 与转义键测试.

monitor 的读写全部可注入, 所以用脚本化命令驱动、捕获输出即可断言,
不必真的占用宿主终端。全部跑在迷你镜像上, 不依赖 hdc-0.11.img。
"""

import unittest

import cpu86
import kernel as kmod
import kmonitor
import ktty
import kvfs
from kmonitor import Monitor, fmt_bytes
from test_kernel import hello_program, make_aout, make_kernel, make_proc


def make_monitored(inputs=None, tty=True):
    """搭一套带 monitor 与转义键的内核."""
    k, term, fs = make_kernel()
    term._tty = tty
    term.pending = list(inputs or [])
    k.terminal = ktty.TTY(term, escape=0x01, on_escape=k.on_escape)
    k.monitor = Monitor(k)
    return k, term, fs


def run_monitor(k, commands):
    """用脚本化命令跑一次 monitor, 返回输出文本."""
    out = []
    cmds = iter(list(commands) + ["cont"])
    mon = Monitor(k, read_line=lambda prompt: next(cmds),
                  write=lambda s: out.append(s))
    k.monitor = mon
    mon.interact()
    return "".join(out)


class TestEscapeKey(unittest.TestCase):
    """Ctrl-A 前缀 —— 仿 qemu, 在行规程之前拦截."""

    def setUp(self):
        self.k, self.term, self.fs = make_monitored()

    def test_ctrl_a_x_requests_quit(self):
        """Linux 下原本没有任何退出途径: raw 模式把 Ctrl-C 变成字节喂给被仿真
        进程, 宿主永远收不到信号。Ctrl-A x 是那条出路。"""
        self.k.terminal.feed(b"\x01x")
        self.assertTrue(self.k.quit_requested)
        self.assertIn("仿真器退出", self.term.text_utf8)

    def test_ctrl_a_c_requests_monitor(self):
        self.k.terminal.feed(b"\x01c")
        self.assertTrue(self.k.monitor_pending)
        self.assertFalse(self.k.quit_requested)

    def test_uppercase_commands_work_too(self):
        self.k.terminal.feed(b"\x01X")
        self.assertTrue(self.k.quit_requested)

    def test_ctrl_a_a_passes_literal_escape_through(self):
        self.k.terminal.feed(b"\x01a")
        self.assertEqual(bytes(self.k.terminal.line), b"\x01")
        self.assertFalse(self.k.quit_requested)

    def test_double_escape_passes_literal_through(self):
        self.k.terminal.feed(b"\x01\x01")
        self.assertEqual(bytes(self.k.terminal.line), b"\x01")

    def test_ctrl_a_question_shows_help(self):
        self.k.terminal.feed(b"\x01?")
        self.assertIn("Ctrl-A c", self.term.text_utf8)
        self.assertIn("Ctrl-A x", self.term.text_utf8)

    def test_normal_input_unaffected(self):
        self.k.terminal.feed(b"ls -l\n")
        self.assertEqual(bytes(self.k.terminal.ready), b"ls -l\n")

    def test_escape_split_across_two_feeds(self):
        """转义键与命令字符可能分两次到达(逐键读取时很常见)."""
        self.k.terminal.feed(b"\x01")
        self.assertFalse(self.k.quit_requested)
        self.k.terminal.feed(b"x")
        self.assertTrue(self.k.quit_requested)

    def test_escape_in_middle_of_input(self):
        self.k.terminal.feed(b"ab\x01xcd\n")
        self.assertTrue(self.k.quit_requested)
        self.assertEqual(bytes(self.k.terminal.ready), b"abcd\n")

    def test_unknown_escape_command_is_swallowed(self):
        self.k.terminal.feed(b"\x01z")
        self.assertFalse(self.k.quit_requested)
        self.assertFalse(self.k.monitor_pending)
        self.assertEqual(bytes(self.k.terminal.line), b"")   # z 不该漏给程序

    def test_escape_works_even_in_raw_mode(self):
        """被仿真程序关掉 ICANON/ISIG(bash 就会这么做)时转义键仍要有效 ——
        因为拦截发生在行规程之前。"""
        self.k.terminal.termios.lflag = 0
        self.k.terminal.feed(b"\x01x")
        self.assertTrue(self.k.quit_requested)

    def test_escape_disabled_when_no_callback(self):
        """--escape none 时整串原样透传给被仿真程序, 不再拦截."""
        self.k.terminal.on_escape = None
        self.k.terminal.feed(b"\x01x")
        self.assertFalse(self.k.quit_requested)
        self.assertEqual(bytes(self.k.terminal.line), b"\x01x")


class TestMonitorCommands(unittest.TestCase):
    def setUp(self):
        self.k, self.term, self.fs = make_monitored()
        self.p = make_proc(self.k, self.fs)
        self.p.name = "/bin/testprog"

    def test_help_lists_commands(self):
        out = run_monitor(self.k, ["help"])
        for cmd in ("info procs", "info mem", "info fs", "info syscalls",
                    "kill", "trace", "cont", "quit"):
            self.assertIn(cmd, out)

    def test_cont_leaves_monitor_without_quitting(self):
        out = run_monitor(self.k, [])
        self.assertIn("继续仿真", out)
        self.assertFalse(self.k.quit_requested)

    def test_quit_sets_flag(self):
        out = []
        mon = Monitor(self.k, read_line=lambda p: "quit",
                      write=lambda s: out.append(s))
        mon.interact()
        self.assertTrue(self.k.quit_requested)
        self.assertIn("停止仿真", "".join(out))

    def test_unknown_command_reports(self):
        out = run_monitor(self.k, ["bogus"])
        self.assertIn("未知命令: bogus", out)

    def test_info_without_subcommand_shows_usage(self):
        out = run_monitor(self.k, ["info"])
        self.assertIn("用法", out)

    def test_info_unknown_subcommand(self):
        out = run_monitor(self.k, ["info nonsense"])
        self.assertIn("未知的 info 项", out)

    # ---- info procs ----

    def test_info_procs_lists_processes(self):
        out = run_monitor(self.k, ["info procs"])
        self.assertIn("/bin/testprog", out)
        self.assertIn(str(self.p.pid), out)
        self.assertIn("运行", out)

    def test_ps_is_alias(self):
        self.assertIn("/bin/testprog", run_monitor(self.k, ["ps"]))

    def test_info_procs_shows_states(self):
        self.p.state = kmod.SLEEPING
        self.assertIn("睡眠", run_monitor(self.k, ["ps"]))
        self.p.state = kmod.ZOMBIE
        self.assertIn("僵尸", run_monitor(self.k, ["ps"]))
        self.p.state = kmod.STOPPED
        self.assertIn("停止", run_monitor(self.k, ["ps"]))

    def test_info_procs_shows_wait_channel(self):
        pipe = kvfs.Pipe()
        pipe.buf.extend(b"abc")
        self.p.wait_channel = ("piperead", pipe)
        out = run_monitor(self.k, ["ps"])
        self.assertIn("piperead(3B)", out)

    def test_info_procs_marks_kernel_task(self):
        self.k.boot_init()
        self.assertIn("内核任务", run_monitor(self.k, ["ps"]))

    # ---- info mem ----

    def test_info_mem_shows_sizes(self):
        out = run_monitor(self.k, ["info mem"])
        self.assertIn("/bin/testprog", out)
        self.assertIn("64.0MB", out)               # 用户空间上限
        self.assertIn("合计", out)

    # ---- info fs ----

    def test_info_fs_reports_overlay_and_base(self):
        self.fs.create("/newfile", 0o644)
        self.fs.write(self.fs.walk("/hello.txt"), 0, b"changed")
        out = run_monitor(self.k, ["info fs"])
        self.assertIn("覆盖层", out)
        self.assertIn("镜像文件永不被写", out)
        self.assertIn("底层镜像", out)
        self.assertIn("magic 0x137f", out)

    def test_overlay_stats_counts_changes(self):
        st0 = self.fs.overlay_stats()
        self.fs.create("/a", 0o644)
        self.fs.write(self.fs.walk("/a"), 0, b"xyz")
        self.fs.write(self.fs.walk("/hello.txt"), 0, b"z")
        self.fs.unlink("/big.bin")
        st = self.fs.overlay_stats()
        self.assertGreater(st["new_inodes"], st0["new_inodes"])
        self.assertGreaterEqual(st["cow_files"], 2)
        self.assertGreaterEqual(st["cow_dirs"], 1)      # 根目录被改过
        self.assertEqual(st["deleted"], 1)
        self.assertGreater(st["bytes"], 0)

    # ---- info syscalls ----

    def test_info_syscalls_empty_at_first(self):
        self.assertIn("还没有系统调用记录", run_monitor(self.k, ["info syscalls"]))

    def test_info_syscalls_counts_and_recent(self):
        import ksyscall
        for _ in range(3):
            self.k._on_int_stats(self.p, ksyscall.NR_GETPID, 0, 0, 0, 7)
        self.k._on_int_stats(self.p, ksyscall.NR_WRITE, 1, 0x100, 5, 5)
        out = run_monitor(self.k, ["info syscalls"])
        self.assertIn("getpid", out)
        self.assertIn("write", out)
        self.assertIn("系统调用共 4 次", out)
        self.assertIn("最近", out)

    def test_syscall_name_lookup(self):
        self.assertEqual(Monitor.syscall_name(1), "exit")
        self.assertEqual(Monitor.syscall_name(4), "write")
        self.assertEqual(Monitor.syscall_name(999), "#999")

    def test_trace_on_off_adjusts_capacity(self):
        """轨迹只有一份环形缓冲且常开, on/off 调的是容量而不是开关."""
        self.assertEqual(self.k.trace_capacity, kmod.TRACE_DEFAULT)
        out = run_monitor(self.k, ["trace on"])
        self.assertIn(str(kmod.TRACE_VERBOSE), out)
        self.assertEqual(self.k.trace_capacity, kmod.TRACE_VERBOSE)
        out = run_monitor(self.k, ["trace off"])
        self.assertIn("仍在记录", out)
        self.assertEqual(self.k.trace_capacity, kmod.TRACE_DEFAULT)

    def test_trace_on_with_explicit_capacity(self):
        run_monitor(self.k, ["trace on 77"])
        self.assertEqual(self.k.trace_capacity, 77)
        self.assertEqual(self.k.recent_syscalls.maxlen, 77)

    def test_trace_capacity_change_keeps_recent_records(self):
        import ksyscall
        for i in range(10):
            self.k._on_int_stats(self.p, ksyscall.NR_GETPID, i, 0, 0, i)
        self.k.set_trace_capacity(3)
        self.assertEqual(len(self.k.recent_syscalls), 3)
        # 保留的是最后 3 条
        self.assertEqual([r[2] for r in self.k.recent_syscalls], [7, 8, 9])

    def test_trace_no_args_shows_usage_and_state(self):
        out = run_monitor(self.k, ["trace"])
        self.assertIn("用法", out)
        self.assertIn(str(self.k.trace_capacity), out)

    def test_trace_bad_subcommand_and_args(self):
        self.assertIn("未知的 trace 子命令", run_monitor(self.k, ["trace bogus"]))
        self.assertIn("必须是整数", run_monitor(self.k, ["trace show abc"]))
        self.assertIn("必须是整数", run_monitor(self.k, ["trace on abc"]))

    def test_trace_show_lists_records(self):
        import ksyscall
        self.k._on_int_stats(self.p, ksyscall.NR_WRITE, 1, 0x100, 5, 5)
        self.k._on_int_stats(self.p, ksyscall.NR_OPEN, 0x200, 0, 0, -2)
        out = run_monitor(self.k, ["trace show"])
        self.assertIn("write", out)
        self.assertIn("open", out)
        self.assertIn(str(self.p.pid), out)

    def test_trace_show_respects_count(self):
        import ksyscall
        for i in range(20):
            self.k._on_int_stats(self.p, ksyscall.NR_GETPID, 0, 0, 0, i)
        out = run_monitor(self.k, ["trace show 5"])
        self.assertIn("最近 5 次调用", out)

    def test_info_trace_is_alias(self):
        import ksyscall
        for _ in range(3):
            self.k._on_int_stats(self.p, ksyscall.NR_WRITE, 1, 0, 0, 0)
        self.assertIn("write", run_monitor(self.k, ["info trace"]))
        self.assertIn("最近 2 次调用", run_monitor(self.k, ["info trace 2"]))

    def test_trace_show_empty(self):
        self.assertIn("轨迹缓冲是空的", run_monitor(self.k, ["trace show"]))

    def test_negative_return_shows_errno_name(self):
        """-2 该标成 -2(ENOENT), 光看数字很难认."""
        import ksyscall
        self.k._on_int_stats(self.p, ksyscall.NR_OPEN, 0x100, 0, 0, -2)
        out = run_monitor(self.k, ["trace show"])
        self.assertIn("-2(ENOENT)", out)

    def test_kernel_no_longer_has_unbounded_trace_list(self):
        """旧的无上限 self.trace 列表已删除, 只留有上限的环形缓冲."""
        self.assertFalse(hasattr(self.k, "trace"))
        self.assertIsNotNone(self.k.recent_syscalls.maxlen)

    # ---- info cpu / fds ----

    def test_info_cpu_shows_registers(self):
        self.p.cpu.regs[0] = 0xDEADBEEF
        out = run_monitor(self.k, ["info cpu"])
        self.assertIn("eax=0xdeadbeef", out)
        self.assertIn("eip=", out)

    def test_regs_is_alias(self):
        self.assertIn("eax=", run_monitor(self.k, ["regs"]))

    def test_info_cpu_by_pid(self):
        out = run_monitor(self.k, [f"info cpu {self.p.pid}"])
        self.assertIn(f"pid {self.p.pid}", out)

    def test_info_cpu_bad_pid(self):
        self.assertIn("没有 pid 999", run_monitor(self.k, ["info cpu 999"]))
        self.assertIn("无效 pid", run_monitor(self.k, ["info cpu abc"]))

    def test_info_cpu_on_kernel_task(self):
        self.k.boot_init()
        out = run_monitor(self.k, [f"info cpu {self.k.init_proc.pid}"])
        self.assertIn("内核任务", out)

    def test_info_fds_lists_terminal(self):
        out = run_monitor(self.k, ["info fds"])
        self.assertIn("0: 终端", out)
        self.assertIn("1: 终端", out)

    def test_info_fds_shows_inode_and_pipe(self):
        v = self.fs.walk("/hello.txt")
        self.p.fds[5] = kmod.OpenFile(v, 0)
        pipe = kvfs.Pipe()
        pipe.buf.extend(b"xy")
        pipe.readers = pipe.writers = 1
        self.p.fds[6] = kmod.OpenFile(pipe, 0)
        out = run_monitor(self.k, ["info fds"])
        self.assertIn(f"inode {v.ino}", out)
        self.assertIn("管道 buf=2B", out)

    def test_info_fds_empty(self):
        self.p.fds = [None] * kmod.NR_OPEN
        self.assertIn("(无)", run_monitor(self.k, ["info fds"]))

    # ---- info tty ----

    def test_info_tty_shows_modes(self):
        out = run_monitor(self.k, ["info tty"])
        self.assertIn("ICANON", out)
        self.assertIn("ECHO", out)
        self.assertIn("24x80", out)
        self.assertIn("INTR=^C", out)

    def test_info_tty_raw_mode(self):
        self.k.terminal.termios.lflag = 0
        self.assertIn("raw 模式", run_monitor(self.k, ["info tty"]))

    # ---- kill ----

    def test_kill_posts_signal(self):
        out = run_monitor(self.k, [f"kill {self.p.pid} 15"])
        self.assertIn("已向 pid", out)
        self.assertTrue(self.p.signal & (1 << (kmod.SIGTERM - 1)))

    def test_kill_defaults_to_sigterm(self):
        run_monitor(self.k, [f"kill {self.p.pid}"])
        self.assertTrue(self.p.signal & (1 << (kmod.SIGTERM - 1)))

    def test_kill_bad_args(self):
        self.assertIn("用法", run_monitor(self.k, ["kill"]))
        self.assertIn("必须是整数", run_monitor(self.k, ["kill abc"]))
        self.assertIn("没有 pid 999", run_monitor(self.k, ["kill 999"]))

    def test_empty_line_is_ignored(self):
        out = run_monitor(self.k, ["", "   "])
        self.assertIn("继续仿真", out)


class TestSchedulerIntegration(unittest.TestCase):
    """monitor 请求要能真的打断调度循环."""

    def _world(self):
        k, term, fs = make_monitored(tty=False)
        v = fs.create("/prog", 0o755)
        # 一个死循环程序: jmp $ (EB FE), 永不退出
        fs.write(v, 0, make_aout(b"\xeb\xfe"))
        k.boot("/prog", [b"/prog"])
        return k, term, fs

    def test_quit_request_stops_run_loop(self):
        k, term, fs = self._world()
        k.quit_requested = True
        k.run(10_000_000)                  # 立刻返回, 不会跑满预算
        self.assertLess(k.current.cpu.icount, 1000)

    def test_monitor_request_enters_monitor_then_continues(self):
        k, term, fs = self._world()
        seen = []
        k.monitor = Monitor(k, read_line=lambda p: "quit",
                            write=lambda s: seen.append(s))
        k.monitor_pending = True
        k.run(10_000_000)
        self.assertTrue(k.quit_requested)
        self.assertIn("停止仿真", "".join(seen))

    def test_monitor_cont_resumes_and_budget_still_applies(self):
        k, term, fs = self._world()
        k.monitor = Monitor(k, read_line=lambda p: "cont",
                            write=lambda s: None)
        k.monitor_pending = True
        k.run(200_000)                     # cont 之后继续跑到预算耗尽
        self.assertGreater(k.current.cpu.icount, 1000)
        self.assertFalse(k.quit_requested)

    def test_escape_quit_stops_a_running_emulation(self):
        """端到端: 转义键让正在死循环的仿真停下来."""
        k, term, fs = self._world()
        term.pending.append(b"\x01x")      # 下一轮 pump 会读到
        k.run(50_000_000)
        self.assertTrue(k.quit_requested)
        self.assertLess(k.current.cpu.icount, 50_000_000)


class TestFmtBytes(unittest.TestCase):
    def test_units(self):
        self.assertEqual(fmt_bytes(512), "512B")
        self.assertEqual(fmt_bytes(2048), "2.0KB")
        self.assertEqual(fmt_bytes(3 * 1024 * 1024), "3.0MB")


class TestDisplayWidth(unittest.TestCase):
    """双宽字符对齐 —— Python 的 f"{s:<5}" 按字符数补齐, 中文会错位."""

    def test_ascii_width_equals_length(self):
        self.assertEqual(kmonitor.dwidth("abc"), 3)
        self.assertEqual(kmonitor.dwidth(""), 0)

    def test_cjk_counts_two_columns(self):
        self.assertEqual(kmonitor.dwidth("状态"), 4)
        self.assertEqual(kmonitor.dwidth("睡眠"), 4)
        self.assertEqual(kmonitor.dwidth("a状态b"), 6)

    def test_ljust_rjust_pad_by_columns(self):
        self.assertEqual(kmonitor.dwidth(kmonitor.ljust("状态", 8)), 8)
        self.assertEqual(kmonitor.dwidth(kmonitor.rjust("睡眠", 8)), 8)
        self.assertTrue(kmonitor.ljust("状态", 8).startswith("状态"))
        self.assertTrue(kmonitor.rjust("睡眠", 8).endswith("睡眠"))

    def test_no_padding_when_already_wide_enough(self):
        self.assertEqual(kmonitor.ljust("状态", 2), "状态")

    def test_table_columns_line_up(self):
        """同一列在各行必须从同一个显示列开始 —— 这是原来错位的病根.

        做法: 每行第 2 列放同一个标记串, 断言它前面的内容显示宽度一致。
        """
        mark = "@@"
        lines = kmonitor.table(("状态", mark), [("睡眠", mark), ("运行", mark),
                                               ("停止", mark)])
        prefixes = {kmonitor.dwidth(line[:line.index(mark)]) for line in lines}
        self.assertEqual(len(prefixes), 1,
                         f"标记列的起始显示位置不一致: {prefixes}")

    def test_table_with_cjk_and_ascii_mixed(self):
        mark = "@@"
        lines = kmonitor.table(("prog", mark),
                               [("/bin/sh", mark), ("中文程序名", mark)])
        prefixes = {kmonitor.dwidth(line[:line.index(mark)]) for line in lines}
        self.assertEqual(len(prefixes), 1)

    def test_table_right_align_puts_numbers_flush(self):
        lines = kmonitor.table(("n",), [("1",), ("1000",)], aligns=["r"])
        widths = {kmonitor.dwidth(l) for l in lines}
        self.assertEqual(len(widths), 1)      # 右对齐后各行等宽

    def test_ps_output_program_column_lines_up(self):
        """真实 ps 输出里, 程序名列在表头与数据行必须从同一显示列开始."""
        k, term, fs = make_monitored()
        p = make_proc(k, fs)
        p.name = "/bin/verylongprogramname"
        p.state = kmod.SLEEPING              # 中文"睡眠", 双宽
        out = run_monitor(k, ["ps"])
        head = next(l for l in out.splitlines() if l.startswith("PID"))
        data = next(l for l in out.splitlines() if p.name in l)
        self.assertEqual(kmonitor.dwidth(head[:head.index("程序")]),
                         kmonitor.dwidth(data[:data.index(p.name)]))


class TestInfoFsNames(unittest.TestCase):
    """info fs 要列出被改动的文件名与目录名."""

    def setUp(self):
        self.k, self.term, self.fs = make_monitored()

    def test_lists_new_file_with_path(self):
        self.fs.create("/brand-new.txt", 0o644)
        out = run_monitor(self.k, ["info fs"])
        self.assertIn("/brand-new.txt", out)
        self.assertIn("新建", out)

    def test_lists_modified_file_with_path(self):
        self.fs.write(self.fs.walk("/hello.txt"), 0, b"changed")
        out = run_monitor(self.k, ["info fs"])
        self.assertIn("/hello.txt", out)
        self.assertIn("改过的文件", out)

    def test_lists_modified_directory(self):
        self.fs.create("/sub/added", 0o644)
        out = run_monitor(self.k, ["info fs"])
        self.assertIn("/sub", out)
        self.assertIn("改过的目录", out)

    def test_nested_path_is_full(self):
        self.fs.mkdir("/d1", 0o755)
        self.fs.mkdir("/d1/d2", 0o755)
        self.fs.create("/d1/d2/deep.txt", 0o644)
        self.assertIn("/d1/d2/deep.txt", run_monitor(self.k, ["info fs"]))

    def test_deleted_file_keeps_full_path(self):
        """删掉的文件已从目录树消失, 靠记下的 (父, 名字) 拼回完整路径 ——
        否则只剩一个孤零零的文件名, 看不出在哪个目录。"""
        self.fs.unlink("/sub/note.txt")
        out = run_monitor(self.k, ["info fs"])
        self.assertIn("/sub/note.txt", out)
        self.assertIn("已删除", out)

    def test_changed_paths_returns_structured_rows(self):
        self.fs.create("/x", 0o644)
        self.fs.write(self.fs.walk("/x"), 0, b"abc")
        rows = self.fs.changed_paths()
        entry = [r for r in rows if r[0] == "/x"]
        self.assertEqual(len(entry), 1)
        path, kind, ino, size = entry[0]
        self.assertEqual(kind, "新建")
        self.assertEqual(size, 3)
        self.assertGreater(ino, self.fs.base.sb.ninodes)

    def test_no_changes_lists_nothing(self):
        out = run_monitor(self.k, ["info fs"])
        self.assertNotIn("改动明细", out)
        self.assertEqual(self.fs.changed_paths(), [])

    def test_limit_caps_the_listing(self):
        for i in range(8):
            self.fs.create(f"/f{i}", 0o644)
        out = []
        mon = Monitor(self.k, write=lambda s: out.append(s))
        mon.info_fs(limit=3)
        text = "".join(out)
        self.assertIn("只列前 3 项", text)
        self.assertIn("/f0", text)
        self.assertNotIn("/f7", text)

    def test_rename_shows_up_as_changed_directory(self):
        """纯改名不动文件内容, 所以体现为父目录被改过(路径为 /)."""
        self.fs.rename("/hello.txt", "/renamed.txt")
        out = run_monitor(self.k, ["info fs"])
        self.assertIn("改过的目录", out)
        self.assertNotIn("<inode 1>", out)      # 根目录该显示成 /

    def test_root_directory_shown_as_slash(self):
        self.fs.create("/x", 0o644)
        rows = self.fs.changed_paths()
        root_rows = [r for r in rows if r[2] == 1]
        self.assertEqual(len(root_rows), 1)
        self.assertEqual(root_rows[0][0], "/")


class TestArgvSplit(unittest.TestCase):
    """命令行拆分: 程序名之后原样透传, 之前归仿真器.

    argparse 的 nargs=REMAINDER 做不到这件事 —— 它会把本该落到 program 的
    位置参数也吞进 args, 于是 `--trace /bin/date` 会跑成引导链。
    """

    def split(self, *argv):
        import emulator
        return emulator.split_argv(list(argv))

    def test_image_only_runs_boot_chain(self):
        head, tail = self.split("img")
        self.assertEqual((head, tail), (["img"], []))

    def test_image_and_program(self):
        head, tail = self.split("img", "/bin/date")
        self.assertEqual((head, tail), (["img"], ["/bin/date"]))

    def test_option_before_image(self):
        head, tail = self.split("--trace", "img", "/bin/date")
        self.assertEqual((head, tail), (["--trace", "img"], ["/bin/date"]))

    def test_option_between_image_and_program(self):
        """这条以前是坏的: /bin/date 会被 REMAINDER 吞掉."""
        head, tail = self.split("img", "--trace", "/bin/date")
        self.assertEqual((head, tail), (["img", "--trace"], ["/bin/date"]))

    def test_program_options_pass_through(self):
        head, tail = self.split("img", "/usr/bin/ls", "-l", "/etc")
        self.assertEqual(head, ["img"])
        self.assertEqual(tail, ["/usr/bin/ls", "-l", "/etc"])

    def test_option_after_program_goes_to_program(self):
        """程序名之后的 --trace 是给被仿真程序的, 不归仿真器(有意如此)."""
        head, tail = self.split("img", "/bin/date", "--trace")
        self.assertEqual(head, ["img"])
        self.assertEqual(tail, ["/bin/date", "--trace"])

    def test_value_option_takes_its_value(self):
        head, tail = self.split("img", "--escape", "b", "/bin/sh")
        self.assertEqual(head, ["img", "--escape", "b"])
        self.assertEqual(tail, ["/bin/sh"])

    def test_value_option_before_image(self):
        head, tail = self.split("--offset", "1024", "img", "/bin/sh")
        self.assertEqual(head, ["--offset", "1024", "img"])
        self.assertEqual(tail, ["/bin/sh"])

    def test_multiple_options(self):
        head, tail = self.split("img", "--trace", "--monitor",
                                "--max-insns", "999", "/bin/sh", "-c", "x")
        self.assertEqual(head, ["img", "--trace", "--monitor",
                                "--max-insns", "999"])
        self.assertEqual(tail, ["/bin/sh", "-c", "x"])

    def test_bare_dash_is_a_positional(self):
        head, tail = self.split("img", "-")
        self.assertEqual(tail, ["-"])


class TestProfile(unittest.TestCase):
    def setUp(self):
        self.k, self.term, self.fs = make_monitored()
        self.p = make_proc(self.k, self.fs)
        self.p.name = "/bin/testprog"

    def test_info_profile_off_by_default(self):
        out = run_monitor(self.k, ["info profile"])
        self.assertIn("未开启", out)

    def test_prof_on_off_toggles(self):
        out = run_monitor(self.k, ["prof on"])
        self.assertIn("已开启", out)
        self.assertTrue(self.k.profiling)
        out = run_monitor(self.k, ["prof off"])
        self.assertIn("已关闭", out)
        self.assertFalse(self.k.profiling)

    def test_prof_reset(self):
        run_monitor(self.k, ["prof on"])
        self.k._profiler.insns = 5
        out = run_monitor(self.k, ["prof reset"])
        self.assertIn("清零", out)
        self.assertEqual(self.k._profiler.insns, 0)

    def test_prof_reset_without_enable(self):
        self.assertIn("未开启", run_monitor(self.k, ["prof reset"]))

    def test_prof_unknown_subcommand_shows_usage(self):
        self.assertIn("用法", run_monitor(self.k, ["prof bogus"]))

    def test_info_profile_renders_mix_and_derived(self):
        self.k.set_profiling(True)
        prof = self.k._profiler
        prof.insns = 100
        prof.cat_counts[cpu86.CAT_MOV] = 40
        prof.cat_counts[cpu86.CAT_ALU] = 30
        prof.cat_counts[cpu86.CAT_BRANCH] = 20
        prof.cat_counts[cpu86.CAT_STRING] = 10
        prof.rep_elems = 500
        prof.hot = {0x1000 >> prof.bucket_shift: 60,
                    0x2000 >> prof.bucket_shift: 40}
        out = run_monitor(self.k, ["info profile"])
        self.assertIn("已剖析 100 条指令", out)
        self.assertIn("MOV", out)
        self.assertIn("40.0%", out)              # MOV 占比
        self.assertIn("分支", out)
        # 派生指标: 访存(MOV+栈+串)=50%, 控制流 20%, 块长 5.0, rep 放大 50.0
        self.assertIn("访存指令占比  50.0%", out)
        self.assertIn("控制流密度    20.0%", out)
        self.assertIn("平均基本块长  5.0", out)
        self.assertIn("rep 放大倍数  50.0", out)

    def test_info_cpu_shows_profiling_state(self):
        self.assertIn("性能剖析: 关", run_monitor(self.k, ["info cpu"]))
        self.k.set_profiling(True)
        self.assertIn("性能剖析: 开", run_monitor(self.k, ["info cpu"]))


if __name__ == "__main__":
    unittest.main()
