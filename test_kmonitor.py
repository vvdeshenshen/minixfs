"""monitor 与转义键测试.

monitor 的读写全部可注入, 所以用脚本化命令驱动、捕获输出即可断言,
不必真的占用宿主终端。全部跑在迷你镜像上, 不依赖 hdc-0.11.img。
"""

import unittest

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

    def test_trace_toggle(self):
        self.assertIn("已开启", run_monitor(self.k, ["trace on"]))
        self.assertTrue(self.k.verbose)
        self.assertIn("已关闭", run_monitor(self.k, ["trace off"]))
        self.assertFalse(self.k.verbose)
        self.assertIn("用法", run_monitor(self.k, ["trace bogus"]))

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


if __name__ == "__main__":
    unittest.main()
