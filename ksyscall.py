"""Linux 0.11 系统调用层.

调用号在 eax, 参数在 ebx/ecx/edx, 返回值写回 eax(成功 >=0, 失败 -errno)。
调用表照镜像内核 include/linux/sys.h 的 sys_call_table —— 该镜像的内核
是打过补丁的后期版本, 共 87 个调用(0..86), 比经典 0.11 的 72 个多出
sigsuspend/setrlimit/getrlimit/lstat/readlink 等, 而镜像里的 libc 正好
用到它们(bash 的 ulimit 用 75/76, ls -l 用 84/85)。
"""

from __future__ import annotations

import struct
import time
from typing import Callable, Dict, Optional

import kvfs
from kvfs import (EACCES, EBADF, EEXIST, EINVAL, EISDIR, ENOENT, ENOSYS,
                  ENOTDIR, ENOTTY, EPERM, ESPIPE, FsError, O_ACCMODE,
                  O_APPEND, O_CREAT, O_EXCL, O_RDONLY, O_TRUNC, O_WRONLY)
from x86mem import SegFault

# ---- 调用号(镜像内核 sys_call_table 的顺序) ----
NR_SETUP, NR_EXIT, NR_FORK, NR_READ, NR_WRITE, NR_OPEN, NR_CLOSE = range(7)
NR_WAITPID, NR_CREAT, NR_LINK, NR_UNLINK, NR_EXECVE, NR_CHDIR = range(7, 13)
NR_TIME, NR_MKNOD, NR_CHMOD, NR_CHOWN, NR_BREAK, NR_STAT, NR_LSEEK = range(13, 20)
NR_GETPID, NR_MOUNT, NR_UMOUNT, NR_SETUID, NR_GETUID, NR_STIME = range(20, 26)
NR_PTRACE, NR_ALARM, NR_FSTAT, NR_PAUSE, NR_UTIME, NR_STTY, NR_GTTY = range(26, 33)
NR_ACCESS, NR_NICE, NR_FTIME, NR_SYNC, NR_KILL, NR_RENAME = range(33, 39)
NR_MKDIR, NR_RMDIR, NR_DUP, NR_PIPE, NR_TIMES, NR_PROF, NR_BRK = range(39, 46)
NR_SETGID, NR_GETGID, NR_SIGNAL, NR_GETEUID, NR_GETEGID = range(46, 51)
NR_ACCT, NR_PHYS, NR_LOCK, NR_IOCTL, NR_FCNTL, NR_MPX = range(51, 57)
NR_SETPGID, NR_ULIMIT, NR_UNAME, NR_UMASK, NR_CHROOT, NR_USTAT = range(57, 63)
NR_DUP2, NR_GETPPID, NR_GETPGRP, NR_SETSID, NR_SIGACTION = range(63, 68)
NR_SGETMASK, NR_SSETMASK, NR_SETREUID, NR_SETREGID = range(68, 72)
NR_SIGSUSPEND, NR_SIGPENDING, NR_SETHOSTNAME, NR_SETRLIMIT = range(72, 76)
NR_GETRLIMIT, NR_GETRUSAGE, NR_GETTIMEOFDAY, NR_SETTIMEOFDAY = range(76, 80)
NR_GETGROUPS, NR_SETGROUPS, NR_SELECT, NR_SYMLINK = range(80, 84)
NR_LSTAT, NR_READLINK, NR_USELIB = range(84, 87)

NR_SYSCALLS = 87

SEEK_SET, SEEK_CUR, SEEK_END = 0, 1, 2

# struct stat: 32 字节。类型取自镜像 /usr/include/sys/types.h ——
# dev_t/ino_t/umode_t/uid_t 是 u16, nlink_t 与 gid_t 是 u8, off_t/time_t 是 long。
# size/时间用无符号打包: 内核 cp_stat 是 put_fs_long 逐字段原样拷 32 位,
# 由程序自己解释符号。镜像里 /etc/mtab 的 mtime 就超出了有符号 i32 范围。
STAT_FMT = struct.Struct("<HHHBxHBxHxxIIII")


def pack_stat(fields) -> bytes:
    """打包 struct stat, 各字段按其宽度截断(照内核逐字段拷 32 位的做法)."""
    dev, ino, mode, nlink, uid, gid, rdev, size, at, mt, ct = fields
    return STAT_FMT.pack(dev & 0xFFFF, ino & 0xFFFF, mode & 0xFFFF,
                         nlink & 0xFF, uid & 0xFFFF, gid & 0xFF,
                         rdev & 0xFFFF, size & 0xFFFFFFFF,
                         at & 0xFFFFFFFF, mt & 0xFFFFFFFF, ct & 0xFFFFFFFF)

# 终端窗口尺寸与 termios 打包见 ktty; 此处只需 ioctl 的分派
UTSNAME_FIELDS = ("Linux", "(none)", "0.11", "0.11", "i386")


class Blocked(Exception):
    """系统调用无法立即完成, 调度器应让进程睡在 channel 上.

    调度器会把 eip 回卷 2 字节(int 0x80 是 CD 80), 唤醒后整条系统调用重做。
    """

    def __init__(self, channel):
        super().__init__(f"阻塞于 {channel!r}")
        self.channel = channel


class SyscallTable:
    """系统调用分派表."""

    def __init__(self, kernel):
        self.k = kernel
        self.handlers: Dict[int, Callable] = {}
        self._register()

    def _register(self) -> None:
        k = self.k
        self.handlers.update({
            NR_SETUP: k.sys_setup,
            NR_EXIT: k.sys_exit,
            NR_READ: k.sys_read,
            NR_WRITE: k.sys_write,
            NR_OPEN: k.sys_open,
            NR_CLOSE: k.sys_close,
            NR_CREAT: k.sys_creat,
            NR_LINK: k.sys_link,
            NR_UNLINK: k.sys_unlink,
            NR_CHDIR: k.sys_chdir,
            NR_TIME: k.sys_time,
            NR_MKNOD: k.sys_mknod,
            NR_CHMOD: k.sys_chmod,
            NR_CHOWN: k.sys_chown,
            NR_STAT: k.sys_stat,
            NR_LSEEK: k.sys_lseek,
            NR_GETPID: k.sys_getpid,
            NR_SETUID: k.sys_setuid,
            NR_GETUID: k.sys_getuid,
            NR_STIME: k.sys_stime,
            NR_FSTAT: k.sys_fstat,
            NR_UTIME: k.sys_utime,
            NR_ACCESS: k.sys_access,
            NR_NICE: k.sys_nice,
            NR_SYNC: k.sys_sync,
            NR_RENAME: k.sys_rename,
            NR_MKDIR: k.sys_mkdir,
            NR_RMDIR: k.sys_rmdir,
            NR_DUP: k.sys_dup,
            NR_BRK: k.sys_brk,
            NR_SETGID: k.sys_setgid,
            NR_GETGID: k.sys_getgid,
            NR_GETEUID: k.sys_geteuid,
            NR_GETEGID: k.sys_getegid,
            NR_IOCTL: k.sys_ioctl,
            NR_FCNTL: k.sys_fcntl,
            NR_UMASK: k.sys_umask,
            NR_CHROOT: k.sys_chroot,
            NR_DUP2: k.sys_dup2,
            NR_GETPPID: k.sys_getppid,
            NR_GETPGRP: k.sys_getpgrp,
            NR_UNAME: k.sys_uname,
            NR_MOUNT: k.sys_mount,
            NR_UMOUNT: k.sys_umount,
            NR_ULIMIT: k.sys_ulimit,
            NR_TIMES: k.sys_times,
            NR_LSTAT: k.sys_stat,          # minix v1 无符号链接, 等价 stat
            NR_READLINK: k.sys_readlink,
            NR_SYMLINK: k.sys_symlink,
            NR_GETRLIMIT: k.sys_getrlimit,
            NR_SETRLIMIT: k.sys_setrlimit,
            NR_GETGROUPS: k.sys_getgroups,
            NR_GETTIMEOFDAY: k.sys_gettimeofday,
            NR_SETHOSTNAME: k.sys_sethostname,
        })

    def dispatch(self, proc, nr: int, a: int, b: int, c: int) -> int:
        if nr >= NR_SYSCALLS:
            return -ENOSYS                  # 内核 bad_sys_call
        fn = self.handlers.get(nr)
        if fn is None:
            return -ENOSYS
        return fn(proc, a, b, c)
