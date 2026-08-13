# 设计文档

按子系统整理的算法与代码流程文档。每篇都是"读代码前先读它":有 `## Context`
导语、编号小节配 `文件:行` 交叉引用、走查示例、`## 设计取舍` 与 `## 关键函数索引`。

## 浏览器(只读那一半)

- [minixfs-and-browser.md](minixfs-and-browser.md) —— Minix v1 盘上布局、超级块/inode、
  zone 映射与间接块、位图语义、checkfs(fsck);以及 `minix_shell.py` 交互层与
  `pager.py` 分页器。

## 仿真器

- [emulator-overview.md](emulator-overview.md) —— 总体架构与单向依赖、用户态仿真模型、
  引导链(内核 init 函数而非 /bin/init)、命令行契约、终端 I/O 分平台。**先读这篇。**
- [x86-decode-and-emulation.md](x86-decode-and-emulation.md) —— CPU 层(cpu86.py +
  x86mem.py):取指-解码-执行主线、ModRM/SIB 寻址、指令组、标志模型、指令长度、异常路径。
- [kernel-process-and-scheduler.md](kernel-process-and-scheduler.md) —— kernel.py:
  进程模型、协作式调度器、异常驱动控制流、fork/execve/waitpid、阻塞唤醒、信号、init 状态机。
- [syscalls-and-loading.md](syscalls-and-loading.md) —— ksyscall.py + kexec.py:
  int 0x80 ABI 与分派、各系统调用族、a.out ZMAGIC 装载、初始栈布局(create_tables)。
- [vfs-overlay-pipes-devices.md](vfs-overlay-pipes-devices.md) —— kvfs.py:
  写时复制覆盖层、文件对象与描述符、管道(按描述符计数)、设备表。
- [terminal-and-line-discipline.md](terminal-and-line-discipline.md) —— ktty.py:
  termios 模型、行规程(规范/非规范)、转义键、输出与控制台留存、ioctl、平台后端。
- [monitor-and-debugger.md](monitor-and-debugger.md) —— kmonitor.py + cpu_disasm.py:
  monitor 架构与视图、CJK 排版、性能剖析视图、gdb 风格单步调试与只读反汇编器。
