const int MAX_SYSCALL_NUM = 348;
struct syscall_entry syscalls[] = {
   {   // 0
  /*.name  =*/ "restart_syscall",
  /*.nargs =*/ 0,
  /*.args  =*/ {ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 1
  /*.name  =*/ "exit",
  /*.nargs =*/ 1,
  /*.args  =*/ {ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 2
  /*.name  =*/ "fork",
  /*.nargs =*/ 0,
  /*.args  =*/ {ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 3
  /*.name  =*/ "read",
  /*.nargs =*/ 3,
  /*.args  =*/ {ARG_INT, ARG_STR, ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 4
  /*.name  =*/ "write",
  /*.nargs =*/ 3,
  /*.args  =*/ {ARG_INT, ARG_STR, ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 5
  /*.name  =*/ "open",
  /*.nargs =*/ 3,
  /*.args  =*/ {ARG_STR, ARG_INT, ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 6
  /*.name  =*/ "close",
  /*.nargs =*/ 1,
  /*.args  =*/ {ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 7
  /*.name  =*/ "waitpid",
  /*.nargs =*/ 3,
  /*.args  =*/ {ARG_INT, ARG_PTR, ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 8
  /*.name  =*/ "creat",
  /*.nargs =*/ 2,
  /*.args  =*/ {ARG_STR, ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 9
  /*.name  =*/ "link",
  /*.nargs =*/ 2,
  /*.args  =*/ {ARG_STR, ARG_STR, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 10
  /*.name  =*/ "unlink",
  /*.nargs =*/ 1,
  /*.args  =*/ {ARG_STR, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 11
  /*.name  =*/ "execve",
  /*.nargs =*/ 3,
  /*.args  =*/ {ARG_STR, ARG_PTR, ARG_PTR, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 12
  /*.name  =*/ "chdir",
  /*.nargs =*/ 1,
  /*.args  =*/ {ARG_STR, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 13
  /*.name  =*/ "time",
  /*.nargs =*/ 1,
  /*.args  =*/ {ARG_PTR, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 14
  /*.name  =*/ "mknod",
  /*.nargs =*/ 3,
  /*.args  =*/ {ARG_STR, ARG_INT, ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 15
  /*.name  =*/ "chmod",
  /*.nargs =*/ 2,
  /*.args  =*/ {ARG_STR, ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 16
  /*.name  =*/ "lchown",
  /*.nargs =*/ 3,
  /*.args  =*/ {ARG_STR, ARG_INT, ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 17
  /*.name  =*/ "break",
  /*.nargs =*/ 6,
  /*.args  =*/ {ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR}},
   {   // 18
  /*.name  =*/ "oldstat",
  /*.nargs =*/ 6,
  /*.args  =*/ {ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR}},
   {   // 19
  /*.name  =*/ "lseek",
  /*.nargs =*/ 3,
  /*.args  =*/ {ARG_INT, ARG_INT, ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 20
  /*.name  =*/ "getpid",
  /*.nargs =*/ 0,
  /*.args  =*/ {ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 21
  /*.name  =*/ "mount",
  /*.nargs =*/ 5,
  /*.args  =*/ {ARG_STR, ARG_STR, ARG_STR, ARG_INT, ARG_PTR, ARG_UNKNOWN}},
   {   // 22
  /*.name  =*/ "umount",
  /*.nargs =*/ 2,
  /*.args  =*/ {ARG_STR, ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 23
  /*.name  =*/ "setuid",
  /*.nargs =*/ 1,
  /*.args  =*/ {ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 24
  /*.name  =*/ "getuid",
  /*.nargs =*/ 0,
  /*.args  =*/ {ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 25
  /*.name  =*/ "stime",
  /*.nargs =*/ 1,
  /*.args  =*/ {ARG_PTR, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 26
  /*.name  =*/ "ptrace",
  /*.nargs =*/ 4,
  /*.args  =*/ {ARG_INT, ARG_INT, ARG_INT, ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 27
  /*.name  =*/ "alarm",
  /*.nargs =*/ 1,
  /*.args  =*/ {ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 28
  /*.name  =*/ "oldfstat",
  /*.nargs =*/ 6,
  /*.args  =*/ {ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR}},
   {   // 29
  /*.name  =*/ "pause",
  /*.nargs =*/ 0,
  /*.args  =*/ {ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 30
  /*.name  =*/ "utime",
  /*.nargs =*/ 2,
  /*.args  =*/ {ARG_STR, ARG_PTR, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 31
  /*.name  =*/ "stty",
  /*.nargs =*/ 6,
  /*.args  =*/ {ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR}},
   {   // 32
  /*.name  =*/ "gtty",
  /*.nargs =*/ 6,
  /*.args  =*/ {ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR}},
   {   // 33
  /*.name  =*/ "access",
  /*.nargs =*/ 2,
  /*.args  =*/ {ARG_STR, ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 34
  /*.name  =*/ "nice",
  /*.nargs =*/ 1,
  /*.args  =*/ {ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 35
  /*.name  =*/ "ftime",
  /*.nargs =*/ 6,
  /*.args  =*/ {ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR}},
   {   // 36
  /*.name  =*/ "sync",
  /*.nargs =*/ 0,
  /*.args  =*/ {ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 37
  /*.name  =*/ "kill",
  /*.nargs =*/ 2,
  /*.args  =*/ {ARG_INT, ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 38
  /*.name  =*/ "rename",
  /*.nargs =*/ 2,
  /*.args  =*/ {ARG_STR, ARG_STR, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 39
  /*.name  =*/ "mkdir",
  /*.nargs =*/ 2,
  /*.args  =*/ {ARG_STR, ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 40
  /*.name  =*/ "rmdir",
  /*.nargs =*/ 1,
  /*.args  =*/ {ARG_STR, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 41
  /*.name  =*/ "dup",
  /*.nargs =*/ 1,
  /*.args  =*/ {ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 42
  /*.name  =*/ "pipe",
  /*.nargs =*/ 1,
  /*.args  =*/ {ARG_PTR, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 43
  /*.name  =*/ "times",
  /*.nargs =*/ 1,
  /*.args  =*/ {ARG_PTR, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 44
  /*.name  =*/ "prof",
  /*.nargs =*/ 6,
  /*.args  =*/ {ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR}},
   {   // 45
  /*.name  =*/ "brk",
  /*.nargs =*/ 1,
  /*.args  =*/ {ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 46
  /*.name  =*/ "setgid",
  /*.nargs =*/ 1,
  /*.args  =*/ {ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 47
  /*.name  =*/ "getgid",
  /*.nargs =*/ 0,
  /*.args  =*/ {ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 48
  /*.name  =*/ "signal",
  /*.nargs =*/ 2,
  /*.args  =*/ {ARG_INT, ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 49
  /*.name  =*/ "geteuid",
  /*.nargs =*/ 0,
  /*.args  =*/ {ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 50
  /*.name  =*/ "getegid",
  /*.nargs =*/ 0,
  /*.args  =*/ {ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 51
  /*.name  =*/ "acct",
  /*.nargs =*/ 1,
  /*.args  =*/ {ARG_STR, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 52
  /*.name  =*/ "umount2",
  /*.nargs =*/ 6,
  /*.args  =*/ {ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR}},
   {   // 53
  /*.name  =*/ "lock",
  /*.nargs =*/ 6,
  /*.args  =*/ {ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR}},
   {   // 54
  /*.name  =*/ "ioctl",
  /*.nargs =*/ 3,
  /*.args  =*/ {ARG_INT, ARG_INT, ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 55
  /*.name  =*/ "fcntl",
  /*.nargs =*/ 3,
  /*.args  =*/ {ARG_INT, ARG_INT, ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 56
  /*.name  =*/ "mpx",
  /*.nargs =*/ 6,
  /*.args  =*/ {ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR}},
   {   // 57
  /*.name  =*/ "setpgid",
  /*.nargs =*/ 2,
  /*.args  =*/ {ARG_INT, ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 58
  /*.name  =*/ "ulimit",
  /*.nargs =*/ 6,
  /*.args  =*/ {ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR}},
   {   // 59
  /*.name  =*/ "oldolduname",
  /*.nargs =*/ 6,
  /*.args  =*/ {ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR}},
   {   // 60
  /*.name  =*/ "umask",
  /*.nargs =*/ 1,
  /*.args  =*/ {ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 61
  /*.name  =*/ "chroot",
  /*.nargs =*/ 1,
  /*.args  =*/ {ARG_STR, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 62
  /*.name  =*/ "ustat",
  /*.nargs =*/ 2,
  /*.args  =*/ {ARG_INT, ARG_PTR, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 63
  /*.name  =*/ "dup2",
  /*.nargs =*/ 2,
  /*.args  =*/ {ARG_INT, ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 64
  /*.name  =*/ "getppid",
  /*.nargs =*/ 0,
  /*.args  =*/ {ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 65
  /*.name  =*/ "getpgrp",
  /*.nargs =*/ 0,
  /*.args  =*/ {ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 66
  /*.name  =*/ "setsid",
  /*.nargs =*/ 0,
  /*.args  =*/ {ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 67
  /*.name  =*/ "sigaction",
  /*.nargs =*/ 3,
  /*.args  =*/ {ARG_INT, ARG_PTR, ARG_PTR, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 68
  /*.name  =*/ "sgetmask",
  /*.nargs =*/ 0,
  /*.args  =*/ {ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 69
  /*.name  =*/ "ssetmask",
  /*.nargs =*/ 1,
  /*.args  =*/ {ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 70
  /*.name  =*/ "setreuid",
  /*.nargs =*/ 2,
  /*.args  =*/ {ARG_INT, ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 71
  /*.name  =*/ "setregid",
  /*.nargs =*/ 2,
  /*.args  =*/ {ARG_INT, ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 72
  /*.name  =*/ "sigsuspend",
  /*.nargs =*/ 3,
  /*.args  =*/ {ARG_INT, ARG_INT, ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 73
  /*.name  =*/ "sigpending",
  /*.nargs =*/ 1,
  /*.args  =*/ {ARG_PTR, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 74
  /*.name  =*/ "sethostname",
  /*.nargs =*/ 2,
  /*.args  =*/ {ARG_STR, ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 75
  /*.name  =*/ "setrlimit",
  /*.nargs =*/ 2,
  /*.args  =*/ {ARG_INT, ARG_PTR, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 76
  /*.name  =*/ "getrlimit",
  /*.nargs =*/ 2,
  /*.args  =*/ {ARG_INT, ARG_PTR, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 77
  /*.name  =*/ "getrusage",
  /*.nargs =*/ 2,
  /*.args  =*/ {ARG_INT, ARG_PTR, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 78
  /*.name  =*/ "gettimeofday",
  /*.nargs =*/ 2,
  /*.args  =*/ {ARG_PTR, ARG_PTR, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 79
  /*.name  =*/ "settimeofday",
  /*.nargs =*/ 2,
  /*.args  =*/ {ARG_PTR, ARG_PTR, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 80
  /*.name  =*/ "getgroups",
  /*.nargs =*/ 2,
  /*.args  =*/ {ARG_INT, ARG_PTR, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 81
  /*.name  =*/ "setgroups",
  /*.nargs =*/ 2,
  /*.args  =*/ {ARG_INT, ARG_PTR, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 82
  /*.name  =*/ "select",
  /*.nargs =*/ 5,
  /*.args  =*/ {ARG_INT, ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR, ARG_UNKNOWN}},
   {   // 83
  /*.name  =*/ "symlink",
  /*.nargs =*/ 2,
  /*.args  =*/ {ARG_STR, ARG_STR, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 84
  /*.name  =*/ "oldlstat",
  /*.nargs =*/ 6,
  /*.args  =*/ {ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR}},
   {   // 85
  /*.name  =*/ "readlink",
  /*.nargs =*/ 3,
  /*.args  =*/ {ARG_STR, ARG_STR, ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 86
  /*.name  =*/ "uselib",
  /*.nargs =*/ 1,
  /*.args  =*/ {ARG_STR, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 87
  /*.name  =*/ "swapon",
  /*.nargs =*/ 2,
  /*.args  =*/ {ARG_STR, ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 88
  /*.name  =*/ "reboot",
  /*.nargs =*/ 4,
  /*.args  =*/ {ARG_INT, ARG_INT, ARG_INT, ARG_PTR, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 89
  /*.name  =*/ "readdir",
  /*.nargs =*/ 6,
  /*.args  =*/ {ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR}},
   {   // 90
  /*.name  =*/ "mmap",
  /*.nargs =*/ 6,
  /*.args  =*/ {ARG_INT, ARG_INT, ARG_INT, ARG_INT, ARG_INT, ARG_INT}},
   {   // 91
  /*.name  =*/ "munmap",
  /*.nargs =*/ 2,
  /*.args  =*/ {ARG_INT, ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 92
  /*.name  =*/ "truncate",
  /*.nargs =*/ 2,
  /*.args  =*/ {ARG_STR, ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 93
  /*.name  =*/ "ftruncate",
  /*.nargs =*/ 2,
  /*.args  =*/ {ARG_INT, ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 94
  /*.name  =*/ "fchmod",
  /*.nargs =*/ 2,
  /*.args  =*/ {ARG_INT, ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 95
  /*.name  =*/ "fchown",
  /*.nargs =*/ 3,
  /*.args  =*/ {ARG_INT, ARG_INT, ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 96
  /*.name  =*/ "getpriority",
  /*.nargs =*/ 2,
  /*.args  =*/ {ARG_INT, ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 97
  /*.name  =*/ "setpriority",
  /*.nargs =*/ 3,
  /*.args  =*/ {ARG_INT, ARG_INT, ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 98
  /*.name  =*/ "profil",
  /*.nargs =*/ 6,
  /*.args  =*/ {ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR}},
   {   // 99
  /*.name  =*/ "statfs",
  /*.nargs =*/ 2,
  /*.args  =*/ {ARG_STR, ARG_PTR, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 100
  /*.name  =*/ "fstatfs",
  /*.nargs =*/ 2,
  /*.args  =*/ {ARG_INT, ARG_PTR, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 101
  /*.name  =*/ "ioperm",
  /*.nargs =*/ 6,
  /*.args  =*/ {ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR}},
   {   // 102
  /*.name  =*/ "socketcall",
  /*.nargs =*/ 2,
  /*.args  =*/ {ARG_INT, ARG_PTR, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 103
  /*.name  =*/ "syslog",
  /*.nargs =*/ 3,
  /*.args  =*/ {ARG_INT, ARG_STR, ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 104
  /*.name  =*/ "setitimer",
  /*.nargs =*/ 3,
  /*.args  =*/ {ARG_INT, ARG_PTR, ARG_PTR, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 105
  /*.name  =*/ "getitimer",
  /*.nargs =*/ 2,
  /*.args  =*/ {ARG_INT, ARG_PTR, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 106
  /*.name  =*/ "stat",
  /*.nargs =*/ 2,
  /*.args  =*/ {ARG_STR, ARG_PTR, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 107
  /*.name  =*/ "lstat",
  /*.nargs =*/ 2,
  /*.args  =*/ {ARG_STR, ARG_PTR, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 108
  /*.name  =*/ "fstat",
  /*.nargs =*/ 2,
  /*.args  =*/ {ARG_INT, ARG_PTR, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 109
  /*.name  =*/ "olduname",
  /*.nargs =*/ 1,
  /*.args  =*/ {ARG_PTR, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 110
  /*.name  =*/ "iopl",
  /*.nargs =*/ 1,
  /*.args  =*/ {ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 111
  /*.name  =*/ "vhangup",
  /*.nargs =*/ 0,
  /*.args  =*/ {ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 112
  /*.name  =*/ "idle",
  /*.nargs =*/ 6,
  /*.args  =*/ {ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR}},
   {   // 113
  /*.name  =*/ "vm86old",
  /*.nargs =*/ 1,
  /*.args  =*/ {ARG_PTR, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 114
  /*.name  =*/ "wait4",
  /*.nargs =*/ 4,
  /*.args  =*/ {ARG_INT, ARG_PTR, ARG_INT, ARG_PTR, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 115
  /*.name  =*/ "swapoff",
  /*.nargs =*/ 1,
  /*.args  =*/ {ARG_STR, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 116
  /*.name  =*/ "sysinfo",
  /*.nargs =*/ 1,
  /*.args  =*/ {ARG_PTR, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 117
  /*.name  =*/ "ipc",
  /*.nargs =*/ 6,
  /*.args  =*/ {ARG_INT, ARG_INT, ARG_INT, ARG_INT, ARG_INT, ARG_INT}},
   {   // 118
  /*.name  =*/ "fsync",
  /*.nargs =*/ 1,
  /*.args  =*/ {ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 119
  /*.name  =*/ "sigreturn",
  /*.nargs =*/ 6,
  /*.args  =*/ {ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR}},
   {   // 120
  /*.name  =*/ "clone",
  /*.nargs =*/ 5,
  /*.args  =*/ {ARG_INT, ARG_INT, ARG_PTR, ARG_PTR, ARG_INT, ARG_UNKNOWN}},
   {   // 121
  /*.name  =*/ "setdomainname",
  /*.nargs =*/ 2,
  /*.args  =*/ {ARG_STR, ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 122
  /*.name  =*/ "uname",
  /*.nargs =*/ 1,
  /*.args  =*/ {ARG_PTR, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 123
  /*.name  =*/ "modify_ldt",
  /*.nargs =*/ 6,
  /*.args  =*/ {ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR}},
   {   // 124
  /*.name  =*/ "adjtimex",
  /*.nargs =*/ 1,
  /*.args  =*/ {ARG_PTR, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 125
  /*.name  =*/ "mprotect",
  /*.nargs =*/ 3,
  /*.args  =*/ {ARG_INT, ARG_INT, ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 126
  /*.name  =*/ "sigprocmask",
  /*.nargs =*/ 3,
  /*.args  =*/ {ARG_INT, ARG_PTR, ARG_PTR, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 127
  /*.name  =*/ "create_module",
  /*.nargs =*/ 6,
  /*.args  =*/ {ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR}},
   {   // 128
  /*.name  =*/ "init_module",
  /*.nargs =*/ 3,
  /*.args  =*/ {ARG_PTR, ARG_INT, ARG_STR, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 129
  /*.name  =*/ "delete_module",
  /*.nargs =*/ 2,
  /*.args  =*/ {ARG_STR, ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 130
  /*.name  =*/ "get_kernel_syms",
  /*.nargs =*/ 6,
  /*.args  =*/ {ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR}},
   {   // 131
  /*.name  =*/ "quotactl",
  /*.nargs =*/ 4,
  /*.args  =*/ {ARG_INT, ARG_STR, ARG_INT, ARG_PTR, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 132
  /*.name  =*/ "getpgid",
  /*.nargs =*/ 1,
  /*.args  =*/ {ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 133
  /*.name  =*/ "fchdir",
  /*.nargs =*/ 1,
  /*.args  =*/ {ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 134
  /*.name  =*/ "bdflush",
  /*.nargs =*/ 2,
  /*.args  =*/ {ARG_INT, ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 135
  /*.name  =*/ "sysfs",
  /*.nargs =*/ 3,
  /*.args  =*/ {ARG_INT, ARG_INT, ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 136
  /*.name  =*/ "personality",
  /*.nargs =*/ 1,
  /*.args  =*/ {ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 137
  /*.name  =*/ "afs_syscall",
  /*.nargs =*/ 6,
  /*.args  =*/ {ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR}},
   {   // 138
  /*.name  =*/ "setfsuid",
  /*.nargs =*/ 1,
  /*.args  =*/ {ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 139
  /*.name  =*/ "setfsgid",
  /*.nargs =*/ 1,
  /*.args  =*/ {ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 140
  /*.name  =*/ "_llseek",
  /*.nargs =*/ 6,
  /*.args  =*/ {ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR}},
   {   // 141
  /*.name  =*/ "getdents",
  /*.nargs =*/ 3,
  /*.args  =*/ {ARG_INT, ARG_PTR, ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 142
  /*.name  =*/ "_newselect",
  /*.nargs =*/ 6,
  /*.args  =*/ {ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR}},
   {   // 143
  /*.name  =*/ "flock",
  /*.nargs =*/ 2,
  /*.args  =*/ {ARG_INT, ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 144
  /*.name  =*/ "msync",
  /*.nargs =*/ 3,
  /*.args  =*/ {ARG_INT, ARG_INT, ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 145
  /*.name  =*/ "readv",
  /*.nargs =*/ 3,
  /*.args  =*/ {ARG_INT, ARG_PTR, ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 146
  /*.name  =*/ "writev",
  /*.nargs =*/ 3,
  /*.args  =*/ {ARG_INT, ARG_PTR, ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 147
  /*.name  =*/ "getsid",
  /*.nargs =*/ 1,
  /*.args  =*/ {ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 148
  /*.name  =*/ "fdatasync",
  /*.nargs =*/ 1,
  /*.args  =*/ {ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 149
  /*.name  =*/ "_sysctl",
  /*.nargs =*/ 6,
  /*.args  =*/ {ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR}},
   {   // 150
  /*.name  =*/ "mlock",
  /*.nargs =*/ 2,
  /*.args  =*/ {ARG_INT, ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 151
  /*.name  =*/ "munlock",
  /*.nargs =*/ 2,
  /*.args  =*/ {ARG_INT, ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 152
  /*.name  =*/ "mlockall",
  /*.nargs =*/ 1,
  /*.args  =*/ {ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 153
  /*.name  =*/ "munlockall",
  /*.nargs =*/ 0,
  /*.args  =*/ {ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 154
  /*.name  =*/ "sched_setparam",
  /*.nargs =*/ 2,
  /*.args  =*/ {ARG_INT, ARG_PTR, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 155
  /*.name  =*/ "sched_getparam",
  /*.nargs =*/ 2,
  /*.args  =*/ {ARG_INT, ARG_PTR, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 156
  /*.name  =*/ "sched_setscheduler",
  /*.nargs =*/ 3,
  /*.args  =*/ {ARG_INT, ARG_INT, ARG_PTR, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 157
  /*.name  =*/ "sched_getscheduler",
  /*.nargs =*/ 1,
  /*.args  =*/ {ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 158
  /*.name  =*/ "sched_yield",
  /*.nargs =*/ 0,
  /*.args  =*/ {ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 159
  /*.name  =*/ "sched_get_priority_max",
  /*.nargs =*/ 1,
  /*.args  =*/ {ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 160
  /*.name  =*/ "sched_get_priority_min",
  /*.nargs =*/ 1,
  /*.args  =*/ {ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 161
  /*.name  =*/ "sched_rr_get_interval",
  /*.nargs =*/ 2,
  /*.args  =*/ {ARG_INT, ARG_PTR, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 162
  /*.name  =*/ "nanosleep",
  /*.nargs =*/ 2,
  /*.args  =*/ {ARG_PTR, ARG_PTR, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 163
  /*.name  =*/ "mremap",
  /*.nargs =*/ 5,
  /*.args  =*/ {ARG_INT, ARG_INT, ARG_INT, ARG_INT, ARG_INT, ARG_UNKNOWN}},
   {   // 164
  /*.name  =*/ "setresuid",
  /*.nargs =*/ 3,
  /*.args  =*/ {ARG_INT, ARG_INT, ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 165
  /*.name  =*/ "getresuid",
  /*.nargs =*/ 3,
  /*.args  =*/ {ARG_PTR, ARG_PTR, ARG_PTR, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 166
  /*.name  =*/ "vm86",
  /*.nargs =*/ 2,
  /*.args  =*/ {ARG_INT, ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 167
  /*.name  =*/ "query_module",
  /*.nargs =*/ 6,
  /*.args  =*/ {ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR}},
   {   // 168
  /*.name  =*/ "poll",
  /*.nargs =*/ 3,
  /*.args  =*/ {ARG_PTR, ARG_INT, ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 169
  /*.name  =*/ "nfsservctl",
  /*.nargs =*/ 6,
  /*.args  =*/ {ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR}},
   {   // 170
  /*.name  =*/ "setresgid",
  /*.nargs =*/ 3,
  /*.args  =*/ {ARG_INT, ARG_INT, ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 171
  /*.name  =*/ "getresgid",
  /*.nargs =*/ 3,
  /*.args  =*/ {ARG_PTR, ARG_PTR, ARG_PTR, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 172
  /*.name  =*/ "prctl",
  /*.nargs =*/ 5,
  /*.args  =*/ {ARG_INT, ARG_INT, ARG_INT, ARG_INT, ARG_INT, ARG_UNKNOWN}},
   {   // 173
  /*.name  =*/ "rt_sigreturn",
  /*.nargs =*/ 6,
  /*.args  =*/ {ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR}},
   {   // 174
  /*.name  =*/ "rt_sigaction",
  /*.nargs =*/ 4,
  /*.args  =*/ {ARG_INT, ARG_PTR, ARG_PTR, ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 175
  /*.name  =*/ "rt_sigprocmask",
  /*.nargs =*/ 4,
  /*.args  =*/ {ARG_INT, ARG_PTR, ARG_PTR, ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 176
  /*.name  =*/ "rt_sigpending",
  /*.nargs =*/ 2,
  /*.args  =*/ {ARG_PTR, ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 177
  /*.name  =*/ "rt_sigtimedwait",
  /*.nargs =*/ 4,
  /*.args  =*/ {ARG_PTR, ARG_PTR, ARG_PTR, ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 178
  /*.name  =*/ "rt_sigqueueinfo",
  /*.nargs =*/ 3,
  /*.args  =*/ {ARG_INT, ARG_INT, ARG_PTR, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 179
  /*.name  =*/ "rt_sigsuspend",
  /*.nargs =*/ 2,
  /*.args  =*/ {ARG_PTR, ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 180
  /*.name  =*/ "pread64",
  /*.nargs =*/ 4,
  /*.args  =*/ {ARG_INT, ARG_STR, ARG_INT, ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 181
  /*.name  =*/ "pwrite64",
  /*.nargs =*/ 4,
  /*.args  =*/ {ARG_INT, ARG_STR, ARG_INT, ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 182
  /*.name  =*/ "chown",
  /*.nargs =*/ 3,
  /*.args  =*/ {ARG_STR, ARG_INT, ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 183
  /*.name  =*/ "getcwd",
  /*.nargs =*/ 2,
  /*.args  =*/ {ARG_STR, ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 184
  /*.name  =*/ "capget",
  /*.nargs =*/ 2,
  /*.args  =*/ {ARG_INT, ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 185
  /*.name  =*/ "capset",
  /*.nargs =*/ 2,
  /*.args  =*/ {ARG_INT, ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 186
  /*.name  =*/ "sigaltstack",
  /*.nargs =*/ 2,
  /*.args  =*/ {ARG_PTR, ARG_PTR, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 187
  /*.name  =*/ "sendfile",
  /*.nargs =*/ 4,
  /*.args  =*/ {ARG_INT, ARG_INT, ARG_PTR, ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 188
  /*.name  =*/ "getpmsg",
  /*.nargs =*/ 6,
  /*.args  =*/ {ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR}},
   {   // 189
  /*.name  =*/ "putpmsg",
  /*.nargs =*/ 6,
  /*.args  =*/ {ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR}},
   {   // 190
  /*.name  =*/ "vfork",
  /*.nargs =*/ 0,
  /*.args  =*/ {ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 191
  /*.name  =*/ "ugetrlimit",
  /*.nargs =*/ 6,
  /*.args  =*/ {ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR}},
   {   // 192
  /*.name  =*/ "mmap2",
  /*.nargs =*/ 6,
  /*.args  =*/ {ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR}},
   {   // 193
  /*.name  =*/ "truncate64",
  /*.nargs =*/ 2,
  /*.args  =*/ {ARG_STR, ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 194
  /*.name  =*/ "ftruncate64",
  /*.nargs =*/ 2,
  /*.args  =*/ {ARG_INT, ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 195
  /*.name  =*/ "stat64",
  /*.nargs =*/ 2,
  /*.args  =*/ {ARG_STR, ARG_PTR, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 196
  /*.name  =*/ "lstat64",
  /*.nargs =*/ 2,
  /*.args  =*/ {ARG_STR, ARG_PTR, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 197
  /*.name  =*/ "fstat64",
  /*.nargs =*/ 2,
  /*.args  =*/ {ARG_INT, ARG_PTR, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 198
  /*.name  =*/ "lchown32",
  /*.nargs =*/ 6,
  /*.args  =*/ {ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR}},
   {   // 199
  /*.name  =*/ "getuid32",
  /*.nargs =*/ 6,
  /*.args  =*/ {ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR}},
   {   // 200
  /*.name  =*/ "getgid32",
  /*.nargs =*/ 6,
  /*.args  =*/ {ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR}},
   {   // 201
  /*.name  =*/ "geteuid32",
  /*.nargs =*/ 6,
  /*.args  =*/ {ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR}},
   {   // 202
  /*.name  =*/ "getegid32",
  /*.nargs =*/ 6,
  /*.args  =*/ {ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR}},
   {   // 203
  /*.name  =*/ "setreuid32",
  /*.nargs =*/ 6,
  /*.args  =*/ {ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR}},
   {   // 204
  /*.name  =*/ "setregid32",
  /*.nargs =*/ 6,
  /*.args  =*/ {ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR}},
   {   // 205
  /*.name  =*/ "getgroups32",
  /*.nargs =*/ 6,
  /*.args  =*/ {ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR}},
   {   // 206
  /*.name  =*/ "setgroups32",
  /*.nargs =*/ 6,
  /*.args  =*/ {ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR}},
   {   // 207
  /*.name  =*/ "fchown32",
  /*.nargs =*/ 6,
  /*.args  =*/ {ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR}},
   {   // 208
  /*.name  =*/ "setresuid32",
  /*.nargs =*/ 6,
  /*.args  =*/ {ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR}},
   {   // 209
  /*.name  =*/ "getresuid32",
  /*.nargs =*/ 6,
  /*.args  =*/ {ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR}},
   {   // 210
  /*.name  =*/ "setresgid32",
  /*.nargs =*/ 6,
  /*.args  =*/ {ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR}},
   {   // 211
  /*.name  =*/ "getresgid32",
  /*.nargs =*/ 6,
  /*.args  =*/ {ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR}},
   {   // 212
  /*.name  =*/ "chown32",
  /*.nargs =*/ 6,
  /*.args  =*/ {ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR}},
   {   // 213
  /*.name  =*/ "setuid32",
  /*.nargs =*/ 6,
  /*.args  =*/ {ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR}},
   {   // 214
  /*.name  =*/ "setgid32",
  /*.nargs =*/ 6,
  /*.args  =*/ {ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR}},
   {   // 215
  /*.name  =*/ "setfsuid32",
  /*.nargs =*/ 6,
  /*.args  =*/ {ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR}},
   {   // 216
  /*.name  =*/ "setfsgid32",
  /*.nargs =*/ 6,
  /*.args  =*/ {ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR}},
   {   // 217
  /*.name  =*/ "pivot_root",
  /*.nargs =*/ 2,
  /*.args  =*/ {ARG_STR, ARG_STR, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 218
  /*.name  =*/ "mincore",
  /*.nargs =*/ 3,
  /*.args  =*/ {ARG_INT, ARG_INT, ARG_PTR, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 219
  /*.name  =*/ "madvise1",
  /*.nargs =*/ 6,
  /*.args  =*/ {ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR}},
   {   // 220
  /*.name  =*/ "getdents64",
  /*.nargs =*/ 3,
  /*.args  =*/ {ARG_INT, ARG_PTR, ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 221
  /*.name  =*/ "fcntl64",
  /*.nargs =*/ 3,
  /*.args  =*/ {ARG_INT, ARG_INT, ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
 { "UNKNOWN_222", 6, {ARG_UNKNOWN,ARG_UNKNOWN,ARG_UNKNOWN,ARG_UNKNOWN,ARG_UNKNOWN,ARG_UNKNOWN}},
 { "UNKNOWN_223", 6, {ARG_UNKNOWN,ARG_UNKNOWN,ARG_UNKNOWN,ARG_UNKNOWN,ARG_UNKNOWN,ARG_UNKNOWN}},
   {   // 224
  /*.name  =*/ "gettid",
  /*.nargs =*/ 0,
  /*.args  =*/ {ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 225
  /*.name  =*/ "readahead",
  /*.nargs =*/ 3,
  /*.args  =*/ {ARG_INT, ARG_INT, ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 226
  /*.name  =*/ "setxattr",
  /*.nargs =*/ 5,
  /*.args  =*/ {ARG_STR, ARG_STR, ARG_PTR, ARG_INT, ARG_INT, ARG_UNKNOWN}},
   {   // 227
  /*.name  =*/ "lsetxattr",
  /*.nargs =*/ 5,
  /*.args  =*/ {ARG_STR, ARG_STR, ARG_PTR, ARG_INT, ARG_INT, ARG_UNKNOWN}},
   {   // 228
  /*.name  =*/ "fsetxattr",
  /*.nargs =*/ 5,
  /*.args  =*/ {ARG_INT, ARG_STR, ARG_PTR, ARG_INT, ARG_INT, ARG_UNKNOWN}},
   {   // 229
  /*.name  =*/ "getxattr",
  /*.nargs =*/ 4,
  /*.args  =*/ {ARG_STR, ARG_STR, ARG_PTR, ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 230
  /*.name  =*/ "lgetxattr",
  /*.nargs =*/ 4,
  /*.args  =*/ {ARG_STR, ARG_STR, ARG_PTR, ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 231
  /*.name  =*/ "fgetxattr",
  /*.nargs =*/ 4,
  /*.args  =*/ {ARG_INT, ARG_STR, ARG_PTR, ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 232
  /*.name  =*/ "listxattr",
  /*.nargs =*/ 3,
  /*.args  =*/ {ARG_STR, ARG_STR, ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 233
  /*.name  =*/ "llistxattr",
  /*.nargs =*/ 3,
  /*.args  =*/ {ARG_STR, ARG_STR, ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 234
  /*.name  =*/ "flistxattr",
  /*.nargs =*/ 3,
  /*.args  =*/ {ARG_INT, ARG_STR, ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 235
  /*.name  =*/ "removexattr",
  /*.nargs =*/ 2,
  /*.args  =*/ {ARG_STR, ARG_STR, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 236
  /*.name  =*/ "lremovexattr",
  /*.nargs =*/ 2,
  /*.args  =*/ {ARG_STR, ARG_STR, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 237
  /*.name  =*/ "fremovexattr",
  /*.nargs =*/ 2,
  /*.args  =*/ {ARG_INT, ARG_STR, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 238
  /*.name  =*/ "tkill",
  /*.nargs =*/ 2,
  /*.args  =*/ {ARG_INT, ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 239
  /*.name  =*/ "sendfile64",
  /*.nargs =*/ 4,
  /*.args  =*/ {ARG_INT, ARG_INT, ARG_PTR, ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 240
  /*.name  =*/ "futex",
  /*.nargs =*/ 6,
  /*.args  =*/ {ARG_PTR, ARG_INT, ARG_INT, ARG_PTR, ARG_PTR, ARG_INT}},
   {   // 241
  /*.name  =*/ "sched_setaffinity",
  /*.nargs =*/ 3,
  /*.args  =*/ {ARG_INT, ARG_INT, ARG_PTR, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 242
  /*.name  =*/ "sched_getaffinity",
  /*.nargs =*/ 3,
  /*.args  =*/ {ARG_INT, ARG_INT, ARG_PTR, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 243
  /*.name  =*/ "set_thread_area",
  /*.nargs =*/ 1,
  /*.args  =*/ {ARG_PTR, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 244
  /*.name  =*/ "get_thread_area",
  /*.nargs =*/ 1,
  /*.args  =*/ {ARG_PTR, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 245
  /*.name  =*/ "io_setup",
  /*.nargs =*/ 2,
  /*.args  =*/ {ARG_INT, ARG_PTR, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 246
  /*.name  =*/ "io_destroy",
  /*.nargs =*/ 1,
  /*.args  =*/ {ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 247
  /*.name  =*/ "io_getevents",
  /*.nargs =*/ 5,
  /*.args  =*/ {ARG_INT, ARG_INT, ARG_INT, ARG_PTR, ARG_PTR, ARG_UNKNOWN}},
   {   // 248
  /*.name  =*/ "io_submit",
  /*.nargs =*/ 3,
  /*.args  =*/ {ARG_INT, ARG_INT, ARG_PTR, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 249
  /*.name  =*/ "io_cancel",
  /*.nargs =*/ 3,
  /*.args  =*/ {ARG_INT, ARG_PTR, ARG_PTR, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 250
  /*.name  =*/ "fadvise64",
  /*.nargs =*/ 4,
  /*.args  =*/ {ARG_INT, ARG_INT, ARG_INT, ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN}},
 { "UNKNOWN_251", 6, {ARG_UNKNOWN,ARG_UNKNOWN,ARG_UNKNOWN,ARG_UNKNOWN,ARG_UNKNOWN,ARG_UNKNOWN}},
   {   // 252
  /*.name  =*/ "exit_group",
  /*.nargs =*/ 1,
  /*.args  =*/ {ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 253
  /*.name  =*/ "lookup_dcookie",
  /*.nargs =*/ 4,
  /*.args  =*/ {ARG_INT, ARG_INT, ARG_STR, ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 254
  /*.name  =*/ "epoll_create",
  /*.nargs =*/ 1,
  /*.args  =*/ {ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 255
  /*.name  =*/ "epoll_ctl",
  /*.nargs =*/ 4,
  /*.args  =*/ {ARG_INT, ARG_INT, ARG_INT, ARG_PTR, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 256
  /*.name  =*/ "epoll_wait",
  /*.nargs =*/ 4,
  /*.args  =*/ {ARG_INT, ARG_PTR, ARG_INT, ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 257
  /*.name  =*/ "remap_file_pages",
  /*.nargs =*/ 5,
  /*.args  =*/ {ARG_INT, ARG_INT, ARG_INT, ARG_INT, ARG_INT, ARG_UNKNOWN}},
   {   // 258
  /*.name  =*/ "set_tid_address",
  /*.nargs =*/ 1,
  /*.args  =*/ {ARG_PTR, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 259
  /*.name  =*/ "timer_create",
  /*.nargs =*/ 3,
  /*.args  =*/ {ARG_INT, ARG_PTR, ARG_PTR, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
 { "UNKNOWN_260", 6, {ARG_UNKNOWN,ARG_UNKNOWN,ARG_UNKNOWN,ARG_UNKNOWN,ARG_UNKNOWN,ARG_UNKNOWN}},
 { "UNKNOWN_261", 6, {ARG_UNKNOWN,ARG_UNKNOWN,ARG_UNKNOWN,ARG_UNKNOWN,ARG_UNKNOWN,ARG_UNKNOWN}},
 { "UNKNOWN_262", 6, {ARG_UNKNOWN,ARG_UNKNOWN,ARG_UNKNOWN,ARG_UNKNOWN,ARG_UNKNOWN,ARG_UNKNOWN}},
 { "UNKNOWN_263", 6, {ARG_UNKNOWN,ARG_UNKNOWN,ARG_UNKNOWN,ARG_UNKNOWN,ARG_UNKNOWN,ARG_UNKNOWN}},
 { "UNKNOWN_264", 6, {ARG_UNKNOWN,ARG_UNKNOWN,ARG_UNKNOWN,ARG_UNKNOWN,ARG_UNKNOWN,ARG_UNKNOWN}},
 { "UNKNOWN_265", 6, {ARG_UNKNOWN,ARG_UNKNOWN,ARG_UNKNOWN,ARG_UNKNOWN,ARG_UNKNOWN,ARG_UNKNOWN}},
 { "UNKNOWN_266", 6, {ARG_UNKNOWN,ARG_UNKNOWN,ARG_UNKNOWN,ARG_UNKNOWN,ARG_UNKNOWN,ARG_UNKNOWN}},
 { "UNKNOWN_267", 6, {ARG_UNKNOWN,ARG_UNKNOWN,ARG_UNKNOWN,ARG_UNKNOWN,ARG_UNKNOWN,ARG_UNKNOWN}},
   {   // 268
  /*.name  =*/ "statfs64",
  /*.nargs =*/ 3,
  /*.args  =*/ {ARG_STR, ARG_INT, ARG_PTR, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 269
  /*.name  =*/ "fstatfs64",
  /*.nargs =*/ 3,
  /*.args  =*/ {ARG_INT, ARG_INT, ARG_PTR, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 270
  /*.name  =*/ "tgkill",
  /*.nargs =*/ 3,
  /*.args  =*/ {ARG_INT, ARG_INT, ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 271
  /*.name  =*/ "utimes",
  /*.nargs =*/ 2,
  /*.args  =*/ {ARG_STR, ARG_PTR, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 272
  /*.name  =*/ "fadvise64_64",
  /*.nargs =*/ 4,
  /*.args  =*/ {ARG_INT, ARG_INT, ARG_INT, ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 273
  /*.name  =*/ "vserver",
  /*.nargs =*/ 6,
  /*.args  =*/ {ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR}},
   {   // 274
  /*.name  =*/ "mbind",
  /*.nargs =*/ 6,
  /*.args  =*/ {ARG_INT, ARG_INT, ARG_INT, ARG_PTR, ARG_INT, ARG_INT}},
   {   // 275
  /*.name  =*/ "get_mempolicy",
  /*.nargs =*/ 5,
  /*.args  =*/ {ARG_PTR, ARG_PTR, ARG_INT, ARG_INT, ARG_INT, ARG_UNKNOWN}},
   {   // 276
  /*.name  =*/ "set_mempolicy",
  /*.nargs =*/ 3,
  /*.args  =*/ {ARG_INT, ARG_PTR, ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 277
  /*.name  =*/ "mq_open",
  /*.nargs =*/ 4,
  /*.args  =*/ {ARG_STR, ARG_INT, ARG_INT, ARG_PTR, ARG_UNKNOWN, ARG_UNKNOWN}},
 { "UNKNOWN_278", 6, {ARG_UNKNOWN,ARG_UNKNOWN,ARG_UNKNOWN,ARG_UNKNOWN,ARG_UNKNOWN,ARG_UNKNOWN}},
 { "UNKNOWN_279", 6, {ARG_UNKNOWN,ARG_UNKNOWN,ARG_UNKNOWN,ARG_UNKNOWN,ARG_UNKNOWN,ARG_UNKNOWN}},
 { "UNKNOWN_280", 6, {ARG_UNKNOWN,ARG_UNKNOWN,ARG_UNKNOWN,ARG_UNKNOWN,ARG_UNKNOWN,ARG_UNKNOWN}},
 { "UNKNOWN_281", 6, {ARG_UNKNOWN,ARG_UNKNOWN,ARG_UNKNOWN,ARG_UNKNOWN,ARG_UNKNOWN,ARG_UNKNOWN}},
 { "UNKNOWN_282", 6, {ARG_UNKNOWN,ARG_UNKNOWN,ARG_UNKNOWN,ARG_UNKNOWN,ARG_UNKNOWN,ARG_UNKNOWN}},
   {   // 283
  /*.name  =*/ "kexec_load",
  /*.nargs =*/ 4,
  /*.args  =*/ {ARG_INT, ARG_INT, ARG_PTR, ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 284
  /*.name  =*/ "waitid",
  /*.nargs =*/ 5,
  /*.args  =*/ {ARG_INT, ARG_INT, ARG_PTR, ARG_INT, ARG_PTR, ARG_UNKNOWN}},
 { "UNKNOWN_285", 6, {ARG_UNKNOWN,ARG_UNKNOWN,ARG_UNKNOWN,ARG_UNKNOWN,ARG_UNKNOWN,ARG_UNKNOWN}},
   {   // 286
  /*.name  =*/ "add_key",
  /*.nargs =*/ 5,
  /*.args  =*/ {ARG_STR, ARG_STR, ARG_PTR, ARG_INT, ARG_INT, ARG_UNKNOWN}},
   {   // 287
  /*.name  =*/ "request_key",
  /*.nargs =*/ 4,
  /*.args  =*/ {ARG_STR, ARG_STR, ARG_STR, ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 288
  /*.name  =*/ "keyctl",
  /*.nargs =*/ 5,
  /*.args  =*/ {ARG_INT, ARG_INT, ARG_INT, ARG_INT, ARG_INT, ARG_UNKNOWN}},
   {   // 289
  /*.name  =*/ "ioprio_set",
  /*.nargs =*/ 6,
  /*.args  =*/ {ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR}},
   {   // 290
  /*.name  =*/ "ioprio_get",
  /*.nargs =*/ 6,
  /*.args  =*/ {ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR}},
   {   // 291
  /*.name  =*/ "inotify_init",
  /*.nargs =*/ 0,
  /*.args  =*/ {ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 292
  /*.name  =*/ "inotify_add_watch",
  /*.nargs =*/ 3,
  /*.args  =*/ {ARG_INT, ARG_STR, ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 293
  /*.name  =*/ "inotify_rm_watch",
  /*.nargs =*/ 2,
  /*.args  =*/ {ARG_INT, ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 294
  /*.name  =*/ "migrate_pages",
  /*.nargs =*/ 4,
  /*.args  =*/ {ARG_INT, ARG_INT, ARG_PTR, ARG_PTR, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 295
  /*.name  =*/ "openat",
  /*.nargs =*/ 4,
  /*.args  =*/ {ARG_INT, ARG_STR, ARG_INT, ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 296
  /*.name  =*/ "mkdirat",
  /*.nargs =*/ 3,
  /*.args  =*/ {ARG_INT, ARG_STR, ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 297
  /*.name  =*/ "mknodat",
  /*.nargs =*/ 4,
  /*.args  =*/ {ARG_INT, ARG_STR, ARG_INT, ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 298
  /*.name  =*/ "fchownat",
  /*.nargs =*/ 5,
  /*.args  =*/ {ARG_INT, ARG_STR, ARG_INT, ARG_INT, ARG_INT, ARG_UNKNOWN}},
   {   // 299
  /*.name  =*/ "futimesat",
  /*.nargs =*/ 3,
  /*.args  =*/ {ARG_INT, ARG_STR, ARG_PTR, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 300
  /*.name  =*/ "fstatat64",
  /*.nargs =*/ 4,
  /*.args  =*/ {ARG_INT, ARG_STR, ARG_PTR, ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 301
  /*.name  =*/ "unlinkat",
  /*.nargs =*/ 3,
  /*.args  =*/ {ARG_INT, ARG_STR, ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 302
  /*.name  =*/ "renameat",
  /*.nargs =*/ 4,
  /*.args  =*/ {ARG_INT, ARG_STR, ARG_INT, ARG_STR, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 303
  /*.name  =*/ "linkat",
  /*.nargs =*/ 5,
  /*.args  =*/ {ARG_INT, ARG_STR, ARG_INT, ARG_STR, ARG_INT, ARG_UNKNOWN}},
   {   // 304
  /*.name  =*/ "symlinkat",
  /*.nargs =*/ 3,
  /*.args  =*/ {ARG_STR, ARG_INT, ARG_STR, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 305
  /*.name  =*/ "readlinkat",
  /*.nargs =*/ 4,
  /*.args  =*/ {ARG_INT, ARG_STR, ARG_STR, ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 306
  /*.name  =*/ "fchmodat",
  /*.nargs =*/ 3,
  /*.args  =*/ {ARG_INT, ARG_STR, ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 307
  /*.name  =*/ "faccessat",
  /*.nargs =*/ 3,
  /*.args  =*/ {ARG_INT, ARG_STR, ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 308
  /*.name  =*/ "pselect6",
  /*.nargs =*/ 6,
  /*.args  =*/ {ARG_INT, ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR}},
   {   // 309
  /*.name  =*/ "ppoll",
  /*.nargs =*/ 5,
  /*.args  =*/ {ARG_PTR, ARG_INT, ARG_PTR, ARG_PTR, ARG_INT, ARG_UNKNOWN}},
   {   // 310
  /*.name  =*/ "unshare",
  /*.nargs =*/ 1,
  /*.args  =*/ {ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 311
  /*.name  =*/ "set_robust_list",
  /*.nargs =*/ 2,
  /*.args  =*/ {ARG_PTR, ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 312
  /*.name  =*/ "get_robust_list",
  /*.nargs =*/ 3,
  /*.args  =*/ {ARG_INT, ARG_PTR, ARG_PTR, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 313
  /*.name  =*/ "splice",
  /*.nargs =*/ 6,
  /*.args  =*/ {ARG_INT, ARG_PTR, ARG_INT, ARG_PTR, ARG_INT, ARG_INT}},
   {   // 314
  /*.name  =*/ "sync_file_range",
  /*.nargs =*/ 4,
  /*.args  =*/ {ARG_INT, ARG_INT, ARG_INT, ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 315
  /*.name  =*/ "tee",
  /*.nargs =*/ 4,
  /*.args  =*/ {ARG_INT, ARG_INT, ARG_INT, ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 316
  /*.name  =*/ "vmsplice",
  /*.nargs =*/ 4,
  /*.args  =*/ {ARG_INT, ARG_PTR, ARG_INT, ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 317
  /*.name  =*/ "move_pages",
  /*.nargs =*/ 6,
  /*.args  =*/ {ARG_INT, ARG_INT, ARG_PTR, ARG_PTR, ARG_PTR, ARG_INT}},
   {   // 318
  /*.name  =*/ "getcpu",
  /*.nargs =*/ 3,
  /*.args  =*/ {ARG_PTR, ARG_PTR, ARG_PTR, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 319
  /*.name  =*/ "epoll_pwait",
  /*.nargs =*/ 6,
  /*.args  =*/ {ARG_INT, ARG_PTR, ARG_INT, ARG_INT, ARG_PTR, ARG_INT}},
   {   // 320
  /*.name  =*/ "utimensat",
  /*.nargs =*/ 4,
  /*.args  =*/ {ARG_INT, ARG_STR, ARG_PTR, ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 321
  /*.name  =*/ "signalfd",
  /*.nargs =*/ 3,
  /*.args  =*/ {ARG_INT, ARG_PTR, ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 322
  /*.name  =*/ "timerfd_create",
  /*.nargs =*/ 2,
  /*.args  =*/ {ARG_INT, ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 323
  /*.name  =*/ "eventfd",
  /*.nargs =*/ 1,
  /*.args  =*/ {ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 324
  /*.name  =*/ "fallocate",
  /*.nargs =*/ 4,
  /*.args  =*/ {ARG_INT, ARG_INT, ARG_INT, ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 325
  /*.name  =*/ "timerfd_settime",
  /*.nargs =*/ 4,
  /*.args  =*/ {ARG_INT, ARG_INT, ARG_PTR, ARG_PTR, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 326
  /*.name  =*/ "timerfd_gettime",
  /*.nargs =*/ 2,
  /*.args  =*/ {ARG_INT, ARG_PTR, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 327
  /*.name  =*/ "signalfd4",
  /*.nargs =*/ 4,
  /*.args  =*/ {ARG_INT, ARG_PTR, ARG_INT, ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 328
  /*.name  =*/ "eventfd2",
  /*.nargs =*/ 2,
  /*.args  =*/ {ARG_INT, ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 329
  /*.name  =*/ "epoll_create1",
  /*.nargs =*/ 1,
  /*.args  =*/ {ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 330
  /*.name  =*/ "dup3",
  /*.nargs =*/ 3,
  /*.args  =*/ {ARG_INT, ARG_INT, ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 331
  /*.name  =*/ "pipe2",
  /*.nargs =*/ 2,
  /*.args  =*/ {ARG_PTR, ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 332
  /*.name  =*/ "inotify_init1",
  /*.nargs =*/ 1,
  /*.args  =*/ {ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 333
  /*.name  =*/ "preadv",
  /*.nargs =*/ 5,
  /*.args  =*/ {ARG_INT, ARG_PTR, ARG_INT, ARG_INT, ARG_INT, ARG_UNKNOWN}},
   {   // 334
  /*.name  =*/ "pwritev",
  /*.nargs =*/ 5,
  /*.args  =*/ {ARG_INT, ARG_PTR, ARG_INT, ARG_INT, ARG_INT, ARG_UNKNOWN}},
   {   // 335
  /*.name  =*/ "rt_tgsigqueueinfo",
  /*.nargs =*/ 4,
  /*.args  =*/ {ARG_INT, ARG_INT, ARG_INT, ARG_PTR, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 336
  /*.name  =*/ "perf_event_open",
  /*.nargs =*/ 5,
  /*.args  =*/ {ARG_PTR, ARG_INT, ARG_INT, ARG_INT, ARG_INT, ARG_UNKNOWN}},
   {   // 337
  /*.name  =*/ "recvmmsg",
  /*.nargs =*/ 5,
  /*.args  =*/ {ARG_INT, ARG_PTR, ARG_INT, ARG_INT, ARG_PTR, ARG_UNKNOWN}},
   {   // 338
  /*.name  =*/ "fanotify_init",
  /*.nargs =*/ 2,
  /*.args  =*/ {ARG_INT, ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 339
  /*.name  =*/ "fanotify_mark",
  /*.nargs =*/ 6,
  /*.args  =*/ {ARG_INT, ARG_INT, ARG_INT, ARG_INT, ARG_INT, ARG_STR}},
   {   // 340
  /*.name  =*/ "prlimit64",
  /*.nargs =*/ 4,
  /*.args  =*/ {ARG_INT, ARG_INT, ARG_PTR, ARG_PTR, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 341
  /*.name  =*/ "name_to_handle_at",
  /*.nargs =*/ 5,
  /*.args  =*/ {ARG_INT, ARG_STR, ARG_PTR, ARG_PTR, ARG_INT, ARG_UNKNOWN}},
   {   // 342
  /*.name  =*/ "open_by_handle_at",
  /*.nargs =*/ 3,
  /*.args  =*/ {ARG_INT, ARG_PTR, ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 343
  /*.name  =*/ "clock_adjtime",
  /*.nargs =*/ 2,
  /*.args  =*/ {ARG_INT, ARG_PTR, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 344
  /*.name  =*/ "syncfs",
  /*.nargs =*/ 1,
  /*.args  =*/ {ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 345
  /*.name  =*/ "sendmmsg",
  /*.nargs =*/ 4,
  /*.args  =*/ {ARG_INT, ARG_PTR, ARG_INT, ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 346
  /*.name  =*/ "setns",
  /*.nargs =*/ 2,
  /*.args  =*/ {ARG_INT, ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 347
  /*.name  =*/ "process_vm_readv",
  /*.nargs =*/ 6,
  /*.args  =*/ {ARG_INT, ARG_PTR, ARG_INT, ARG_PTR, ARG_INT, ARG_INT}},
};
