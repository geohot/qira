const int MAX_SYSCALL_NUM = 311;
struct syscall_entry syscalls[] = {
   {   // 0
  /*.name  =*/ "read",
  /*.nargs =*/ 3,
  /*.args  =*/ {ARG_INT, ARG_PTR, ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 1
  /*.name  =*/ "write",
  /*.nargs =*/ 3,
  /*.args  =*/ {ARG_INT, ARG_PTR, ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 2
  /*.name  =*/ "open",
  /*.nargs =*/ 3,
  /*.args  =*/ {ARG_STR, ARG_INT, ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 3
  /*.name  =*/ "close",
  /*.nargs =*/ 1,
  /*.args  =*/ {ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 4
  /*.name  =*/ "stat",
  /*.nargs =*/ 2,
  /*.args  =*/ {ARG_STR, ARG_PTR, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 5
  /*.name  =*/ "fstat",
  /*.nargs =*/ 2,
  /*.args  =*/ {ARG_INT, ARG_PTR, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 6
  /*.name  =*/ "lstat",
  /*.nargs =*/ 2,
  /*.args  =*/ {ARG_STR, ARG_PTR, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 7
  /*.name  =*/ "poll",
  /*.nargs =*/ 3,
  /*.args  =*/ {ARG_PTR, ARG_INT, ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 8
  /*.name  =*/ "lseek",
  /*.nargs =*/ 3,
  /*.args  =*/ {ARG_INT, ARG_INT, ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 9
  /*.name  =*/ "mmap",
  /*.nargs =*/ 6,
  /*.args  =*/ {ARG_INT, ARG_INT, ARG_INT, ARG_INT, ARG_INT, ARG_INT}},
   {   // 10
  /*.name  =*/ "mprotect",
  /*.nargs =*/ 3,
  /*.args  =*/ {ARG_INT, ARG_INT, ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 11
  /*.name  =*/ "munmap",
  /*.nargs =*/ 2,
  /*.args  =*/ {ARG_INT, ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 12
  /*.name  =*/ "brk",
  /*.nargs =*/ 1,
  /*.args  =*/ {ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 13
  /*.name  =*/ "rt_sigaction",
  /*.nargs =*/ 4,
  /*.args  =*/ {ARG_INT, ARG_PTR, ARG_PTR, ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 14
  /*.name  =*/ "rt_sigprocmask",
  /*.nargs =*/ 4,
  /*.args  =*/ {ARG_INT, ARG_PTR, ARG_PTR, ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 15
  /*.name  =*/ "rt_sigreturn",
  /*.nargs =*/ 6,
  /*.args  =*/ {ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR}},
   {   // 16
  /*.name  =*/ "ioctl",
  /*.nargs =*/ 3,
  /*.args  =*/ {ARG_INT, ARG_INT, ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 17
  /*.name  =*/ "pread64",
  /*.nargs =*/ 4,
  /*.args  =*/ {ARG_INT, ARG_STR, ARG_INT, ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 18
  /*.name  =*/ "pwrite64",
  /*.nargs =*/ 4,
  /*.args  =*/ {ARG_INT, ARG_STR, ARG_INT, ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 19
  /*.name  =*/ "readv",
  /*.nargs =*/ 3,
  /*.args  =*/ {ARG_INT, ARG_PTR, ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 20
  /*.name  =*/ "writev",
  /*.nargs =*/ 3,
  /*.args  =*/ {ARG_INT, ARG_PTR, ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 21
  /*.name  =*/ "access",
  /*.nargs =*/ 2,
  /*.args  =*/ {ARG_STR, ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 22
  /*.name  =*/ "pipe",
  /*.nargs =*/ 1,
  /*.args  =*/ {ARG_PTR, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 23
  /*.name  =*/ "select",
  /*.nargs =*/ 5,
  /*.args  =*/ {ARG_INT, ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR, ARG_UNKNOWN}},
   {   // 24
  /*.name  =*/ "sched_yield",
  /*.nargs =*/ 0,
  /*.args  =*/ {ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 25
  /*.name  =*/ "mremap",
  /*.nargs =*/ 5,
  /*.args  =*/ {ARG_INT, ARG_INT, ARG_INT, ARG_INT, ARG_INT, ARG_UNKNOWN}},
   {   // 26
  /*.name  =*/ "msync",
  /*.nargs =*/ 3,
  /*.args  =*/ {ARG_INT, ARG_INT, ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 27
  /*.name  =*/ "mincore",
  /*.nargs =*/ 3,
  /*.args  =*/ {ARG_INT, ARG_INT, ARG_PTR, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 28
  /*.name  =*/ "madvise",
  /*.nargs =*/ 3,
  /*.args  =*/ {ARG_INT, ARG_INT, ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 29
  /*.name  =*/ "shmget",
  /*.nargs =*/ 3,
  /*.args  =*/ {ARG_INT, ARG_INT, ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 30
  /*.name  =*/ "shmat",
  /*.nargs =*/ 3,
  /*.args  =*/ {ARG_INT, ARG_STR, ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 31
  /*.name  =*/ "shmctl",
  /*.nargs =*/ 3,
  /*.args  =*/ {ARG_INT, ARG_INT, ARG_PTR, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 32
  /*.name  =*/ "dup",
  /*.nargs =*/ 1,
  /*.args  =*/ {ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 33
  /*.name  =*/ "dup2",
  /*.nargs =*/ 2,
  /*.args  =*/ {ARG_INT, ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 34
  /*.name  =*/ "pause",
  /*.nargs =*/ 0,
  /*.args  =*/ {ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 35
  /*.name  =*/ "nanosleep",
  /*.nargs =*/ 2,
  /*.args  =*/ {ARG_PTR, ARG_PTR, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 36
  /*.name  =*/ "getitimer",
  /*.nargs =*/ 2,
  /*.args  =*/ {ARG_INT, ARG_PTR, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 37
  /*.name  =*/ "alarm",
  /*.nargs =*/ 1,
  /*.args  =*/ {ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 38
  /*.name  =*/ "setitimer",
  /*.nargs =*/ 3,
  /*.args  =*/ {ARG_INT, ARG_PTR, ARG_PTR, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 39
  /*.name  =*/ "getpid",
  /*.nargs =*/ 0,
  /*.args  =*/ {ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 40
  /*.name  =*/ "sendfile",
  /*.nargs =*/ 4,
  /*.args  =*/ {ARG_INT, ARG_INT, ARG_PTR, ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 41
  /*.name  =*/ "socket",
  /*.nargs =*/ 3,
  /*.args  =*/ {ARG_INT, ARG_INT, ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 42
  /*.name  =*/ "connect",
  /*.nargs =*/ 3,
  /*.args  =*/ {ARG_INT, ARG_PTR, ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 43
  /*.name  =*/ "accept",
  /*.nargs =*/ 3,
  /*.args  =*/ {ARG_INT, ARG_PTR, ARG_PTR, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 44
  /*.name  =*/ "sendto",
  /*.nargs =*/ 6,
  /*.args  =*/ {ARG_INT, ARG_PTR, ARG_INT, ARG_INT, ARG_PTR, ARG_INT}},
   {   // 45
  /*.name  =*/ "recvfrom",
  /*.nargs =*/ 6,
  /*.args  =*/ {ARG_INT, ARG_PTR, ARG_INT, ARG_INT, ARG_PTR, ARG_PTR}},
   {   // 46
  /*.name  =*/ "sendmsg",
  /*.nargs =*/ 3,
  /*.args  =*/ {ARG_INT, ARG_PTR, ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 47
  /*.name  =*/ "recvmsg",
  /*.nargs =*/ 3,
  /*.args  =*/ {ARG_INT, ARG_PTR, ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 48
  /*.name  =*/ "shutdown",
  /*.nargs =*/ 2,
  /*.args  =*/ {ARG_INT, ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 49
  /*.name  =*/ "bind",
  /*.nargs =*/ 3,
  /*.args  =*/ {ARG_INT, ARG_PTR, ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 50
  /*.name  =*/ "listen",
  /*.nargs =*/ 2,
  /*.args  =*/ {ARG_INT, ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 51
  /*.name  =*/ "getsockname",
  /*.nargs =*/ 3,
  /*.args  =*/ {ARG_INT, ARG_PTR, ARG_PTR, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 52
  /*.name  =*/ "getpeername",
  /*.nargs =*/ 3,
  /*.args  =*/ {ARG_INT, ARG_PTR, ARG_PTR, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 53
  /*.name  =*/ "socketpair",
  /*.nargs =*/ 4,
  /*.args  =*/ {ARG_INT, ARG_INT, ARG_INT, ARG_PTR, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 54
  /*.name  =*/ "setsockopt",
  /*.nargs =*/ 5,
  /*.args  =*/ {ARG_INT, ARG_INT, ARG_INT, ARG_STR, ARG_INT, ARG_UNKNOWN}},
   {   // 55
  /*.name  =*/ "getsockopt",
  /*.nargs =*/ 5,
  /*.args  =*/ {ARG_INT, ARG_INT, ARG_INT, ARG_STR, ARG_PTR, ARG_UNKNOWN}},
   {   // 56
  /*.name  =*/ "clone",
  /*.nargs =*/ 5,
  /*.args  =*/ {ARG_INT, ARG_INT, ARG_PTR, ARG_PTR, ARG_INT, ARG_UNKNOWN}},
   {   // 57
  /*.name  =*/ "fork",
  /*.nargs =*/ 0,
  /*.args  =*/ {ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 58
  /*.name  =*/ "vfork",
  /*.nargs =*/ 0,
  /*.args  =*/ {ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 59
  /*.name  =*/ "execve",
  /*.nargs =*/ 3,
  /*.args  =*/ {ARG_STR, ARG_PTR, ARG_PTR, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 60
  /*.name  =*/ "exit",
  /*.nargs =*/ 1,
  /*.args  =*/ {ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 61
  /*.name  =*/ "wait4",
  /*.nargs =*/ 4,
  /*.args  =*/ {ARG_INT, ARG_PTR, ARG_INT, ARG_PTR, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 62
  /*.name  =*/ "kill",
  /*.nargs =*/ 2,
  /*.args  =*/ {ARG_INT, ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 63
  /*.name  =*/ "uname",
  /*.nargs =*/ 1,
  /*.args  =*/ {ARG_PTR, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 64
  /*.name  =*/ "semget",
  /*.nargs =*/ 3,
  /*.args  =*/ {ARG_INT, ARG_INT, ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 65
  /*.name  =*/ "semop",
  /*.nargs =*/ 3,
  /*.args  =*/ {ARG_INT, ARG_PTR, ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 66
  /*.name  =*/ "semctl",
  /*.nargs =*/ 4,
  /*.args  =*/ {ARG_INT, ARG_INT, ARG_INT, ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 67
  /*.name  =*/ "shmdt",
  /*.nargs =*/ 1,
  /*.args  =*/ {ARG_STR, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 68
  /*.name  =*/ "msgget",
  /*.nargs =*/ 2,
  /*.args  =*/ {ARG_INT, ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 69
  /*.name  =*/ "msgsnd",
  /*.nargs =*/ 4,
  /*.args  =*/ {ARG_INT, ARG_INT, ARG_INT, ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 70
  /*.name  =*/ "msgrcv",
  /*.nargs =*/ 5,
  /*.args  =*/ {ARG_INT, ARG_INT, ARG_INT, ARG_INT, ARG_INT, ARG_UNKNOWN}},
   {   // 71
  /*.name  =*/ "msgctl",
  /*.nargs =*/ 3,
  /*.args  =*/ {ARG_INT, ARG_INT, ARG_PTR, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 72
  /*.name  =*/ "fcntl",
  /*.nargs =*/ 3,
  /*.args  =*/ {ARG_INT, ARG_INT, ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 73
  /*.name  =*/ "flock",
  /*.nargs =*/ 2,
  /*.args  =*/ {ARG_INT, ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 74
  /*.name  =*/ "fsync",
  /*.nargs =*/ 1,
  /*.args  =*/ {ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 75
  /*.name  =*/ "fdatasync",
  /*.nargs =*/ 1,
  /*.args  =*/ {ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 76
  /*.name  =*/ "truncate",
  /*.nargs =*/ 2,
  /*.args  =*/ {ARG_STR, ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 77
  /*.name  =*/ "ftruncate",
  /*.nargs =*/ 2,
  /*.args  =*/ {ARG_INT, ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 78
  /*.name  =*/ "getdents",
  /*.nargs =*/ 3,
  /*.args  =*/ {ARG_INT, ARG_PTR, ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 79
  /*.name  =*/ "getcwd",
  /*.nargs =*/ 2,
  /*.args  =*/ {ARG_STR, ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 80
  /*.name  =*/ "chdir",
  /*.nargs =*/ 1,
  /*.args  =*/ {ARG_STR, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 81
  /*.name  =*/ "fchdir",
  /*.nargs =*/ 1,
  /*.args  =*/ {ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 82
  /*.name  =*/ "rename",
  /*.nargs =*/ 2,
  /*.args  =*/ {ARG_STR, ARG_STR, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 83
  /*.name  =*/ "mkdir",
  /*.nargs =*/ 2,
  /*.args  =*/ {ARG_STR, ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 84
  /*.name  =*/ "rmdir",
  /*.nargs =*/ 1,
  /*.args  =*/ {ARG_STR, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 85
  /*.name  =*/ "creat",
  /*.nargs =*/ 2,
  /*.args  =*/ {ARG_STR, ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 86
  /*.name  =*/ "link",
  /*.nargs =*/ 2,
  /*.args  =*/ {ARG_STR, ARG_STR, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 87
  /*.name  =*/ "unlink",
  /*.nargs =*/ 1,
  /*.args  =*/ {ARG_STR, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 88
  /*.name  =*/ "symlink",
  /*.nargs =*/ 2,
  /*.args  =*/ {ARG_STR, ARG_STR, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 89
  /*.name  =*/ "readlink",
  /*.nargs =*/ 3,
  /*.args  =*/ {ARG_STR, ARG_STR, ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 90
  /*.name  =*/ "chmod",
  /*.nargs =*/ 2,
  /*.args  =*/ {ARG_STR, ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 91
  /*.name  =*/ "fchmod",
  /*.nargs =*/ 2,
  /*.args  =*/ {ARG_INT, ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 92
  /*.name  =*/ "chown",
  /*.nargs =*/ 3,
  /*.args  =*/ {ARG_STR, ARG_INT, ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 93
  /*.name  =*/ "fchown",
  /*.nargs =*/ 3,
  /*.args  =*/ {ARG_INT, ARG_INT, ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 94
  /*.name  =*/ "lchown",
  /*.nargs =*/ 3,
  /*.args  =*/ {ARG_STR, ARG_INT, ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 95
  /*.name  =*/ "umask",
  /*.nargs =*/ 1,
  /*.args  =*/ {ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 96
  /*.name  =*/ "gettimeofday",
  /*.nargs =*/ 2,
  /*.args  =*/ {ARG_PTR, ARG_PTR, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 97
  /*.name  =*/ "getrlimit",
  /*.nargs =*/ 2,
  /*.args  =*/ {ARG_INT, ARG_PTR, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 98
  /*.name  =*/ "getrusage",
  /*.nargs =*/ 2,
  /*.args  =*/ {ARG_INT, ARG_PTR, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 99
  /*.name  =*/ "sysinfo",
  /*.nargs =*/ 1,
  /*.args  =*/ {ARG_PTR, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 100
  /*.name  =*/ "times",
  /*.nargs =*/ 1,
  /*.args  =*/ {ARG_PTR, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 101
  /*.name  =*/ "ptrace",
  /*.nargs =*/ 4,
  /*.args  =*/ {ARG_INT, ARG_INT, ARG_INT, ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 102
  /*.name  =*/ "getuid",
  /*.nargs =*/ 0,
  /*.args  =*/ {ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 103
  /*.name  =*/ "syslog",
  /*.nargs =*/ 3,
  /*.args  =*/ {ARG_INT, ARG_STR, ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 104
  /*.name  =*/ "getgid",
  /*.nargs =*/ 0,
  /*.args  =*/ {ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 105
  /*.name  =*/ "setuid",
  /*.nargs =*/ 1,
  /*.args  =*/ {ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 106
  /*.name  =*/ "setgid",
  /*.nargs =*/ 1,
  /*.args  =*/ {ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 107
  /*.name  =*/ "geteuid",
  /*.nargs =*/ 0,
  /*.args  =*/ {ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 108
  /*.name  =*/ "getegid",
  /*.nargs =*/ 0,
  /*.args  =*/ {ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 109
  /*.name  =*/ "setpgid",
  /*.nargs =*/ 2,
  /*.args  =*/ {ARG_INT, ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 110
  /*.name  =*/ "getppid",
  /*.nargs =*/ 0,
  /*.args  =*/ {ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 111
  /*.name  =*/ "getpgrp",
  /*.nargs =*/ 0,
  /*.args  =*/ {ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 112
  /*.name  =*/ "setsid",
  /*.nargs =*/ 0,
  /*.args  =*/ {ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 113
  /*.name  =*/ "setreuid",
  /*.nargs =*/ 2,
  /*.args  =*/ {ARG_INT, ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 114
  /*.name  =*/ "setregid",
  /*.nargs =*/ 2,
  /*.args  =*/ {ARG_INT, ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 115
  /*.name  =*/ "getgroups",
  /*.nargs =*/ 2,
  /*.args  =*/ {ARG_INT, ARG_PTR, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 116
  /*.name  =*/ "setgroups",
  /*.nargs =*/ 2,
  /*.args  =*/ {ARG_INT, ARG_PTR, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 117
  /*.name  =*/ "setresuid",
  /*.nargs =*/ 3,
  /*.args  =*/ {ARG_INT, ARG_INT, ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 118
  /*.name  =*/ "getresuid",
  /*.nargs =*/ 3,
  /*.args  =*/ {ARG_PTR, ARG_PTR, ARG_PTR, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 119
  /*.name  =*/ "setresgid",
  /*.nargs =*/ 3,
  /*.args  =*/ {ARG_INT, ARG_INT, ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 120
  /*.name  =*/ "getresgid",
  /*.nargs =*/ 3,
  /*.args  =*/ {ARG_PTR, ARG_PTR, ARG_PTR, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 121
  /*.name  =*/ "getpgid",
  /*.nargs =*/ 1,
  /*.args  =*/ {ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 122
  /*.name  =*/ "setfsuid",
  /*.nargs =*/ 1,
  /*.args  =*/ {ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 123
  /*.name  =*/ "setfsgid",
  /*.nargs =*/ 1,
  /*.args  =*/ {ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 124
  /*.name  =*/ "getsid",
  /*.nargs =*/ 1,
  /*.args  =*/ {ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 125
  /*.name  =*/ "capget",
  /*.nargs =*/ 2,
  /*.args  =*/ {ARG_INT, ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 126
  /*.name  =*/ "capset",
  /*.nargs =*/ 2,
  /*.args  =*/ {ARG_INT, ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 127
  /*.name  =*/ "rt_sigpending",
  /*.nargs =*/ 2,
  /*.args  =*/ {ARG_PTR, ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 128
  /*.name  =*/ "rt_sigtimedwait",
  /*.nargs =*/ 4,
  /*.args  =*/ {ARG_PTR, ARG_PTR, ARG_PTR, ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 129
  /*.name  =*/ "rt_sigqueueinfo",
  /*.nargs =*/ 3,
  /*.args  =*/ {ARG_INT, ARG_INT, ARG_PTR, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 130
  /*.name  =*/ "rt_sigsuspend",
  /*.nargs =*/ 2,
  /*.args  =*/ {ARG_PTR, ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 131
  /*.name  =*/ "sigaltstack",
  /*.nargs =*/ 2,
  /*.args  =*/ {ARG_PTR, ARG_PTR, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 132
  /*.name  =*/ "utime",
  /*.nargs =*/ 2,
  /*.args  =*/ {ARG_STR, ARG_PTR, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 133
  /*.name  =*/ "mknod",
  /*.nargs =*/ 3,
  /*.args  =*/ {ARG_STR, ARG_INT, ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 134
  /*.name  =*/ "uselib",
  /*.nargs =*/ 1,
  /*.args  =*/ {ARG_STR, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 135
  /*.name  =*/ "personality",
  /*.nargs =*/ 1,
  /*.args  =*/ {ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 136
  /*.name  =*/ "ustat",
  /*.nargs =*/ 2,
  /*.args  =*/ {ARG_INT, ARG_PTR, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 137
  /*.name  =*/ "statfs",
  /*.nargs =*/ 2,
  /*.args  =*/ {ARG_STR, ARG_PTR, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 138
  /*.name  =*/ "fstatfs",
  /*.nargs =*/ 2,
  /*.args  =*/ {ARG_INT, ARG_PTR, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 139
  /*.name  =*/ "sysfs",
  /*.nargs =*/ 3,
  /*.args  =*/ {ARG_INT, ARG_INT, ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 140
  /*.name  =*/ "getpriority",
  /*.nargs =*/ 2,
  /*.args  =*/ {ARG_INT, ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 141
  /*.name  =*/ "setpriority",
  /*.nargs =*/ 3,
  /*.args  =*/ {ARG_INT, ARG_INT, ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 142
  /*.name  =*/ "sched_setparam",
  /*.nargs =*/ 2,
  /*.args  =*/ {ARG_INT, ARG_PTR, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 143
  /*.name  =*/ "sched_getparam",
  /*.nargs =*/ 2,
  /*.args  =*/ {ARG_INT, ARG_PTR, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 144
  /*.name  =*/ "sched_setscheduler",
  /*.nargs =*/ 3,
  /*.args  =*/ {ARG_INT, ARG_INT, ARG_PTR, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 145
  /*.name  =*/ "sched_getscheduler",
  /*.nargs =*/ 1,
  /*.args  =*/ {ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 146
  /*.name  =*/ "sched_get_priority_max",
  /*.nargs =*/ 1,
  /*.args  =*/ {ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 147
  /*.name  =*/ "sched_get_priority_min",
  /*.nargs =*/ 1,
  /*.args  =*/ {ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 148
  /*.name  =*/ "sched_rr_get_interval",
  /*.nargs =*/ 2,
  /*.args  =*/ {ARG_INT, ARG_PTR, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 149
  /*.name  =*/ "mlock",
  /*.nargs =*/ 2,
  /*.args  =*/ {ARG_INT, ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 150
  /*.name  =*/ "munlock",
  /*.nargs =*/ 2,
  /*.args  =*/ {ARG_INT, ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 151
  /*.name  =*/ "mlockall",
  /*.nargs =*/ 1,
  /*.args  =*/ {ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 152
  /*.name  =*/ "munlockall",
  /*.nargs =*/ 0,
  /*.args  =*/ {ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 153
  /*.name  =*/ "vhangup",
  /*.nargs =*/ 0,
  /*.args  =*/ {ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 154
  /*.name  =*/ "modify_ldt",
  /*.nargs =*/ 6,
  /*.args  =*/ {ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR}},
   {   // 155
  /*.name  =*/ "pivot_root",
  /*.nargs =*/ 2,
  /*.args  =*/ {ARG_STR, ARG_STR, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 156
  /*.name  =*/ "_sysctl",
  /*.nargs =*/ 6,
  /*.args  =*/ {ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR}},
   {   // 157
  /*.name  =*/ "prctl",
  /*.nargs =*/ 5,
  /*.args  =*/ {ARG_INT, ARG_INT, ARG_INT, ARG_INT, ARG_INT, ARG_UNKNOWN}},
   {   // 158
  /*.name  =*/ "arch_prctl",
  /*.nargs =*/ 6,
  /*.args  =*/ {ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR}},
   {   // 159
  /*.name  =*/ "adjtimex",
  /*.nargs =*/ 1,
  /*.args  =*/ {ARG_PTR, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 160
  /*.name  =*/ "setrlimit",
  /*.nargs =*/ 2,
  /*.args  =*/ {ARG_INT, ARG_PTR, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 161
  /*.name  =*/ "chroot",
  /*.nargs =*/ 1,
  /*.args  =*/ {ARG_STR, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 162
  /*.name  =*/ "sync",
  /*.nargs =*/ 0,
  /*.args  =*/ {ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 163
  /*.name  =*/ "acct",
  /*.nargs =*/ 1,
  /*.args  =*/ {ARG_STR, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 164
  /*.name  =*/ "settimeofday",
  /*.nargs =*/ 2,
  /*.args  =*/ {ARG_PTR, ARG_PTR, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 165
  /*.name  =*/ "mount",
  /*.nargs =*/ 5,
  /*.args  =*/ {ARG_STR, ARG_STR, ARG_STR, ARG_INT, ARG_PTR, ARG_UNKNOWN}},
   {   // 166
  /*.name  =*/ "umount2",
  /*.nargs =*/ 6,
  /*.args  =*/ {ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR}},
   {   // 167
  /*.name  =*/ "swapon",
  /*.nargs =*/ 2,
  /*.args  =*/ {ARG_STR, ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 168
  /*.name  =*/ "swapoff",
  /*.nargs =*/ 1,
  /*.args  =*/ {ARG_STR, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 169
  /*.name  =*/ "reboot",
  /*.nargs =*/ 4,
  /*.args  =*/ {ARG_INT, ARG_INT, ARG_INT, ARG_PTR, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 170
  /*.name  =*/ "sethostname",
  /*.nargs =*/ 2,
  /*.args  =*/ {ARG_STR, ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 171
  /*.name  =*/ "setdomainname",
  /*.nargs =*/ 2,
  /*.args  =*/ {ARG_STR, ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 172
  /*.name  =*/ "iopl",
  /*.nargs =*/ 1,
  /*.args  =*/ {ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 173
  /*.name  =*/ "ioperm",
  /*.nargs =*/ 6,
  /*.args  =*/ {ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR}},
   {   // 174
  /*.name  =*/ "create_module",
  /*.nargs =*/ 6,
  /*.args  =*/ {ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR}},
   {   // 175
  /*.name  =*/ "init_module",
  /*.nargs =*/ 3,
  /*.args  =*/ {ARG_PTR, ARG_INT, ARG_STR, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 176
  /*.name  =*/ "delete_module",
  /*.nargs =*/ 2,
  /*.args  =*/ {ARG_STR, ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 177
  /*.name  =*/ "get_kernel_syms",
  /*.nargs =*/ 6,
  /*.args  =*/ {ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR}},
   {   // 178
  /*.name  =*/ "query_module",
  /*.nargs =*/ 6,
  /*.args  =*/ {ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR}},
   {   // 179
  /*.name  =*/ "quotactl",
  /*.nargs =*/ 4,
  /*.args  =*/ {ARG_INT, ARG_STR, ARG_INT, ARG_PTR, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 180
  /*.name  =*/ "nfsservctl",
  /*.nargs =*/ 6,
  /*.args  =*/ {ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR}},
   {   // 181
  /*.name  =*/ "getpmsg",
  /*.nargs =*/ 6,
  /*.args  =*/ {ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR}},
   {   // 182
  /*.name  =*/ "putpmsg",
  /*.nargs =*/ 6,
  /*.args  =*/ {ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR}},
   {   // 183
  /*.name  =*/ "afs_syscall",
  /*.nargs =*/ 6,
  /*.args  =*/ {ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR}},
   {   // 184
  /*.name  =*/ "tuxcall",
  /*.nargs =*/ 6,
  /*.args  =*/ {ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR}},
   {   // 185
  /*.name  =*/ "security",
  /*.nargs =*/ 6,
  /*.args  =*/ {ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR}},
   {   // 186
  /*.name  =*/ "gettid",
  /*.nargs =*/ 0,
  /*.args  =*/ {ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 187
  /*.name  =*/ "readahead",
  /*.nargs =*/ 3,
  /*.args  =*/ {ARG_INT, ARG_INT, ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 188
  /*.name  =*/ "setxattr",
  /*.nargs =*/ 5,
  /*.args  =*/ {ARG_STR, ARG_STR, ARG_PTR, ARG_INT, ARG_INT, ARG_UNKNOWN}},
   {   // 189
  /*.name  =*/ "lsetxattr",
  /*.nargs =*/ 5,
  /*.args  =*/ {ARG_STR, ARG_STR, ARG_PTR, ARG_INT, ARG_INT, ARG_UNKNOWN}},
   {   // 190
  /*.name  =*/ "fsetxattr",
  /*.nargs =*/ 5,
  /*.args  =*/ {ARG_INT, ARG_STR, ARG_PTR, ARG_INT, ARG_INT, ARG_UNKNOWN}},
   {   // 191
  /*.name  =*/ "getxattr",
  /*.nargs =*/ 4,
  /*.args  =*/ {ARG_STR, ARG_STR, ARG_PTR, ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 192
  /*.name  =*/ "lgetxattr",
  /*.nargs =*/ 4,
  /*.args  =*/ {ARG_STR, ARG_STR, ARG_PTR, ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 193
  /*.name  =*/ "fgetxattr",
  /*.nargs =*/ 4,
  /*.args  =*/ {ARG_INT, ARG_STR, ARG_PTR, ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 194
  /*.name  =*/ "listxattr",
  /*.nargs =*/ 3,
  /*.args  =*/ {ARG_STR, ARG_STR, ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 195
  /*.name  =*/ "llistxattr",
  /*.nargs =*/ 3,
  /*.args  =*/ {ARG_STR, ARG_STR, ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 196
  /*.name  =*/ "flistxattr",
  /*.nargs =*/ 3,
  /*.args  =*/ {ARG_INT, ARG_STR, ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 197
  /*.name  =*/ "removexattr",
  /*.nargs =*/ 2,
  /*.args  =*/ {ARG_STR, ARG_STR, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 198
  /*.name  =*/ "lremovexattr",
  /*.nargs =*/ 2,
  /*.args  =*/ {ARG_STR, ARG_STR, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 199
  /*.name  =*/ "fremovexattr",
  /*.nargs =*/ 2,
  /*.args  =*/ {ARG_INT, ARG_STR, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 200
  /*.name  =*/ "tkill",
  /*.nargs =*/ 2,
  /*.args  =*/ {ARG_INT, ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 201
  /*.name  =*/ "time",
  /*.nargs =*/ 1,
  /*.args  =*/ {ARG_PTR, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 202
  /*.name  =*/ "futex",
  /*.nargs =*/ 6,
  /*.args  =*/ {ARG_PTR, ARG_INT, ARG_INT, ARG_PTR, ARG_PTR, ARG_INT}},
   {   // 203
  /*.name  =*/ "sched_setaffinity",
  /*.nargs =*/ 3,
  /*.args  =*/ {ARG_INT, ARG_INT, ARG_PTR, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 204
  /*.name  =*/ "sched_getaffinity",
  /*.nargs =*/ 3,
  /*.args  =*/ {ARG_INT, ARG_INT, ARG_PTR, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 205
  /*.name  =*/ "set_thread_area",
  /*.nargs =*/ 1,
  /*.args  =*/ {ARG_PTR, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 206
  /*.name  =*/ "io_setup",
  /*.nargs =*/ 2,
  /*.args  =*/ {ARG_INT, ARG_PTR, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 207
  /*.name  =*/ "io_destroy",
  /*.nargs =*/ 1,
  /*.args  =*/ {ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 208
  /*.name  =*/ "io_getevents",
  /*.nargs =*/ 5,
  /*.args  =*/ {ARG_INT, ARG_INT, ARG_INT, ARG_PTR, ARG_PTR, ARG_UNKNOWN}},
   {   // 209
  /*.name  =*/ "io_submit",
  /*.nargs =*/ 3,
  /*.args  =*/ {ARG_INT, ARG_INT, ARG_PTR, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 210
  /*.name  =*/ "io_cancel",
  /*.nargs =*/ 3,
  /*.args  =*/ {ARG_INT, ARG_PTR, ARG_PTR, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 211
  /*.name  =*/ "get_thread_area",
  /*.nargs =*/ 1,
  /*.args  =*/ {ARG_PTR, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 212
  /*.name  =*/ "lookup_dcookie",
  /*.nargs =*/ 4,
  /*.args  =*/ {ARG_INT, ARG_INT, ARG_STR, ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 213
  /*.name  =*/ "epoll_create",
  /*.nargs =*/ 1,
  /*.args  =*/ {ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 214
  /*.name  =*/ "epoll_ctl_old",
  /*.nargs =*/ 6,
  /*.args  =*/ {ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR}},
   {   // 215
  /*.name  =*/ "epoll_wait_old",
  /*.nargs =*/ 6,
  /*.args  =*/ {ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR}},
   {   // 216
  /*.name  =*/ "remap_file_pages",
  /*.nargs =*/ 5,
  /*.args  =*/ {ARG_INT, ARG_INT, ARG_INT, ARG_INT, ARG_INT, ARG_UNKNOWN}},
   {   // 217
  /*.name  =*/ "getdents64",
  /*.nargs =*/ 3,
  /*.args  =*/ {ARG_INT, ARG_PTR, ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 218
  /*.name  =*/ "set_tid_address",
  /*.nargs =*/ 1,
  /*.args  =*/ {ARG_PTR, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 219
  /*.name  =*/ "restart_syscall",
  /*.nargs =*/ 0,
  /*.args  =*/ {ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 220
  /*.name  =*/ "semtimedop",
  /*.nargs =*/ 4,
  /*.args  =*/ {ARG_INT, ARG_PTR, ARG_INT, ARG_PTR, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 221
  /*.name  =*/ "fadvise64",
  /*.nargs =*/ 4,
  /*.args  =*/ {ARG_INT, ARG_INT, ARG_INT, ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 222
  /*.name  =*/ "timer_create",
  /*.nargs =*/ 3,
  /*.args  =*/ {ARG_INT, ARG_PTR, ARG_PTR, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 223
  /*.name  =*/ "timer_settime",
  /*.nargs =*/ 4,
  /*.args  =*/ {ARG_INT, ARG_INT, ARG_PTR, ARG_PTR, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 224
  /*.name  =*/ "timer_gettime",
  /*.nargs =*/ 2,
  /*.args  =*/ {ARG_INT, ARG_PTR, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 225
  /*.name  =*/ "timer_getoverrun",
  /*.nargs =*/ 1,
  /*.args  =*/ {ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 226
  /*.name  =*/ "timer_delete",
  /*.nargs =*/ 1,
  /*.args  =*/ {ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 227
  /*.name  =*/ "clock_settime",
  /*.nargs =*/ 2,
  /*.args  =*/ {ARG_INT, ARG_PTR, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 228
  /*.name  =*/ "clock_gettime",
  /*.nargs =*/ 2,
  /*.args  =*/ {ARG_INT, ARG_PTR, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 229
  /*.name  =*/ "clock_getres",
  /*.nargs =*/ 2,
  /*.args  =*/ {ARG_INT, ARG_PTR, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 230
  /*.name  =*/ "clock_nanosleep",
  /*.nargs =*/ 4,
  /*.args  =*/ {ARG_INT, ARG_INT, ARG_PTR, ARG_PTR, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 231
  /*.name  =*/ "exit_group",
  /*.nargs =*/ 1,
  /*.args  =*/ {ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 232
  /*.name  =*/ "epoll_wait",
  /*.nargs =*/ 4,
  /*.args  =*/ {ARG_INT, ARG_PTR, ARG_INT, ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 233
  /*.name  =*/ "epoll_ctl",
  /*.nargs =*/ 4,
  /*.args  =*/ {ARG_INT, ARG_INT, ARG_INT, ARG_PTR, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 234
  /*.name  =*/ "tgkill",
  /*.nargs =*/ 3,
  /*.args  =*/ {ARG_INT, ARG_INT, ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 235
  /*.name  =*/ "utimes",
  /*.nargs =*/ 2,
  /*.args  =*/ {ARG_STR, ARG_PTR, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 236
  /*.name  =*/ "vserver",
  /*.nargs =*/ 6,
  /*.args  =*/ {ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR}},
   {   // 237
  /*.name  =*/ "mbind",
  /*.nargs =*/ 6,
  /*.args  =*/ {ARG_INT, ARG_INT, ARG_INT, ARG_PTR, ARG_INT, ARG_INT}},
   {   // 238
  /*.name  =*/ "set_mempolicy",
  /*.nargs =*/ 3,
  /*.args  =*/ {ARG_INT, ARG_PTR, ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 239
  /*.name  =*/ "get_mempolicy",
  /*.nargs =*/ 5,
  /*.args  =*/ {ARG_PTR, ARG_PTR, ARG_INT, ARG_INT, ARG_INT, ARG_UNKNOWN}},
   {   // 240
  /*.name  =*/ "mq_open",
  /*.nargs =*/ 4,
  /*.args  =*/ {ARG_STR, ARG_INT, ARG_INT, ARG_PTR, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 241
  /*.name  =*/ "mq_unlink",
  /*.nargs =*/ 1,
  /*.args  =*/ {ARG_STR, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 242
  /*.name  =*/ "mq_timedsend",
  /*.nargs =*/ 5,
  /*.args  =*/ {ARG_INT, ARG_STR, ARG_INT, ARG_INT, ARG_PTR, ARG_UNKNOWN}},
   {   // 243
  /*.name  =*/ "mq_timedreceive",
  /*.nargs =*/ 5,
  /*.args  =*/ {ARG_INT, ARG_STR, ARG_INT, ARG_PTR, ARG_PTR, ARG_UNKNOWN}},
   {   // 244
  /*.name  =*/ "mq_notify",
  /*.nargs =*/ 2,
  /*.args  =*/ {ARG_INT, ARG_PTR, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 245
  /*.name  =*/ "mq_getsetattr",
  /*.nargs =*/ 3,
  /*.args  =*/ {ARG_INT, ARG_PTR, ARG_PTR, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 246
  /*.name  =*/ "kexec_load",
  /*.nargs =*/ 4,
  /*.args  =*/ {ARG_INT, ARG_INT, ARG_PTR, ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 247
  /*.name  =*/ "waitid",
  /*.nargs =*/ 5,
  /*.args  =*/ {ARG_INT, ARG_INT, ARG_PTR, ARG_INT, ARG_PTR, ARG_UNKNOWN}},
   {   // 248
  /*.name  =*/ "add_key",
  /*.nargs =*/ 5,
  /*.args  =*/ {ARG_STR, ARG_STR, ARG_PTR, ARG_INT, ARG_INT, ARG_UNKNOWN}},
   {   // 249
  /*.name  =*/ "request_key",
  /*.nargs =*/ 4,
  /*.args  =*/ {ARG_STR, ARG_STR, ARG_STR, ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 250
  /*.name  =*/ "keyctl",
  /*.nargs =*/ 5,
  /*.args  =*/ {ARG_INT, ARG_INT, ARG_INT, ARG_INT, ARG_INT, ARG_UNKNOWN}},
   {   // 251
  /*.name  =*/ "ioprio_set",
  /*.nargs =*/ 6,
  /*.args  =*/ {ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR}},
   {   // 252
  /*.name  =*/ "ioprio_get",
  /*.nargs =*/ 6,
  /*.args  =*/ {ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR}},
   {   // 253
  /*.name  =*/ "inotify_init",
  /*.nargs =*/ 0,
  /*.args  =*/ {ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 254
  /*.name  =*/ "inotify_add_watch",
  /*.nargs =*/ 3,
  /*.args  =*/ {ARG_INT, ARG_STR, ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 255
  /*.name  =*/ "inotify_rm_watch",
  /*.nargs =*/ 2,
  /*.args  =*/ {ARG_INT, ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 256
  /*.name  =*/ "migrate_pages",
  /*.nargs =*/ 4,
  /*.args  =*/ {ARG_INT, ARG_INT, ARG_PTR, ARG_PTR, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 257
  /*.name  =*/ "openat",
  /*.nargs =*/ 4,
  /*.args  =*/ {ARG_INT, ARG_STR, ARG_INT, ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 258
  /*.name  =*/ "mkdirat",
  /*.nargs =*/ 3,
  /*.args  =*/ {ARG_INT, ARG_STR, ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 259
  /*.name  =*/ "mknodat",
  /*.nargs =*/ 4,
  /*.args  =*/ {ARG_INT, ARG_STR, ARG_INT, ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 260
  /*.name  =*/ "fchownat",
  /*.nargs =*/ 5,
  /*.args  =*/ {ARG_INT, ARG_STR, ARG_INT, ARG_INT, ARG_INT, ARG_UNKNOWN}},
   {   // 261
  /*.name  =*/ "futimesat",
  /*.nargs =*/ 3,
  /*.args  =*/ {ARG_INT, ARG_STR, ARG_PTR, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 262
  /*.name  =*/ "newfstatat",
  /*.nargs =*/ 4,
  /*.args  =*/ {ARG_INT, ARG_STR, ARG_PTR, ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 263
  /*.name  =*/ "unlinkat",
  /*.nargs =*/ 3,
  /*.args  =*/ {ARG_INT, ARG_STR, ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 264
  /*.name  =*/ "renameat",
  /*.nargs =*/ 4,
  /*.args  =*/ {ARG_INT, ARG_STR, ARG_INT, ARG_STR, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 265
  /*.name  =*/ "linkat",
  /*.nargs =*/ 5,
  /*.args  =*/ {ARG_INT, ARG_STR, ARG_INT, ARG_STR, ARG_INT, ARG_UNKNOWN}},
   {   // 266
  /*.name  =*/ "symlinkat",
  /*.nargs =*/ 3,
  /*.args  =*/ {ARG_STR, ARG_INT, ARG_STR, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 267
  /*.name  =*/ "readlinkat",
  /*.nargs =*/ 4,
  /*.args  =*/ {ARG_INT, ARG_STR, ARG_STR, ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 268
  /*.name  =*/ "fchmodat",
  /*.nargs =*/ 3,
  /*.args  =*/ {ARG_INT, ARG_STR, ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 269
  /*.name  =*/ "faccessat",
  /*.nargs =*/ 3,
  /*.args  =*/ {ARG_INT, ARG_STR, ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 270
  /*.name  =*/ "pselect6",
  /*.nargs =*/ 6,
  /*.args  =*/ {ARG_INT, ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR}},
   {   // 271
  /*.name  =*/ "ppoll",
  /*.nargs =*/ 5,
  /*.args  =*/ {ARG_PTR, ARG_INT, ARG_PTR, ARG_PTR, ARG_INT, ARG_UNKNOWN}},
   {   // 272
  /*.name  =*/ "unshare",
  /*.nargs =*/ 1,
  /*.args  =*/ {ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 273
  /*.name  =*/ "set_robust_list",
  /*.nargs =*/ 2,
  /*.args  =*/ {ARG_PTR, ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 274
  /*.name  =*/ "get_robust_list",
  /*.nargs =*/ 3,
  /*.args  =*/ {ARG_INT, ARG_PTR, ARG_PTR, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 275
  /*.name  =*/ "splice",
  /*.nargs =*/ 6,
  /*.args  =*/ {ARG_INT, ARG_PTR, ARG_INT, ARG_PTR, ARG_INT, ARG_INT}},
   {   // 276
  /*.name  =*/ "tee",
  /*.nargs =*/ 4,
  /*.args  =*/ {ARG_INT, ARG_INT, ARG_INT, ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 277
  /*.name  =*/ "sync_file_range",
  /*.nargs =*/ 4,
  /*.args  =*/ {ARG_INT, ARG_INT, ARG_INT, ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 278
  /*.name  =*/ "vmsplice",
  /*.nargs =*/ 4,
  /*.args  =*/ {ARG_INT, ARG_PTR, ARG_INT, ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 279
  /*.name  =*/ "move_pages",
  /*.nargs =*/ 6,
  /*.args  =*/ {ARG_INT, ARG_INT, ARG_PTR, ARG_PTR, ARG_PTR, ARG_INT}},
   {   // 280
  /*.name  =*/ "utimensat",
  /*.nargs =*/ 4,
  /*.args  =*/ {ARG_INT, ARG_STR, ARG_PTR, ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 281
  /*.name  =*/ "epoll_pwait",
  /*.nargs =*/ 6,
  /*.args  =*/ {ARG_INT, ARG_PTR, ARG_INT, ARG_INT, ARG_PTR, ARG_INT}},
   {   // 282
  /*.name  =*/ "signalfd",
  /*.nargs =*/ 3,
  /*.args  =*/ {ARG_INT, ARG_PTR, ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 283
  /*.name  =*/ "timerfd_create",
  /*.nargs =*/ 2,
  /*.args  =*/ {ARG_INT, ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 284
  /*.name  =*/ "eventfd",
  /*.nargs =*/ 1,
  /*.args  =*/ {ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 285
  /*.name  =*/ "fallocate",
  /*.nargs =*/ 4,
  /*.args  =*/ {ARG_INT, ARG_INT, ARG_INT, ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 286
  /*.name  =*/ "timerfd_settime",
  /*.nargs =*/ 4,
  /*.args  =*/ {ARG_INT, ARG_INT, ARG_PTR, ARG_PTR, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 287
  /*.name  =*/ "timerfd_gettime",
  /*.nargs =*/ 2,
  /*.args  =*/ {ARG_INT, ARG_PTR, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 288
  /*.name  =*/ "accept4",
  /*.nargs =*/ 4,
  /*.args  =*/ {ARG_INT, ARG_PTR, ARG_PTR, ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 289
  /*.name  =*/ "signalfd4",
  /*.nargs =*/ 4,
  /*.args  =*/ {ARG_INT, ARG_PTR, ARG_INT, ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 290
  /*.name  =*/ "eventfd2",
  /*.nargs =*/ 2,
  /*.args  =*/ {ARG_INT, ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 291
  /*.name  =*/ "epoll_create1",
  /*.nargs =*/ 1,
  /*.args  =*/ {ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 292
  /*.name  =*/ "dup3",
  /*.nargs =*/ 3,
  /*.args  =*/ {ARG_INT, ARG_INT, ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 293
  /*.name  =*/ "pipe2",
  /*.nargs =*/ 2,
  /*.args  =*/ {ARG_PTR, ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 294
  /*.name  =*/ "inotify_init1",
  /*.nargs =*/ 1,
  /*.args  =*/ {ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 295
  /*.name  =*/ "preadv",
  /*.nargs =*/ 5,
  /*.args  =*/ {ARG_INT, ARG_PTR, ARG_INT, ARG_INT, ARG_INT, ARG_UNKNOWN}},
   {   // 296
  /*.name  =*/ "pwritev",
  /*.nargs =*/ 5,
  /*.args  =*/ {ARG_INT, ARG_PTR, ARG_INT, ARG_INT, ARG_INT, ARG_UNKNOWN}},
   {   // 297
  /*.name  =*/ "rt_tgsigqueueinfo",
  /*.nargs =*/ 4,
  /*.args  =*/ {ARG_INT, ARG_INT, ARG_INT, ARG_PTR, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 298
  /*.name  =*/ "perf_event_open",
  /*.nargs =*/ 5,
  /*.args  =*/ {ARG_PTR, ARG_INT, ARG_INT, ARG_INT, ARG_INT, ARG_UNKNOWN}},
   {   // 299
  /*.name  =*/ "recvmmsg",
  /*.nargs =*/ 5,
  /*.args  =*/ {ARG_INT, ARG_PTR, ARG_INT, ARG_INT, ARG_PTR, ARG_UNKNOWN}},
   {   // 300
  /*.name  =*/ "fanotify_init",
  /*.nargs =*/ 2,
  /*.args  =*/ {ARG_INT, ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 301
  /*.name  =*/ "fanotify_mark",
  /*.nargs =*/ 6,
  /*.args  =*/ {ARG_INT, ARG_INT, ARG_INT, ARG_INT, ARG_INT, ARG_STR}},
   {   // 302
  /*.name  =*/ "prlimit64",
  /*.nargs =*/ 4,
  /*.args  =*/ {ARG_INT, ARG_INT, ARG_PTR, ARG_PTR, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 303
  /*.name  =*/ "name_to_handle_at",
  /*.nargs =*/ 5,
  /*.args  =*/ {ARG_INT, ARG_STR, ARG_PTR, ARG_PTR, ARG_INT, ARG_UNKNOWN}},
   {   // 304
  /*.name  =*/ "open_by_handle_at",
  /*.nargs =*/ 3,
  /*.args  =*/ {ARG_INT, ARG_PTR, ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 305
  /*.name  =*/ "clock_adjtime",
  /*.nargs =*/ 2,
  /*.args  =*/ {ARG_INT, ARG_PTR, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 306
  /*.name  =*/ "syncfs",
  /*.nargs =*/ 1,
  /*.args  =*/ {ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 307
  /*.name  =*/ "sendmmsg",
  /*.nargs =*/ 4,
  /*.args  =*/ {ARG_INT, ARG_PTR, ARG_INT, ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 308
  /*.name  =*/ "setns",
  /*.nargs =*/ 2,
  /*.args  =*/ {ARG_INT, ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 309
  /*.name  =*/ "getcpu",
  /*.nargs =*/ 3,
  /*.args  =*/ {ARG_PTR, ARG_PTR, ARG_PTR, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN}},
   {   // 310
  /*.name  =*/ "process_vm_readv",
  /*.nargs =*/ 6,
  /*.args  =*/ {ARG_INT, ARG_PTR, ARG_INT, ARG_PTR, ARG_INT, ARG_INT}},
};
