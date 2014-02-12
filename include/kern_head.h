

/* x86_64 sys_call_table for kernel 2.4.x
 * generated from 2.6.33 unistd_64.h
 * grep ^__SYSCALL unistd_64.h | \
 *   sed s/.*,[[:blank:]]// | sed 's/)//' | \
 *   awk 'BEGIN{n = 0;}{ printf "    %-32s /%c %03d %c/\n", \
 *                              sprintf("\"%s\",", $1), "*", n, "*"; ++n; }'
 *
 */
char * syscalls_64[] = {
    "sys_read",                      /* 000 */
    "sys_write",                     /* 001 */
    "sys_open",                      /* 002 */
    "sys_close",                     /* 003 */
    "sys_newstat",                   /* 004 */
    "sys_newfstat",                  /* 005 */
    "sys_newlstat",                  /* 006 */
    "sys_poll",                      /* 007 */
    "sys_lseek",                     /* 008 */
    "sys_mmap",                      /* 009 */
    "sys_mprotect",                  /* 010 */
    "sys_munmap",                    /* 011 */
    "sys_brk",                       /* 012 */
    "sys_rt_sigaction",              /* 013 */
    "sys_rt_sigprocmask",            /* 014 */
    "stub_rt_sigreturn",             /* 015 */
    "sys_ioctl",                     /* 016 */
    "sys_pread64",                   /* 017 */
    "sys_pwrite64",                  /* 018 */
    "sys_readv",                     /* 019 */
    "sys_writev",                    /* 020 */
    "sys_access",                    /* 021 */
    "sys_pipe",                      /* 022 */
    "sys_select",                    /* 023 */
    "sys_sched_yield",               /* 024 */
    "sys_mremap",                    /* 025 */
    "sys_msync",                     /* 026 */
    "sys_mincore",                   /* 027 */
    "sys_madvise",                   /* 028 */
    "sys_shmget",                    /* 029 */
    "sys_shmat",                     /* 030 */
    "sys_shmctl",                    /* 031 */
    "sys_dup",                       /* 032 */
    "sys_dup2",                      /* 033 */
    "sys_pause",                     /* 034 */
    "sys_nanosleep",                 /* 035 */
    "sys_getitimer",                 /* 036 */
    "sys_alarm",                     /* 037 */
    "sys_setitimer",                 /* 038 */
    "sys_getpid",                    /* 039 */
    "sys_sendfile64",                /* 040 */
    "sys_socket",                    /* 041 */
    "sys_connect",                   /* 042 */
    "sys_accept",                    /* 043 */
    "sys_sendto",                    /* 044 */
    "sys_recvfrom",                  /* 045 */
    "sys_sendmsg",                   /* 046 */
    "sys_recvmsg",                   /* 047 */
    "sys_shutdown",                  /* 048 */
    "sys_bind",                      /* 049 */
    "sys_listen",                    /* 050 */
    "sys_getsockname",               /* 051 */
    "sys_getpeername",               /* 052 */
    "sys_socketpair",                /* 053 */
    "sys_setsockopt",                /* 054 */
    "sys_getsockopt",                /* 055 */
    "stub_clone",                    /* 056 */
    "stub_fork",                     /* 057 */
    "stub_vfork",                    /* 058 */
    "stub_execve",                   /* 059 */
    "sys_exit",                      /* 060 */
    "sys_wait4",                     /* 061 */
    "sys_kill",                      /* 062 */
    "sys_uname",                     /* 063 */
    "sys_semget",                    /* 064 */
    "sys_semop",                     /* 065 */
    "sys_semctl",                    /* 066 */
    "sys_shmdt",                     /* 067 */
    "sys_msgget",                    /* 068 */
    "sys_msgsnd",                    /* 069 */
    "sys_msgrcv",                    /* 070 */
    "sys_msgctl",                    /* 071 */
    "sys_fcntl",                     /* 072 */
    "sys_flock",                     /* 073 */
    "sys_fsync",                     /* 074 */
    "sys_fdatasync",                 /* 075 */
    "sys_truncate",                  /* 076 */
    "sys_ftruncate",                 /* 077 */
    "sys_getdents",                  /* 078 */
    "sys_getcwd",                    /* 079 */
    "sys_chdir",                     /* 080 */
    "sys_fchdir",                    /* 081 */
    "sys_rename",                    /* 082 */
    "sys_mkdir",                     /* 083 */
    "sys_rmdir",                     /* 084 */
    "sys_creat",                     /* 085 */
    "sys_link",                      /* 086 */
    "sys_unlink",                    /* 087 */
    "sys_symlink",                   /* 088 */
    "sys_readlink",                  /* 089 */
    "sys_chmod",                     /* 090 */
    "sys_fchmod",                    /* 091 */
    "sys_chown",                     /* 092 */
    "sys_fchown",                    /* 093 */
    "sys_lchown",                    /* 094 */
    "sys_umask",                     /* 095 */
    "sys_gettimeofday",              /* 096 */
    "sys_getrlimit",                 /* 097 */
    "sys_getrusage",                 /* 098 */
    "sys_sysinfo",                   /* 099 */
    "sys_times",                     /* 100 */
    "sys_ptrace",                    /* 101 */
    "sys_getuid",                    /* 102 */
    "sys_syslog",                    /* 103 */
    "sys_getgid",                    /* 104 */
    "sys_setuid",                    /* 105 */
    "sys_setgid",                    /* 106 */
    "sys_geteuid",                   /* 107 */
    "sys_getegid",                   /* 108 */
    "sys_setpgid",                   /* 109 */
    "sys_getppid",                   /* 110 */
    "sys_getpgrp",                   /* 111 */
    "sys_setsid",                    /* 112 */
    "sys_setreuid",                  /* 113 */
    "sys_setregid",                  /* 114 */
    "sys_getgroups",                 /* 115 */
    "sys_setgroups",                 /* 116 */
    "sys_setresuid",                 /* 117 */
    "sys_getresuid",                 /* 118 */
    "sys_setresgid",                 /* 119 */
    "sys_getresgid",                 /* 120 */
    "sys_getpgid",                   /* 121 */
    "sys_setfsuid",                  /* 122 */
    "sys_setfsgid",                  /* 123 */
    "sys_getsid",                    /* 124 */
    "sys_capget",                    /* 125 */
    "sys_capset",                    /* 126 */
    "sys_rt_sigpending",             /* 127 */
    "sys_rt_sigtimedwait",           /* 128 */
    "sys_rt_sigqueueinfo",           /* 129 */
    "sys_rt_sigsuspend",             /* 130 */
    "stub_sigaltstack",              /* 131 */
    "sys_utime",                     /* 132 */
    "sys_mknod",                     /* 133 */
    "sys_ni_syscall",                /* 134 */
    "sys_personality",               /* 135 */
    "sys_ustat",                     /* 136 */
    "sys_statfs",                    /* 137 */
    "sys_fstatfs",                   /* 138 */
    "sys_sysfs",                     /* 139 */
    "sys_getpriority",               /* 140 */
    "sys_setpriority",               /* 141 */
    "sys_sched_setparam",            /* 142 */
    "sys_sched_getparam",            /* 143 */
    "sys_sched_setscheduler",        /* 144 */
    "sys_sched_getscheduler",        /* 145 */
    "sys_sched_get_priority_max",    /* 146 */
    "sys_sched_get_priority_min",    /* 147 */
    "sys_sched_rr_get_interval",     /* 148 */
    "sys_mlock",                     /* 149 */
    "sys_munlock",                   /* 150 */
    "sys_mlockall",                  /* 151 */
    "sys_munlockall",                /* 152 */
    "sys_vhangup",                   /* 153 */
    "sys_modify_ldt",                /* 154 */
    "sys_pivot_root",                /* 155 */
    "sys_sysctl",                    /* 156 */
    "sys_prctl",                     /* 157 */
    "sys_arch_prctl",                /* 158 */
    "sys_adjtimex",                  /* 159 */
    "sys_setrlimit",                 /* 160 */
    "sys_chroot",                    /* 161 */
    "sys_sync",                      /* 162 */
    "sys_acct",                      /* 163 */
    "sys_settimeofday",              /* 164 */
    "sys_mount",                     /* 165 */
    "sys_umount",                    /* 166 */
    "sys_swapon",                    /* 167 */
    "sys_swapoff",                   /* 168 */
    "sys_reboot",                    /* 169 */
    "sys_sethostname",               /* 170 */
    "sys_setdomainname",             /* 171 */
    "stub_iopl",                     /* 172 */
    "sys_ioperm",                    /* 173 */
    "sys_ni_syscall",                /* 174 */
    "sys_init_module",               /* 175 */
    "sys_delete_module",             /* 176 */
    "sys_ni_syscall",                /* 177 */
    "sys_ni_syscall",                /* 178 */
    "sys_quotactl",                  /* 179 */
    "sys_nfsservctl",                /* 180 */
    "sys_ni_syscall",                /* 181 */
    "sys_ni_syscall",                /* 182 */
    "sys_ni_syscall",                /* 183 */
    "sys_ni_syscall",                /* 184 */
    "sys_ni_syscall",                /* 185 */
    "sys_gettid",                    /* 186 */
    "sys_readahead",                 /* 187 */
    "sys_setxattr",                  /* 188 */
    "sys_lsetxattr",                 /* 189 */
    "sys_fsetxattr",                 /* 190 */
    "sys_getxattr",                  /* 191 */
    "sys_lgetxattr",                 /* 192 */
    "sys_fgetxattr",                 /* 193 */
    "sys_listxattr",                 /* 194 */
    "sys_llistxattr",                /* 195 */
    "sys_flistxattr",                /* 196 */
    "sys_removexattr",               /* 197 */
    "sys_lremovexattr",              /* 198 */
    "sys_fremovexattr",              /* 199 */
    "sys_tkill",                     /* 200 */
    "sys_time",                      /* 201 */
    "sys_futex",                     /* 202 */
    "sys_sched_setaffinity",         /* 203 */
    "sys_sched_getaffinity",         /* 204 */
    "sys_ni_syscall",                /* 205 */
    "sys_io_setup",                  /* 206 */
    "sys_io_destroy",                /* 207 */
    "sys_io_getevents",              /* 208 */
    "sys_io_submit",                 /* 209 */
    "sys_io_cancel",                 /* 210 */
    "sys_ni_syscall",                /* 211 */
    "sys_lookup_dcookie",            /* 212 */
    "sys_epoll_create",              /* 213 */
    "sys_ni_syscall",                /* 214 */
    "sys_ni_syscall",                /* 215 */
    "sys_remap_file_pages",          /* 216 */
    "sys_getdents64",                /* 217 */
    "sys_set_tid_address",           /* 218 */
    "sys_restart_syscall",           /* 219 */
    "sys_semtimedop",                /* 220 */
    "sys_fadvise64",                 /* 221 */
    "sys_timer_create",              /* 222 */
    "sys_timer_settime",             /* 223 */
    "sys_timer_gettime",             /* 224 */
    "sys_timer_getoverrun",          /* 225 */
    "sys_timer_delete",              /* 226 */
    "sys_clock_settime",             /* 227 */
    "sys_clock_gettime",             /* 228 */
    "sys_clock_getres",              /* 229 */
    "sys_clock_nanosleep",           /* 230 */
    "sys_exit_group",                /* 231 */
    "sys_epoll_wait",                /* 232 */
    "sys_epoll_ctl",                 /* 233 */
    "sys_tgkill",                    /* 234 */
    "sys_utimes",                    /* 235 */
    "sys_ni_syscall",                /* 236 */
    "sys_mbind",                     /* 237 */
    "sys_set_mempolicy",             /* 238 */
    "sys_get_mempolicy",             /* 239 */
    "sys_mq_open",                   /* 240 */
    "sys_mq_unlink",                 /* 241 */
    "sys_mq_timedsend",              /* 242 */
    "sys_mq_timedreceive",           /* 243 */
    "sys_mq_notify",                 /* 244 */
    "sys_mq_getsetattr",             /* 245 */
    "sys_kexec_load",                /* 246 */
    "sys_waitid",                    /* 247 */
    "sys_add_key",                   /* 248 */
    "sys_request_key",               /* 249 */
    "sys_keyctl",                    /* 250 */
    "sys_ioprio_set",                /* 251 */
    "sys_ioprio_get",                /* 252 */
    "sys_inotify_init",              /* 253 */
    "sys_inotify_add_watch",         /* 254 */
    "sys_inotify_rm_watch",          /* 255 */
    "sys_migrate_pages",             /* 256 */
    "sys_openat",                    /* 257 */
    "sys_mkdirat",                   /* 258 */
    "sys_mknodat",                   /* 259 */
    "sys_fchownat",                  /* 260 */
    "sys_futimesat",                 /* 261 */
    "sys_newfstatat",                /* 262 */
    "sys_unlinkat",                  /* 263 */
    "sys_renameat",                  /* 264 */
    "sys_linkat",                    /* 265 */
    "sys_symlinkat",                 /* 266 */
    "sys_readlinkat",                /* 267 */
    "sys_fchmodat",                  /* 268 */
    "sys_faccessat",                 /* 269 */
    "sys_pselect6",                  /* 270 */
    "sys_ppoll",                     /* 271 */
    "sys_unshare",                   /* 272 */
    "sys_set_robust_list",           /* 273 */
    "sys_get_robust_list",           /* 274 */
    "sys_splice",                    /* 275 */
    "sys_tee",                       /* 276 */
    "sys_sync_file_range",           /* 277 */
    "sys_vmsplice",                  /* 278 */
    "sys_move_pages",                /* 279 */
    "sys_utimensat",                 /* 280 */
    "sys_epoll_pwait",               /* 281 */
    "sys_signalfd",                  /* 282 */
    "sys_timerfd_create",            /* 283 */
    "sys_eventfd",                   /* 284 */
    "sys_fallocate",                 /* 285 */
    "sys_timerfd_settime",           /* 286 */
    "sys_timerfd_gettime",           /* 287 */
    "sys_accept4",                   /* 288 */
    "sys_signalfd4",                 /* 289 */
    "sys_eventfd2",                  /* 290 */
    "sys_epoll_create1",             /* 291 */
    "sys_dup3",                      /* 292 */
    "sys_pipe2",                     /* 293 */
    "sys_inotify_init1",             /* 294 */
    "sys_preadv",                    /* 295 */
    "sys_pwritev",                   /* 296 */
    "sys_rt_tgsigqueueinfo",         /* 297 */
    "sys_perf_event_open",           /* 298 */
    "sys_recvmmsg",                  /* 299 */
    NULL
};

/* i386 sys_call_table for kernel 2.4.x
 */
char * syscalls_32[] = {
    "sys_restart_syscall",    /* 0 - old setup() system call*/
    "sys_exit",
    "sys_fork",
    "sys_read",
    "sys_write",
    "sys_open",        /* 5 */
    "sys_close",
    "sys_waitpid",
    "sys_creat",
    "sys_link",
    "sys_unlink",        /* 10 */
    "sys_execve",
    "sys_chdir",
    "sys_time",
    "sys_mknod",
    "sys_chmod",        /* 15 */
    "sys_lchown16",
    "sys_break",
    "sys_stat",
    "sys_lseek",
    "sys_getpid",        /* 20 */
    "sys_mount",
    "sys_oldumount",
    "sys_setuid16",
    "sys_getuid16",
    "sys_stime",        /* 25 */
    "sys_ptrace",
    "sys_alarm",
    "sys_fstat",
    "sys_pause",
    "sys_utime",        /* 30 */
    "sys_stty",
    "sys_gtty",
    "sys_access",
    "sys_nice",
    "sys_ftime",        /* 35 */
    "sys_sync",
    "sys_kill",
    "sys_rename",
    "sys_mkdir",
    "sys_rmdir",        /* 40 */
    "sys_dup",
    "sys_pipe",
    "sys_times",
    "sys_prof",
    "sys_brk",        /* 45 */
    "sys_setgid16",
    "sys_getgid16",
    "sys_signal",
    "sys_geteuid16",
    "sys_getegid16",    /* 50 */
    "sys_acct",
    "sys_umount2",
    "sys_lock",
    "sys_ioctl",
    "sys_fcntl",        /* 55 */
    "sys_mpx",
    "sys_setpgid",
    "sys_ulimit",
    "sys_olduname",
    "sys_umask",        /* 60 */
    "sys_chroot",
    "sys_ustat",
    "sys_dup2",
    "sys_getppid",
    "sys_getpgrp",        /* 65 */
    "sys_setsid",
    "sys_sigaction",
    "sys_sgetmask",
    "sys_ssetmask",
    "sys_setreuid16",    /* 70 */
    "sys_setregid16",
    "sys_sigsuspend",
    "sys_sigpending",
    "sys_sethostname",
    "sys_setrlimit",    /* 75 */
    "sys_getrlimit",
    "sys_getrusage",
    "sys_gettimeofday",
    "sys_settimeofday",
    "sys_getgroups16",    /* 80 */
    "sys_setgroups16",
    "old_select",
    "sys_symlink",
    "sys_lstat",
    "sys_readlink",        /* 85 */
    "sys_uselib",
    "sys_swapon",
    "sys_reboot",
    "old_readdir",
    "old_mmap",        /* 90 */
    "sys_munmap",
    "sys_truncate",
    "sys_ftruncate",
    "sys_fchmod",
    "sys_fchown16",        /* 95 */
    "sys_getpriority",
    "sys_setpriority",
    "sys_profil",
    "sys_statfs",
    "sys_fstatfs",        /* 100 */
    "sys_ioperm",
    "sys_socketcall",
    "sys_syslog",
    "sys_setitimer",
    "sys_getitimer",    /* 105 */
    "sys_newstat",
    "sys_newlstat",
    "sys_newfstat",
    "sys_olduname",
    "sys_iopl",        /* 110 */
    "sys_vhangup",
    "sys_idle",
    "sys_vm86old",
    "sys_wait4",
    "sys_swapoff",        /* 115 */
    "sys_sysinfo",
    "sys_ipc",
    "sys_fsync",
    "sys_sigreturn",
    "sys_clone",        /* 120 */
    "sys_setdomainname",
    "sys_newuname",
    "sys_modify_ldt",
    "sys_adjtimex",
    "sys_mprotect",        /* 125 */
    "sys_sigprocmask",
    "sys_create_module",
    "sys_init_module",
    "sys_delete_module",
    "sys_get_kernel_syms",    /* 130 */
    "sys_quotactl",
    "sys_getpgid",
    "sys_fchdir",
    "sys_bdflush",
    "sys_sysfs",        /* 135 */
    "sys_personality",
    "sys_afs_syscall",
    "sys_setfsuid16",
    "sys_setfsgid16",
    "sys_llseek",        /* 140 */
    "sys_getdents",
    "sys_select",
    "sys_flock",
    "sys_msync",
    "sys_readv",        /* 145 */
    "sys_writev",
    "sys_getsid",
    "sys_fdatasync",
    "sys__sysctl",
    "sys_mlock",        /* 150 */
    "sys_munlock",
    "sys_mlockall",
    "sys_munlockall",
    "sys_sched_setparam",
    "sys_sched_getparam",  /* 155 */
    "sys_sched_setscheduler",
    "sys_sched_getscheduler",
    "sys_sched_yield",
    "sys_sched_get_priority_max",
    "sys_sched_get_priority_min", /* 160 */
    "sys_sched_rr_get_interval",
    "sys_nanosleep",
    "sys_mremap",
    "sys_setresuid",
    "sys_getresuid",    /* 165 */
    "sys_vm86",
    "sys_query_module",
    "sys_poll",
    "sys_nfsservctl",
    "sys_setresgid",    /* 170 */
    "sys_getresgid",
    "sys_prctl",
    "sys_rt_sigreturn",
    "sys_rt_sigaction",
    "sys_rt_sigprocmask",    /* 175 */
    "sys_rt_sigpending",
    "sys_rt_sigtimedwait",
    "sys_rt_sigqueueinfo",
    "sys_rt_sigsuspend",
    "sys_pread",        /* 180 */
    "sys_pwrite",
    "sys_chown16",
    "sys_getcwd",
    "sys_capget",
    "sys_capset",      /* 185 */
    "sys_sigaltstack",
    "sys_sendfile",
    "sys_getpmsg",        /* streams1 */
    "sys_putpmsg",        /* streams2 */
    "sys_vfork",      /* 190 */
    "sys_ugetrlimit",
    "sys_mmap2",
    "sys_truncate64",
    "sys_ftruncate64",
    "sys_stat64",        /* 195 */
    "sys_lstat64",
    "sys_fstat64",
    "sys_lchown32",
    "sys_getuid32",
    "sys_getgid32",        /* 200 */
    "sys_geteuid32",
    "sys_getegid32",
    "sys_setreuid32",
    "sys_setregid32",
    "sys_getgroups32",    /* 205 */
    "sys_setgroups32",
    "sys_fchown32",
    "sys_setresuid32",
    "sys_getresuid32",
    "sys_setresgid32",    /* 210 */
    "sys_getresgid32",
    "sys_chown32",
    "sys_setuid32",
    "sys_setgid32",
    "sys_setfsuid32",        /* 215 */
    "sys_setfsgid32",
    "sys_pivot_root",
    "sys_mincore",
    "sys_madvise",
    "sys_getdents64",    /* 220 */
    "sys_fcntl64",
    "sys_tux",     /* reserved for TUX, unused */
    "sys_security",
    "sys_gettid",
    "sys_readahead",     /* 225 */
    "sys_setxattr",
    "sys_lsetxattr",
    "sys_fsetxattr",
    "sys_getxattr",
    "sys_lgetxattr",     /* 230 */
    "sys_fgetxattr",
    "sys_listxattr",
    "sys_llistxattr",
    "sys_flistxattr",
    "sys_removexattr",   /* 235 */
    "sys_lremovexattr",
    "sys_fremovexattr",
    "sys_tkill",
    "sys_sendfile64",
    "sys_futex",         /* 240 */
    "sys_sched_setaffinity",
    "sys_sched_getaffinity",
    "sys_set_thread_area",
    "sys_get_thread_area",   
    "sys_io_setup",           /* 245 */
    "sys_io_destroy",         
    "sys_io_getevents",       
    "sys_io_submit",          
    "sys_io_cancel",          
    "sys_alloc_hugepages",    /* 250 */
    "sys_free_hugepages",     
    "sys_exit_group",         
    "sys_lookup_dcookie",     /* 2.6 */
    "sys_epoll_create",
    "sys_epoll_ctl",          /* 255 */
    "sys_epoll_wait",
    "sys_remap_file_pages",
    "sys_set_tid_address",
    "sys_timer_create",
    "sys_timer_settime",      /* 260 */
    "sys_timer_gettime",
    "sys_timer_getoverrun",
    "sys_timer_delete",
    "sys_clock_settime",
    "sys_clock_gettime",      /* 265 */
    "sys_clock_getres",
    "sys_clock_nanosleep",
    "sys_statfs64",
    "sys_fstatfs64",
    "sys_tgkill",             /* 270 */
    "sys_utimes",
    "sys_fadvise64_64",
    "sys_vserver",            /* last 2.4 */
    "sys_mbind",
    "sys_get_mempolicy",      /* 275 */
    "sys_set_mempolicy",
    "sys_mq_open",
    "sys_mq_unlink",
    "sys_mq_timedsend",
    "sys_mq_timedreceive",    /* 280 */
    "sys_mq_notify",
    "sys_mq_getsetattr",
    "sys_kexec_load",
    "sys_waitid",
    "sys_sys_setaltroot",     /* 285 */
    "sys_add_key",
    "sys_request_key",
    "sys_keyctl",
    "sys_ioprio_set",
    "sys_ioprio_get",         /* 290 */
    "sys_inotify_init",
    "sys_inotify_add_watch",
    "sys_inotify_rm_watch",
    "sys_migrate_pages",
    "sys_openat",             /* 295 */
    "sys_mkdirat",
    "sys_mknodat",
    "sys_fchownat",
    "sys_futimesat",
    "sys_fstatat64",          /* 300 */
    "sys_unlinkat",
    "sys_renameat",
    "sys_linkat",
    "sys_symlinkat",
    "sys_readlinkat",         /* 305 */
    "sys_fchmodat",
    "sys_faccessat",
    "sys_pselect6",
    "sys_ppoll",
    "sys_unshare",            /* 310 */
    "sys_set_robust_list",
    "sys_get_robust_list",
    "sys_splice",
    "sys_sync_file_range",
    "sys_tee",                /* 315 */
    "sys_vmsplice",
    "sys_move_pages",
    "sys_getcpu",
    "sys_epoll_pwait",
    "sys_utimensat",          /* 320 */
    "sys_signalfd",
    "sys_timerfd_create",
    "sys_eventfd",
    "sys_fallocate",          /* last 2.6.24 */
    "sys_timerfd_settime",    /* 325 */
    "sys_timerfd_gettime",
    "sys_signalfd4",
    "sys_eventfd2",
    "sys_epoll_create1",
    "sys_dup3",               /* 330 */
    "sys_pipe2",
    "sys_inotify_init1",      /* end 2.6.27 */
    "sys_preadv",
    "sys_pwritev",            /* end 2.6.30 */
    "sys_rt_tgsigqueueinfo",  /* 335 */
    "sys_perf_event_open",    /* end 2.6.31 */
    "sys_recvmmsg",
    NULL
};



/* i386 sys_call_table for openbsd
 */
char * callz_obsd[]={
  "_nosys",               /*   0 */
  "_sys_exit",
  "_sys_fork",
  "_sys_read",
  "_sys_write",
  "_sys_open",            /*   5 */
  "_sys_close",
  "_sys_wait4",
  "_compat_43_sys_creat",
  "_sys_link",
  "_sys_unlink",          /*  10 */
  "_sys_nosys",
  "_sys_chdir",
  "_sys_fchdir",
  "_sys_mknod",
  "_sys_chmod",           /*  15 */
  "_sys_chown",
  "_sys_break",
  "_nosys",
  "_compat_43_sys_lseek",
  "_sys_getpid",          /*  20 */       
  "_sys_mount",
  "_sys_unmount",
  "_sys_setuid",
  "_sys_getuid",
  "_sys_geteuid",         /*  25 */
  "_sys_ptrace",
  "_sys_recvmsg",  /*	27 */
  "_sys_sendmsg",  /*	28 */
  "_sys_recvfrom", /*	29 */
  "_sys_accept",   /*	30 */
  "_sys_getpeername", /*	31 */
  "_sys_getsockname", /*	32 */
  "_sys_access",   /*	33 */
  "_sys_chflags",  /*	34 */
  "_sys_fchflags", /*	35 */
  "_sys_sync",     /*	36 */
  "_sys_kill",     /*	37 */
  "_compat_43_sys_stat",			/* 38 is old stat */
  "_sys_getppid",  /*	39 */
  "_compat_43_sys_lstat",		        /* 40 is old lstat */
  "_sys_dup",      /*	41 */
  "_sys_opipe",    /*	42 */
  "_sys_getegid",  /*	43 */
  "_sys_profil",   /*	44 */
  "_sys_ktrace",   /*	45 */
  "_sys_sigaction",/*       46 */
  "_sys_getgid",   /*	47 */
  "_sys_sigprocmask",
  "_sys_getlogin", /*	49 */
  "_sys_setlogin", /*	50 */
  "_sys_acct",     /*	51 */
  "_sys_sigpending",
  "_sys_osigaltstack", /*	53 */
  "_sys_ioctl",    /*	54 */
  "_sys_reboot",   /*	55 */
  "_sys_revoke",   /*	56 */
  "_sys_symlink",  /*	57 */
  "_sys_readlink", /*	58 */
  "_sys_execve",   /*	59 */
  "_sys_umask",    /*	60 */
  "_sys_chroot",   /*	61 */
  "_compat_43_sys_fstat",			/* 62 is old fstat */
  "_compat_43_sys_getkerninfo",			/* 63 is old ogetkerninfo */
  "_compat_43_sys_getpagesize",			/* 64 is old ogetpagesize */
  "_nosys",                     /* 65 is omsync */
  "_sys_vfork",    /*	66 */
  "_nosys",			/* 67 is obsolete vread */
  "_nosys",			/* 68 is obsolete vwrite */
  "_sys_sbrk",     /*	69 */
  "_sys_sstk",     /*	70 */
  "_compat_43_sys_mmap",			/* 71 is ommap */
  "_sys_ovadvise",  /*	72 */
  "_sys_munmap",   /*	73 */
  "_sys_mprotect", /*	74 */
  "_sys_madvise",  /*	75 */
  "_nosys",			/* 76 is obsolete vhangup */
  "_nosys",			/* 77 is obsolete vlimit */
  "_sys_mincore",  /*	78 */
  "_sys_getgroups",/*	79 */
  "_sys_setgroups",/*	80 */
  "_sys_getpgrp",  /*	81 */
  "_sys_setpgid",  /*	82 */
  "_sys_setitimer",/*	83 */
  "_compat_43_sys_wait",			/* 84 is owait */
  "_nosys",                      /* 85 is swapon */
  "_sys_getitimer",/*	86 */
  "_compat_43_sys_gethostname",			/* 87 is ogethostname */
  "_compat_43_sys_sethostname",			/* 88 is osethostname */
  "_compat_43_sys_getdtablesize",               /* 89 os ogetdtablesize */
  "_sys_dup2",     /*	90 */
  "_nosys",			/* 91 is ??? */
  "_sys_fcntl",    /*	92 */
  "_sys_select",   /*	93 */
  "_nosys",			/* 94 is ??? */
  "_sys_fsync",    /*	95 */
  "_sys_setpriority", /*	96 */
  "_sys_socket",   /*	97 */
  "_sys_connect",  /*	98 */
  "_compat_43_sys_accept",			/* 99 is oaccept */
  "_sys_getpriority", /*	100 */
  "_compat_43_sys_send",			/* 101 is osend */
  "_compat_43_sys_recv",			/* 102 is orecv */
  "_sys_sigreturn",
  "_sys_bind",     /*	104 */
  "_sys_setsockopt", /*	105 */
  "_sys_listen",   /*	106 */
  "_nosys",			/* 107 is obsolete vtimes */
  "_compat_43_sys_sigvec",			/* 108 is osigvec */
  "_compat_43_sys_sigblock",			/* 109 is osigblock */
  "_compat_43_sys_sigsetmask",			/* 110 is osigsetmask */
  "_sys_sigsuspend",
  "_compat_43_sys_sigstack",			/* 112 is osigstack */
  "_compat_43_sys_recvmsg",			/* 113 is orecvmsg */
  "_compat_43_sys_sendmsg",			/* 114 is osendmsg */
  "_nosys",			/* 115 is obsolete vtrace */
  "_sys_gettimeofday", /*	116 */ 
  "_sys_getrusage",    /*	117 */
  "_sys_getsockopt",   /*	118 */
  "_nosys",			/* 119 is obsolete resuba */
  "_sys_readv",        /*	120 */
  "_sys_writev",       /*	121 */
  "_sys_settimeofday", /*	122 */
  "_sys_fchown",       /*	123 */
  "_sys_fchmod",       /*	124 */
  "_compat_43_sys_recvfrom",			/* 125 is orecvfrom */
  "_sys_setreuid",     /*	126 */
  "_sys_setregid",     /*	127 */
  "_sys_rename",       /*	128 */
  "_compat_43_sys_truncate",			/* 129 is old truncate */
  "_compat_43_sys_ftruncate",			/* 130 is old ftruncate */
  "_sys_flock",        /*	131 */
  "_sys_mkfifo",       /*	132 */
  "_sys_sendto",       /*	133 */
  "_sys_shutdown",     /*	134 */
  "_sys_socketpair",   /*	135 */
  "_sys_mkdir",        /*	136 */
  "_sys_rmdir",        /*	137 */
  "_sys_utimes",       /*	138 */
  "_nosys",			/* 139 is obsolete 4.2 sigreturn */
  "_sys_adjtime",      /*	140 */
  "_compat_43_sys_getpeername",			/* 141 is ogetpeername */
  "_compat_43_sys_gethostid",			/* 142 is ogethostid */
  "_compat_43_sys_sethostid",			/* 143 is osethostid */
  "_compat_43_sys_getrlimit",			/* 144 is ogetrlimit */
  "_compat_43_sys_setrlimit",			/* 145 is osetrlimit */
  "_compat_43_sys_killpg",			/* 146 is okillpg */
  "_sys_setsid",       /*	147 */
  "_sys_quotactl",     /*	148 */
  "_compat_43_sys_quota",			/* 149 is oquota */
  "_compat_43_sys_getsockname",			/* 150 is ogetsockname */
  "_nosys",			/* 151 is ??? */
  "_nosys",			/* 152 is ??? */
  "_nosys",			/* 153 is ??? */
  "_nosys",			/* 154 is ??? */
  "_sys_nfssvc",       /*	155 */
  "_compat_43_sys_getdirentries",	        /* 156 is ogetdirentries */
  "_nosys",                      /* 157 is ostatfs */
  "_nosys",                     /* 158 is ofstatfs */
  "_nosys",			/* 159 is ??? */
  "_nosys",			/* 160 is ??? */
  "_sys_getfh",        /*	161 */
  "_nosys",               /* 162 is ogetdomainname */
  "_nosys",               /* 163 is osetdomainname */
  "_nosys",                       /* 164 is ouname */
  "_sys_sysarch",      /*	165 */
  "_nosys",
  "_nosys",			/* 167 is ??? */
  "_nosys",			/* 168 is ??? */
  "_nosys",       /*	169 is compat_10 osemsys */
  "_nosys",       /*	170 is compat_10 omsgsys */
  "_nosys",       /*	171 is compat_10 oshmsys */
  "_nosys",			/* 172 is ??? */
  "_sys_pread",        /*	173 */
  "_sys_pwrite",       /*	174 */
  "_nosys",			/* 175 is ??? */
  "_nosys",                     /* 176 is ??? */
  "_nosys",			/* 177 is ??? */
  "_nosys",			/* 178 is ??? */
  "_nosys",			/* 179 is ??? */
  "_nosys",			/* 180 is ??? */
  "_sys_setgid",       /*	181 */
  "_sys_setegid",      /*	182 */
  "_sys_seteuid",      /*	183 */
  "_sys_bmapv",	   /*   184 */
  "_sys_markv",	   /*   185 */
  "_sys_segclean",	   /*   186 */
  "_sys_segwait",	   /*   187 */
  "_compat_35_sys_stat",        /*	188 is compat_35 stat35 */
  "_compat_35_sys_fstat",       /*	189 is compat_35 fstat35 */
  "_compat_35_sys_lstat",       /*	190 is compat_35 lstat35 */
  "_sys_pathconf",     /*	191 */
  "_sys_fpathconf",    /*	192 */
  "_sys_swapctl",	   /*   193 */
  "_sys_getrlimit",    /*	194 */
  "_sys_setrlimit",    /*	195 */
  "_sys_getdirentries", /*	196 */
  "_sys_mmap",         /*	197 */
  "_sys___syscall",    /*	198 */
  "_sys_lseek",        /*	199 */
  "_sys_truncate",     /*	200 */
  "_sys_ftruncate",    /*	201 */
  "_sys___sysctl",     /*	202 */
  "_sys_mlock",        /*	203 */
  "_sys_munlock",      /*	204 */
  "_sys_undelete",     /*	205 */
  "_sys_futimes",      /*	206 */
  "_sys_getpgid",      /*	207 */
  "_sys_xfspioctl",    /*   208 */
  "_nosys",                     /* 209 is ??? */
  "_nosys",			/* 210 is ??? */
  "_nosys",			/* 211 is ??? */
  "_nosys",			/* 212 is ??? */
  "_nosys",			/* 213 is ??? */
  "_nosys",			/* 214 is ??? */
  "_nosys",			/* 215 is ??? */
  "_nosys",			/* 216 is ??? */
  "_nosys",			/* 217 is ??? */
  "_nosys",			/* 218 is ??? */
  "_nosys",			/* 219 is ??? */
  "_nosys",                     /* 220 is ??? */
  "_sys_semget",       /*	221 */
  "_compat_35_sys_semop",       /* 222 is compat_35 semop */
  "_nosys",			/* 223 is obsolete sys_semconfig */
  "_nosys",                     /* 224 is compat_23 msgctl23 */
  "_sys_msgget",       /*	225 */
  "_sys_msgsnd",       /*	226 */
  "_sys_msgrcv",       /*	227 */
  "_sys_shmat",        /*	228 */
  "_nosys",                     /* 229 is compat_23 shmctl23 */
  "_sys_shmdt",        /*	230 */
  "_compat_35_sys_shmget",      /* 231 is compat_35 shmget */
  "_sys_clock_gettime", /*	232 */
  "_sys_clock_settime", /*	233 */
  "_sys_clock_getres", /*	234 */
  "_nosys",			/* 235 is ??? */
  "_nosys",			/* 236 is ??? */
  "_nosys",			/* 237 is ??? */
  "_nosys",			/* 238 is ??? */
  "_nosys",			/* 239 is ??? */
  "_sys_nanosleep",    /*	240 */
  "_nosys",			/* 241 is ??? */
  "_nosys",			/* 242 is ??? */
  "_nosys",			/* 243 is ??? */
  "_nosys",			/* 244 is ??? */
  "_nosys",			/* 245 is ??? */
  "_nosys",			/* 246 is ??? */
  "_nosys",			/* 247 is ??? */
  "_nosys",			/* 248 is ??? */
  "_nosys",			/* 249 is ??? */
  "_sys_minherit",     /*	250 */
  "_sys_rfork",        /*	251 */
  "_sys_poll",         /*	252 */
  "_sys_issetugid",    /*	253 */
  "_sys_lchown",       /*	254 */
  "_sys_getsid",	   /*   255 */
  "_sys_msync",	   /*   256 */
  "_compat_35_sys___semctl",		/* 257 is compat_35 semctl35 */
  "_compat_35_sys_shmctl",		/* 258 is is compat_35 shmctl35 */
  "_compat_35_sys_msgctl",		/* 259 is is compat_35 msgctl35 */
  "_sys_getfsstat",	   /* 260  */
  "_sys_statfs",	   /* 261  */
  "_sys_fstatfs",	   /* 262  */
  "_sys_pipe",	   /* 263  */
  "_sys_fhopen",	   /* 264  */
  "_compat_35_sys_fhstat",	        /* 265 is compat_35 fhstat */
  "_sys_fhstatfs",	   /* 266  */
  "_sys_preadv",	   /* 267  */
  "_sys_pwritev",	   /* 268  */
  "_sys_kqueue",	   /* 269  */
  "_sys_kevent",	   /* 270  */
  "_sys_mlockall",	   /* 271  */
  "_sys_munlockall",   /* 272  */
  "_sys_getpeereid",   /* 273  */
  "_nosys",                     /*	274 */
  "_nosys",                     /*	275 */
  "_nosys",                     /*	276 */
  "_nosys",                     /*	277 */
  "_nosys",                     /*	278 */
  "_nosys",                     /*	279 */
  "_nosys",                     /*	280 */
  "_sys_getresuid",	   /* 281  */
  "_sys_setresuid",	   /* 282  */
  "_sys_getresgid",	   /* 283  */
  "_sys_setresgid",	   /* 284  */
  "_nosys",			/* 285 is ??? */
  "_sys_mquery",       /* 286  */
  "_sys_closefrom",	   /* 287  */
  "_sys_sigaltstack",  /* 288  */
  "_sys_shmget",	   /* 289  */
  "_sys_semop",	   /* 290  */
  "_sys_stat",	   /* 291  */
  "_sys_fstat",	   /* 292  */
  "_sys_lstat",	   /* 293  */
  "_sys_fhstat",	   /* 294  */
  "_sys___semctl",	   /* 295  */
  "_sys_shmctl",	   /* 296  */
  "_sys_msgctl",           /* 297  */
  "_sys_sched_yield",      /* 298  */
  "_sys_getthrid",         /* 299  */
  "_sys_thrsleep",         /* 300  */
  "_sys_thrwakeup",        /* 301  */
  "_sys_threxit",          /* 302  */
  "_sys_thrsigdivert",     /* 303  */
  "_sys___getcwd",         /* 304  */
  NULL
};



/* i386 sys_call_table for freebsd
 */
char * callz_fbsd[]={
  "_syscall",  /*	 0 */
  "sys_exit",  /*	 1 */
  "_fork",     /*	 2 */
  "_read",     /*	 3 */
  "_write",    /*	 4 */
  "_open",     /*	 5 */
  "_close",    /*	 6 */
  "_wait4",    /*	 7 */
  "_nosys",			/* 8 is old creat */
  "_link",     /*	 9 */
  "_unlink",   /*	10 */
  "_nosys",			/* 11 is obsolete execv */
  "_chdir",    /*	12 */
  "_fchdir",   /*	13 */
  "_mknod",    /*	14 */
  "_chmod",    /*	15 */
  "_chown",    /*	16 */
  "_break",    /*	17 */
  "_getfsstat",/*	18 */
  "_nosys",	        	/* 19 is old lseek */
  "_getpid",   /*	20 */
  "_mount",    /*	21 */
  "_unmount",  /*	22 */
  "_setuid",   /*	23 */
  "_getuid",   /*	24 */
  "_geteuid",  /*	25 */
  "_ptrace",   /*	26 */
  "_recvmsg",  /*	27 */
  "_sendmsg",  /*	28 */
  "_recvfrom", /*	29 */
  "_accept",   /*	30 */
  "_getpeername", /*	31 */
  "_getsockname", /*	32 */
  "_access",   /*	33 */
  "_chflags",  /*	34 */
  "_fchflags", /*	35 */
  "_sync",     /*	36 */
  "_kill",     /*	37 */
  "_nosys",			/* 38 is old stat */
  "_getppid",  /*	39 */
  "_nosys",		        /* 40 is old lstat */
  "_dup",      /*	41 */
  "_pipe",     /*	42 */
  "_getegid",  /*	43 */
  "_profil",   /*	44 */
  "_ktrace",   /*	45 */
  "_nosys",			/* 46 is old sigaction */
  "_getgid",   /*	47 */
  "_nosys",			/* 48 is old sigprocmask */
  "_getlogin", /*	49 */
  "_setlogin", /*	50 */
  "_acct",     /*	51 */
  "_nosys",			/* 52 is old sigpending */
  "_sigaltstack", /*	53 */
  "_ioctl",    /*	54 */
  "_reboot",   /*	55 */
  "_revoke",   /*	56 */
  "_symlink",  /*	57 */
  "_readlink", /*	58 */
  "_execve",   /*	59 */
  "_umask",    /*	60 */
  "_chroot",   /*	61 */
  "_nosys",			/* 62 is old fstat */
  "_nosys",			/* 63 is old getkerninfo */
  "_nosys",			/* 64 is old getpagesize */
  "_msync",    /*	65 */
  "_vfork",    /*	66 */
  "_nosys",			/* 67 is obsolete vread */
  "_nosys",			/* 68 is obsolete vwrite */
  "_sbrk",     /*	69 */
  "_sstk",     /*	70 */
  "_nosys",			/* 71 is old mmap */
  "_vadvise",  /*	72 */
  "_munmap",   /*	73 */
  "_mprotect", /*	74 */
  "_madvise",  /*	75 */
  "_nosys",			/* 76 is obsolete vhangup */
  "_nosys",			/* 77 is obsolete vlimit */
  "_mincore",  /*	78 */
  "_getgroups",/*	79 */
  "_setgroups",/*	80 */
  "_getpgrp",  /*	81 */
  "_setpgid",  /*	82 */
  "_setitimer",/*	83 */
  "_nosys",			/* 84 is old wait */
  "_swapon",   /*	85 */
  "_getitimer",/*	86 */
  "_nosys",			/* 87 is old gethostname */
  "_nosys",			/* 88 is old sethostname */
  "_getdtablesize", /*	89 */
  "_dup2",     /*	90 */
  "_nosys",			/* 91 is ??? */
  "_fcntl",    /*	92 */
  "_select",   /*	93 */
  "_nosys",			/* 94 is ??? */
  "_fsync",    /*	95 */
  "_setpriority", /*	96 */
  "_socket",   /*	97 */
  "_connect",  /*	98 */
  "_nosys",			/* 99 is old accept */
  "_getpriority", /*	100 */
  "_nosys",			/* 101 is old send */
  "_nosys",			/* 102 is old recv */
  "_nosys",			/* 103 is old sigreturn */
  "_bind",    /*	104 */
  "_setsockopt", /*	105 */
  "_listen",  /*	106 */
  "_nosys",			/* 107 is obsolete vtimes */
  "_nosys",			/* 108 is old sigvec */
  "_nosys",			/* 109 is old sigblock */
  "_nosys",			/* 110 is old sigsetmask */
  "_nosys",			/* 111 is old sigsuspend */
  "_nosys",			/* 112 is old sigstack */
  "_nosys",			/* 113 is old recvmsg */
  "_nosys",			/* 114 is old sendmsg */
  "_nosys",			/* 115 is obsolete vtrace */
  "_gettimeofday", /*	116 */ 
  "_getrusage",    /*	117 */
  "_getsockopt",   /*	118 */
  "_nosys",			/* 119 is ??? */
  "_readv",        /*	120 */
  "_writev",       /*	121 */
  "_settimeofday", /*	122 */
  "_fchown",       /*	123 */
  "_fchmod",       /*	124 */
  "_nosys",			/* 125 is old recvfrom */
  "_setreuid",     /*	126 */
  "_setregid",     /*	127 */
  "_rename",       /*	128 */
  "_nosys",			/* 129 is old truncate */
  "_nosys",			/* 130 is old ftruncate */
  "_flock",        /*	131 */
  "_mkfifo",       /*	132 */
  "_sendto",       /*	133 */
  "_shutdown",     /*	134 */
  "_socketpair",   /*	135 */
  "_mkdir",        /*	136 */
  "_rmdir",        /*	137 */
  "_utimes",       /*	138 */
  "_nosys",			/* 139 is obsolete 4.2 sigreturn */
  "_adjtime",      /*	140 */
  "_nosys",			/* 141 is old getpeername */
  "_nosys",			/* 142 is old gethostid */
  "_nosys",			/* 143 is old sethostid */
  "_nosys",			/* 144 is old getrlimit */
  "_nosys",			/* 145 is old setrlimit */
  "_nosys",			/* 146 is old killpg */
  "_setsid",       /*	147 */
  "_quotactl",     /*	148 */
  "_nosys",			/* 149 is old quota */
  "_nosys",			/* 150 is old getsockname */
  "_nosys",			/* 151 is ??? */
  "_nosys",			/* 152 is ??? */
  "_nosys",			/* 153 is ??? */
  "_nosys",			/* 154 is ??? */
  "_nfssvc",       /*	155 */
  "_nosys",		        /* 156 is old getdirentries */
  "_statfs",       /*	157 */
  "_fstatfs",      /*	158 */
  "_nosys",			/* 159 is ??? */
  "_nosys",			/* 160 is ??? */
  "_getfh",        /*	161 */
  "_getdomainname", /*	162 */
  "_setdomainname", /*	163 */
  "_uname",        /*	164 */
  "_sysarch",      /*	165 */
  "_rtprio",       /*	166 */
  "_nosys",			/* 167 is ??? */
  "_nosys",			/* 168 is ??? */
  "_semsys",       /*	169 */
  "_msgsys",       /*	170 */
  "_shmsys",       /*	171 */
  "_nosys",			/* 172 is ??? */
  "_pread",        /*	173 */
  "_pwrite",       /*	174 */
  "_nosys",			/* 175 is ??? */
  "_ntp_adjtime",  /*	176 */
  "_nosys",			/* 177 is ??? */
  "_nosys",			/* 178 is ??? */
  "_nosys",			/* 179 is ??? */
  "_nosys",			/* 180 is ??? */
  "_setgid",       /*	181 */
  "_setegid",      /*	182 */
  "_seteuid",      /*	183 */
  "_nosys",			/* 184 is ??? */
  "_nosys",			/* 185 is ??? */
  "_nosys",			/* 186 is ??? */
  "_nosys",			/* 187 is ??? */
  "_stat",         /*	188 */
  "_fstat",        /*	189 */
  "_lstat",        /*	190 */
  "_pathconf",     /*	191 */
  "_fpathconf",    /*	192 */
  "_nosys",			/* 193 is ??? */
  "_getrlimit",    /*	194 */
  "_setrlimit",    /*	195 */
  "_getdirentries", /*	196 */
  "_mmap",         /*	197 */
  "___syscall",    /*	198 */
  "_lseek",        /*	199 */
  "_truncate",     /*	200 */
  "_ftruncate",    /*	201 */
  "___sysctl",     /*	202 */
  "_mlock",        /*	203 */
  "_munlock",      /*	204 */
  "_undelete",     /*	205 */
  "_futimes",      /*	206 */
  "_getpgid",      /*	207 */
  "_nosys",			/* 208 is ??? */
  "_poll",         /*	209 */
  "_nosys",			/* 210 is ??? */
  "_nosys",			/* 211 is ??? */
  "_nosys",			/* 212 is ??? */
  "_nosys",			/* 213 is ??? */
  "_nosys",			/* 214 is ??? */
  "_nosys",			/* 215 is ??? */
  "_nosys",			/* 216 is ??? */
  "_nosys",			/* 217 is ??? */
  "_nosys",			/* 218 is ??? */
  "_nosys",			/* 219 is ??? */
  "___semctl",     /*	220 */
  "_semget",       /*	221 */
  "_semop",        /*	222 */
  "_nosys",			/* 223 is ??? */
  "_msgctl",       /*	224 */
  "_msgget",       /*	225 */
  "_msgsnd",       /*	226 */
  "_msgrcv",       /*	227 */
  "_shmat",        /*	228 */
  "_shmctl",       /*	229 */
  "_shmdt",        /*	230 */
  "_shmget",       /*	231 */
  "_clock_gettime", /*	232 */
  "_clock_settime", /*	233 */
  "_clock_getres", /*	234 */
  "_nosys",			/* 235 is ??? */
  "_nosys",			/* 236 is ??? */
  "_nosys",			/* 237 is ??? */
  "_nosys",			/* 238 is ??? */
  "_nosys",			/* 239 is ??? */
  "_nanosleep",    /*	240 */
  "_nosys",			/* 241 is ??? */
  "_nosys",			/* 242 is ??? */
  "_nosys",			/* 243 is ??? */
  "_nosys",			/* 244 is ??? */
  "_nosys",			/* 245 is ??? */
  "_nosys",			/* 246 is ??? */
  "_nosys",			/* 247 is ??? */
  "_nosys",			/* 248 is ??? */
  "_nosys",			/* 249 is ??? */
  "_minherit",     /*	250 */
  "_rfork",        /*	251 */
  "_openbsd_poll", /*	252 */
  "_issetugid",    /*	253 */
  "_lchown",       /*	254 */
  "_nosys",			/* 255 is ??? */
  "_nosys",			/* 256 is ??? */
  "_nosys",			/* 257 is ??? */
  "_nosys",			/* 258 is ??? */
  "_nosys",			/* 259 is ??? */
  "_nosys",			/* 260 is ??? */
  "_nosys",			/* 261 is ??? */
  "_nosys",			/* 262 is ??? */
  "_nosys",			/* 263 is ??? */
  "_nosys",			/* 264 is ??? */
  "_nosys",			/* 265 is ??? */
  "_nosys",			/* 266 is ??? */
  "_nosys",			/* 267 is ??? */
  "_nosys",			/* 268 is ??? */
  "_nosys",			/* 269 is ??? */
  "_nosys",			/* 270 is ??? */
  "_nosys",			/* 271 is ??? */
  "_getdents",     /*	272 */
  "_nosys",			/* 273 is ??? */
  "_lchmod",       /*	274 */
  "_netbsd_lchown", /*	275 */
  "_lutimes",      /*	276 */
  "_netbsd_msync", /*	277 */
  "_nstat",        /*	278 */
  "_nfstat",       /*	279 */
  "_nlstat",       /*	280 */
  "_nosys",			/* 281 is ??? */
  "_nosys",			/* 282 is ??? */
  "_nosys",			/* 283 is ??? */
  "_nosys",			/* 284 is ??? */
  "_nosys",			/* 285 is ??? */
  "_nosys",			/* 286 is ??? */
  "_nosys",			/* 287 is ??? */
  "_nosys",			/* 288 is ??? */
  "_nosys",			/* 289 is ??? */
  "_nosys",			/* 290 is ??? */
  "_nosys",			/* 291 is ??? */
  "_nosys",			/* 292 is ??? */
  "_nosys",			/* 293 is ??? */
  "_nosys",			/* 294 is ??? */
  "_nosys",			/* 295 is ??? */
  "_nosys",			/* 296 is ??? */
  "_fhstatfs",     /*	297 */
  "_fhopen",       /*	298 */
  "_fhstat",       /*	299 */
  "_modnext",      /*	300 */
  "_modstat",      /*	301 */
  "_modfnext",     /*	302 */
  "_modfind",      /*	303 */
  "_kldload",      /*	304 */
  "_kldunload",    /*	305 */
  "_kldfind",      /*	306 */
  "_kldnext",      /*	307 */
  "_kldstat",      /*	308 */
  "_kldfirstmod",  /*	309 */
  "_getsid",       /*	310 */
  "_setresuid",    /*	311 */
  "_setresgid",    /*	312 */
  "_nosys",			/* 313 is obsolete signanosleep */
  "_aio_return",   /*	314 */
  "_aio_suspend",  /*	315 */
  "_aio_cancel",   /*	316 */
  "_aio_error",    /*	317 */
  "_aio_read",     /*	318 */
  "_aio_write",    /*	319 */
  "_lio_listio",   /*	320 */
  "_yield",        /*	321 */
  "_thr_sleep",    /*	322 */
  "_thr_wakeup",   /*	323 */
  "_mlockall",     /*	324 */
  "_munlockall",   /*	325 */
  "___getcwd",     /*	326 */
  "_sched_setparam", /*	327 */
  "_sched_getparam", /*	328 */
  "_sched_setscheduler", /*	329 */
  "_sched_getscheduler", /*	330 */
  "_sched_yield",  /*	331 */
  "_sched_get_priority_max", /*	332 */
  "_sched_get_priority_min", /*	333 */
  "_sched_rr_get_interval", /*	334 */
  "_utrace",       /*	335 */
  "_sendfile",     /*	336 */
  "_kldsym",       /*	337 */
  "_jail",         /*	338 */
  "_nosys",			/* 339 is ??? */
  "_sigprocmask",  /*	340 */
  "_sigsuspend",   /*	341 */
  "_sigaction",    /*	342 */
  "_sigpending",   /*	343 */
  "_sigreturn",    /*	344 */
  "_nosys",			/* 345 is ??? */
  "_nosys",			/* 346 is ??? */
  "___acl_get_file", /*	347 */
  "___acl_set_file", /*	348 */
  "___acl_get_fd", /*	349 */
  "___acl_set_fd", /*	350 */
  "___acl_delete_file", /*	351 */
  "___acl_delete_fd",   /*	352 */
  "___acl_aclcheck_file", /*	353 */
  "___acl_aclcheck_fd", /*	354 */
  "_extattrctl",   /*	355 */
  "_extattr_set_file", /*	356 */
  "_extattr_get_file", /*	357 */
  "_extattr_delete_file", /*	358 */
  "_aio_waitcomplete", /*	359 */
  "_getresuid",    /*	360 */
  "_getresgid",    /*	361 */
  "_kqueue",       /*	362 */
  "_kevent",       /*	363 */
  "_nosys",			/* 364 is ??? */
  "_nosys",			/* 365 is ??? */
  "_nosys",			/* 366 is ??? */
  "_nosys",			/* 367 is ??? */
  "_nosys",			/* 368 is ??? */
  "_nosys",			/* 369 is ??? */
  "_nosys",			/* 370 is ??? */
  "_nosys",			/* 371 is ??? */
  "_nosys",			/* 372 is ??? */
  "_nosys",			/* 373 is ??? */
  "_nosys",			/* 374 is ??? */
  "_nosys",			/* 375 is ??? */
  "_nosys",			/* 376 is ??? */
  "_nosys",			/* 377 is ??? */
  "_nosys",			/* 378 is ??? */
  "_nosys",			/* 379 is ??? */
  "_nosys",			/* 380 is ??? */
  "_nosys",			/* 381 is ??? */
  "_nosys",			/* 382 is ??? */
  "_nosys",			/* 383 is ??? */
  "_nosys",			/* 384 is ??? */
  "_nosys",			/* 385 is ??? */
  "_nosys",			/* 386 is ??? */
  "_nosys",			/* 387 is ??? */
  "_nosys",			/* 388 is ??? */
  "_nosys",			/* 389 is ??? */
  "_nosys",			/* 390 is ??? */
  "_nosys",			/* 391 is ??? */
  "_nosys",			/* 392 is ??? */
  "_sendfile",	/* 393 */
  NULL
};

/* i386 sys_call_table for freebsd
 */
char * callz_fbsd5[]={
  "_syscall",  /*	 0 */
  "sys_exit",  /*	 1 */
  "_fork",     /*	 2 */
  "_read",     /*	 3 */
  "_write",    /*	 4 */
  "_open",     /*	 5 */
  "_close",    /*	 6 */
  "_wait4",    /*	 7 */
  "_nosys",			/* 8 is old creat */
  "_link",     /*	 9 */
  "_unlink",   /*	10 */
  "_nosys",			/* 11 is obsolete execv */
  "_chdir",    /*	12 */
  "_fchdir",   /*	13 */
  "_mknod",    /*	14 */
  "_chmod",    /*	15 */
  "_chown",    /*	16 */
  "_break",    /*	17 */
  "_nosys",                     /* 18 is old getfsstat */
  "_nosys",	        	/* 19 is old lseek */
  "_getpid",   /*	20 */
  "_mount",    /*	21 */
  "_unmount",  /*	22 */
  "_setuid",   /*	23 */
  "_getuid",   /*	24 */
  "_geteuid",  /*	25 */
  "_ptrace",   /*	26 */
  "_recvmsg",  /*	27 */
  "_sendmsg",  /*	28 */
  "_recvfrom", /*	29 */
  "_accept",   /*	30 */
  "_getpeername", /*	31 */
  "_getsockname", /*	32 */
  "_access",   /*	33 */
  "_chflags",  /*	34 */
  "_fchflags", /*	35 */
  "_sync",     /*	36 */
  "_kill",     /*	37 */
  "_nosys",			/* 38 is old stat */
  "_getppid",  /*	39 */
  "_nosys",		        /* 40 is old lstat */
  "_dup",      /*	41 */
  "_pipe",     /*	42 */
  "_getegid",  /*	43 */
  "_profil",   /*	44 */
  "_ktrace",   /*	45 */
  "_nosys",			/* 46 is old sigaction */
  "_getgid",   /*	47 */
  "_nosys",			/* 48 is old sigprocmask */
  "_getlogin", /*	49 */
  "_setlogin", /*	50 */
  "_acct",     /*	51 */
  "_nosys",			/* 52 is old sigpending */
  "_sigaltstack", /*	53 */
  "_ioctl",    /*	54 */
  "_reboot",   /*	55 */
  "_revoke",   /*	56 */
  "_symlink",  /*	57 */
  "_readlink", /*	58 */
  "_execve",   /*	59 */
  "_umask",    /*	60 */
  "_chroot",   /*	61 */
  "_nosys",			/* 62 is old fstat */
  "_nosys",			/* 63 is old getkerninfo */
  "_nosys",			/* 64 is old getpagesize */
  "_msync",    /*	65 */
  "_vfork",    /*	66 */
  "_nosys",			/* 67 is obsolete vread */
  "_nosys",			/* 68 is obsolete vwrite */
  "_sbrk",     /*	69 */
  "_sstk",     /*	70 */
  "_nosys",			/* 71 is old mmap */
  "_vadvise",  /*	72 */
  "_munmap",   /*	73 */
  "_mprotect", /*	74 */
  "_madvise",  /*	75 */
  "_nosys",			/* 76 is obsolete vhangup */
  "_nosys",			/* 77 is obsolete vlimit */
  "_mincore",  /*	78 */
  "_getgroups",/*	79 */
  "_setgroups",/*	80 */
  "_getpgrp",  /*	81 */
  "_setpgid",  /*	82 */
  "_setitimer",/*	83 */
  "_nosys",			/* 84 is old wait */
  "_swapon",   /*	85 */
  "_getitimer",/*	86 */
  "_nosys",			/* 87 is old gethostname */
  "_nosys",			/* 88 is old sethostname */
  "_getdtablesize", /*	89 */
  "_dup2",     /*	90 */
  "_nosys",			/* 91 is ??? */
  "_fcntl",    /*	92 */
  "_select",   /*	93 */
  "_nosys",			/* 94 is ??? */
  "_fsync",    /*	95 */
  "_setpriority", /*	96 */
  "_socket",   /*	97 */
  "_connect",  /*	98 */
  "_nosys",			/* 99 is old accept */
  "_getpriority", /*	100 */
  "_nosys",			/* 101 is old send */
  "_nosys",			/* 102 is old recv */
  "_nosys",			/* 103 is old sigreturn */
  "_bind",    /*	104 */
  "_setsockopt", /*	105 */
  "_listen",  /*	106 */
  "_nosys",			/* 107 is obsolete vtimes */
  "_nosys",			/* 108 is old sigvec */
  "_nosys",			/* 109 is old sigblock */
  "_nosys",			/* 110 is old sigsetmask */
  "_nosys",			/* 111 is old sigsuspend */
  "_nosys",			/* 112 is old sigstack */
  "_nosys",			/* 113 is old recvmsg */
  "_nosys",			/* 114 is old sendmsg */
  "_nosys",			/* 115 is obsolete vtrace */
  "_gettimeofday", /*	116 */ 
  "_getrusage",    /*	117 */
  "_getsockopt",   /*	118 */
  "_nosys",			/* 119 is ??? */
  "_readv",        /*	120 */
  "_writev",       /*	121 */
  "_settimeofday", /*	122 */
  "_fchown",       /*	123 */
  "_fchmod",       /*	124 */
  "_nosys",			/* 125 is old recvfrom */
  "_setreuid",     /*	126 */
  "_setregid",     /*	127 */
  "_rename",       /*	128 */
  "_nosys",			/* 129 is old truncate */
  "_nosys",			/* 130 is old ftruncate */
  "_flock",        /*	131 */
  "_mkfifo",       /*	132 */
  "_sendto",       /*	133 */
  "_shutdown",     /*	134 */
  "_socketpair",   /*	135 */
  "_mkdir",        /*	136 */
  "_rmdir",        /*	137 */
  "_utimes",       /*	138 */
  "_nosys",			/* 139 is obsolete 4.2 sigreturn */
  "_adjtime",      /*	140 */
  "_nosys",			/* 141 is old getpeername */
  "_nosys",			/* 142 is old gethostid */
  "_nosys",			/* 143 is old sethostid */
  "_nosys",			/* 144 is old getrlimit */
  "_nosys",			/* 145 is old setrlimit */
  "_nosys",			/* 146 is old killpg */
  "_setsid",       /*	147 */
  "_quotactl",     /*	148 */
  "_nosys",			/* 149 is old quota */
  "_nosys",			/* 150 is old getsockname */
  "_nosys",			/* 151 is ??? */
  "_nosys",			/* 152 is ??? */
  "_nosys",			/* 153 is ??? */
  "_nosys",			/* 154 is ??? */
  "_nfssvc",       /*	155 */
  "_nosys",		        /* 156 is old getdirentries */
  "_nosys",                     /* 157 is old statfs */
  "_nosys",                     /* 158 is old fstatfs */
  "_nosys",			/* 159 is ??? */
  "_lgetfh",       /*   160 */
  "_getfh",        /*	161 */
  "_getdomainname", /*	162 */
  "_setdomainname", /*	163 */
  "_uname",        /*	164 */
  "_sysarch",      /*	165 */
  "_rtprio",       /*	166 */
  "_nosys",			/* 167 is ??? */
  "_nosys",			/* 168 is ??? */
  "_semsys",       /*	169 */
  "_msgsys",       /*	170 */
  "_shmsys",       /*	171 */
  "_nosys",			/* 172 is ??? */
  "_pread",        /*	173 */
  "_pwrite",       /*	174 */
  "_nosys",			/* 175 is ??? */
  "_ntp_adjtime",  /*	176 */
  "_nosys",			/* 177 is ??? */
  "_nosys",			/* 178 is ??? */
  "_nosys",			/* 179 is ??? */
  "_nosys",			/* 180 is ??? */
  "_setgid",       /*	181 */
  "_setegid",      /*	182 */
  "_seteuid",      /*	183 */
  "_nosys",			/* 184 is ??? */
  "_nosys",			/* 185 is ??? */
  "_nosys",			/* 186 is ??? */
  "_nosys",			/* 187 is ??? */
  "_stat",         /*	188 */
  "_fstat",        /*	189 */
  "_lstat",        /*	190 */
  "_pathconf",     /*	191 */
  "_fpathconf",    /*	192 */
  "_nosys",			/* 193 is ??? */
  "_getrlimit",    /*	194 */
  "_setrlimit",    /*	195 */
  "_getdirentries", /*	196 */
  "_mmap",         /*	197 */
  "___syscall",    /*	198 */
  "_lseek",        /*	199 */
  "_truncate",     /*	200 */
  "_ftruncate",    /*	201 */
  "___sysctl",     /*	202 */
  "_mlock",        /*	203 */
  "_munlock",      /*	204 */
  "_undelete",     /*	205 */
  "_futimes",      /*	206 */
  "_getpgid",      /*	207 */
  "_nosys",			/* 208 is ??? */
  "_poll",         /*	209 */
  "_nosys",			/* 210 is ??? */
  "_nosys",			/* 211 is ??? */
  "_nosys",			/* 212 is ??? */
  "_nosys",			/* 213 is ??? */
  "_nosys",			/* 214 is ??? */
  "_nosys",			/* 215 is ??? */
  "_nosys",			/* 216 is ??? */
  "_nosys",			/* 217 is ??? */
  "_nosys",			/* 218 is ??? */
  "_nosys",			/* 219 is ??? */
  "___semctl",     /*	220 */
  "_semget",       /*	221 */
  "_semop",        /*	222 */
  "_nosys",			/* 223 is ??? */
  "_msgctl",       /*	224 */
  "_msgget",       /*	225 */
  "_msgsnd",       /*	226 */
  "_msgrcv",       /*	227 */
  "_shmat",        /*	228 */
  "_shmctl",       /*	229 */
  "_shmdt",        /*	230 */
  "_shmget",       /*	231 */
  "_clock_gettime", /*	232 */
  "_clock_settime", /*	233 */
  "_clock_getres", /*	234 */
  "_nosys",			/* 235 is ??? */
  "_nosys",			/* 236 is ??? */
  "_nosys",			/* 237 is ??? */
  "_nosys",			/* 238 is ??? */
  "_nosys",			/* 239 is ??? */
  "_nanosleep",    /*	240 */
  "_nosys",			/* 241 is ??? */
  "_nosys",			/* 242 is ??? */
  "_nosys",			/* 243 is ??? */
  "_nosys",			/* 244 is ??? */
  "_nosys",			/* 245 is ??? */
  "_nosys",			/* 246 is ??? */
  "_nosys",			/* 247 is ??? */
  "_nosys",			/* 248 is ??? */
  "_nosys",			/* 249 is ??? */
  "_minherit",     /*	250 */
  "_rfork",        /*	251 */
  "_openbsd_poll", /*	252 */
  "_issetugid",    /*	253 */
  "_lchown",       /*	254 */
  "_nosys",			/* 255 is ??? */
  "_nosys",			/* 256 is ??? */
  "_nosys",			/* 257 is ??? */
  "_nosys",			/* 258 is ??? */
  "_nosys",			/* 259 is ??? */
  "_nosys",			/* 260 is ??? */
  "_nosys",			/* 261 is ??? */
  "_nosys",			/* 262 is ??? */
  "_nosys",			/* 263 is ??? */
  "_nosys",			/* 264 is ??? */
  "_nosys",			/* 265 is ??? */
  "_nosys",			/* 266 is ??? */
  "_nosys",			/* 267 is ??? */
  "_nosys",			/* 268 is ??? */
  "_nosys",			/* 269 is ??? */
  "_nosys",			/* 270 is ??? */
  "_nosys",			/* 271 is ??? */
  "_getdents",     /*	272 */
  "_nosys",			/* 273 is ??? */
  "_lchmod",       /*	274 */
  "_netbsd_lchown", /*	275 */
  "_lutimes",      /*	276 */
  "_netbsd_msync", /*	277 */
  "_nstat",        /*	278 */
  "_nfstat",       /*	279 */
  "_nlstat",       /*	280 */
  "_nosys",			/* 281 is ??? */
  "_nosys",			/* 282 is ??? */
  "_nosys",			/* 283 is ??? */
  "_nosys",			/* 284 is ??? */
  "_nosys",			/* 285 is ??? */
  "_nosys",			/* 286 is ??? */
  "_nosys",			/* 287 is ??? */
  "_nosys",			/* 288 is ??? */
  "_nosys",			/* 289 is ??? */
  "_nosys",			/* 290 is ??? */
  "_nosys",			/* 291 is ??? */
  "_nosys",			/* 292 is ??? */
  "_nosys",			/* 293 is ??? */
  "_nosys",			/* 294 is ??? */
  "_nosys",			/* 295 is ??? */
  "_nosys",			/* 296 is ??? */
  "_nosys",                     /* 297 is old fhstatfs */
  "_fhopen",       /*	298 */
  "_fhstat",       /*	299 */
  "_modnext",      /*	300 */
  "_modstat",      /*	301 */
  "_modfnext",     /*	302 */
  "_modfind",      /*	303 */
  "_kldload",      /*	304 */
  "_kldunload",    /*	305 */
  "_kldfind",      /*	306 */
  "_kldnext",      /*	307 */
  "_kldstat",      /*	308 */
  "_kldfirstmod",  /*	309 */
  "_getsid",       /*	310 */
  "_setresuid",    /*	311 */
  "_setresgid",    /*	312 */
  "_nosys",			/* 313 is obsolete signanosleep */
  "_aio_return",   /*	314 */
  "_aio_suspend",  /*	315 */
  "_aio_cancel",   /*	316 */
  "_aio_error",    /*	317 */
  "_aio_read",     /*	318 */
  "_aio_write",    /*	319 */
  "_lio_listio",   /*	320 */
  "_yield",        /*	321 */
  "_thr_sleep",    /*	322 */
  "_thr_wakeup",   /*	323 */
  "_mlockall",     /*	324 */
  "_munlockall",   /*	325 */
  "___getcwd",     /*	326 */
  "_sched_setparam", /*	327 */
  "_sched_getparam", /*	328 */
  "_sched_setscheduler", /*	329 */
  "_sched_getscheduler", /*	330 */
  "_sched_yield",  /*	331 */
  "_sched_get_priority_max", /*	332 */
  "_sched_get_priority_min", /*	333 */
  "_sched_rr_get_interval", /*	334 */
  "_utrace",       /*	335 */
  "_nosys",                  /* 336 is old sendfile */
  "_kldsym",       /*	337 */
  "_jail",         /*	338 */
  "_nosys",			/* 339 is ??? */
  "_sigprocmask",  /*	340 */
  "_sigsuspend",   /*	341 */
  "_nosys",                     /* 342 is old sigaction */
  "_sigpending",   /*	343 */
  "_nosys",                     /* 344 is old sigreturn */
  "_sigtimedwait", /*   345 */
  "_sigwaitinfo",  /*   346 */
  "___acl_get_file", /*	347 */
  "___acl_set_file", /*	348 */
  "___acl_get_fd", /*	349 */
  "___acl_set_fd", /*	350 */
  "___acl_delete_file", /*	351 */
  "___acl_delete_fd",   /*	352 */
  "___acl_aclcheck_file", /*	353 */
  "___acl_aclcheck_fd", /*	354 */
  "_extattrctl",   /*	355 */
  "_extattr_set_file", /*	356 */
  "_extattr_get_file", /*	357 */
  "_extattr_delete_file", /*	358 */
  "_aio_waitcomplete", /*	359 */
  "_getresuid",    /*	360 */
  "_getresgid",    /*	361 */
  "_kqueue",       /*	362 */
  "_kevent",       /*	363 */
  "_nosys",			/* 364 is ??? */
  "_nosys",			/* 365 is ??? */
  "_nosys",			/* 366 is ??? */
  "_nosys",			/* 367 is ??? */
  "_nosys",			/* 368 is ??? */
  "_nosys",			/* 369 is ??? */
  "_nosys",			/* 370 is ??? */
  "_extattr_set_fd",            /* 371 */
  "_extattr_get_fd",            /* 372 */
  "_extattr_delete_fd",         /* 373 */
  "___setugid",                 /* 374 */
  "_nfsclnt",                   /* 375 */
  "_eaccess",                   /* 376 */
  "_nosys",			/* 377 is ??? */
  "_nmount",                    /* 378 */
  "_kse_exit",                  /* 379 */
  "_kse_wakeup",                /* 380 */
  "_kse_create",                /* 381 */
  "_kse_thr_interrupt",         /* 382 */
  "_kse_release",               /* 383 */
  "___mac_get_proc",            /* 384 */
  "___mac_set_proc",            /* 385 */
  "___mac_get_fd",              /* 386 */
  "___mac_get_file",            /* 387 */
  "___mac_set_fd",              /* 388 */
  "___mac_set_file",            /* 389 */
  "_kenv",			/* 390 */
  "_lchflags",                  /* 391 */
  "_uuidgen",                   /* 392 */
  "_sendfile",	  /* 393 */
  "_mac_syscall",	  /* 394 */
  "_getfsstat",	  /* 395 */
  "_statfs",	  /* 396 */
  "_fstatfs",	  /* 397 */
  "_fhstatfs",	  /* 398 */
  "_nosys",	  /* 399 */
  "_ksem_close",  /* 400 */
  "_ksem_post",	  /* 401 */
  "_ksem_wait",	  /* 402 */
  "_ksem_trywait",	  /* 403 */
  "_ksem_init",	  /* 404 */
  "_ksem_open",	  /* 405 */
  "_ksem_unlink",	  /* 406 */
  "_ksem_getvalue",	  /* 407 */
  "_ksem_destroy",	  /* 408 */
  "___mac_get_pid",	  /* 409 */
  "___mac_get_link",	  /* 410 */
  "___mac_set_link",	  /* 411 */
  "_extattr_set_link",	  /* 412 */
  "_extattr_get_link",	  /* 413 */
  "_extattr_delete_link",	  /* 414 */
  "___mac_execve",	  /* 415 */
  "_sigaction",	  /* 416 */
  "_sigreturn",	  /* 417 */
  "_nosys",	  /* 418 */
  "_nosys",	  /* 419 */
  "_nosys",	  /* 420 */
  "_getcontext",	  /* 421 */
  "_setcontext",	  /* 422 */
  "_swapcontext",	  /* 423 */
  "_swapoff",	  /* 424 */
  "___acl_get_link",	  /* 425 */
  "___acl_set_link",	  /* 426 */
  "___acl_delete_link",	  /* 427 */
  "___acl_aclcheck_link",	  /* 428 */
  "_sigwait",	  /* 429 */
  "_thr_create",	  /* 430 */
  "_thr_exit",	  /* 431 */
  "_thr_self",	  /* 432 */
  "_thr_kill",	  /* 433 */
  "__umtx_lock",	  /* 434 */
  "__umtx_unlock",	  /* 435 */
  "_jail_attach",	  /* 436 */
  "_extattr_list_fd",	  /* 437 */
  "_extattr_list_file",	  /* 438 */
  "_extattr_list_link",	  /* 439 */
  "_kse_switchin",        /* 440 */
  "_ksem_timedwait",      /* 441 */
  "_thr_suspend",         /* 442 */
  "_thr_wake",            /* 443 */
  "_kldunloadf",          /* 444 */
  NULL
};

