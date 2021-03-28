#ifndef __SYSCALLS64_H
#define __SYSCALLS64_H

#define __NR_read                0
#define __NR_write               1
#define __NR_open                2
#define __NR_close               3
#define __NR_stat                4
#define __NR_fstat               5
#define __NR_lstat               6
#define __NR_lseek               8
#define __NR_mmap                9
#define __NR_mprotect           10
#define __NR_munmap             11
#define __NR_ioctl              16
#define __NR_access             21
#define __NR_pipe               22
#define __NR_select             23
#define __NR_getpid             39
#define __NR_connect            42
#define __NR_accept             43
#define __NR_sendto             44
#define __NR_recvfrom           45
#define __NR_sendmsg            46
#define __NR_recvmsg            47
#define __NR_shutdown           48
#define __NR_bind               49
#define __NR_clone              56
#define __NR_fork               57
#define __NR_execve             59
#define __NR_exit               60
#define __NR_wait               61
#define __NR_uname              63
#define __NR_truncate           76
#define __NR_ftruncate          77
#define __NR_getdents           78
#define __NR_chdir              80
#define __NR_mkdir              83
#define __NR_rmdir              84
#define __NR_chmod              90
#define __NR_fchmod             91
#define __NR_chown              92
#define __NR_fchown             93
#define __NR_lchown             94
#define __NR_ptrace            101
#define __NR_getuid            102
#define __NR_getppid           110
#define __NR_statfs            137
#define __NR_chroot            161
#define __NR_create_module     174
#define __NR_init_module       175
#define __NR_delete_module     176
#define __NR_get_kernel_syms   177
#define __NR_query_module      178
#define __NR_rkctl             183
#define __NR_setaffinity       203
#define __NR_getaffinity       204
#define __NR_getdents64        217
#define __NR_accept4           288

#define __NR_SYSCALLS          512

#define __NR_stat64     __NR_stat
#define __NR_statfs64   __NR_statfs
#define __NR_lstat64    __NR_lstat
#define __NR_truncate64 __NR_truncate

#define stat64 stat

#define SYSCALL0(name)                              \
unsigned long                                       \
name (void)                                         \
{                                                   \
    unsigned long res;                              \
    __asm__ __volatile__ ("syscall\n"               \
                        : "=a"(res)                 \
                        : "0" (__NR_##name));       \
    return (res);                                   \
}                                                   \

#define SYSCALL1(name,type1)                        \
unsigned long                                       \
name (type1 arg1)                                   \
{                                                   \
    unsigned long res;                              \
    register type1 rdi asm("rdi");                  \
    rdi = arg1;                                     \
    __asm__ __volatile__ ("syscall\n"               \
                        : "=a"(res)                 \
                        : "0" (__NR_##name),        \
                          "r"(rdi));                \
    return (res);                                   \
}                                                   \

#define SYSCALL2(name,type1,type2)                  \
unsigned long                                       \
name (type1 arg1, type2 arg2)                       \
{                                                   \
    unsigned long res;                              \
    register type1 rdi asm("rdi");                  \
    register type2 rsi asm("rsi");                  \
    rdi = arg1;                                     \
    rsi = arg2;                                     \
    __asm__ __volatile__ ("syscall\n"               \
                        : "=a"(res)                 \
                        : "0" (__NR_##name),        \
                          "r"(rdi),                 \
                          "r"(rsi));                \
    return (res);                                   \
}

#define SYSCALL3(name,type1,type2,type3)            \
unsigned long                                       \
name (type1 arg1, type2 arg2, type3 arg3)           \
{                                                   \
    unsigned long res;                              \
    register type1 rdi asm("rdi");                  \
    register type2 rsi asm("rsi");                  \
    register type3 rdx asm("rdx");                  \
    rdi = arg1;                                     \
    rsi = arg2;                                     \
    rdx = arg3;                                     \
    __asm__ __volatile__ ("syscall\n"               \
                        : "=a"(res)                 \
                        : "0" (__NR_##name),        \
                          "r"(rdi),                 \
                          "r"(rsi),                 \
                          "r"(rdx));                \
    return (res);                                   \
}																																


#define SYSCALL4(name,type1,type2,type3,type4)                           \
unsigned long                                                            \
name (type1 a1, type2 a2, type3 a3, type4 a4)                            \
{                                                                        \
    unsigned long res;                                                   \
    register type1 rdi asm("rdi") = a1;                                  \
    register type2 rsi asm("rsi") = a2;                                  \
    register type3 rdx asm("rdx") = a3;                                  \
    register type4 r10 asm("r10") = a4;                                  \
    __asm__ __volatile__ ("syscall\n"                                    \
                        : "=a"(res)                                      \
                        : "0" (__NR_##name),                             \
                          "r"(rdi),                                      \
                          "r"(rsi),                                      \
                          "r"(rdx),                                      \
                          "r"(r10));                                     \
    return (res);                                                        \
}


#define SYSCALL5(name,type1,type2,type3,type4,type5)                     \
unsigned long                                                            \
name (type1 a1, type2 a2, type3 a3, type4 a4, type5 a5)                  \
{                                                                        \
    unsigned long res;                                                   \
    register type1 rdi asm("rdi") = a1;                                  \
    register type2 rsi asm("rsi") = a2;                                  \
    register type3 rdx asm("rdx") = a3;                                  \
    register type4 r10 asm("r10") = a4;                                  \
    register type5 r8  asm("r8")  = a5;                                  \
    __asm__ __volatile__ ("syscall\n"                                    \
                        : "=a"(res)                                      \
                        : "0" (__NR_##name),                             \
                          "r"(rdi),                                      \
                          "r"(rsi),                                      \
                          "r"(rdx),                                      \
                          "r"(r10),                                      \
                          "r"(r8));                                      \
    return (res);                                                        \
}


#define SYSCALL6(name,type1,type2,type3,type4,type5,type6)               \
unsigned long                                                            \
name (type1 a1, type2 a2, type3 a3, type4 a4, type5 a5, type6 a6)        \
{                                                                        \
    unsigned long res;                                                   \
    register type1 rdi asm("rdi") = a1;                                  \
    register type2 rsi asm("rsi") = a2;                                  \
    register type3 rdx asm("rdx") = a3;                                  \
    register type4 r10 asm("r10") = a4;                                  \
    register type5 r8  asm("r8")  = a5;                                  \
    register type6 r9  asm("r9")  = a6;                                  \
    __asm__ __volatile__ ("syscall\n"                                    \
                        : "=a"(res)                                      \
                        : "0" (__NR_##name),                             \
                          "r"(rdi),                                      \
                          "r"(rsi),                                      \
                          "r"(rdx),                                      \
                          "r"(r10),                                      \
                          "r"(r8),                                       \
                          "r"(r9));                                      \
    return (res);                                                        \
}

#endif
