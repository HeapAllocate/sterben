#ifndef __MIPS_H
#define __MIPS_H

#define WORDSIZE   32
#define FHOOKSZ    16

#define RKJMP(jmp, addr) \
({ \
        *(unsigned short *)(jmp+2) = (unsigned short)(addr>>16); \
	*(unsigned short *)(jmp+6) = (unsigned short)(addr&0x0000ffff); \
})

#define SCTJMP RKJMP

#define __NR_BASE              4000
#define __NR_SYSCALLS          512*2
#define SYSCALL(name, args...) ((int(*)())osctmap[__NR_##name])(args)
#define REGPARM(x)

#define KERNEL_DS  0
#define TIOCGPGRP  0x40047477

#if   defined __MIPS32__
#define NARGS 2
#elif defined __MIPS64__
#define NARGS 1
#endif

#define __NR_exit              (1*NARGS)
#define __NR_fork              (2*NARGS)
#define __NR_read              (3*NARGS)
#define __NR_write             (4*NARGS)
#define __NR_open              (5*NARGS)
#define __NR_close             (6*NARGS)
#define __NR_waitpid           (7*NARGS)
#define __NR_unlink            (10*NARGS)
#define __NR_execve            (11*NARGS)
#define __NR_chdir             (12*NARGS)
#define __NR_lseek             (19*NARGS)
#define __NR_getpid            (20*NARGS)
#define __NR_setuid            (23*NARGS)
#define __NR_getuid            (24*NARGS)
#define __NR_ptrace            (26*NARGS)
#define __NR_alarm             (27*NARGS)
#define __NR_access            (33*NARGS)
#define __NR_ioctl             (54*NARGS)
#define __NR_chroot            (60*NARGS)
#define __NR_getppid           (64*NARGS)
#define __NR_mmap              (90*NARGS)
#define __NR_munmap            (91*NARGS)
#define __NR_truncate          (92*NARGS)
#define __NR_statfs            (99*NARGS)
#define __NR_stat              (106*NARGS)
#define __NR_lstat             (107*NARGS)
#define __NR_fstat             (108*NARGS)
#define __NR_uname             (122*NARGS)
#define __NR_mprotect          (125*NARGS)
#define __NR_create_module     (127*NARGS)
#define __NR_init_module       (128*NARGS)
#define __NR_delete_module     (129*NARGS)
#define __NR_get_kernel_syms   (130*NARGS)
#define __NR_getdents          (141*NARGS)
#define __NR_rkctl             (150*NARGS)
#define __NR_query_module      (187*NARGS)
#define __NR_truncate64        (211*NARGS)
#define __NR_stat64            (213*NARGS)
#define __NR_lstat64           (214*NARGS)
#define __NR_fstat64           (215*NARGS)
#define __NR_getdents64        (219*NARGS)
#define __NR_setaffinity       (239*NARGS)
#define __NR_getaffinity       (240*NARGS)
#define __NR_statfs64          (255*NARGS)


#define SYSCALL0(name)	                                    \
long                                                        \
name(void)                                                  \
{                                                           \
    unsigned long res;                                      \
    register long v0 asm ("$2");                            \
    register long s0 asm ("$16") = __NR_##name;             \
    __asm__ volatile (                                      \
    ".set noreorder\n"                                      \
    "move %0, %1\n"                                         \
    "srl %0, %0, 1\n"                                       \
    "addiu %0, %0, %2\n"                                    \
    "syscall\n"                                             \
    ".set reorder"                                          \
    : "=r" (v0)                                             \
    : "r" (s0), "i" (__NR_BASE));                           \
    res = v0;                                               \
    return (res);                                           \
}

#define SYSCALL1(name, type1)                               \
long                                                        \
name(type1 arg1)                                            \
{                                                           \
    unsigned long  res;                                     \
    register long  v0 asm ("$2");                           \
    register type1 a0 asm ("$4")  = arg1;                   \
    register long  s0 asm ("$16") = __NR_##name;            \
    __asm__ volatile (                                      \
    ".set noreorder\n"                                      \
    "move %0, %1\n"                                         \
    "srl %0, %0, 1\n"                                       \
    "addiu %0, %0, %2\n"                                    \
    "syscall\n"                                             \
    ".set reorder"                                          \
    : "=r"(v0)                                              \
    : "r" (s0), "i" (__NR_BASE), "r" (a0));                 \
    res = v0;                                               \
    return (res);                                           \
}

#define SYSCALL2(name, type1, type2)                        \
long                                                        \
name(type1 arg1, type2 arg2)                                \
{                                                           \
    unsigned long  res;                                     \
    register long  v0 asm ("$2");                           \
    register type1 a0 asm ("$4")  = arg1;                   \
    register type2 a1 asm ("$5")  = arg2;                   \
    register long  s0 asm ("$16") = __NR_##name;            \
    __asm__ volatile (                                      \
    ".set noreorder\n"                                      \
    "move %0, %1\n"                                         \
    "srl %0, %0, 1\n"                                       \
    "addiu %0, %0, %2\n"                                    \
    "syscall\n"                                             \
    ".set reorder"                                          \
    : "=r"(v0)                                              \
    : "r" (s0), "i" (__NR_BASE), "r" (a0), "r" (a1));       \
    res = v0;                                               \
    return (res);                                           \
}

#define SYSCALL3(name, type1, type2, type3)                 \
long                                                        \
name(type1 arg1, type2 arg2, type3 arg3)                    \
{                                                           \
    unsigned long  res;                                     \
    register long  v0 asm ("$2");                           \
    register type1 a0 asm ("$4")  = arg1;                   \
    register type2 a1 asm ("$5")  = arg2;                   \
    register type3 a2 asm ("$6")  = arg3;                   \
    register long  s0 asm ("$16") = __NR_##name;            \
    __asm__ volatile (                                      \
    ".set noreorder\n"                                      \
    ".set noat\n"                                           \
    "move %0, %1\n"                                         \
    "srl %0, %0, 1\n"                                       \
    "addiu %0, %0, %2\n"                                    \
    "syscall\n\t"                                           \
    "bnez $a3, 1f\n"                                        \
    "nop\n"                                                 \
    "j 2f\n"                                                \
    "nop\n"                                                 \
    "1:\n"                                                  \
    "li $v0, -1\n"                                          \
    "2:\n"                                                  \
    ".set reorder\n"                                        \
    ".set at\n"                                             \
    : "=r"(v0)                                              \
    : "r" (s0), "i" (__NR_BASE),                            \
      "r" (a0), "r" (a1), "r" (a2));                        \
    res = v0;                                               \
    return (res);                                           \
}

#define SYSCALL4(name, type1, type2, type3)                 \
long                                                        \
name(type1 arg1, type2 arg2, type3 arg3)                    \
{                                                           \
    unsigned long  res;                                     \
    register long  v0 asm ("$2");                           \
    register type1 a0 asm ("$4")  = arg1;                   \
    register type2 a1 asm ("$5")  = arg2;                   \
    register type3 a2 asm ("$6")  = arg3;                   \
    register type4 a3 asm ("$7")  = arg4;                   \
    register long  s0 asm ("$16") = __NR_##name;            \
    __asm__ volatile (                                      \
    ".set noreorder\n"                                      \
    "move %0, %1\n"                                         \
    "srl %0, %0, 1\n"                                       \
    "addiu %0, %0, %2\n"                                    \
    "syscall\n\t"                                           \
    ".set reorder"                                          \
    : "=r"(v0)                                              \
    : "r" (s0), "i" (__NR_BASE),                            \
      "r" (a0), "r" (a1), "r" (a2), "r" (a3));              \
    res = v0;                                               \
    return (res);                                           \
}

#define SYSCALL5(name, t1, t2, t3, t4, t5)                  \
long                                                        \
name(t1 arg1, t2 arg2, t3 arg3, t4 arg4, t5 arg5)           \
{                                                           \
    unsigned long  res;                                     \
    register long  v0 asm ("$2");                           \
    register t1 a0    asm ("$4")  = arg1;                   \
    register t2 a1    asm ("$5")  = arg2;                   \
    register t3 a2    asm ("$6")  = arg3;                   \
    register t4 a3    asm ("$7")  = arg4;                   \
    register long  s0 asm ("$16") = __NR_##name;            \
    __asm__ volatile (                                      \
    ".set noreorder\n"                                      \
    "sw %6, 16($29)\n"                                      \
    "move %0, %1\n"                                         \
    "srl %0, %0, 1\n"                                       \
    "addiu %0, %0, %2\n"                                    \
    "syscall\n\t"                                           \
    ".set reorder"                                          \
    : "=r"(v0)                                              \
    : "r" (s0), "i" (__NR_BASE),                            \
      "r" (a0), "r" (a1), "r" (a2), "r" (a3), "r" (arg5));  \
    res = v0;                                               \
    return (res);                                           \
}

#define SYSCALL6(name, t1, t2, t3, t4, t5, t6)              \
long                                                        \
name(t1 arg1, t2 arg2, t3 arg3, t4 arg4, t5 arg5, t6 arg6)  \
{                                                           \
    unsigned long  res;                                     \
    register long  v0 asm ("$2");                           \
    register t1 a0    asm ("$4")  = arg1;                   \
    register t2 a1    asm ("$5")  = arg2;                   \
    register t3 a2    asm ("$6")  = arg3;                   \
    register t4 a3    asm ("$7")  = arg4;                   \
    register long  s0 asm ("$16") = __NR_##name;            \
    __asm__ volatile (                                      \
    ".set noreorder\n"                                      \
    "sw %6, 16($29)\n"                                      \
    "sw %7, 20($29)\n"                                      \
    "move %0, %1\n"                                         \
    "srl %0, %0, 1\n"                                       \
    "addiu %0, %0, %2\n"                                    \
    "syscall\n\t"                                           \
    ".set reorder"                                          \
    : "=r"(v0)                                              \
    : "r" (s0),"i"(__NR_BASE),                              \
      "r" (a0),"r"(a1),"r"(a2),"r"(a3),"r"(arg5),"r"(arg6));\
    res = v0;                                               \
    return (res);                                           \
}

extern long open(char *, int, int);
extern long close(int);
extern long exit(int);
extern long uname(void *);
extern long read(int, void *, unsigned long);
extern long write(int, void *, unsigned long);
extern long lseek(int, unsigned long, int);
extern long mmap(void *, unsigned long, int, int, int, unsigned long);

/*
        "mfc0    \\result, $12         \n"
        "ori     $1, \\result, 0x1f    \n"
        "xori    $1, 0x1f              \n"
        ".set    noreorder             \n"
        "mtc0    $1, $12               \n"
*/

#define task_thread_info(task)  ((struct thread_info *)(task)->stack)
#define current_thread_info() task_thread_info((struct task_struct *)current())

struct thread_info {
	void           *task;
	void           *exec_domain;
	unsigned long   flags;
	unsigned long   tp_value;
	unsigned int    cpu;
	int             preempt_count;
	unsigned long   addr_limit;
};

struct pt_regs {
    unsigned long pad0[6];
    unsigned long regs[32];
    unsigned long cp0_status;
    unsigned long hi,lo;
    unsigned long cp0_badvaddr;
    unsigned long cp0_cause;
    unsigned long cp0_epc;
}__attribute__((aligned(8)));

struct stat {
	unsigned        st_dev;
	long            st_pad1[3];
	unsigned int    st_ino;
	unsigned int    st_mode;
	unsigned int    st_nlink;
	unsigned int    st_uid;
	unsigned int    st_gid;
	unsigned        st_rdev;
	long            st_pad2[2];
	long            st_size;
	long            st_pad3;
	long            st_atime;
	long            st_atime_nsec;
	long            st_mtime;
	long            st_mtime_nsec;
	long            st_ctime;
	long            st_ctime_nsec;
	long            st_blksize;
	long            st_blocks;
	long            st_pad4[14];
};

#endif
