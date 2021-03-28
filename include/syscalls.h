#ifndef __SYSCALLS_H
#define __SYSCALLS_H

#define __NR_exit                1
#define __NR_fork                2
#define __NR_read                3
#define __NR_write               4
#define __NR_open                5
#define __NR_close               6
#define __NR_oldstat            18
#define __NR_lseek              19
#define __NR_getpid             20
#define __NR_ptrace             26
#define __NR_oldfstat           28
#define __NR_access             33
#define __NR_ioctl              54
#define __NR_setpgid            57
#define __NR_rkctl              59
#define __NR_getppid            64
#define __NR_oldlstat           84
#define __NR_mmap              192
#define __NR_truncate           92
#define __NR_statfs             99
#define __NR_fstatfs           100
#define __NR_stat              106
#define __NR_lstat             107
#define __NR_fstat             108
#define __NR_wait              114
#define __NR_clone             120
#define __NR_uname             122
#define __NR_init_module       128
#define __NR_getdents          141
#define __NR_rt_sigqueueinfo   178
#define __NR_truncate64        193
#define __NR_stat64            195
#define __NR_lstat64           196
#define __NR_fstat64           197
#define __NR_getdents64        220
#define __NR_getaffinity       242
#define __NR_statfs64          268
#define __NR_fstatfs64         269
#define __NR_fstatat64         300
#define __NR_rt_tgsigqueueinfo 335

#define __NR_SYSCALLS          512

#define SYSCALL0(name)                                    \
unsigned long                                             \
name (void)                                               \
{                                                         \
    int res;                                              \
    __asm__ __volatile__ (                                \
          "int $0x80\n"                                   \
        : "=a" (res)                                      \
        : "0" (__NR_##name));                             \
    return (res);                                         \
}

#define SYSCALL1(name, type1)                             \
unsigned long                                             \
name (type1 arg1)					                      \
{							                              \
	int res;					                          \
	__asm__ __volatile__ (				                  \
		"int $0x80\n"				                      \
		: "=a" (res)				                      \
		: "0" (__NR_##name), "b" (arg1));	              \
	return (res);					                      \
}

#define SYSCALL2(name, type1, type2)                      \
unsigned long                                             \
name (type1 arg1, type2 arg2)                             \
{                                                         \
	int res;                                              \
	__asm__ __volatile__ (                                \
		"int $0x80\n"                                     \
		: "=a" (res)                                      \
		: "0" (__NR_##name), "b" (arg1), "c" (arg2));     \
	return (res);                                         \
}

#define SYSCALL3(name, type1, type2, type3)               \
unsigned long                                             \
name (type1 arg1, type2 arg2, type3 arg3)                 \
{                                                         \
	int res;                                              \
	__asm__ __volatile__ (                                \
		"int $0x80\n"                                     \
		: "=a" (res)                                      \
		: "0" (__NR_##name),                              \
          "b" (arg1), "c" (arg2), "d" (arg3));            \
	return (res);                                         \
}

#define SYSCALL4(name, type1, type2, type3, type4)        \
unsigned long                                             \
name (type1 arg1, type2 arg2, type3 arg3, type4 arg4)     \
{                                                         \
	int res;                                              \
	__asm__ __volatile__ (                                \
		"int $0x80\n"                                     \
		: "=a" (res)                                      \
		: "0" (__NR_##name), "b" (arg1),                  \
          "c" (arg2), "d" (arg3), "S" (arg4));            \
	return (res);                                         \
}

#define SYSCALL5(name, type1, type2, type3, type4, type5)                         \
unsigned long                                                                     \
name (type1 arg1, type2 arg2, type3 arg3, type4 arg4, type5 arg5)                 \
{                                                                                 \
	int res;                                                                      \
	__asm__ __volatile__ (                                                        \
		"int $0x80\n"                                                             \
		: "=a" (res)                                                              \
		: "0" (__NR_##name), "b" (arg1), "c" (arg2),                              \
          "d" (arg3), "S" (arg4), "D" (arg5));                                    \
	return (res);                                                                 \
}

#define SYSCALL6(name, type1, type2, type3, type4, type5, type6)                  \
unsigned long                                                                     \
name (type1 arg1, type2 arg2, type3 arg3, type4 arg4, type5 arg5, type6 arg6)     \
{                                                                                 \
	int res;                                                                      \
	__asm__ __volatile__ (                                                        \
	"push %%ebp; movl %%eax,%%ebp; movl %1,%%eax; int $0x80; pop %%ebp"           \
	: "=a" (res)                                                                  \
	: "i" (__NR_##name), "b" (arg1), "c" (arg2),                                  \
	  "d" (arg3), "S" (arg4), "D" (arg5),                                         \
	  "0" (arg6)                                                                  \
	);                                                                            \
	return (res);                                                                 \
}

#endif
