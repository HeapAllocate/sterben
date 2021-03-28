#ifndef __X86_H
#define __X86_H

#define SYSCALL(name, args...)    ((int(*)())osctmap[__NR_##name])(args)

#define KERNEL_DS  -1
#define TIOCGPGRP  0x540F
#define X86_CR0_WP 0x10000

#define X86_EFLAGS_RF (1<<16)
#define X86_EFLAGS_TF (1<<8)
#define X86_EFLAGS_IF (1<<9)

#define SCTJMP(jmp, addr) \
({ \
        *(unsigned int *)((char *)jmp+3) = (unsigned int)addr; \
})

struct thread_info {
        void          *task;
        void          *exec_domain;
        unsigned int   flags;
        unsigned int   status;
        unsigned int   cpu;
        int            preempt_count;
        unsigned long  addr_limit;
};

#define current_thread_info() (sp() & ~(8192-1))

static __inline__
unsigned long read_cr0()
{
	unsigned long val;
	__asm__ __volatile__("mov %%cr0, %0" : "=r"(val) ::"memory");
	return (val);
}

static __inline__
void write_cr0(unsigned long val)
{
	__asm__ __volatile__("mov %0, %%cr0" :: "r"(val) : "memory");
}

static __inline__
void setrw()
{
	unsigned long cr0;

	cr0 = read_cr0();
	cr0 &= ~X86_CR0_WP;
	write_cr0(cr0);
}

static __inline__
void setro()
{
	unsigned long cr0;

	cr0 = read_cr0();
	cr0 |= X86_CR0_WP;
	write_cr0(cr0);
}

static __inline__
int ffs(int n)
{
	int r;

        asm("bsfl %1,%0"
            : "=r" (r)
            : "rm" (n), "0" (-1));
	return (r+1);
}

#endif
