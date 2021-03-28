#ifndef __ARCH32_H
#define __ARCH32_H

#include <syscalls.h>

#define WORDSIZE 32
#define FHOOKSZ  8

#define RKJMP(jmp, addr) \
({ \
        *(unsigned long *)(jmp+1) = addr; \
})

#define REGPARM(n) __attribute__  ((regparm(n)))

#define IDTVEC(x) ((x).off1 | ((x).off2 << 16))

#define __SCT_SYM "\xff\x14\x85"

#define MSR_IA32_SYSENTER_EIP 0x00000176
#define MSR_SYSENTER          MSR_IA32_SYSENTER_EIP

static __inline__
unsigned long sp(void)
{
	__asm__ __volatile__("movl %esp, %eax\n");
}

struct idtr {
	unsigned short ulimit;
	unsigned long  base;
} __attribute__((packed));

struct idt {
	unsigned short off1;
	unsigned short sel;
	unsigned char  none;
	unsigned char  flags;
	unsigned short off2;
};

struct pt_regs {
	unsigned long bx,cx,dx,si,di,bp,ax;
	unsigned long ds,es,fs,gs,orax;
	unsigned long ip,cs,eflags,sp,ss;
};

#endif
