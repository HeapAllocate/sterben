#ifndef __ARCH64_H
#define __ARCH64_H

#include <syscalls64.h>
#include <cdefs.h>

#define WORDSIZE   64
#define FHOOKSZ    12

#define RKJMP(jmp, addr) \
({ \
        *(unsigned long *)(jmp+2) = addr; \
})

#define REGPARM(x)

#define X86_CR0_WP 0x10000

static __inline__
unsigned long sp(void)
{
	register unsigned long rsp __asm__("rsp");
	return (rsp);
}

/* 64bit IDT */
struct idtr {
	unsigned short ulimit;
	unsigned long  base;
} __attribute__((packed));

struct rkgatedesc_64 {
         u16 offset_low;
         u16 segment;
         unsigned ist : 3, zero0 : 5, type : 5, dpl : 2, p : 1;
         u16 offset_middle;
         u32 offset_high;
         u32 zero1;
} __attribute__((packed));

struct pt_regs {
	unsigned long r15,r14,r13,r12;
	unsigned long bp,bx;
	unsigned long r11,r10,r9,r8;
	unsigned long ax,cx,dx,si,di,orax;
	unsigned long ip,cs,eflags,sp,ss;
};

#define idt rkgatedesc_64

#define TOP(x) ((x).offset_high)
#define MID(x) ((x).offset_middle)
#define BOT(x) ((x).offset_low)
#define OFF2(x) (((MID(x)) << 16) | BOT(x))

#define IDTVEC(x) ((long long)TOP(x) << 32) | ((long long) OFF2(x) & 0xffffffff)

#define __SCT_SYM "\xff\x14\xc5"
#define __CURRENT "\xd0\xd0\x00\x00"
#define __CPU_NUM "\xb0\xb0\x00\x00"

#define MSR_GS_BASE  0xc0000101
#define MSR_LSTAR    0xc0000082
#define MSR_SYSENTER MSR_LSTAR

#define rdmsr(msr, low, high) \
		__asm__ __volatile__("rdmsr" : "=a"(low), "=d"(high) : "c"(msr))

#endif
