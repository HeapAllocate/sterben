#include <libc.h>
#include <rkcore.h>

asm(".globl kend");
asm(".globl kdbstart");

extern struct ksyms rksyms;
extern unsigned long sct_disp;
extern unsigned long brk_syscall;
extern unsigned char *dbjmp;
extern unsigned char *dborg;

#if defined ( __AMD64__) || defined (__IA32__)
/* do_debug hook */
static unsigned char ddbjmp[12]  = {'\x48','\xb8','\xcc','\xcc','\xcc','\xcc','\xcc','\xcc','\xcc','\xcc','\xff','\xe0'};
static unsigned char ddborg[12]  = {'\xff','\xff','\xff','\xff','\xff','\xff','\xff','\xff','\xff','\xff','\xff','\xff'};

#define GETDR6(x) __asm__ __volatile("mov %%dr6, %0" : "=r"(x))
#define DR_SETBRK(addr, regnum) __asm__ __volatile__("mov %0, %%dr" #regnum  : : "r" (addr))
#define DR_GETBRK(addr, regnum) __asm__ __volatile__("mov %dr" #regnum ", %0" : "=r"(addr))

/* debug register macros */
#define DR7_SET_LG(dr7, regnum) (dr7 | (3<<(regnum*2)))
#define DR7_SET_SZ(dr7, regnum, size) ((size-1) ? (dr7 | ((size-1)<<(18+(regnum*4)))) : (dr7))
#define DR7_SET_RWX(dr7, regnum, rwx) ((rwx)    ? (dr7 | (rwx<<(16+(regnum*4))))      : (dr7))

/* debug register contstants */
#define DR_TRAP_MASK     0x0f
#define DR_TRAP_SYSCALL  0x01
#define DR_TRAP_SYSENTER 0x02
#define DR_TRAP_TCPSHOW  0x04
#define DR7_IFETCH       0x00
#define DR7_WRONLY       0x01
#define DR7_IO           0x02
#define DR7_RDWR         0x02
#define DR7_LGBASE       0x03
#define DR7_RWXBASE      0x10
#define DR7_SZBASE  	 0x12
#define DR0              0x00
#define DR1              0x01
#define DR2              0x02
#define DR3              0x03
#define DR6              0x04
#define DR7              0x05
#define DR_TRAP0          0x1
#define DR_TRAP1          0x2
#define DR_TRAP2          0x4
#define DR_TRAP3          0x8
#define DR_GD          0x2000
#define DR_STEP        0x4000

struct dbop {
	unsigned char op;
	unsigned char val;
};

#define PTREGS_BX (5<<3)
#define PTREGS_AX (10<<3)
#define PTREGS_CX (11<<3)
#define PTREGS_DX (12<<3)
#define PTREGS_SI (13<<3)
#define PTREGS_DI (14<<3)
#define PTREGS_SP (19<<3)

struct dbop dbmap[] = {
	{ 0xf8, (PTREGS_AX|DR7) },
	{ 0xfc, (PTREGS_SP|DR7) },
	{ 0xfb, (PTREGS_BX|DR7) },
	{ 0xf9, (PTREGS_CX|DR7) },
	{ 0xfa, (PTREGS_DX|DR7) },
	{ 0xff, (PTREGS_DI|DR7) },
	{ 0xfe, (PTREGS_SI|DR7) },
	{ 0xc0, (PTREGS_AX|DR0) },
	{ 0xc3, (PTREGS_BX|DR0) },
	{ 0xc1, (PTREGS_CX|DR0) },
	{ 0xc2, (PTREGS_DX|DR0) },
	{ 0xc7, (PTREGS_DI|DR0) },
	{ 0xc6, (PTREGS_SI|DR0) },
	{ 0xc4, (PTREGS_SP|DR0) },
	{ 0xc8, (PTREGS_AX|DR1) },
	{ 0xcb, (PTREGS_BX|DR1) },
	{ 0xc9, (PTREGS_CX|DR1) },
	{ 0xca, (PTREGS_DX|DR1) },
	{ 0xcf, (PTREGS_DI|DR1) },
	{ 0xce, (PTREGS_SI|DR1) },
	{ 0xcc, (PTREGS_SP|DR1) },
	{ 0xd0, (PTREGS_AX|DR2) },
	{ 0xd3, (PTREGS_BX|DR2) },
	{ 0xd1, (PTREGS_CX|DR2) },
	{ 0xd2, (PTREGS_DX|DR2) },
	{ 0xd7, (PTREGS_DI|DR2) },
	{ 0xd6, (PTREGS_SI|DR2) },
	{ 0xd4, (PTREGS_SP|DR2) },
	{ 0xd8, (PTREGS_AX|DR3) },
	{ 0xdb, (PTREGS_BX|DR3) },
	{ 0xd9, (PTREGS_CX|DR3) },
	{ 0xda, (PTREGS_DX|DR3) },
	{ 0xdf, (PTREGS_DI|DR3) },
	{ 0xde, (PTREGS_SI|DR3) },
	{ 0xdc, (PTREGS_SP|DR3) },
};

char dbtab[256] = {'\xff'};

void
dbmapinit() {
	int i, n;
	n = sizeof(dbmap)/sizeof(struct dbop);
	for (i=0; i<n; i++) {
		struct dbop *op = &dbmap[i];
		dbtab[op->op] = op->val;
	}
}

void
emucpu(struct pt_regs *regs)
{
	unsigned long mask, dr6, dr7 = 0xc;
	unsigned long *reg;
	unsigned char opcode[3];
	unsigned char op;
	int i, ridx, dbreg = 0;

	for(i=0;i<3;i++)
		opcode[i] = *(char *)((regs->ip)+i);

	if (opcode[0]!=0x0f||(opcode[1]!=0x23&&opcode[1]!=0x21))
		return;

	__asm__ __volatile__("mov %%db6,%0" : "=r" (dr6));
	dr6&=~DR_GD;
	__asm__ __volatile__ ("mov %0, %%db6" : : "r" (dr6));

	op    = dbtab[opcode[2]];
	ridx  = (op>>3);
	dbreg = (op&~0xf8);
	reg   = (unsigned long *)(regs+ridx);

	switch (dbreg) {
	case DR7:
		if (opcode[1]==0x23) {
			if ((*reg) != dr7) {
				mask=dr7|(*reg);
				__asm__ __volatile__("mov %0,%%db7" : : "r" (mask));
			}
		} else {
			__asm__ __volatile__("mov %%db7, %0" : "=r" (mask));
			mask&=~dr7;
			__asm__ __volatile__("mov %1, %0" : "=r" (reg) : "r" (mask));
		}
		break;
	case DR6:
		if (opcode[1]==0x23)
        	__asm__ __volatile__("mov %0, %%db6" : : "r"(*reg));
        else
        	__asm__ __volatile__("mov %%db6, %0" : "=r"(reg));
		break;
	case DR1:
		if (opcode[1]==0x23) {
			if ((*reg)==brk_syscall)
				__asm__ __volatile__("mov %0,%%db1" : : "r"((*reg)));
		}
		else {
			__asm__ __volatile__("mov %1, %0" : "=r"(reg) : "r"(0UL));
		}
		break;
	}
}
/* *********************************************
 * --------------------------------------------\
 * |               DEBUG REGZ                  |
 * \-------------------------------------------/
 * *********************************************/

void
setbrk(unsigned long addr, int regnum)
{
	unsigned long dr7;

	switch (regnum) {
	case DR0:
		DR_SETBRK(addr, 0);
		break;
	case DR1:
		DR_SETBRK(addr, 1);
		break;
	case DR2:
		DR_SETBRK(addr, 2);
		break;
	case DR3:
		DR_SETBRK(addr, 3);
		break;
	}
	__asm__ __volatile__ ("mov %%dr7, %0" : "=r"(dr7));
	dr7 = DR7_SET_LG(dr7, regnum);
	dr7 = 3;
	__asm__ __volatile__ ("mov %0, %%dr7" : : "r" (dr7));
}

REGPARM(2) void
rkdbg(struct pt_regs *regs, long err)
{
	unsigned long dr6, dr7 = 3;

	__asm__ __volatile__("mov %%dr6, %0" : "=r"(dr6));
	__asm__ __volatile__("mov %%dr7, %0" : "=r"(dr7));
	if (dr6 & DR_GD) {
		emucpu(regs);
		__asm__ __volatile__("mov %%dr7, %0" : "=r"(dr7));
		dr7 |= DR_GD;
		__asm__ __volatile__("mov %0, %%dr7" : : "r"(dr7));
		regs->ip += 3;
	}
	if (dr6 & DR_TRAP_SYSCALL) {
		regs->ax = (regs->ax+sct_disp);
		dr6 &= ~DR_TRAP_SYSCALL;
		regs->eflags |= X86_EFLAGS_RF;
		regs->eflags &= ~X86_EFLAGS_TF;
		__asm__ __volatile__ ("mov %0, %%dr6" : :"r"(dr6));
		__asm__ __volatile__ ("mov %0, %%dr7" : :"r"(dr7));
		return;
	}
#ifdef __IA32__
	else if (dr6 & DR_TRAP_SYSENTER) {
		regs->ax = (regs->ax+sct_disp);	
		dr6 &= ~DR_TRAP_SYSENTER;
		dr7 = DR7_SET_LG(dr7, DR1);
		regs->eflags |= X86_EFLAGS_RF;
		regs->eflags &= ~X86_EFLAGS_TF;
		__asm__ __volatile__ ("mov %0, %%dr6" : : "r"(dr6));
		__asm__ __volatile__ ("mov %0, %%dr7" : : "r"(dr7));
		return;
	}
#endif
}

void
rkconfdbg()
{
	dbmapinit();
}

void
rkunhookdr()
{
	unsigned long mask = 0x400;
	__asm__ __volatile__ ("mov %0, %%dr7\n" : : "r"(mask));
	__asm__ __volatile__ ("mov %0, %%dr0\n" : : "r"(0UL));
	__asm__ __volatile__ ("mov %0, %%dr1\n" : : "r"(0UL));
	rkmemcpy((char *)do_debug, ddborg, sizeof(ddborg));
}
#endif

#ifdef __MIPS32__

#define CP0_DEBUG   23
#define CP0_DEPC    24

#define DMSEG 0xff200000
#define DRSEG 0xff300000

void
rkconfdbg(struct pt_regs *regs)

{
    unsigned int drc = *(unsigned int *)DRSEG;
}

#define KSEG1        0xa0000000
#define CPHYSADDR(a) (a & 0x1fffffff)
#define KSEG1ADDR(a) (CPHYSADDR(a))

void
rkhookdr()
{
    unsigned long addr = KSEG1ADDR(0xbfc00480);
    *(unsigned short *)(dbjmp+2) = (unsigned short)(addr>>16);
    *(unsigned short *)(dbjmp+6) = (unsigned short)(addr&0x0000ffff);
    rkmemcpy((char *)0xbfc00480, dbjmp, 16);
}

#endif
