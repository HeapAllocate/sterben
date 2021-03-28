#ifndef __KDEFS_H
#define __KDEFS_H

#include <cdefs.h>

#define GFP_KERNEL 0x20

struct task_struct {
	volatile long  state;
	void          *stack;
	unsigned int   usage;
	unsigned long  flags;
	unsigned long  ptrace;
	int            lock_depth;
};

struct path {
	void *vfsmount;
	void *dentry;
};

typedef struct spinlock {
	unsigned int rlock;
} spinlock_t;

struct timespec {
	long int tv_sec;
	long tv_nsec;
};

struct kstat {
	unsigned long long ino;
	unsigned int       dev;
	unsigned short     mode;
	unsigned int       nlink;
	unsigned int       uid;
	unsigned int       gid;
	unsigned int       rdev;
	unsigned long      size;
	struct timespec    atime;
	struct timespec    mtime;
	struct timespec    ctime;
	unsigned long      blksize;
	unsigned long long blocks;
};

struct seq_file {
	char *buf;
	unsigned long size;
	unsigned long from;
	unsigned long count;
};

struct seq_operations {
        void *(*start)(struct seq_file *m, loff_t *pos);
        void  (*stop) (struct seq_file *m, void *v);
        void *(*next) (struct seq_file *m, void *v, loff_t *pos);
        int   (*show) (struct seq_file *m, void *v);
};

struct dir_context {
	void *actor;
	long long off;
};

typedef int (*filldir_t)(void *, char *, int, loff_t, uint64_t, unsigned);

#define LIST_HEAD_INIT(name) { &(name), &(name) }

#define LIST_HEAD(name) \
        struct list_head name = LIST_HEAD_INIT(name)

struct list_head {
	struct list_head *next, *prev;
};

static __inline__ void
list_add(struct list_head *new, struct list_head *head) 
{
	struct list_head *next = head->next;
	struct list_head *prev = head;

	next->prev = new;
	new->next = next;
	new->prev = prev;
	prev->next = new;
}

static __inline__ void
list_del(struct list_head *entry)
{
	struct list_head *next = entry->next;
	struct list_head *prev = entry->prev;

	next->prev = prev;
	prev->next = next;
}

#define LIST_ENTRY(ptr, type, member) \
        ((type *)((char *)(ptr)-(unsigned long)(&((type *)0)->member)))

#define LIST_FOR_EACH_ENTRY(pos, head, member)                          \
        for (pos = LIST_ENTRY((head)->next, typeof(*pos), member);      \
             &pos->member != (head);                                    \
             pos = LIST_ENTRY(pos->member.next, typeof(*pos), member))

#endif
