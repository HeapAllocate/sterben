#include <cdefs.h>
#include <defs.h>
#include <arch.h>
#include <unistd.h>
#include <libmem.h>
#include <libio.h>

int mfd;
int ukmem = 0;

void
kmem_init(void)
{	
	/* first try /dev/kmem 
	mfd = open("/dev/kmem", O_RDWR);
	if (mfd) {
		ukmem = 1;
		return;
	}*/

	/* try /dev/mem */
	mfd = open("/dev/mem", O_RDWR, 0);
}

int
rkm(void *buf, unsigned int offset, int count)
{
	unsigned int n;

    n = lseek(mfd, ukmem ? offset : offset&0x0fffffff, SEEK_SET);
 	if (n < 0) return -1;	

	n = read(mfd, buf, count);
	if (n < 0) return -1;
	return (n);
}

int
wkm(void *buf, unsigned int offset, int count)
{
	unsigned int n;

	if (count == 4) {
		offset &= 0x0fffffff;
		printf("off4: %x\n", offset);
	}
	else {
//		sleep(10);
//		offset &= 0x00ffffff;
		offset -= 0xc0000000;
		printf("offlong: %x\n", offset);
	}

	n = lseek(mfd, offset, SEEK_SET);
	if (n < 0) return -1;
	
	n = write(mfd, buf, count);
	if (n < 0) return -1;
	return (n);
}

void
wkml(unsigned long val, unsigned int offset)
{
	wkm(&val, offset, sizeof(unsigned long));
}

#if 0
int
kmemprobe(void)
{
	struct idtr idtr;
	unsigned long kernbase;
	int n;

	__asm__("sidt %0" : "=m" (idtr));
	kernbase = idtr.base & 0xff000000;
	n = rkm(&kernbase, kernbase, sizeof(void *));
	return (n);
}
#endif
