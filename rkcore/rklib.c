asm(".globl klibstart");

#include <rklib.h>

void
rkmemset(char *s, int c, unsigned int size)
{
        register unsigned int i;
        for (i = 0; i < size; i++) {
                *s++ = c;
        }
}

void
rkmemcpy(void *dst, void *src, unsigned long n)
{
    register unsigned long i = 0;
    for (; i<n; i++) {
        *(unsigned char *)dst++=*(unsigned char *)src++;
    }
}

unsigned char *
rkmemmem(void *haystack, unsigned long h_size, void *needle, unsigned long n_size)
{
        register unsigned long i,j;

        for(i=0;i<h_size;i++)
        {
                if(j==n_size)
                        return (haystack+i-1);
                for(j=0;j<n_size;j++)
			if(*(unsigned char *)(haystack+i+j)!=*(unsigned char *)(needle+j))
                                break;
        }
        return ((void *)0);
}
