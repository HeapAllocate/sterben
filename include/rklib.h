#ifndef __RKLIB_H
#define __RKLIB_H

void rkmemset(char *s, int c, unsigned int size);
//void rkmemcpy(void *dst, void *src, unsigned long n);
unsigned char *rkmemmem(void *haystack, unsigned long h_size, void *needle, unsigned long n_size);

#endif
