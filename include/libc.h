#ifndef __LIBC_H
#define __LIBC_H

#include <cdefs.h>
#include <defs.h>
#include <rklib.h>

#define isspace(c)      ((c) == ' ' || ((c) >= '\t' && (c) <= '\r'))
#define isascii(c)      (((c) & ~0x7f) == 0)
#define isupper(c)      ((c) >= 'A' && (c) <= 'Z')
#define islower(c)      ((c) >= 'a' && (c) <= 'z')
#define isalpha(c)      (isupper(c) || islower(c))
#define isdigit(c)      ((c) >= '0' && (c) <= '9')

static __inline__
int
rkstrlen(char *s)
{
	int len = 0;
	while (*s != '\0') {
		s++;
		len++;
	}
	return (len);
}

static __inline__
int
rkstrcmp(char *s1, char *s2)
{
	while (1) {
		if (*s1 != *s2++) {
			return (*s1 - *(s2-1));
		}
		if (!*s1++)
			break;
	}
	return (0);
}

static __inline__
void
rkstrcpy(char *dst, char *src)
{
	for (; (*dst = *src)!= '\0'; src++, dst++);
}

static __inline__
void
rkstrcat(char *s1, char *s2) {
	rkmemcpy(s1 + rkstrlen(s1), s2, rkstrlen(s2));
}

static __inline__
int
rkmemcmp(char *s1, char *s2, unsigned int n)
{
    if (n != 0) {
        char *p1 = s1, *p2 = s2;
        do {
            if (*p1++ != *p2++)
                return (*--p1 - *--p2);
        } while (--n != 0);
    }
    return (0);
}

static __inline__
void *
rkmemchr(char *s, int c, unsigned long n)
{
	register char *r = s;
	while (n--) {
		if (*r == c)
			return ((char *)r);
		r++;
	}
	return (NULL);
}

static __inline__
void *
rkstrchr(char *str, int ch)
{
	char *p = str;

	while (*p != '\0') {
		if (*p == ch) {
			return (p);
		}
			p++;
	}
	return (NULL);
}

static __inline__
int
rkitoa(char *s, unsigned long n, int base)
{
	char buf[24];
	int i = sizeof(buf)-1;
	int rem = 0;
	do {
		rem = n%base;
		buf[i--] = (rem < 10) ? rem + '0' : rem + 'a' - 10;
	} while(n/=base);
	rkmemcpy(s, &buf[i+1], sizeof(buf)-i);
	return (sizeof(buf)-i);
}

static __inline__
int
rkatoi(char *s)
{
	int i, n = 0;
	for (i = 0; s[i] != '\0'; i++)
		n = n*10 + s[i] - '0';
	return (n);
}

/* ripped due to lazyness */
static __inline__
char *
rknstrstr(char *data,char *pattern, unsigned int size)
{
	char *tmp=data,*ptr=pattern;
	while(*tmp&&(tmp<=(data+size)))
	{
		if(*tmp==*ptr)
			ptr++;
		else
			ptr=pattern;
		if(*ptr=='\0')
			return tmp-rkstrlen(pattern)+1;
		tmp++;
	}
	return (void *)0;
}

static __inline__
unsigned long
rkstrtoul(char *nptr, int base)
{
	unsigned char c;
	unsigned long n = 0;
	while (1) {
		c = *nptr++;
		if (isdigit(c))
			c -= '0';
		else if (isalpha(c))
			c -= isupper(c) ? 'A' - 10 : 'a' - 10;
		else
			break;
		if (c >= base)
			break;
		n = n * base + c;
	}
	return (n);
}

#endif
