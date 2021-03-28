#ifndef __LIB_STDIO_H
#define __LIB_STDIO_H

extern char *optarg;

int opensyms(void);
int readline(char *, int);
int getopt(int, char **, char *);
void printf(char *fmt, ...);
void sprintf(char *s, char *fmt, ...);
void memset(char *s, int c, unsigned int size);
void memcpy(void *dst, void *src, unsigned long n);
void *memmem(void *, unsigned long, void *, unsigned long);
void *memchr(void *, unsigned char, unsigned long);
char *strstr(char *, char *);
unsigned char *mapfile(char *, unsigned long *);
unsigned char *maplib(char *, int, unsigned long *);
int procfslookup(char *, char *);
int procfs_base(int, char *, unsigned long *, unsigned long);
void elf_lookup2(struct elfarg *);

#endif
