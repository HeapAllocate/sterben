#ifndef __CDEFS_H
#define __CDEFS_H

#ifndef NULL
#define NULL ((void *)0)
#endif

#define __inline__ inline __attribute__((always_inline))

typedef unsigned long long             uint64_t;
typedef unsigned int                   uint32_t;
typedef unsigned short                 uint16_t;
typedef uint64_t                       u64;
typedef uint32_t                       u32;
typedef uint16_t                       u16;
typedef long long                      loff_t;

typedef unsigned int                   uintptr_t;
#endif
