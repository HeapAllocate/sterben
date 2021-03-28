#ifndef __INCS_H__
#define __INCS_H__

#define __IA32__ 1

#ifdef __AMD64__
#include <x64.h>
#include <x86.h>
#endif

#ifdef __IA32__
#include <x32.h>
#include <x86.h>
#endif

#ifdef __MIPS32__
#include <mips.h>
#endif

#ifdef __MIPS64__
#include <mips.h>
#endif

#endif
