#ifndef __RKTRAMPS_H
#define __RKTRAMPS_H

#ifdef __AMD64__
void
kmtramp(void) {
    __asm__ __volatile__("movq   kmalloc, %rbx \n"
                         "movq   $12288, %rdi  \n"
                         "movq   $0xd0, %rsi   \n"
                         "callq *%rbx          \n"
                         "movq   %rax, kmem    \n"
                         "xorq   %rax, %rax    \n"
                         "decl   %eax          \n"
                        );
}

void
vmtramp(void *ts) {
    __asm__ __volatile__("movq   $4096, %rax   \n"
                         "movq   vmalloc, %rbx \n"
                         "callq *%rbx          \n"
                         "movq   %rax, kmem    \n"
                        );
}

void
kinitramp() {
	__asm__ __volatile__("movq   kinit, %rbx   \n"
						 "callq *%rbx          \n"
						 "xorq   %rax, %rax    \n"
						 "decl   %eax          \n"
						);
}

void
rktrig() {
	__asm__ __volatile__("syscall\n"
                         : : "D"(0), "S"(sizeof(cpu_set_t)), "d"(0), "a"(__NR_getaffinity)
				        );
}
#else
void
kmtramp(void) {
	__asm__ __volatile__("movl   kmalloc, %ebx     \n"
		                 "movl   $12288, %eax      \n"
		                 "movl   $0xd0, %edx       \n"
		                 "call  *%ebx              \n"
		                 "movl   %eax, kmem        \n"
		                 "xorl   %eax, %eax        \n"
		                 "decl   %eax              \n"
		                );
}
void
vmtramp(void *ts) {
	asm ("movl   $4096, %eax   \n"
		 "movl   vmalloc, %ebx \n"
		 "call  *%ebx          \n"
		 "movl   %eax, kmem    \n"
		);
}
void
rktrig() {
	__asm__ __volatile__("int $0x80\n"
                         : : "b"(0), "c"(sizeof(cpu_set_t)), "d"(0), "a"(__NR_getaffinity)
				        );
}
void
kinitramp() {
	__asm__ __volatile__("mov kinit, %ebx\n"
						 "call *%ebx\n"
						 "mov $0xffffffff, %eax\n"
						);
}
#endif

#endif