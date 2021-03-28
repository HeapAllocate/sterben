#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <elf.h>
#include "arch.h"

#ifdef __AMD64__
#define WORDSIZE 64
#endif
#ifdef __i386__
#define WORDSIZE 32
#endif

#if WORDSIZE > 32
#define ELF_EHDR Elf64_Ehdr
#define ELF_SHDR Elf64_Shdr
#else
#define ELF_EHDR Elf32_Ehdr
#define ELF_SHDR Elf32_Shdr
#endif

int
main(int argc, char *argv[])
{
	ELF_EHDR *ehdr;
	ELF_SHDR *shdr;
	struct stat sb;
	unsigned char *buf, *p;
	unsigned int len;
	int fd, i;

	fd = open(argv[1], O_RDONLY);
	if (fstat(fd, &sb) == -1)
		return -1;

	buf = mmap(NULL, sb.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
	if (buf == (void *)-1)
		return -1;

	ehdr = (ELF_EHDR *) buf;
	shdr = (ELF_SHDR *) (buf + ehdr->e_shoff + sizeof(*shdr));

	len = shdr->sh_size;
	len--;

	p = (unsigned char *)(buf+shdr->sh_offset);
	printf("char sshbd[] = ");
	i = 0;
	while (1) {
		printf("\"");
		for (i = 0; i < 15; i++, len--) {
			printf("\\x%.2x", *(unsigned char *)p++);
			if (!len) {
				printf("\";");
				break;
			}
		}
		if (len)
			printf("\"\n");
		printf("\t       ");
		if (!len) {
			printf("\n");
			break;
		}
	}
	return 0;
}
