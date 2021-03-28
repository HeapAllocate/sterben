#ifndef __UNISTD_H
#define __UNISTD_H

#include <arch.h>

#define PROT_READ       0x00000001
#define PROT_WRITE      0x00000002
#define PROT_EXEC       0x00000004
#define MAP_ANONYMOUS   0x00000020
#define MAP_SHARED      0x00000001
#define MAP_PRIVATE     0x00000002
#define MAP_FIXED       0x00000010
#define O_RDONLY        0000000000
#define O_WRONLY        0000000001
#define O_RDWR          0000000002
#define O_CREAT         0000000100
#define O_APPEND        0000002000
#define MAXPID               32768
#define ENOENT                   2
#define SEEK_SET                 0
#define AF_INET                  2
#define AF_INET6                10
#define PTRACE_PEEKTEXT          1
#define PTRACE_PEEKDATA          2
#define PTRACE_PEEKUSER          3
#define PTRACE_POKETEXT          4
#define PTRACE_CONT              7
#define PTRACE_GETREGS          12
#define PTRACE_SETREGS          13
#define PTRACE_ATTACH           16
#define PTRACE_DETACH           17

struct dirent32 {
	long             d_ino;
	unsigned long    d_off;
	unsigned short   d_reclen;
	char             d_name[1];
};

struct dirent64 {
	unsigned long    d_ino;
	long long        d_off;
	unsigned short   d_reclen;
	unsigned char    d_type;
	char             d_name[0];
};

struct linux_dirent {
        long            d_ino;
        unsigned long   d_off;
        unsigned short  d_reclen;
        char            d_name[];
};

#ifdef __AMD64__
struct stat {
	unsigned long   st_dev;
	unsigned long   st_ino;
	unsigned long   st_nlink;
	unsigned int    st_mode;
	unsigned int    st_uid;
	unsigned int    st_gid;
	unsigned int    __pad0;
	unsigned long   st_rdev;
	long            st_size;
	long            st_blksize;
	long            st_blocks;
	unsigned long   st_atime;
	unsigned long   st_atime_nsec;
	unsigned long   st_mtime;
	unsigned long   st_mtime_nsec;
	unsigned long   st_ctime;
	unsigned long   st_ctime_nsec;
	long            __unused[3];
};
#elif defined __IA32__
struct stat {
	unsigned long  st_dev;
	unsigned long  st_ino;
	unsigned short st_mode;
	unsigned short st_nlink;
	unsigned short st_uid;
	unsigned short st_gid;
	unsigned long  st_rdev;
	unsigned long  st_size;
	unsigned long  st_blksize;
	unsigned long  st_blocks;
	unsigned long  st_atime;
	unsigned long  st_atime_nsec;
	unsigned long  st_mtime;
	unsigned long  st_mtime_nsec;
	unsigned long  st_ctime;
	unsigned long  st_ctime_nsec;
	unsigned long  __unused4;
	unsigned long  __unused5;
};
struct stat64 {
	unsigned long  st_dev;
	unsigned long  st_ino;
	unsigned int   st_mode;
	unsigned int   st_nlink;
	unsigned int   st_uid;
	unsigned int   st_gid;
	unsigned long  st_rdev;
	unsigned long  __pad1;
	long long      st_size;
	int            st_blksize;
	int            __pad2;
	long long      st_blocks;
	int            st_atime;
	unsigned int   st_atime_nsec;
	int            st_mtime;
	unsigned int   st_mtime_nsec;
	int            st_ctime;
	unsigned int   st_ctime_nsec;
	unsigned int   __unused4;
	unsigned int   __unused5;
};
#endif

struct utsname {
	char sysname[65];
	char nodename[65];
	char release[65];
	char version[65];
	char machine[65];
	char domainname[65];
};

#define ETH_IPV4 0x8
#define ETH_IPV6 0xDD68

struct sockaddr {
	unsigned short sa_family;
	char           sa_data[14];
};

struct sockaddr_in4 {
	unsigned short sin_family;
	unsigned short sin_port;
	unsigned int   sin_addr;
};

struct sockaddr_in6 {
	unsigned short sin6_family;
	unsigned short sin6_port;
	unsigned int   sin6_flowinfo;
	unsigned char  sin6_addr[16];
};

struct iphdr {
    unsigned char    ihl:4;
    unsigned char    version:4;
    unsigned char    tos;
    unsigned short   tot_len;
    unsigned short   id;
    unsigned short   frag_off;
    unsigned char    ttl;
    unsigned char    protocol;
    unsigned short   check;
    unsigned int     saddr;
    unsigned int     daddr;
};

struct iphdr6 {
	unsigned char     priority:4,version:4;
	unsigned char     flow_lbl[3];
	unsigned short    payload_len;
	unsigned char     nexthdr;
	unsigned char     hop_limit;
	unsigned char     saddr[16];
	unsigned char     daddr[16];
};

extern unsigned long open(char *, int, int);
extern unsigned long close(int);
extern unsigned long exit(int);
extern unsigned long wait(int *);
extern unsigned long uname(void *);
extern unsigned long stat(char *, struct stat *);
extern unsigned long read(int, void *, unsigned long);
extern unsigned long write(int, void *, unsigned long);
extern unsigned long lseek(int, unsigned long, int);
extern unsigned long ptrace(int, int, void *, void *);
extern unsigned long mmap(void *, unsigned long, int, int, int, unsigned long);

#endif
