CC=gcc
AS=as
LD=ld
SEX=./sex
BDFLAGS=-s -c -O0 -fno-stack-protector -D_FORTIFY_SOURCE=0 -fomit-frame-pointer -fno-builtin -nostdlib

ifeq ($(shell uname -m),x86_64)
	ARCH=__AMD64__
	BDOPS=sshbd64.s
else
	BDOPS=sshbd32.s 
	ARCH=__i386__
endif
all:
	@echo "#define $(ARCH) 1" > arch.h
	$(CC) -ggdb sex.c -o sex
	$(AS) $(BDOPS) -o sshbd.o
	$(SEX) sshbd.o > bdops.h
	$(CC) -I ../include $(BDFLAGS) bd.c
#	@strip -s bd
#	@objcopy --remove-section=.comment bd

clean:
	@rm -rf bd sshbd.o bdops.h sex *~
