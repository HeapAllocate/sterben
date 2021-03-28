CC=gcc
CFLAGS=-s -c -O0 -fno-stack-protector -fno-builtin -nostdlib -nodefaultlibs

CFLAGS += -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=0

all:
	$(CC) -I../include $(CFLAGS) $(UFLAGS) rk.c

clean:
	@rm -rf *.o *.s
