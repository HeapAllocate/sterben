CC=gcc
CFLAGS=-s -fno-builtin -nostdlib -c -O0 -fno-stack-protector

CFLAGS += -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=0

all:
	$(CC) -I../include $(CFLAGS) libio.c libmem.c

clean:
	rm -f *.o
