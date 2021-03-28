CC=gcc
CFLAGS=-fno-builtin -nostdlib -nodefaultlibs -fomit-frame-pointer
STRIP=grep -vE "\.bss|\.text|\.data|\.rodata|\.ident|^ \#|\#NO_APP|\#APP|\.file|\.version|\.note|\.rdata"

KFLAGS += $(ZFLAGS)
CFLAGS += -I../include

all:
	@echo $(UFLAGS)
	@echo $(ZFLAGS)
	@echo $(KFLAGS)
	@echo .data > rkcore.s
	@echo "kstart:" >> rkcore.s
	$(CC) $(CFLAGS) $(KFLAGS) rkcore.c  -O0 -o - |$(STRIP) >> rkcore.s
	@echo .data > rklib.s
	@echo "klibstart:" >> rklib.s
	$(CC) $(CFLAGS) $(KFLAGS) rklib.c   -O0 -o - |$(STRIP) >> rklib.s
	@echo .data > rkopsig.s
	@echo "opsigstart:" >> rkopsig.s
	$(CC) $(CFLAGS) $(KFLAGS) rkopsig.c -O0 -o - |$(STRIP) >> rkopsig.s
	@echo .data > rkdbg.s
	@echo "kdbstart:" >> rkdbg.s
	$(CC) $(CFLAGS) $(KFLAGS) rkdbg.c   -O0 -o - |$(STRIP) >> rkdbg.s
	@echo "kend:" >> rkdbg.s
	$(CC) -c $(CFLAGS) $(ZFLAGS) rkcore.s
	$(CC) -c $(CFLAGS) $(ZFLAGS) rklib.s
	$(CC) -c $(CFLAGS) $(ZFLAGS) rkopsig.s
	$(CC) -c $(CFLAGS) $(ZFLAGS) rkdbg.s

clean:
	@rm -rf *.s *.o
