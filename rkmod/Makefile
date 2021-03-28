obj-m += kmodd.o

all:
	$(MAKE) -Wno-strict-prototypes -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
