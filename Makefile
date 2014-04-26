obj-m += hwaddr-cache.o
hwaddr-cache-objs := cache.o hash.o hwaddr.o netfilter.o proc.o

CFLAGS_cache.o := -DDEBUG
CFLAGS_hash.o := -DDEBUG
CFLAGS_hwaddr.o := -DDEBUG
CFLAGS_netfilter.o := -DDEBUG
CFLAGS_proc.o := -DDEBUG

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
