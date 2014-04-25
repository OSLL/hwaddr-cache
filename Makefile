obj-m += hwaddr-cache.o
hwaddr-cache-objs := cache.o hwaddr.o hash4.o netfilter4.o proc4.o

CFLAGS_cache.o := -DDEBUG
CFLAGS_hwaddr.o := -DDEBUG
CFLAGS_hash4.o := -DDEBUG
CFLAGS_netfilter4.o := -DDEBUG
CFLAGS_proc4.o := -DDEBUG

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
