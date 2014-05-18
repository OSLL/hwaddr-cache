obj-m += hwaddr-cache.o
hwaddr-cache-objs := route.o output.o netfilter.o hash.o cache.o proc.o

CFLAGS_route.o := -DDEBUG
CFLAGS_output.o := -DDEBUG
CFLAGS_netfilter.o := -DDEBUG
CFLAGS_hash.o := -DDEBUG
CFLAGS_cache.o := -DDEBUG
CFLAGS_proc.o := -DDEBUG

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
