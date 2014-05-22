obj-m += hwaddr-cache.o
hwaddr-cache-objs := route.o route6.o output.o output6.o netfilter.o netfilter6.o hash.o hash6.o cache.o proc.o proc6.o

CFLAGS_route.o := -DDEBUG
CFLAGS_route6.o := -DDEBUG
CFLAGS_output.o := -DDEBUG
CFLAGS_output6.o := -DDEBUG
CFLAGS_netfilter.o := -DDEBUG
CFLAGS_netfilter6.o := -DDEBUG
CFLAGS_hash.o := -DDEBUG
CFLAGS_hash6.o := -DDEBUG
CFLAGS_cache.o := -DDEBUG
CFLAGS_proc.o := -DDEBUG
CFLAGS_proc6.o := -DDEBUG

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
