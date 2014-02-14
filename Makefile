ccflags-y += -Wall
obj-m += hwaddr-cache.o

CFLAGS_hwaddr-cache.o := -DDEBUG

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
