ccflags-y += -Wall
obj-$(CONFIG_HWADDRCACHE) += hwaddr-cache.o
CFLAGS_hwaddr-cache.o := -DDEBUG
