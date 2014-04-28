/************************************************************
 * Userspace program to check ipreflect reference counting. *
 *                                                          *
 * Usage:                                                   *
 *     ./iprf ref|unref <remote ip> <local ip>              *
 *                                                          *
 * ref         - to increment reference counter             *
 * unref       - to decrement reference counter             *
 * <remote ip> - client ip address in dot-decimal notation  *
 * <local ip>  - storage ip address in dot0decimal notation *
 ************************************************************/

#include <fcntl.h>
#include <netinet/in.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/types.h>

#define CANNOT_OPEN "cannot open /proc/hwaddr/cache\n"
#define CANNOT_IOCT "cannot ioctl /proc/hwaddr/cache\n"
#define CANNOT_PRSD "cannot not parse destination ip address\n"
#define CANNOT_PRSS "cannot not parse source ip address\n"
#define TOO_FEW_ARG "too few arguments, command, remote and local ip expected\n"
#define UNKNOWN_CMD "unknown command"

struct hwaddr_rfreq
{
	struct in_addr remote;
	struct in_addr local;
};

#define HWADDR_IOC_MAGIC	0xFE
#define HWADDR_ENTRY_REF	_IOW(HWADDR_IOC_MAGIC, 1, struct hwaddr_rfreq)
#define HWADDR_ENTRY_UNREF	_IOW(HWADDR_IOC_MAGIC, 2, struct hwaddr_rfreq)


int main(int argc, char **argv)
{
	struct hwaddr_rfreq request;
	unsigned long command = 0;
	int fd = -1;

	if (argc < 4)
	{
		write(1, TOO_FEW_ARG, strlen(TOO_FEW_ARG));
		return 1;
	}

	if (!strcmp("ref", argv[1]))
		command = HWADDR_ENTRY_REF;
	else if (!strcmp("unref", argv[1]))
		command = HWADDR_ENTRY_UNREF;
	else
	{
		write(1, UNKNOWN_CMD, strlen(UNKNOWN_CMD));
		return 1;
	}

	if (inet_pton(AF_INET, argv[2], &request.remote) <= 0)
	{
		write(1, CANNOT_PRSD, strlen(CANNOT_PRSD));
		return 1;
	}

	if (inet_pton(AF_INET, argv[3], &request.local) <= 0)
	{
		write(1, CANNOT_PRSS, strlen(CANNOT_PRSS));
		return 1;
	}

	fd = open("/proc/hwaddr/cache", O_WRONLY);
	if (fd == -1)
	{
		write(1, CANNOT_OPEN, strlen(CANNOT_OPEN));
		return 1;
	}


	if (ioctl(fd, command, &request))
	{
		write(1, CANNOT_IOCT, strlen(CANNOT_IOCT));
		return 1;
	}

	close(fd);

	return 0;
}
