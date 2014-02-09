#ifndef __HWADDR_CACHE_H__
#define __HWADDR_CACHE_H__

#define AUTHOR			"Mike Krinkin <krinkin.m.u@gmail.com>"
#define DESCRIPTION		"network hardware address cache"
#define LICENSE			"Dual MIT/GPL"

#include <uapi/linux/netdevice.h>
#include <linux/kernel.h>

struct hwaddr_entry
{
	struct hlist_node	node;
	atomic_t			refcnt;
	__be32				remote;
	__be32				local;

	unsigned char		ha[ALIGN(MAX_ADDR_LEN, sizeof(unsigned long))];
};

#endif /*__HWADDR_CACHE_H__*/
