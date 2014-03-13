#ifndef __HWADDR_CACHE_H__
#define __HWADDR_CACHE_H__

#define AUTHOR			"Mike Krinkin <krinkin.m.u@gmail.com>"
#define DESCRIPTION		"network hardware address cache"
#define LICENSE			"Dual MIT/GPL"

#include <linux/kernel.h>
#include <linux/rwlock.h>
#include <linux/inetdevice.h>

struct hwaddr_entry
{
	struct hlist_node	node;

	/* prevents entry destroy */
	atomic_t			refcnt;

	__be32				remote;

	/* prevents data races on ha */
	rwlock_t			lock;	
	unsigned int		ha_len;
	unsigned char		ha[ALIGN(MAX_ADDR_LEN, sizeof(unsigned long))];
};

#endif /*__HWADDR_CACHE_H__*/
