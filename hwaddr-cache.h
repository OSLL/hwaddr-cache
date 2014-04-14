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
	
	__be32				local;
	__be32				remote;
	rwlock_t			lock;	
	unsigned			ha_len;
	u8					ha[ALIGN(MAX_ADDR_LEN, sizeof(unsigned long))];
};

#endif /*__HWADDR_CACHE_H__*/
