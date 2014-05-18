#ifndef __HWADDR_ROUTE_H__
#define __HWADDR_ROUTE_H__

#include <linux/inetdevice.h>
#include <net/route.h>

struct hwaddr_entry
{
	struct rtable		h_rt;

	#define h_dst		h_rt.dst
	#define h_dev		h_rt.dst.dev

	__be32			h_remote;
	__be32			h_local;
	unsigned		h_ha_len;
	u8			h_ha[ALIGN(MAX_ADDR_LEN, sizeof(long))];

	atomic_long_t		h_stamp;
	atomic_t		h_refcnt;
	
	struct hlist_node	h_node;
};


int hwaddr_cache_create(void);
void hwaddr_cache_destroy(void);

struct hwaddr_entry *hwaddr_alloc(struct net_device *dev, __be32 remote,
			__be32 local, u8 const *ha, unsigned ha_len);

#endif /*__HWADDR_ROUTE_H__*/
