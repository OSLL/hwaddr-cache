#ifndef __HWADDR_ROUTE6_H__
#define __HWADDR_ROUTE6_H__

#include <linux/inetdevice.h>
#include <net/ip6_route.h>

struct hwaddr6_entry
{
	struct rt6_info		h_rt;

	#define h_dst		h_rt.dst
	#define h_dev		h_rt.dst.dev

	struct in6_addr		h_remote;
	struct in6_addr		h_local;
	unsigned		h_ha_len;
	u8			h_ha[ALIGN(MAX_ADDR_LEN, sizeof(long))];

	atomic_long_t		h_stamp;
	atomic_t		h_refcnt;
	
	struct hlist_node	h_node;
};


int hwaddr6_cache_create(void);
void hwaddr6_cache_destroy(void);

struct hwaddr6_entry *hwaddr6_alloc(struct net_device *dev,
			struct in6_addr *remote, struct in6_addr *local,
			u8 const *ha, unsigned ha_len);

#endif /*__HWADDR_ROUTE6_H__*/
