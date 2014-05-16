#ifndef __HWADDR_CACHE_HWADDR_H__
#define __HWADDR_CACHE_HWADDR_H__

#include <linux/inetdevice.h>
#include <linux/kernel.h>
#include <linux/string.h>

struct hwaddr_entry
{
	struct rcu_head		h_rcu;
	struct hlist_node	h_node;

	atomic_long_t		h_stamp;
	atomic_t		h_refcnt;

	struct rtable*		h_route;

	unsigned		h_ha_len;
	u8			h_ha[ALIGN(MAX_ADDR_LEN, sizeof(long))];
	__be32			h_local;
	__be32			h_remote;
};

void hwaddr_slab_destroy(void);
int hwaddr_slab_create(void);

void hwaddr_free(struct hwaddr_entry *entry);
struct hwaddr_entry *hwaddr_alloc(struct net_device const *dev, __be32 remote,
			__be32 local, u8 const *ha, unsigned ha_len);

#endif /*__HWADDR_CACHE_HWADDR_H__*/
