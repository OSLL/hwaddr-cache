#ifndef __HWADDR_CACHE_HWADDR_H__
#define __HWADDR_CACHE_HWADDR_H__

#include <linux/inetdevice.h>
#include <linux/kernel.h>
#include <linux/string.h>

struct hwaddr_common
{
	struct rcu_head		h_rcu;
	struct hlist_node	h_node;

	atomic_long_t		h_stamp;
	atomic_t		h_refcnt;
	struct rtable*		h_route;
	unsigned		h_ha_len;
	u8			h_ha[ALIGN(MAX_ADDR_LEN, sizeof(long))];
};

struct hwaddr_entry
{
	struct hwaddr_common	common;

	#define h_rcu		common.h_rcu
	#define h_node		common.h_node

	#define h_stamp		common.h_stamp
	#define h_refcnt	common.h_refcnt
	#define h_route		common.h_route
	#define h_ha_len	common.h_ha_len
	#define h_ha		common.h_ha

	__be32			h_local;
	__be32			h_remote;
};

void hwaddr_slab_destroy(void);
int hwaddr_slab_create(void);

void hwaddr_free(struct hwaddr_entry *entry);
struct hwaddr_entry *hwaddr_alloc(struct net_device const *dev, __be32 remote,
			__be32 local, u8 const *ha, unsigned ha_len);

struct hwaddr_entry *hwaddr_fake(__be32 remote, __be32 local);

#endif /*__HWADDR_CACHE_HWADDR_H__*/
