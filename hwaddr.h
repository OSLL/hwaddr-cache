#ifndef __HWADDR_CACHE_HWADDR_H__
#define __HWADDR_CACHE_HWADDR_H__

#include <linux/inetdevice.h>
#include <linux/ipv6.h>
#include <linux/kernel.h>
#include <linux/rwlock.h>
#include <linux/string.h>

#define HW_PERSIST	0x01

enum hwaddr_proto
{
	HW_IPv4,
	HW_IPv6
};

struct hwaddr_common
{
	struct rcu_head		h_rcu;
	struct hlist_node	h_node;

	atomic_long_t		h_stamp;
	u8			h_flags;
	rwlock_t		h_lock;	
	unsigned		h_ha_len;
	u8			h_ha[ALIGN(MAX_ADDR_LEN, sizeof(long))];
};

struct hwaddr_entry
{
	struct hwaddr_common	common;
	enum hwaddr_proto	h_proto;

	#define h_rcu		common.h_rcu
	#define h_node		common.h_node

	#define h_stamp		common.h_stamp
	#define h_flags		common.h_flags
	#define h_lock		common.h_lock
	#define h_ha_len	common.h_ha_len
	#define h_ha		common.h_ha

	union
	{
		__be32			h_local_ipv4;
		struct in6_addr		h_local_ipv6;
	};

	union
	{
		__be32			h_remote_ipv4;
		struct in6_addr		h_remote_ipv6;
	};
};

static inline void init_hwaddr_entry(struct hwaddr_entry *entry, u8 const *ha,
			unsigned ha_len)
{
	entry->h_ha_len = ha_len;
	memcpy(entry->h_ha, ha, ha_len);
}

void hwaddr_slab_destroy(void);
int hwaddr_slab_create(void);

void hwaddr_free(struct hwaddr_entry *entry);
struct hwaddr_entry *hwaddr_v4_alloc(__be32 remote, __be32 local, u8 const *ha,
			unsigned ha_len);
struct hwaddr_entry *hwaddr_v6_alloc(struct in6_addr const *remote,
			struct in6_addr const *local, u8 const *ha,
			unsigned ha_len);

#endif /*__HWADDR_CACHE_HWADDR_H__*/
