#ifndef __HWADDR_CACHE_HWADDR_H__
#define __HWADDR_CACHE_HWADDR_H__

#include <linux/inetdevice.h>
#include <linux/kernel.h>
#include <linux/rwlock.h>
#include <linux/string.h>

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

struct hwaddr_v4_entry
{
	struct hwaddr_common	common;

	__be32			h_local;
	__be32			h_remote;
};

static inline void init_hwaddr_common(struct hwaddr_common *entry, u8 const *ha,
			unsigned len)
{
	entry->h_ha_len = len;
	memcpy(entry->h_ha, ha, len);
}

static inline void init_hwaddr_v4_entry(struct hwaddr_v4_entry *entry,
			__be32 remote, __be32 local, u8 const *ha,
			unsigned ha_len)
{
	init_hwaddr_common(&entry->common, ha, ha_len);
	entry->h_remote = remote;
	entry->h_local = local;
}


void hwaddr_v4_slab_destroy(void);
int hwaddr_v4_slab_create(void);

void hwaddr_v4_free(struct hwaddr_v4_entry *entry);
struct hwaddr_v4_entry *hwaddr_v4_alloc(__be32 remote, __be32 local,
			u8 const *ha, unsigned ha_len);


struct hwaddr_v6_entry
{
	struct hwaddr_common	common;

	struct in6_addr		h_local;
	struct in6_addr		h_remote;
};

static inline void init_hwaddr_v6_entry(struct hwaddr_v6_entry *entry,
			struct in6_addr const *remote,
			struct in6_addr const *local,
			u8 const *ha, unsigned ha_len)
{
	init_hwaddr_common(&entry->common, ha, ha_len);
	memcpy(&entry->h_remote, remote, sizeof(struct in6_addr));
	memcpy(&entry->h_local, local, sizeof(struct in6_addr));
}

void hwaddr_v6_slab_destroy(void);
int hwaddr_v6_slab_create(void);

void hwaddr_v6_free(struct hwaddr_v4_entry *entry);
struct hwaddr_v4_entry *hwaddr_v6_alloc(struct in6_addr const *remote,
			struct in6_addr const *local, u8 const *ha,
			unsigned ha_len);

#endif /*__HWADDR_CACHE_HWADDR_H__*/
