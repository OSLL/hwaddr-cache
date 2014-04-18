#ifndef __HWADDR_CACHE_HWADDR_H__
#define __HWADDR_CACHE_HWADDR_H__

#include <linux/inetdevice.h>
#include <linux/kernel.h>
#include <linux/rwlock.h>
#include <linux/string.h>

struct hwaddr_entry
{
	struct rcu_head		rcu;
	struct hlist_node	node;

	__be32			local;
	__be32			remote;
	rwlock_t		lock;	
	unsigned		ha_len;
	u8			ha[ALIGN(MAX_ADDR_LEN, sizeof(unsigned long))];
};

static inline void init_hwaddr_entry(struct hwaddr_entry *entry, __be32 remote,
			__be32 local, u8 const *ha, unsigned ha_len)
{
	entry->remote = remote;
	entry->local = local;
	entry->ha_len = ha_len;
	memcpy(entry->ha, ha, ha_len);
}

void hwaddr_slab_destroy(void);
int hwaddr_slab_create(void);

void hwaddr_free(struct hwaddr_entry *entry);
struct hwaddr_entry *hwaddr_alloc(__be32 remote, __be32 local, u8 const *ha, unsigned ha_len);

#endif /*__HWADDR_CACHE_HWADDR_H__*/
