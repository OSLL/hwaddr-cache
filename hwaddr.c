#include <linux/slab.h>
#include <linux/string.h>

#include "hwaddr.h"
#include "hash4.h"

static struct kmem_cache *hwaddr_v4_cache;

void hwaddr_v4_slab_destroy(void)
{
	hwaddr_v4_remove_entries(htonl(INADDR_ANY));
	rcu_barrier();
	kmem_cache_destroy(hwaddr_v4_cache);
}

int hwaddr_v4_slab_create(void)
{
	hwaddr_v4_cache = kmem_cache_create("hwaddr_v4_entry",
				sizeof(struct hwaddr_v4_entry), 0,
				SLAB_HWCACHE_ALIGN, NULL);

	if (!hwaddr_v4_cache)
		return -ENOMEM;

	return 0;
}

void hwaddr_v4_free(struct hwaddr_v4_entry *entry)
{
	pr_debug("freeing entry for %pI4\n", &entry->h_remote);
			
	kmem_cache_free(hwaddr_v4_cache, entry);
}

struct hwaddr_v4_entry *hwaddr_v4_alloc(__be32 remote, __be32 local,
			u8 const *ha, unsigned ha_len)
{
	struct hwaddr_v4_entry *entry = NULL;

	if (ha_len > MAX_ADDR_LEN)
		return NULL;

	entry = (struct hwaddr_v4_entry *)kmem_cache_zalloc(hwaddr_v4_cache,
				GFP_ATOMIC);
	if (!entry)
		return NULL;

	rwlock_init(&entry->common.h_lock);
	atomic_long_set(&entry->common.h_stamp, (long)jiffies);
	init_hwaddr_v4_entry(entry, remote, local, ha, ha_len);

	return entry;
}
