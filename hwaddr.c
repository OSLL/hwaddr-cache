#include <linux/slab.h>
#include <linux/string.h>

#include "hash.h"
#include "hwaddr.h"

static struct kmem_cache *hwaddr_cache;

void hwaddr_slab_destroy(void)
{
	hwaddr_remove_entries(htonl(INADDR_ANY));
	rcu_barrier();
	kmem_cache_destroy(hwaddr_cache);
}

int hwaddr_slab_create(void)
{
	hwaddr_cache = kmem_cache_create("hwaddr_entry",
				sizeof(struct hwaddr_entry), 0,
				SLAB_HWCACHE_ALIGN, NULL);

	if (!hwaddr_cache)
		return -ENOMEM;

	return 0;
}

void hwaddr_free(struct hwaddr_entry *entry)
{
	pr_debug("freeing entry for %pI4\n", &entry->h_remote);
			
	kmem_cache_free(hwaddr_cache, entry);
}

struct hwaddr_entry *hwaddr_alloc(__be32 remote, __be32 local, u8 const *ha,
			unsigned ha_len)
{
	struct hwaddr_entry *entry = NULL;

	if (ha_len > MAX_ADDR_LEN)
		return NULL;

	entry = (struct hwaddr_entry *)kmem_cache_zalloc(hwaddr_cache,
				GFP_ATOMIC);
	if (!entry)
		return NULL;

	rwlock_init(&entry->h_lock);
	atomic_long_set(&entry->h_stamp, (long)jiffies);

	entry->h_remote = remote;
	entry->h_local = local;
	init_hwaddr_entry(entry, ha, ha_len);

	return entry;
}
