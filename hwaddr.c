#include <linux/slab.h>
#include <linux/string.h>

#include "hash.h"
#include "hwaddr.h"

static struct kmem_cache *hwaddr_cache;

void hwaddr_slab_destroy(void)
{
	hwaddr_remove_entries();
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
	if (entry->h_proto == HW_IPv4)
		pr_debug("freeing entry for remote %pI4 and local %pI4\n",
					&entry->h_remote_ipv4,
					&entry->h_local_ipv4);
	else
		pr_debug("freeing entry for remote %pI6 and local %pI6\n",
					&entry->h_remote_ipv6,
					&entry->h_local_ipv6);
			
	kmem_cache_free(hwaddr_cache, entry);
}

static struct hwaddr_entry *__hwaddr_alloc(u8 const *ha, unsigned ha_len)
{
	struct hwaddr_entry *entry = NULL;

	if (ha_len > MAX_ADDR_LEN)
	{
		pr_warning("link layer address is too long\n");
		return NULL;
	}

	entry = (struct hwaddr_entry *)kmem_cache_zalloc(hwaddr_cache,
				GFP_ATOMIC);
	if (!entry)
		return NULL;

	rwlock_init(&entry->h_lock);
	atomic_long_set(&entry->h_stamp, (long)get_seconds());
	init_hwaddr_entry(entry, ha, ha_len);

	return entry;
}

struct hwaddr_entry *hwaddr_v4_alloc(__be32 remote, __be32 local, u8 const *ha,
			unsigned ha_len)
{
	struct hwaddr_entry *entry = __hwaddr_alloc(ha, ha_len);

	if (!entry)
		return NULL;


	entry->h_proto = HW_IPv4;
	entry->h_remote_ipv4 = remote;
	entry->h_local_ipv4 = local;

	return entry;
}

struct hwaddr_entry *hwaddr_v6_alloc(struct in6_addr const *remote,
			struct in6_addr const *local, u8 const *ha,
			unsigned ha_len)
{
	struct hwaddr_entry *entry = __hwaddr_alloc(ha, ha_len);

	if (!entry)
		return NULL;

	entry->h_proto = HW_IPv6;
	entry->h_remote_ipv6 = *remote;
	entry->h_local_ipv6 = *local;

	return entry;
}
