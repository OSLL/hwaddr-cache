#include <linux/slab.h>
#include <linux/string.h>
#include <net/route.h>

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
	{
		pr_err("hwaddr-cache: cannot create entry cache\n");
		return -ENOMEM;
	}

	return 0;
}

void hwaddr_free(struct hwaddr_entry *entry)
{
	pr_debug("hwaddr-cache: freeing entry for %pI4\n", &entry->h_remote);

	dst_release(&entry->h_route->dst);
	kmem_cache_free(hwaddr_cache, entry);
}

static struct rtable* hwaddr_create_route(struct net_device const *dev,
			__be32 remote, __be32 local)
{
	struct rtable *rt = ip_route_output(dev_net(dev), remote, local,
				RTO_ONLINK, dev->ifindex);

	if (!IS_ERR_OR_NULL(rt))
		return rt;

	pr_warn("hwaddr-cache: cannor create route from %pI4 to %pI4\n",
				&local, &remote);
	return NULL;
}

struct hwaddr_entry *hwaddr_alloc(struct net_device const *dev, __be32 remote,
			__be32 local, u8 const *ha, unsigned ha_len)
{
	struct hwaddr_entry *entry = NULL;

	if (ha_len > MAX_ADDR_LEN)
	{
		pr_err("hwaddr-cache: link layer address is too long\n");
		return NULL;
	}

	entry = (struct hwaddr_entry *)kmem_cache_zalloc(hwaddr_cache,
				GFP_ATOMIC);
	if (!entry)
	{
		pr_warn("hwaddr-cache: cannot allocate hwaddr_entry\n");
		return NULL;
	}

	atomic_long_set(&entry->h_stamp, (long)get_seconds());
	atomic_set(&entry->h_refcnt, 0);
	memcpy(entry->h_ha, ha, ha_len);

	entry->h_ha_len = ha_len;
	entry->h_remote = remote;
	entry->h_local = local;

	entry->h_route = hwaddr_create_route(dev, remote, local);
	if (!entry->h_route)
	{
		kmem_cache_free(hwaddr_cache, entry);
		return NULL;
	}

	return entry;
}
