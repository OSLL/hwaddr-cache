#include <linux/string.h>
#include <net/ipv6.h>

#include "hash6.h"
#include "hwaddr-hashtable.h"
#include "route6.h"

static DEFINE_HASHTABLE(hwaddr_hashtable, 16);
static DEFINE_SPINLOCK(hwaddr_hashtable_lock);

/* backport from linux kernel */
static inline u32 hwaddr_addr_hash(struct in6_addr const *addr)
{
#if defined(CONFIG_HAVE_EFFICIENT_UNALIGNED_ACCESS) && BITS_PER_LONG == 64
	unsigned long const *ul = (unsigned long const *)addr;
	unsigned long x = ul[0] ^ ul[1];

	return (u32)(x ^ (x >> 32));
#else
	return (u32)(addr->s6_addr32[0] ^ addr->s6_addr32[1] ^
				addr->s6_addr32[2] ^ addr->s6_addr32[3]);
#endif
}

static void hwaddr_create_slow(struct net_device *dev, struct in6_addr *remote,
			struct in6_addr *local, u8 const *ha, unsigned ha_len)
{
	struct hwaddr6_entry *entry = NULL, *new_entry = NULL;

	spin_lock(&hwaddr_hashtable_lock);
	entry = hwaddr6_lookup(remote, local);
	if (entry && entry->h_ha_len == ha_len &&
				!memcmp(entry->h_ha, ha, ha_len))
	{
		spin_unlock(&hwaddr_hashtable_lock);
		return;
	}

	new_entry = hwaddr6_alloc(dev, remote, local, ha, ha_len);
	if (new_entry)
	{
		if (entry)
		{
			hlist_replace_rcu(&entry->h_node, &new_entry->h_node);
			dst_release(&entry->h_dst);
		}
		else
		{
			u32 const hash = hwaddr_addr_hash(remote);
			hash_add_rcu(hwaddr_hashtable, &new_entry->h_node,
						hash);
		}
	}
	spin_unlock(&hwaddr_hashtable_lock);

	pr_debug("hwaddr-cache6: update entry for remote %pI6 and local %pI6\n",
				remote, local);
}

struct hwaddr6_entry *hwaddr6_lookup(struct in6_addr *remote,
			struct in6_addr *local)
{
	struct hwaddr6_entry *entry = NULL;
	struct hlist_node *list = NULL;
	u32 const hash = hwaddr_addr_hash(remote);

	(void)list; //supress warning for new kernel version

	hwaddr_hash_for_each_possible_rcu(hwaddr_hashtable, entry, list,
				h_node, hash)
	{
		if (ipv6_addr_equal(&entry->h_remote, remote) &&
					ipv6_addr_equal(&entry->h_local, local))
		{
			atomic_long_set(&entry->h_stamp, (long)get_seconds());
			return entry;
		}
	}

	return NULL;
}

void hwaddr6_update(struct net_device *dev, struct in6_addr *remote,
			struct in6_addr *local, u8 const *ha, unsigned ha_len)
{
	struct hwaddr6_entry *entry = NULL;

	rcu_read_lock();
	entry = hwaddr6_lookup(remote, local);
	if (!entry || entry->h_ha_len != ha_len ||
				memcmp(entry->h_ha, ha, ha_len))
		hwaddr_create_slow(dev, remote, local, ha, ha_len);
	rcu_read_unlock();
}

void hwaddr6_clear_outdated(unsigned long timeout1, unsigned long timeout2)
{
	struct hwaddr6_entry *entry = NULL;
	struct hlist_node *tmp = NULL;
	struct hlist_node *list = NULL;
	int index = 0;

	(void)list; //supress warning for new kernel versions

	spin_lock(&hwaddr_hashtable_lock);
	hwaddr_hash_for_each_safe(hwaddr_hashtable, index, list, tmp, entry,
				h_node)
	{
		unsigned long const inactive = get_seconds() -
			(unsigned long)atomic_long_read(&entry->h_stamp);

		if (inactive < timeout1)
			continue;

		if ((atomic_read(&entry->h_refcnt) > 0) && inactive < timeout2)
			continue;

		hash_del_rcu(&entry->h_node);
		dst_release(&entry->h_dst);
	}
	spin_unlock(&hwaddr_hashtable_lock);
}

void hwaddr6_clear_cache(void)
{
	struct hwaddr6_entry *entry = NULL;
	struct hlist_node *tmp = NULL;
	struct hlist_node *list = NULL;
	int index = 0;

	(void)list; //supress warning for new kernel versions

	spin_lock(&hwaddr_hashtable_lock);
	hwaddr_hash_for_each_safe(hwaddr_hashtable, index, list, tmp, entry,
				h_node)
	{
		hash_del_rcu(&entry->h_node);
		dst_release(&entry->h_dst);
	}
	spin_unlock(&hwaddr_hashtable_lock);
}

void hwaddr6_foreach(hwaddr6_hash_callback_t callback, void *data)
{
	struct hwaddr6_entry *entry = NULL;
	struct hlist_node *list = NULL;
	int index = 0;

	(void)list; //supress warning for new kernel versions

	rcu_read_lock();
	hwaddr_hash_for_each_rcu(hwaddr_hashtable, index, list, entry, h_node)
	{
		callback(entry, data);
	}
	rcu_read_unlock();
}
