#include <linux/string.h>

#include "hash.h"
#include "hwaddr-hashtable.h"
#include "route.h"

static DEFINE_HASHTABLE(hwaddr_hashtable, 16);
static DEFINE_SPINLOCK(hwaddr_hashtable_lock);

static void hwaddr_create_slow(struct net_device *dev, __be32 remote,
			__be32 local, u8 const *ha, unsigned ha_len)
{
	struct hwaddr_entry *entry = NULL, *new_entry = NULL;

	spin_lock(&hwaddr_hashtable_lock);
	entry = hwaddr_lookup(remote, local);
	if (entry && entry->h_ha_len == ha_len &&
				!memcmp(entry->h_ha, ha, ha_len))
	{
		spin_unlock(&hwaddr_hashtable_lock);
		return;
	}

	new_entry = hwaddr_alloc(dev, remote, local, ha, ha_len);
	if (new_entry)
	{
		if (entry)
		{
			hlist_replace_rcu(&entry->h_node, &new_entry->h_node);
			dst_release(&entry->h_dst);
		}
		else
			hash_add_rcu(hwaddr_hashtable, &new_entry->h_node,
						remote);
	}
	spin_unlock(&hwaddr_hashtable_lock);

	pr_debug("hwaddr-cache: update entry for remote %pI4 and local %pI4\n",
				&remote, &local);
}

struct hwaddr_entry *hwaddr_lookup(__be32 remote, __be32 local)
{
	struct hwaddr_entry *entry = NULL;
	struct hlist_node *list = NULL;

	(void)list; //supress warning for new kernel version

	hwaddr_hash_for_each_possible_rcu(hwaddr_hashtable, entry, list,
				h_node, remote)
	{
		if (entry->h_remote == remote && entry->h_local == local)
		{
			atomic_long_set(&entry->h_stamp, (long)get_seconds());
			return entry;
		}
	}

	return NULL;
}

void hwaddr_update(struct net_device *dev, __be32 remote, __be32 local,
			u8 const *ha, unsigned ha_len)
{
	struct hwaddr_entry *entry = NULL;

	rcu_read_lock();
	entry = hwaddr_lookup(remote, local);
	if (!entry || entry->h_ha_len != ha_len ||
				memcmp(entry->h_ha, ha, ha_len))
		hwaddr_create_slow(dev, remote, local, ha, ha_len);
	rcu_read_unlock();
}

void hwaddr_clear_outdated(unsigned long timeout1, unsigned long timeout2)
{
	struct hwaddr_entry *entry = NULL;
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

void hwaddr_clear_cache(void)
{
	struct hwaddr_entry *entry = NULL;
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

void hwaddr_foreach(hwaddr_hash_callback_t callback, void *data)
{
	struct hwaddr_entry *entry = NULL;
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
