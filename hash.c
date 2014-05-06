#include <linux/in.h>
#include <linux/netdevice.h>
#include <linux/spinlock.h>
#include <linux/string.h>

#include "hash.h"
#include "hwaddr.h"
#include "hwaddr-hashtable.h"

static DEFINE_HASHTABLE(hwaddr_hash_table, 16);
static DEFINE_SPINLOCK(hwaddr_hash_table_lock);


static void hwaddr_entry_free_callback(struct rcu_head *head)
{
	hwaddr_free(container_of(head, struct hwaddr_entry, h_rcu));
}


static void hwaddr_create_slow(struct net_device const *dev, __be32 remote,
			__be32 local, u8 const *ha, unsigned ha_len)
{
	struct hwaddr_entry *entry = NULL, *new_entry = NULL;

	spin_lock(&hwaddr_hash_table_lock);

	entry = hwaddr_lookup(remote, local);
	if (entry && entry->h_ha_len == ha_len &&
				!memcmp(entry->h_ha, ha, ha_len))
	{
		spin_unlock(&hwaddr_hash_table_lock);
		return entry;
	}

	new_entry = hwaddr_alloc(dev, remote, local, ha, ha_len);
	if (new_entry)
	{
		if (entry)
		{
			hlist_replace_rcu(&entry->h_node, &new_entry->h_node);
			call_rcu(&entry->h_rcu, hwaddr_entry_free_callback);
		}
		else
			hash_add_rcu(hwaddr_hash_table, &new_entry->h_node,
						remote);
	}

	spin_unlock(&hwaddr_hash_table_lock);

	pr_debug("create entry for remote ip = %pI4 and local ip = %pI4\n",
				&remote, &local);

	return new_entry;
}


struct hwaddr_entry *hwaddr_lookup(__be32 remote, __be32 local)
{
	struct hwaddr_entry *entry = NULL;
	struct hlist_node *list = NULL;

	rcu_read_lock();
	hwaddr_hash_for_each_possible_rcu(hwaddr_hash_table, entry, list,
				h_node, remote)
	{
		if (entry->h_remote == remote && entry->h_local == local)
		{
			atomic_long_set(&entry->h_stamp, (long)get_seconds());
			rcu_read_unlock();
			return entry;
		}
	}
	rcu_read_unlock();

	return NULL;
}


void hwaddr_update(struct net_device const *dev, __be32 remote, __be32 local,
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


void hwaddr_remove_entries(__be32 local)
{
	__be32 const ANY = htonl(INADDR_ANY);

	struct hwaddr_entry *entry = NULL;
	struct hlist_node *tmp = NULL;
	struct hlist_node *list = NULL;
	int index = 0;

	spin_lock(&hwaddr_hash_table_lock);
	hwaddr_hash_for_each_safe(hwaddr_hash_table, index, list, tmp, entry,
				h_node)
	{
		if ((local == ANY) || (entry->h_local == local))
		{
			hash_del_rcu(&entry->h_node);
			call_rcu(&entry->h_rcu, hwaddr_entry_free_callback);
		}
	}
	spin_unlock(&hwaddr_hash_table_lock);
}


void hwaddr_remove_old_entries(unsigned long timeout1, unsigned long timeout2)
{
	struct hwaddr_entry *entry = NULL;
	struct hlist_node *tmp = NULL;
	struct hlist_node *list = NULL;
	int index = 0;

	spin_lock(&hwaddr_hash_table_lock);
	hwaddr_hash_for_each_safe(hwaddr_hash_table, index, list, tmp, entry,
				h_node)
	{
		unsigned long const inactive = get_seconds() -
			(unsigned long)atomic_long_read(&entry->h_stamp);

		if (inactive < timeout1)
			continue;

		if ((atomic_read(&entry->h_refcnt) > 0) && inactive < timeout2)
			continue;

		hash_del_rcu(&entry->h_node);
		call_rcu(&entry->h_rcu, hwaddr_entry_free_callback);
	}
	spin_unlock(&hwaddr_hash_table_lock);
}

void hwaddr_foreach(hwaddr_callback_t cb, void *data)
{
	struct hwaddr_entry *entry = NULL;
	struct hlist_node *list = NULL;
	int index = 0;

	rcu_read_lock();
	hwaddr_hash_for_each_rcu(hwaddr_hash_table, index, list, entry, h_node)
	{
		cb(entry, data);
	}
	rcu_read_unlock();
}
