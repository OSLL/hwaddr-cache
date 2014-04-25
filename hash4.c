#include <linux/in.h>
#include <linux/spinlock.h>
#include <linux/string.h>

#include "hwaddr-hashtable.h"
#include "hwaddr.h"
#include "hash4.h"

static DEFINE_HASHTABLE(hwaddr_hash_table, 16);
static DEFINE_SPINLOCK(hwaddr_hash_table_lock);

static struct hwaddr_v4_entry * hwaddr_create_slow(__be32 remote, __be32 local,
			u8 const *ha, unsigned ha_len)
{
	struct hwaddr_v4_entry *entry = NULL;

	spin_lock(&hwaddr_hash_table_lock);
	entry = hwaddr_v4_lookup(remote, local);
	if (entry)
	{
		spin_unlock(&hwaddr_hash_table_lock);
		return entry;
	}

	entry = hwaddr_v4_alloc(remote, local, ha, ha_len);
	if (entry)
		hash_add_rcu(hwaddr_hash_table, &entry->common.h_node, remote);
	spin_unlock(&hwaddr_hash_table_lock);

	pr_debug("create entry for remote ip = %pI4\n", &remote);

	return entry;
}


struct hwaddr_v4_entry *hwaddr_v4_lookup(__be32 remote, __be32 local)
{
	struct hwaddr_v4_entry *entry = NULL;
	struct hlist_node *list = NULL;

	hwaddr_hash_for_each_possible_rcu(hwaddr_hash_table, entry, list,
				common.h_node, remote)
	{
		if (entry->h_remote == remote && entry->h_local == local)
		{
			atomic_long_set(&entry->common.h_stamp, (long)jiffies);
			return entry;
		}
	}

	return NULL;
}


void hwaddr_v4_update(__be32 remote, __be32 local, u8 const *ha,
			unsigned ha_len)
{
	struct hwaddr_v4_entry *entry = NULL;
	
	rcu_read_lock();
	entry = hwaddr_v4_lookup(remote, local);
	if (!entry)
		entry = hwaddr_create_slow(remote, local, ha, ha_len);

	if (entry)
	{
		write_lock(&entry->common.h_lock);
		if (entry->common.h_ha_len != ha_len ||
					memcmp(entry->common.h_ha, ha, ha_len))
		{
			pr_debug("update entry for %pI4\n", &entry->h_remote);
			init_hwaddr_v4_entry(entry, remote, local, ha, ha_len);
		}
		write_unlock(&entry->common.h_lock);
	}
	rcu_read_unlock();
}


static void hwaddr_entry_free_callback(struct rcu_head *head)
{
	hwaddr_v4_free(container_of(head, struct hwaddr_v4_entry,
				common.h_rcu));
}

void hwaddr_v4_remove_entries(__be32 local)
{
	__be32 const ANY = htonl(INADDR_ANY);

	struct hwaddr_v4_entry *entry = NULL;
	struct hlist_node *tmp = NULL;
	struct hlist_node *list = NULL;
	int index = 0;

	spin_lock(&hwaddr_hash_table_lock);
	hwaddr_hash_for_each_safe(hwaddr_hash_table, index, list, tmp, entry,
				common.h_node)
	{
		if ((local == ANY) || (entry->h_local == local))
		{
			hash_del_rcu(&entry->common.h_node);
			call_rcu(&entry->common.h_rcu,
						hwaddr_entry_free_callback);
		}
	}
	spin_unlock(&hwaddr_hash_table_lock);
}

void hwaddr_v4_foreach(hwaddr_v4_callback_t cb, void *data)
{
	struct hwaddr_v4_entry *entry = NULL;
	struct hlist_node *list = NULL;
	int index = 0;

	rcu_read_lock();
	hwaddr_hash_for_each_rcu(hwaddr_hash_table, index, list, entry,
				common.h_node)
	{
		cb(entry, data);
	}
	rcu_read_unlock();
}
