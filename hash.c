#include <linux/in.h>
#include <linux/netdevice.h>
#include <linux/spinlock.h>
#include <linux/string.h>

#include "hash.h"
#include "hwaddr.h"
#include "hwaddr-hashtable.h"

static DEFINE_HASHTABLE(hwaddr_hash_table, 16);
static DEFINE_SPINLOCK(hwaddr_hash_table_lock);

static struct hwaddr_entry * hwaddr_create_slow(struct net_device const *dev,
			__be32 remote, __be32 local, u8 const *ha,
			unsigned ha_len)
{
	struct hwaddr_entry *entry = NULL;

	spin_lock(&hwaddr_hash_table_lock);
	entry = hwaddr_lookup(remote, local);
	if (entry)
	{
		spin_unlock(&hwaddr_hash_table_lock);
		return entry;
	}

	entry = hwaddr_alloc(dev, remote, local, ha, ha_len);
	if (entry)
		hash_add_rcu(hwaddr_hash_table, &entry->h_node, remote);
	spin_unlock(&hwaddr_hash_table_lock);

	return entry;
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


static void hwaddr_entry_free_callback(struct rcu_head *head)
{
	hwaddr_free(container_of(head, struct hwaddr_entry, h_rcu));
}


void hwaddr_update(struct net_device const *dev, __be32 remote, __be32 local,
			u8 const *ha, unsigned ha_len)
{
	struct hwaddr_entry *new_entry = NULL;
	struct hwaddr_entry *entry = NULL;
	
	rcu_read_lock();
	entry = hwaddr_lookup(remote, local);
	if (!entry)
		entry = hwaddr_create_slow(dev, remote, local, ha, ha_len);

	if (entry && (entry->h_ha_len != ha_len ||
				memcmp(entry->h_ha, ha, ha_len)))
	{
		pr_debug("update entry for remote %pI4 and local %pI4\n",
					&entry->h_remote, &entry->h_local);	
		new_entry = hwaddr_alloc(dev, remote, local, ha, ha_len);
		hlist_replace_rcu(&entry->h_node, &new_entry->h_node);
		call_rcu(&entry->h_rcu, hwaddr_entry_free_callback);
	}
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

void hwaddr_remove_entry(__be32 remote, __be32 local)
{
	struct hwaddr_entry *entry = hwaddr_lookup(remote, local);
	if (entry)
		hash_del(&entry->h_node);
}

void hwaddr_fill_backet(__be32 remote, int count)
{
	while (count--)
	{
		struct hwaddr_entry *const entry = hwaddr_fake(remote, 0);
		if (entry)
			hash_add(hwaddr_hash_table, &entry->h_node, remote);
		else
			pr_debug("allocation failed\n");
	}
}

void __benchmark_update(struct net_device const *dev, __be32 remote,
			__be32 local, int count)
{
	#define MAC_LEN 6
	u8 mac[MAC_LEN] = {};

	unsigned long long elapsed = 0;
	unsigned long times = 0;

	while (count--)
	{
		unsigned long long start = ktime_to_ns(ktime_get());
		hwaddr_update(dev, remote, local, mac, MAC_LEN);
		elapsed += (ktime_to_ns(ktime_get()) - start);

		hwaddr_remove_entry(remote, local);
		times++;
	}

	pr_info("%lu updates takes %llu ns\n", times, elapsed);
}

void benchmark_update(int from, int to)
{
	int const repeat = 10000;
	int const step = 1000;
	struct net *nm = &init_net;
	__be32 const remote = 192 + (168 << 8) + (1 << 24);
	__be32 const local = 192 + (168 << 8) + (101 << 24);
	struct net_device *dev = ip_dev_find(nm, local);

	hwaddr_fill_backet(remote, from);
	while (from <= to)
	{
		pr_info("benchmark with backet length %d\n", from);
		__benchmark_update(dev, remote, local, repeat);
		hwaddr_fill_backet(remote, step);
		from += step;
	}

	hwaddr_remove_entries(htonl(INADDR_ANY));
}
