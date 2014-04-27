#include <linux/in.h>
#include <linux/spinlock.h>
#include <linux/string.h>

#include "hash.h"
#include "hwaddr-hashtable.h"

#define HWADDR_HASH_BITS	16

static DEFINE_HASHTABLE(hwaddr_hash_table, HWADDR_HASH_BITS);
static DEFINE_SPINLOCK(hwaddr_hash_table_lock);


static int hwaddr_equal(struct hwaddr_entry const *entry, u8 const *remote,
			u8 const *local, unsigned na_len)
{
	enum hwaddr_proto const proto = entry->h_proto;

	unsigned const len = (proto == HW_IPv4)
				? sizeof(entry->h_remote_ipv4)
				: sizeof(entry->h_remote_ipv6);

	u8 const *eremote = (proto == HW_IPv4)
				? (u8 const *) &entry->h_remote_ipv4
				: (u8 const *) &entry->h_remote_ipv6;

	u8 const *elocal = (proto == HW_IPv4)
				? (u8 const *) &entry->h_local_ipv4
				: (u8 const *) &entry->h_local_ipv6;


	return (len == na_len) && !(memcmp(remote, eremote, na_len) ||
				memcmp(local, elocal, na_len));
}


static unsigned hwaddr_hash(u8 const *addr, unsigned na_len)
{
	unsigned value = 0x811c9dc5;

	while (na_len--)
	{
		value ^= (unsigned)*addr++;
		value *= 0x01000193;
	}

	return value;
}


static struct hwaddr_entry *hwaddr_v4_create_slow(__be32 remote, __be32 local,
			u8 const *ha, unsigned ha_len)
{
	struct hwaddr_entry *entry = NULL;

	spin_lock(&hwaddr_hash_table_lock);
	entry = hwaddr_v4_lookup(remote, local);
	if (entry)
	{
		spin_unlock(&hwaddr_hash_table_lock);
		return entry;
	}

	entry = hwaddr_v4_alloc(remote, local, ha, ha_len);
	if (entry)
		hash_add_rcu(hwaddr_hash_table, &entry->h_node,
					hwaddr_hash((u8 const *)&remote,
						sizeof(remote)));
	spin_unlock(&hwaddr_hash_table_lock);

	pr_debug("create entry for remote ip = %pI4 and local ip = %pI4\n",
				&remote, &local);

	return entry;
}


static struct hwaddr_entry *hwaddr_v6_create_slow(struct in6_addr const *remote,
			struct in6_addr const *local, u8 const *ha,
			unsigned ha_len)
{
	struct hwaddr_entry *entry = NULL;

	spin_lock(&hwaddr_hash_table_lock);
	entry = hwaddr_v6_lookup(remote, local);
	if (entry)
	{
		spin_unlock(&hwaddr_hash_table_lock);
		return entry;
	}

	entry = hwaddr_v6_alloc(remote, local, ha, ha_len);
	if (entry)
		hash_add_rcu(hwaddr_hash_table, &entry->h_node,
					hwaddr_hash((u8 const *)&remote,
						sizeof(*remote)));
	spin_unlock(&hwaddr_hash_table_lock);

	pr_debug("create entry for remote ip = %pI6 and local ip = %pI6\n",
				remote, local);

	return entry;
}


static struct hwaddr_entry *__hwaddr_lookup(u8 const *remote, u8 const *local,
			unsigned na_len)
{
	unsigned const hash = hwaddr_hash(remote, na_len);

	struct hwaddr_entry *entry = NULL;
	struct hlist_node *list = NULL;

	hwaddr_hash_for_each_possible_rcu(hwaddr_hash_table, entry, list,
				h_node, hash)
	{
		if (hwaddr_equal(entry, remote, local, na_len))
		{
			atomic_long_set(&entry->h_stamp, (long)get_seconds());
			return entry;
		}
	}

	return NULL;
}


struct hwaddr_entry *hwaddr_v4_lookup(__be32 remote, __be32 local)
{
	return __hwaddr_lookup((u8 const *)&remote, (u8 const *)&local,
				sizeof(remote));
}


struct hwaddr_entry *hwaddr_v6_lookup(struct in6_addr const *remote,
			struct in6_addr const *local)
{
	return __hwaddr_lookup((u8 const *)remote, (u8 const *)local,
				sizeof(*remote));
}


void hwaddr_v4_update(__be32 remote, __be32 local, u8 const *ha,
			unsigned ha_len)
{
	struct hwaddr_entry *entry = NULL;
	
	rcu_read_lock();
	entry = hwaddr_v4_lookup(remote, local);
	if (!entry)
		entry = hwaddr_v4_create_slow(remote, local, ha, ha_len);

	if (entry)
	{
		write_lock(&entry->h_lock);
		if (entry->h_ha_len != ha_len ||
					memcmp(entry->h_ha, ha, ha_len))
		{
			pr_debug("update entry for remote %pI4"
						"and local %pI4\n",
						&entry->h_remote_ipv4,
						&entry->h_local_ipv4);

			init_hwaddr_entry(entry, ha, ha_len);
		}
		write_unlock(&entry->h_lock);
	}
	rcu_read_unlock();
}


void hwaddr_v6_update(struct in6_addr const *remote,
			struct in6_addr const *local, u8 const *ha,
			unsigned ha_len)
{
	struct hwaddr_entry *entry = NULL;
	
	rcu_read_lock();
	entry = hwaddr_v6_lookup(remote, local);
	if (!entry)
		entry = hwaddr_v6_create_slow(remote, local, ha, ha_len);

	if (entry)
	{
		write_lock(&entry->h_lock);
		if (entry->h_ha_len != ha_len ||
					memcmp(entry->h_ha, ha, ha_len))
		{
			pr_debug("update entry for remote %pI4"
						"and local %pI4\n",
						&entry->h_remote_ipv6,
						&entry->h_local_ipv6);

			init_hwaddr_entry(entry, ha, ha_len);
		}
		write_unlock(&entry->h_lock);
	}
	rcu_read_unlock();
}


static void hwaddr_entry_free_callback(struct rcu_head *head)
{
	hwaddr_free(container_of(head, struct hwaddr_entry, h_rcu));
}

void hwaddr_v4_remove_entries(__be32 local)
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
		if ((local == ANY) || (entry->h_local_ipv4 == local))
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

		if ((entry->h_flags & HW_PERSIST) && inactive < timeout2)
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
