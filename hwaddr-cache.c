#include <linux/hashtable.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/rwsem.h>
#include <linux/slab.h>
#include <linux/string.h>

#include <linux/if_arp.h>
#include <linux/if_ether.h>
#include <linux/inetdevice.h>
#include <linux/ip.h>
#include <linux/netdevice.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>

#include "hwaddr-cache.h"

static struct kmem_cache *hwaddr_cache;
static DECLARE_RWSEM(hwaddr_hash_table_rwsem);
static DEFINE_HASHTABLE(hwaddr_hash_table, 16);


static void hwaddr_free(struct hwaddr_entry *entry)
{
	printk(KERN_INFO "freeing entry for %pI4\n", &entry->remote);
			
	kmem_cache_free(hwaddr_cache, entry);
}

static struct hwaddr_entry * hwaddr_alloc(__be32 remote,
											__be32 local,
											unsigned char const *ha,
											unsigned ha_len)
{
	struct hwaddr_entry *entry = NULL;

	if (ha_len > MAX_ADDR_LEN)
		return NULL;

	entry = (struct hwaddr_entry *)kmem_cache_zalloc(hwaddr_cache, GFP_KERNEL);

	if (!entry)
		return NULL;

	atomic_set(&entry->refcnt, 1);
	entry->remote = remote;
	entry->local = local;
	memcpy(entry->ha, ha, ha_len);

	return entry;
}

static void hwaddr_hold(struct hwaddr_entry *entry)
{
	if (!entry)
		return;

	atomic_inc(&entry->refcnt);
}

static void hwaddr_put(struct hwaddr_entry *entry)
{
	if (!entry)
		return;

	if (atomic_dec_and_test(&entry->refcnt))
		hwaddr_free(entry);
}

static struct hwaddr_entry * hwaddr_lookup_unsafe(__be32 remote)
{
	struct hwaddr_entry * entry = NULL;

	hash_for_each_possible(hwaddr_hash_table, entry, node, remote)
	{
		if (entry->remote == remote)
		{
			hwaddr_hold(entry);
			return entry;
		}
	}

	return NULL;
}

static struct hwaddr_entry * hwaddr_lookup(__be32 remote)
{
	struct hwaddr_entry * entry = NULL;

	down_read(&hwaddr_hash_table_rwsem);
	entry = hwaddr_lookup_unsafe(remote);
	up_read(&hwaddr_hash_table_rwsem);

	return entry;
}

static struct hwaddr_entry * hwaddr_create_slow(__be32 remote,
												__be32 local,
												unsigned char const *ha,
												unsigned ha_len)
{
	struct hwaddr_entry * entry = NULL;

	down_write(&hwaddr_hash_table_rwsem);
	
	entry = hwaddr_lookup_unsafe(remote);
	if (entry)
	{
		up_write(&hwaddr_hash_table_rwsem);
		return entry;
	}

	entry = hwaddr_alloc(remote, local, ha, ha_len);
	if (entry)
	{
		hash_add(hwaddr_hash_table, &entry->node, remote);
		hwaddr_hold(entry);
	}

	up_write(&hwaddr_hash_table_rwsem);

	printk(KERN_INFO "create entry for remote ip = %pI4\n", &remote);

	return entry;
}

static struct hwaddr_entry * hwaddr_create(__be32 remote,
											__be32 local,
											unsigned char const *ha,
											unsigned ha_len)
{
	struct hwaddr_entry * entry = hwaddr_lookup(remote);

	/**
	 * Check gateway changed
	 **/
	if (entry && (remote != entry->remote || local != entry->local
		|| !memcmp(entry->ha, ha, ha_len)))
	{
		down_write(&hwaddr_hash_table_rwsem);
		hash_del(&entry->node);
		up_write(&hwaddr_hash_table_rwsem);
		hwaddr_put(entry);

		hwaddr_put(entry);
		entry = NULL;
	}

	if (!entry)
		entry = hwaddr_create_slow(remote, local, ha, ha_len);

	return entry;
}

static void hwaddr_cache_release(void)
{
	struct hwaddr_entry * entry = NULL;
	struct hlist_node * tmp = NULL;
	int index = 0;

	down_write(&hwaddr_hash_table_rwsem);
	hash_for_each_safe(hwaddr_hash_table, index, tmp, entry, node)
	{
		hash_del(&entry->node);
		hwaddr_put(entry);
	}
	up_write(&hwaddr_hash_table_rwsem);
}

/**
 * Interface changed in kernel version 3.13 to:
 * static unsigned int hwaddr_hook_fn(struct nf_hook_ops const *ops,
 **/
static unsigned int hwaddr_hook_fn(unsigned int hooknum,
									struct sk_buff *skb,
									struct net_device const *in,
									struct net_device const *out,
									int (*okfn)(struct sk_buff *))
{
	struct net_device * target = NULL;
	struct ethhdr * lhdr = NULL;
	struct iphdr * nhdr = NULL;

	if (!in)
		return NF_ACCEPT;

	if (in->type != ARPHRD_ETHER && in->type != ARPHRD_IEEE802)
		return NF_ACCEPT;

	if (skb->mac_len != ETH_HLEN)
		return NF_ACCEPT;

	lhdr = eth_hdr(skb);
	nhdr = ip_hdr(skb);
	target = __ip_dev_find(dev_net(in), nhdr->daddr, false);

	if (target == in)
		hwaddr_put(hwaddr_create(nhdr->saddr, nhdr->daddr,
									lhdr->h_source, ETH_ALEN));

	return NF_ACCEPT;
}

static struct nf_hook_ops hwaddr_hook = {
	.hook = hwaddr_hook_fn,
	.owner = THIS_MODULE,
	.pf = NFPROTO_IPV4,
	.hooknum = NF_INET_LOCAL_IN,
	.priority = NF_IP_PRI_LAST
};

static int __init hwaddr_cache_init(void)
{
	int rc = 0;

	hwaddr_cache = kmem_cache_create("hwaddr-cache",
										sizeof(struct hwaddr_entry),
										sizeof(unsigned long),
										SLAB_RED_ZONE | SLAB_POISON
											| SLAB_HWCACHE_ALIGN,
										NULL);

	if (!hwaddr_cache)
	{
		printk(KERN_ERR "cannot create slab cache for hwaddr module\n");
		return -ENOMEM;
	}

	rc = nf_register_hook(&hwaddr_hook);
	if (rc)
	{
		printk(KERN_ERR "cannot register netfilter hook\n");
		kmem_cache_destroy(hwaddr_cache);
		return rc;
	}

	printk(KERN_INFO "hwaddr-cache module loaded\n");

	return 0;
}

static void __exit hwaddr_cache_cleanup(void)
{
	hwaddr_cache_release();

	nf_unregister_hook(&hwaddr_hook);
	kmem_cache_destroy(hwaddr_cache);

	printk(KERN_INFO "hwaddr-cache module unloaded\n");
}

module_init(hwaddr_cache_init);
module_exit(hwaddr_cache_cleanup);

MODULE_LICENSE(LICENSE);
MODULE_AUTHOR(AUTHOR);
MODULE_DESCRIPTION(DESCRIPTION);
