#include <linux/init.h>
#include <linux/module.h>
#include <linux/version.h>

#include <linux/if_arp.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/string.h>

#include <net/arp.h>
#include <net/neighbour.h>
#include <net/route.h>

#include "hwaddr-hashtable.h"
#include "hwaddr-cache.h"

static struct kmem_cache *hwaddr_cache;
static DEFINE_SPINLOCK(hwaddr_hash_table_lock);
static DEFINE_HASHTABLE(hwaddr_hash_table, 16);


static void init_hwaddr_entry(struct hwaddr_entry *entry,
				__be32 remote,
				u8 const *ha,
				unsigned ha_len)
{
	entry->remote = remote;
	entry->ha_len = ha_len;
	memcpy(entry->ha, ha, ha_len);
}

static void hwaddr_free(struct hwaddr_entry *entry)
{
	pr_debug("freeing entry for %pI4\n", &entry->remote);
			
	kmem_cache_free(hwaddr_cache, entry);
}

static struct hwaddr_entry *hwaddr_alloc(__be32 remote,
						u8 const *ha,
						unsigned ha_len)
{
	struct hwaddr_entry *entry = NULL;

	if (ha_len > MAX_ADDR_LEN)
		return NULL;

	entry = (struct hwaddr_entry *)kmem_cache_zalloc(hwaddr_cache, GFP_ATOMIC);
	if (!entry)
		return NULL;

	atomic_set(&entry->refcnt, 1);
	rwlock_init(&entry->lock);

	init_hwaddr_entry(entry, remote, ha, ha_len);

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

static struct hwaddr_entry *hwaddr_lookup_unsafe(__be32 remote)
{
	struct hwaddr_entry *entry = NULL;
	struct hlist_node *list = NULL;
	hwaddr_hash_for_each_rcu(hwaddr_hash_table, entry, list, node, remote)
	{
		if (entry->remote == remote)
		{
			hwaddr_hold(entry);
			return entry;
		}
	}

	return NULL;
}

static struct hwaddr_entry *hwaddr_lookup(__be32 remote)
{
	struct hwaddr_entry *entry = NULL;

	rcu_read_lock();
	entry = hwaddr_lookup_unsafe(remote);
	rcu_read_unlock();

	return entry;
}

static struct hwaddr_entry * hwaddr_create_slow(__be32 remote,
						u8 const *ha,
						unsigned ha_len)
{
	struct hwaddr_entry *entry = NULL;

	spin_lock(&hwaddr_hash_table_lock);
	
	entry = hwaddr_lookup(remote);
	if (entry)
	{
		spin_unlock(&hwaddr_hash_table_lock);
		return entry;
	}

	entry = hwaddr_alloc(remote, ha, ha_len);
	if (entry)
	{
		hash_add_rcu(hwaddr_hash_table, &entry->node, remote);
		hwaddr_hold(entry);
	}

	spin_unlock(&hwaddr_hash_table_lock);

	pr_debug("create entry for remote ip = %pI4\n", &remote);

	return entry;
}

static void hwaddr_update(__be32 remote,
				u8 const *ha,
				unsigned ha_len)
{
	struct hwaddr_entry *entry = hwaddr_lookup(remote);
	if (!entry)
		entry = hwaddr_create_slow(remote, ha, ha_len);

	if (!entry)
		return;

	write_lock(&entry->lock);
	if (entry->ha_len != ha_len || memcmp(entry->ha, ha, ha_len))
	{
		pr_debug("update entry for %pI4\n", &entry->remote);
		init_hwaddr_entry(entry, remote, ha, ha_len);
	}
	write_unlock(&entry->lock);

	hwaddr_put(entry);
}

static void hwaddr_cache_release(void)
{
	struct hwaddr_entry *entry = NULL;
	struct hlist_node *tmp = NULL;
	struct hlist_node *list = NULL;
	int index = 0;

	synchronize_rcu();
	hwaddr_hash_for_each_safe(hwaddr_hash_table, index, list, tmp, entry, node)
	{
		hash_del_rcu(&entry->node);
		hwaddr_put(entry);
	}

	kmem_cache_destroy(hwaddr_cache);
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,14,0)
static unsigned int hwaddr_in_hook_fn(unsigned hooknum,
#else
static unsigned int hwaddr_in_hook_fn(struct nf_hook_ops const *ops,
#endif
					struct sk_buff *skb,
					struct net_device const *in,
					struct net_device const *out,
					int (*okfn)(struct sk_buff *))
{
	struct net_device *target = NULL;
	struct ethhdr *lhdr = NULL;
	struct iphdr *nhdr = NULL;

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
		hwaddr_update(nhdr->saddr, lhdr->h_source, ETH_ALEN);

	return NF_ACCEPT;
}

static void hwaddr_ensure_neigh(struct rtable *rt, struct hwaddr_entry *entry)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,1,0)
	struct neighbour *neigh = rt->dst._neighbour;
#else
	struct neighbour *neigh = NULL;
	__be32 next = 0;

	rcu_read_lock_bh();
	next = rt_nexthop(rt, entry->remote);
	neigh = __ipv4_neigh_lookup_noref(rt->dst.dev, next);
	if (!neigh)
		neigh = __neigh_create(&arp_tbl, &next, rt->dst.dev, false);
	rcu_read_unlock_bh();
#endif

	if (!neigh)
		return;

	read_lock(&entry->lock);
	neigh_update(neigh, entry->ha, NUD_NOARP, NEIGH_UPDATE_F_OVERRIDE);
	read_unlock(&entry->lock);
}

static struct rtable *update_route(struct sk_buff *skb,
					struct net_device const *out,
					struct hwaddr_entry *entry)
{
	struct iphdr const *const nhdr = ip_hdr(skb);
	struct rtable *const rt = ip_route_output(dev_net(out),
							nhdr->daddr,
							nhdr->saddr,
							nhdr->tos,
							out->ifindex);

	if (rt)
	{
		dst_hold(&rt->dst);
		skb_dst_drop(skb);
		skb_dst_set(skb, &rt->dst);
		hwaddr_ensure_neigh(rt, entry);
		if (skb->sk)
			sk_setup_caps(skb->sk, &rt->dst);
	}

	return rt;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,14,0)
static unsigned int hwaddr_out_hook_fn(unsigned hooknum,
#else
static unsigned int hwaddr_out_hook_fn(struct nf_hook_ops const *ops,
#endif
					struct sk_buff *skb,
					struct net_device const *in,
					struct net_device const *out,
					int (*okfn)(struct sk_buff *))
{
	struct net_device *target = NULL;
	struct hwaddr_entry *entry = NULL;
	struct rtable *rt = NULL;
	struct iphdr const *const nhdr = ip_hdr(skb);

	if (!out)
		return NF_ACCEPT;

	entry = hwaddr_lookup(nhdr->daddr);
	if (!entry)
		return NF_ACCEPT;

	target = ip_dev_find(dev_net(out), nhdr->saddr);
	if (!target)
	{
		hwaddr_put(entry);
		return NF_ACCEPT;
	}

	rt = update_route(skb, target, entry);
	if (!rt)
		pr_warn("cannot reroute packet to %pI4\n", &nhdr->daddr);

	dev_put(target);
	hwaddr_put(entry);

	return NF_ACCEPT;
}

static struct nf_hook_ops hwaddr_in_hook = {
	.hook = hwaddr_in_hook_fn,
	.owner = THIS_MODULE,
	.pf = NFPROTO_IPV4,
	.hooknum = NF_INET_LOCAL_IN,
	.priority = NF_IP_PRI_LAST
};

static struct nf_hook_ops hwaddr_out_hook = {
	.hook = hwaddr_out_hook_fn,
	.owner = THIS_MODULE,
	.pf = NFPROTO_IPV4,
	.hooknum = NF_INET_LOCAL_OUT,
	.priority = NF_IP_PRI_LAST
};

static int __init hwaddr_cache_init(void)
{
	int rc = 0;
	hwaddr_cache = kmem_cache_create("hwaddr-cache",
						sizeof(struct hwaddr_entry),
						0, SLAB_HWCACHE_ALIGN, NULL);

	if (!hwaddr_cache)
	{
		printk(KERN_ERR "cannot create slab cache for hwaddr module\n");
		return -ENOMEM;
	}

	rc = nf_register_hook(&hwaddr_in_hook);
	if (rc)
	{
		printk(KERN_ERR "cannot register netfilter input hook\n");
		hwaddr_cache_release();
		return rc;
	}

	rc = nf_register_hook(&hwaddr_out_hook);
	if (rc)
	{
		printk(KERN_ERR "cannot register netfilter output hook\n");
		nf_unregister_hook(&hwaddr_in_hook);
		hwaddr_cache_release();
		return rc;
	}

	pr_debug("hwaddr-cache module loaded\n");

	return 0;
}

static void __exit hwaddr_cache_cleanup(void)
{
	nf_unregister_hook(&hwaddr_out_hook);
	nf_unregister_hook(&hwaddr_in_hook);
	hwaddr_cache_release();

	pr_debug("hwaddr-cache module unloaded\n");
}

module_init(hwaddr_cache_init);
module_exit(hwaddr_cache_cleanup);

MODULE_LICENSE(LICENSE);
MODULE_AUTHOR(AUTHOR);
MODULE_DESCRIPTION(DESCRIPTION);
