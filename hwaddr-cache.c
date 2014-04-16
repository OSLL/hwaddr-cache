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

static void init_hwaddr_entry(struct hwaddr_entry *entry, __be32 remote,
			__be32 local, u8 const *ha, unsigned ha_len)
{
	entry->remote = remote;
	entry->local = local;
	entry->ha_len = ha_len;
	memcpy(entry->ha, ha, ha_len);
}

static void hwaddr_free(struct hwaddr_entry *entry)
{
	pr_debug("freeing entry for %pI4\n", &entry->remote);
			
	kmem_cache_free(hwaddr_cache, entry);
}

static struct hwaddr_entry *hwaddr_alloc(__be32 remote, __be32 local,
			u8 const *ha, unsigned ha_len)
{
	struct hwaddr_entry *entry = NULL;

	if (ha_len > MAX_ADDR_LEN)
		return NULL;

	entry = (struct hwaddr_entry *)kmem_cache_zalloc(hwaddr_cache, GFP_ATOMIC);
	if (!entry)
		return NULL;

	rwlock_init(&entry->lock);
	init_hwaddr_entry(entry, remote, local, ha, ha_len);

	return entry;
}

static struct hwaddr_entry *hwaddr_lookup(__be32 remote)
{
	struct hwaddr_entry *entry = NULL;
	struct hlist_node *list = NULL;
	hwaddr_hash_for_each_possible_rcu(hwaddr_hash_table, entry, list, node,
				remote)
	{
		if (entry->remote == remote)
			return entry;
	}

	return NULL;
}

static struct hwaddr_entry * hwaddr_create_slow(__be32 remote, __be32 local,
			u8 const *ha, unsigned ha_len)
{
	struct hwaddr_entry *entry = NULL;

	spin_lock(&hwaddr_hash_table_lock);
	
	entry = hwaddr_lookup(remote);
	if (entry)
	{
		spin_unlock(&hwaddr_hash_table_lock);
		return entry;
	}

	entry = hwaddr_alloc(remote, local, ha, ha_len);
	if (entry)
		hash_add_rcu(hwaddr_hash_table, &entry->node, remote);

	spin_unlock(&hwaddr_hash_table_lock);

	pr_debug("create entry for remote ip = %pI4\n", &remote);

	return entry;
}

static void hwaddr_update(__be32 remote, __be32 local, u8 const *ha,
			unsigned ha_len)
{
	struct hwaddr_entry *entry = NULL;
	
	rcu_read_lock();

	entry = hwaddr_lookup(remote);
	if (!entry)
		entry = hwaddr_create_slow(remote, local, ha, ha_len);

	if (entry)
	{
		write_lock(&entry->lock);
		if (entry->ha_len != ha_len || memcmp(entry->ha, ha, ha_len))
		{
			pr_debug("update entry for %pI4\n", &entry->remote);
			init_hwaddr_entry(entry, remote, local, ha, ha_len);
		}
		write_unlock(&entry->lock);
	}

	rcu_read_unlock();
}

static void hwaddr_entry_free_callback(struct rcu_head *head)
{
	hwaddr_free(container_of(head, struct hwaddr_entry, rcu));
}

static void hwaddr_remove_entries(__be32 local)
{
	__be32 const ANY = htonl(INADDR_ANY);

	struct hwaddr_entry *entry = NULL;
	struct hlist_node *tmp = NULL;
	struct hlist_node *list = NULL;
	int index = 0;

	hwaddr_hash_for_each_safe(hwaddr_hash_table, index, list, tmp, entry, node)
	{
		if ((local == ANY) || (entry->local == local))
		{
			hash_del_rcu(&entry->node);
			call_rcu(&entry->rcu, hwaddr_entry_free_callback);
		}
	}
}

static void hwaddr_slab_destroy(void)
{
	hwaddr_remove_entries(htonl(INADDR_ANY));
	rcu_barrier();
	kmem_cache_destroy(hwaddr_cache);
}

static int hwaddr_slab_create(void)
{
	hwaddr_cache = kmem_cache_create("hwaddr-cache",
				sizeof(struct hwaddr_entry), 0, SLAB_HWCACHE_ALIGN, NULL);

	if (!hwaddr_cache)
		return -ENOMEM;

	return 0;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,14,0)
static unsigned int hwaddr_in_hook_fn(unsigned hooknum,
#else
static unsigned int hwaddr_in_hook_fn(struct nf_hook_ops const *ops,
#endif
			struct sk_buff *skb, struct net_device const *in,
			struct net_device const *out, int (*okfn)(struct sk_buff *))
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
		hwaddr_update(nhdr->saddr, nhdr->daddr, lhdr->h_source, ETH_ALEN);

	return NF_ACCEPT;
}

static struct nf_hook_ops hwaddr_in_hook = {
	.hook = hwaddr_in_hook_fn,
	.owner = THIS_MODULE,
	.pf = NFPROTO_IPV4,
	.hooknum = NF_INET_LOCAL_IN,
	.priority = NF_IP_PRI_LAST
};

static void hwaddr_ensure_neigh(struct rtable *rt, struct hwaddr_entry *entry)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,1,0)
	struct neighbour *neigh = rt->dst.neighbour;
#else
	struct neighbour *neigh = NULL;
	__be32 next = 0;

	rcu_read_lock_bh();
	next = rt_nexthop(rt, entry->remote);
	neigh = __ipv4_neigh_lookup_noref(rt->dst.dev, next);
	if (IS_ERR_OR_NULL(neigh))
		neigh = __neigh_create(&arp_tbl, &next, rt->dst.dev, false);
	rcu_read_unlock_bh();
#endif

	if (IS_ERR(neigh))
		return;

	read_lock(&entry->lock);
	neigh_update(neigh, entry->ha, NUD_NOARP, NEIGH_UPDATE_F_OVERRIDE);
	read_unlock(&entry->lock);
}

static struct rtable *update_route(struct sk_buff *skb,
			struct net_device const *out, struct hwaddr_entry *entry)
{
	struct iphdr const *const nhdr = ip_hdr(skb);
	struct rtable *const rt = ip_route_output(dev_net(out), nhdr->daddr,
				nhdr->saddr, nhdr->tos | RTO_ONLINK, out->ifindex);

	if (!IS_ERR(rt))
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
			struct sk_buff *skb, struct net_device const *in,
			struct net_device const *out, int (*okfn)(struct sk_buff *))
{
	struct net_device *target = NULL;
	struct hwaddr_entry *entry = NULL;
	struct rtable *rt = NULL;
	struct iphdr const *const nhdr = ip_hdr(skb);

	if (!out)
		return NF_ACCEPT;

	target = ip_dev_find(dev_net(out), nhdr->saddr);
	if (!target)
		return NF_ACCEPT;

	rcu_read_lock();
	entry = hwaddr_lookup(nhdr->daddr);
	if (entry)
	{
		rt = update_route(skb, target, entry);
		if (IS_ERR(rt))
			pr_warn("cannot reroute packet to %pI4\n", &nhdr->daddr);
	}
	rcu_read_unlock();

	dev_put(target);

	return NF_ACCEPT;
}

static struct nf_hook_ops hwaddr_out_hook = {
	.hook = hwaddr_out_hook_fn,
	.owner = THIS_MODULE,
	.pf = NFPROTO_IPV4,
	.hooknum = NF_INET_LOCAL_OUT,
	.priority = NF_IP_PRI_LAST
};


/* network interface notifiers */

static int aufs_inetaddr_event(struct notifier_block *nb, unsigned long event,
			void *ptr)
{
	struct in_ifaddr const* const ifa = (struct in_ifaddr *)ptr;
	switch (event)
	{
	case NETDEV_UP:
		pr_debug("inet addr %pI4 up\n", &ifa->ifa_local);
		break;
	case NETDEV_DOWN:
		pr_debug("inet addr %pI4 down\n", &ifa->ifa_local);
		break;
	}
	return NOTIFY_DONE;
}

static struct notifier_block aufs_inetaddr_notifier = {
	.notifier_call = aufs_inetaddr_event,
};

static int aufs_netdev_event(struct notifier_block *nb, unsigned long event,
			void *ptr)
{
	struct net_device const* const dev =
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,11,0)
				(struct net_device const *)ptr;
#else
				netdev_notifier_info_to_dev(ptr);
#endif
	struct in_device const* const in_dev = __in_dev_get_rtnl(dev);

	if (!in_dev)
		return NOTIFY_DONE;

	switch (event)
	{
	case NETDEV_UP:
		for_ifa(in_dev) {
			pr_debug("inet addr %pI4 up\n", &ifa->ifa_local);
		} endfor_ifa(in_dev);
		break;
	case NETDEV_DOWN:
		for_ifa(in_dev) {
			pr_debug("inet addr %pI4 down\n", &ifa->ifa_local);
		} endfor_ifa(in_dev);
		break;
	}
	return NOTIFY_DONE;
}

static struct notifier_block aufs_netdev_notifier = {
	.notifier_call = aufs_netdev_event,
};


/* procfs interface */

static struct proc_dir_entry *proc_info_root = NULL;
static char const proc_info_root_name[] = "hwaddr";

static int hwaddr_show_cache(struct seq_file *sf, void *unused)
{
	struct hwaddr_entry *entry = NULL;
	struct hlist_node *list = NULL;
	int index = 0;

	rcu_read_lock();
	hwaddr_hash_for_each_rcu(hwaddr_hash_table, index, list, entry, node)
	{
		seq_printf(sf, "local ip = %pI4, remote ip = %pI4, hwaddr = %pM\n",
					&entry->local, &entry->remote, entry->ha);
	}
	rcu_read_unlock();

	return 0;
}

static int hwaddr_proc_open(struct inode *inode, struct file *file)
{
	return single_open(file, hwaddr_show_cache, NULL);
}

static struct file_operations const hwaddr_proc_ops = {
	.open = hwaddr_proc_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};

static int hwaddr_proc_create(void)
{
	proc_info_root = proc_mkdir(proc_info_root_name, NULL);
	if (!proc_info_root)
		return -ENOMEM;

	proc_create_data("cache", 0, proc_info_root, &hwaddr_proc_ops, NULL);

	return 0;
}

static void hwaddr_proc_destroy(void)
{
	remove_proc_entry("cache", proc_info_root);
	remove_proc_entry(proc_info_root_name, NULL);
	proc_info_root = NULL;
}


/* hwaddr load and cleanup routines */

static int __init hwaddr_cache_init(void)
{
	int rc = 0;

	register_netdevice_notifier(&aufs_netdev_notifier);
	register_inetaddr_notifier(&aufs_inetaddr_notifier);

	rc = hwaddr_proc_create();
	if (rc)
	{
		pr_err("cannot create procfs entry\n");
		goto free_notifiers;
	}

	rc = hwaddr_slab_create();
	if (rc)
	{
		pr_err("cannot create slab cache for hwaddr module\n");
		goto free_proc;
	}

	rc = nf_register_hook(&hwaddr_in_hook);
	if (rc)
	{
		pr_err("cannot register netfilter input hook\n");
		goto free_cache;
	}

	rc = nf_register_hook(&hwaddr_out_hook);
	if (rc)
	{
		pr_err("cannot register netfilter output hook\n");
		goto free_in;
	}

	pr_debug("hwaddr-cache module loaded\n");
	return 0;

free_in:
	nf_unregister_hook(&hwaddr_in_hook);

free_cache:
	hwaddr_slab_destroy();

free_proc:
	hwaddr_proc_destroy();

free_notifiers:
	unregister_inetaddr_notifier(&aufs_inetaddr_notifier);
	unregister_netdevice_notifier(&aufs_netdev_notifier);

	return rc;
}

static void __exit hwaddr_cache_cleanup(void)
{
	nf_unregister_hook(&hwaddr_out_hook);
	nf_unregister_hook(&hwaddr_in_hook);
	hwaddr_slab_destroy();
	hwaddr_proc_destroy();
	unregister_inetaddr_notifier(&aufs_inetaddr_notifier);
	unregister_netdevice_notifier(&aufs_netdev_notifier);

	pr_debug("hwaddr-cache module unloaded\n");
}

module_init(hwaddr_cache_init);
module_exit(hwaddr_cache_cleanup);

MODULE_LICENSE(LICENSE);
MODULE_AUTHOR(AUTHOR);
MODULE_DESCRIPTION(DESCRIPTION);
