#include <linux/if_arp.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/version.h>

#include <net/arp.h>
#include <net/neighbour.h>
#include <net/route.h>

#include "hash.h"
#include "hwaddr.h"

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

static void hwaddr_ensure_neigh(struct rtable *rt, struct hwaddr_entry *entry)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,1,0)
	struct neighbour *neigh = rt->dst.neighbour;
#else
	struct neighbour *neigh = NULL;
	__be32 next = 0;

	rcu_read_lock_bh();
	next = rt_nexthop(rt, entry->h_remote);
	neigh = __ipv4_neigh_lookup_noref(rt->dst.dev, next);
	if (IS_ERR_OR_NULL(neigh))
		neigh = __neigh_create(&arp_tbl, &next, rt->dst.dev, false);
	rcu_read_unlock_bh();
#endif

	if (IS_ERR(neigh))
		return;

	read_lock(&entry->h_lock);
	neigh_update(neigh, entry->h_ha, NUD_NOARP, NEIGH_UPDATE_F_OVERRIDE);
	read_unlock(&entry->h_lock);
}

static struct rtable *hwaddr_update_route(struct sk_buff *skb,
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
	entry = hwaddr_lookup(nhdr->daddr, nhdr->saddr);
	if (entry)
	{
		rt = hwaddr_update_route(skb, target, entry);
		if (IS_ERR(rt))
			pr_warn("cannot reroute packet to %pI4\n", &nhdr->daddr);
	}
	rcu_read_unlock();

	dev_put(target);

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


int hwaddr_register_hooks(void)
{
	int rc = nf_register_hook(&hwaddr_in_hook);
	if (rc)
		return rc;

	rc = nf_register_hook(&hwaddr_out_hook);
	if (rc)
		nf_unregister_hook(&hwaddr_in_hook);

	return rc;
}

void hwaddr_unregister_hooks(void)
{
	nf_unregister_hook(&hwaddr_out_hook);
	nf_unregister_hook(&hwaddr_in_hook);
}
