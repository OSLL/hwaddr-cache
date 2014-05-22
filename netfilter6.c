#include <linux/if_arp.h>
#include <linux/if_ether.h>
#include <linux/module.h>
#include <linux/netfilter_ipv6.h>
#include <linux/skbuff.h>
#include <linux/version.h>

#include <net/ip6_route.h>

#include "hash6.h"
#include "route6.h"

static unsigned int hwaddr_input_hook(
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,13,0)
			unsigned unused,
#else
			struct nf_hook_ops const *unused,
#endif
			struct sk_buff *skb, struct net_device const *in,
			struct net_device const *out,
			int (*okfn)(struct sk_buff *))
{
	struct net_device *target = NULL;
	struct ethhdr *llhdr = NULL;
	struct ipv6hdr *nhdr = NULL;

	if (!in)
		return NF_ACCEPT;

	if (in->type != ARPHRD_ETHER && in->type != ARPHRD_IEEE802)
		return NF_ACCEPT;

	llhdr = eth_hdr(skb);
	nhdr = ipv6_hdr(skb);
	hwaddr6_update(target, &nhdr->saddr, &nhdr->daddr, llhdr->h_source,
				ETH_ALEN);

	return NF_ACCEPT;
}

static unsigned int hwaddr_output_hook(
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,13,0)
			unsigned unused,
#else
			struct nf_hook_ops const *unused,
#endif
			struct sk_buff *skb, struct net_device const *in,
			struct net_device const *out,
			int (*okfn)(struct sk_buff *))
{
	struct hwaddr6_entry *entry = NULL;
	struct ipv6hdr *nhdr = ipv6_hdr(skb);

	rcu_read_lock();
	entry = hwaddr6_lookup(&nhdr->daddr, &nhdr->saddr);
	if (entry)
	{
		dst_hold(&entry->h_dst);
		skb_dst_drop(skb);
		skb_dst_set(skb, &entry->h_dst);
	}
	rcu_read_unlock();

	return NF_ACCEPT;
}

static struct nf_hook_ops hwaddr_input =
{
	.hook		=	hwaddr_input_hook,
	.owner		=	THIS_MODULE,
	.pf		=	NFPROTO_IPV6,
	.hooknum	=	NF_INET_LOCAL_IN,
	.priority	=	NF_IP6_PRI_LAST,
};

static struct nf_hook_ops hwaddr_output =
{
	.hook		=	hwaddr_output_hook,
	.owner		=	THIS_MODULE,
	.pf		=	NFPROTO_IPV6,
	.hooknum	=	NF_INET_LOCAL_OUT,
	.priority	=	NF_IP6_PRI_LAST,
};

int hwaddr6_netfilter_register(void)
{
	int rc = nf_register_hook(&hwaddr_output);
	if (rc)
		return rc;

	rc = nf_register_hook(&hwaddr_input);
	if (rc)
		nf_unregister_hook(&hwaddr_output);

	return rc;
}

void hwaddr6_netfilter_unregister(void)
{
	nf_unregister_hook(&hwaddr_input);
	nf_unregister_hook(&hwaddr_output);
}
