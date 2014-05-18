#include <net/ip.h>

#include "route.h"

static int hwaddr_connected_output(struct hwaddr_entry *entry,
			struct sk_buff *skb)
{
	struct net_device *dev = entry->h_rt.dst.dev;
	int err = dev_hard_header(skb, dev, ntohs(skb->protocol),
				entry->h_ha, NULL, skb->len);

	if (err >= 0)
		err = dev_queue_xmit(skb);
	else
	{
		err = -EINVAL;
		kfree_skb(skb);
	}

	return err;
}

static inline int hwaddr_finish_output2(struct sk_buff *skb)
{
	struct dst_entry *dst = skb_dst(skb);
	struct hwaddr_entry *entry = (struct hwaddr_entry *)dst;
	struct net_device *dev = dst->dev;
	unsigned int hh_len = LL_RESERVED_SPACE(dev);

	if (unlikely(skb_headroom(skb) < hh_len && dev->header_ops))
	{
		struct sk_buff *skb2;

		skb2 = skb_realloc_headroom(skb, LL_RESERVED_SPACE(dev));
		if (skb2 == NULL)
		{
			kfree_skb(skb);
			return -ENOMEM;
		}
		if (skb->sk)
			skb_set_owner_w(skb2, skb->sk);
		consume_skb(skb);
		skb = skb2;
	}

	return hwaddr_connected_output(entry, skb);
}

static int hwaddr_finish_output(struct sk_buff *skb)
{
#if defined(CONFIG_XFRM)
	if (skb_dst(skb)->xfrm != NULL)
	{
		IPCB(skb)->flags |= IPSKB_REROUTED;
		return dst_output(skb);
	}
#endif

	if (skb->len > ip_skb_dst_mtu(skb) && !skb_is_gso(skb))
		return ip_fragment(skb, hwaddr_finish_output2);
	else
		return hwaddr_finish_output2(skb);
}

int hwaddr_output(struct sk_buff *skb)
{
	struct net_device *dev = skb_dst(skb)->dev;

	IP_UPD_PO_STATS(dev_net(dev), IPSTATS_MIB_OUT, skb->len);

	skb->dev = dev;
	skb->protocol = htons(ETH_P_IP);

	return NF_HOOK_COND(NFPROTO_IPV4, NF_INET_POST_ROUTING, skb, NULL, dev,
				hwaddr_finish_output,
				!(IPCB(skb)->flags & IPSKB_REROUTED));
}
