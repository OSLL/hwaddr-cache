#include <linux/icmpv6.h>
#include <linux/string.h>
#include <linux/slab.h>
#include <linux/version.h>
#include <net/addrconf.h>
#include <net/dst.h>

#include "hash6.h"
#include "output6.h"
#include "route6.h"

static struct dst_entry *hwaddr_dst_check(struct dst_entry *dst, u32 cookie)
{
	WARN_ON(1);
	return dst;
}

static unsigned int hwaddr_default_advmss(struct dst_entry const *dst)
{
	static unsigned int const hwaddr_max_plen = 65535;

	struct net_device *dev = dst->dev;
	struct net *net = dev_net(dev);
	unsigned int advmss = dst_mtu(dst) -
				sizeof(struct ipv6hdr) - sizeof(struct tcphdr);

	if (advmss < net->ipv6.sysctl.ip6_rt_min_advmss)
		advmss = net->ipv6.sysctl.ip6_rt_min_advmss;

	if (advmss > hwaddr_max_plen - sizeof(struct tcphdr))
		advmss = hwaddr_max_plen;

	return advmss;
}

static unsigned int hwaddr_mtu(struct dst_entry const *dst)
{
	static unsigned int const hwaddr_min_mtu = 1280;

	struct inet6_dev *idev = NULL;
	unsigned int mtu = hwaddr_min_mtu;

	rcu_read_lock();
	idev = __in6_dev_get(dst->dev);
	if (idev)
		mtu = idev->cnf.mtu6;
	rcu_read_unlock();

	return mtu;
}

static u32 *hwaddr_cow_metrics(struct dst_entry *dst, unsigned long old)
{
	WARN_ON(1);
	return NULL;
}

static void hwaddr_dst_destroy(struct dst_entry *dst)
{
	struct hwaddr6_entry *entry = (struct hwaddr6_entry *)dst;
	struct inet6_dev *idev = entry->h_rt.rt6i_idev;

	if (idev)
	{
		entry->h_rt.rt6i_idev = NULL;
		in6_dev_put(idev);
	}

	pr_debug("hwaddr-cache6: destroy entry for local %pI6 and remote %pI6\n",
				&entry->h_local, &entry->h_remote);
}

static void hwaddr_ifdown(struct dst_entry *dst, struct net_device *dev,
			int unused)
{
	struct hwaddr6_entry *entry = (struct hwaddr6_entry *)dst;
	struct rt6_info *rt = (struct rt6_info *)&entry->h_rt;
	struct inet6_dev *idev = rt->rt6i_idev;
	struct net_device *lp_dev = dev_net(dev)->loopback_dev;

	if (dev != lp_dev && idev && idev->dev == dev)
	{
		struct inet6_dev *lp_idev = in6_dev_get(lp_dev);
		if (lp_idev)
		{
			rt->rt6i_idev = lp_idev;
			in6_dev_put(idev);
		}
	}
}

static struct dst_entry *hwaddr_negative_advice(struct dst_entry *dst)
{
	WARN_ON(1);
	return dst;
}

static void hwaddr_link_failure(struct sk_buff *skb)
{
	icmpv6_send(skb, ICMPV6_DEST_UNREACH, ICMPV6_ADDR_UNREACH, 0);
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,6,0)
static void hwaddr_update_pmtu(struct dst_entry *dst, struct sock *sk,
			struct sk_buff *skb, u32 mtu)
#else
static void hwaddr_update_pmtu(struct dst_entry *dst, u32 mtu)
#endif
{
	WARN_ON(1);
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,6,0)
static void hwaddr_redirect(struct dst_entry *dst, struct sock *sk,
			struct sk_buff *skb)
{
	WARN_ON(1);
}
#endif

static int hwaddr_local_out(struct sk_buff *skb)
{
	WARN_ON(1); // i don't understand why do we need this function;
	return -EPERM;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,1,0)
static struct neighbour *hwaddr_neigh_lookup(struct dst_entry const *dst,
			struct sk_buff *skb, const void *daddr)
{
	WARN_ON(1);
	return NULL; //wait for better times
}
#endif

static struct dst_ops hwaddr_dst_ops = {
	.family			=	AF_INET6,
	.protocol		=	cpu_to_be16(ETH_P_IPV6),
	.check			=	hwaddr_dst_check,
	.default_advmss		=	hwaddr_default_advmss,
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,2,0)
	.default_mtu		=	hwaddr_mtu,
#else
	.mtu			=	hwaddr_mtu,
#endif
	.cow_metrics		=	hwaddr_cow_metrics,
	.destroy		=	hwaddr_dst_destroy,
	.ifdown			=	hwaddr_ifdown,
	.negative_advice	=	hwaddr_negative_advice,
	.link_failure		=	hwaddr_link_failure,
	.update_pmtu		=	hwaddr_update_pmtu,
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,6,0)
	.redirect		=	hwaddr_redirect,
#endif
	.local_out		=	hwaddr_local_out,
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,1,0)
	.neigh_lookup		=	hwaddr_neigh_lookup,
#endif
};

static struct kmem_cache *hwaddr_cache;

int hwaddr6_cache_create(void)
{
	WARN_ON(hwaddr_cache);

	hwaddr_cache = KMEM_CACHE(hwaddr6_entry, SLAB_HWCACHE_ALIGN);
	if (!hwaddr_cache)
	{
		pr_err("hwaddr-cache6: cannot create entry cache\n");
		return -ENOMEM;
	}
	
	hwaddr_dst_ops.kmem_cachep = hwaddr_cache;

	return 0;
}

static void hwaddr6_cache_destroy_barrier(void)
{
	static unsigned long const hwaddr_max_timeout = HZ * 2;

	unsigned long const expire = jiffies + hwaddr_max_timeout;
	while (time_before(jiffies, expire) && kmem_cache_shrink(hwaddr_cache))
		schedule_timeout_interruptible(MAX_SCHEDULE_TIMEOUT);

	if (kmem_cache_shrink(hwaddr_cache))
		pr_warn("hwaddr-cache6: there are entries in use!\n");
}

void hwaddr6_cache_destroy(void)
{
	hwaddr6_clear_cache();
	hwaddr6_cache_destroy_barrier();
	kmem_cache_destroy(hwaddr_cache);
}

#ifndef DST_OBSOLETE_NONE
#define DST_OBSOLETE_NONE	0
#endif

static inline struct hwaddr6_entry *__hwaddr_alloc(struct net_device *dev)
{
	return dst_alloc(&hwaddr_dst_ops, dev, 1, DST_OBSOLETE_NONE,
				DST_HOST | DST_NOCACHE | DST_NOCOUNT);
}

struct hwaddr6_entry *hwaddr6_alloc(struct net_device *dev,
			struct in6_addr *remote, struct in6_addr *local,
			u8 const *ha, unsigned ha_len)
{
	struct hwaddr6_entry *entry = NULL;
	struct rt6_info *rt = NULL;
	struct inet6_dev *idev = in6_dev_get(dev);

	if (!idev)
	{
		pr_err("hwaddr-cache6: not ipv6 device\n");
		return NULL;
	}

	entry = __hwaddr_alloc(dev);
	if (!entry)
	{
		in6_dev_put(idev);
		pr_err("hwaddr-cache6: cannot allocate memory\n");
		return NULL;
	}

	rt = &entry->h_rt;
	rt->dst.output = hwaddr6_output;
	rt->rt6i_idev = idev;

	atomic_long_set(&entry->h_stamp, (long)get_seconds());
	atomic_set(&entry->h_refcnt, 0);

	memcpy(entry->h_ha, ha, ha_len);
	entry->h_ha_len = ha_len;
	entry->h_remote = *remote;
	entry->h_local = *local;

	return entry;
}
