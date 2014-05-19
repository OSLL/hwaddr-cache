#include <linux/string.h>
#include <linux/slab.h>
#include <linux/version.h>
#include <net/dst.h>
#include <net/icmp.h>

#include "hash.h"
#include "output.h"
#include "route.h"

static struct dst_entry *hwaddr_dst_check(struct dst_entry *dst, u32 cookie)
{
	WARN_ON(1);
	return dst;
}

static unsigned int hwaddr_default_advmss(struct dst_entry const *dst)
{
	static unsigned int const hwaddr_max_advmss = 65495;
	static unsigned int const hwaddr_min_advmss = 256;

	unsigned int const advmss = max_t(unsigned int, dst->dev->mtu - 40,
				hwaddr_min_advmss);

	if (advmss > hwaddr_max_advmss)
		return hwaddr_max_advmss;

	return advmss;
}

static unsigned int hwaddr_mtu(struct dst_entry const *dst)
{
	static unsigned int const hwaddr_max_mtu = 65535;
	unsigned int const mtu = dst->dev->mtu;

	return min_t(unsigned int, mtu, hwaddr_max_mtu);
}

static u32 *hwaddr_cow_metrics(struct dst_entry *dst, unsigned long old)
{
	WARN_ON(1);
	return NULL;
}

static void hwaddr_dst_destroy(struct dst_entry *dst)
{
	struct hwaddr_entry *entry = (struct hwaddr_entry *)dst;
	pr_debug("hwaddr-cache: destroy entry for local %pI4 and remote %pI4\n",
				&entry->h_local, &entry->h_remote);
}

static void hwaddr_ifdown(struct dst_entry *dst, struct net_device *dev,
			int unused)
{
}

static struct dst_entry *hwaddr_negative_advice(struct dst_entry *dst)
{
	WARN_ON(1);
	return dst;
}

static void hwaddr_link_failure(struct sk_buff *skb)
{
	struct dst_entry *dst = skb_dst(skb);

	icmp_send(skb, ICMP_DEST_UNREACH, ICMP_HOST_UNREACH, 0);

	if (dst)
		dst_set_expires(dst, 0);
}

static void hwaddr_update_pmtu(struct dst_entry *dst, struct sock *sk,
			struct sk_buff *skb, u32 mtu)
{
#if 0
	static int const ip_rt_min_pmtu = 512 + 20 + 20;
	static int const ip_rt_mtu_expires = 10 * 60 * HZ;

	struct rtable *rt = (struct rtable *)dst;
#endif

	WARN_ON(1); // we do not update pmtu so far, but provide implemetation
#if 0
	if (dst->dev->mtu < mtu)
		return;

	if (mtu < ip_rt_min_pmtu)
		mtu = ip_rt_min_pmtu;

	if (rt->rt_pmtu == mtu && time_before(jiffies,
				dst->expires - ip_rt_mtu_expires / 2))
		return;

	rt->rt_pmtu = mtu;
	dst->expires = jiffies + ip_rt_mtu_expires;
#endif
}

static void hwaddr_redirect(struct dst_entry *dst, struct sock *sk,
			struct sk_buff *skb)
{
	WARN_ON(1);
}

static int hwaddr_local_out(struct sk_buff *skb)
{
	WARN_ON(1); // i don't understand why do we need this function;
	return -EPERM;
}

static struct neighbour *hwaddr_neigh_lookup(struct dst_entry const *dst,
			struct sk_buff *skb, const void *daddr)
{
	return NULL; //wait for netter times
}

static struct dst_ops hwaddr_dst_ops = {
	.family			=	AF_INET,
	.protocol		=	cpu_to_be16(ETH_P_IP),
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
	.redirect		=	hwaddr_redirect,
	.local_out		=	hwaddr_local_out,
	.neigh_lookup		=	hwaddr_neigh_lookup,
};

static struct kmem_cache *hwaddr_cache;

int hwaddr_cache_create(void)
{
	WARN_ON(hwaddr_cache);

	hwaddr_cache = KMEM_CACHE(hwaddr_entry, SLAB_HWCACHE_ALIGN);
	if (!hwaddr_cache)
	{
		pr_err("hwaddr-cache: cannot create entry cache\n");
		return -ENOMEM;
	}
	
	hwaddr_dst_ops.kmem_cachep = hwaddr_cache;

	return 0;
}

static void hwaddr_cache_destroy_barrier(void)
{
	static unsigned long const hwaddr_max_timeout = HZ * 2;

	unsigned long const expire = jiffies + hwaddr_max_timeout;
	while (time_before(jiffies, expire) && kmem_cache_shrink(hwaddr_cache))
		schedule_timeout_interruptible(MAX_SCHEDULE_TIMEOUT);

	if (kmem_cache_shrink(hwaddr_cache))
		pr_warn("hwaddr-cache: there are entries in use!\n");
}

void hwaddr_cache_destroy(void)
{
	hwaddr_clear_cache();
	hwaddr_cache_destroy_barrier();
	kmem_cache_destroy(hwaddr_cache);
}

static inline struct hwaddr_entry *__hwaddr_alloc(struct net_device *dev)
{
	return dst_alloc(&hwaddr_dst_ops, dev, 1, DST_OBSOLETE_NONE,
				DST_HOST | DST_NOCACHE | DST_NOCOUNT);
}

struct hwaddr_entry *hwaddr_alloc(struct net_device *dev, __be32 remote,
			__be32 local, u8 const *ha, unsigned ha_len)
{
	struct hwaddr_entry *entry = __hwaddr_alloc(dev);
	struct rtable *rt = &entry->h_rt;

	rt->rt_genid = rt_genid_ipv4(dev_net(dev));
	rt->rt_flags = 0;
	rt->rt_type = 0;
	rt->rt_is_input = 0;
	rt->rt_iif = 0;
	rt->rt_pmtu = 0;
	rt->rt_gateway = 0;
	rt->rt_uses_gateway = 0;
	INIT_LIST_HEAD(&rt->rt_uncached);

	rt->dst.output = hwaddr_output;

	atomic_long_set(&entry->h_stamp, (long)get_seconds());
	atomic_set(&entry->h_refcnt, 0);

	memcpy(entry->h_ha, ha, ha_len);
	entry->h_ha_len = ha_len;
	entry->h_remote = remote;
	entry->h_local = local;

	return entry;
}
