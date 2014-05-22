#ifndef __HWADDR_ENTRIES_CACHE6_H__
#define __HWADDR_ENTRIES_CACHE6_H__

#include <linux/kernel.h>

struct hwaddr6_entry;
struct net_device;
struct in6_addr;

void hwaddr6_update(struct net_device *dev, struct in6_addr *remote,
			struct in6_addr *local, u8 const *ha, unsigned ha_len);
struct hwaddr6_entry *hwaddr6_lookup(struct in6_addr *remote,
			struct in6_addr *local);

void hwaddr6_clear_outdated(unsigned long timeout1, unsigned long timeout2);
void hwaddr6_clear_cache(void);

typedef void (*hwaddr6_hash_callback_t)(struct hwaddr6_entry *, void *);
void hwaddr6_foreach(hwaddr6_hash_callback_t callback, void *data);

#endif /*__HWADDR_ENTRIES_CACHE6_H__*/
