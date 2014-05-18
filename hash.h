#ifndef __HWADDR_ENTRIES_CACHE_H__
#define __HWADDR_ENTRIES_CACHE_H__

#include <linux/kernel.h>

struct hwaddr_entry;
struct net_device;

void hwaddr_update(struct net_device *dev, __be32 remote, __be32 local,
			u8 const *ha, unsigned ha_len);
struct hwaddr_entry *hwaddr_lookup(__be32 remote, __be32 local);

void hwaddr_clear_outdated(unsigned long timeout1, unsigned long timeout2);
void hwaddr_clear_cache(void);

typedef void (*hwaddr_hash_callback_t)(struct hwaddr_entry *, void *);
void hwaddr_foreach(hwaddr_hash_callback_t callback, void *data);

#endif /*__HWADDR_ENTRIES_CACHE_H__*/
