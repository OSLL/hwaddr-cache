#ifndef __HWADDR_CACHE_HASH_H__
#define __HWADDR_CACHE_HASH_H__

#include <linux/kernel.h>

struct hwaddr_v4_entry;

typedef void (*hwaddr_v4_callback_t)(struct hwaddr_v4_entry *, void *);

void hwaddr_v4_update(__be32 remote, __be32 local, u8 const *ha,
			unsigned ha_len);
struct hwaddr_v4_entry *hwaddr_v4_lookup(__be32 remote, __be32 local);
void hwaddr_v4_remove_entries(__be32 local);
void hwaddr_v4_foreach(hwaddr_v4_callback_t cb, void *data);

#endif /* __HWADDR_CACHE_HASH_H__ */
