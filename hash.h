#ifndef __HWADDR_CACHE_HASH_H__
#define __HWADDR_CACHE_HASH_H__

#include <linux/kernel.h>

struct hwaddr_entry;

typedef void (*hwaddr_callback_t)(struct hwaddr_entry *, void *);

void hwaddr_update(__be32 remote, __be32 local, u8 const *ha, unsigned ha_len);
struct hwaddr_entry *hwaddr_lookup(__be32 remote, __be32 local);
void hwaddr_remove_entries(__be32 local);
void hwaddr_remove_old_entries(unsigned long timeout1, unsigned long timeout2);
void hwaddr_foreach(hwaddr_callback_t cb, void *data);

#endif /* __HWADDR_CACHE_HASH_H__ */
