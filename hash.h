#ifndef __HWADDR_CACHE_HASH_H__
#define __HWADDR_CACHE_HASH_H__

#include <linux/kernel.h>

#include "hwaddr.h"

typedef void (*hwaddr_callback_t)(struct hwaddr_entry *, void *);

void hwaddr_v4_update(__be32 remote, __be32 local, u8 const *ha,
			unsigned ha_len);
void hwaddr_v6_update(struct in6_addr const *remote,
			struct in6_addr const *local, u8 const *ha,
			unsigned ha_len);

struct hwaddr_entry *hwaddr_v4_lookup(__be32 remote, __be32 local);
struct hwaddr_entry *hwaddr_v6_lookup(struct in6_addr const *remote,
			struct in6_addr const *local);

void hwaddr_v4_remove_entries(__be32 local);
void hwaddr_v6_remote_entries(struct in6_addr const *local);
void hwaddr_remove_entries(void);


void hwaddr_remove_old_entries(unsigned long timeout1, unsigned long timeout2);
void hwaddr_foreach(hwaddr_callback_t cb, void *data);

#endif /* __HWADDR_CACHE_HASH_H__ */
