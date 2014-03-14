#ifndef HWADDR_HASHTABLE_H
#define HWADDR_HASHTABLE_H

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,1,0)

#include "hashtable_old.h"
#define hack_for_each_rcu(name, obj, node, member, key) hash_for_each_possible_rcu(name, obj, node, member, key)
#define hack_for_each_safe(name, bkt, node, tmp, obj, member) hash_for_each_safe(name, bkt, node, tmp, obj, member)

#else

#include <linux/hashtable.h>
#define hack_for_each_rcu(name, obj, node, member, key) hash_for_each_possible_rcu(name, obj, member, key)
#define hack_for_each_safe(name, bkt, node, tmp, obj, member) hash_for_each_safe(name, bkt, tmp, obj, member)

#endif /*LINUX_VERSION_CODE < KERNEL_VERSION(3,1,0)*/

#endif /*HWADDR_HASHTABLE_H*/
