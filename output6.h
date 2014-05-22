#ifndef __HWADDR_OUTPUT6_H__
#define __HWADDR_OUTPUT6_H__

struct sk_buff;

void hwaddr_initialize_hashidentrnd(void);
int hwaddr6_output(struct sk_buff *skb);

#endif /*__HWADDR_OUTPUT6_H__*/
