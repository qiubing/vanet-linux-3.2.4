/*
 *	IPv6 input
 *	Linux INET6 implementation
 *
 *	Authors:
 *	Pedro Roque		<roque@di.fc.ul.pt>
 *	Ian P. Morris		<I.P.Morris@soton.ac.uk>
 *
 *	Based in linux/net/ipv4/ip_input.c
 *
 *	This program is free software; you can redistribute it and/or
 *      modify it under the terms of the GNU General Public License
 *      as published by the Free Software Foundation; either version
 *      2 of the License, or (at your option) any later version.
 */
/* Changes
 *
 * 	Mitsuru KANDA @USAGI and
 * 	YOSHIFUJI Hideaki @USAGI: Remove ipv6_parse_exthdrs().
 */

#include <linux/errno.h>
#include <linux/types.h>
#include <linux/socket.h>
#include <linux/sockios.h>
#include <linux/net.h>
#include <linux/netdevice.h>
#include <linux/in6.h>
#include <linux/icmpv6.h>
#include <linux/mroute6.h>
#include <linux/slab.h>

#include <linux/netfilter.h>
#include <linux/netfilter_ipv6.h>

#include <net/sock.h>
#include <net/snmp.h>

#include <net/ipv6.h>
#include <net/protocol.h>
#include <net/transp_v6.h>
#include <net/rawv6.h>
#include <net/ndisc.h>
#include <net/ip6_route.h>
#include <net/addrconf.h>
#include <net/xfrm.h>



inline int ip6_rcv_finish( struct sk_buff *skb)
{
	if (skb_dst(skb) == NULL)
		ip6_route_input(skb);

	return dst_input(skb);
}

#if VANET_UNICAST_FORWARD
/*
 * VANET: unicast packet forward
 * return value is based on dev_queue_xmit() or NET_RX_DROP.
 */
int ip6_uc_forward_vanet(struct sk_buff *skb, struct net_device *dev)
{
	struct ipv6hdr *ipv6h;
	int err;

	printk("VANET-debug: %s\n", __func__);
	ipv6h = ipv6_hdr(skb);

	if (ipv6h->hop_limit <= 1) {
		printk("VANET-debug: %s hop_limit less than 1, DROP\n", __func__);
		goto out_free;
	}
	// TODO FIXME: since skb->len contains IPv6 header's length, can not compare with
	// VANET_DATALEN_MAX directly.
	if (skb->len > VANET_DATALEN_MAX) {
		printk("VANET-debug: %s MTU(%d) exceed, DROP\n", __func__, VANET_DATALEN_MAX);
		goto out_free;
	}
	/**
	 * VANET: TODO XXX make sure skb's headroom is big enough, and do not need reallocating
	 * frequently to improve performance.
	 */
	if (skb_cow(skb, sizeof(*ipv6h) + LL_RESERVED_SPACE(skb->dev))) {
		printk("VANET-debug: %s skb_cow failed, need to DROP\n", __func__);
		goto out_free;
	}

	ipv6h = ipv6_hdr(skb);
	ipv6h->hop_limit--;
	skb->protocol = htons(ETH_P_IPV6);
	IP6CB(skb)->flags |= IP6SKB_FORWARDED;

	memcpy(skb->data - ETH_HLEN, vanet_hhd, ETH_HLEN);
	skb_push(skb, ETH_HLEN);

	err = vanet_uc_find_path(&ipv6h->daddr, skb->data);
	if (err == 0)
		return dev_queue_xmit(skb);

	/*
	 * VANET: TODO XXX for (err != 0) which means find path failed, this packet will be
	 * dropped silently. Need informing the sender of the packet?
	 */
out_free:
	kfree_skb(skb);
	return NET_RX_DROP;
}
#endif

int ipv6_rcv(struct sk_buff *skb, struct net_device *dev, struct packet_type *pt, struct net_device *orig_dev)
{
	const struct ipv6hdr *hdr;
	u32 		pkt_len;
	struct inet6_dev *idev;
	struct net *net = dev_net(skb->dev);
#if VANET_UNICAST_FORWARD
	static int addrtype;
#endif
#if 0 //debug information for PowerPC
	int i;
#endif

	if (skb->pkt_type == PACKET_OTHERHOST) {
		kfree_skb(skb);
		return NET_RX_DROP;
	}

	rcu_read_lock();

	idev = __in6_dev_get(skb->dev);

	IP6_UPD_PO_STATS_BH(net, idev, IPSTATS_MIB_IN, skb->len);

	if ((skb = skb_share_check(skb, GFP_ATOMIC)) == NULL ||
	    !idev || unlikely(idev->cnf.disable_ipv6)) {
		IP6_INC_STATS_BH(net, idev, IPSTATS_MIB_INDISCARDS);
		goto drop;
	}

	memset(IP6CB(skb), 0, sizeof(struct inet6_skb_parm));

	/*
	 * Store incoming device index. When the packet will
	 * be queued, we cannot refer to skb->dev anymore.
	 *
	 * BTW, when we send a packet for our own local address on a
	 * non-loopback interface (e.g. ethX), it is being delivered
	 * via the loopback interface (lo) here; skb->dev = loopback_dev.
	 * It, however, should be considered as if it is being
	 * arrived via the sending interface (ethX), because of the
	 * nature of scoping architecture. --yoshfuji
	 */
	IP6CB(skb)->iif = skb_dst(skb) ? ip6_dst_idev(skb_dst(skb))->dev->ifindex : dev->ifindex;

	if (unlikely(!pskb_may_pull(skb, sizeof(*hdr))))
		goto err;

	hdr = ipv6_hdr(skb);

#if 0 //debug information for PowerPC
	printk("VANET-debug: %s DA<", __func__);
	for (i=0; i<16; i++)
		printk("%2x", hdr->daddr.s6_addr[i]);
	printk(">\tSA<");
	for (i=0; i<16; i++)
		printk("%2x", hdr->saddr.s6_addr[i]);
	printk(">\n");
#endif

	if (hdr->version != 6)
		goto err;

	/*
	 * RFC4291 2.5.3
	 * A packet received on an interface with a destination address
	 * of loopback must be dropped.
	 */
	if (!(dev->flags & IFF_LOOPBACK) &&
	    ipv6_addr_loopback(&hdr->daddr))
		goto err;

	/*
	 * RFC4291 2.7
	 * Multicast addresses must not be used as source addresses in IPv6
	 * packets or appear in any Routing header.
	 */
	if (ipv6_addr_is_multicast(&hdr->saddr))
		goto err;

	skb->transport_header = skb->network_header + sizeof(*hdr);
	IP6CB(skb)->nhoff = offsetof(struct ipv6hdr, nexthdr);

	pkt_len = ntohs(hdr->payload_len);

	/* pkt_len may be zero if Jumbo payload option is present */
	if (pkt_len || hdr->nexthdr != NEXTHDR_HOP) {
		if (pkt_len + sizeof(struct ipv6hdr) > skb->len) {
			IP6_INC_STATS_BH(net,
					 idev, IPSTATS_MIB_INTRUNCATEDPKTS);
			goto drop;
		}
		if (pskb_trim_rcsum(skb, pkt_len + sizeof(struct ipv6hdr))) {
			IP6_INC_STATS_BH(net, idev, IPSTATS_MIB_INHDRERRORS);
			goto drop;
		}
		hdr = ipv6_hdr(skb);
	}

	if (hdr->nexthdr == NEXTHDR_HOP) {
		if (ipv6_parse_hopopts(skb) < 0) {
			IP6_INC_STATS_BH(net, idev, IPSTATS_MIB_INHDRERRORS);
			rcu_read_unlock();
			return NET_RX_DROP;
		}
	}

	rcu_read_unlock();

	/* Must drop socket now because of tproxy. */
	skb_orphan(skb);

#if VANET_UNICAST_FORWARD
	addrtype = ipv6_addr_type(&hdr->daddr);
	if (!ipv6_addr_equal(&vanet_self_lladdr, &hdr->daddr) &&
			(addrtype & IPV6_ADDR_LINKLOCAL) &&
			!(addrtype & IPV6_ADDR_MULTICAST)) { //VANET: XXX FF02:xxx is LINKLOCAL
		return ip6_uc_forward_vanet(skb, dev);
	}
#endif

	return NF_HOOK(NFPROTO_IPV6, NF_INET_PRE_ROUTING, skb, dev, NULL,
		       ip6_rcv_finish);
err:
	IP6_INC_STATS_BH(net, idev, IPSTATS_MIB_INHDRERRORS);
drop:
	rcu_read_unlock();
	kfree_skb(skb);
	return NET_RX_DROP;
}

/*
 *	Deliver the packet to the host
 */


static int ip6_input_finish(struct sk_buff *skb)
{
	const struct inet6_protocol *ipprot;
	unsigned int nhoff;
	int nexthdr, raw;
	u8 hash;
	struct inet6_dev *idev;
	struct net *net = dev_net(skb_dst(skb)->dev);

	/*
	 *	Parse extension headers
	 */

	rcu_read_lock();
resubmit:
	idev = ip6_dst_idev(skb_dst(skb));
	if (!pskb_pull(skb, skb_transport_offset(skb)))
		goto discard;
	nhoff = IP6CB(skb)->nhoff;
	nexthdr = skb_network_header(skb)[nhoff];

	raw = raw6_local_deliver(skb, nexthdr);

	hash = nexthdr & (MAX_INET_PROTOS - 1);
	if ((ipprot = rcu_dereference(inet6_protos[hash])) != NULL) {
		int ret;

		if (ipprot->flags & INET6_PROTO_FINAL) {
			const struct ipv6hdr *hdr;

			/* Free reference early: we don't need it any more,
			   and it may hold ip_conntrack module loaded
			   indefinitely. */
			nf_reset(skb);

			skb_postpull_rcsum(skb, skb_network_header(skb),
					   skb_network_header_len(skb));
			hdr = ipv6_hdr(skb);
			if (ipv6_addr_is_multicast(&hdr->daddr) &&
			    !ipv6_chk_mcast_addr(skb->dev, &hdr->daddr,
			    &hdr->saddr) &&
			    !ipv6_is_mld(skb, nexthdr))
				goto discard;
		}
		if (!(ipprot->flags & INET6_PROTO_NOPOLICY) &&
		    !xfrm6_policy_check(NULL, XFRM_POLICY_IN, skb))
			goto discard;

		ret = ipprot->handler(skb);
		if (ret > 0)
			goto resubmit;
		else if (ret == 0)
			IP6_INC_STATS_BH(net, idev, IPSTATS_MIB_INDELIVERS);
	} else {
		if (!raw) {
			if (xfrm6_policy_check(NULL, XFRM_POLICY_IN, skb)) {
				IP6_INC_STATS_BH(net, idev,
						 IPSTATS_MIB_INUNKNOWNPROTOS);
				icmpv6_send(skb, ICMPV6_PARAMPROB,
					    ICMPV6_UNK_NEXTHDR, nhoff);
			}
		} else
			IP6_INC_STATS_BH(net, idev, IPSTATS_MIB_INDELIVERS);
		kfree_skb(skb);
	}
	rcu_read_unlock();
	return 0;

discard:
	IP6_INC_STATS_BH(net, idev, IPSTATS_MIB_INDISCARDS);
	rcu_read_unlock();
	kfree_skb(skb);
	return 0;
}


int ip6_input(struct sk_buff *skb)
{
	return NF_HOOK(NFPROTO_IPV6, NF_INET_LOCAL_IN, skb, skb->dev, NULL,
		       ip6_input_finish);
}

/*
 * VANET: safety multicast packets fast forward
 */
struct in6_addr vanet_mc_grp;
struct in6_addr vanet_self_lladdr;
unsigned char vanet_hhd[ETH_HLEN];

struct kmem_cache *vanet_node_cache __read_mostly;
struct vn_htentry vn_hash_table[VN_HTLEN] __read_mostly;

/*
 * Under spin_lock_bh of hte, run as fast as we can!
 */
static inline struct vanet_node *
vanet_find_node_release(struct vn_htentry *htep, struct in6_addr *addr, struct vanet_node **release)
{
	struct vanet_node *np, *npp, *temp;
	if (htep->count < 0) {
		printk("VANET-debug: %s FATAL ERROR\n", __func__);
		/*
		 * VANET: FIXME TODO what can we do, poor man!
		 */
		return NULL;
	}
	for (np=htep->first, npp=NULL; np!=NULL; ) {
		if (ipv6_addr_equal(&np->addr, addr)) {
			return np;
		} else {
			if (time_before(np->lvt, jiffies - HZ * VN_TIMEOUT)) { //timeout
				if (npp == NULL) { //np is the first in mostly situation
					htep->first = np->next;
					htep->count --;
					np->flags |= VANET_NODE_F_RELEASE;
					np->next = NULL;
					if (*release == NULL) {
						*release = np;
					} else {
						for (temp=(*release); temp->next!=NULL; temp=temp->next)
							;
						temp->next = np;
					}
					np = htep->first;
				} else {
					npp->next = np->next;
					htep->count --;
					np->flags |= VANET_NODE_F_RELEASE;
					np->next = NULL;
					if (*release != NULL) {
						for (temp=(*release); temp->next!=NULL; temp=temp->next)
							;
						temp->next = np;
					} else {
						*release = np;
					}
					np = npp->next;
				}
			} else {
				npp = np;
				np = np->next;
			}
		}
	}

	return NULL;
}

static inline struct vanet_node *
vanet_find_node_fast(struct vn_htentry *hte, struct in6_addr *addr)
{
	struct vanet_node *np;
	for (np=hte->first; np!=NULL; np=np->next) {
		if (ipv6_addr_equal(&np->addr, addr))
			return np;
	}

	return NULL;
}

static inline int
vanet_add_node(struct vn_htentry *hte, struct vanet_node *vn)
{
	vn->next = hte->first;
	hte->first = vn;
	hte->count++;
	printk("VANET-debug: %s hte count[%d] first<0x%p>, vn<0x%p>, vnext<0x%p>\n",
			__func__, hte->count, hte->first, vn, vn->next);
	return 0;
}

static inline int
vanet_check_packet_id(struct vanet_node *vn, u32 id)
{
	unsigned char *bm = vn->bitmap;
	int sf, sp, i;

	/*
	 * vanet bitmap only take care VANET_BM_TOTAL packet in a period of time,
	 * wrap the id.
	 */
	id = id % VANET_BM_TOTAL;

	/*
	 * have forwarded this packet and fast return.
	 */
	if (bm[id/8] & (1<<(id%8)))
		return 1;

	/*
	 * First of all, set up corresponding bit.
	 */
	bm[id/8] |= (1<<(id%8));

	/*
	 * Then, mask out protection interval
	 */
	sf = id + VANET_BM_OF + 1;
	sp = id + VANET_BM_TOTAL -VANET_BM_OP - 1;
	/*
	 * Since VANET_BM_INTERVAL is fixed, we can divide sub-situation specifically
	 */
#if (VANET_BM_INTERVAL > 8)
	for (i=(sf/8+1); i<(sp/8); i++)
		memset(&bm[i%VANET_BM_LEN], 0, sizeof(unsigned char));
	bm[(sf/8)%VANET_BM_LEN] &= ((1<<(sf%8))-1);
	bm[(sp/8)%VANET_BM_LEN] &= (~((1<<(sp%8+1))-1));
#else
	if ((sf/8)%VANET_BM_LEN == (sp/8)%VANET_BM_LEN) {
		bm[(sf/8)%VANET_BM_LEN] &= (((1<<(sf%8))-1) | (~((1<<(sp%8+1))-1)));
	} else {
		bm[(sf/8)%VANET_BM_LEN] &= ((1<<(sf%8))-1);
		bm[(sp/8)%VANET_BM_LEN] &= (~((1<<(sp%8+1))-1));
	}
#endif

	return 0;
}

#if VANET_UNICAST_FORWARD
/*
 * VANET: main forwarding procedure of unicast packet
 * return 0, find path and copy it's MAC address to path;
 * return -1, do not find path.
 */
int vanet_uc_find_path(struct in6_addr *dest, void *path)
{
	struct vn_htentry *htep;
	struct vanet_node *vnp;

	htep = &vn_hash_table[VN_HASH(*dest)];

	spin_lock_bh(&htep->lock);
	vnp = vanet_find_node_fast(htep, dest);
	if (vnp != NULL) {
		memcpy(path, vnp->mrt_via, ETH_ALEN);
		spin_unlock_bh(&htep->lock);
//		printk("VANET-debug: %s find next hop\n", __func__);
		return 0;
	} else {
		spin_unlock_bh(&htep->lock);
		printk("VANET-debug: %s DO NOT find next hop\n", __func__);
		return -1;
	}
}
#endif

/*
 * VANET: XXX check multicast packet duplicated?
 * return 0, if not forward this packet yet;
 * return 1, have forward this packet.
 */
int vanet_check_mc_dup(struct sk_buff *skb)
{
	int ret = 0;
	struct ipv6hdr *ipv6h;
#if VANET_UNICAST_FORWARD
	struct ethhdr *ethh;
#endif
	struct vn_htentry *htep;
	struct vanet_node *vnp, *vnp2, *release;
	u32 id;
	unsigned char *fl;
	int i;

	ipv6h = ipv6_hdr(skb);
#if VANET_UNICAST_FORWARD
	ethh = eth_hdr(skb);
#endif
	fl = ipv6h->flow_lbl;
	/*
	 * VANET: XXX __BIG_ENDIAN and __BIG_ENDIAN_BITFIELD in
	 * x86 and PowerPC.
	 */
#if defined(__LITTLE_ENDIAN_BITFIELD) //x86
//	printk("VANET-debug: %s (LE BITFIELD) fl[0] = 0x%x\n",
//			__func__, fl[0]);
#elif defined(__BIG_ENDIAN_BITFIELD) //PowerPC
//	printk("VANET-debug: %s (BE BITFIELD) fl[0] = 0x%x\n",
//			__func__, fl[0]);
#else
#error	"Not define __XXX_ENDIAN_BITFIELD"
#endif
	id = ((fl[0] & 0xf) << 16) + (fl[1] << 8) + fl[2];

	printk("VANET-debug: %s node<", __func__);
	for (i=0; i<sizeof(struct in6_addr); i++) {
		printk("%2x", ipv6h->saddr.s6_addr[i]);
	}
	printk(">\tid<%u>\n", id);

	htep = &vn_hash_table[VN_HASH(ipv6h->saddr)];
	release = NULL;

	spin_lock_bh(&htep->lock);
	vnp = vanet_find_node_release(htep, &ipv6h->saddr, &release);
	spin_unlock_bh(&htep->lock);

	if (release != NULL) {
		printk("VANET-debug: %s releasing node on hte[%d]\n",
				__func__, VN_HASH(ipv6h->saddr));
		for (vnp2=release; vnp2!=NULL; vnp2=vnp2->next) {
			printk("VANET-debug: %s RELEASE node<", __func__);
			for (i=0; i<sizeof(struct in6_addr); i++)
				printk("%2x", vnp2->addr.s6_addr[i]);
			printk(">\n");
			kmem_cache_free(vanet_node_cache, vnp2);
		}
	}

	/*
	 * VANET: XXX TODO BUG: during this lock gap vnp may be released!
	 */

	if (vnp != NULL) { // find node
		spin_lock_bh(&htep->lock);
		vnp->lvt = jiffies;
		ret = vanet_check_packet_id(vnp, id);
		spin_unlock_bh(&htep->lock);
	} else { // add node
		printk("VANET-debug: DO NOT FIND node\n");
		vnp2 = (struct vanet_node *)kmem_cache_alloc(vanet_node_cache,
								GFP_ATOMIC);
		if (vnp2 == NULL) {
			/*
			 * Cannot alloc memory immediately, forward packet unconditionally
			 */
			printk("VANET-debug: %s alloc vanet_node failed\n", __func__);
			return 0;
		}
		memset(vnp2, 0, sizeof(struct vanet_node));
		memcpy(&vnp2->addr, &ipv6h->saddr, sizeof(struct in6_addr));
		vnp2->next = NULL;
		vnp2->hte = htep;

		spin_lock_bh(&htep->lock);
		/**
		 * VANET: TODO re-finding is not needed in NON-SMP while under big lock.
		 */
		vnp = vanet_find_node_fast(htep, &ipv6h->saddr);
		if (vnp == NULL) { // add node can proceed
			vnp2->lvt = jiffies;
			ret = vanet_check_packet_id(vnp2, id);
			vanet_add_node(htep, vnp2);
			vnp = vnp2;
			spin_unlock_bh(&htep->lock);
			printk("VANET-debug: ADD node<");
			for (i=0; i<sizeof(struct in6_addr); i++)
				printk("%2x", vnp2->addr.s6_addr[i]);
			printk(">\n");
		} else { // during former process, node is added by other's
			vnp->lvt = jiffies;
			ret = vanet_check_packet_id(vnp, id);
			spin_unlock_bh(&htep->lock);
			kmem_cache_free(vanet_node_cache, vnp2);
			printk("VANET-debug: WARNING other process has added this node\n");
		}
	}

	/**
	 * If packet has not yet forwarded(ret == 0), which means I am first receiving this
	 * vanet node's packet <id> VANET Safety Message.
	 * Using this packet's info to build & update vanet's Messaging Relation Table (MRT).
	 * MRT is embedded in vanet_node hash table.
	 */
	/**
	 * VANET: TODO vanet_unicast_forward's code is a mess, need tuning.
	 */
#if VANET_UNICAST_FORWARD
//	printk("VANET-debug: %s generating or updating vanet MRT\n", __func__);
	if (ret == 0) {
		spin_lock_bh(&htep->lock);
		if ((ipv6h->hop_limit > vnp->mrt_hl) || (vnp->mrt_hl == 0)) { // find better via or new node
			vnp->mrt_update = jiffies;
			vnp->mrt_hl = ipv6h->hop_limit;
			memcpy(vnp->mrt_via, ethh->h_source, ETH_ALEN);
		} else {
			if (time_before(vnp->mrt_update, jiffies - HZ * VANET_MRT_FRESH_TIME)) { // old
				vnp->mrt_update = jiffies;
				vnp->mrt_hl = ipv6h->hop_limit;
				memcpy(vnp->mrt_via, ethh->h_source, ETH_ALEN);
			} else { // fresh
				if ((!memcmp(vnp->mrt_via, ethh->h_source, ETH_ALEN)) &&
							(vnp->mrt_hl == ipv6h->hop_limit)) {
					vnp->mrt_update = jiffies;
				}
			}
		}
		spin_unlock_bh(&htep->lock);

		printk("VANET-debug: %s VIA<", __func__);
		for (i=0; i<ETH_ALEN-1; i++)
			printk("%2x:", vnp->mrt_via[i]);
		printk("%2x>\tHOP_LIMIT<%u>\tTIME<%lu>\n", vnp->mrt_via[ETH_ALEN-1],
						vnp->mrt_hl, vnp->mrt_update);
	}
#endif

	return ret;
}

/*
 * VANET: init in ipv6 module's normal path
 */
int __init vanet_ipv6_init(void)
{
	int i;
	printk("VANET-debug: %s\n", __func__);

	/*
	 * VANET: TODO (add configuration interface) notice BE & LE,
	 * VN_MC_GRP's value is now stored in net/ipv6.h temporarily.
	 */
	ipv6_addr_set(&vanet_mc_grp, __cpu_to_be32(VN_MC_GRP_1),
				     __cpu_to_be32(VN_MC_GRP_2),
				     __cpu_to_be32(VN_MC_GRP_3),
				     __cpu_to_be32(VN_MC_GRP_4));
	printk("VANET-debug: vanet_mc_grp address is ");
	for (i=0; i<sizeof(struct in6_addr); i++) {
		printk("%2x", vanet_mc_grp.s6_addr[i]);
	}
	printk("\n");
	ipv6_eth_mc_map(&vanet_mc_grp, vanet_hhd);
	// vanet_hhd's source mac address is completed in addrconf_notify()
	/*
	 * VANET: ipv6 in ethernet prototype is 0x86dd
	 */
	vanet_hhd[ETH_HLEN-2] = 0x86;
	vanet_hhd[ETH_HLEN-1] = 0xdd;

	/*
	 * Slub initial
	 */
	vanet_node_cache = kmem_cache_create("vanet_node_cache",
			sizeof(struct vanet_node), 0, 0, NULL);

	if (vanet_node_cache == NULL) {
		/*
		 * VANET: TODO XXX how to deal with this tough situation?
		 */
		printk("VANET-debug: %s ERROR create vanet_node_cache failed\n", __func__);
	}

	/*
	 * Hash table initial
	 */
	for (i=0; i<VN_HTLEN; i++) {
		spin_lock_init(&vn_hash_table[i].lock);
		vn_hash_table[i].count = 0;
		vn_hash_table[i].first = NULL;
	}

	return 0;
}

/*
 * VANET: XXX specific multicast process
 *                      Powered by Vanet
 */
int ip6_mc_fast_forward(struct sk_buff *skb)
{
	struct ipv6hdr *ipv6h;

	ipv6h = ipv6_hdr(skb);

	if (ipv6h->hop_limit <= 1) {
		printk("VANET-debug: %s hop_limit less than 1, DROP\n", __func__);
		goto out_free;
	}

	/*
	 * VANET: XXX key process, check duplication of forwarded packet
	 */
	if (vanet_check_mc_dup(skb)) {
		printk("VANET-debug: %s packet has been forward, DROP\n", __func__);
		goto out_free;
	}

	/*
	 * VANET: XXX after skb_cow, skb's header is changed, any pointing value
	 * point to skb's header SHOULD be revalued.
	 * 	  TODO XXX make sure skb's headroom is big enough, and avoiding
	 * reallocating frequently.
	 */
	if (skb_cow(skb, sizeof(*ipv6h)+LL_RESERVED_SPACE(skb->dev))) {
		printk("VANET-debug: skb_cow failed, need to drop\n");
		goto out_free;
	}
	ipv6h = ipv6_hdr(skb);

	ipv6h->hop_limit--;
	IP6CB(skb)->flags |= IP6SKB_FORWARDED;

	/**
	 * VANET: TODO FIXME skb->len contains IPv6 header's length
	 */
	if (skb->len > VANET_DATALEN_MAX) {
		printk("VANET-debug: %s MTU(%d) exceed, DROP\n", __func__, VANET_DATALEN_MAX);
		goto out_free;
	}

	skb->protocol = htons(ETH_P_IPV6);
	/*
	 * VANET: XXX pay attention to vanet_hhd, it's fixed Ethernet Header for 
	 * all IPv6 multicast packet
	 */
	memcpy(skb->data-ETH_HLEN, vanet_hhd, ETH_HLEN);
	skb_push(skb, ETH_HLEN);

	return dev_queue_xmit(skb);

out_free:
	kfree_skb(skb);
	return 0;
}

int ip6_mc_input(struct sk_buff *skb)
{
	const struct ipv6hdr *hdr;
	int deliver;

	IP6_UPD_PO_STATS_BH(dev_net(skb_dst(skb)->dev),
			 ip6_dst_idev(skb_dst(skb)), IPSTATS_MIB_INMCAST,
			 skb->len);

	hdr = ipv6_hdr(skb);
	deliver = ipv6_chk_mcast_addr(skb->dev, &hdr->daddr, NULL);

	/*
	 * VANET: XXX free self-generated packet, and loopback is now disabled
	 * even though it is setted.
	 */
	if (deliver && ipv6_addr_equal(&vanet_self_lladdr, &hdr->saddr)) {
//		printk("VANET-debug: %s self-generated packet, DROP\n", __func__);
		kfree_skb(skb);
		return 0;
	}

#ifdef CONFIG_IPV6_MROUTE
	/*
	 *      IPv6 multicast router mode is now supported ;)
	 */
	if (dev_net(skb->dev)->ipv6.devconf_all->mc_forwarding &&
	    !(ipv6_addr_type(&hdr->daddr) & IPV6_ADDR_LINKLOCAL) &&
	    likely(!(IP6CB(skb)->flags & IP6SKB_FORWARDED))) {
		/*
		 * Okay, we try to forward - split and duplicate
		 * packets.
		 */
		struct sk_buff *skb2;
		struct inet6_skb_parm *opt = IP6CB(skb);

		/* Check for MLD */
		if (unlikely(opt->ra)) {
			/* Check if this is a mld message */
			u8 *ptr = skb_network_header(skb) + opt->ra;
			struct icmp6hdr *icmp6;
			u8 nexthdr = hdr->nexthdr;
			int offset;

			printk("VANET-debug: %s check for MLD\n", __func__);

			/* Check if the value of Router Alert
			 * is for MLD (0x0000).
			 */
			if ((ptr[2] | ptr[3]) == 0) {
				deliver = 0;

				if (!ipv6_ext_hdr(nexthdr)) {
					/* BUG */
					goto out;
				}
				offset = ipv6_skip_exthdr(skb, sizeof(*hdr),
							  &nexthdr);
				if (offset < 0)
					goto out;

				if (nexthdr != IPPROTO_ICMPV6)
					goto out;

				if (!pskb_may_pull(skb, (skb_network_header(skb) +
						   offset + 1 - skb->data)))
					goto out;

				icmp6 = (struct icmp6hdr *)(skb_network_header(skb) + offset);

				switch (icmp6->icmp6_type) {
				case ICMPV6_MGM_QUERY:
				case ICMPV6_MGM_REPORT:
				case ICMPV6_MGM_REDUCTION:
				case ICMPV6_MLD2_REPORT:
					deliver = 1;
					break;
				}
				goto out;
			}
			/* unknown RA - process it normally */
		}

		if (deliver)
			skb2 = skb_clone(skb, GFP_ATOMIC);
		else {
			skb2 = skb;
			skb = NULL;
		}

		if (skb2) {
			struct ipv6hdr *ipv6h;
			int i;

			ipv6h = ipv6_hdr(skb2);
			if (!ipv6_addr_equal(&vanet_mc_grp, &ipv6h->daddr)) {
				printk("VANET-debug: %s not vanet addr\n", __func__);
				printk("VANET-debug: skb's daddr is ");
				for (i=0; i<16; i++) printk("%2x", ipv6h->daddr.s6_addr[i]);
				printk("\n");

				ip6_mr_input(skb2);
			} else {
				/*
				 * VANET: process start point
				 */
				ip6_mc_fast_forward(skb2);
			}
		}
	}
out:
#endif
	if (likely(deliver)) {
#if 0 //debug information for PowerPC
		printk("VANET-debug: %s deliver to host stack\n", __func__);
#endif
		ip6_input(skb);
	}
	else {
		/* discard */
		kfree_skb(skb);
	}

	return 0;
}
