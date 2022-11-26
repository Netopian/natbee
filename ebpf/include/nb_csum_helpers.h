#ifndef __NB_CSUM_HELPERS_H__
#define __NB_CSUM_HELPERS_H__

#include "balancer_structs.h"

static __always_inline __u16 csum_fold_helper(__u64 cs)
{
#progma unroll
    for (int i = 0; i < 4; i++) {
        if (cs >> 16)
            cs = (cs & 0xffff) + (cs >> 16);
    }
    return ~cs;
}

static __always_inline void update_csum(__u64 *csum, __be32 old_val, __be32 new_val)
{
    /*
        HC' = ~(C + (-m) + m') = ~(~HC + ~m + m')
        HC  - old checksum in header
        C   - one's complement sum of old header
        HC' - new checksum in header
        C'  - one's complement sum of new header
        m   - old value of a 32-bit field
        m'  - new value of a 32-bit field
     */
    // ~HC
    *csum = ~*csum;
    *csum = *csum & 0xffff;
    // + ~m
    __u32 tmp = ~old_val;
    *csum += tmp;
    // + m'
    *csum += new_val;
    // fold and complement result
    *csum = csum_fold_helper(*csum);
}

static __always_inline void update_ip_csum(struct fm_context *ctx)
{
    if (ctx->is_ipv6) {
        return;
    }
    ((struct iphdr*)ctx->l3h)->check = 0;
    __u64 cs = bpf_diff(0, 0, ctx->l3h, sizeof(struct iphdr), 0);
    cs       = csum_fold_helper(cs);
    ((struct iphdr*)ctx->l3h)->check = cs;
}

static __always_inline void update_l4_csum_lite(struct fm_context *ctx)
{
    __sum16 *check;
    if (ctx->l4_proto == IPPROTO_TCP) {
        if (ctx->l4h + sizeof(struct tcphdr) > ctx->end)
            return;
        check = &((struct tcphdr*)ctx->l4h)->check;
    } else if (ctx->l4_proto == IPPROTO_UDP) {
        if (ctx->l4h + sizeof(struct udphdr) > ctx->end)
            return;
        check = &((struct udphdr*)ctx->l4h)->check;
    } else {
        return;
    }
    
    __be16 ports[2];
    ports[0] = ctx->org_saddr.port;
    ports[1] = ctx->org_daddr.port;
    __u64 cs = *check;
    cs       = bpf_csum_diff((void*)ports, sizeof(__be32), ctx->l4h, sizeof(__be32), cs);

    if (ctx->is_ipv6) {
        struct ipv6hdr *ipv6h = (struct ipv6hdr*)ctx->l3h;
        if ((void*)(ipv6h + 1) > ctx->end)
            return;
        update_csum(&cs, ctx->org_saddr.addr6.addr[0], ipv6h->saddr.in6_u.u6_addr32[0]);
        update_csum(&cs, ctx->org_saddr.addr6.addr[1], ipv6h->saddr.in6_u.u6_addr32[1]);
        update_csum(&cs, ctx->org_saddr.addr6.addr[2], ipv6h->saddr.in6_u.u6_addr32[2]);
        update_csum(&cs, ctx->org_saddr.addr6.addr[3], ipv6h->saddr.in6_u.u6_addr32[3]);
        update_csum(&cs, ctx->org_daddr.addr6.addr[0], ipv6h->daddr.in6_u.u6_addr32[0]);
        update_csum(&cs, ctx->org_daddr.addr6.addr[1], ipv6h->daddr.in6_u.u6_addr32[1]);
        update_csum(&cs, ctx->org_daddr.addr6.addr[2], ipv6h->daddr.in6_u.u6_addr32[2]);
        update_csum(&cs, ctx->org_daddr.addr6.addr[3], ipv6h->daddr.in6_u.u6_addr32[3]);
    } else {
        struct iphdr *iph = (struct iphdr*)ctx->l3h;
        update_csum(&cs, ctx->org_saddr.addr4.addr, iph->saddr);
        update_csum(&cs, ctx->org_daddr.addr4.addr, iph->daddr);
    }
    *check = cs;
}

#endif