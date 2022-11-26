// +build ignore

#include "nb_structs.h"
#include "nb_maps.h"
#include "nb_helpers.h"
#include "nb_csum_helpers.h"

static __always_inline struct fm_sockaddr* get_rs(struct fm_service *srv, struct fm_sockaddr *key, __u32 cpu)
{
    __u32 *inner_fd = bpf_map_lookup_elem(&map_nat_rs, key);
    if (!inner_fd) {
        return 0;
    }

    struct fm_realserver *val = bpf_map_lookup_elem(inner_fd, &cpu);
    if (!val) {
        return 0;
    }

    __u32 inner_key = val->idx;
    val->idx++;
    if (val->idx >= srv->rs_cnt) {
        val->idx = 0;
    }

    val = bpf_map_lookup_elem(inner_fd, &inner_key);
    if (!val) {
        return 0;
    }
    return &val->addr;
}

static __always_inline enum fm_action get_or_gen_conn(struct fm_context *ctx)
{
    // in_conn
    struct fm_conn in_conn;
    __builtin_memset(&in_conn, 0, sizeof(in_conn));
    in_conn.saddr.l4p = ctx->l4_proto;
    in_conn.daddr.l4p = ctx->l4_proto;
    if (ctx->is_ipv6) {
        in_conn.saddr.af = AF_INET6;
        in_conn.daddr.af = AF_INET6;
        __builtin_memcpy(&in_conn.saddr.addr6, &(((struct ipv6hdr*)ctx->l3h)->saddr), 16);
        __builtin_memcpy(&in_conn.daddr.addr6, &(((struct ipv6hdr*)ctx->l3h)->daddr), 16);
    } else {
        in_conn.saddr.af = AF_INET;
        in_conn.daddr.af = AF_INET;
        in_conn.saddr.addr4.addr = ((struct ipvhdr*)ctx->l3h)->saddr;
        in_conn.daddr.addr4.addr = ((struct ipvhdr*)ctx->l3h)->daddr;
    }
    in_conn.saddr.port = ((struct udphdr*)ctx->l4h)->source;
    in_conn.daddr.port = ((struct udphdr*)ctx->l4h)->dest;

    struct fm_redirect *look_fwd = bpf_map_lookup_elem(&map_nat_conn, &in_conn);
    if (look_fwd) {
        ctx->fwd     = *look_fwd;
        look_fwd->ts = bpf_ktime_get_ns();
        return FM_OK;
    }

    struct fm_service *srv = bpf_map_lookup_elem(&map_nat_srv, &in_conn.daddr);
    if (!srv || !srv->rs_cnt) {
        return FM_PASS;
    }

    struct fm_sockaddr *rs = get_rs(srv, &in_conn.daddr, ctx->cpu);
    if (!rs) {
        return FM_DROP;
    }

    // build postive conn redirect data
    ctx->fwd.rconn.saddr      = in_conn.saddr;
    ctx->fwd.rconn.daddr      = *rs;
    ctx->fwd.rconn.daddr.port = srv->rport;
    ctx->fwd.rdev_idx         = srv->ldev_idx;
    ctx->fwd.ts               = bpf_ktime_get_ns();
    ctx->fwd.positive         = FM_SET;

    // build reverse conn
    struct fm_conn rin_conn;
    rin_conn.saddr = ctx->fwd.rconn.daddr;
    rin_conn.daddr = ctx->fwd.rconn.saddr;

    // build reverse conn redirect data
    struct fm_redirect rev;
    __builtin_memset(&rev, 0, sizeof(rev));
    rev.rconn.saddr  = in_conn.daddr;
    rev.rconn.daddr  = in_conn.saddr;
    rev.rdev_idx     = srv->vdev_idx;
    rev.ts           = ctx->fwd.ts;

    long update_ret = bpf_map_update_elem(&map_nat_conn, &in_conn, &ctx->fwd, BPF_NOEXIST);
    if (update_ret) {
        return FM_DROP;
    }
    update_ret = bpf_map_update_elem(&map_nat_conn, &rin_conn, &ctx->rev, BPF_NOEXIST);
    if (update_ret) {
        bpf_map_delete_elem(&map_nat_conn, &in_conn)
        return FM_DROP;
    }

    return FM_OK;
}

SEC("xdp_nat")
int xdp_l4_nat(struct xdp_md *xdp_ctx)
{
    struct fm_context ctx;
    __builtin_memset(&ctx, 0, sizeof*ctx);
    ctx.end       = (void*)(long)xdp_ctx->data_end;
    ctx.begin     = (void*)(long)xdp_ctx->data;
    ctx.stack_ctx = (void*)xdp_ctx;
    ctx.cpu       = bpf_get_smp_processor_id();

    enum fm_action rc = parse_ctx(&ctx);
    if (rc != FM_OK) {
        return xdp_act(rc);
    }

    rc = get_or_gen_conn(&ctx);
    if (rc != FM_OK) {
        return xdp_act(rc);
    }

    rc = swap_addr(&ctx);
    if (rc != FM_OK) {
        if (rc == FM_UNREACH) {
            struct fm_neigh_info ev;
            ev.local = ctx.fwd.rconn.saddr;
            ev.neigh = ctx.fwd.rconn.daddr;
            bpf_perf_event_output(ctx.stack_ctx, &map_nat_event, BPF_F_CURRENT_CPU, &ev, sizeof(ev));
        }
        return xdp_act(rc);
    }

    rc = dec_ttl(&ctx);
    if (rc != FM_OK) {
        return xdp_act(rc);
    }

    update_ip_csum(&ctx);
    update_l4_csum_lite(&ctx);

    return bpf_redirect(ctx.fwd.rdev.idx, 0);
}

char __license[] SEC("license") = "GPL";