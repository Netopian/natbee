// +build ignore

#include "nb_structs.h"
#include "nb_maps.h"
#include "nb_helpers.h"
#include "nb_csum_helpers.h"

#define CNT_STORE_IDX       65535
#define PUT_STORE_IDX       65534
#define GET_STORE_IDX       65533
#define MIN_PORT_NO         5001
#define MAX_PORT_NO         65536
#define MAX_COLLISION_TIMES 3
#define STRATEGY_SHARED     0
#define STRATEGY_EXCLUSIVE  1

static __always_inline struct nb_sockaddr* select_real_server(struct nb_service *srv, struct nb_sockaddr *key, __u32 cpu)
{
    __u32 *inner_fd = bpf_map_lookup_elem(&nb_map_fnat_real_server, key);
    if (!inner_fd) {
        return 0;
    }

    struct nb_real_server *val = bpf_map_lookup_elem(inner_fd, &cpu);
    if (!val) {
        return 0;
    }

    __u32 inner_key = val->idx;
    val->idx++;
    if (val->idx >= srv->real_server_cnt) {
        val->idx = 0;
    }

    val = bpf_map_lookup_elem(inner_fd, &inner_key);
    if (!val) {
        return 0;
    }
    return &val->addr;
}

static __always_inline __be16 select_shared_port(struct nb_sockaddr *src, struct nb_sockaddr *dst)
{
    struct nb_connection conn;
    conn.saddr = *src;
    conn.daddr = *dst;
    struct nb_redirect *exist = bpf_map_lookup_elem(&nb_map_fnat_connection, &conn);
    if (!exist) {
        return conn.daddr.port;
    }

    __u16 port = bpf_ntohs(conn.daddr.port);
    for (int i = 0; i < MAX_COLLISION_TIMES; i++) {
        __u32 rand = bpf_get_prandom_u32();
        port += (__u16)(rand % MAX_PORT_NO);
        port  = port < MIN_PORT_NO ? port + MIN_PORT_NO : port;
        conn.daddr.port = bpf_htons(port);
        exist = bpf_map_lookup_elem(&nb_map_fnat_connection, &conn);
        if (!exist) {
            return conn.daddr.port;
        }
    }
    return 0;
}

static __always_inline __be16 select_exclusive_port(__u32 cpu)
{
    __u32 *inner_fd = bpf_map_lookup_elem(&nb_map_fnat_port, &cpu);
    if (!inner_fd) {
        return 0;
    }
    __u32 inner_key = CNT_STORE_IDX;
    __u32 *cnt = bpf_map_lookup_elem(inner_fd, &inner_key);
    if (!cnt || !*cnt) {
        return 0;
    }
    inner_key = GET_STORE_IDX;
    __u32 *get = bpf_map_lookup_elem(inner_fd, &inner_key);
    if (!get) {
        return 0;
    }
    __u32 *port = bpf_map_lookup_elem(inner_fd, get);
    if (!port || !*port) {
        return 0;
    }
    inner_key = *port;
    *get      = *get >= *cnt - 1 ? 0 : *get + 1;
    *port     = 0;

    return bpf_htons((__be16)inner_key);
}

static __always_inline void release_port(__be16 port)
{
    __u32 val = 0;
    __u32 key = bpf_ntohs(port);
    bpf_map_update_elem(&nb_map_fnat_release_port, &key, &val, BPF_ANY);
}

static __always_inline enum nb_action get_or_gen_conn(struct nb_context *ctx)
{
    // forward
    struct nb_connection fwd_key;
    __builtin_memset(&fwd_key, 0, sizeof(fwd_key));
    fwd_key.saddr.l4_proto = ctx->l4_proto;
    fwd_key.daddr.l4_proto = ctx->l4_proto;
    if (ctx->is_ipv6) {
        fwd_key.saddr.af = AF_INET6;
        fwd_key.daddr.af = AF_INET6;
        __builtin_memcpy(&fwd_key.saddr.addr6, &(((struct ipv6hdr*)ctx->l3h)->saddr), 16);
        __builtin_memcpy(&fwd_key.daddr.addr6, &(((struct ipv6hdr*)ctx->l3h)->daddr), 16);
    } else {
        fwd_key.saddr.af = AF_INET;
        fwd_key.daddr.af = AF_INET;
        fwd_key.saddr.addr4.addr = ((struct iphdr*)ctx->l3h)->saddr;
        fwd_key.daddr.addr4.addr = ((struct iphdr*)ctx->l3h)->daddr;
    }
    fwd_key.saddr.port = ((struct udphdr*)ctx->l4h)->source;
    fwd_key.daddr.port = ((struct udphdr*)ctx->l4h)->dest;

    struct nb_redirect *look_fwd = bpf_map_lookup_elem(&nb_map_fnat_connection, &fwd_key);
    if (look_fwd) {
        ctx->forward       = *look_fwd;
        look_fwd->ts       = bpf_ktime_get_ns();
        look_fwd->is_local = NB_SET;
        return NB_ACT_OK;
    }

    struct nb_service *srv = bpf_map_lookup_elem(&nb_map_fnat_service, &fwd_key.daddr);
    if (!srv || !srv->real_server_cnt) {
        return NB_ACT_PASS;
    }

    struct nb_sockaddr *rs = select_real_server(srv, &fwd_key.daddr, ctx->cpu);
    if (!rs) {
        return NB_ACT_DROP;
    }

    // build forward redirect data
    ctx->forward.redirect.saddr      = srv->laddr;
    ctx->forward.redirect.saddr.port = fwd_key.saddr.port;
    ctx->forward.redirect.daddr      = *rs;
    ctx->forward.redirect.daddr.port = srv->real_port;
    ctx->forward.redirect_if_idx     = srv->local_if_idx;
    ctx->forward.is_local            = NB_SET;
    ctx->forward.is_local_port       = NB_UNSET; // this conn will not use exclusive port
    ctx->forward.positive            = NB_SET;
    ctx->forward.ts                  = bpf_ktime_get_ns();
    if (srv->strategy == STRATEGY_SHARED) {
        ctx->forward.redirect.saddr.port = select_shared_port(&ctx->forward.redirect.daddr, &ctx->forward.redirect.saddr);
    } else if (srv->strategy == STRATEGY_EXCLUSIVE) {
        ctx->forward.redirect.saddr.port = select_exclusive_port(ctx->cpu);
    } else {
        return NB_ACT_PASS;
    }

    if (!ctx->forward.redirect.saddr.port) {
        return NB_ACT_PASS;
    }

    // reverse
    struct nb_connection rvs_key;
    rvs_key.saddr = ctx->forward.redirect.daddr;
    rvs_key.daddr = ctx->forward.redirect.saddr;
    // build reverse conn redirect data
    struct nb_redirect reverse;
    __builtin_memset(&reverse, 0, sizeof(reverse));
    reverse.redirect.saddr  = fwd_key.daddr;
    reverse.redirect.daddr  = fwd_key.saddr;
    reverse.redirect_if_idx = srv->vitual_if_idx;
    reverse.is_local        = NB_SET;
    reverse.is_local_port   = NB_SET; // this conn will use exclusive port
    reverse.ts              = ctx->forward.ts;

    long update_ret = bpf_map_update_elem(&nb_map_fnat_connection, &fwd_key, &ctx->forward, BPF_NOEXIST);
    if (update_ret) {
        if (srv->strategy == STRATEGY_EXCLUSIVE) {
            release_port(ctx->forward.redirect.saddr.port);
        }
        return NB_ACT_DROP;
    }
    update_ret = bpf_map_update_elem(&nb_map_fnat_connection, &rvs_key, &reverse, BPF_NOEXIST);
    if (update_ret) {
        bpf_map_delete_elem(&nb_map_fnat_connection, &fwd_key);
        if (srv->strategy == STRATEGY_EXCLUSIVE) {
            release_port(ctx->forward.redirect.saddr.port);
        }
        return NB_ACT_DROP;
    }

    return NB_ACT_OK;
}

SEC("xdp_fnat")
int nb_xdp_fnat(struct xdp_md *xdp_ctx)
{
    struct nb_context ctx;
    __builtin_memset(&ctx, 0, sizeof(ctx));
    ctx.end       = (void*)(long)xdp_ctx->data_end;
    ctx.begin     = (void*)(long)xdp_ctx->data;
    ctx.stack_ctx = (void*)xdp_ctx;
    ctx.cpu       = bpf_get_smp_processor_id();

    enum nb_action act = nb_parse_ctx(&ctx);
    if (act != NB_ACT_OK) {
        return nb_xdp_act(act);
    }

    act = get_or_gen_conn(&ctx);
    if (act != NB_ACT_OK) {
        return nb_xdp_act(act);
    }

    act = nb_swap_addr(&ctx);
    if (act != NB_ACT_OK) {
        if (act == NB_ACT_UNREACH) {
            struct nb_neigh_event ev;
            ev.local = ctx.forward.redirect.saddr;
            ev.neigh = ctx.forward.redirect.daddr;
            bpf_perf_event_output(ctx.stack_ctx, &nb_map_fnat_event, BPF_F_CURRENT_CPU, &ev, sizeof(ev));
        }
        return nb_xdp_act(act);
    }

    act = nb_dec_ttl(&ctx);
    if (act != NB_ACT_OK) {
        return nb_xdp_act(act);
    }

    nb_update_ip_csum(&ctx);
    nb_update_l4_csum_incre(&ctx);

    return bpf_redirect(ctx.forward.redirect_if_idx, 0);
}

SEC("tc_fnat")
int nb_tc_fnat(struct __sk_buff *skb)
{
    struct nb_context ctx;
    __builtin_memset(&ctx, 0, sizeof(ctx));
    ctx.end       = (void*)(long)skb->data_end;
    ctx.begin     = (void*)(long)skb->data;
    ctx.stack_ctx = (void*)skb;
    ctx.cpu       = bpf_get_smp_processor_id();

    enum nb_action act = nb_parse_ctx(&ctx);
    if (act != NB_ACT_OK) {
        return nb_tc_act(act);
    }

    act = get_or_gen_conn(&ctx);
    if (act != NB_ACT_OK) {
        return nb_tc_act(act);
    }

    act = nb_swap_addr(&ctx);
    if (act != NB_ACT_OK) {
        if (act == NB_ACT_UNREACH) {
            struct nb_neigh_event ev;
            ev.local = ctx.forward.redirect.saddr;
            ev.neigh = ctx.forward.redirect.daddr;
            bpf_perf_event_output(ctx.stack_ctx, &nb_map_fnat_event, BPF_F_CURRENT_CPU, &ev, sizeof(ev));
        }
        return nb_tc_act(act);
    }

    act = nb_dec_ttl(&ctx);
    if (act != NB_ACT_OK) {
        return nb_tc_act(act);
    }

    nb_update_ip_csum(&ctx);
    nb_update_l4_csum_incre(&ctx);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0)
    act = nb_tc_extend_toa(&ctx);
    if (act != NB_ACT_OK) {
        return nb_tc_act(act);
    }
#endif

    return bpf_redirect(ctx.forward.redirect_if_idx, 0);
}

char __license[] SEC("license") = "GPL";
