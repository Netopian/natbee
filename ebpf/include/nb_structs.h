#ifndef __NB_STRUCTS_H__
#define __NB_STRUCTS_H__

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/in.h>
#include <linux/pkt_cls.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/string.h>
#include <linux/version.h>
#include <sys/socket.h>

#include <bpf_helpers.h>
#include <bpf_endian.h>

#define NB_SET    1
#define NB_UNSET  0

enum nb_action {
    NB_ACT_OK = 0,
    NB_ACT_PASS,
    NB_ACT_DROP,
    NB_ACT_REDIRECT,
    NB_ACT_UNREACH,
    NB_ACT_MAX,
};

#ifndef bool
#define bool _Bool
#endif

enum {
    false = 0,
    true  = 1,
};

struct nb_ip {
    __be32 addr;
};

struct nb_ipv6 {
    __be32 addr[4];
};

struct nb_sockaddr {
    __u8   af;
    __u8   l4_proto;
    __be16 port;
    union
    {
        struct nb_ip   addr4;
        struct nb_ipv6 addr6;
    };
};

struct nb_ipaddr {
    union
    {
        struct nb_ip   addr4;
        struct nb_ipv6 addr6;
    };
};

struct nb_fib_cache {
    unsigned char dmac[ETH_ALEN];
    unsigned char smac[ETH_ALEN];
};

struct nb_connection {
    struct nb_sockaddr saddr;
    struct nb_sockaddr daddr;
};

struct nb_redirect {
    struct nb_connection redirect;
    __s32                redirect_if_idx;
    __u8                 is_local;
    __u8                 is_local_port;
    __u8                 positive;
    __u8                 reserve;
    __u64                ts;
};

struct nb_context {
    bool               is_ipv6;
    __u8               l4_proto;
    __u8               l3_header_len;
    __u32              l4_header_len;
    __u32              cpu;
    struct ethhdr     *l2h;
    void              *l3h;
    void              *l4h;
    void              *begin;
    void              *end; 
    struct nb_sockaddr org_saddr;
    struct nb_sockaddr org_daddr;
    struct nb_redirect forward;
    void              *stack_ctx;
};

struct nb_service {
    struct nb_sockaddr laddr;
    __u8               strategy;
    __u8               reserve_byte;
    __u16              real_port;
    __u16              real_server_cnt;
    __u16              reserve_short;
    __s32              vitual_if_idx;
    __s32              local_if_idx;
};

// this is a coposite structure, cause of reusing bpf map
struct nb_real_server {
    struct nb_sockaddr addr;
    __u32              idx;
};

struct nb_toa {
    __u8  opcode;
    __u8  opsize;
    __u16 port;
    __u32 ip;
};

struct nb_ipv6_toa {
    __u8  opcode;
    __u8  opsize;
    __u16 port;
    __u32 ip[4];
};

struct nb_neigh_event {
    struct nb_sockaddr local;
    struct nb_sockaddr neigh;
};

#endif