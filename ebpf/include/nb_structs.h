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

#define FM_SET    1
#define FM_UNSET  0

enum fm_action {
    FM_OK = 0,
    FM_PASS,
    FM_DROP,
    FM_REDIRECT,
    FM_UNREACH,
    FM_ACT_MAX,
};

#ifndef bool
#define bool _Bool
#endif

enum {
    false = 0,
    true  = 1,
}

struct fm_ip {
    __be32 addr;
};

struct fm_ipv6 {
    __be32 addr[4];
};

struct fm_sockaddr {
    __u8   af;
    __u8   l4p;
    __be16 port;
    union
    {
        struct fm_ip   addr4;
        struct fm_ipv6 addr6;
    };
};

struct fm_ipaddr {
    union
    {
        struct fm_ip   addr4;
        struct fm_ipv6 addr6;
    };
};

struct fm_fibcache {
    unsigned char dmac[ETH_ALEN];
    unsigned char smac[ETH_ALEN];
};

struct fm_conn {
    struct fm_sockaddr saddr;
    struct fm_sockaddr daddr;
};

struct fm_redirect {
    struct fm_conn rconn;
    __s32          rdev_idx;
    __u8           local;
    __u8           local_port;
    __u8           positive;
    __u8           res;
    __u64          ts;
};

struct fm_context {
    bool               is_ipv6;
    __u8               l4_proto;
    __u8               ihl;
    __u32              l4l;
    __u32              cpu;
    struct ethhdr     *l2h;
    void              *l3h;
    void              *l4h;
    void              *begin;
    void              *end; 
    struct fm_sockaddr org_saddr;
    struct fm_sockaddr org_daddr;
    struct fm_redirect fwd;
    void              *stack_ctx;
};

struct fm_service {
    struct fm_sockaddr laddr;
    __u8               strategy;
    __u8               res_byte;
    __u16              rport;
    __u16              rs_cnt;
    __u16              res_short;
    __s32              vdev_idx;
    __s32              ldev_idx;
};

// this is a coposite structure, cause of reusing bpf map
struct fn_realserver {
    struct fm_sockaddr addr;
    __u32              idx;
};

struct fm_toa {
    __u8  opcode;
    __u8  opsize;
    __u16 port;
    __u32 ip;
};

struct fm_ipv6_toa {
    __u8  opcode;
    __u8  opsize;
    __u16 port;
    __u32 ip[4];
};

struct fm_neigh_info {
    struct fm_sockaddr local;
    struct fm_sockaddr neigh;
};

#endif