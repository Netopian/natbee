#ifndef __NB_MAPS_H__
#define __NB_MAPS_H__

#include "nb_structs.h"

// map #0
struct bpf_map_def SEC("maps") map_inner_rs = {
    .type        = BPF_MAP_TYPE_ARRAY,
    .key_size    = sizeof(__u32),
    .value_size  = sizeof(struct fm_realserver),
    .max_entries = 1 << 10,
};

// map #1
struct bpf_map_def SEC("maps") map_inner_port = {
    .type        = BPF_MAP_TYPE_ARRAY,
    .key_size    = sizeof(__u32),
    .value_size  = sizeof(__u32),
    .max_entries = 1 << 16,
};

// map #2
struct bpf_map_def SEC("maps") map_nat_srv = {
    .type        = BPF_MAP_TYPE_HASH,
    .key_size    = sizeof(struct fm_sockaddr),
    .value_size  = sizeof(struct fm_service),
    .max_entries = 1 << 8,
};

// map #3
struct bpf_map_def SEC("maps") map_nat_rs = {
    .type          = BPF_MAP_TYPE_HASH_OF_MAPS,
    .key_size      = sizeof(struct fm_sockaddr),
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0)
    .value_size    = sizeof(__u32),
#else
    .inner_map_idx = 0,
#endif
    .max_entries   = 1 << 8,
};

// map #4
struct bpf_map_def SEC("maps") map_nat_conn = {
    .type        = BPF_MAP_TYPE_HASH,
    .key_size    = sizeof(struct fm_conn),
    .value_size  = sizeof(struct fm_redirect),
    .max_entries = 1 << 17,
};

// map #5
struct bpf_map_def SEC("maps") map_fnat_srv = {
    .type        = BPF_MAP_TYPE_HASH,
    .key_size    = sizeof(struct fm_sockaddr),
    .value_size  = sizeof(struct fm_service),
    .max_entries = 1 << 8,
};

// map #6
struct bpf_map_def SEC("maps") map_fnat_rs = {
    .type          = BPF_MAP_TYPE_HASH_OF_MAPS,
    .key_size      = sizeof(struct fm_sockaddr),
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0)
    .value_size    = sizeof(__u32),
#else
    .inner_map_idx = 0,
#endif
    .max_entries   = 1 << 8,
};

// map #7
struct bpf_map_def SEC("maps") map_fnat_port = {
    .type          = BPF_MAP_TYPE_HASH_OF_MAPS,
    .key_size      = sizeof(__u32),
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0)
    .value_size    = sizeof(__u32),
#else
    .inner_map_idx = 1,
#endif
    .max_entries   = 1 << 8,
};

// map #8
struct bpf_map_def SEC("maps") map_fnat_conn = {
    .type        = BPF_MAP_TYPE_HASH,
    .key_size    = sizeof(struct fm_conn),
    .value_size  = sizeof(struct fm_redirect),
    .max_entries = 1 << 17,
};

// map #9
struct bpf_map_def SEC("maps") map_fnat_release_port = {
    .type        = BPF_MAP_TYPE_HASH,
    .key_size    = sizeof(__u32),
    .value_size  = sizeof(__u32),
    .max_entries = 1 << 16,
};

// map #10
struct bpf_map_def SEC("maps") map_nat_event = {
    .type        = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
    .key_size    = sizeof(int),
    .value_size  = sizeof(__u32),
    .max_entries = 1200,
};

// map #11
struct bpf_map_def SEC("maps") map_fnat_event = {
    .type        = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
    .key_size    = sizeof(int),
    .value_size  = sizeof(__u32),
    .max_entries = 1200,
};

#endif