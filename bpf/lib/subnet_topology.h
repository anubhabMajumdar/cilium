/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#pragma once

#include "common.h"

#include <linux/ip.h>

struct subnet_key {
    struct bpf_lpm_trie_key lpm_key;
    __u32 ipv4;
};

struct subnet_value {
    __u32 identity;
};

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, 1024);
    __type(key, struct subnet_key);
    __type(value, struct subnet_value);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} subnet_topology_map __section_maps_btf;

static __always_inline __maybe_unused __u32 subnet_identity_lookup(__be32 ipv4)
{
    struct subnet_value *value;
    struct subnet_key key = {
        .lpm_key = {
            .prefixlen = 32,
        },
        .ipv4 = ipv4,
    };
    value = (struct subnet_value *) map_lookup_elem(&subnet_topology_map, &key);
    if (!value)
        return 0; // No identity found for this subnet
    return value->identity;
}
