/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#ifndef __LIB_SUBNET_H_
#define __LIB_SUBNET_H_

#include <linux/bpf.h>
#include <bpf/section.h>
#include "common.h"

/**
 * Key structure for LPM trie map
 * Supports both IPv4 and IPv6 addresses
 */
struct lpm_trie_key {
	__u32 prefixlen;     // 32 for IPv4, 128 for IPv6
	__u8  addr[16];      // Supports both IPv4 (first 4 bytes) and IPv6 (full 16 bytes)
};

/**
 * CIDR to Subnet ID mapping using LPM trie
 * Maps CIDR blocks to their corresponding subnet IDs
 */
struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__uint(max_entries, 1024);
	__type(key, struct lpm_trie_key);
	__type(value, __u32); // Subnet ID
	__uint(map_flags, BPF_F_NO_PREALLOC);
} cidr_subnet_map __section_maps_btf;

/**
 * lookup_subnet_id returns subnet ID for given IPv4 or IPv6 address
 * - return 0 if no matching CIDR found
 * - return ID (>=1) otherwise
 */
static __always_inline __u32 lookup_subnet_id(void *ip, __u8 family)
{
	struct lpm_trie_key key = {};
	__u32 *subnet_id;

	if (family == AF_INET) {
		// IPv4 lookup
		key.prefixlen = 32;
		__builtin_memcpy(key.addr, ip, 4);
		// Clear remaining bytes for IPv4
		__builtin_memset(key.addr + 4, 0, 12);
	} else if (family == AF_INET6) {
		// IPv6 lookup
		key.prefixlen = 128;
		__builtin_memcpy(key.addr, ip, 16);
	} else {
		return 0; // Unsupported address family
	}

	subnet_id = (__u32 *)map_lookup_elem(&cidr_subnet_map, &key);
	if (!subnet_id)
		return 0; // No matching CIDR found

	return *subnet_id;
}

#endif /* __LIB_SUBNET_H_ */
