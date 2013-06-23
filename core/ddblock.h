/* 
 * Copyright (C) Shivaram Upadhyayula <shivaram.u@quadstor.com>
 * 
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * Version 2 as published by the Free Software Foundation
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, 
 * Boston, MA  02110-1301, USA.
 */

#ifndef QS_DDBLOCK_H_
#define QS_DDBLOCK_H_

#include "coredefs.h"
#include "sha.h"

typedef uint32_t index_t;

#define LOOKUP_MAX_LEVELS	2

/*
 * dd block flags format
 * 
 * 8 bits - refs 
 * 33 bits - time of creation
 */

struct ddblock_entry {
	uint64_t block;
	uint8_t hash[SHA256_DIGEST_LENGTH];
	uint16_t time;
} __attribute__ ((__packed__));

struct ddblock_info {
	uint64_t block;
	uint64_t node_block;
	struct index_info *index_info;
	int32_t status;
	struct pgdata *pgdata;
};

enum {
	DDBLOCK_ZERO_BLOCK,
	DDBLOCK_DEDUPE_DISABLED,
	DDBLOCK_ENTRY_DONE_ALLOC,
	DDBLOCK_ENTRY_FOUND_DUPLICATE,
	SKIP_RCACHE_INSERT,
	PGDATA_SKIP_UNCOMP,
	PGDATA_SKIP_DDCHECK,
	PGDATA_COMP_ENABLED,
	PGDATA_NEED_REMOTE_IO,
	PGDATA_FROM_RCACHE,
	PGDATA_FROM_READ_LIST,
	PGDATA_DONE_AMAP_UPDATE,
	PGDATA_HASH_CHECK_DONE,
	DDBLOCK_UNMAP_BLOCK,
	DDBLOCK_ENTRY_INDEX_LOADING,
};

#define NODE_CLIENT_WRITE_MASK	0x3

extern struct pgdata pgzero;
extern uint8_t *pgzero_addr;

extern uint32_t memcmp_ticks;
extern mtx_t *glob_stats_lock;
#ifdef ENABLE_STATS
#define GLOB_TSTART(sjiff)	(sjiff = ticks)
#define GLOB_TEND(count,sjiff)				\
do {								\
	mtx_lock(glob_stats_lock);				\
	count += (ticks - sjiff);				\
	mtx_unlock(glob_stats_lock);				\
} while (0)

#define GLOB_INC(count,val)					\
do {									\
	mtx_lock(glob_stats_lock);				\
	count += val;						\
	mtx_unlock(glob_stats_lock);				\
} while (0)
#else
#define GLOB_TSTART(sjiff)		do {} while (0)
#define GLOB_TEND(count,sjiff)		do {} while (0)
#define GLOB_INC(count,val)		do {} while (0)
#endif

static inline int
zero_memcmp(uint64_t *pgdata_addr)
{
	int i;
	uint64_t val;

	for (i = 0; i < (LBA_SIZE / 8); i+=8) {
		val = pgdata_addr[i] | pgdata_addr[i+1] | pgdata_addr[i+2] | pgdata_addr[i+3] | pgdata_addr[i+4] | pgdata_addr[i+5] | pgdata_addr[i+6] | pgdata_addr[i+7];
		if (val)
			return 1;
	}
	return 0;
}

static inline void
ddblock_hash_compute(struct pgdata *pgdata)
{
	uint8_t *pgdata_addr = (uint8_t *)pgdata_page_address(pgdata);
	SHA256X_CTX ctx;
	int retval;
#ifdef ENABLE_STATS
	uint32_t start_ticks;
#endif

	GLOB_TSTART(start_ticks);
#if 0
	retval = memcmp(pgdata_addr, pgzero_addr, LBA_SIZE);
#endif
	retval = zero_memcmp((uint64_t *)pgdata_addr);
	GLOB_TEND(memcmp_ticks, start_ticks);

	if (!retval) {
		atomic_set_bit(DDBLOCK_ZERO_BLOCK, &pgdata->flags);
		return;
	}

	shax_init(&ctx);
	shax_update(&ctx, pgdata_addr, LBA_SIZE);
	shax_final(pgdata->hash, &ctx);
#if 0
	read_random(pgdata->hash, 32);
#endif
}

static inline int
hash_valid(uint64_t *hash)
{
	int i;

	for (i = 0; i < (SHA256_DIGEST_LENGTH >> 3); i++) {
		if (hash[i])
			return 1;
	}
	debug_check(1);
	return 0; 
}

static inline int
hash_equal(uint64_t *hash1, uint64_t *hash2)
{
	int i;

	for (i = 0; i < (SHA256_DIGEST_LENGTH >> 3); i++) {
		if (hash1[i] != hash2[i])
			return 0;
	}
	return 1;
}
 
#endif
