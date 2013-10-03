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

#ifndef QSTOR_AMAP_H_
#define QSTOR_AMAP_H_

#include "coredefs.h"
#include "bdevmgr.h"

struct raw_amap {
	uint64_t csum;
} __attribute__ ((__packed__));

struct raw_amap_table {
	uint64_t csum;
} __attribute__ ((__packed__));

struct aio_meta {
	struct iowaiter_list io_waiters_post;
	void *priv;
};

enum {
	ATABLE_CSUM_CHECK_DONE, 
	ATABLE_META_DATA_ERROR,
	ATABLE_META_DATA_DIRTY,
	ATABLE_META_DATA_READ_DIRTY,
	ATABLE_META_DATA_CLONED,
	ATABLE_META_IO_PENDING,
	ATABLE_META_DATA_INVALID,
	ATABLE_META_DATA_NEW,
	ATABLE_META_LOG_DONE,
	ATABLE_WRITE_BMAP_INVALID,
};

enum { 
	AMAP_META_IO_NEEDED,
	AMAP_META_IO_PENDING,
	AMAP_META_DATA_BUSY,
	AMAP_META_DATA_NEW,
	AMAP_CSUM_CHECK_DONE,
	AMAP_META_DATA_ERROR,
	AMAP_META_DATA_DIRTY,
	AMAP_META_DATA_INVALID,
	AMAP_META_DATA_READ_DIRTY,
	AMAP_META_DATA_CLONED,
	AMAP_META_LOG_DONE,
};

struct amap {
	uint64_t write_id;
	uint64_t amap_block;
	pagestruct_t *metadata;
	struct amap_table *amap_table;
	struct iowaiter_list io_waiters;
	uint32_t amap_id;
	uint16_t amap_idx;
	int16_t flags;
	sx_t *amap_lock;
	wait_chan_t *amap_wait;
	atomic_t pending_writes; 
	atomic_t refs;
};

static inline struct bdevint *
amap_bint(struct amap *amap)
{
	return bdev_find(BLOCK_BID(amap->amap_block));
}

static inline uint64_t
amap_bstart(struct amap *amap)
{
	return BLOCK_BLOCKNR(amap->amap_block);
}

struct amap * amap_alloc(struct amap_table *amap_table, uint32_t amap_id, uint32_t amap_idx);
void amap_insert(struct amap_table *amap_table, struct amap *amap, uint32_t amap_idx);

#define amap_lock(amp)				\
do {							\
	debug_check(sx_xlocked_check((amp)->amap_lock));	\
	sx_xlock((amp)->amap_lock);			\
} while (0)

#define amap_unlock(amp)				\
do {							\
	debug_check(!sx_xlocked((amp)->amap_lock));	\
	sx_xunlock((amp)->amap_lock);			\
} while (0)

#define amap_read_lock(amp)		if (amp) sx_slock((amp)->amap_lock)
#define amap_read_unlock(amp)		if (amp) sx_sunlock((amp)->amap_lock)

#define AMAP_SHIFT		12
#define AMAP_SIZE		(1U << AMAP_SHIFT)
#define AMAP_BLOCK_BITS		((BLOCK_BLOCKNR_BITS + BLOCK_BID_BITS + 3))
#define AMAP_BLOCK_MASK		((1ULL << (AMAP_BLOCK_BITS)) - 1)
#define ENTRIES_PER_AMAP	(((AMAP_SIZE - sizeof(struct raw_amap)) * 8) / AMAP_BLOCK_BITS)
#define RAW_AMAP_OFFSET		(AMAP_SIZE - sizeof(struct raw_amap))

#define AMAP_PENDING_WAITERS_MAX	64

static inline void
amap_entry_set_block(struct amap *amap, int idx, uint64_t block)
{
	debug_check(idx >= ENTRIES_PER_AMAP);
	debug_check(block > AMAP_BLOCK_MASK);
	BMAP_SET_BLOCK(((uint64_t *)vm_pg_address(amap->metadata)), idx, block, AMAP_BLOCK_BITS);
}

static inline uint64_t
amap_entry_get_block(struct amap *amap, int idx)
{
	debug_check(idx >= ENTRIES_PER_AMAP);
	return BMAP_GET_BLOCK(((uint64_t *)vm_pg_address(amap->metadata)), idx, AMAP_BLOCK_BITS);
}

static inline uint64_t
amap_metadata_get_block(pagestruct_t *metadata, int idx)
{
	debug_check(idx >= ENTRIES_PER_AMAP);
	return BMAP_GET_BLOCK(((uint64_t *)vm_pg_address(metadata)), idx, AMAP_BLOCK_BITS);
}

#define LBAS_PER_AMAP		(ENTRIES_PER_AMAP)
#define AMAP_TABLE_SHIFT	12
#define AMAP_TABLE_SIZE		(1U << AMAP_TABLE_SHIFT)
#define AMAP_TABLE_BLOCK_BITS	((BLOCK_BLOCKNR_BITS + BLOCK_BID_BITS))
#define AMAPS_PER_AMAP_TABLE	(((AMAP_TABLE_SIZE - sizeof(struct raw_amap_table)) * 8) / AMAP_TABLE_BLOCK_BITS)
#define LBAS_PER_AMAP_TABLE	(LBAS_PER_AMAP * AMAPS_PER_AMAP_TABLE)
#define ATABLE_WRITE_BMAP_SIZE	(((AMAPS_PER_AMAP_TABLE) / 8) + 1) /* + 1 intentional */

#define AMAP_TABLE_GROUP_SHIFT	(9)
#define AMAP_TABLE_GROUP_MASK	((1U << AMAP_TABLE_GROUP_SHIFT) - 1)
#define AMAP_TABLE_PER_GROUP	((1U << AMAP_TABLE_GROUP_SHIFT))
#define AGROUP_WRITE_BMAP_SIZE	(AMAP_TABLE_PER_GROUP / 8)

#define INDEX_TABLE_GROUP_SHIFT	AMAP_TABLE_GROUP_SHIFT
#define INDEX_TABLE_GROUP_MASK	AMAP_TABLE_GROUP_MASK

#define LBA_BLOCK_SIZE_BITS	3
#define LBA_BLOCK_SIZE_MASK	((1U << LBA_BLOCK_SIZE_BITS) - 1)

#define RAW_AMAP_TABLE_OFFSET	(AMAP_TABLE_SIZE - sizeof(struct raw_amap_table))

struct write_bmap {
	uint8_t bmap[ATABLE_WRITE_BMAP_SIZE];
} __attribute__ ((__packed__));

struct group_write_bmap {
	uint8_t bmap[AGROUP_WRITE_BMAP_SIZE];
} __attribute__ ((__packed__));
 
static inline uint32_t
lba_block_size(uint64_t block)
{
	uint64_t size;

	size = (block >> (BLOCK_BLOCKNR_BITS + BLOCK_BID_BITS)) & 0x7; 
	if (size)
		return (size << 9);
	else
		return LBA_SIZE;
}

#define SET_BLOCK_SIZE(block,size)				\
do {								\
	debug_check((size & 0x1FF));				\
	if (size != LBA_SIZE)					\
		block |= ((((uint64_t)size) >> 9) << (BLOCK_BLOCKNR_BITS + BLOCK_BID_BITS));	\
} while (0)

#define amap_table_id(llbax)	((uint32_t)(llbax / LBAS_PER_AMAP_TABLE))

static inline uint32_t
amap_table_group_id(uint32_t amap_table_id, uint32_t *group_offset)
{
	if (group_offset)
		*group_offset = (amap_table_id & AMAP_TABLE_GROUP_MASK);

	return (amap_table_id >> AMAP_TABLE_GROUP_SHIFT);
}

static inline uint64_t
amap_table_get_lba_start(uint64_t amap_table_id)
{
	return (amap_table_id * LBAS_PER_AMAP_TABLE);
}

static inline uint64_t
amap_get_lba_start(uint64_t amap_id)
{
	return (amap_id * LBAS_PER_AMAP);
}

static inline uint32_t 
amap_get_id(uint64_t lba)
{
	uint32_t id;

	id = (uint32_t)(lba / LBAS_PER_AMAP);
	return id;
}

static inline uint32_t
amap_entry_id(struct amap *amap, uint64_t lba)
{
	uint64_t amap_lba_start;
	uint32_t id;

	amap_lba_start = (amap->amap_id * LBAS_PER_AMAP);
	id = (uint32_t)(lba - amap_lba_start);
	return id;
}

#define amap_get(amp)	atomic_inc(&(amp)->refs)

struct tdisk;
struct amap_table {
	uint64_t write_id;
	struct tdisk *tdisk;
	uint64_t amap_table_block;
	pagestruct_t *metadata;
	struct amap **amap_index; /* Faster lookups */
	TAILQ_ENTRY(amap_table) t_list;
	wait_chan_t *amap_table_wait;
	struct iowaiter_list io_waiters;
	sx_t *amap_table_lock;
	struct write_bmap *write_bmap;
	uint32_t amap_table_id;
	uint16_t pad;
	int16_t flags;
	atomic_t refs;
	atomic_t pending_writes; 
};

static inline uint32_t
amap_table_group_offset(struct amap_table *amap_table)
{
	return (amap_table->amap_table_id & AMAP_TABLE_GROUP_MASK);
}

static inline struct bdevint *
amap_table_bint(struct amap_table *amap_table)
{
	return bdev_find(BLOCK_BID(amap_table->amap_table_block));
}

static inline uint64_t
amap_table_bstart(struct amap_table *amap_table)
{
	return BLOCK_BLOCKNR(amap_table->amap_table_block);
}

#define amap_table_lock(amp)				\
do {							\
	debug_check(sx_xlocked_check((amp)->amap_table_lock));	\
	sx_xlock((amp)->amap_table_lock);			\
} while (0)

#define amap_table_unlock(amp)				\
do {							\
	debug_check(!sx_xlocked((amp)->amap_table_lock));	\
	sx_xunlock((amp)->amap_table_lock);			\
} while (0)

#define amap_table_get(ampt)	atomic_inc(&(ampt)->refs)

struct amap_group_bitmap {
	uint32_t group_offset;
	pagestruct_t *bmap;
	STAILQ_ENTRY(amap_group_bitmap) b_list;
};
STAILQ_HEAD(group_bmap_list, amap_group_bitmap);

struct amap_table_group {
	struct amap_table **amap_table;
	sx_t *group_lock;
	struct group_write_bmap *group_write_bmap;
	uint32_t amap_table_max;
	TAILQ_ENTRY(amap_table_group) g_list;
	TAILQ_HEAD(, amap_table) table_list;
};

#define amap_table_group_lock(agrp)					\
do {								\
	debug_check(sx_xlocked_check((agrp)->group_lock));		\
	sx_xlock((agrp)->group_lock);				\
} while (0)

#define amap_table_group_unlock(agrp)					\
do {								\
	debug_check(!sx_xlocked((agrp)->group_lock));		\
	sx_xunlock((agrp)->group_lock);				\
} while (0)


int amap_table_io(struct amap_table *amap_table, int rw);
int amap_io(struct amap *amap, uint64_t write_id, int rw);
struct amap * amap_load(struct amap_table *amap_table, uint32_t amap_id, uint32_t amap_idx, uint64_t block, struct tpriv *priv);
struct amap * amap_new(struct amap_table *amap_table, uint32_t amap_id, uint32_t amap_idx, struct index_info_list *index_info_list, int *error);
void amap_table_free(struct amap_table *amap_table);
void amap_table_free_amaps(struct amap_table *amap_table);
void amap_free(struct amap *amap);

#define amap_put(amp)					\
do {							\
	if (atomic_dec_and_test(&(amp)->refs))		\
		amap_free(amp);				\
} while (0)

#define amap_table_put(ampt)				\
do {							\
	if (atomic_dec_and_test(&(ampt)->refs))		\
		amap_table_free(ampt);			\
} while (0)


void mirror_clear_write_id_skip(void);
void mirror_set_write_id_skip(void);
#endif
