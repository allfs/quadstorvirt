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

#ifndef QUADSTOR_BDEV_H_
#define QUADSTOR_BDEV_H_

#include "coredefs.h"
#include "../common/commondefs.h"
#include "ddblock.h"

#define ILOOKUPS_ARRAY_MAX	512 /* Will span upto 32 TB for 512 sector size disks */


/* For now a subgroup is just a place holder for indexes */
#define SUBGROUP_INDEX_LIST_BUCKETS	8
#define SUBGROUP_INDEX_LIST_MASK	(SUBGROUP_INDEX_LIST_BUCKETS - 1)

enum {
	IOWAITER_DONE_IO,
	IOWAITER_IO_COMPLETE,
	IOWAITER_IO_ERROR,
};

struct iowaiter {
	SLIST_ENTRY(iowaiter) w_list;
	wait_chan_t *chan;
	int flags;
} __attribute__ ((__packed__));

SLIST_HEAD(iowaiter_list, iowaiter);

static inline void
iowaiter_set_bit(struct iowaiter *iowaiter, int bit)
{
	unsigned long flags;

	chan_lock_intr(iowaiter->chan, &flags);
	atomic_set_bit(bit, &iowaiter->flags);
	chan_wakeup_unlocked(iowaiter->chan);
	chan_unlock_intr(iowaiter->chan, &flags);
}

static inline void
init_iowaiter(struct iowaiter *iowaiter)
{
	if (!iowaiter->chan)
		iowaiter->chan = wait_chan_alloc("io wait chan");
	iowaiter->flags = 0;
}

static inline void
free_iowaiter(struct iowaiter *iowaiter)
{
	if (iowaiter->chan)
		wait_chan_free(iowaiter->chan);
}

static inline int
iowaiter_done_io(struct iowaiter *iowaiter)
{
	return atomic_test_bit(IOWAITER_DONE_IO, &iowaiter->flags);
}

static inline void
iowaiter_wait_for_done_io(struct iowaiter *iowaiter)
{
	wait_on_chan_check(iowaiter->chan, atomic_test_bit(IOWAITER_DONE_IO, &iowaiter->flags) || atomic_test_bit(IOWAITER_IO_COMPLETE, &iowaiter->flags) || atomic_test_bit(IOWAITER_IO_ERROR, &iowaiter->flags));
}

static inline void
iowaiter_end_wait(struct iowaiter *iowaiter)
{
	if (iowaiter->chan)
		wait_on_chan(iowaiter->chan, atomic_test_bit(IOWAITER_IO_COMPLETE, &iowaiter->flags) || atomic_test_bit(IOWAITER_IO_ERROR, &iowaiter->flags));
}

#define index_end_wait(indx, iwaitr)	iowaiter_end_wait((iwaitr))

struct index_subgroup {
	uint16_t subgroup_id;
	uint8_t inload:1;
	uint8_t donefirstload:1;
	uint8_t pad:6;
	uint8_t slow_idx;
	atomic16_t free_indexes;
	uint16_t max_indexes;
	sx_t *subgroup_lock;
	sx_t *subgroup_write_lock;
	mtx_t *free_list_lock;
	struct index_group *group;
	SLIST_ENTRY(index_subgroup) s_list;
	TAILQ_HEAD(, bintindex) free_list;
	SLIST_HEAD(, bintindex) write_list;
	struct iowaiter_list io_waiters;
	BSD_LIST_HEAD(, bintindex) index_list[SUBGROUP_INDEX_LIST_BUCKETS];
	wait_chan_t *subgroup_wait;
	atomic_t pending_writes;
};

#define subgroup_write_lock(s)				\
do {							\
	debug_check(sx_xlocked_check((s)->subgroup_write_lock));	\
	sx_xlock((s)->subgroup_write_lock);			\
} while (0)

#define subgroup_write_unlock(s)				\
do {							\
	debug_check(!sx_xlocked((s)->subgroup_write_lock));	\
	sx_xunlock((s)->subgroup_write_lock);			\
} while (0)

struct index_lookup {
	uint64_t b_start;
	struct index_group *group;
	mtx_t *lookup_lock;
	wait_chan_t *lookup_wait;
	pagestruct_t *metadata;
	int flags;
	atomic_t refs;
};

struct index_group {
	struct bdevint *bint;
	struct index_subgroup **subgroups;
	struct index_subgroup *free_subgroup;
	struct index_lookup *index_lookup;
	sx_t *group_lock;
	SLIST_ENTRY(index_group) g_list;
	SLIST_HEAD(, index_subgroup) free_list;
	uint32_t group_id;
	atomic16_t free_indexes;
	uint16_t max_subgroups;
};

static inline uint32_t
subgroup_index_id(struct index_subgroup *subgroup)
{
	return (subgroup->group->group_id << INDEX_ID_GROUP_SHIFT) + (subgroup->subgroup_id << INDEX_ID_SUBGROUP_SHIFT);
}

static inline uint32_t
group_index_id(struct index_group *group)
{
	return (group->group_id << INDEX_ID_GROUP_SHIFT);
}

struct raw_bintindex {
	uint64_t csum;
} __attribute__ ((__packed__));

#define RAW_INDEX_OFFSET	(BINT_BMAP_SIZE - sizeof(struct raw_bintindex))

#define WRITE_ID_MAX		((1ULL << 48) - 1)

static inline int
write_id_greater(uint64_t current, uint64_t write_id)
{
	uint64_t current_diff, write_id_diff;

	if (current > write_id)
		return 1;

	write_id_diff = (WRITE_ID_MAX - write_id);
	current_diff = (WRITE_ID_MAX - current); 
	if ((current_diff - write_id_diff) > (1ULL << 32))
		return 1;
	else
		return 0;

}

static inline uint64_t
write_id_incr(uint64_t write_id, uint32_t incr)
{
	uint64_t diff;

	if ((write_id + incr) < WRITE_ID_MAX) {
		write_id++;
	}
	else {
		diff = ((write_id + incr) - (WRITE_ID_MAX - 1));
		write_id = diff;
	}
	return write_id;
}

struct bintindex {
	uint64_t write_id;
	pagestruct_t *metadata;
	wait_chan_t *index_wait;
	struct index_subgroup *subgroup;
	TAILQ_ENTRY(bintindex) i_list;
	LIST_ENTRY(bintindex) x_list;
	TAILQ_ENTRY(bintindex) b_list;
	SLIST_ENTRY(bintindex) t_list;
	SLIST_ENTRY(bintindex) tc_list;
	struct iowaiter_list io_waiters;
	sx_t *index_lock;
	uint32_t index_id;
	uint16_t free_blocks;
	uint16_t check_idx;
	int flags;
	atomic_t refs;
	atomic_t pending_writes;
};

#define index_lock(ind)				\
do {							\
	debug_check(sx_xlocked_check((ind)->index_lock));	\
	sx_xlock((ind)->index_lock);			\
} while (0)

#define index_unlock(ind)				\
do {							\
	debug_check(!sx_xlocked((ind)->index_lock));	\
	sx_xunlock((ind)->index_lock);			\
} while (0)

struct index_sync {
	struct bintindex *index;
	SLIST_ENTRY(index_sync) s_list;
	struct iowaiter iowaiter;
	int16_t needs_io;
	uint16_t bid;
};

SLIST_HEAD(index_sync_list, index_sync);
enum {
	INDEX_INFO_TYPE_AMAP,
	INDEX_INFO_TYPE_AMAP_TABLE,
};

struct index_info {
	struct bintindex *index;
	uint64_t b_start;
	uint64_t index_write_id;
	TAILQ_ENTRY(index_info) i_list;
	struct log_page *log_page;
	struct iowaiter iowaiter;
	int16_t log_offset;
	int16_t meta_type;
};
TAILQ_HEAD(index_info_list, index_info);

extern uint64_t qs_availmem;

#define index_get(ind)	atomic_inc(&(ind)->refs)

void index_free(struct bintindex *index);

#define index_put(ind)					\
do {							\
	if (atomic_dec_and_test(&(ind)->refs))		\
		index_free(ind);			\
} while (0)

static inline uint32_t
index_group_id(uint32_t index_id)
{
	return (index_id >> INDEX_ID_GROUP_SHIFT);
}

static inline uint32_t
index_subgroup_id(uint32_t index_id, uint32_t *sub_group_offset)
{
	uint32_t sub_group = index_id & INDEX_ID_GROUP_MASK;

	if (sub_group_offset)
		*sub_group_offset = (sub_group & INDEX_ID_SUBGROUP_MASK);

	return (sub_group >> INDEX_ID_SUBGROUP_SHIFT);
}

struct cdevsw;
enum {
	BINT_V2_LOG_FORMAT = 1,
	BINT_V3_LOG_FORMAT = 2,
};

struct bdevint {
	uint64_t b_start;
	uint64_t index_b_start;
	uint64_t usize;
	atomic64_t free;
	atomic64_t free_block_counter;
	uint32_t max_indexes;
	uint32_t max_index_groups;
	iodev_t *b_dev;
	g_consumer_t *cp;
	struct bdevgroup *group;
	struct index_group **index_groups;
	struct index_group *free_group;
	SLIST_HEAD(, index_group) free_list;
	SLIST_ENTRY(bdevint) a_list;
	SLIST_ENTRY(bdevint) b_list;
	SLIST_ENTRY(bdevint) l_list;
	struct bint_stats stats;
	uint32_t bid: 9;
	uint32_t sector_shift: 4;
	uint32_t ddmaster: 1;
	uint32_t ddbits: 5;
	uint32_t log_disks: 6;
	uint32_t log_disk: 1;
	uint32_t log_write: 1;
	uint32_t enable_comp: 1;
	uint32_t v2_disk: 1;
	uint32_t rid_set: 1;
	uint32_t pad1: 2;
	uint8_t in_log_replay;
	uint8_t write_cache;
	uint8_t v2_log_format;
	int8_t initialized;
	int flags;
	int group_flags;
	atomic_t index_count;
	atomic_t free_list_indexes;
	atomic_t post_writes;
	TAILQ_HEAD(, bintindex) index_list;

	mtx_t *bint_lock;
	mtx_t *stats_lock;
	sx_t  *alloc_lock;

	kproc_t *sync_task;
	kproc_t *load_task;
	kproc_t *free_task;
	kproc_t *create_task;
	wait_chan_t *sync_wait;
	wait_chan_t *load_wait;
	wait_chan_t *free_wait;
	BSD_LIST_HEAD(, log_group) log_group_list;
	uint8_t  vendor[8];
	uint8_t  product[16];
	uint8_t  serialnumber[256];
	int serial_len;
	char mrid[TL_RID_MAX];

#ifdef ENABLE_STATS
	uint32_t async_load;
	uint32_t load_count;
	uint32_t index_reads;
	uint32_t index_waits;
	uint32_t index_writes;
	uint32_t async_skipped;
	uint32_t async_freed;
	uint32_t fast_lookups;
	uint64_t pgalloc_size;
	uint64_t pgrequest_size;
	uint64_t slow_size;
	uint64_t fast_size;
	uint32_t pgalloc_lookups;
	uint32_t pgalloc_indexes;
	uint32_t fast_lookups_failed;
	uint32_t slow_lookups;
	uint32_t tcache_add_page_ticks;
	uint32_t wait_for_tcache_ticks;
	uint32_t tcache_bio_count;
	uint32_t tcache_index_count;
	uint32_t index_barrier_ticks;
	uint32_t index_check_load_ticks;
	uint32_t index_check_load_hits;
	uint32_t index_check_load_count;
	uint32_t check_io_ticks;
	uint32_t fast_alloc_ticks;
	uint32_t fast_alloc_misses;
	uint32_t fast_alloc_hits;
	uint32_t bint_fast_alloc_ticks;
	uint32_t bint_subgroup_load_async_ticks;
	uint32_t alloc_block_ticks;
	uint32_t pgdata_alloc_ticks;
	uint32_t pgdata_duplicate_hits;
	uint32_t pgdata_duplicate_misses;
	uint32_t subgroup_wait_for_io_ticks;
	uint32_t bint_pgdata_alloc_ticks;
	uint32_t log_page_count_misses;
	uint32_t log_try_lock_misses;
	uint32_t log_page_busy_misses;
	uint32_t subgroup_waits;
	uint32_t bint_clear_node_block_ticks;
	uint32_t bint_set_node_block_ticks;
	uint32_t bint_locate_node_block_ticks;
#endif
};

SLIST_HEAD(bdev_log_list, bdevint);

#define FREE_LIST_INDEXES_CACHED	2048

#define bint_lock(b)	mtx_lock((b)->bint_lock)
#define bint_unlock(b)	mtx_unlock((b)->bint_lock)
#define BINT_MAX_INDEX_COUNT		64

extern struct bdevint *bint_list[];
extern sx_t *gchain_lock;


#ifdef ENABLE_STATS
#define BINT_TSTART(sjiff)	(sjiff = ticks)
#define BINT_TEND(tdk,count,sjiff)				\
do {								\
	mtx_lock(tdk->stats_lock);				\
	tdk->count += (ticks - sjiff);	\
	mtx_unlock(tdk->stats_lock);			\
} while (0)

#define BINT_INC(tdk,count,val)					\
do {									\
	mtx_lock(tdk->stats_lock);				\
	tdk->count += val;						\
	mtx_unlock(tdk->stats_lock);			\
} while (0)

#define BINT_DEC(tdk,count,val)					\
do {									\
	tdk->count -= val;						\
} while (0)
#else
#define BINT_TSTART(sjiff)		do {} while (0)
#define BINT_TEND(tdk,count,sjiff)	do {} while (0)
#define BINT_INC(tdk,count,val)		do {} while (0)
#define BINT_DEC(tdk,count,val)		do {} while (0)
#endif

#ifdef CLANG_CHECK
struct bdevint * bdev_find(uint32_t bid);
#else
static inline struct bdevint *
bdev_find(uint32_t bid)
{
	if (bid < TL_MAX_DISKS)
		return bint_list[bid];
	else
		return NULL;
}
#endif

enum {
	TYPE_META_BLOCK,
	TYPE_DATA_BLOCK,
};

int bdev_add_new(struct bdev_info *binfo);
int bdev_remove(struct bdev_info *binfo);
int bdev_add_stub(struct bdev_info *binfo);
int bdev_remove_stub(struct bdev_info *binfo);
int bdev_get_info(struct bdev_info *binfo);
int bdev_ha_config(struct bdev_info *binfo);
int bdev_unmap_config(struct bdev_info *binfo);
int bdev_wc_config(struct bdev_info *binfo);
uint64_t bdev_alloc_block(struct bdevgroup *group, uint32_t size, struct bdevint **ret, struct index_info *index_info, int type);
uint64_t __bdev_alloc_block(struct bdevint *bint, uint32_t size, struct index_info *index_info, int type);
int bint_sync(struct bdevint *bint);
int bint_group_sync(struct bdevint *bint);
int bdev_check_space(uint64_t vsize);
void bdev_finalize(void);
void bdev_reclaim_block(struct bdevint *bint, uint64_t block);
int bint_ref_block(struct bdevint *bint, struct bintindex *index, uint32_t entry, uint32_t size, struct index_info *index_info, uint64_t node_block);
int bdev_log_replay(struct bdevint *bint, uint64_t block, uint64_t index_write_id, uint32_t size, struct index_info_list *index_info_list, int type);

void bint_index_free(struct bintindex *index);
uint64_t bdev_get_disk_index_block(struct bdevint *bint, uint32_t target_id);
int bint_log_replay(struct bdevint *bint, struct bintindex *index, uint32_t entry, uint32_t size, int type);

void bint_reset_stats(struct bdevint *bint);
static inline uint64_t
bint_index_bstart(struct bdevint *bint, int index)
{
	uint32_t blocks;
	uint32_t sector_mask = ((1U << bint->sector_shift) - 1);

	blocks = BINT_INDEX_META_SIZE >> bint->sector_shift;
	if (BINT_INDEX_META_SIZE & sector_mask)
		blocks++;
	return (bint->index_b_start + (index * blocks));
}


#define FREE_BLOCKS_MIN		64

enum {
	BDEV_ERROR_GENERIC	= -1,
	BDEV_ERROR_INVALID_REFS	= -2,
	BDEV_ERROR_MAX_REFS	= -3,
	BDEV_INDEX_LOADING	= -4,
	BDEV_ERROR_INVALID_NODE_BLOCK = -5,
};

#define INDEX_REFS_BITS	13
#define INDEX_REFS_MASK	((1ULL << INDEX_REFS_BITS) - 1)
#define BMAP_ENTRY_MAX_REFS	(uint32_t)((1ULL << INDEX_REFS_BITS) - 1)

int bdev_get_node_block(struct bintindex *index, uint32_t *refs, uint64_t *node_block, uint32_t entry_id);
int bdev_set_node_block(struct bdevint *bint, struct bintindex *index, uint64_t block, uint64_t node_block);
void bint_free_block(struct bdevint *bint, struct bintindex *index, uint32_t entry, uint32_t size, int *freed, int type, int ignore_errors);
int bint_unmark_index_full(struct bintindex *index);

static inline void
index_info_free(struct index_info *index_info)
{
	free_iowaiter(&index_info->iowaiter);
	uma_zfree(index_info_cache, index_info);
}

static inline void
index_info_release(struct index_info *index_info)
{
	index_put(index_info->index);
	index_info_free(index_info);
}


static inline struct index_info *
index_info_alloc(void)
{
	struct index_info *index_info;

	index_info = __uma_zalloc(index_info_cache, Q_NOWAIT | Q_ZERO, sizeof(*index_info));
	if (unlikely(!index_info)) {
		debug_warn("Memory allocation failure\n");
		return NULL;
	}

	index_info->log_offset = -1;
	return index_info;
}

static inline struct index_info *
index_info_clone(struct index_info *index_info)
{
	struct index_info *dest;
	
	dest = index_info_alloc();
	index_get(index_info->index);
	dest->index = index_info->index;
	return dest;
}

void index_info_list_free(struct index_info_list *index_info_list);
void index_info_list_free_unmap(struct index_info_list *index_info_list);
void index_info_list_free_error(struct index_info_list *index_info_list, int free);
int bdev_alloc_for_pgdata(struct tdisk *tdisk, struct pgdata_wlist *alloc_list, struct index_info_list *index_info_list, uint32_t size, struct bdevint **ret_bint);

static inline int
index_busy(struct bintindex *index)
{
	if (atomic_read(&index->refs) > 1 ||
	    atomic_test_bit(META_DATA_DIRTY, &index->flags) || 
	    atomic_test_bit(META_DATA_READ_DIRTY, &index->flags) ||
	    atomic_test_bit(META_IO_PENDING, &index->flags) ||
	    atomic_test_bit(META_IO_READ_PENDING, &index->flags))
		return 1;
	else
		return 0;
}

enum {
	ALLOC_BLOCK_SLOW = 0,
	ALLOC_BLOCK_FAST = 1,
	ALLOC_BLOCK_PGDATA = 2,
};

#define CACHED_INDEXES_PERCENTAGE	8
#define CACHED_INDEX_COUNT		1024

#define BMAP_SET_BLOCK(mtd, ix, blk, bbits)		\
do {								\
	int bits = (ix * bbits);				\
	uint64_t v, v1;					\
	int bit_idx = (bits >> 6);				\
	int bit_offset = (bits & 0x3F);				\
	int vbits, v1bits;					\
	uint64_t vmask, v1mask;				\
								\
	v = mtd[bit_idx];				\
	if (bit_offset && ((bit_offset + bbits) > 64)) {	\
		vbits = (64 - bit_offset);			\
		vmask = (1ULL << vbits) - 1;		\
								\
		v &= ~(vmask << bit_offset);		\
		v |= ((((uint64_t)blk) & vmask) << bit_offset);	\
								\
		v1 = mtd[bit_idx + 1];			\
		v1bits = (bbits - (64 - bit_offset));	\
		v1mask = (1ULL << v1bits) - 1;		\
		v1 &= ~(v1mask);				\
		v1 |= (((uint64_t)blk) >> vbits);			\
								\
		mtd[bit_idx + 1] = v1;			\
	}							\
	else {							\
		vmask = (1ULL << bbits) - 1;		\
		v &= (~(vmask << bit_offset));		\
		v |= (((uint64_t)blk) << bit_offset);			\
	}							\
	mtd[bit_idx] = v;				\
} while (0);

#define BMAP_GET_BLOCK(mtd, ix, bbits)		\
({								\
	int bits = (ix * bbits);				\
	uint64_t v, v1;					\
	int bit_idx = (bits >> 6);				\
	int bit_offset = (bits & 0x3F);				\
	int vbits, v1bits;					\
	uint64_t vmask, v1mask;				\
								\
	v = mtd[bit_idx];				\
	v >>= bit_offset;					\
	if (bit_offset && ((bit_offset + bbits) > 64)) {	\
		vbits = (64 - bit_offset);			\
		vmask = (1ULL << vbits) - 1;		\
		v &= vmask;					\
								\
		v1 = mtd[bit_idx + 1];			\
		v1bits = (bbits - (64 - bit_offset));	\
		v1mask = (1ULL << v1bits) - 1;		\
		v1 &= v1mask;				\
		v |= (v1 << vbits);			\
	}							\
	else {							\
		vmask = (1ULL << bbits) - 1;		\
		v &= vmask;					\
	}							\
	v;							\
})

#define bint_meta_shift(bnt)	((bnt)->enable_comp ? 10 : LBA_SHIFT)

static inline uint64_t
block_from_index(struct bdevint *bint, uint64_t index_id, uint32_t index_offset)
{
	uint64_t span;
	int meta_shift = bint_meta_shift(bint);

	span = ((index_id * BMAP_ENTRIES_UNCOMP) + index_offset) << meta_shift;
	return (span >> bint->sector_shift);
}

static inline uint64_t
index_id_from_block(struct bdevint *bint, uint64_t block, uint32_t *index_offset)
{
	uint64_t index_id;
	uint64_t span;
	int meta_shift = bint_meta_shift(bint);

	span = block << bint->sector_shift;
	block = (span >> meta_shift);

	index_id = (block / BMAP_ENTRIES_UNCOMP);
	*index_offset = (block - (index_id * BMAP_ENTRIES_UNCOMP));
	return index_id;
}

void __subgroup_add_to_free_list(struct index_subgroup *subgroup, struct bintindex *index);
static inline void
subgroup_add_to_free_list(struct index_subgroup *subgroup, struct bintindex *index)
{
	mtx_lock(subgroup->free_list_lock);
	if (TAILQ_ENTRY_EMPTY(index, i_list))
		__subgroup_add_to_free_list(subgroup, index);
	mtx_unlock(subgroup->free_list_lock);
}

#ifdef FREEBSD
#else
#endif

#define TCACHE_ALLOC_SIZE	32

static inline void
subgroup_wait_for_io(struct index_subgroup *subgroup)
{
	if (subgroup->inload) {
		BINT_INC(subgroup->group->bint, subgroup_waits, 1);
		wait_on_chan(subgroup->subgroup_wait, !subgroup->inload);
	}
}

#if 0
static inline void
index_write_barrier(struct bdevint *bint, struct bintindex *index)
{
	wait_on_chan(index->index_wait, !atomic_test_bit(META_DATA_DIRTY, &index->flags));
}
#endif

static inline void
index_write_barrier(struct bdevint *bint, struct bintindex *index)
{
#ifdef ENABLE_STATS
	uint32_t start_ticks;
#endif
	pagestruct_t *page, *tmp;

	debug_check(!atomic_test_bit(META_CSUM_CHECK_DONE, &index->flags));
	if (!atomic_test_bit(META_DATA_DIRTY, &index->flags) || atomic_test_bit(META_DATA_CLONED, &index->flags))
		return;

	BINT_TSTART(start_ticks);
	page = vm_pg_alloc(0);
	if (unlikely(!page)) {
		wait_on_chan(index->index_wait, !atomic_test_bit(META_DATA_DIRTY, &index->flags));
	}
	else {
		tmp = index->metadata;
		memcpy(vm_pg_address(page), vm_pg_address(tmp), BINT_INDEX_META_SIZE);
		index->metadata = page;
		atomic_set_bit(META_DATA_CLONED, &index->flags);
		vm_pg_free(tmp);
	}
	BINT_TEND(bint, index_barrier_ticks, start_ticks);
}

enum {
	TYPE_INDEX_LOOKUP,
	TYPE_INDEX,
	TYPE_BINT,
	TYPE_AMAP_TABLE,
	TYPE_AMAP,
	TYPE_DDLOOKUP,
	TYPE_DDTABLE,
	TYPE_LOG,
	TYPE_TDISK_INDEX,
	TYPE_HA_INDEX,
};

static inline void
mark_io_waiters(struct iowaiter_list *lhead)
{
	struct iowaiter *iowaiter;

	SLIST_FOREACH(iowaiter, lhead, w_list) {
		iowaiter_set_bit(iowaiter, IOWAITER_DONE_IO);
	}

}

static inline void
complete_io_waiters(struct iowaiter_list *lhead)
{
	struct iowaiter *iowaiter;

	while ((iowaiter = SLIST_FIRST(lhead)) != NULL) {
		SLIST_REMOVE_HEAD(lhead, w_list);
		iowaiter_set_bit(iowaiter, IOWAITER_IO_COMPLETE);
	}
}

static inline void
subgroup_start_writes(struct index_subgroup *subgroup)
{
	atomic_inc(&subgroup->pending_writes);
}

extern uint32_t subgroup_index_writes;

static inline void
subgroup_add_write_index(struct index_subgroup *subgroup, struct bintindex *index)
{
	struct bintindex *iter, *prev = NULL;

	if (atomic_test_bit(META_WRITE_PENDING, &index->flags))
		return;

	atomic_set_bit(META_WRITE_PENDING, &index->flags);
	GLOB_INC(subgroup_index_writes, 1);
	SLIST_FOREACH(iter, &subgroup->write_list, t_list) {
		if (iter->index_id > index->index_id) {
			break;
		}
		prev = iter;
	}

	if (prev)
		SLIST_INSERT_AFTER(prev, index, t_list);
	else
		SLIST_INSERT_HEAD(&subgroup->write_list, index, t_list);
}

int subgroup_write_io(struct index_subgroup *subgroup, struct tcache **ret_tcache, int incr);

static inline void
subgroup_end_writes(struct index_subgroup *subgroup, int incr)
{
	if (atomic_dec_and_test(&subgroup->pending_writes)) {
		subgroup_write_io(subgroup, NULL, incr);
	}
}

static inline void
index_start_writes(struct bintindex *index, struct iowaiter *iowaiter)
{
	struct index_subgroup *subgroup = index->subgroup;

	init_iowaiter(iowaiter);

	subgroup_write_lock(subgroup);
	subgroup_start_writes(subgroup);
	index_lock(index);
	atomic_inc(&index->pending_writes);
	SLIST_INSERT_HEAD(&index->io_waiters, iowaiter, w_list);
	index_unlock(index);
	subgroup_write_unlock(subgroup);
}

static inline void
iowaiters_move(struct iowaiter_list *dest, struct iowaiter_list *src)
{
	dest->slh_first = src->slh_first;
	SLIST_INIT(src);
}

static inline void
iowaiters_merge(struct iowaiter_list *dest, struct iowaiter_list *src)
{
	struct iowaiter *iowaiter, *prev = NULL;

	if (SLIST_EMPTY(src))
		return;

	SLIST_FOREACH(iowaiter, dest, w_list) {
		prev = iowaiter;
	}

	iowaiter = SLIST_FIRST(src);
	src->slh_first = NULL;
	if (prev)
		prev->w_list.sle_next = iowaiter;
	else
		dest->slh_first = iowaiter;
}

static inline void
index_end_writes(struct bintindex *index, int incr)
{
	struct iowaiter_list tmp_list;
	struct index_subgroup *subgroup = index->subgroup;

	SLIST_INIT(&tmp_list);

	wait_on_chan_check(index->index_wait, !atomic_test_bit(META_DATA_DIRTY, &index->flags));

	subgroup_write_lock(subgroup);
	index_lock(index);
	if (atomic_dec_and_test(&index->pending_writes)) {
		subgroup_add_write_index(subgroup, index);
		mark_io_waiters(&index->io_waiters);
		iowaiters_move(&tmp_list, &index->io_waiters);
	}
	index_unlock(index);

	iowaiters_merge(&subgroup->io_waiters, &tmp_list);
	subgroup_end_writes(subgroup, incr);
	subgroup_write_unlock(subgroup);
}

void index_info_insert(struct index_sync_list *sync_list, struct index_info *index_info);
void index_sync_insert(struct index_sync_list *sync_list, struct bintindex *index);
int index_sync_start_io(struct index_sync_list *index_sync_list, int incr);
int index_sync_wait(struct index_sync_list *index_sync_list);
void index_sync_free(struct index_sync_list *index_sync_list);
void index_list_insert(struct index_sync_list *sync_list, struct index_info_list *index_info_list);
struct bintindex * bint_get_index(struct bdevint *bint, uint32_t index_id);
struct bintindex * bint_locate_index(struct bdevint *bint, uint32_t index_id, struct index_info_list *index_info_list);

static inline void
index_add_iowaiter(struct bintindex *index, struct iowaiter *iowaiter)
{
	init_iowaiter(iowaiter);
	SLIST_INSERT_HEAD(&index->io_waiters, iowaiter, w_list);
}

static inline void
index_info_sync(struct bintindex *index, struct index_info *index_info)
{
	struct iowaiter iowaiter;
 
	bzero(&iowaiter, sizeof(iowaiter));
	index_start_writes(index, &iowaiter);
	index_end_writes(index, 1);
	index_end_wait(index, &iowaiter);
	index_end_wait(index, &index_info->iowaiter);
	free_iowaiter(&iowaiter);
}

int index_info_wait(struct index_info_list *index_info_list);
int __index_info_wait(struct index_info_list *index_info_list);
int index_check_csum(struct bintindex *index);
void index_check_load(struct bintindex *index);
void calc_mem_restrictions(uint64_t availmem);
int calc_ddbits(void);
void bdev_add_to_alloc_list(struct bdevint *bint);
void bdev_remove_from_alloc_list(struct bdevint *bint);
int bint_dev_open(struct bdevint *bint, struct bdev_info *binfo);
void bint_free(struct bdevint *bint, int free_alloc);
void bdev_added(void);
void bdev_list_remove(struct bdevint *bint);
void bdev_list_insert(struct bdevint *bint);
void bdev_log_list_insert(struct bdevint *bint);
void bdev_log_list_remove(struct bdevint *bint, int decr);
int bdev_log_list_count(struct bdevgroup *group);
struct bintindex * subgroup_get_index(struct index_subgroup *subgroup, uint32_t index_id, int load);
void bint_tail_index(struct bdevint *bint, struct bintindex *index);
struct bintindex * subgroup_locate_index(struct index_subgroup *subgroup, uint32_t index_id, struct bintindex **ret_prev);
void bint_initialize_blocks(struct bdevint *bint, int isnew);
int bint_initialize_groups(struct bdevint *bint, int isnew, int load);

#define BINT_STATS_ADD(bnt,count,val)					\
do {									\
	atomic64_add(val, (atomic64_t *)&bnt->stats.count);		\
	if (!atomic_test_bit(BINT_IO_PENDING, &bnt->flags)) {		\
		atomic_set_bit(BINT_IO_PENDING, &bnt->flags);		\
	}								\
} while (0)

#define BINT_STATS_SUB(bnt,count,val)					\
do {									\
	uint64_t prev_count = atomic64_read((atomic64_t *)&bnt->stats.count); \
	atomic64_sub(val, (atomic64_t *)&bnt->stats.count);		\
	if (atomic64_read((atomic64_t *)&bnt->stats.count) > (prev_count + 0xFFFFFFFF))									\
		atomic64_set((atomic64_t *)&bnt->stats.count, 0);	\
	if (!atomic_test_bit(BINT_IO_PENDING, &bnt->flags)) {		\
		atomic_set_bit(BINT_IO_PENDING, &bnt->flags);		\
	}								\
} while (0)

#ifdef FREEBSD 
void bint_sync_thread(void *data);
void bint_free_thread(void *data);
void bint_load_thread(void *data);
#else
int bint_sync_thread(void *data);
int bint_free_thread(void *data);
int bint_load_thread(void *data);
#endif
void bdev_alloc_list_insert(struct bdevint *bint);
int bint_ha_takeover(struct bdevint *bint);
int bint_ha_takeover_post(struct bdevint *bint);
int bint_ha_takeover_post_load(struct bdevint *bint);
int bdevs_load_post(void);
void bdevs_load_ddtables_post(void);
int bdevs_fix_rids(void);
void bint_reset(struct bdevint *bint);
int bint_fix_rid(struct bdevint *bint);
struct bdevgroup * bdev_group_get_log_group(struct bdevgroup *group);
int bdev_conditional_ref(struct bdevint *bint, uint64_t b_start, struct index_sync_list *index_sync_list);

static inline int
bint_unmap_supported(struct bdevint *bint)
{
	return atomic_test_bit(GROUP_FLAGS_UNMAP, &bint->group_flags);
}
void __bint_set_free(struct bdevint *bint, uint64_t size);

#endif
