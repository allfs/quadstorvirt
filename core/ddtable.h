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

#ifndef QS_DDTABLE_H_
#define QS_DDTABLE_H_

#include "coredefs.h"
#include "ddblock.h"
#include "bdevmgr.h"

#define NODE_CACHED_COUNT_PERCENTAGE	42
#define NODE_CACHED_COUNT_MAX		48
#define NODE_CACHED_COUNT_CRIT		54

#define DDTABLE_LOOKUP_NODE_SHIFT	(12)
#define DDTABLE_LOOKUP_NODE_SIZE	(1U << DDTABLE_LOOKUP_NODE_SHIFT)

#define DDTABLE_LOOKUP_NODE_MAX_BLOCKS	((DDTABLE_LOOKUP_NODE_SIZE - sizeof(struct raw_ddtable_ddlookup_node)) / sizeof(struct ddblock_entry))
//#define DDTABLE_LOOKUP_NODE_MAX_BLOCKS		8

struct raw_ddtable_ddlookup_node {
	uint64_t next_block;
	uint16_t num_entries;
	uint64_t csum;
} __attribute__ ((__packed__));

SLIST_HEAD(ddlookup_node_list, ddtable_ddlookup_node); 
struct ddlookup_list {
	struct ddlookup_node_list lhead;
	mtx_t *lhead_lock;
	sx_t *insert_lock;
};

enum {
	DDLOOKUP_META_DATA_ERROR,
	DDLOOKUP_META_DATA_DIRTY,
	DDLOOKUP_META_DATA_READ_DIRTY,
	DDLOOKUP_META_IO_PENDING,
	DDLOOKUP_META_IO_READ_PENDING,
	DDLOOKUP_META_DATA_CLONED,
	DDLOOKUP_META_DATA_BUSY,
	DDLOOKUP_META_DATA_INVALID,
	DDLOOKUP_META_DATA_NEEDS_SYNC,
	DDLOOKUP_IS_ROOT,
	DDLOOKUP_DONE_LOAD,
};

struct ddtable_ddlookup_node {
	uint64_t b_start;
	uint64_t write_id;
	pagestruct_t *metadata;
	struct ddlookup_list *ddlookup_list;
	LIST_ENTRY(ddtable_ddlookup_node) n_list;
	SLIST_ENTRY(ddtable_ddlookup_node) p_list;
	TAILQ_ENTRY(ddtable_ddlookup_node) t_list; /* table list */
	TAILQ_ENTRY(ddtable_ddlookup_node) s_list; /* sync list */
	sx_t *ddlookup_lock;
	wait_chan_t *ddlookup_wait;
	int16_t flags;
	uint16_t num_entries;
	atomic_t refs;
};

static inline int
ddlookup_is_root(struct ddtable_ddlookup_node *ddlookup)
{
	return (atomic_test_bit_short(DDLOOKUP_IS_ROOT, &ddlookup->flags));
}

#define ddtable_ddlookup_node_put(ddtln)		\
do {							\
	if (atomic_dec_and_test(&(ddtln)->refs))	\
		ddtable_ddlookup_node_free(ddtln);	\
} while (0)

#define ddtable_ddlookup_node_get(ddtln)	atomic_inc(&(ddtln)->refs)

#define RAW_LOOKUP_OFFSET	(DDTABLE_LOOKUP_NODE_SIZE - sizeof(struct raw_ddtable_ddlookup_node))
static inline struct ddblock_entry *
ddtable_ddlookup_get_block_entry(struct ddtable_ddlookup_node *ddlookup, int idx)
{
	struct ddblock_entry *block = (struct ddblock_entry *)((((uint8_t *)vm_pg_address(ddlookup->metadata))));
	return &block[idx];
}

struct raw_ddtable {
	uint64_t root[(BINT_INDEX_META_SIZE/sizeof(uint64_t))];
};

struct node_group {
	struct ddlookup_list **ddlookup_lists;
	struct ddtable_node **ddnodes_list;
};

struct ddtable_node {
	BSD_LIST_HEAD(, ddtable_ddlookup_node) node_list; 
	sx_t *node_lock;
};

struct ddtable {
	struct bdevint *bint;
	struct node_group **node_groups;
	int flags;
	atomic_t inited;
	uint32_t max_roots;
	atomic_t sync_count;
	mtx_t *ddtable_lock;
	TAILQ_HEAD(, ddtable_ddlookup_node) ddlookup_list;
	TAILQ_HEAD(, ddtable_ddlookup_node) sync_list;
	wait_chan_t *sync_wait;
	wait_chan_t *free_wait;
	wait_chan_t *load_wait;
	kproc_t *sync_task;
	kproc_t *free_task;
	kproc_t *load_task;
};

struct ddtable_global {
	uint64_t reserved_size;
	uint64_t ddlookup_count;
	uint64_t max_ddlookup_count;
	int max_ddtables;
	atomic_t cur_ddtables;
	int max_log_disks;
	atomic_t cur_log_disks;
	mtx_t *global_lock;
};

extern struct ddtable_global ddtable_global;

static inline void
dump_ddtable_global(void)
{
	debug_info("reserved_size: %llu\n", (unsigned long long)ddtable_global.reserved_size);
	debug_info("ddlookup_count: %llu max_ddlookup_count: %llu\n", (unsigned long long)ddtable_global.ddlookup_count, (unsigned long long)ddtable_global.max_ddlookup_count);
	debug_info("cur ddtables: %d max ddtables %d\n", atomic_read(&ddtable_global.cur_ddtables), ddtable_global.max_ddtables);
	debug_info("cur log disks: %d max log disks %d\n", atomic_read(&ddtable_global.cur_log_disks), ddtable_global.max_log_disks);
}

static inline uint64_t
ddtable_global_ddlookup_count(void)
{
	uint64_t ret;

	mtx_lock(ddtable_global.global_lock);
	ret = ddtable_global.ddlookup_count;
	mtx_unlock(ddtable_global.global_lock);
	return ret;
}

static inline void
ddtable_global_ddlookup_incr(void)
{
	mtx_lock(ddtable_global.global_lock);
	ddtable_global.ddlookup_count++;
	mtx_unlock(ddtable_global.global_lock);
}

static inline void
ddtable_global_ddlookup_decr(void)
{
	mtx_lock(ddtable_global.global_lock);
	debug_check(!ddtable_global.ddlookup_count);
	ddtable_global.ddlookup_count--;
	mtx_unlock(ddtable_global.global_lock);
}

static inline int
ddtable_global_can_add_ddlookup(void)
{
	int ret;

	mtx_lock(ddtable_global.global_lock);
	ret = ddtable_global.ddlookup_count < ddtable_global.max_ddlookup_count;
	mtx_unlock(ddtable_global.global_lock);
	return ret;
}

struct ddtable_stats {
#ifdef ENABLE_STATS
	mtx_t *stats_lock;
	uint64_t async_load;
	uint64_t sync_load;
	uint64_t hash_load;
	uint64_t find_load;
	uint64_t insert_load;
	uint32_t ddlookups_synced;
	uint32_t ddlookups_alloced;
	uint32_t ddlookups_freed;
	uint32_t free_thread;
	uint32_t free_run;
	uint32_t sync_thread;
	uint32_t sync_run;
	uint32_t hash_remove_misses;
	uint32_t critical_wait;
	uint32_t ddlookups_new;
	uint32_t root_new;
	uint32_t ddlookups_load;
	uint32_t root_load;
	uint64_t hashes;
	uint64_t dedupe_blocks;
	uint32_t transit_blocks;
	uint64_t zero_blocks;
	uint64_t hash_ddlookups;
	uint64_t hash_replaced;
	uint64_t max_refed;
	uint64_t hash_count;
	uint64_t blocks_removed;
	uint64_t blocks_replaced;
	uint64_t blocks_inserted;
	uint32_t invalid_node_blocks;
	uint32_t invalid_block_refs;
	uint64_t post_dedupe;
	uint64_t post_dedupe_skipped;
	uint64_t inline_dedupe;
	uint32_t peer_count;
	uint32_t peer_load_count;
	uint32_t process_queue_ticks;
	uint32_t handle_ddwork_ticks;
	uint32_t delete_block_pre_ticks;
	uint32_t hash_insert_setup_ticks;
	uint32_t hash_insert_post_setup_ticks;
	uint32_t amap_sync_start_ticks;
	uint32_t log_list_start_ticks;
	uint32_t hash_insert_post_ticks;
	uint32_t log_list_writes_ticks;
	uint32_t cloning_wait_ticks;
	uint32_t index_list_insert_ticks;
	uint32_t index_list_meta_insert_ticks;
	uint32_t log_list_end_ticks;
	uint32_t delete_block_ticks;
	uint32_t hash_compute_ticks;
	uint32_t compression_ticks;
	uint32_t hash_str_ticks;
	uint32_t hash_ddlookup_ticks;
	uint32_t node_dirty_ticks;
	uint32_t insert_entry_ticks;
	uint32_t insert_find_entry_ticks;
	uint32_t sanity_check_ticks;
	uint32_t set_node_block_ticks;
	uint32_t set_hash_ticks;
	uint32_t load_node_ticks;
	uint32_t ddlookup_list_find_ticks;
	uint32_t find_entry_ticks;
	uint32_t hash_insert_ticks;
	uint32_t ddlookup_barrier_ticks;
	uint32_t get_node_block_ticks;
	uint32_t free_block_ticks;
	uint32_t ddlookup_find_node_ticks;
	uint32_t process_delete_block_ticks;
	uint32_t hash_remove_block_ticks;
	uint32_t process_delete_free_block_ticks;
	uint32_t index_sync_ticks;
	uint32_t index_sync_wait_ticks;
	uint32_t index_info_wait_ticks;
	uint32_t index_info_meta_wait_ticks;
	uint32_t node_pgdata_sync_ticks;
	uint32_t handle_meta_sync_ticks;
	uint32_t amap_sync_ticks;
	uint32_t amap_sync_wait_ticks;
	uint32_t index_sync_post_ticks;
	uint32_t amap_sync_post_ticks;
	uint32_t log_clear_ticks;
	uint32_t post_free_ticks;
	uint32_t set_node_failed;
	uint32_t set_node_success;
	uint32_t invalid_amap_entry;
	uint32_t invalid_amap_entry_pre;
	uint32_t locate_spec_new;
	uint32_t locate_spec_replace;
	uint32_t locate_spec_misses;
#endif
};

struct ddsync_spec {
	struct ddtable_ddlookup_node *last;
	struct ddtable_ddlookup_node *child;
	struct index_info *index_info;
	int root_id;
	STAILQ_ENTRY(ddsync_spec) d_list;
};
STAILQ_HEAD(ddspec_list, ddsync_spec);

int ddtable_create(struct ddtable *ddtable, struct bdevint *table_bint);
int ddtable_load(struct ddtable *ddtable, struct bdevint *table_bint);
void ddtable_load_thr_start(struct ddtable *ddtable);
void ddtable_exit(struct ddtable *ddtable);

struct tdisk;
struct write_list;
void scan_dedupe_data(struct bdevgroup *group, struct pgdata *pgdata, struct write_list *wlist);

void ddtable_hash_insert(struct bdevgroup *group, struct pgdata *pgdata, struct index_info_list *index_info_list, struct ddspec_list *ddspec_list);
void ddtable_hash_remove_block(struct ddtable *ddtable, struct ddtable_ddlookup_node *ddlookup, uint64_t block);
struct ddtable_ddlookup_node *ddtable_ddlookup_find_node(struct ddtable *ddtable, uint64_t node_block);

#define LOOKUPS_SYNC_CACHED_COUNT	4096

#ifdef ENABLE_STATS
#define DD_TSTART(sjiff)	(sjiff = ticks)
#define DD_TEND(count,sjiff)					\
do {								\
	mtx_lock(ddtable_stats.stats_lock);			\
	ddtable_stats.count += (ticks - sjiff);			\
	mtx_unlock(ddtable_stats.stats_lock);			\
} while (0)

#define DD_INC(count,val)					\
do {								\
	mtx_lock(ddtable_stats.stats_lock);			\
	ddtable_stats.count += val;				\
	mtx_unlock(ddtable_stats.stats_lock);		\
} while (0)

#define DD_DEC(count,val)					\
do {								\
	mtx_lock(ddtable_stats.stats_lock);			\
	ddtable_stats.count -= val;				\
	mtx_unlock(ddtable_stats.stats_lock);			\
} while (0)
#else
#define DD_TSTART(sjiff)		do {} while (0)
#define DD_TEND(count,sjiff)		do {} while (0)
#define DD_INC(count,val)		do {} while (0)	
#define DD_DEC(count,val)		do {} while (0)	
#endif

#define node_ddlookup_lock(lkp)			\
do {							\
	debug_check(sx_xlocked_check((lkp)->ddlookup_lock));	\
	sx_xlock(lkp->ddlookup_lock);			\
} while (0)

#define node_ddlookup_unlock(lkp)			\
do {							\
	debug_check(!sx_xlocked((lkp)->ddlookup_lock));	\
	sx_xunlock(lkp->ddlookup_lock);			\
} while (0)

#define node_lock(lkp)						\
do {								\
	debug_check(sx_xlocked_check((lkp)->node_lock));	\
	sx_xlock(lkp->node_lock);				\
} while (0)

#define node_unlock(lkp)					\
do {								\
	debug_check(!sx_xlocked((lkp)->node_lock));		\
	sx_xunlock(lkp->node_lock);				\
} while (0)

#define ddlookup_list_lock(lkp)		mtx_lock(lkp->lhead_lock)
#define ddlookup_list_unlock(lkp)	mtx_unlock(lkp->lhead_lock)

#define ddlookup_list_insert_lock(lkp)	sx_xlock(lkp->insert_lock)
#define ddlookup_list_insert_unlock(lkp)	sx_xunlock(lkp->insert_lock)


void ddtable_ddlookup_node_free(struct ddtable_ddlookup_node *ddlookup);

extern struct ddtable_stats ddtable_stats;
#define NODE_GROUP_SHIFT	9
#define NODE_GROUP_SIZE		(1U << NODE_GROUP_SHIFT)
#define NODE_GROUP_MASK		(NODE_GROUP_SIZE - 1)

static inline void
ddtable_ddlookup_write_barrier(struct ddtable_ddlookup_node *ddlookup)
{
#ifdef ENABLE_STATS
	uint32_t start_ticks;
#endif

	pagestruct_t *page, *tmp;

	debug_check(!atomic_test_bit_short(DDLOOKUP_DONE_LOAD, &ddlookup->flags));

	if (!atomic_test_bit_short(DDLOOKUP_META_DATA_DIRTY, &ddlookup->flags) || atomic_test_bit_short(DDLOOKUP_META_DATA_CLONED, &ddlookup->flags))
		return;

	DD_TSTART(start_ticks);
	page = vm_pg_alloc(0);
	if (unlikely(!page)) {
		wait_on_chan(ddlookup->ddlookup_wait, !atomic_test_bit_short(DDLOOKUP_META_DATA_DIRTY, &ddlookup->flags));
	}
	else {
		tmp = ddlookup->metadata;
		memcpy(vm_pg_address(page), vm_pg_address(tmp), DDTABLE_LOOKUP_NODE_SIZE);
		ddlookup->metadata = page;
		atomic_set_bit_short(DDLOOKUP_META_DATA_CLONED, &ddlookup->flags);
		vm_pg_free(tmp);
	}
	DD_TEND(ddlookup_barrier_ticks, start_ticks);
}

extern atomic_t write_requests;

static inline void
ddlookup_set_next_block(struct ddtable_ddlookup_node *ddlookup, uint64_t b_start, uint32_t bid)
{
	struct raw_ddtable_ddlookup_node *raw_ddlookup;

	raw_ddlookup = (struct raw_ddtable_ddlookup_node *)(((uint8_t *)vm_pg_address(ddlookup->metadata)) + RAW_LOOKUP_OFFSET);
	debug_check(raw_ddlookup->next_block);
	SET_BLOCK(raw_ddlookup->next_block, b_start, bid);
}

int ddtable_ddlookup_sync(struct ddtable *ddtable, struct ddtable_ddlookup_node *ddlookup, int async, int root_id, uint64_t prev_b_start);
void ddtable_decr_sync_count(struct ddtable *ddtable, struct ddtable_ddlookup_node *ddlookup);
void ddtable_ddlookup_node_dirty(struct ddtable *ddtable, struct ddtable_ddlookup_node *ddlookup);
void ddtable_ddlookup_node_wait(struct ddtable_ddlookup_node *ddlookup);
struct ddtable_node * node_get(struct ddtable *ddtable, uint64_t b_start);
struct ddtable_ddlookup_node * node_ddlookup(struct ddtable_node *node, uint64_t b_start);
struct ddtable_ddlookup_node * ddtable_ddlookup_node_alloc(allocflags_t flags);
void node_insert(struct ddtable *ddtable, struct ddtable_node *node, struct ddtable_ddlookup_node *child);
struct ddlookup_list * ddlookup_list_get(struct ddtable *ddtable, uint32_t id);
struct ddtable_ddlookup_node * ddtable_sync_list_first(struct ddtable *ddtable);
struct ddtable_ddlookup_node * ddtable_sync_list_next(struct ddtable *ddtable, struct ddtable_ddlookup_node *prev);
void node_ddtable_ha_takeover(struct bdevgroup *group);
void ddtable_check_count(struct ddtable *ddtable);

#endif
