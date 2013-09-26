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

#include "coredefs.h"
#include "bdevmgr.h"
#include "amap.h"
#include "ddtable.h"
#include "tcache.h"
#include "fastlog.h"
#include "log_group.h"
#include "rcache.h"
#include "qs_lib.h"
#include "node_ha.h"
#include "cluster.h"
#include "node_sync.h"
#include "node_ha.h"
#include "bdevgroup.h"

#ifdef ENABLE_STATS
#define PRINT_STAT(x,y)	printf(x" %llu \n", (unsigned long long)bint->y); pause("psg", 10);
#else
#define PRINT_STAT(x,y) do {} while(0)
#endif

#ifdef FREEBSD
struct g_class bdev_vdev_class = {
	.name = "QSTOR::VDEV",
	.version = G_VERSION,
};
#endif

extern struct bdevgroup *group_none;

struct bdevint *bint_list[TL_MAX_DISKS];

uint32_t max_pglist_cnt;

uint32_t index_loads;
uint32_t index_syncs;
uint32_t index_lookup_loads;
uint32_t index_lookup_syncs;
uint32_t bint_syncs;

atomic_t bdevs;
uint32_t cached_indexes_max;
uint32_t cached_indexes;

static struct bintindex * index_alloc(struct index_subgroup *subgroup, uint32_t index_id, allocflags_t flags);
static int bint_mark_index_full(struct bintindex *index);

static void 
calc_index_cache_count(void)
{
	uint64_t availmem = qs_availmem;
	int entry_size;
	int bdev_count = max_t(int, atomic_read(&bdevs), 1);  

	entry_size = sizeof(struct bintindex) + BINT_BMAP_SIZE;
	availmem = availmem/entry_size;
	cached_indexes_max = (availmem * CACHED_INDEXES_PERCENTAGE)/100;
	cached_indexes_max = (cached_indexes_max / bdev_count);
	cached_indexes = (cached_indexes_max * 90) / 100; 
	debug_info("cached indexes %u cached indexes max %u\n", cached_indexes, cached_indexes_max);
}

static void
bdev_removed(void)
{
	atomic_dec(&bdevs);
	calc_index_cache_count();
}

void
bdev_added(void)
{
	atomic_inc(&bdevs);
	calc_index_cache_count();
}

void
bdev_list_remove(struct bdevint *bint)
{
	sx_xlock(bint->group->alloc_lock);
	bdev_remove_from_alloc_list(bint);
	sx_xunlock(bint->group->alloc_lock);
	bint_list[bint->bid] = NULL;
	bint_clear_group_master(bint);
	bdev_group_clear_ha_bint(bint);
	bdev_removed();
}

void
bdev_list_insert(struct bdevint *bint)
{
	sx_xlock(gchain_lock);
	bint_list[bint->bid] = bint;
	sx_xunlock(gchain_lock);
	bdev_added();
}

int
bdev_log_list_count(struct bdevgroup *group)
{
	struct bdevint *bint;
	int count = 0;

	SLIST_FOREACH(bint, &group->bdev_log_list, l_list) {
		count++;
	}
	return count;
}

void
bdev_log_list_insert(struct bdevint *bint)
{
	SLIST_INSERT_HEAD(&bint->group->bdev_log_list, bint, l_list);
}

void
bdev_log_list_remove(struct bdevint *bint, int decr)
{
	struct bdevint *iter;
	int found = 0;
	struct bdevgroup *group = bint->group;

	sx_xlock(group->log_lock);
	SLIST_FOREACH(iter, &group->bdev_log_list, l_list) {
		if (iter == bint) {
			found = 1;
			break;
		}
	}

	if (!found) {
		sx_xunlock(group->log_lock);
		return;
	}
	SLIST_REMOVE(&group->bdev_log_list, bint, bdevint, l_list);
	if (decr)
		atomic_dec(&ddtable_global.cur_log_disks);
	sx_xunlock(group->log_lock);
}

#define MAX_PGLIST_CNT 131072
void
calc_mem_restrictions(uint64_t availmem)
{
	uint64_t logmem;
	uint64_t pgmem;
	int pgdata_size;
	uint32_t max_log_disks;
	int ddbits;
	int entry_size;

	logmem = (availmem * 6) / 100;
	max_log_disks = (logmem / LOG_PAGES_RESERVED); 
	if (max_log_disks > 32)
		max_log_disks = 32;
	if (!max_log_disks)
		max_log_disks = 1;
	debug_info("max log disks %u\n", max_log_disks);

	pgdata_size = (sizeof(struct pgdata)) + LBA_SIZE;
	pgmem = (availmem * 8) / 100;
	max_pglist_cnt = pgmem/pgdata_size;
	if (max_pglist_cnt > MAX_PGLIST_CNT)
		max_pglist_cnt = MAX_PGLIST_CNT;
	ddtable_global.max_log_disks = max_log_disks;
	ddbits = calc_ddbits();
	ddtable_global.max_ddtables = ddbits - 14;

	entry_size = sizeof(struct ddtable_ddlookup_node) + DDTABLE_LOOKUP_NODE_SIZE;
	ddtable_global.max_ddlookup_count = (((availmem / entry_size) * NODE_CACHED_COUNT_CRIT) / 100);
	ddtable_global.reserved_size = (ddtable_global.max_ddlookup_count * DDTABLE_LOOKUP_NODE_SIZE);
	debug_info("max ddlookup count %llu reserved size %llu\n", ddtable_global.max_ddlookup_count, ddtable_global.reserved_size);
	debug_info("max_pglist_cnt %d\n", max_pglist_cnt);
}

static struct bintindex *
bint_index_list_first(struct bdevint *bint)
{
	struct bintindex *index;

	bint_lock(bint);
	index = TAILQ_FIRST(&bint->index_list);
	bint_unlock(bint);
	return index;
}

static struct bintindex *
bint_index_list_next(struct bdevint *bint, struct bintindex *prev)
{
	struct bintindex *index;

	bint_lock(bint);
	index = TAILQ_NEXT(prev, b_list);
	bint_unlock(bint);
	return index;
}

#ifdef FREEBSD 
void bint_free_thread(void *data)
#else
int bint_free_thread(void *data)
#endif
{
	struct bdevint *bint = (struct bdevint *)(data);
	struct bintindex *index, *next;

	for(;;)
	{
		wait_on_chan_interruptible(bint->free_wait, atomic_test_bit(BINT_FREE_START, &bint->flags) || kernel_thread_check(&bint->flags, BINT_FREE_EXIT));
		atomic_clear_bit(BINT_FREE_START, &bint->flags);

		if (kernel_thread_check(&bint->flags, BINT_FREE_EXIT))
			break;

		index = bint_index_list_first(bint);
		while (index) {
			next = bint_index_list_next(bint, index);
			if (atomic_test_bit(META_DATA_ASYNC, &index->flags)) {
				index = next;
				continue;
			}

			sx_xlock(index->subgroup->subgroup_lock);
			mtx_lock(index->subgroup->free_list_lock);
			if (index_busy(index)) {
				mtx_unlock(index->subgroup->free_list_lock);
				sx_xunlock(index->subgroup->subgroup_lock);
				index = next;
				continue;
			}
			TAILQ_REMOVE_INIT(&index->subgroup->free_list, index, i_list);
			LIST_REMOVE_INIT(index, x_list);
			mtx_unlock(index->subgroup->free_list_lock);
			sx_xunlock(index->subgroup->subgroup_lock);

			bint_lock(bint);
			TAILQ_REMOVE_INIT(&bint->index_list, index, b_list);
			bint_unlock(bint);

			if (atomic_test_bit(META_DATA_ASYNC, &index->flags))
				BINT_INC(bint, async_freed, 1);

			index_put(index);
			debug_check(!atomic_read(&bint->index_count));
			atomic_dec(&bint->index_count);
			if (atomic_read(&bint->index_count) < cached_indexes)
				break;
			index = next;
		}
	}
#ifdef FREEBSD 
	kproc_exit(0);
#else
	return 0;
#endif
}

static inline void
bint_remove_index(struct bdevint *bint, struct bintindex *index)
{
	bint_lock(bint);
	if (!TAILQ_ENTRY_EMPTY(index, b_list)) {
		TAILQ_REMOVE_INIT(&bint->index_list, index, b_list);
		debug_check(!atomic_read(&bint->index_count));
		atomic_dec(&bint->index_count);
	}
	bint_unlock(bint);
}

void
bint_tail_index(struct bdevint *bint, struct bintindex *index)
{
	bint_lock(bint);
	if (!TAILQ_ENTRY_EMPTY(index, b_list))
		TAILQ_REMOVE(&bint->index_list, index, b_list);
	TAILQ_INSERT_TAIL(&bint->index_list, index, b_list);
	bint_unlock(bint);
}

static inline void
bint_add_index(struct bdevint *bint, struct bintindex *index)
{
	bint_lock(bint);
	TAILQ_INSERT_TAIL(&bint->index_list, index, b_list);
	atomic_inc(&bint->index_count);
	bint_unlock(bint);
	if (bint->initialized && atomic_read(&bint->index_count) >= cached_indexes_max) {
		atomic_set_bit(BINT_FREE_START, &bint->flags);
		chan_wakeup_one_nointr(bint->free_wait);
	}
}

static inline void 
__bint_decr_free(struct bdevint *bint, uint32_t used)
{
	atomic64_sub(used, &bint->free);
	atomic64_sub(used, &bint->group->free);
}

static inline void 
__bint_incr_free(struct bdevint *bint, uint32_t freed)
{
	atomic64_add(freed, &bint->free);
	atomic64_add(freed, &bint->group->free);
}

void 
__bint_set_free(struct bdevint *bint, uint64_t size)
{
	atomic64_sub(atomic64_read(&bint->free), &bint->group->free);
	atomic64_set(&bint->free, size);
	atomic64_add(size, &bint->group->free);
}

static inline void
bint_decr_free(struct bdevint *bint, uint32_t blocks)
{
	int meta_shift = bint_meta_shift(bint);
	uint32_t used = (blocks << meta_shift);

	__bint_decr_free(bint, used);
	if (!atomic_test_bit(BINT_IO_PENDING, &bint->flags))
		atomic_set_bit(BINT_IO_PENDING, &bint->flags);
}

static inline void
bint_incr_free(struct bdevint *bint, uint32_t blocks)
{
	int meta_shift = bint_meta_shift(bint);
	uint32_t freed = (blocks << meta_shift);

	__bint_incr_free(bint, freed);
	atomic64_add(freed, &bint->free_block_counter);
	if (!atomic_test_bit(BINT_IO_PENDING, &bint->flags))
		atomic_set_bit(BINT_IO_PENDING, &bint->flags);
}


static void
__subgroup_add_to_free_list(struct index_subgroup *subgroup, struct bintindex *index)
{
	struct bintindex *iter;

	debug_check(!TAILQ_ENTRY_EMPTY(index, i_list));
	TAILQ_FOREACH(iter, &subgroup->free_list, i_list) {
#if 0
		if (iter->free_blocks <= index->free_blocks) {
			TAILQ_INSERT_BEFORE(iter, index, i_list);
			return;
		}
#endif
		if (iter->index_id > index->index_id) {
			TAILQ_INSERT_BEFORE(iter, index, i_list);
			atomic_inc(&subgroup->group->bint->free_list_indexes);
			return;
		}
	}
	TAILQ_INSERT_TAIL(&subgroup->free_list, index, i_list);
	atomic_inc(&subgroup->group->bint->free_list_indexes);
}

static inline void
__subgroup_remove_from_free_list(struct index_subgroup *subgroup, struct bintindex *index)
{
	atomic_clear_bit(META_DATA_ASYNC, &index->flags);
	if (!TAILQ_ENTRY_EMPTY(index, i_list)) {
		TAILQ_REMOVE_INIT(&index->subgroup->free_list, index, i_list);
		atomic_dec(&subgroup->group->bint->free_list_indexes);
	}
}

static inline void
subgroup_remove_from_free_list(struct index_subgroup *subgroup, struct bintindex *index)
{
	mtx_lock(subgroup->free_list_lock);
	__subgroup_remove_from_free_list(subgroup, index);
	mtx_unlock(subgroup->free_list_lock);
}

void
index_free(struct bintindex *index)
{
	vm_pg_free(index->metadata);
	wait_chan_free(index->index_wait);
	sx_free(index->index_lock);
	uma_zfree(index_cache, index);
}

static inline uint64_t
bint_index_lookup_bstart(struct bdevint *bint, uint32_t group_id)
{
	uint32_t blocks;
	uint32_t sector_mask = ((1U << bint->sector_shift) - 1);
	uint64_t lookup_b_start;

	lookup_b_start = DDTABLE_META_OFFSET >> bint->sector_shift;
	if (bint->ddmaster) {
		uint32_t ddtables_blocks;
		int ddtables_size;

		ddtables_size = (1U << bint->ddbits) * (sizeof(uint64_t));
		ddtables_blocks = ddtables_size >> bint->sector_shift;
		lookup_b_start += ddtables_blocks;
	}

	blocks = INDEX_LOOKUP_MAP_SIZE >> bint->sector_shift;
	if (INDEX_LOOKUP_MAP_SIZE & sector_mask)
		blocks++;

	return (lookup_b_start + (group_id * blocks));
}

static inline void
index_write_csum(struct bdevint *bint, struct bintindex *index, int incr)
{
	uint64_t csum;
	uint64_t write_id;
	struct raw_bintindex *raw_index;

	raw_index = (struct raw_bintindex *)(((uint8_t *)vm_pg_address(index->metadata)) + RAW_INDEX_OFFSET);
	if (bint->v2_disk) {
		csum = calc_csum16(vm_pg_address(index->metadata), BINT_BMAP_SIZE - sizeof(uint64_t));
		if (incr)
			write_id = write_id_incr(index->write_id, 1);
		else
			write_id = index->write_id;
		csum |= (write_id << 16);
	}
	else {
		write_id = write_id_incr(index->write_id, 1);
		csum = calc_csum(vm_pg_address(index->metadata), BINT_BMAP_SIZE - sizeof(uint64_t));
	}
	index->write_id = write_id;
	raw_index->csum = csum;
}

int 
index_check_csum(struct bintindex *index)
{
	uint64_t csum, raw_csum;
	struct raw_bintindex *raw_index;
	struct bdevint *bint = index->subgroup->group->bint;

	if (atomic_test_bit(META_CSUM_CHECK_DONE, &index->flags))
		return 0;

	if (atomic_test_bit(META_DATA_ERROR, &index->flags))
		return -1;

	raw_index = (struct raw_bintindex *)(((uint8_t *)vm_pg_address(index->metadata)) + RAW_INDEX_OFFSET);
	if (bint->v2_disk) {
		csum = calc_csum16(vm_pg_address(index->metadata), BINT_BMAP_SIZE - sizeof(uint64_t));
		raw_csum = raw_index->csum & 0xFFFF;
		index->write_id = raw_index->csum >> 16;
	}
	else {
		csum = calc_csum(vm_pg_address(index->metadata), BINT_BMAP_SIZE - sizeof(uint64_t));
		raw_csum = raw_index->csum;
		index->write_id = 1;
	}

	if (raw_csum != csum) {
		debug_warn("Metadata csum mismatch for index at %llu %u index csum %llx csum %llx flags %u\n",(unsigned long long)bint_index_bstart(index->subgroup->group->bint, index->index_id), index->subgroup->group->bint->bid, (unsigned long long)raw_index->csum, (unsigned long long)csum, index->flags);
		atomic_set_bit(META_DATA_ERROR, &index->flags);
	}

	atomic_set_bit(META_CSUM_CHECK_DONE, &index->flags);
	return 0;
}

void
bint_initialize_blocks(struct bdevint *bint, int isnew)
{
	uint64_t size = bint->usize;
	int meta_shift = bint_meta_shift(bint);

	bint->max_indexes = ((size >> meta_shift) / BMAP_ENTRIES_UNCOMP);

	bint->max_index_groups = bint->max_indexes >> INDEX_ID_GROUP_SHIFT;
	if (bint->max_indexes & INDEX_ID_GROUP_MASK)
		bint->max_index_groups++;

	bint->index_b_start = bint_index_lookup_bstart(bint, bint->max_index_groups);

	if (isnew)
		__bint_set_free(bint, bint->usize);
}

#ifdef FREEBSD
static void subgroup_end_bio(struct bio *bio)
#else
static void subgroup_end_bio(struct bio *bio, int err)
#endif
{
	struct tcache *tcache;
#ifdef FREEBSD
	int err = bio->bio_error;
	struct biot *biot = (struct biot *)bio_get_caller(bio);
#endif
	struct bintindex *index;

#ifdef FREEBSD
	tcache = biot->cache;
#else
	tcache = (struct tcache *)bio_get_caller(bio);
#endif

	if (unlikely(err))
	{
		SLIST_FOREACH(index, &tcache->priv.meta_list, tc_list) {
			atomic_set_bit(META_DATA_ERROR, &index->flags);
		}
	}

	if (!(atomic_dec_and_test(&tcache->bio_remain)))
		return;

	while ((index = SLIST_FIRST(&tcache->priv.meta_list)) != NULL) {
		SLIST_REMOVE_HEAD(&tcache->priv.meta_list, tc_list);
		if (bio_get_command(bio) == QS_IO_WRITE)
			atomic_clear_bit(META_DATA_DIRTY, &index->flags);
		else
			atomic_clear_bit(META_DATA_READ_DIRTY, &index->flags);
		chan_wakeup(index->index_wait);
		index_put(index);
	}

	complete_io_waiters(&tcache->io_waiters);
	tcache_free_pages(tcache);
	wait_complete_all(tcache->completion);
	tcache_put(tcache);
}

uint32_t subgroup_read_bio;
uint32_t subgroup_write_bio;
uint32_t subgroup_writes;
uint32_t subgroup_index_writes;
uint32_t subgroup_reads;
extern uint32_t index_writes;

int subgroup_write_io(struct index_subgroup *subgroup, struct tcache **ret_tcache, int incr)
{
	struct bintindex *index;
	struct tcache *tcache;
	pagestruct_t *metadata;
	struct index_group *group = subgroup->group;
	struct bdevint *bint = group->bint;
	uint64_t write_id;

	tcache = tcache_alloc(subgroup->max_indexes);
	iowaiters_move(&tcache->io_waiters, &subgroup->io_waiters);

	while ((index = SLIST_FIRST(&subgroup->write_list)) != NULL) {
		SLIST_REMOVE_HEAD(&subgroup->write_list, t_list);
		if (atomic_test_bit(META_DATA_ERROR, &index->flags))
			continue;
		index_get(index);
		index_lock(index);
		metadata = index->metadata;
		vm_pg_ref(metadata);
		atomic_clear_bit(META_IO_PENDING, &index->flags);
		atomic_set_bit(META_DATA_DIRTY, &index->flags);
		atomic_clear_bit(META_DATA_CLONED, &index->flags);
		atomic_clear_bit(META_WRITE_PENDING, &index->flags);
		index_write_csum(bint, index, incr);
		write_id = index->write_id;
		index_unlock(index);
		node_bintindex_sync_send(index, tcache, metadata, write_id);
		SLIST_INSERT_HEAD(&tcache->priv.meta_list, index, tc_list);
		__tcache_add_page(tcache, metadata, bint_index_bstart(bint, index->index_id), bint, BINT_BMAP_SIZE, QS_IO_WRITE, subgroup_end_bio);
		GLOB_INC(index_writes, 1);
	}

	if (!atomic_read(&tcache->bio_remain)) {
		complete_io_waiters(&tcache->io_waiters);
		tcache_put(tcache);
		return 0;
	}

	GLOB_INC(subgroup_write_bio, atomic_read(&tcache->bio_remain));
	GLOB_INC(subgroup_writes, 1);
	__tcache_entry_rw(tcache, QS_IO_WRITE, subgroup_end_bio);
	if (!ret_tcache)
		tcache_put(tcache);
	else
		*ret_tcache = tcache;
	return 0;
}

static struct bintindex * 
bint_subgroup_load_async(struct index_subgroup *subgroup, uint32_t index_id)
{
	int i, start;
	struct tcache *tcache;
	int max = 4;
	struct bintindex *start_index = NULL, *index, *prev;

	tcache = tcache_alloc(max);
	start = index_id - subgroup_index_id(subgroup);
	max = min_t(int, subgroup->max_indexes - start, 4);

	for (i = 0; i < max; i++, index_id++) {
		prev = NULL;
		index = subgroup_locate_index(subgroup, index_id, &prev);
		if (index)
			continue;

		index = index_alloc(subgroup, index_id, 0);
		if (unlikely(!index))
			break;

		if (!start_index) {
			index_get(index);
			start_index = index;
		}

		index_get(index);

		if (prev) {
			LIST_INSERT_AFTER(prev, index, x_list);
		}
		else {
			uint32_t idx = (index->index_id & SUBGROUP_INDEX_LIST_MASK);
			LIST_INSERT_HEAD(&subgroup->index_list[idx], index, x_list);
		}

		atomic_set_bit(META_DATA_READ_DIRTY, &index->flags);
		vm_pg_ref(index->metadata);
		__tcache_add_page(tcache, index->metadata, bint_index_bstart(subgroup->group->bint, index->index_id), subgroup->group->bint, BINT_BMAP_SIZE, QS_IO_READ, subgroup_end_bio);
		SLIST_INSERT_HEAD(&tcache->priv.meta_list, index, tc_list);
		bint_add_index(subgroup->group->bint, index);
		prev = index;
	}

	if (!atomic_read(&tcache->bio_remain)) {
		tcache_put(tcache);
		return start_index;
	}

	GLOB_INC(subgroup_read_bio, atomic_read(&tcache->bio_remain));
	GLOB_INC(subgroup_reads, 1);
	__tcache_entry_rw(tcache, QS_IO_READ, subgroup_end_bio);
	tcache_put(tcache);
	return start_index;
}

static inline void
index_lookup_free(struct index_lookup *ilookup)
{
	if (ilookup->metadata)
		vm_pg_free(ilookup->metadata);

	wait_chan_free(ilookup->lookup_wait);
	mtx_free(ilookup->lookup_lock);
	uma_zfree(index_lookup_cache, ilookup);
}

#define index_lookup_put(indl)				\
do {							\
	if (atomic_dec_and_test(&(indl)->refs))		\
		index_lookup_free(indl);		\
} while (0)

#ifdef FREEBSD 
static void index_lookup_end_bio(struct bio *bio)
#else
static void index_lookup_end_bio(struct bio *bio, int err)
#endif
{
	struct  index_lookup *ilookup = (struct index_lookup *)bio_get_caller(bio);
#ifdef FREEBSD
	int err = bio->bio_error;
#endif

	if (unlikely(err))
	{
		atomic_set_bit(META_DATA_ERROR, &ilookup->flags);
	}

	atomic_clear_bit(META_DATA_DIRTY, &ilookup->flags);
	atomic_clear_bit(META_DATA_READ_DIRTY, &ilookup->flags);
	chan_wakeup(ilookup->lookup_wait);
	index_lookup_put(ilookup);
	bio_free_page(bio);
	g_destroy_bio(bio);
}

#define index_lookup_get(indl)	atomic_inc(&(indl)->refs)

static int
index_lookup_io(struct index_group *group, int rw)
{
	struct index_lookup *ilookup = group->index_lookup;
	pagestruct_t *page = NULL;
	pagestruct_t *metadata;
	int retval;

	if (rw == QS_IO_WRITE && !atomic_test_bit(META_IO_PENDING, &ilookup->flags))
	{
		return 0;
	}
	else if (rw == QS_IO_READ && !atomic_test_bit(META_IO_READ_PENDING, &ilookup->flags))
	{
		return 0;
	}

	if (rw == QS_IO_WRITE)
	{
		atomic_set_bit(META_DATA_DIRTY, &ilookup->flags);
		atomic_clear_bit(META_IO_PENDING, &ilookup->flags);
		page = vm_pg_alloc(0);
		if (unlikely(!page))
			return -1;

		mtx_lock(ilookup->lookup_lock);
		memcpy(vm_pg_address(page), vm_pg_address(ilookup->metadata), PAGE_SIZE);
		mtx_unlock(ilookup->lookup_lock);
		metadata = page;
		node_index_lookup_sync_send(group, page);
	}
	else
	{
		atomic_set_bit(META_DATA_READ_DIRTY, &ilookup->flags);
		atomic_clear_bit(META_IO_READ_PENDING, &ilookup->flags);
		metadata = ilookup->metadata;
	}

	index_lookup_get(ilookup);

	retval = qs_lib_bio_page(ilookup->group->bint, ilookup->b_start, INDEX_LOOKUP_MAP_SIZE, metadata, index_lookup_end_bio, ilookup, rw, TYPE_INDEX_LOOKUP);
	if (unlikely(retval != 0)) {
		atomic_clear_bit(META_DATA_DIRTY, &ilookup->flags); 
		atomic_clear_bit(META_DATA_READ_DIRTY, &ilookup->flags);
		atomic_set_bit(META_DATA_ERROR, &ilookup->flags);
		chan_wakeup(ilookup->lookup_wait);
		index_lookup_put(ilookup);
		if (page)
			vm_pg_free(page);
		return -1;
	}

	wait_on_chan(ilookup->lookup_wait, !atomic_test_bit(META_DATA_DIRTY, &ilookup->flags) && !atomic_test_bit(META_DATA_READ_DIRTY, &ilookup->flags));
	if (page)
		vm_pg_free(page);
	return 0;
}

static struct bintindex *
index_alloc(struct index_subgroup *subgroup, uint32_t index_id, allocflags_t flags)
{
	struct bintindex *index;

	index = __uma_zalloc(index_cache, Q_NOWAIT | Q_ZERO, sizeof(*index));
	if (unlikely(!index)) {
		debug_warn("Memory allocation failure\n");
		return NULL;
	}

	index->metadata = vm_pg_alloc(flags);
	if (unlikely(!index->metadata))
	{
		debug_warn("Unable to allocate index's metadata\n");
		uma_zfree(index_cache, index);
		return NULL;
	}

	index->index_id = index_id;
	SLIST_INIT(&index->io_waiters);
	index->index_lock = sx_alloc("bint index lock");
	index->index_wait = wait_chan_alloc("bint index wait");
	atomic_set(&index->refs, 1);
	index->subgroup = subgroup;
	return index;
}

#ifdef FREEBSD 
static void
bint_dev_close(struct bdevint *bint)
{
	int flags = FREAD | FWRITE;
	
	if (bint->cp) {
		struct g_geom *gp;

		g_topology_lock();
 		gp = bint->cp->geom;
		g_access(bint->cp, -1, -1, 0);
		g_detach(bint->cp);
		g_destroy_consumer(bint->cp);
		g_destroy_geom(gp);
		g_topology_unlock();
	}

	if (bint->b_dev) {
		int vfslocked;

		vfslocked = VFS_LOCK_GIANT(bint->b_dev->v_mount);
		(void)vn_close(bint->b_dev, flags, NOCRED, curthread);
		VFS_UNLOCK_GIANT(vfslocked);
	}
}
#else
static void
bint_dev_close(struct bdevint *bint)
{
	(*kcbs.close_block_device)(bint->b_dev);
}
#endif

static inline void
subgroup_free_index(struct index_subgroup *subgroup, struct bintindex *index)
{
	mtx_lock(subgroup->free_list_lock);
	if (!TAILQ_ENTRY_EMPTY(index, i_list))
		__subgroup_remove_from_free_list(subgroup, index);
	mtx_unlock(subgroup->free_list_lock);

	LIST_REMOVE_INIT(index, x_list);
	bint_remove_index(subgroup->group->bint, index);
	index_put(index);
}

static void
index_subgroup_free(struct index_subgroup *subgroup)
{
	struct bintindex *index, *tvar;
	int i;

	for (i = 0; i < SUBGROUP_INDEX_LIST_BUCKETS; i++) {
		LIST_FOREACH_SAFE(index, &subgroup->index_list[i], x_list, tvar) {
			LIST_REMOVE(index, x_list);
			wait_on_chan(index->index_wait, !atomic_test_bit(META_DATA_DIRTY, &index->flags));
			if (unlikely(atomic_read(&index->refs) > 1)) {
				debug_warn("Index id %u refs %d\n", index->index_id, atomic_read(&index->refs));
			}
#if 0
			debug_check(atomic_test_bit(META_DATA_DIRTY, &index->flags));
			debug_check(atomic_test_bit(META_IO_PENDING, &index->flags));
#endif
			index_put(index);
		}
	}
	wait_chan_free(subgroup->subgroup_wait);
	sx_free(subgroup->subgroup_lock);
	sx_free(subgroup->subgroup_write_lock);
	mtx_free(subgroup->free_list_lock);
	uma_zfree(subgroup_cache, subgroup);
}

static void
index_group_free(struct index_group *group)
{
	int i;
	struct index_subgroup *subgroup;

	if (group->subgroups) {
		for (i = 0; i < group->max_subgroups; i++) {
			subgroup = group->subgroups[i];
			if (!subgroup)
				break;
			index_subgroup_free(subgroup);
		}
		uma_zfree(subgroup_index_cache, group->subgroups);
	}

	if (group->index_lookup)
		index_lookup_put(group->index_lookup);

	sx_free(group->group_lock);
	uma_zfree(group_cache, group);
	return;
}

extern uint64_t bio_reads;
extern uint64_t bio_read_size;
extern uint64_t bio_writes;
extern uint64_t bio_write_size;
extern uint32_t index_lookup_writes;
extern uint32_t bint_writes;
extern uint32_t amap_table_writes;
extern uint32_t amap_writes;
extern uint32_t ddlookup_writes;
extern uint32_t ddtable_writes;
extern uint32_t log_writes;
extern uint32_t tdisk_index_writes;
extern uint32_t index_lookup_reads;
extern uint32_t index_reads;
extern uint32_t bint_reads;
extern uint32_t amap_table_reads;
extern uint32_t amap_reads;
extern uint32_t ddlookup_reads;
extern uint32_t ddtable_reads;
extern uint32_t log_reads;
extern uint32_t tdisk_index_reads;

void
bint_reset_stats(struct bdevint *bint)
{
#ifdef ENABLE_STATS
	bint->index_writes = bint->index_reads = 0;
	bint->fast_lookups = bint->slow_lookups = bint->fast_size = bint->slow_size = 0;
	bint->index_waits = 0;
	bio_reads = bio_read_size = bio_writes = bio_write_size = 0;
	index_lookup_writes = index_writes = bint_writes = amap_table_writes = amap_writes = ddlookup_writes = ddtable_writes = log_writes = tdisk_index_writes = 0;
	index_lookup_reads = index_reads = bint_reads = amap_table_reads = amap_reads = ddlookup_reads = ddtable_reads = log_reads = tdisk_index_reads = 0;
#endif
}

static void
bint_clear(struct bdevint *bint)
{
	pagestruct_t *page;
	int retval;
	uint64_t b_start;
	int pages;

	page = vm_pg_alloc(VM_ALLOC_ZERO);
	if (unlikely(!page)) {
		debug_warn("Page allocation failure\n");
		return;
	}

	if (atomic_test_bit(GROUP_FLAGS_TAIL_META, &bint->group_flags)) {
		b_start = bint->usize >> bint->sector_shift;
		pages = BDEV_META_RESERVED >> LBA_SHIFT;
		pages += (TL_MAX_TDISKS + 1); /* 1 for BDEV META itself */
		retval = tcache_zero_range(bint, b_start, pages);
		if (unlikely(retval != 0))
			debug_warn("Clear failed for vdisk meta and meta from b_start %llu\n", (unsigned long long)b_start);
	}

	retval = qs_lib_bio_lba(bint, bint->b_start, page, QS_IO_WRITE, TYPE_BINT);
	if (unlikely(retval != 0))
		debug_warn("Clear failed for bdev meta at b_start %llu\n", (unsigned long long)bint->b_start);

	b_start = bdev_get_disk_index_block(bint, 0);
	retval = tcache_zero_range(bint, b_start, TL_MAX_TDISKS);
	if (unlikely(retval != 0))
		debug_warn("Clear failed for vdisk meta from b_start %llu\n", (unsigned long long)b_start);
	vm_pg_free(page);
}

void
bint_reset(struct bdevint *bint)
{
	int i;
	struct index_group *group;

	if (bint->sync_task) {
		kernel_thread_stop(bint->sync_task, &bint->flags, bint->sync_wait, BINT_SYNC_EXIT);
		bint->sync_task = NULL;
	}

	if (bint->load_task) {
		kernel_thread_stop(bint->load_task, &bint->flags, bint->load_wait, BINT_LOAD_EXIT);
		bint->load_task = NULL;
	}

	if (bint->free_task) {
		kernel_thread_stop(bint->free_task, &bint->flags, bint->free_wait, BINT_FREE_EXIT);
		bint->free_task = NULL;
	}

	bint_log_groups_free(bint);

	if (bint->index_groups) {
		for (i = 0; i < bint->max_index_groups; i++) {
			group = bint->index_groups[i];
			if (!group)
				continue;
			index_group_free(group);
		}
		free(bint->index_groups, M_INDEXGROUP);
		bint->index_groups = NULL;
	}

	atomic_set(&bint->index_count, 0);
	atomic_set(&bint->free_list_indexes, 0);
	SLIST_INIT(&bint->free_list);
	TAILQ_INIT(&bint->index_list);
}

void 
bint_free(struct bdevint *bint, int free_alloc)
{
	int i;
	struct index_group *group;

	PRINT_STAT("pgdata_duplicate_hits", pgdata_duplicate_hits);
	PRINT_STAT("pgdata_duplicate_misses", pgdata_duplicate_misses);
	PRINT_STAT("subgroup_waits", subgroup_waits);
	PRINT_STAT("log_page_count_misses", log_page_count_misses);
	PRINT_STAT("log_try_lock_misses", log_try_lock_misses);
	PRINT_STAT("log_page_busy_misses", log_page_busy_misses);
	PRINT_STAT("tcache_index_count", tcache_index_count);
	PRINT_STAT("tcache_bio_count", tcache_bio_count);
	PRINT_STAT("index_reads", index_reads);
	PRINT_STAT("index_waits", index_waits);
	PRINT_STAT("index_writes", index_writes);
	PRINT_STAT("async_load", async_load);
	PRINT_STAT("async_skipped", async_skipped);
	PRINT_STAT("async_freed", async_freed);
	PRINT_STAT("load_count", load_count);
	PRINT_STAT("index_barrier_ticks", index_barrier_ticks);
	PRINT_STAT("index_check_load_ticks", index_check_load_ticks);
	PRINT_STAT("index_check_load_hits", index_check_load_hits);
	PRINT_STAT("index_check_load_count", index_check_load_count);
	PRINT_STAT("fast_alloc_ticks", fast_alloc_ticks);
	PRINT_STAT("fast_alloc_misses", fast_alloc_misses);
	PRINT_STAT("fast_alloc_hits", fast_alloc_hits);
	PRINT_STAT("bint_fast_alloc_ticks", bint_fast_alloc_ticks);
	PRINT_STAT("bint_subgroup_load_async_ticks", bint_subgroup_load_async_ticks);
	PRINT_STAT("pgdata_alloc_ticks", pgdata_alloc_ticks);
	PRINT_STAT("subgroup_wait_for_io_ticks", subgroup_wait_for_io_ticks);
	PRINT_STAT("bint_pgdata_alloc_ticks", bint_pgdata_alloc_ticks);
	PRINT_STAT("alloc_block_ticks", alloc_block_ticks);
	PRINT_STAT("bint_clear_node_block_ticks", bint_clear_node_block_ticks);
	PRINT_STAT("bint_locate_node_block_ticks", bint_locate_node_block_ticks);
	PRINT_STAT("bint_set_node_block_ticks", bint_set_node_block_ticks);
	PRINT_STAT("fast_lookups", fast_lookups);
	PRINT_STAT("slow_lookups", slow_lookups);
	PRINT_STAT("fast_lookups_failed", fast_lookups_failed);
	PRINT_STAT("slow_size", slow_size);
	PRINT_STAT("fast_size", fast_size);
	PRINT_STAT("pgalloc_size", pgalloc_size);
	PRINT_STAT("pgrequest_size", pgrequest_size);
	PRINT_STAT("pgalloc_indexes", pgalloc_indexes);
	PRINT_STAT("pgalloc_lookups", pgalloc_lookups);

	if (bint->sync_task) {
		kernel_thread_stop(bint->sync_task, &bint->flags, bint->sync_wait, BINT_SYNC_EXIT);
		bint->sync_task = NULL;
	}

	if (bint->load_task) {
		kernel_thread_stop(bint->load_task, &bint->flags, bint->load_wait, BINT_LOAD_EXIT);
		bint->load_task = NULL;
	}

	if (bint->free_task) {
		kernel_thread_stop(bint->free_task, &bint->flags, bint->free_wait, BINT_FREE_EXIT);
		bint->free_task = NULL;
	}

	bint_log_groups_free(bint);

	if (bint->index_groups) {
		for (i = 0; i < bint->max_index_groups; i++) {
			group = bint->index_groups[i];
			if (!group)
				continue;
			index_group_free(group);
		}
		free(bint->index_groups, M_INDEXGROUP);
		bint->index_groups = NULL;
	}

	if (free_alloc)
		bint_clear(bint);

	if (bint->b_dev)
	{
		bint_dev_close(bint);
	}

	wait_chan_free(bint->sync_wait);
	wait_chan_free(bint->load_wait);
	wait_chan_free(bint->free_wait);
	mtx_free(bint->bint_lock);
	mtx_free(bint->stats_lock);
	sx_free(bint->alloc_lock);
	free(bint, M_BINT);
}

void
index_check_load(struct bintindex *index)
{
	uint32_t free_blocks = 0;
	uint64_t *bmap;
	int i;
	int check_idx = BMAP_ENTRIES_UNCOMP;
#ifdef ENABLE_STATS
	uint32_t start_ticks;
#endif

	BINT_INC(index->subgroup->group->bint, index_check_load_count, 1);
	debug_check(atomic_test_bit(META_IO_READ_PENDING, &index->flags));
	debug_check(atomic_test_bit(META_DATA_READ_DIRTY, &index->flags));
	/* Check to avoid lock */
	if (atomic_test_bit(META_LOAD_DONE, &index->flags)) {
		BINT_INC(index->subgroup->group->bint, index_check_load_hits, 1);
		return;
	}

	index_check_csum(index);
	if (atomic_test_bit(META_DATA_ERROR, &index->flags))
		return;

	BINT_TSTART(start_ticks);
	bmap = (uint64_t *)(vm_pg_address(index->metadata));

	for (i = 0; i < BMAP_ENTRIES_UNCOMP; i++)
	{
		bmapentry_t val = BMAP_GET_BLOCK(bmap, i, BMAP_BLOCK_BITS_UNCOMP);
		if (val)
			continue;
		free_blocks++;
		if (i < check_idx)
			check_idx = i;
	}

	index->free_blocks = free_blocks;
	atomic_set_bit(META_LOAD_DONE, &index->flags);
	index->check_idx = check_idx;
	debug_info("subgroup id %u index id %u check idx %d free blocks %u\n", index->subgroup->subgroup_id, index->index_id, index->check_idx, free_blocks);
	if (index->check_idx == BMAP_ENTRIES_UNCOMP)
		bint_mark_index_full(index);
	else if (!atomic_test_bit(META_INDEX_UNMARKED_FULL, &index->flags))
		bint_unmark_index_full(index);
	BINT_TEND(index->subgroup->group->bint, index_check_load_ticks, start_ticks);
	return;
}

struct bintindex *
subgroup_locate_index(struct index_subgroup *subgroup, uint32_t index_id, struct bintindex **ret_prev)
{
	struct bintindex *prev = NULL, *index;
	uint32_t idx = (index_id & SUBGROUP_INDEX_LIST_MASK);

	LIST_FOREACH(index, &subgroup->index_list[idx], x_list) {
		if (index->index_id == index_id)
			return index;
		else if (index->index_id > index_id)
			break;
		prev = index;
	}

	if (ret_prev)
		*ret_prev = prev;
	return NULL;
}

static struct bintindex *
__subgroup_get_index(struct index_subgroup *subgroup, uint32_t index_id, int load, struct bintindex *prev)
{
	struct bintindex *index;

	if (load) {
		index = bint_subgroup_load_async(subgroup, index_id);
	}
	else {
		index = index_alloc(subgroup, index_id, 0);
		if (unlikely(!index))
			return NULL;

		atomic_set_bit(META_IO_READ_PENDING, &index->flags);
		index_get(index);
		if (prev) {
			LIST_INSERT_AFTER(prev, index, x_list);
		}
		else {
			uint32_t idx = (index->index_id & SUBGROUP_INDEX_LIST_MASK);
			LIST_INSERT_HEAD(&subgroup->index_list[idx], index, x_list);
		}
		bint_add_index(subgroup->group->bint, index);
	}

	return index;
}
 
struct bintindex *
subgroup_get_index(struct index_subgroup *subgroup, uint32_t index_id, int load)
{
	struct bintindex *index;
	struct bintindex *prev = NULL;

	index = subgroup_locate_index(subgroup, index_id, &prev);
	if (index) {
		bint_tail_index(subgroup->group->bint, index);
		index_get(index);
		return (index);
	}

	return __subgroup_get_index(subgroup, index_id, load, prev);
}
 
struct bintindex *
bint_get_index(struct bdevint *bint, uint32_t index_id)
{
	struct bintindex *index;
	struct index_group *group;
	struct index_subgroup *subgroup;
	uint32_t group_id;
	uint32_t subgroup_id, subgroup_offset;

	group_id = index_group_id(index_id);
	subgroup_id = index_subgroup_id(index_id, &subgroup_offset); 

	debug_check(group_id >= bint->max_index_groups);
	if (unlikely(group_id >= bint->max_index_groups))
		return NULL;

	group = bint->index_groups[group_id];

	debug_check(subgroup_id >= group->max_subgroups);
	if (unlikely(subgroup_id >= group->max_subgroups))
		return NULL;

	subgroup = group->subgroups[subgroup_id];
	if (unlikely(!subgroup)) {
		debug_warn("Cannot get subgroup at %u:%u:%u\n", group_id, subgroup_id, index_id);
		return NULL;
	}

	sx_xlock(subgroup->subgroup_lock);
	index = subgroup_get_index(subgroup, index_id, 1);
	sx_xunlock(subgroup->subgroup_lock);
	return index;
}

uint64_t index_locate_hits;
uint64_t index_locate_misses;
uint64_t index_locate_iters;
uint32_t locate_index_ticks;

struct bintindex *
bint_locate_index(struct bdevint *bint, uint32_t index_id, struct index_info_list *index_info_list)
{
	struct index_info *index_info;
	struct bintindex *index;
#ifdef ENABLE_STATS
	uint32_t start_ticks;

	GLOB_TSTART(start_ticks);
#endif

	if (!TAILQ_EMPTY(index_info_list)) {
		index_info = TAILQ_LAST(index_info_list, index_info_list);
		index = index_info->index;
		if (index->index_id == index_id && index->subgroup->group->bint == bint) {
			index_get(index);
			GLOB_INC(index_locate_hits, 1);
			GLOB_TEND(locate_index_ticks, start_ticks);
			return index;
		}
	}

	GLOB_INC(index_locate_misses, 1);
	index = bint_get_index(bint, index_id);
	GLOB_TEND(locate_index_ticks, start_ticks);
	return index;
}

static void
group_decr_free_indexes(struct index_group *group, struct index_subgroup *subgroup)
{
	atomic16_dec(&subgroup->free_indexes);
	atomic16_dec(&group->free_indexes);
}

static void
group_incr_free_indexes(struct index_group *group, struct index_subgroup *subgroup)
{
	atomic16_inc(&subgroup->free_indexes);
	atomic16_inc(&group->free_indexes);
}

static int
bint_mark_index_full(struct bintindex *index)
{
	struct index_group *group = index->subgroup->group;
	struct index_lookup *ilookup = group->index_lookup;
	int id;
	int mask;
	uint32_t val;
	uint32_t index_id;

	index_id = index->index_id - (group->group_id << INDEX_ID_GROUP_SHIFT);
	id = index_id >> 5;
	mask = index_id & 0x1F;

	atomic_clear_bit(META_INDEX_UNMARKED_FULL, &index->flags);
	mtx_lock(ilookup->lookup_lock);
	val = ((uint32_t *)(vm_pg_address(ilookup->metadata)))[id];
	if (val & (1 << mask)) {
		mtx_unlock(ilookup->lookup_lock);
		return 0;
	}

	val |= (1 << mask);
	((uint32_t *)(vm_pg_address(ilookup->metadata)))[id] = val;

	atomic_set_bit(META_IO_PENDING, &ilookup->flags);
	group_decr_free_indexes(group, index->subgroup);
	mtx_unlock(ilookup->lookup_lock);
	return 0;
}

static int
bint_check_if_index_full(struct index_group *group, uint32_t index_id)
{
	struct index_lookup *ilookup = group->index_lookup;
	int id;
	int mask;
	uint32_t val;
	int retval;

	index_id -= (group->group_id << INDEX_ID_GROUP_SHIFT);
	id = index_id >> 5;
	mask = index_id & 0x1F;

	mtx_lock(ilookup->lookup_lock);
	val = ((uint32_t *)(vm_pg_address(ilookup->metadata)))[id];
	if (val & (1 << mask))
		retval = 1;
	else
		retval = 0;
	mtx_unlock(ilookup->lookup_lock);
	return retval;
}

int
bint_unmark_index_full(struct bintindex *index)
{
	struct index_group *group = index->subgroup->group;
	struct index_lookup *ilookup = group->index_lookup;
	int id;
	int mask;
	uint32_t val;
	uint32_t index_id;

	index_id = index->index_id - (group->group_id << INDEX_ID_GROUP_SHIFT);
	id = index_id >> 5;
	mask = index_id & 0x1F;

	atomic_set_bit(META_INDEX_UNMARKED_FULL, &index->flags);
	mtx_lock(ilookup->lookup_lock);
	val = ((uint32_t *)(vm_pg_address(ilookup->metadata)))[id];

	if (!(val & (1 << mask))) {
		mtx_unlock(ilookup->lookup_lock);
		return 0;
	}

	val &= ~(1 << mask);
	((uint32_t *)(vm_pg_address(ilookup->metadata)))[id] = val;

	atomic_set_bit(META_IO_PENDING, &ilookup->flags);
	group_incr_free_indexes(group, index->subgroup);
	mtx_unlock(ilookup->lookup_lock);
	return 0;
}

static inline void
index_mark_blocks(struct bdevint *bint, struct bintindex *index, int start_idx, int count, int barriercheck)
{
	int i;
	uint64_t *bmap;
	int end_count;

	if (barriercheck)
		index_write_barrier(bint, index);

	bmap = (uint64_t *)(vm_pg_address(index->metadata));
	end_count = start_idx + count;
	for (i = start_idx; i < end_count; i++) {
		BMAP_SET_BLOCK(bmap, i, 1ULL, BMAP_BLOCK_BITS_UNCOMP);
	}
	index->free_blocks -= count;
	bint_decr_free(bint, count);
}

static inline int 
index_ref_blocks(struct bdevint *bint, struct bintindex *index, int start_idx, int count)
{
	int i;
	uint64_t *bmap;
	bmapentry_t refs;
	int end_count;

	bmap = (uint64_t *)(vm_pg_address(index->metadata));
	end_count = start_idx + count;
	for (i = start_idx; i < end_count; i++) {
		refs = BMAP_GET_BLOCK(bmap, i, BMAP_BLOCK_BITS_UNCOMP);
		if (unlikely(refs == BMAP_ENTRY_MAX_REFS))
			return -1;
		refs++;
		BMAP_SET_BLOCK(bmap, i, refs, BMAP_BLOCK_BITS_UNCOMP);
	}
	BINT_STATS_ADD(bint, dedupe_blocks, 1);
	return 0;
}

static void
bint_pgdata_scan_duplicates(struct tdisk *tdisk, struct bdevint *bint, struct bintindex *index, struct pgdata *pgdata, struct pgdata_wlist *alloc_list, int start_idx, int count)
{
	struct pgdata *iter, *next, *prev = NULL;
	int retval;

	if (atomic_test_bit(DDBLOCK_DEDUPE_DISABLED, &pgdata->flags) || tdisk->enable_verify)
		return;

	if (!hash_valid((uint64_t *)pgdata->hash))
		return;

	STAILQ_FOREACH_SAFE(iter, alloc_list, w_list, next) {
		if (atomic_test_bit(DDBLOCK_DEDUPE_DISABLED, &iter->flags)) {
			prev = iter;
			BINT_INC(bint, pgdata_duplicate_misses, 1);
			continue;
		}

		if (!hash_equal((uint64_t *)pgdata->hash, (uint64_t *)iter->hash)) {
			prev = iter;
			BINT_INC(bint, pgdata_duplicate_misses, 1);
			continue;
		}

		retval = index_ref_blocks(bint, index, start_idx, count);
		if (unlikely(retval != 0)) {
			prev = iter;
			BINT_INC(bint, pgdata_duplicate_misses, 1);
			continue;
		}

		iter->index_info = pgdata->index_info;
		iter->amap_block = pgdata->amap_block;
		iter->write_size = 0;
		atomic_set_bit(DDBLOCK_ENTRY_FOUND_DUPLICATE, &iter->flags);
		atomic_set_bit(DDBLOCK_ENTRY_DONE_ALLOC, &iter->flags);
		TDISK_STATS_ADD(tdisk, blocks_deduped, 1);
		TDISK_STATS_ADD(tdisk, inline_deduped, 1);
		if (prev)
			STAILQ_REMOVE_AFTER(alloc_list, prev, w_list);
		else
			STAILQ_REMOVE_HEAD(alloc_list, w_list);
		BINT_STATS_ADD(bint, dedupe_blocks, 1);
		BINT_INC(bint, pgdata_duplicate_hits, 1);
	}
}

static int 
bint_alloc_for_pgdata(struct tdisk *tdisk, struct bdevint *bint, struct bintindex *index, struct pgdata_wlist *alloc_list, struct index_info_list *index_info_list, int *mark_full, struct bdevint **ret_bint)
{
	uint64_t *bmap;
	struct pgdata *pgdata;
	int meta_shift = bint_meta_shift(bint);
	uint32_t sector_size = (1U << meta_shift);
	struct index_info *index_info = NULL;
	int i;
	int count;
	int done = 0;
	uint64_t block;
	int alloced = 0;
	int error = 0;
	int barriercheck = 1;

	bmap = (uint64_t *)(vm_pg_address(index->metadata));
	while ((pgdata = STAILQ_FIRST(alloc_list)) != NULL) {
		debug_check(!pgdata->write_size);
		if (pgdata->write_size < sector_size) {
			if (pgdata->comp_pgdata) {
				pgdata_free(pgdata->comp_pgdata);
				pgdata->comp_pgdata = NULL;
			}
			pgdata->write_size = LBA_SIZE;
		}
 
		count = pgdata->write_size >> meta_shift;
		for (i = index->check_idx; i < BMAP_ENTRIES_UNCOMP; i++)
		{
			bmapentry_t val = BMAP_GET_BLOCK(bmap, i, BMAP_BLOCK_BITS_UNCOMP);

			index->check_idx++;
			if (val) {
				done = 0;
				continue;
			}

			if ((done + 1) == count) {
				block = block_from_index(bint, index->index_id, (i - done));
				if (!index_info) {
					index_info = index_info_alloc();
					if (unlikely(!index_info)) {
						error = -1;
						goto out;
					}

					index_info->b_start = block;
					index_get(index);
					index_info->index = index;
					index_info->index_write_id = index->write_id;
					index_add_iowaiter(index, &index_info->iowaiter);
					TAILQ_INSERT_TAIL(index_info_list, index_info, i_list);
				}
				index_mark_blocks(bint, index, (i - done), count, barriercheck);
				if (barriercheck) {
					barriercheck = 0;
					bmap = (uint64_t *)(vm_pg_address(index->metadata));
				}

				STAILQ_REMOVE_HEAD(alloc_list, w_list);
				atomic_set_bit(DDBLOCK_ENTRY_DONE_ALLOC, &pgdata->flags);
				SET_BLOCK(pgdata->amap_block, block, bint->bid);
				SET_BLOCK_SIZE(pgdata->amap_block, pgdata->write_size);
				pgdata->index_info = index_info;
				BINT_INC(bint, pgalloc_size, pgdata->write_size);
				if (pgdata->write_size == LBA_SIZE)
					BINT_STATS_ADD(bint, uncompressed_size, pgdata->write_size);
				else {
					BINT_STATS_ADD(bint, compression_hits, LBA_SIZE);
					BINT_STATS_ADD(bint, compressed_size, pgdata->write_size);
				}

				bint_pgdata_scan_duplicates(tdisk, bint, index, pgdata, alloc_list, (i - done), count);
				alloced = 1;
				done = 0;
				break;
			}
			done++;
		}

		if (index->check_idx == BMAP_ENTRIES_UNCOMP)
			break;
	}

	if (!STAILQ_EMPTY(alloc_list))
		*mark_full = 1;

out:
	if (alloced) {
		*ret_bint = bint;
		BINT_INC(bint, pgalloc_indexes, 1);
		atomic_set_bit(META_IO_PENDING, &index->flags);
	}
	return error;
}
 
static uint64_t
bint_alloc_block(struct bdevint *bint, struct bintindex *index, uint32_t size, struct index_info *index_info, int *mark_full, int type)
{
	uint64_t i;
	uint64_t block;
	uint64_t index_id;
	uint64_t *bmap;
	int meta_shift = bint_meta_shift(bint);
	uint32_t count = size >> meta_shift;
	int done = 0;

	index_id = index->index_id;
	bmap = (uint64_t *)(vm_pg_address(index->metadata));

	for (i = index->check_idx; i < BMAP_ENTRIES_UNCOMP; i++)
	{
		bmapentry_t val = BMAP_GET_BLOCK(bmap, i, BMAP_BLOCK_BITS_UNCOMP);

		if (val) {
			done = 0;
			continue;
		}

		if ((done + 1) == count)
			goto found;
		done++;
	}

	index->check_idx = i;
	*mark_full = 1;
	return (0ULL);

found:
	block = block_from_index(bint, index_id, (i - done));
	debug_check(!block);

	index_mark_blocks(bint, index, (i - done), count, 1);
	atomic_set_bit(META_IO_PENDING, &index->flags);
	index_add_iowaiter(index, &index_info->iowaiter);
	index->check_idx = i + 1;

	if (type == TYPE_DATA_BLOCK) {
		if (size == LBA_SIZE)
			BINT_STATS_ADD(bint, uncompressed_size, size);
		else {
			BINT_STATS_ADD(bint, compression_hits, LBA_SIZE);
			BINT_STATS_ADD(bint, compressed_size, size);
		}
	}

	if (index->check_idx == BMAP_ENTRIES_UNCOMP)
		*mark_full = 1;

	index_get(index);
	index_info->index = index;
	index_info->index_write_id = index->write_id;
	return block;
}

int 
bint_ref_block(struct bdevint *bint, struct bintindex *index, uint32_t entry, uint32_t size, struct index_info *index_info, uint64_t node_block)
{
	uint64_t *bmap;
	int meta_shift = bint_meta_shift(bint);
	uint32_t count = size >> meta_shift;
	int i, j;
	int error = 0;
	bmapentry_t val, refs;
	int oldrefs = 0;
	int end_count;
	uint64_t old_node_block;

	debug_check((entry + count) > BMAP_ENTRIES_UNCOMP);

	bmap = (uint64_t *)(vm_pg_address(index->metadata));
	debug_info("entry %d count %d\n", entry, count);
	end_count = entry + count;
	for (i = entry; i < end_count; i++) {
		val = BMAP_GET_BLOCK(bmap, i, BMAP_BLOCK_BITS_UNCOMP);
		refs = val & INDEX_REFS_MASK;
		old_node_block = (val >> INDEX_REFS_BITS);
 
		if (i == entry) {
			if (node_block && old_node_block != node_block)  {
				debug_info("node block %llu old node block %llu refs %llu\n", (unsigned long long)node_block, (unsigned long long)old_node_block, (unsigned long long)refs);
				return BDEV_ERROR_INVALID_NODE_BLOCK;
			}
		}

		if (unlikely(!refs)) {
			error = BDEV_ERROR_INVALID_REFS;
			goto err;
		}

		if (i == entry)
			oldrefs = refs;
		else if (refs != oldrefs) {
			debug_info("Invalid refs %u oldrefs %d entry %u i %u count %d\n", (uint32_t)refs, oldrefs, entry, i, count);
			error = BDEV_ERROR_INVALID_REFS;
			goto err;
		}
		if (unlikely(refs == BMAP_ENTRY_MAX_REFS)) {
			error = BDEV_ERROR_MAX_REFS;
			goto err;
		}
		refs++;
		val = (old_node_block << INDEX_REFS_BITS) | refs;
		BMAP_SET_BLOCK(bmap, i, val, BMAP_BLOCK_BITS_UNCOMP);
	}

	atomic_set_bit(META_IO_PENDING, &index->flags);

	BINT_STATS_ADD(bint, dedupe_blocks, 1);
	index_add_iowaiter(index, &index_info->iowaiter);
	index_get(index);
	index_info->index = index;
	index_info->index_write_id = index->write_id;
	return 0;
err:
	for (j = entry; j < i; j++) {
		val = BMAP_GET_BLOCK(bmap, j, BMAP_BLOCK_BITS_UNCOMP);
		refs = val & INDEX_REFS_MASK;
		refs--;
		old_node_block = (val >> INDEX_REFS_BITS);
		val = (old_node_block << INDEX_REFS_BITS) | refs;
		BMAP_SET_BLOCK(bmap, j, val, BMAP_BLOCK_BITS_UNCOMP);
	}
	return error;
}

int 
bint_log_replay(struct bdevint *bint, struct bintindex *index, uint32_t entry, uint32_t size, int type)
{
	uint64_t *bmap;
	int meta_shift = bint_meta_shift(bint);
	uint32_t count = size >> meta_shift;
	int i;
	int end_count;
	bmapentry_t val, refs;

	debug_check((entry + count) > BMAP_ENTRIES_UNCOMP);

	bmap = (uint64_t *)(vm_pg_address(index->metadata));
	debug_info("entry %d count %d\n", entry, count);
	end_count = entry + count;
	for (i = entry; i < end_count; i++) {
		val = BMAP_GET_BLOCK(bmap, i, BMAP_BLOCK_BITS_UNCOMP);
		refs = (val & INDEX_REFS_MASK);
		if ((refs == BMAP_ENTRY_MAX_REFS) || (refs && type == TYPE_META_BLOCK))
			continue;
		if (!refs) {
			__bint_decr_free(bint, (1 << meta_shift));
			atomic_set_bit(BINT_IO_PENDING, &bint->flags);
		}
		refs++;
		BMAP_SET_BLOCK(bmap, i, refs, BMAP_BLOCK_BITS_UNCOMP);
	}
	atomic_clear_bit(META_LOAD_DONE, &index->flags);
	atomic_set_bit(META_IO_PENDING, &index->flags);
	return 0;
}

int
bdev_log_replay(struct bdevint *bint, uint64_t block, uint64_t index_write_id, uint32_t size, struct index_info_list *index_info_list, int type)
{
	struct bintindex *index;
	uint64_t index_id;
	uint32_t entry;
	int retval;
	struct index_info *index_info;

	index_id = index_id_from_block(bint, block, &entry);

	index = bint_get_index(bint, index_id);
	if (unlikely(!index))
	{
		debug_warn("Cannot get a index at index_id %llu\n", (unsigned long long)index_id);
		return -1;
	}

	wait_on_chan_check(index->index_wait, !atomic_test_bit(META_DATA_READ_DIRTY, &index->flags));

	index_lock(index);
	index_check_csum(index);
	if (atomic_test_bit(META_DATA_ERROR, &index->flags)) {
		index_put(index);
		index_unlock(index);
		return 0;
	}

	debug_check(index_write_id && !bint->v2_disk);
	if (index_write_id && write_id_greater(index->write_id, index_write_id)) {
		debug_info("index write id %llu index's write id %llu\n", (unsigned long long)index_write_id, (unsigned long long)index->write_id);
		index_unlock(index);
		index_put(index);
		return 0;
	}

	index_info = index_info_alloc();
	if (unlikely(!index_info)) {
		debug_warn("Failed to alloc for index_info\n");
		index_unlock(index);
		index_put(index);
		return -1;
	}

	index_info->index = index;
	debug_info("replay block %u %llu\n", bint->bid, (unsigned long long)block);
	retval = bint_log_replay(bint, index, entry, size, type);
	index_add_iowaiter(index, &index_info->iowaiter);
	index_unlock(index);
	TAILQ_INSERT_TAIL(index_info_list, index_info, i_list);
	return retval;
}

int
bdev_get_node_block(struct bintindex *index, uint32_t *refs, uint64_t *node_block, uint32_t entry_id)
{
	uint64_t *bmap;
	bmapentry_t val;

	index_check_csum(index);
	if (atomic_test_bit(META_DATA_ERROR, &index->flags)) {
		return -1;
	}
	bmap = (uint64_t *)(vm_pg_address(index->metadata));
	val = BMAP_GET_BLOCK(bmap, entry_id, BMAP_BLOCK_BITS_UNCOMP);

	*refs = (uint32_t)(val & INDEX_REFS_MASK);
	*node_block = (val >> INDEX_REFS_BITS);
	return 0;
}

int
bdev_set_node_block(struct bdevint *bint, struct bintindex *index, uint64_t block, uint64_t node_block)
{
	uint64_t *bmap;
	uint32_t entry;
	bmapentry_t val;
	uint64_t old_node_block;
	bmapentry_t refs;

	debug_info("block %lu node_block %lu\n", block, node_block);
	index_id_from_block(bint, block, &entry);

	bmap = (uint64_t *)(vm_pg_address(index->metadata));
	val = BMAP_GET_BLOCK(bmap, entry, BMAP_BLOCK_BITS_UNCOMP);
	debug_info("val before %lu\n", val);
	if (!val) {
		debug_warn("Invalid refs for setting node block\n");
		return -1;
	}

	old_node_block = (val >> INDEX_REFS_BITS);
	if (old_node_block) {
		debug_info("Invalid node block %llu new node block %llu\n", (unsigned long long)old_node_block, (unsigned long long)node_block);
		return -1;
	}

	refs = val & INDEX_REFS_MASK;
	val = (node_block << INDEX_REFS_BITS) | refs;
	index_write_barrier(bint, index);
	bmap = (uint64_t *)(vm_pg_address(index->metadata));
	BMAP_SET_BLOCK(bmap, entry, val, BMAP_BLOCK_BITS_UNCOMP);
	atomic_set_bit(META_IO_PENDING, &index->flags);
	return 0;
}

#ifdef FREEBSD 
static void bio_unmap_end_bio(bio_t *bio)
#else
static void bio_unmap_end_bio(bio_t *bio, int err)
#endif
{
	struct bintindex *index = (struct bintindex *)bio_get_caller(bio);
#ifdef FREEBSD
	int err = bio->bio_error;

	if (err == EOPNOTSUPP) {
		struct bdevint *bint = index->subgroup->group->bint;
		atomic_clear_bit(GROUP_FLAGS_UNMAP, &bint->group_flags);
	}
#endif

	atomic_clear_bit(META_DATA_UNMAP, &index->flags);
	chan_wakeup(index->index_wait);
	g_destroy_bio(bio);
}

static void
bint_unmap_blocks(struct bintindex *index)
{
	struct bdevint *bint;
	uint64_t *bmap;
	int i, meta_shift, retval;
	uint32_t size, blocks;
	uint64_t block;

	index_lock(index);
	if (!atomic_test_bit(META_DATA_UNMAP, &index->flags)) {
		index_unlock(index);
		return;
	}

	debug_info("unmap blocks for index %u check idx %d free blocks %u\n", index->index_id, index->check_idx, index->free_blocks);
	atomic_clear_bit(META_DATA_UNMAP, &index->flags);
	bint = index->subgroup->group->bint;
	if (!bint_unmap_supported(bint) || index->free_blocks != BMAP_ENTRIES_UNCOMP || atomic_test_bit(META_DATA_ERROR, &index->flags)) {
		index_unlock(index);
		return;
	}

	bmap = (uint64_t *)(vm_pg_address(index->metadata));
	for (i = 0; i < BMAP_ENTRIES_UNCOMP; i++) {
		bmapentry_t val = BMAP_GET_BLOCK(bmap, i, BMAP_BLOCK_BITS_UNCOMP);
		debug_check(val);
		if (val) {
			index_unlock(index);
			return;
		}
	}
	index->check_idx = 0;

	meta_shift = bint_meta_shift(bint);
	size = (BMAP_ENTRIES_UNCOMP << meta_shift);
	blocks = size >> bint->sector_shift;
	block = block_from_index(bint, index->index_id, 0);

	debug_info("block %llu blocks %u size %d\n", (unsigned long long)block, blocks, size);
	retval = bio_unmap(bint->b_dev, bint->cp, block, blocks, bint->sector_shift, bio_unmap_end_bio, index);
	if (unlikely(retval != 0)) {
		atomic_clear_bit(META_DATA_UNMAP, &index->flags);
		chan_wakeup(index->index_wait);
		index_unlock(index);
		return;
	}

	wait_on_chan_check(index->index_wait, !atomic_test_bit(META_DATA_UNMAP, &index->flags));
	index_unlock(index);
}

void
bint_free_block(struct bdevint *bint, struct bintindex *index, uint32_t entry, uint32_t size, int *freed, int type, int ignore_errors)
{
	uint64_t *bmap;
	uint32_t count;
	uint32_t i;
	bmapentry_t val;
	bmapentry_t refs, old_refs = 0;
	int end_count;
	int need_free = 0, unmark_full = 0;
	int meta_shift = bint_meta_shift(bint);

	debug_check(!index);
	count = (size >> meta_shift);

	bmap = (uint64_t *)(vm_pg_address(index->metadata));
	end_count = entry + count;
	for (i = entry; i < end_count; i++) {
		val = BMAP_GET_BLOCK(bmap, i, BMAP_BLOCK_BITS_UNCOMP);
		refs = (val & INDEX_REFS_MASK);
		if (i == entry)
			old_refs = refs;
		if (unlikely(!refs || (refs != old_refs))) {
			if (!ignore_errors)
				debug_warn("block %llu index id %u entry %u count %u i %d type %d flags %d\n", (unsigned long long)block_from_index(bint, index->index_id, entry), index->index_id, entry, count, i, type, index->flags);
			return;
		}

		refs--;
		if (!refs) {
			BMAP_SET_BLOCK(bmap, i, 0ULL, BMAP_BLOCK_BITS_UNCOMP);
			bint_incr_free(bint, 1);
			index->free_blocks++;
			debug_check(index->free_blocks > BMAP_ENTRIES_UNCOMP); 
			unmark_full = 1;
			need_free = 1;
		} else {
			bmapentry_t old_node_block;

			old_node_block = (val >> INDEX_REFS_BITS);
			val = ((old_node_block << INDEX_REFS_BITS) | refs);
			BMAP_SET_BLOCK(bmap, i, val, BMAP_BLOCK_BITS_UNCOMP);
			if (i == entry && refs >= 1 && type == TYPE_DATA_BLOCK)
				BINT_STATS_SUB(bint, dedupe_blocks, 1);
		}
	}
	atomic_set_bit(META_IO_PENDING, &index->flags);
	if (need_free && type == TYPE_DATA_BLOCK) {
		if (size == LBA_SIZE)
			BINT_STATS_SUB(bint, uncompressed_size, size);
		else {
			BINT_STATS_SUB(bint, compression_hits, LBA_SIZE);
			BINT_STATS_SUB(bint, compressed_size, size);
		}
	}

	*freed = need_free;
	if (unmark_full && !atomic_test_bit(META_INDEX_UNMARKED_FULL, &index->flags))
		bint_unmark_index_full(index);
	return;
}

int
bint_group_sync(struct bdevint *bint)
{
	int i;
	struct index_group *group;

	for (i = 0; i < bint->max_index_groups; i++) {
		group = bint->index_groups[i];
		if (!group)
			continue;
		index_lookup_io(group, QS_IO_WRITE);
	}
	return 0;
}

int
bint_sync(struct bdevint *bint)
{
	struct raw_bdevint *raw_bint;
	int error = 0;
	int retval, serial_max;
	pagestruct_t *page;

	page = vm_pg_alloc(VM_ALLOC_ZERO);
	if (unlikely(!page)) {
		debug_warn("Page allocation failure\n");
		return -1;
	}

	bint_lock(bint);
	if (!atomic_test_bit(BINT_IO_PENDING, &bint->flags)) {
		bint_unlock(bint);
		vm_pg_free(page);
		while (atomic_test_bit(BINT_DATA_DIRTY, &bint->flags)) {
			pause("psg", 2);
		}

		return 0;
	}
	atomic_clear_bit(BINT_IO_PENDING, &bint->flags);

	raw_bint = (struct raw_bdevint *)(vm_pg_address(page));
	bzero(raw_bint, sizeof(*raw_bint));
	raw_bint->bid = bint->bid;
	raw_bint->group_id = bint->group->group_id;
	raw_bint->usize = bint->usize;
	raw_bint->free = atomic64_read(&bint->free);
	raw_bint->b_start = bint->b_start;
	raw_bint->ddmaster = bint->ddmaster;
	raw_bint->log_disk = bint->log_disk;
	raw_bint->log_disks = bint->log_disks;
	raw_bint->enable_comp = bint->enable_comp;
	raw_bint->ddbits = bint->ddbits;
	raw_bint->sector_shift = bint->sector_shift;
	raw_bint->initialized = bint->initialized;
	raw_bint->log_write = bint->log_write;
	raw_bint->write_cache = bint->write_cache;
	raw_bint->flags = 0;
	if (bint->v2_disk)
		raw_bint->flags |= V2_DISK;
	if (bint->v2_log_format == BINT_V2_LOG_FORMAT)
		raw_bint->flags |= V2_LOG_FORMAT;
	if (bint->v2_log_format == BINT_V3_LOG_FORMAT)
		raw_bint->flags |= V3_LOG_FORMAT;
	if (bint->rid_set) {
		raw_bint->flags |= RID_SET;
		memcpy(raw_bint->mrid, bint->mrid, TL_RID_MAX);
	}
	raw_bint->group_flags = bint->group_flags;
	memcpy(raw_bint->magic, "QUADSTOR", strlen("QUADSTOR"));
	memcpy(raw_bint->quad_prod, "VIRT", strlen("VIRT"));
	memcpy(raw_bint->vendor, bint->vendor, sizeof(bint->vendor));
	memcpy(raw_bint->product, bint->product, sizeof(bint->product));
	serial_max = sizeof(raw_bint->serialnumber);
	memcpy(raw_bint->serialnumber, bint->serialnumber, serial_max);
	memcpy(raw_bint->ext_serialnumber, bint->serialnumber + serial_max, sizeof(raw_bint->ext_serialnumber));
	memcpy(&raw_bint->stats, &bint->stats, sizeof(bint->stats));
	strcpy(raw_bint->group_name, bint->group->name);
	atomic_set_bit(BINT_DATA_DIRTY, &bint->flags);
	bint_unlock(bint);
	node_bint_sync_send(bint);

	retval = qs_lib_bio_lba(bint, bint->b_start, page, QS_IO_WRITE, TYPE_BINT);
	if (unlikely(retval != 0)) {
		debug_warn("Sync failed for bdev meta at b_start %llu\n", (unsigned long long)bint->b_start);
		error = -1;
	}
	atomic_clear_bit(BINT_DATA_DIRTY, &bint->flags);
	vm_pg_free(page);
	return error;
}

static void
bint_finalize(struct bdevint *bint)
{
	if (!bint->sync_task)
		goto free;

	kernel_thread_stop(bint->sync_task, &bint->flags, bint->sync_wait, BINT_SYNC_EXIT);
	kernel_thread_stop(bint->load_task, &bint->flags, bint->load_wait, BINT_LOAD_EXIT);
	kernel_thread_stop(bint->free_task, &bint->flags, bint->free_wait, BINT_FREE_EXIT);
	bint->sync_task = NULL;
	bint->load_task = NULL;
	bint->free_task = NULL;
 	if (!node_in_standby()) {
		bint_sync(bint);
		bint_group_sync(bint);
	}
free:
	atomic_dec(&bint->group->bdevs);
	bint_free(bint, 0);
}

void
bdev_finalize(void)
{
	struct bdevint *bint;
	int i;

#if 0
	if (!atomic_read(&log_error) && master_bint && !node_in_standby()) {
		master_bint->log_write = 1;
		atomic_set_bit(BINT_IO_PENDING, &master_bint->flags);
		bint_sync(master_bint);
	}
#endif

	sx_xlock(gchain_lock);
	for (i = 0; i < TL_MAX_DISKS; i++) {
		bint = bint_list[i];
		if (!bint)
			continue;

		while (bint->create_task) {
			sx_xunlock(gchain_lock);
			pause("psg", 100);
			sx_xlock(gchain_lock);
		}

		if (bint->log_disk) {
			bdev_log_remove(bint, 1);
			bdev_log_list_remove(bint, 1);
		}

		if (!node_in_standby() && bint_is_group_master(bint) && !bint->in_log_replay) {
			bint->log_write = 1;
			atomic_set_bit(BINT_IO_PENDING, &bint->flags);
			bint_sync(bint);
		}

		bdev_list_remove(bint);
		bint_finalize(bint);
	}
	sx_xunlock(gchain_lock);
}

int
bdev_remove(struct bdev_info *binfo)
{
	struct bdevint *bint, *tmp;
	struct bdevint *master_bint;
	struct bdevgroup *group;
	int retval, i;

	dump_ddtable_global();
	if (!atomic_read(&kern_inited) || node_in_standby())
		return -1;

	sx_xlock(gchain_lock);
	bint = bint_list[binfo->bid];
	if (!bint) {
		sx_xunlock(gchain_lock);
		return 0;
	}

	group = bint->group;
	master_bint = bint_get_group_master(bint);

	if (atomic_read(&group->log_error)) {
		sx_xunlock(gchain_lock);
		sprintf(binfo->errmsg, "Cannot delete disk when pool is in error state");
		return -1;
	}

	if (atomic_read(&group->bdevs) > 1 && (bint == master_bint)) {
		sx_xunlock(gchain_lock);
		sprintf(binfo->errmsg, "Cannot delete pool's %s master disk, when pool contains other disks", group->name);
		return -1;
	}

	if (group == group_none && atomic_read(&group->bdevs) == 1) {
		for (i = 0; i < TL_MAX_DISKS; i++) {
			tmp = bint_list[i];
			if (!tmp || tmp == bint)
				continue;

			if (bdev_group_get_log_group(tmp->group) == group_none) {
				sx_xunlock(gchain_lock);
				sprintf(binfo->errmsg, "Cannot delete pool's %s master disk, when other pools depend on Default pool for logging", group->name);
				return -1;
			}

			if (bdev_group_ddtable(tmp->group)->bint == bint) {
				sx_xunlock(gchain_lock);
				sprintf(binfo->errmsg, "Cannot delete pool's %s master disk, when other pools depend on Default pool for deduple tables", group->name);
				return -1;
			}
		}
	}

	while (bint->create_task) {
		sx_xunlock(gchain_lock);
		pause("psg", 100);
		sx_xlock(gchain_lock);
	}

	if (!bint->initialized) {
		sx_xunlock(gchain_lock);
		return -1;
	}

	if (bint->log_disk) {
		retval = bdev_log_remove(bint, 0);
		if (unlikely(retval != 0)) {
			sx_xunlock(gchain_lock);
			return -1;
		}
		bdev_log_list_remove(bint, 1);
		if (bint->log_disk && bint != master_bint) {
			bint_lock(master_bint);
			master_bint->log_disks--;
			atomic_set_bit(BINT_IO_PENDING, &master_bint->flags);
			bint_unlock(master_bint);
			retval = bint_sync(master_bint);
			if (unlikely(retval != 0)) {
				bint_lock(master_bint);
				master_bint->log_disks++;
				bint_unlock(master_bint);
				sx_xunlock(gchain_lock);
				return -1;
			}
		}
	}

	atomic_clear_bit(BINT_SYNC_ENABLED, &bint->flags);
	while (atomic_read(&bint->post_writes))
		pause("psg", 100);

	bdev_list_remove(bint);
	if (bint->ddmaster)
		ddtable_exit(&bint->group->ddtable);

	node_bint_delete_send(bint);
	atomic_dec(&bint->group->bdevs);
	bint_free(bint, binfo->free_alloc);
	sx_xunlock(gchain_lock);
	dump_ddtable_global();
	return 0;
}

int
bdev_wc_config(struct bdev_info *binfo)
{
	struct bdevint *bint;
	int retval;

	if (!atomic_read(&kern_inited) || node_in_standby())
		return -1;

	bint = bdev_find(binfo->bid);
	if (!bint) {
		debug_warn("Cannot find bdev at id %u\n", binfo->bid);
		return -1;
	}

	if (bint->write_cache == binfo->write_cache)
		return 0;

	bint->write_cache = binfo->write_cache;
	atomic_set_bit(BINT_IO_PENDING, &bint->flags);
	retval = bint_sync(bint);
	return retval;
}

int
bdev_unmap_config(struct bdev_info *binfo)
{
	struct bdevint *bint;
	int retval, unmap;

	if (!atomic_read(&kern_inited) || node_in_standby())
		return -1;

	bint = bdev_find(binfo->bid);
	if (!bint) {
		debug_warn("Cannot find bdev at id %u\n", binfo->bid);
		return -1;
	}

	if (binfo->unmap && atomic_test_bit(GROUP_FLAGS_UNMAP_ENABLED, &bint->group_flags))
		return 0;
	else if (!binfo->unmap && !atomic_test_bit(GROUP_FLAGS_UNMAP_ENABLED, &bint->group_flags))
		return 0;

	if (binfo->unmap) {
		atomic_set_bit(GROUP_FLAGS_UNMAP_ENABLED, &bint->group_flags);
		unmap = bdev_unmap_support(bint->b_dev);
		if (unmap)
			atomic_set_bit(GROUP_FLAGS_UNMAP, &bint->group_flags);
	}
	else {
		atomic_clear_bit(GROUP_FLAGS_UNMAP_ENABLED, &bint->group_flags);
		atomic_clear_bit(GROUP_FLAGS_UNMAP, &bint->group_flags);
	}

	atomic_set_bit(BINT_IO_PENDING, &bint->flags);
	retval = bint_sync(bint);
	return retval;
}

int
bdev_ha_config(struct bdev_info *binfo)
{
	struct bdevint *bint;
	struct bdevint *ha_bint;
	int retval;

	if (!atomic_read(&kern_inited) || node_in_standby())
		return -1;

	bint = bdev_find(binfo->bid);
	if (!bint) {
		debug_warn("Cannot find bdev at id %u\n", binfo->bid);
		return -1;
	}

	ha_bint = bdev_group_get_ha_bint();
	if (binfo->ha_disk && ha_bint) {
		debug_warn("HA disk already set to %u from pool %s\n", ha_bint->bid, ha_bint->group->name);
		return -1;
	}

	if (!binfo->ha_disk && !bint_is_ha_disk(bint)) {
		debug_check(ha_bint);
		return 0;
	}

	if (binfo->ha_disk)
		atomic_set_bit(GROUP_FLAGS_HA_DISK, &bint->group_flags);
	else
		atomic_clear_bit(GROUP_FLAGS_HA_DISK, &bint->group_flags);

	atomic_set_bit(BINT_IO_PENDING, &bint->flags);
	retval = bint_sync(bint);
	if (unlikely(retval != 0))
		goto err;

	if (bint_is_ha_disk(bint)) {
		bdev_group_set_ha_bint(bint);
		ha_init_config();
		node_controller_ha_init();
	}
	else {
		bdev_group_clear_ha_bint(bint);
	}

	return 0;
err:
	if (binfo->ha_disk)
		atomic_set_bit(GROUP_FLAGS_HA_DISK, &bint->group_flags);
	else
		atomic_clear_bit(GROUP_FLAGS_HA_DISK, &bint->group_flags);
	return -1;
}

int
bdev_get_info(struct bdev_info *binfo)
{
	struct bdevint *bint;
	uint64_t reserved;

	if (!atomic_read(&kern_inited))
		return -1;

	bint = bdev_find(binfo->bid);
	if (!bint)
	{
		debug_warn("Cannot find bdev at id %u\n", binfo->bid);
		return -1;
	}

	reserved = (bint_index_bstart(bint, bint->max_indexes) << bint->sector_shift);

	binfo->size = bint->usize;
	binfo->usize = bint->usize;
	binfo->free = atomic64_read(&bint->free);
	binfo->log_disk = bint->log_disk;
	binfo->ha_disk = bint_is_ha_disk(bint);
	binfo->enable_comp = bint->enable_comp;
	binfo->ddmaster = bint->ddmaster;
	binfo->reserved = reserved;
	binfo->group_id = bint->group->group_id;
	binfo->write_cache = bint->write_cache;
	binfo->unmap = atomic_test_bit(GROUP_FLAGS_UNMAP_ENABLED, &bint->group_flags) ? 1 : 0;
	if (bint->initialized > 0)
		binfo->initialized = bint->initialized && !bint->create_task;
	else
		binfo->initialized = bint->initialized;
	binfo->max_index_groups = bint->max_index_groups;
	memcpy(&binfo->stats, &bint->stats, sizeof(bint->stats));
	return 0;
}

static int
bint_load(struct bdevint *bint)
{
	struct raw_bdevint *raw_bint;
	int retval;
	pagestruct_t *page;

	page = vm_pg_alloc(0);
	if (unlikely(!page)) {
		debug_warn("Page allocation failure\n");
		return -1;
	}

	retval = qs_lib_bio_lba(bint, bint->b_start, page, QS_IO_READ, TYPE_BINT);
	if (unlikely(retval != 0)) {
		debug_warn("Failed to read bint meta\n");
		goto err;
	}

	raw_bint = (struct raw_bdevint *)(vm_pg_address(page));

	if (memcmp(raw_bint->magic, "QUADSTOR", strlen("QUADSTOR"))) {
		debug_warn("raw bint magic mismatch\n");
		goto err;
	}

	if (memcmp(raw_bint->vendor, bint->vendor, sizeof(bint->vendor))) {
		debug_warn("raw bint vendor mismatch\n");
		goto err;
	}

	if (memcmp(raw_bint->product, bint->product, sizeof(bint->product))) {
		debug_warn("raw bint product mismatch\n");
		goto err;
	}

	if (!raw_bint_serial_match(raw_bint, bint->serialnumber, bint->serial_len)) {
		debug_warn("raw bint serialnumber mismatch %.32s %.32s\n", raw_bint->serialnumber, bint->serialnumber);
		goto err;
	}

	if (unlikely(raw_bint->bid != bint->bid)) {
		debug_warn("raw bid %u mismatch with bid %u\n", raw_bint->bid, bint->bid);
		goto err;
	}

	if (unlikely(raw_bint->usize != bint->usize)) {
		if (bint->usize < raw_bint->usize) {
			/* Cannot shrink a disk */
			debug_warn("raw size %llu mismatch with size %llu\n", (unsigned long long)raw_bint->usize, (unsigned long long)bint->usize);
			goto err;
		}
		bint->usize = raw_bint->usize;
	}

	if (unlikely(raw_bint->b_start != bint->b_start)) {
		debug_warn("raw b_start %llu mismatch with b_start %llu\n", (unsigned long long)raw_bint->b_start, (unsigned long long)bint->b_start);
		goto err;
	}

	if (unlikely(raw_bint->sector_shift != bint->sector_shift)) {
		debug_warn("raw sector_shift %u mismatch with sector shift %u\n", raw_bint->sector_shift, bint->sector_shift);
		goto err;
	}

	bint->group = bdev_group_locate(raw_bint->group_id, NULL);
	if (unlikely(!bint->group)) {
		debug_warn("Cannot locate pool at %u\n", raw_bint->group_id);
		goto err;
	}

	bint->ddmaster = raw_bint->ddmaster;
	bint->log_disk = raw_bint->log_disk;
	bint->log_disks = raw_bint->log_disks;
	bint->enable_comp = raw_bint->enable_comp;
	bint->ddbits = raw_bint->ddbits;
	__bint_set_free(bint, raw_bint->free);
	bint->initialized = raw_bint->initialized;
	bint->log_write = raw_bint->log_write;
	bint->write_cache = raw_bint->write_cache;

	if (raw_bint->flags & V2_DISK)
		bint->v2_disk = 1;
	if (raw_bint->flags & V2_LOG_FORMAT)
		bint->v2_log_format = BINT_V2_LOG_FORMAT;
	if (raw_bint->flags & V3_LOG_FORMAT)
		bint->v2_log_format = BINT_V3_LOG_FORMAT;
	if (raw_bint->flags & RID_SET) {
		bint->rid_set = 1;
		memcpy(bint->mrid, raw_bint->mrid, TL_RID_MAX);
	}
	bint->group_flags = raw_bint->group_flags;
	memcpy(&bint->stats, &raw_bint->stats, sizeof(bint->stats));
	/* Fix for older stats, with compression hits missing */
	if (bint->stats.compressed_size && !bint->stats.compression_hits) {
		bint->stats.compression_hits = (bint->stats.compressed_size * 2); /* Assume 2:1 */
	}
	vm_pg_free(page);

	return 0;
err:
	vm_pg_free(page);
	return -1;
}

#ifdef FREEBSD 
static void
bdev_orphan(struct g_consumer *cp)
{
}

int
bint_dev_open(struct bdevint *bint, struct bdev_info *binfo)
{
	struct nameidata nd;
	int flags = FREAD | FWRITE; /* snm need to check on O_EXLOCK */
	int error;
	int vfslocked;
	struct g_provider *pp;
	struct g_geom *gp;
	struct g_consumer *cp;
	uint32_t sector_shift = 0;

	NDINIT(&nd, LOOKUP, NOFOLLOW, UIO_SYSSPACE, binfo->devpath, curthread);
	error = vn_open(&nd, &flags, 0, NULL);
	if (error)
	{
		debug_warn("failed to open disk %s error %d\n", binfo->devpath, error);
		return -1;
	}
	vfslocked = NDHASGIANT(&nd);
	NDFREE(&nd, NDF_ONLY_PNBUF);

	bint->b_dev = nd.ni_vp;
	if (!vn_isdisk(bint->b_dev, &error))
	{
		debug_warn("path %s doesnt correspond to a disk error %d\n", binfo->devpath, error);
		goto err;
	}

	g_topology_lock();

	pp = g_dev_getprovider(bint->b_dev->v_rdev);
	gp = g_new_geomf(&bdev_vdev_class, "qstor::vdev");
	gp->orphan = bdev_orphan;
	cp = g_new_consumer(gp);

	error = g_attach(cp, pp);
	if (error != 0) {
		debug_warn("Failed to attached GEOM consumer error %d\n", error);
		goto gcleanup;
	}

	error = g_access(cp, 1, 1, 0);
	if (error != 0) {
		debug_warn("Failed to set access for GEOM consumer error %d\n", error);
		g_detach(cp);
		goto gcleanup;
	}

	calc_sector_bits(pp->sectorsize, &sector_shift);
	bint->sector_shift = sector_shift;
	bint->usize = pp->mediasize;

	bint->cp = cp;
	g_topology_unlock();

	VOP_UNLOCK(bint->b_dev, 0);
	VFS_UNLOCK_GIANT(vfslocked);
	return 0;
gcleanup:
	g_destroy_consumer(cp);
	g_destroy_geom(gp);
	g_topology_unlock();
err:
	VOP_UNLOCK(bint->b_dev, 0);
	bint_dev_close(bint);
	VFS_UNLOCK_GIANT(vfslocked);
	return -1;
}
#else
int
bint_dev_open(struct bdevint *bint, struct bdev_info *binfo)
{
	int error = 0;
	uint32_t sector_size = 0;
	uint32_t sector_shift = 0;

	bint->b_dev = (*kcbs.open_block_device)(binfo->devpath, &bint->usize, &sector_size, &error);
	if (unlikely(!bint->b_dev)) {
		debug_warn("Unable to open dev %s err is %d\n", binfo->devpath, error);
		return -1;
	}

	calc_sector_bits(sector_size, &sector_shift);
	bint->sector_shift = sector_shift;
	return 0;
}
#endif

static struct index_subgroup *
index_subgroup_alloc(struct index_group *group, uint32_t subgroup_id)
{
	struct index_subgroup *subgroup;
	int i;

	subgroup = __uma_zalloc(subgroup_cache, Q_NOWAIT | Q_ZERO, sizeof(*subgroup));
	if (unlikely(!subgroup)) {
		debug_warn("Memory allocation failure\n");
		return NULL;
	}

	TAILQ_INIT(&subgroup->free_list);
	for (i = 0; i < SUBGROUP_INDEX_LIST_BUCKETS; i++)
		LIST_INIT(&subgroup->index_list[i]);
	SLIST_INIT(&subgroup->write_list);
	SLIST_INIT(&subgroup->io_waiters);
	subgroup->subgroup_lock = sx_alloc("subgroup lock");
	subgroup->subgroup_write_lock = sx_alloc("subgroup write lock");
	subgroup->subgroup_wait = wait_chan_alloc("subgroup wait");
	subgroup->free_list_lock = mtx_alloc("free list lock");
	subgroup->group = group;
	subgroup->subgroup_id = subgroup_id;
	subgroup->max_indexes = min_t(uint32_t, MAX_INDEXES_PER_SUBGROUP, (subgroup->group->bint->max_indexes - subgroup_index_id(subgroup)));
	return subgroup;
}

static struct index_lookup *
index_lookup_alloc(struct index_group *group)
{
	struct index_lookup *ilookup;

	ilookup = __uma_zalloc(index_lookup_cache, Q_NOWAIT | Q_ZERO, sizeof(*ilookup));
	if (unlikely(!ilookup)) {
		debug_warn("Memory allocation failure\n");
		return NULL;
	}

	ilookup->metadata = vm_pg_alloc(0);
	if (unlikely(!ilookup->metadata)) {
		debug_warn("Page allocation failure\n");
		uma_zfree(index_lookup_cache, ilookup);
		return NULL;
	}

	ilookup->group = group;
	ilookup->b_start = bint_index_lookup_bstart(group->bint, group->group_id);
	atomic_set(&ilookup->refs, 1);
	ilookup->lookup_lock = mtx_alloc("ilookup lock");
	ilookup->lookup_wait = wait_chan_alloc("ilookup wait");
	return ilookup;
}

static struct index_group * 
index_group_alloc(struct bdevint *bint, uint32_t group_id)
{
	struct index_group *group;
	int max_indexes;

	group = __uma_zalloc(group_cache, Q_NOWAIT | Q_ZERO, sizeof(*group));
	if (unlikely(!group)) {
		debug_warn("Slab allocation failure\n");
		return NULL;
	}

	group->group_lock = sx_alloc("group lock");
	SLIST_INIT(&group->free_list);
	group->group_id = group_id;
	group->bint = bint;
	max_indexes = min_t(uint32_t, MAX_INDEXES_PER_GROUP, (group->bint->max_indexes - group_index_id(group)));

	group->max_subgroups = max_indexes >> INDEX_ID_SUBGROUP_SHIFT;
	if ((max_indexes & INDEX_ID_SUBGROUP_MASK))
		group->max_subgroups++;

	debug_check(group->max_subgroups > INDEX_GROUP_MAX_SUBGROUPS);
	group->subgroups = __uma_zalloc(subgroup_index_cache, Q_NOWAIT | Q_ZERO, INDEX_GROUP_MAX_SUBGROUPS * sizeof(struct index_subgroup *));
	if (unlikely(!group->subgroups)) {
		debug_warn("Memory allocation failure\n");
		uma_zfree(group_cache, group);
		return NULL;
	}

	group->index_lookup = index_lookup_alloc(group);
	if (unlikely(!group->index_lookup)) {
		uma_zfree(subgroup_index_cache, group->subgroups);
		uma_zfree(group_cache, group);
		return NULL;
	}

	return group;
}

static struct bintindex *
__bint_index_new(struct index_subgroup *subgroup, uint32_t index_id)
{
	struct bintindex *index;

	index = index_alloc(subgroup, index_id, VM_ALLOC_ZERO);
	if (unlikely(!index))
		return NULL;

	index->check_idx = 0;
	index->write_id = 1;
	index->free_blocks = BMAP_ENTRIES_UNCOMP;
	atomic_set_bit(META_LOAD_DONE, &index->flags);
	atomic_set_bit(META_CSUM_CHECK_DONE, &index->flags);
	return index;
}

static int
tcache_add_index(struct tcache *tcache, struct index_subgroup *subgroup, struct bintindex *index, int dir)
{
	int retval;
#ifdef ENABLE_STATS
	uint32_t start_ticks;
#endif

	index_get(index);
	BINT_TSTART(start_ticks);
	retval = tcache_add_page(tcache, index->metadata, bint_index_bstart(subgroup->group->bint, index->index_id), index->subgroup->group->bint, BINT_INDEX_META_SIZE, dir);
	BINT_TEND(subgroup->group->bint, tcache_add_page_ticks, start_ticks);
	if (unlikely(retval != 0)) {
		index_put(index);
		return -1;
	}
	if (dir == QS_IO_WRITE) {
		atomic_clear_bit(META_IO_PENDING, &index->flags);
		atomic_set_bit(META_DATA_DIRTY, &index->flags);
	}
	else {
		atomic_clear_bit(META_IO_READ_PENDING, &index->flags);
		atomic_set_bit(META_DATA_READ_DIRTY, &index->flags);
	}
	SLIST_INSERT_HEAD(&tcache->priv.meta_list, index, t_list);
	return 0;
}

static void
tcache_put_indexes_write(struct tcache *tcache)
{
	struct bintindex *index;

	while ((index = SLIST_FIRST(&tcache->priv.meta_list)) != NULL) {
		SLIST_REMOVE_HEAD(&tcache->priv.meta_list, t_list);
		atomic_clear_bit(META_DATA_DIRTY, &index->flags);
		chan_wakeup(index->index_wait);
		index_put(index);
	}
}

static void
tcache_put_indexes_read(struct index_subgroup *subgroup, struct tcache *tcache, int mark_async)
{
	struct bintindex *index;

	while ((index = SLIST_FIRST(&tcache->priv.meta_list)) != NULL) {
		SLIST_REMOVE_HEAD(&tcache->priv.meta_list, t_list);
		atomic_clear_bit(META_DATA_READ_DIRTY, &index->flags);
		chan_wakeup(index->index_wait);
		index_lock(index);
		index_check_load(index);
		index_unlock(index);
		if (atomic_test_bit(META_DATA_ERROR, &index->flags)) {
			index_put(index);
			continue;
		}
		mtx_lock(subgroup->free_list_lock);
		if (index->free_blocks >= FREE_BLOCKS_MIN && TAILQ_ENTRY_EMPTY(index, i_list)) {
			if (mark_async)
				atomic_set_bit(META_DATA_ASYNC, &index->flags);
			__subgroup_add_to_free_list(subgroup, index);
		}
		mtx_unlock(subgroup->free_list_lock);
		index_put(index);
	}
}

static void
tcache_error_indexes(struct tcache *tcache)
{
	struct bintindex *index;

	while ((index = SLIST_FIRST(&tcache->priv.meta_list)) != NULL) {
		SLIST_REMOVE_HEAD(&tcache->priv.meta_list, t_list);
		atomic_set_bit(META_DATA_ERROR, &index->flags);
		atomic_clear_bit(META_DATA_READ_DIRTY, &index->flags);
		atomic_clear_bit(META_DATA_DIRTY, &index->flags);
		chan_wakeup(index->index_wait);
		index_put(index);
	}
}

static void
bint_subgroup_load_post(struct index_subgroup *subgroup, struct tcache *tcache, int mark_async)
{
	BINT_INC(subgroup->group->bint, tcache_bio_count, atomic_read(&tcache->bio_remain));
	tcache_entry_rw(tcache, QS_IO_READ);
	wait_for_done(tcache->completion);
	if (atomic_test_bit_short(TCACHE_IO_ERROR, &tcache->flags))
		goto err;

	tcache_put_indexes_read(subgroup, tcache, mark_async);
	tcache_put(tcache);

	sx_xlock(subgroup->subgroup_lock);
	subgroup->inload = 0;
	sx_xunlock(subgroup->subgroup_lock);
	chan_wakeup(subgroup->subgroup_wait);
	return;
err:
	tcache_error_indexes(tcache);
	tcache_put(tcache);
}

static int
bint_subgroup_load(struct index_subgroup *subgroup, int start, int max, uint32_t *index_count, struct tcache **ret_tcache, int mark_async)
{
	struct bintindex *prev;
	struct bintindex *index;
	uint32_t start_index_id;
	struct tcache *tcache;
	int i;
	int done = 0;
	int error = 0;
	int retval;

	debug_info("subgroup load start %d subgroup id %u free indexes %d\n", start, subgroup->subgroup_id, atomic_read(&subgroup->free_indexes));
	tcache = tcache_alloc(max);
	start_index_id = subgroup_index_id(subgroup);
	for (i = start; i < subgroup->max_indexes; i++) {
		prev = NULL;
		index = subgroup_locate_index(subgroup, start_index_id + i, &prev);
		if (index) {
			if (atomic_test_bit(META_DATA_READ_DIRTY, &index->flags))
				continue;

			if (!atomic_test_bit(META_LOAD_DONE, &index->flags)) {
				index_lock(index);
				index_check_load(index);
				index_unlock(index);
			}

			if (atomic_test_bit(META_DATA_ERROR, &index->flags))
				continue;

			mtx_lock(subgroup->free_list_lock);
			if (index->free_blocks >= FREE_BLOCKS_MIN && TAILQ_ENTRY_EMPTY(index, i_list)) {
				if (mark_async)
					atomic_set_bit(META_DATA_ASYNC, &index->flags);
				__subgroup_add_to_free_list(subgroup, index);
			}
			mtx_unlock(subgroup->free_list_lock);
			continue;
		}

		if (subgroup->donefirstload && bint_check_if_index_full(subgroup->group, start_index_id + i))
			continue;

		index = __subgroup_get_index(subgroup, start_index_id + i, 0, prev);
		if (!index)
			return -1;

		if (atomic_test_bit(META_IO_READ_PENDING, &index->flags)) {
			BINT_INC(subgroup->group->bint, tcache_index_count, 1);
			retval = tcache_add_index(tcache, subgroup, index, QS_IO_READ);
			if (unlikely(retval)) {
				error = -1;
				index_put(index);
				goto err;
			}
		}
		index_put(index);
		*(index_count) += 1;
		done++;
		if (done == max)
			break;
	}

	if (!atomic_read(&tcache->bio_remain)) {
		tcache_put(tcache);
		return done;
	}

	subgroup->inload = 1;
	*ret_tcache = tcache;
	subgroup->donefirstload = 1;
	return done;
err:
	tcache_error_indexes(tcache);
	tcache_put(tcache);
	return error;
}

static int
bint_subgroup_load_init(struct index_subgroup *subgroup)
{
	int i;
	uint32_t start_index_id;

	start_index_id = subgroup_index_id(subgroup);
	for (i = 0; i < subgroup->max_indexes; i++) {
		if (bint_check_if_index_full(subgroup->group, start_index_id + i))
			continue;
		group_incr_free_indexes(subgroup->group, subgroup);
	}

	return 0;
}

static void
subgroup_free_unused(struct index_subgroup *subgroup, uint32_t *index_count, int force)
{
	struct bintindex *index, *tvar;
	int i;

	if (!force && *index_count <= CACHED_INDEX_COUNT) {
		return;
	}

	for (i = 0; i < SUBGROUP_INDEX_LIST_BUCKETS; i++) {
		LIST_FOREACH_SAFE(index, &subgroup->index_list[i], x_list, tvar) {
			if (index_busy(index))
				continue;

			subgroup_free_index(subgroup, index);
			*(index_count) -= 1;

			if (!force && *index_count <= CACHED_INDEX_COUNT)
				return; 
		}
	}
	return;

}

static int
bint_group_new(struct index_group *group)
{
	struct index_lookup *ilookup = group->index_lookup;

	atomic_set_bit(META_IO_PENDING, &ilookup->flags);
	bzero(vm_pg_address(ilookup->metadata), INDEX_LOOKUP_MAP_SIZE);
	return 0;
}

static int
bint_group_load(struct index_group *group)
{
	atomic_set_bit(META_IO_READ_PENDING, &group->index_lookup->flags);
	return index_lookup_io(group, QS_IO_READ);
}

static void 
bint_index_mark_reserved(struct bintindex *index, uint32_t *reserved_blocks)
{
	uint32_t todo;
	uint64_t *bmap;
	int i;
	struct bdevint *bint = index->subgroup->group->bint;
	bmapentry_t val = 1;

	todo = min_t(uint32_t, (*reserved_blocks), BMAP_ENTRIES_UNCOMP);

	bmap = (uint64_t *)(vm_pg_address(index->metadata));
	for (i = 0; i < todo; i++)
	{
		BMAP_SET_BLOCK(bmap, i, val, BMAP_BLOCK_BITS_UNCOMP);
	}
	*(reserved_blocks) -= todo;
	index->free_blocks -= todo;
	bint_decr_free(bint, todo);

	if (i == BMAP_ENTRIES_UNCOMP)
		bint_mark_index_full(index);
}

static int
tcache_free_unused_write(struct tcache_list *tcache_list)
{
	int error = 0;
	struct tcache *tcache;

	while ((tcache = SLIST_FIRST(tcache_list)) != NULL) {
		wait_for_done(tcache->completion);

		if (atomic_test_bit_short(TCACHE_IO_ERROR, &tcache->flags)) {
			debug_warn("tcache write failed\n");
			error = -1;
		}

		SLIST_REMOVE_HEAD(tcache_list, t_list);
		if (error)
			tcache_error_indexes(tcache);
		else
			tcache_put_indexes_write(tcache);
		tcache_put(tcache);
	}
	return error;
}

static int
bint_subgroup_new(struct index_subgroup *subgroup, uint32_t *reserved_blocks, uint32_t *index_count, struct tcache_list *tcache_list)
{
	uint32_t start_index_id;
	uint32_t max;
	uint32_t i;
	uint32_t idx;
	struct bintindex *index, *prev = NULL;
	struct bdevint *bint = subgroup->group->bint;
	int need_sync = 0;
	int retval;
	struct tcache *tcache = NULL;

	start_index_id = subgroup_index_id(subgroup);
	max = start_index_id + subgroup->max_indexes;
	atomic16_set(&subgroup->free_indexes, subgroup->max_indexes);
	atomic16_add(subgroup->max_indexes, &subgroup->group->free_indexes);

	for (i = start_index_id; i < max; i++) {
		index = __bint_index_new(subgroup, i);
		if (unlikely(!index)) {
			debug_warn("Failed to create index at id %u\n", i);
			return -1;
		}

		if (*reserved_blocks) {
			bint_index_mark_reserved(index, reserved_blocks);
		}

		idx = (index->index_id & SUBGROUP_INDEX_LIST_MASK);
		if (prev)
			LIST_INSERT_AFTER(prev, index, x_list);
		else
			LIST_INSERT_HEAD(&subgroup->index_list[idx], index, x_list);
		prev = index;
		bint_add_index(bint, index);

		if (!tcache)
			tcache = tcache_alloc(TCACHE_ALLOC_SIZE);

		BINT_INC(bint, tcache_index_count, 1);
		index_write_csum(bint, index, 1);
		retval = tcache_add_index(tcache, subgroup, index, QS_IO_WRITE);

		mtx_lock(subgroup->free_list_lock);
		if (index->free_blocks >= FREE_BLOCKS_MIN) {
			__subgroup_add_to_free_list(subgroup, index);
		}
		mtx_unlock(subgroup->free_list_lock);

		if (unlikely(retval != 0)) {
			debug_warn("Cannot add index to tcache\n");
			return -1;
		}

		need_sync++;
		if (need_sync == TCACHE_ALLOC_SIZE) {
			BINT_INC(subgroup->group->bint, tcache_bio_count, atomic_read(&tcache->bio_remain));
			tcache_entry_rw(tcache, QS_IO_WRITE);
			SLIST_INSERT_HEAD(tcache_list, tcache, t_list);
			tcache = NULL;
			need_sync = 0;
		}
	}

	if (need_sync) {
		tcache_entry_rw(tcache, QS_IO_WRITE);
		SLIST_INSERT_HEAD(tcache_list, tcache, t_list);
	}

	*(index_count) += i;
	return 0;
}

static inline int
subgroup_compare(struct index_subgroup *subgroup1, struct index_subgroup *subgroup2)
{
	if (subgroup1->group->group_id < subgroup2->group->group_id)
		return -1;
	if (subgroup1->group->group_id > subgroup2->group->group_id)
		return 1;
	if (subgroup1->subgroup_id < subgroup2->subgroup_id)
		return -1;
	if (subgroup1->subgroup_id > subgroup2->subgroup_id)
		return 1;
	debug_check(1);
	return 0;
}

static inline void
index_subgroup_insert(struct index_group *group, struct index_subgroup *subgroup) 
{
	struct index_subgroup *iter, *prev = NULL;
	uint16_t subgroup_free_indexes, iter_free_indexes;

	subgroup_free_indexes = atomic16_read(&subgroup->free_indexes);
	SLIST_FOREACH(iter, &group->free_list, s_list) {
		iter_free_indexes = atomic16_read(&iter->free_indexes);
		if (subgroup_free_indexes > iter_free_indexes) {
			break;
		}
		else if ((subgroup_free_indexes == iter_free_indexes) && subgroup_compare(subgroup, iter) < 0) {
			break;
		}
		prev = iter;
	}

	if (prev)
		SLIST_INSERT_AFTER(prev, subgroup, s_list);
	else
		SLIST_INSERT_HEAD(&group->free_list, subgroup, s_list);
}
 
static inline struct index_group *
bint_get_free_group(struct bdevint *bint)
{
	struct index_group *group;

	bint_lock(bint);
	debug_check(!bint->free_group);
	group = bint->free_group;
	bint_unlock(bint);
	return group;
}

static int
bint_initialize_subgroups(struct index_group *group, int isnew, int load, uint32_t *reserved_blocks, uint32_t *index_count)
{
	int i;
	int retval;
	struct index_subgroup *subgroup;
	struct tcache_list tcache_list;
#ifdef ENABLE_STATS
	uint32_t start_ticks;
#endif

	SLIST_INIT(&tcache_list);
	for (i = 0; i < group->max_subgroups; i++) {
		subgroup = index_subgroup_alloc(group, i);
		if (unlikely(!subgroup))
			return -1;

		group->subgroups[i] = subgroup;
		if (isnew)
			retval = bint_subgroup_new(subgroup, reserved_blocks, index_count, &tcache_list);
		else if (load)
			retval = bint_subgroup_load_init(subgroup);
		else {
			retval = 0;
		}

		if (unlikely(retval != 0)) {
			tcache_list_wait(&tcache_list);
			debug_warn("Group %u subgroup %u create/load failed\n", group->group_id, i);
			return retval;
		}

		if (isnew || load)
			index_subgroup_insert(group, subgroup);
	}

	group->free_subgroup = SLIST_FIRST(&group->free_list);
	BINT_TSTART(start_ticks);
	retval = tcache_free_unused_write(&tcache_list);
	BINT_TEND(group->bint, wait_for_tcache_ticks, start_ticks);
	debug_check(!SLIST_EMPTY(&tcache_list));
	for (i = 0; i < group->max_subgroups; i++) {
		subgroup = group->subgroups[i];
		subgroup_free_unused(subgroup, index_count, 1);
	}

	return retval;
}

static inline void
index_group_insert(struct bdevint *bint, struct index_group *group)
{
	struct index_group *prev = NULL;
	struct index_group *iter;
	uint16_t group_free_indexes, iter_free_indexes;

	group_free_indexes = atomic16_read(&group->free_indexes);
	SLIST_FOREACH(iter, &bint->free_list, g_list) {
		iter_free_indexes = atomic16_read(&iter->free_indexes);
		if (group_free_indexes > 1024 && group->group_id < iter->group_id) {
			break;
		}

		if (group_free_indexes && !iter_free_indexes) {
			break;
		}

		if (group_free_indexes == iter_free_indexes && group->group_id < iter->group_id) {
			break;
		}
#if 0
		if (group_free_indexes > iter_free_indexes) {
			break;
		}
		if (group_free_indexes == iter_free_indexes && group->group_id < iter->group_id) {
			break;
		}
#endif
		prev = iter;
	}

	if (prev)
		SLIST_INSERT_AFTER(prev, group, g_list);
	else
		SLIST_INSERT_HEAD(&bint->free_list, group, g_list);
}
 
int
bint_initialize_groups(struct bdevint *bint, int isnew, int load)
{
	int i, retval;
	struct index_group *group;
	uint32_t reserved_blocks = 0;
	uint32_t index_count = 0;
	struct index_subgroup *subgroup;
	struct tcache *tcache;
	int meta_shift = bint_meta_shift(bint);

	bint->index_groups = zalloc((bint->max_index_groups * sizeof(struct index_group *)), M_INDEXGROUP, Q_NOWAIT);
	if (unlikely(!bint->index_groups)) {
		debug_warn("Memory allocation failure\n");
		return -1;
	}

	if (isnew) {
		uint64_t reserved;

		reserved = (bint_index_bstart(bint, bint->max_indexes) << bint->sector_shift);
		reserved_blocks = (reserved >> meta_shift);
	}

	for (i = 0; i < bint->max_index_groups; i++) {
		group = index_group_alloc(bint, i);
		bint->index_groups[i] = group;
		if (isnew)
			retval = bint_group_new(group);
		else if (load)
			retval = bint_group_load(group);
		else
			retval = 0;

		if (unlikely(retval != 0)) {
			debug_warn("Group %d create/load failed\n", i);
			return -1;
		}

		retval = bint_initialize_subgroups(group, isnew, load, &reserved_blocks, &index_count);
		if (unlikely(retval != 0)) {
			debug_warn("Failed to initialize subgroups for group %d\n", i);
			return -1;
		}

		if (isnew) {
			retval = index_lookup_io(group, QS_IO_WRITE);
			if (unlikely(retval != 0)) {
				return -1;
			}
		}

		if (isnew || load)
			index_group_insert(bint, group);

	}

	if (!load)
		return 0;

	bint->free_group = SLIST_FIRST(&bint->free_list);

	index_count = 0;
	group = bint_get_free_group(bint);
	if (group) {
		SLIST_FOREACH(subgroup, &group->free_list, s_list) {
			tcache = NULL;
			bint_subgroup_load(subgroup, 0, subgroup->max_indexes, &index_count, &tcache, 0);
			if (tcache)
				bint_subgroup_load_post(subgroup, tcache, 0);

			if (atomic_read(&bint->index_count) >= CACHED_INDEX_COUNT)
				break;
		}
	}

#if 0
	SLIST_FOREACH(group, &bint->free_list, g_list) {
		printf("group id %u free_indexes %u\n", group->group_id, atomic16_read(&group->free_indexes));
		SLIST_FOREACH(subgroup, &group->free_list, s_list) {
			printf("subgroup %u free indexes %u\n", subgroup->subgroup_id, atomic16_read(&subgroup->free_indexes));
		}
		printf("\n");
	}
#endif

	return 0;
}

static struct index_subgroup *
group_subgroup_next_rotate(struct index_group *group, struct index_subgroup *subgroup)
{
	struct index_subgroup *next;

	next = SLIST_NEXT(subgroup, s_list);
	if (!next)
		next = SLIST_FIRST(&group->free_list);
	return next;
}

static struct index_subgroup *
group_subgroup_next(struct index_subgroup *subgroup)
{
	struct index_subgroup *next;

	next = SLIST_NEXT(subgroup, s_list);
	if (next)
		next->slow_idx = 0;
	return next;
}

static inline void
group_tail_subgroup(struct index_group *group, struct index_subgroup *subgroup)
{
	struct index_subgroup *next;
	int need_wakeup = 0;

	sx_xlock(group->group_lock);
	if (group->free_subgroup == subgroup) {
		next = group_subgroup_next(subgroup);
		group->free_subgroup = next;
		need_wakeup = 1;
	}
	sx_xunlock(group->group_lock);

	if (need_wakeup && !atomic_test_bit(BINT_LOAD_START, &group->bint->flags)) {
		atomic_set_bit(BINT_LOAD_START, &group->bint->flags);
		chan_wakeup_one_nointr(group->bint->load_wait);
	}
}

static struct index_group *
bint_index_group_next_rotate(struct bdevint *bint, struct index_group *group)
{
	struct index_group *next;

	next = SLIST_NEXT(group, g_list);
	if (!next)
		next = SLIST_FIRST(&bint->free_list);
	return next;
}

static inline void
bint_tail_group(struct bdevint *bint, struct index_group *group)
{
	struct index_group *next;
	int need_wakeup = 0;

	bint_lock(bint);
	if (bint->free_group == group) {
		next = bint_index_group_next_rotate(bint, group);
		bint->free_group = next;
		need_wakeup = 1;
		if (!next->free_subgroup) {
			next->free_subgroup = SLIST_FIRST(&next->free_list);
		}
	}
	bint_unlock(bint);

	if (need_wakeup && !atomic_test_bit(BINT_LOAD_START, &bint->flags)) {
		atomic_set_bit(BINT_LOAD_START, &bint->flags);
		chan_wakeup_one_nointr(bint->load_wait);
	}
}

static inline struct index_subgroup *
group_get_free_subgroup(struct index_group *group)
{
	struct index_subgroup *subgroup;

	sx_xlock(group->group_lock);
	subgroup = group->free_subgroup;
	sx_xunlock(group->group_lock);
	return subgroup;
}

#ifdef FREEBSD 
void bint_load_thread(void *data)
#else
int bint_load_thread(void *data)
#endif
{
	struct bdevint *bint = (struct bdevint *)(data);
	struct index_group *group, *start_group;
	struct index_subgroup *subgroup = NULL;
	uint32_t index_count = 0;
	int done;
	struct tcache *tcache;
#ifdef ENABLE_STATS
	int load;
	uint32_t start_ticks;
#endif

	__sched_prio(curthread, QS_PRIO_INOD);

	thread_start();

	for(;;)
	{
		wait_on_chan_interruptible(bint->load_wait, atomic_test_bit(BINT_LOAD_START, &bint->flags) || kernel_thread_check(&bint->flags, BINT_LOAD_EXIT));
		atomic_clear_bit(BINT_LOAD_START, &bint->flags);

		if (kernel_thread_check(&bint->flags, BINT_LOAD_EXIT))
			break;

		if (node_in_standby()) {
			atomic_clear_bit(BINT_IO_PENDING, &bint->flags);
			continue;
		}

		if (atomic_read(&bint->free_list_indexes) > FREE_LIST_INDEXES_CACHED) {
			if (atomic_test_bit(BINT_IN_SYNC_DATA, &bint->flags)) {
				atomic_clear_bit(BINT_IN_SYNC_DATA, &bint->flags);
				chan_wakeup_nointr(bint->load_wait);
			}
			continue;
		}

		start_group = group = bint_get_free_group(bint);
		debug_check(!group);
again:
		sx_xlock(group->group_lock);
		subgroup = group->free_subgroup;
		sx_xunlock(group->group_lock);
		while (subgroup) {
load_next:
			sx_xlock(group->group_lock);
			if (bint->max_index_groups == 1)
				subgroup = group_subgroup_next_rotate(group, subgroup);
			else
				subgroup = group_subgroup_next(subgroup);
			if (!subgroup || subgroup == group->free_subgroup) {
				subgroup = NULL;
				sx_xunlock(group->group_lock);
				break;
			}
			sx_xunlock(group->group_lock);

			subgroup_wait_for_io(subgroup);
			sx_xlock(subgroup->subgroup_lock);
			debug_info("subgroup %u free indexes %d done first load %d\n", subgroup->subgroup_id, atomic16_read(&subgroup->free_indexes), subgroup->donefirstload);
			if ((atomic16_read(&subgroup->free_indexes) || !subgroup->donefirstload) && TAILQ_EMPTY(&subgroup->free_list)) {
				sx_xunlock(subgroup->subgroup_lock);
				break;
			}
			sx_xunlock(subgroup->subgroup_lock);
		}

		if (!subgroup) {
			bint_lock(bint);
			group = bint_index_group_next_rotate(bint, group);
			bint_unlock(bint);
			if (group == start_group) {
				if (atomic_test_bit(BINT_IN_SYNC_DATA, &bint->flags)) {
					atomic_clear_bit(BINT_IN_SYNC_DATA, &bint->flags);
					chan_wakeup_nointr(bint->load_wait);
				}
				pause("psg", 2000);
				continue;
			}
			goto again;
		}

		done = 0;
#ifdef ENABLE_STATS
		load = 0;
#endif
		tcache = NULL;
		BINT_TSTART(start_ticks);
		sx_xlock(subgroup->subgroup_lock);
		if (atomic16_read(&subgroup->free_indexes) || !subgroup->donefirstload) {
			debug_info("group id %u subgroup id %u\n", subgroup->group->group_id, subgroup->subgroup_id);
			done = bint_subgroup_load(subgroup, 0, subgroup->max_indexes, &index_count, &tcache, 1);
#ifdef ENABLE_STATS
			load = 1;
#endif
		}
		sx_xunlock(subgroup->subgroup_lock);
		BINT_TEND(bint, bint_subgroup_load_async_ticks, start_ticks);
		if (tcache)
			bint_subgroup_load_post(subgroup, tcache, 1);

		if (done > 0) {
			BINT_INC(bint, async_load, done);
		}
		BINT_INC(bint, load_count, load);
		if (atomic_read(&bint->free_list_indexes) < FREE_LIST_INDEXES_CACHED)
			goto load_next;

		if (atomic_test_bit(BINT_IN_SYNC_DATA, &bint->flags)) {
			atomic_clear_bit(BINT_IN_SYNC_DATA, &bint->flags);
			chan_wakeup_nointr(bint->load_wait);
		}

	}
	thread_end();
#ifdef FREEBSD 
	kproc_exit(0);
#else
	return 0;
#endif
}

#ifdef FREEBSD 
void bint_sync_thread(void *data)
#else
int bint_sync_thread(void *data)
#endif
{
	struct bdevint *bint = (struct bdevint *)(data);

	thread_start();

	for(;;)
	{
#if 0
		wait_on_chan_interruptible(bint->sync_wait, atomic_test_bit(BINT_IO_PENDING, &bint->flags) || kernel_thread_check(&bint->flags, BINT_SYNC_EXIT));
#endif

		wait_on_chan_timeout(bint->sync_wait, kernel_thread_check(&bint->flags, BINT_SYNC_EXIT), 10000);

		if (node_in_standby()) {
			if (kernel_thread_check(&bint->flags, BINT_SYNC_EXIT))
				break;
			atomic_clear_bit(BINT_IO_PENDING, &bint->flags);
			continue;
		}

		bint_sync(bint);
		bint_group_sync(bint);
		if (kernel_thread_check(&bint->flags, BINT_SYNC_EXIT))
			break;
	}

	thread_end();
#ifdef FREEBSD 
	kproc_exit(0);
#else
	return 0;
#endif
}

void
bdev_alloc_list_insert(struct bdevint *bint)
{
	struct bdevint *iter, *prev = NULL;
	struct bdevgroup *group = bint->group;

	sx_xlock(group->alloc_lock);
	bint_lock(bint);
	if (atomic_test_bit(BINT_ALLOC_INSERTED, &bint->flags)) {
		bint_unlock(bint);
		sx_xunlock(group->alloc_lock);
		return;
	}

	if (bint->enable_comp)
		atomic_inc(&group->comp_bdevs);
	SLIST_FOREACH(iter, &group->alloc_list, a_list) {
		if (atomic64_read(&iter->free) < atomic64_read(&bint->free))
			break;
		prev = iter;
	}
	if (prev)
		SLIST_INSERT_AFTER(prev, bint, a_list);
	else
		SLIST_INSERT_HEAD(&group->alloc_list, bint, a_list);
	atomic_set_bit(BINT_ALLOC_INSERTED, &bint->flags);
	bint_unlock(bint);
	sx_xunlock(group->alloc_lock);
}

static void
bint_create_notify_mdaemon(void)
{
	struct usr_notify msg;

	bzero(&msg, sizeof(msg));
	node_usr_notify_msg(USR_NOTIFY_BINT_CREATE_DONE, 0, &msg);
}

uint32_t increate;
#ifdef FREEBSD 
static void bint_create_thread(void *data)
#else
static int bint_create_thread(void *data)
#endif
{
	struct bdevint *bint = (struct bdevint *)(data);
	struct bdevint *master_bint;
	struct bdevint *ha_bint;
	int retval;

	sx_xlock(gchain_lock);
	while (increate) {
		sx_xunlock(gchain_lock);
		pause("psg", 1000);
		sx_xlock(gchain_lock);
	}
	increate = 1;
	sx_xunlock(gchain_lock);

	retval = bint_initialize_groups(bint, 1, 1);
	if (unlikely(retval != 0)) {
		debug_warn("failed to initialize groups\n");
		bint->initialized = -1;
		goto exit;
	}

	if (bint->log_disk) {
		retval = bint_create_logs(bint, QS_IO_WRITE, MAX_LOG_PAGES, LOG_PAGES_OFFSET);
		if (unlikely(retval != 0)) {
			debug_warn("Failed to create/load log pages\n");
			bint->initialized = -1;
			goto exit;
		}
	}

	if (bint->ddmaster) {
		retval = ddtable_create(&bint->group->ddtable, bint);

		if (unlikely(retval != 0)) {
			debug_warn("failed to create or load ddtable\n");
			bint->initialized = -1;
			goto exit;
		}
	}

#if 0
	atomic_set_bit(BINT_IO_PENDING, &bint->flags);
	retval = bint_sync(bint);
	if (unlikely(retval != 0))
	{
		bint->initialized = -1;
		goto exit;
	}
#endif

	retval = kernel_thread_create(bint_sync_thread, bint, bint->sync_task, "synct%u", bint->bid);
	if (unlikely(retval != 0)) {
		bint->initialized = -1;
		goto exit;
	}

	retval = kernel_thread_create(bint_load_thread, bint, bint->load_task, "loadt%u", bint->bid);
	if (unlikely(retval != 0)) {
		bint->initialized = -1;
		goto exit;
	}

	retval = kernel_thread_create(bint_free_thread, bint, bint->free_task, "bintfreet%u", bint->bid);
	if (unlikely(retval != 0)) {
		bint->initialized = -1;
		goto exit;
	}

	if (bint->log_disk)
		bdev_log_add(bint);

	if (atomic_test_bit(GROUP_FLAGS_MASTER, &bint->group_flags)) {
		bint_set_group_master(bint);
	}

	if (atomic_test_bit(GROUP_FLAGS_HA_DISK, &bint->group_flags)) {
		ha_bint = bdev_group_get_ha_bint();
		if (!ha_bint) {
			bdev_group_set_ha_bint(bint);
			ha_init_config();
			node_controller_ha_init();
		}
		else {
			atomic_clear_bit(GROUP_FLAGS_HA_DISK, &bint->group_flags);
		}
	}

	atomic_set_bit(BINT_LOAD_START, &bint->flags);
	atomic_set_bit(BINT_IN_SYNC_DATA, &bint->flags);
	chan_wakeup_one_nointr(bint->load_wait);
	wait_on_chan(bint->load_wait, !atomic_test_bit(BINT_IN_SYNC_DATA, &bint->flags));

	master_bint = bint_get_group_master(bint);
	if (bint != master_bint)
		memcpy(bint->mrid, master_bint->mrid, TL_RID_MAX);
	else {
		if (bint->log_disk)
			master_bint->log_disks = 1;
	}

	bint->rid_set = 1;

	bint->initialized = 1;
	atomic_set_bit(BINT_IO_PENDING, &bint->flags);
	retval = bint_sync(bint);
	if (unlikely(retval != 0))
	{
		bint->initialized = -1;
		goto exit;
	}

	if (bint->log_disk && bint != master_bint) {
		bint_lock(master_bint);
		master_bint->log_disks++;
		atomic_set_bit(BINT_IO_PENDING, &master_bint->flags);
		bint_unlock(master_bint);
		retval = bint_sync(master_bint);
		if (unlikely(retval != 0))
		{
			bint_lock(master_bint);
			master_bint->log_disks--;
			bint_unlock(master_bint);
			bint->initialized = -1;
			goto exit;
		}
	}

	if (node_sync_enabled()) {
		retval = __node_bint_sync_send(bint);
		if (retval == 0) {
			atomic_set_bit(BINT_SYNC_ENABLED, &bint->flags);
			if (atomic_test_bit(GROUP_FLAGS_HA_DISK, &bint->group_flags))
				node_ha_enable();
		}
	}
	bdev_alloc_list_insert(bint);

exit:
	sx_xlock(gchain_lock);
	increate = 0;
	if (bint->initialized == -1) {
		if (bint->log_disk) {
			bdev_log_remove(bint, 1);
			bdev_log_list_remove(bint, 0);
		}
	}
	sx_xunlock(gchain_lock);
	bint->create_task = NULL;
	bint_create_notify_mdaemon();

#ifdef FREEBSD 
	kproc_exit(0);
#else
	return 0;
#endif
}

#define DDTABLE_MAX_BITS	23

int
calc_ddbits(void)
{
	uint64_t availmem = qs_availmem;
	int bits = 16;
	uint64_t used;

	used = (1ULL << 31);
	while (used < availmem) {
		bits++;
		used = (used << 1);
	}

	if (bits > DDTABLE_MAX_BITS)
		bits = DDTABLE_MAX_BITS;

	debug_info("bits %d\n", bits);
	return bits;
}

static int
bint_load_post(struct bdevint *bint)
{
	int retval;
	struct bdevint *master_bint;

	retval = bint_initialize_groups(bint, 0, 1);
	if (unlikely(retval != 0)) {
		debug_warn("failed to initialize groups\n");
		return -1;
	}

	master_bint = bint_get_group_master(bint);
	if (bint->log_disk && (!master_bint || !master_bint->log_write)) {
		retval = bint_create_logs(bint, QS_IO_READ, MAX_LOG_PAGES, LOG_PAGES_OFFSET);
		if (unlikely(retval != 0)) {
			debug_warn("Failed to create/load log pages\n");
			return -1;
		}
		bdev_log_list_insert(bint);
		atomic_inc(&ddtable_global.cur_log_disks);
	}
	else if (bint->log_disk) {
		debug_info("not loading due to log_disk %d master bint %p log write %d\n", bint->log_disk, master_bint, (master_bint ? master_bint->log_write : 0));
		bdev_log_list_insert(bint);
		atomic_inc(&ddtable_global.cur_log_disks);
	}

	if (bint->ddmaster) {
		retval = ddtable_load(&bint->group->ddtable, bint);

		if (unlikely(retval != 0)) {
			debug_warn("failed to create or load ddtable\n");
			return -1;
		}
	}

	retval = kernel_thread_create(bint_sync_thread, bint, bint->sync_task, "synct%u", bint->bid);
	if (unlikely(retval != 0)) {
		return -1;
	}

	retval = kernel_thread_create(bint_load_thread, bint, bint->load_task, "loadt%u", bint->bid);
	if (unlikely(retval != 0)) {
		return -1;
	}

	retval = kernel_thread_create(bint_free_thread, bint, bint->free_task, "bintfreet%u", bint->bid);
	if (unlikely(retval != 0)) {
		return -1;
	}

	atomic_set_bit(BINT_LOAD_START, &bint->flags);
	atomic_set_bit(BINT_LOAD_DONE, &bint->flags);
	chan_wakeup_one_nointr(bint->load_wait);
	bdev_alloc_list_insert(bint);
	bint->initialized = 1;
	return 0;
}

void
bdevs_load_ddtables_post(void)
{
#if 0
	struct bdevint *bint;
	int i;

	for (i = 0; i < TL_MAX_DISKS; i++) {
		bint = bint_list[i];
		if (!bint || bint->initialized != 1 || !bint->ddmaster)
			continue;

		ddtable_load_thr_start(&bint->group->ddtable);
	}
#endif
}

int
bdevs_load_post(void)
{
	struct bdevint *bint;
	int i, error = 0, retval;

	for (i = 0; i < TL_MAX_DISKS; i++) {
		bint = bint_list[i];
		if (!bint || bint->initialized != 1)
			continue;
		if (atomic_test_bit(BINT_LOAD_DONE, &bint->flags))
			continue;
		retval = bint_load_post(bint);
		if (unlikely(retval != 0))
			error = -1;
	}
	return error;
}

int
bint_fix_rid(struct bdevint *bint)
{
	int retval;
	struct bdevint *master_bint;

	if (bint->rid_set)
		return 0;

	master_bint = bint_get_group_master(bint);
	if (bint != master_bint)
		memcpy(bint->mrid, master_bint->mrid, TL_RID_MAX);
	atomic_set_bit(BINT_IO_PENDING, &bint->flags);
	bint->rid_set = 1;
	retval = bint_sync(bint);
	return retval;
}

int
bdevs_fix_rids(void)
{
	struct bdevint *bint;
	int i, error = 0, retval;

	retval = bdev_groups_fix_rids();
	if (retval != 0)
		return -1;

	for (i = 0; i < TL_MAX_DISKS; i++) {
		bint = bint_list[i];
		if (!bint || bint->initialized != 1)
			continue;

		if (bint_is_group_master(bint))
			continue;

		retval = bint_fix_rid(bint);
		if (unlikely(retval != 0))
			error = -1;
	}

	for (i = 0; i < TL_MAX_DISKS; i++) {
		bint = bint_list[i];
		if (!bint || bint->initialized != 1)
			continue;

		if (atomic_test_bit(BINT_IO_PENDING, &bint->flags))
			bint_sync(bint);
	}
	return error;
}

static int 
bint_gen_properties(struct bdevint *bint, struct bdev_info *binfo)
{
	struct bdevgroup *group = bint->group;
	struct bdevint *ha_bint;
	int ddmaster = 0;
	int log_disk = 0;
	int group_master = 0;
	int max_roots;

	if (atomic_read(&group->bdevs) && !binfo->log_disk) {
		return 0;
	}

	if (!group->dedupemeta || !group->logdata) {
		if (!group_none || !atomic_read(&group_none->bdevs)) {
			sprintf(binfo->errmsg, "Pool %s depends on Default pool for either dedupe or log, but Default pool has no disk configured\n", group->name);
			return -1;
		}

 		if (atomic_read(&group_none->log_error)) {
			sprintf(binfo->errmsg, "Pool %s depends on Default pool for either dedupe or log, but Default pool is in an error state\n", group->name);
			return -1;
		}

		if (!group_none->master_bint) {
			sprintf(binfo->errmsg, "Pool %s depends on Default pool for either dedupe or log, but Default pool has no master disk\n", group->name);
			return -1;
		}
	}

	if (group->dedupemeta && !atomic_read(&group->bdevs)) {
		if ((atomic_read(&ddtable_global.cur_ddtables) + 1) > ddtable_global.max_ddtables) {
			sprintf(binfo->errmsg, "Pool %s needs to maintain its own dedupe tables, but dedupe tables limit reached", group->name);
			return -1;
		}
		max_roots = (1U << calc_ddbits());

		if ((ddtable_global_ddlookup_count() + max_roots) > ddtable_global.max_ddlookup_count) {
			sprintf(binfo->errmsg, "Pool %s needs to maintain its own dedupe tables, but dedupe tables limit reached", group->name);
			return -1;
		}

		ddmaster = 1;
		atomic_inc(&ddtable_global.cur_ddtables);
	}

	if (group->logdata && (!atomic_read(&group->bdevs) || binfo->log_disk)) {
		if ((atomic_read(&ddtable_global.cur_log_disks) + 1) > ddtable_global.max_log_disks) {
			if (!atomic_read(&group->bdevs)) {
				if (ddmaster)
					atomic_dec(&ddtable_global.cur_ddtables);
				sprintf(binfo->errmsg, "Pool %s needs to maintain its own logs, but limit on log disks reached", group->name);
				return -1;
			}
			else {
				binfo->log_disk = 0;
			}
		}
		else {
			log_disk = 1;
			atomic_inc(&ddtable_global.cur_log_disks);
		}
	}

	if (!atomic_read(&group->bdevs)) {
		group_master = 1;
	}

	bint->ddmaster = ddmaster;
	bint->log_disk = log_disk;
	if (group_master) {
		atomic_set_bit(GROUP_FLAGS_MASTER, &bint->group_flags);
		if (group->dedupemeta)
			atomic_set_bit(GROUP_FLAGS_DEDUPEMETA, &bint->group_flags);
		if (group->logdata)
			atomic_set_bit(GROUP_FLAGS_LOGDATA, &bint->group_flags);
	}

	ha_bint = bdev_group_get_ha_bint();

	if ((!ha_bint && binfo->ha_disk) || (!ha_bint && !group->group_id))
		atomic_set_bit(GROUP_FLAGS_HA_DISK, &bint->group_flags);

	return 0;
}

static void
bint_error_free(struct bdevint *bint)
{
	wait_chan_free(bint->sync_wait);
	wait_chan_free(bint->load_wait);
	wait_chan_free(bint->free_wait);
	mtx_free(bint->bint_lock);
	mtx_free(bint->stats_lock);
	sx_free(bint->alloc_lock);
	free(bint, M_BINT);
}

int
bdev_add_new(struct bdev_info *binfo)
{
	struct bdevint *bint;
	int retval, unmap;

	if (!atomic_read(&kern_inited))
		return -1;

	bint = bdev_find(binfo->bid);
	if (bint)
	{
		return 0;
	}

	bint = zalloc(sizeof(struct bdevint), M_BINT, Q_NOWAIT);
	if (unlikely(!bint))
	{
		debug_warn("Cannot allocate for a new bint\n");
		return -1;
	}

	bint->bint_lock = mtx_alloc("bint lock");
	bint->stats_lock = mtx_alloc("bint stats lock");
	bint->alloc_lock = sx_alloc("bint alloc lock");
	SLIST_INIT(&bint->free_list);
	TAILQ_INIT(&bint->index_list);
	LIST_INIT(&bint->log_group_list);
	bint->sync_wait = wait_chan_alloc("bint sync wait");
	bint->load_wait = wait_chan_alloc("bint load wait");
	bint->free_wait = wait_chan_alloc("bint free wait");

	bint->bid = binfo->bid;
#if 0
	bint->ddmaster = binfo->ddmaster;
#endif
	memcpy(bint->vendor, binfo->vendor, sizeof(bint->vendor));
	memcpy(bint->product, binfo->product, sizeof(bint->product));
	memcpy(bint->serialnumber, binfo->serialnumber, sizeof(bint->serialnumber));
	bint->serial_len = binfo->serial_len;
	retval = bint_dev_open(bint, binfo);
	if (unlikely(retval != 0)) {
		bint_error_free(bint);
		return -1;
	}

	if (bint->usize < (1ULL << 32)) {
		debug_warn("Invalid bint size %llu, too less\n", (unsigned long long)bint->usize);
		goto err;
	}

	bint->b_start = BDEV_META_OFFSET >> bint->sector_shift;
	if (!binfo->isnew)
	{
		retval = bint_load(bint);
		if (unlikely(retval != 0 || bint->initialized != 1))
		{
			debug_warn("Failed to load bint at bid %u retval %d initialized %d\n", bint->bid, retval, bint->initialized);
			goto err;
		}
		binfo->ddmaster = bint->ddmaster;
		binfo->group_id = bint->group->group_id;
		if (!bint->rid_set && bint_is_group_master(bint))
			memcpy(bint->mrid, binfo->rid, TL_RID_MAX);

		if (bint_is_group_master(bint)) {
			bint_set_group_master(bint);
			if (!bint->log_write)
				bint->in_log_replay = 1;
		}

		if (bint_is_ha_disk(bint))
			bdev_group_set_ha_bint(bint);

		if (atomic_test_bit(GROUP_FLAGS_UNMAP_ENABLED, &bint->group_flags)) {
			unmap = bdev_unmap_support(bint->b_dev);
			if (unmap)
				atomic_set_bit(GROUP_FLAGS_UNMAP, &bint->group_flags);
		}
	}
	else {
		bint->group = bdev_group_locate(binfo->group_id, NULL);
		if (unlikely(!bint->group)) {
			debug_warn("Cannot locate pool at %u\n", binfo->group_id);
			goto err;
		}

		if (unlikely(atomic_read(&bint->group->log_error))) {
			goto err;
		}

		bint->usize -= BINT_TAIL_RESERVED;
		atomic_set_bit(GROUP_FLAGS_TAIL_META, &bint->group_flags);
		bint_clear(bint);
		bint->ddbits = calc_ddbits();
		dump_ddtable_global();
		retval = bint_gen_properties(bint, binfo);
		dump_ddtable_global();
		if (unlikely(retval != 0)) {
			goto err;
		}
		if (binfo->enable_comp) {
			if (bint->sector_shift != 9 && bint->sector_shift != 10)
				binfo->enable_comp = 0;
		}
		bint->enable_comp = binfo->enable_comp;
		bint->v2_disk = 1;
		bint->v2_log_format = BINT_V3_LOG_FORMAT;
		memcpy(bint->mrid, binfo->rid, TL_RID_MAX);
	}

	bint_initialize_blocks(bint, binfo->isnew);
	bdev_list_insert(bint);
	atomic_inc(&bint->group->bdevs);

	if (bint_is_group_master(bint))
		binfo->ismaster = 1;

	if (binfo->isnew) {
		retval = kernel_thread_create(bint_create_thread, bint, bint->create_task, "bintcr");
		if (unlikely(retval != 0)) {
			atomic_dec(&bint->group->bdevs);
			bdev_remove(binfo);
			if (bint->log_disk)
				atomic_dec(&ddtable_global.cur_log_disks);
			if (bint->ddmaster)
				atomic_dec(&ddtable_global.cur_ddtables);
			return -1;
		}
		return 0;
	}

	return 0;

err:
	bint_free(bint, 0);
	return -1;
}

static inline struct bintindex * 
subgroup_free_list_first(struct index_subgroup *subgroup)
{
	struct bintindex *index;

	mtx_lock(subgroup->free_list_lock);
	index = TAILQ_FIRST(&subgroup->free_list);
	if (index)
		index_get(index);
	mtx_unlock(subgroup->free_list_lock);
	return index;
}

static struct bintindex * 
subgroup_index_list_first(struct index_subgroup *subgroup, int start)
{
	struct bintindex *index;
	struct bdevint *bint = subgroup->group->bint;
	int meta_shift = bint_meta_shift(bint);
	int i;

	sx_xlock(subgroup->subgroup_lock);
	for (i = start; i < SUBGROUP_INDEX_LIST_BUCKETS; i++) {
		LIST_FOREACH(index, &subgroup->index_list[i], x_list) {
			wait_on_chan_check(index->index_wait, !atomic_test_bit(META_DATA_DIRTY, &index->flags));
			wait_on_chan_check(index->index_wait, !atomic_test_bit(META_DATA_READ_DIRTY, &index->flags));
			index_lock(index);
			index_check_load(index);
			if (!atomic_test_bit(META_DATA_ERROR, &index->flags) && index->free_blocks >= (LBA_SIZE >> meta_shift)) {
				index_get(index);
				index_unlock(index);
				subgroup->slow_idx = i;
				sx_xunlock(subgroup->subgroup_lock);
				return index;
			}
			index_unlock(index);
		}
	}
	sx_xunlock(subgroup->subgroup_lock);
	return NULL;
}

static struct bintindex * 
subgroup_index_list_next(struct index_subgroup *subgroup, struct bintindex *index)
{
	struct bintindex *next;
	struct bdevint *bint = subgroup->group->bint;
	int meta_shift = bint_meta_shift(bint);
	uint32_t idx;

	idx = (index->index_id & SUBGROUP_INDEX_LIST_MASK);
	sx_xlock(subgroup->subgroup_lock);
	next = LIST_NEXT(index, x_list);
	if (!next) {
		sx_xunlock(subgroup->subgroup_lock);
 		if (((idx +1) == SUBGROUP_INDEX_LIST_BUCKETS)) {
			return NULL;
		}
		return subgroup_index_list_first(subgroup, idx+1);
	}

	while (next) {
		wait_on_chan_check(next->index_wait, !atomic_test_bit(META_DATA_DIRTY, &next->flags));
		wait_on_chan_check(next->index_wait, !atomic_test_bit(META_DATA_READ_DIRTY, &next->flags));
		index_lock(next);
		index_check_load(next);
		if (!atomic_test_bit(META_DATA_ERROR, &next->flags) && next->free_blocks >= (LBA_SIZE >> meta_shift)) {
			index_get(next);
			index_unlock(next);
			sx_xunlock(subgroup->subgroup_lock);
			bint_tail_index(subgroup->group->bint, next);
			return next;
		}
		index_unlock(next);

		next = LIST_NEXT(next, x_list);
	}

	sx_xunlock(subgroup->subgroup_lock);
 	if (((idx +1) == SUBGROUP_INDEX_LIST_BUCKETS)) {
		return NULL;
	}
	return subgroup_index_list_first(subgroup, idx+1);
}

static uint64_t
__bint_subgroup_alloc_fast(struct bdevint *bint, struct index_subgroup *subgroup, uint32_t size, struct index_info *index_info, int type)
{
	struct bintindex *index;
	uint64_t ret;
	int mark_full;
#ifdef ENABLE_STATS
	uint32_t start_ticks;
#endif

	while ((index = subgroup_free_list_first(subgroup)) != NULL) {
		mark_full = 0;
		BINT_TSTART(start_ticks);
		index_lock(index);
		ret = bint_alloc_block(bint, index, size, index_info, &mark_full, type);
		if (mark_full)
			bint_mark_index_full(index);
		index_unlock(index);
		BINT_TEND(bint, alloc_block_ticks, start_ticks);


		if (!ret || mark_full) {
			atomic_clear_bit(META_LOAD_DONE, &index->flags);
			subgroup_remove_from_free_list(subgroup, index);
		}
		index_put(index);

		if (ret)
			return ret;
	}
	return 0ULL;
}

static uint64_t
__bint_alloc_fast(struct bdevint *bint, uint32_t size, struct index_info *index_info, int type)
{
	struct index_group *group, *start_group = NULL;
	struct index_subgroup *subgroup;
	uint64_t ret;
#ifdef ENABLE_STATS
	uint32_t start_ticks;
#endif

	while ((group = bint_get_free_group(bint)) != NULL) {
		struct index_subgroup *start_subgroup = NULL;

		if (start_group && group == start_group)
			break;

		if (!start_group)
			start_group = group;

		while ((subgroup = group_get_free_subgroup(group)) != NULL) {
			if (start_subgroup && subgroup == start_subgroup)
				break;

			if (!start_subgroup)
				start_subgroup = subgroup;

			BINT_TSTART(start_ticks);
			subgroup_wait_for_io(subgroup);
			BINT_TEND(bint, subgroup_wait_for_io_ticks, start_ticks);
			BINT_TSTART(start_ticks);
			ret = __bint_subgroup_alloc_fast(bint, subgroup, size, index_info, type);
			BINT_TEND(bint, bint_fast_alloc_ticks, start_ticks);
			if (ret) {
				BINT_INC(bint, fast_alloc_hits, 1);
				return ret;
			}
			else {
				BINT_INC(bint, fast_alloc_misses, 1);
			}
			group_tail_subgroup(group, subgroup);
		}
		bint_tail_group(bint, group);
	}
	return 0ULL;
}

static int 
__bint_alloc_for_pgdata(struct tdisk *tdisk, struct bdevint *bint, struct pgdata_wlist *alloc_list, struct index_info_list *index_info_list, uint32_t size, struct bdevint **ret_bint)
{
	struct index_group *group, *start_group = NULL;
	struct index_subgroup *subgroup;
	struct bintindex *index;
	int mark_full;
	int retval;
#ifdef ENABLE_STATS
	uint32_t start_ticks;
#endif

	BINT_INC(bint, pgrequest_size, size);
	while ((group = bint_get_free_group(bint)) != NULL) {
		struct index_subgroup *start_subgroup = NULL;

		if (start_group && group == start_group)
			break;

		if (!start_group)
			start_group = group;

		while ((subgroup = group_get_free_subgroup(group)) != NULL) {

			if (start_subgroup && subgroup == start_subgroup)
				break;

			if (!start_subgroup)
				start_subgroup = subgroup;

			BINT_TSTART(start_ticks);
			subgroup_wait_for_io(subgroup);
			BINT_TEND(bint, subgroup_wait_for_io_ticks, start_ticks);
			while ((index = subgroup_free_list_first(subgroup)) != NULL) {
				mark_full = 0;
 				BINT_TSTART(start_ticks);
				index_lock(index);
				retval = bint_alloc_for_pgdata(tdisk, bint, index, alloc_list, index_info_list, &mark_full, ret_bint);
				if (mark_full)
					bint_mark_index_full(index);
				index_unlock(index);
 				BINT_TEND(bint, bint_pgdata_alloc_ticks, start_ticks);

				if (unlikely(retval != 0)) {
					index_put(index);
					return -1;
				}

				if (STAILQ_EMPTY(alloc_list)) {
					index_put(index);
					return 0;
				}
				atomic_clear_bit(META_LOAD_DONE, &index->flags);
				subgroup_remove_from_free_list(subgroup, index);
				index_put(index);
			}
			group_tail_subgroup(group, subgroup);
		}
		bint_tail_group(bint, group);
	}
	return 0;
}

static struct bdevint *
bdev_alloc_list_next_rotate(struct bdevint *bint)
{
	struct bdevint *ret;
	struct bdevgroup *group = bint->group;

	ret = SLIST_NEXT(bint, a_list);
	if (!ret)
		ret = SLIST_FIRST(&group->alloc_list);
	return ret;
}

#define BINT_ALLOC_RESERVED		(1ULL << 26) /* 64 MB */

void
bdev_add_to_alloc_list(struct bdevint *bint)
{
	if (atomic_test_bit(BINT_ALLOC_INSERTED, &bint->flags) || (atomic64_read(&bint->free_block_counter) < BINT_ALLOC_RESERVED))
		return;

	bdev_alloc_list_insert(bint);
}

void
bdev_remove_from_alloc_list(struct bdevint *bint)
{
	struct bdevgroup *group = bint->group;

	bint_lock(bint);
	if (bint == group->eligible)
		group->eligible = NULL;

	if (!atomic_test_bit(BINT_ALLOC_INSERTED, &bint->flags)) {
		bint_unlock(bint);
		return;
	}
	SLIST_REMOVE(&group->alloc_list, bint, bdevint, a_list);
	atomic_clear_bit(BINT_ALLOC_INSERTED, &bint->flags);
	if (bint->enable_comp)
		atomic_dec(&group->comp_bdevs);
	atomic64_set(&bint->free_block_counter, 0);
	bint_unlock(bint);
}

static struct bdevint *
bint_get_eligible(struct bdevgroup *group, uint32_t size)
{
	struct bdevint *found = NULL, *next, *eligible;
	uint32_t max_size;

	sx_xlock(group->alloc_lock);
	eligible = group->eligible;
	if (!eligible) {
		eligible = SLIST_FIRST(&group->alloc_list);
	}

	max_size = max_t(int, size, BINT_ALLOC_RESERVED);
	while (eligible) {
		debug_info("eligible initialized %d ddmaster %d free %llu max_size %u ddtable_global.reserved_size %llu\n", eligible->initialized, eligible->ddmaster, (unsigned long long)eligible->free, max_size, (unsigned long long)ddtable_global.reserved_size);
		if (eligible->initialized == 1 && ((!eligible->ddmaster && (atomic64_read(&eligible->free) > max_size)) || (eligible->ddmaster && (atomic64_read(&eligible->free) > ddtable_global.reserved_size)))) {
			found = eligible;
			eligible = bdev_alloc_list_next_rotate(eligible);
			break;
		}
		next = bdev_alloc_list_next_rotate(eligible);
		bdev_remove_from_alloc_list(eligible);
		if (next == eligible) {
			eligible = NULL;
			break;
		}
		eligible = next;
	}
	group->eligible = eligible;
	sx_xunlock(group->alloc_lock);
	return found;
}

extern uint32_t bint_eligible_ticks;
int
bdev_alloc_for_pgdata(struct tdisk *tdisk, struct pgdata_wlist *alloc_list, struct index_info_list *index_info_list, uint32_t size, struct bdevint **ret_bint)
{
	struct bdevint *bint;
	int retval;
#ifdef ENABLE_STATS
	uint32_t start_ticks;
#endif

	GLOB_TSTART(start_ticks);
	bint = bint_get_eligible(tdisk->group, size);
	GLOB_TEND(bint_eligible_ticks, start_ticks);
	if (!bint)
		return 0;

	BINT_INC(bint, pgalloc_lookups, 1);
	BINT_TSTART(start_ticks);
	sx_xlock(bint->alloc_lock);
	retval = __bint_alloc_for_pgdata(tdisk, bint, alloc_list, index_info_list, size, ret_bint);
	sx_xunlock(bint->alloc_lock);
	BINT_TEND(bint,pgdata_alloc_ticks,start_ticks);
	return retval;
}

static uint64_t
__bint_alloc_slow(struct bdevint *bint, uint32_t size, struct index_info *index_info, int type)
{
	struct index_group *group, *start_group = NULL;
	struct index_subgroup *subgroup;
	struct bintindex *index, *next;
	uint64_t ret;
	int mark_full;
	uint32_t index_count = 0;
	struct tcache *tcache;
#ifdef ENABLE_STATS
	uint32_t start_ticks;
#endif

	/* When no indexes are tentatively available */
	debug_check(SLIST_EMPTY(&bint->free_list));

	while ((group = bint_get_free_group(bint)) != NULL) {
		struct index_subgroup *start_subgroup = NULL;

		if (start_group && group == start_group)
			break;
		if (!start_group)
			start_group = group;

		while ((subgroup = group_get_free_subgroup(group)) != NULL) {

			if (start_subgroup && subgroup == start_subgroup)
				break;

			if (!start_subgroup)
				start_subgroup = subgroup;

			if (!atomic16_read(&subgroup->free_indexes)) {
				group_tail_subgroup(group, subgroup);
				continue;
			}

			tcache = NULL;
			sx_xlock(subgroup->subgroup_lock);
			if (TAILQ_EMPTY(&subgroup->free_list))
				bint_subgroup_load(subgroup, 0, subgroup->max_indexes, &index_count, &tcache, 0);
			sx_xunlock(subgroup->subgroup_lock);
			if (tcache)
				bint_subgroup_load_post(subgroup, tcache, 0);

			BINT_TSTART(start_ticks);
			subgroup_wait_for_io(subgroup);
			BINT_TEND(bint, subgroup_wait_for_io_ticks, start_ticks);

			index = subgroup_index_list_first(subgroup, subgroup->slow_idx);
			while (index) {
				mark_full = 0;
				index_lock(index);
				ret = bint_alloc_block(bint, index, size, index_info, &mark_full, type);
				if (mark_full)
					bint_mark_index_full(index);
				index_unlock(index);


				if (ret) {
					index_put(index);
					return ret;
				}

				atomic_clear_bit(META_DATA_ASYNC, &index->flags);
				next = subgroup_index_list_next(subgroup, index);
				index_put(index);
				index = next;
			}
			group_tail_subgroup(group, subgroup);
		}
		bint_tail_group(bint, group);
	}
	return 0ULL;
}

uint64_t
__bdev_alloc_block(struct bdevint *bint, uint32_t size, struct index_info *index_info, int type)
{
	uint64_t ret;
#ifdef ENABLE_STATS
	uint32_t start_ticks;
#endif

	BINT_TSTART(start_ticks);
	ret = __bint_alloc_fast(bint, size, index_info, type);
	BINT_TEND(bint,fast_alloc_ticks,start_ticks);
	if (ret) {
		BINT_INC(bint, fast_lookups, 1);
		BINT_INC(bint, fast_size, size);
		return ret;
	}

#if 0
	if (size > LBA_SIZE) {
		BINT_INC(bint, fast_lookups_failed, 1);
		return 0ULL;
	}
#endif

	ret = __bint_alloc_slow(bint, size, index_info, type);
	BINT_INC(bint, slow_lookups, 1);
	BINT_INC(bint, slow_size, size);
	return ret;
}

uint64_t
bdev_alloc_block(struct bdevgroup *group, uint32_t size, struct bdevint **ret_bint, struct index_info *index_info, int type)
{
	struct bdevint *bint, *start_bint = NULL;
#ifdef ENABLE_STATS
	uint32_t start_ticks;
#endif
	uint64_t ret;

	GLOB_TSTART(start_ticks);
	bint = bint_get_eligible(group, size);
	GLOB_TEND(bint_eligible_ticks, start_ticks);
	while (bint) {
		if (!start_bint)
			start_bint = bint;
		else if (start_bint == bint)
			break;
		ret = __bint_alloc_fast(bint, size, index_info, type);
		if (ret) {
			BINT_INC(bint, fast_lookups, 1);
			BINT_INC(bint, fast_size, size);
			*ret_bint = bint;
			return ret;
		}

		GLOB_TSTART(start_ticks);
		bint = bint_get_eligible(group, size);
		GLOB_TEND(bint_eligible_ticks, start_ticks);
	}

	GLOB_TSTART(start_ticks);
	bint = bint_get_eligible(group, size);
	GLOB_TEND(bint_eligible_ticks, start_ticks);
	while (bint) {
		ret = __bint_alloc_slow(bint, size, index_info, type);
		if (ret) {
			BINT_INC(bint, slow_lookups, 1);
			BINT_INC(bint, slow_size, size);
			*ret_bint = bint;
			return ret;
		}

		sx_xlock(bint->group->alloc_lock);
		bdev_remove_from_alloc_list(bint);
		sx_xunlock(bint->group->alloc_lock);

		GLOB_TSTART(start_ticks);
		bint = bint_get_eligible(group, size);
		GLOB_TEND(bint_eligible_ticks, start_ticks);
	}

	return 0ULL;
}

uint64_t
bdev_get_disk_index_block(struct bdevint *bint, uint32_t target_id)
{
	uint64_t span = (TDISK_RESERVED_OFFSET + (target_id * BINT_INDEX_META_SIZE));
	return (span >> bint->sector_shift);
}

void
index_info_list_free_error(struct index_info_list *index_info_list, int free)
{
	struct index_info *index_info, *next;

	TAILQ_FOREACH_SAFE(index_info, index_info_list, i_list, next) {
		index_lock(index_info->index);
		if (iowaiter_done_io(&index_info->iowaiter)) {
			index_unlock(index_info->index);
			iowaiter_end_wait(&index_info->iowaiter);
		}
		else {
			SLIST_REMOVE(&index_info->index->io_waiters, &index_info->iowaiter, iowaiter, w_list);
			index_unlock(index_info->index);
		}
		if (!free)
			continue;

		TAILQ_REMOVE(index_info_list, index_info, i_list);
		index_put(index_info->index);
		index_info_free(index_info);
	} 
}

void
index_info_list_free_unmap(struct index_info_list *index_info_list)
{
	struct index_info *index_info;
	struct bintindex *index;

	while ((index_info = TAILQ_FIRST(index_info_list)) != NULL) {
		TAILQ_REMOVE(index_info_list, index_info, i_list);
		index = index_info->index;
		if (atomic_test_bit(META_DATA_UNMAP, &index->flags))
			bint_unmap_blocks(index);

		index_put(index);
		index_info_free(index_info);
	} 
}

void
index_info_list_free(struct index_info_list *index_info_list)
{
	struct index_info *index_info;

	while ((index_info = TAILQ_FIRST(index_info_list)) != NULL) {
		TAILQ_REMOVE(index_info_list, index_info, i_list);
		index_put(index_info->index);
		index_info_free(index_info);
	} 
}

int
__index_info_wait(struct index_info_list *index_info_list)
{
	int error = 0;
	struct index_info *index_info;
	struct bintindex *index;

	TAILQ_FOREACH_REVERSE(index_info, index_info_list, index_info_list, i_list) {
		index = index_info->index;
		if (index_info->iowaiter.chan)
			index_end_wait(index, &index_info->iowaiter);

		if (atomic_test_bit(META_DATA_ERROR, &index->flags)) {
			debug_warn("Meta data error for index at %u:%llu\n", index->subgroup->group->bint->bid, (unsigned long long)bint_index_bstart(index->subgroup->group->bint, index->index_id));
			error = -1;
		}
	}
	return error;
}

int
index_info_wait(struct index_info_list *index_info_list)
{
	int error = 0;
	struct index_info *index_info, *prev;
	struct bintindex *index;

	TAILQ_FOREACH_REVERSE_SAFE(index_info, index_info_list, index_info_list, i_list, prev) {
		index = index_info->index;
		index_end_wait(index, &index_info->iowaiter);

		if (atomic_test_bit(META_DATA_ERROR, &index->flags)) {
			debug_warn("Meta data error for index at %u:%llu\n", index->subgroup->group->bint->bid, (unsigned long long)bint_index_bstart(index->subgroup->group->bint, index->index_id));
			error = -1;
		}

		TAILQ_REMOVE(index_info_list, index_info, i_list);
		if (atomic_test_bit(META_DATA_UNMAP, &index->flags))
			bint_unmap_blocks(index);
		index_put(index);
		index_info_free(index_info);
	}
	return error;
}

void
index_sync_free(struct index_sync_list *index_sync_list)
{
	struct index_sync *index_sync;
	struct bintindex *index;

	while ((index_sync = SLIST_FIRST(index_sync_list)) != NULL) {
		SLIST_REMOVE_HEAD(index_sync_list, s_list);
		index = index_sync->index;
		index_put(index);
		free_iowaiter(&index_sync->iowaiter);
		uma_zfree(index_sync_cache, index_sync);
	}
}

int
index_sync_wait(struct index_sync_list *index_sync_list)
{
	int error = 0;
	struct index_sync *index_sync;
	struct bintindex *index;

	while ((index_sync = SLIST_FIRST(index_sync_list)) != NULL) {
		SLIST_REMOVE_HEAD(index_sync_list, s_list);
		index = index_sync->index;
		index_end_wait(index, &index_sync->iowaiter);
		if (atomic_test_bit(META_DATA_ERROR, &index->flags)) {
			debug_warn("Meta data error for index at %u:%llu\n", index->subgroup->group->bint->bid, (unsigned long long)bint_index_bstart(index->subgroup->group->bint, index->index_id));
			error = -1;
		}
		index_put(index);
		free_iowaiter(&index_sync->iowaiter);
		uma_zfree(index_sync_cache, index_sync);
	}
	return error;
}

int
index_sync_start_io(struct index_sync_list *index_sync_list, int incr)
{
	struct index_sync *index_sync;
	struct bintindex *index;

	SLIST_FOREACH(index_sync, index_sync_list, s_list) {
		index = index_sync->index;
		index_end_writes(index, incr);
	}
	return 0;

}

void
index_sync_insert(struct index_sync_list *sync_list, struct bintindex *index)
{
	struct index_sync *index_sync;

	SLIST_FOREACH(index_sync, sync_list, s_list) {
		if (index == index_sync->index)
			return;
	}

	index_sync = __uma_zalloc(index_sync_cache, Q_WAITOK | Q_ZERO, sizeof(*index_sync));
	index_get(index);
	index_sync->index = index;
	index_start_writes(index, &index_sync->iowaiter);
	SLIST_INSERT_HEAD(sync_list, index_sync, s_list);

}

void
index_info_insert(struct index_sync_list *sync_list, struct index_info *index_info)
{
	struct index_sync *index_sync;
	struct bintindex *index;
	struct iowaiter *iowaiter;

	iowaiter = &index_info->iowaiter;
	if (iowaiter_done_io(iowaiter))
		return;

	index = index_info->index;

	SLIST_FOREACH(index_sync, sync_list, s_list) {
		if (index == index_sync->index)
			return;
	}

	index_sync = __uma_zalloc(index_sync_cache, Q_WAITOK | Q_ZERO, sizeof(*index_sync));
	index_get(index);
	index_sync->index = index;
	index_start_writes(index, &index_sync->iowaiter);
	SLIST_INSERT_HEAD(sync_list, index_sync, s_list);
}

void
index_list_insert(struct index_sync_list *sync_list, struct index_info_list *index_info_list)
{
	struct index_info *index_info;

	TAILQ_FOREACH(index_info, index_info_list, i_list) {
		index_info_insert(sync_list, index_info);
	}
}

static int
bint_subgroup_sync_pending(struct index_subgroup *subgroup, struct tcache_list *tcache_list)
{
	struct bintindex *index, *prev = NULL;
	struct tcache *tcache = NULL;
	int i, retval;

	debug_check(!SLIST_EMPTY(&subgroup->write_list));
	for (i = 0; i < SUBGROUP_INDEX_LIST_BUCKETS; i++) {
		LIST_FOREACH(index, &subgroup->index_list[i], x_list) {
			if (!atomic_test_bit(META_IO_PENDING, &index->flags))
				continue;

			if (prev)
				SLIST_INSERT_AFTER(prev, index, t_list);
			else
				SLIST_INSERT_HEAD(&subgroup->write_list, index, t_list);
			prev = index;
		}
	}

	if (SLIST_EMPTY(&subgroup->write_list))
		return 0;

	retval = subgroup_write_io(subgroup, &tcache, 1);
	if (unlikely(retval != 0))
		return -1;

	if (tcache)
		SLIST_INSERT_HEAD(tcache_list, tcache, t_list);
	return 0;
}

static int 
bint_group_sync_pending(struct index_group *group)
{
	struct index_subgroup *subgroup;
	int i, retval, error = 0;
	struct tcache_list tcache_list;

	SLIST_INIT(&tcache_list);
	for (i = 0; i < group->max_subgroups; i++) {
		subgroup = group->subgroups[i];
		atomic16_set(&subgroup->free_indexes, 0);
		retval = bint_subgroup_sync_pending(subgroup, &tcache_list);
		if (unlikely(retval != 0))
			error = -1;
		bint_subgroup_load_init(subgroup);
		index_subgroup_insert(group, subgroup);
	}
	retval = tcache_list_wait(&tcache_list);
	if (unlikely(retval != 0))
		error = -1;
	return error;
}

#if 0
static inline void
bint_subgroup_free_list_clear(struct index_group *group)
{
	struct index_subgroup *subgroup;

	while ((subgroup = SLIST_FIRST(&group->free_list)) != NULL) {
		SLIST_REMOVE_HEAD(&group->free_list, s_list);
	}
}

static inline void
bint_group_free_list_clear(struct bdevint *bint)
{
	struct index_group *group;

	while ((group = SLIST_FIRST(&bint->free_list)) != NULL) {
		SLIST_REMOVE_HEAD(&bint->free_list, g_list);
	}
}
#endif

int
bint_ha_takeover_post(struct bdevint *bint)
{
	atomic_set_bit(BINT_IN_SYNC_DATA, &bint->flags);
	atomic_set_bit(BINT_LOAD_START, &bint->flags);
	chan_wakeup_one_nointr(bint->load_wait);
	bdev_alloc_list_insert(bint);
	return 0;
}

int
bint_ha_takeover_post_load(struct bdevint *bint)
{
	chan_wakeup_one_nointr(bint->load_wait);
	wait_on_chan(bint->load_wait, !atomic_test_bit(BINT_IN_SYNC_DATA, &bint->flags));
	return 0;
}

int
bint_ha_takeover(struct bdevint *bint)
{
	struct index_group *group;
	int i, retval, error = 0;

	SLIST_INIT(&bint->free_list);
	debug_info("start max index groups %u\n", bint->max_index_groups);
	for (i = 0; i < bint->max_index_groups; i++) {
		group = bint->index_groups[i];
		debug_check(!group);
		atomic16_set(&group->free_indexes, 0);
		SLIST_INIT(&group->free_list);
		debug_info("sync pending for group at %u\n", i);
		retval = bint_group_sync_pending(group);
		if (unlikely(retval != 0))
			error = -1;
	}

	for (i = 0; i < bint->max_index_groups; i++) {
		group = bint->index_groups[i];
		group->free_subgroup = SLIST_FIRST(&group->free_list);
		debug_info("group insert for group at %u\n", i);
		index_group_insert(bint, group);
	}

	bint->free_group = SLIST_FIRST(&bint->free_list);
	debug_info("end\n");
	return error;
}

