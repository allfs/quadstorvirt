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

#include "bdevmgr.h"
#include "amap.h"
#include "ddtable.h"
#include "ddthread.h"
#include "tdisk.h"
#include "rcache.h"
#include "log_group.h"
#include "cluster.h"
#include "node_sync.h"
#include "node_ha.h"
#include "bdevgroup.h"

static SLIST_HEAD(, ddthread) ddthread_list = SLIST_HEAD_INITIALIZER(ddthread_list);
struct ddwork_list work_list = STAILQ_HEAD_INITIALIZER(work_list);
unsigned long ddthread_flags;
wait_chan_t *ddthread_wait;
static atomic_t ddthread_pending;

static inline struct ddwork *
ddthread_list_first(void)
{
	struct ddwork *ddwork;

	chan_lock(ddthread_wait);
	ddwork = STAILQ_FIRST(&work_list);
	if (ddwork) {
		atomic_inc(&ddthread_pending);
		STAILQ_REMOVE_HEAD(&work_list, w_list);
	}
	chan_unlock(ddthread_wait);
	return ddwork;
}

static void
process_delete_block_pre(uint64_t block, struct index_info_list *index_info_list)
{
	struct bdevint *bint;
	uint64_t index_id;
	uint32_t entry;
	struct index_info *index_info;
	struct bintindex *index;

	if (!block)
		return;

	bint = bdev_find(BLOCK_BID(block));
	if (unlikely(!bint))
		return;

	index_id = index_id_from_block(bint, BLOCK_BLOCKNR(block), &entry);
	if (!TAILQ_EMPTY(index_info_list)) {
		index_info = TAILQ_LAST(index_info_list, index_info_list);
		index = index_info->index;
		if (index->index_id == index_id && index->subgroup->group->bint == bint) {
			return;
		}
	}

	index = bint_get_index(bint, index_id);
	if (unlikely(!index)) {
		return;
	}

	index_info = index_info_alloc();
	if (unlikely(!index_info)) {
		index_put(index);
		return;
	}
	index_info->index = index;
	TAILQ_INSERT_TAIL(index_info_list, index_info, i_list);
}

extern uint32_t delete_index_wait_ticks;

static struct bintindex *
bint_index_search(struct bdevint *bint, uint32_t index_id, struct index_info_list *index_info_list)
{
	struct index_info *index_info;
	struct bintindex *index;

	TAILQ_FOREACH(index_info, index_info_list, i_list) {
		index = index_info->index;
		if (index->index_id == index_id && index->subgroup->group->bint == bint) {
			index_get(index);
			return index;
		}
	}
	debug_check(1);
	return NULL;
}
 
void
process_delete_block(struct ddtable *ddtable, uint64_t old_block, struct index_info_list *index_info_list, struct index_sync_list *index_sync_list, struct index_info_list *search_index_info_list, int type)
{
	struct bdevint *bint;
	struct bintindex *index;
	uint64_t node_block;
	uint32_t index_entry_id, refs;
	int retval;
	struct index_info *index_info = NULL;
	struct ddtable_ddlookup_node *ddlookup = NULL;
	int freed;
	uint64_t index_id;
#ifdef ENABLE_STATS
	uint32_t start_ticks, tmp_ticks;
#endif

	if (!old_block)
		return;

	DD_TSTART(start_ticks);

	bint = bdev_find(BLOCK_BID(old_block));
	if (unlikely(!bint)) {
		debug_warn("Failed to locate bint at bid %u\n", BLOCK_BID(old_block));
		return;
	}

	index_id = index_id_from_block(bint, BLOCK_BLOCKNR(old_block), &index_entry_id);
	if (search_index_info_list)
		index = bint_index_search(bint, index_id, search_index_info_list); 
	else
		index = bint_locate_index(bint, index_id, index_info_list);
	if (unlikely(!index)) {
		debug_warn("Cannot get a index at index_id %llu\n", (unsigned long long)index_id);
		return;
	}

	GLOB_TSTART(tmp_ticks);
	wait_on_chan_check(index->index_wait, !atomic_test_bit(META_DATA_READ_DIRTY, &index->flags));
	GLOB_TEND(delete_index_wait_ticks, tmp_ticks);

	if (!index_sync_list) {
		index_info = index_info_alloc();
		if (unlikely(!index_info)) {
			debug_warn("Failed to alloc for index_info\n");
			index_put(index);
			return;
		}
		index_info->index = index;
		index_info->b_start = BLOCK_BLOCKNR(old_block);
	}

	index_lock(index);
	index_check_load(index);
	if (atomic_test_bit(META_DATA_ERROR, &index->flags)) {
		index_unlock(index);
		index_put(index);
		if (index_info)
			index_info_free(index_info);
		return;
	}
	DD_TSTART(tmp_ticks);
	retval = bdev_get_node_block(index, &refs, &node_block, index_entry_id);
	DD_TEND(get_node_block_ticks, tmp_ticks);
	if (unlikely(retval != 0)) {
		index_unlock(index);
		index_put(index);
		if (index_info)
			index_info_free(index_info);
		debug_warn("Failed to locate node block from disk, Cannot free block at %u:%llu\n", BLOCK_BID(old_block), (unsigned long long)BLOCK_BLOCKNR(old_block));
		return;
	}

	if (refs > 1 || !node_block) {
		/* When refs are yet more than one */
		index_write_barrier(bint, index);
		freed = 0;
		DD_TSTART(tmp_ticks);
		bint_free_block(bint, index, index_entry_id, lba_block_size(old_block), &freed, type, 0);
		DD_TEND(free_block_ticks, tmp_ticks);
		if (freed) {
			if (index->free_blocks == BMAP_ENTRIES_UNCOMP && bint_unmap_supported(bint))
				atomic_set_bit(META_DATA_UNMAP, &index->flags);
			rcache_remove(old_block);
		}
		index_unlock(index);

		if (freed)
			bdev_add_to_alloc_list(bint);
		if (index_sync_list) {
			index_sync_insert(index_sync_list, index);
			index_put(index);
		}
		else
			TAILQ_INSERT_TAIL(index_info_list, index_info, i_list);
		DD_TEND(process_delete_block_ticks, start_ticks);
		return;
	}

	index_unlock(index);

	rcache_remove(old_block);

	debug_info("Got node block %llu refs %d\n", (unsigned long long)(node_block), refs);
	if (node_block) {
		DD_TSTART(tmp_ticks);
		ddlookup = ddtable_ddlookup_find_node(ddtable, node_block);
		DD_TEND(ddlookup_find_node_ticks, tmp_ticks);
	}

	if (index_sync_list)
		index_sync_insert(index_sync_list, index);

	debug_info("index entry id %d\n", index_entry_id);
	index_lock(index);
	index_write_barrier(bint, index);
	debug_info("free block %u %llu\n", BLOCK_BID(old_block), (unsigned long long)BLOCK_BLOCKNR(old_block));
	debug_info("free block %llu\n", (unsigned long long)old_block);
	freed = 0;
	DD_TSTART(tmp_ticks);
	bint_free_block(bint, index, index_entry_id, lba_block_size(old_block), &freed, type, 0);
	DD_TEND(free_block_ticks, tmp_ticks);

	if (freed) {
		DD_TSTART(tmp_ticks);
		if (ddlookup)
			ddtable_hash_remove_block(ddtable, ddlookup, old_block);
		DD_TEND(hash_remove_block_ticks, tmp_ticks);
		if (index->free_blocks == BMAP_ENTRIES_UNCOMP && bint_unmap_supported(bint))
			atomic_set_bit(META_DATA_UNMAP, &index->flags);
	}
	index_unlock(index);

	if (ddlookup) {
		node_ddlookup_unlock(ddlookup);
		ddtable_ddlookup_node_put(ddlookup);
	}

	if (freed)
		bdev_add_to_alloc_list(bint);

	if (index_info)
		TAILQ_INSERT_TAIL(index_info_list, index_info, i_list);
	else
		index_put(index);
	DD_TEND(process_delete_free_block_ticks, start_ticks);
	return;
}

static inline void
__pglist_free(struct pgdata **pglist, int pglist_cnt)
{
	int i;

	for (i = 0; i < pglist_cnt; i++) {
		struct pgdata *pgtmp = pglist[i];

		pgdata_cleanup(pgtmp);
		wait_completion_free(pgtmp->completion);
		uma_zfree(pgdata_cache, pgtmp);
	}
	free(pglist, M_PGLIST);
}

int
handle_amap_sync_wait(struct amap_sync_list *amap_sync_list)
{
	struct amap_sync *amap_sync;
	struct amap *amap;
	int error = 0;

	while ((amap_sync = SLIST_FIRST(amap_sync_list)) != NULL) {
		SLIST_REMOVE_HEAD(amap_sync_list, s_list);
		amap = amap_sync->amap;
		amap_end_wait(amap, &amap_sync->iowaiter);
		if (atomic_test_bit_short(AMAP_META_DATA_ERROR, &amap->flags))
			error = -1;
		amap_put(amap);
		free_iowaiter(&amap_sync->iowaiter);
		uma_zfree(amap_sync_cache, amap_sync);
	}
	return error;
}

int
handle_amap_sync(struct amap_sync_list *amap_sync_list)
{
	struct amap_sync *amap_sync;
	struct amap *amap;

	SLIST_FOREACH(amap_sync, amap_sync_list, s_list) {
		amap = amap_sync->amap;
		amap_end_writes(amap, amap_sync->write_id);
	}

	return 0;
}

void
amap_check_sync_list(struct amap *amap, struct amap_sync_list *amap_sync_list, struct pgdata *pgdata, uint64_t write_id)
{
	struct amap_sync *amap_sync, *prev = NULL;

	SLIST_FOREACH(amap_sync, amap_sync_list, s_list) {
		if (amap_sync->amap->amap_id >= amap->amap_id) {
			if (amap_sync->amap == amap) {
				if (pgdata) {
					STAILQ_INSERT_TAIL(&amap_sync->pgdata_list, pgdata, a_list);
				}
				return;
			}
			break;
		}
		prev = amap_sync;
	}

	/* amap is locked here */
	amap_sync = amap_sync_alloc(amap, write_id);
	debug_check(!amap_sync);
	if (pgdata)
		amap_lock(amap);
	__amap_start_writes(amap, &amap_sync->iowaiter);
	if (pgdata) {
		amap_unlock(amap);
		STAILQ_INSERT_TAIL(&amap_sync->pgdata_list, pgdata, a_list);
	}
	if (prev)
		SLIST_INSERT_AFTER(prev, amap_sync, s_list);
	else
		SLIST_INSERT_HEAD(amap_sync_list, amap_sync, s_list);
}

static void
handle_ddspec_pre(struct ddtable *ddtable, struct ddsync_spec *spec)
{
	struct ddtable_ddlookup_node *child = spec->child;

	while (atomic_test_bit(DDTABLE_IN_SYNC, &ddtable->flags))
		pause("psg", 200);

	node_ddlookup_lock(child);
	ddtable_ddlookup_sync(ddtable, child, 1, spec->root_id, spec->last->b_start);
	ddtable_decr_sync_count(ddtable, child);
	atomic_clear_bit_short(DDLOOKUP_META_DATA_BUSY, &child->flags);
	chan_wakeup(child->ddlookup_wait);
	node_ddlookup_unlock(child);
}

static void
handle_ddspec_post(struct ddtable *ddtable, struct ddsync_spec *spec)
{
	struct ddtable_ddlookup_node *child = spec->child;
	struct ddtable_ddlookup_node *last = spec->last;

	wait_on_chan_check(child->ddlookup_wait, !atomic_test_bit_short(DDLOOKUP_META_DATA_DIRTY, &child->flags));
	if (atomic_test_bit_short(DDLOOKUP_META_DATA_ERROR, &child->flags)) {
		ddtable_ddlookup_node_put(last);
		ddtable_ddlookup_node_put(child);
		return;
	}

	while (atomic_test_bit(DDTABLE_IN_SYNC, &ddtable->flags))
		pause("psg", 200);

	node_ddlookup_lock(last);
	ddtable_ddlookup_write_barrier(last);
	ddlookup_set_next_block(last, child->b_start, ddtable->bint->bid);
	ddtable_ddlookup_node_dirty(ddtable, last);
	ddtable_ddlookup_node_wait(last);
	ddtable_ddlookup_sync(ddtable, last, 1, spec->root_id, spec->last->b_start);
	ddtable_decr_sync_count(ddtable, last);
	atomic_clear_bit_short(DDLOOKUP_META_DATA_BUSY, &last->flags);
	chan_wakeup(last->ddlookup_wait);
	node_ddlookup_unlock(last);
	ddtable_ddlookup_node_put(last);
	ddtable_ddlookup_node_put(child);
}

static void
handle_ddspec_list(struct ddtable *ddtable, struct ddspec_list *ddspec_list)
{
	struct ddsync_spec *spec;

	STAILQ_FOREACH(spec, ddspec_list, d_list) {
		handle_ddspec_pre(ddtable, spec);
	}

	while ((spec = STAILQ_FIRST(ddspec_list)) != NULL) {
		STAILQ_REMOVE_HEAD(ddspec_list, d_list);
		handle_ddspec_post(ddtable, spec);
		free(spec, M_DDTABLE);
	}
}

static void
handle_meta_list_sync(struct tdisk *tdisk, struct index_info_list *meta_index_info_list, struct amap_sync_list *amap_sync_list)
{
	struct index_info *index_info, *next;
	struct bintindex *index;
	struct bdevint *bint;
	struct amap *amap;
	struct amap_table *amap_table;

	if (TAILQ_EMPTY(meta_index_info_list))
		return;

	if (!node_sync_enabled() || !node_tdisk_sync_enabled(tdisk)) {
		index_info_list_free(meta_index_info_list);
		return;
	}

	TAILQ_FOREACH_SAFE(index_info, meta_index_info_list, i_list, next) {
		index = index_info->index;

		if (index_info->meta_type != INDEX_INFO_TYPE_AMAP)
			continue;

		bint = index->subgroup->group->bint;
		amap = amap_locate_by_block(index_info->b_start, bint, amap_sync_list);
		debug_check(!amap);
		node_amap_meta_sync_send(amap);
		TAILQ_REMOVE(meta_index_info_list, index_info, i_list);
		index_put(index);
		index_info_free(index_info);
	}

	TAILQ_FOREACH_SAFE(index_info, meta_index_info_list, i_list, next) {
		index = index_info->index;
		if (index_info->meta_type == INDEX_INFO_TYPE_AMAP_TABLE) {
			bint = index->subgroup->group->bint;
			amap_table = amap_table_locate_by_block(index_info->b_start, bint, amap_sync_list);
			debug_check(!amap_table);
			node_amap_table_meta_sync_send(amap_table);
		}
		TAILQ_REMOVE(meta_index_info_list, index_info, i_list);
		index_put(index);
		index_info_free(index_info);
	}
}

static void
ddthread_handle_ddwork(struct ddwork *ddwork)
{
	struct tdisk *tdisk = ddwork->tdisk;
	struct ddtable *ddtable = bdev_group_ddtable(tdisk->group);
	struct pgdata *pgdata;
	struct ddspec_list ddspec_list;
	struct index_sync_list delete_sync_list;
	struct index_info_list delete_index_info_list;
	struct index_info_list tmp_index_info_list;
	int retval;
	int error = 0, i;
#ifdef ENABLE_STATS
	uint32_t start_ticks, tmp_ticks;
#endif

	STAILQ_INIT(&ddspec_list);
	TAILQ_INIT(&tmp_index_info_list);
	TAILQ_INIT(&delete_index_info_list);
	SLIST_INIT(&delete_sync_list);

	SLIST_INIT(&ddwork->index_sync_list);
	DD_TSTART(start_ticks);
	index_list_insert(&ddwork->index_sync_list, &ddwork->index_info_list);
	DD_TEND(index_list_insert_ticks, start_ticks);

	DD_TSTART(start_ticks);
	index_list_insert(&ddwork->index_sync_list, &ddwork->meta_index_info_list);
	DD_TEND(index_list_meta_insert_ticks, start_ticks);

	DD_TSTART(start_ticks);
	for (i = 0; i < ddwork->pglist_cnt; i++) {
		pgdata = ddwork->pglist[i];
		pgdata_free_page(pgdata);
		DD_TSTART(tmp_ticks);
		process_delete_block_pre(pgdata->old_amap_block, &tmp_index_info_list);
		DD_TEND(delete_block_pre_ticks, tmp_ticks);
		if (atomic_test_bit(DDBLOCK_ZERO_BLOCK, &pgdata->flags) || atomic_test_bit(DDBLOCK_DEDUPE_DISABLED, &pgdata->flags)) {
			debug_info("old amap block %lu\n", pgdata->old_amap_block);
			debug_info("amap block %lu\n", pgdata->amap_block);
			continue;
		}

		if (atomic_test_bit(DDBLOCK_ENTRY_FOUND_DUPLICATE, &pgdata->flags)) {
			debug_info("old amap block %lu\n", pgdata->old_amap_block);
			debug_info("amap block %lu\n", pgdata->amap_block);
			continue;
		}

		/* Skip lock */
		if (!pgdata_amap_entry_valid(pgdata)) {
			DD_INC(invalid_amap_entry_pre, 1);
			continue;
		}

		if (!hash_valid((uint64_t *)pgdata->hash))
			continue;

		DD_TSTART(tmp_ticks);
		ddtable_hash_insert(tdisk->group, pgdata, &delete_index_info_list, &ddspec_list);
		DD_TEND(hash_insert_ticks, tmp_ticks);
	}
	DD_TEND(hash_insert_setup_ticks, start_ticks);

	DD_TSTART(start_ticks);
	retval = index_sync_start_io(&ddwork->index_sync_list, 1);
	if (unlikely(retval != 0))
		error = -1;
	DD_TEND(index_sync_ticks, start_ticks);

	DD_TSTART(start_ticks);
	if (tdisk_in_mirroring(tdisk) || tdisk_in_cloning(tdisk)) {
		for (i = 0; i < ddwork->pglist_cnt; i++) {
			pgdata = ddwork->pglist[i];
			if (!pgdata->amap || !atomic_test_bit_short(AMAP_META_DATA_BUSY, &pgdata->amap->flags))
				continue;
			wait_on_chan(pgdata->amap->amap_wait, !atomic_test_bit_short(AMAP_META_DATA_BUSY, &pgdata->amap->flags));
		}
	}
	DD_TEND(cloning_wait_ticks, start_ticks);

	DD_TSTART(start_ticks);
	index_list_insert(&delete_sync_list, &delete_index_info_list);
	DD_TEND(index_list_meta_insert_ticks, start_ticks);

	DD_TSTART(start_ticks);
	for (i = 0; i < ddwork->pglist_cnt; i++) {
		pgdata = ddwork->pglist[i];
		process_delete_block(ddtable, pgdata->old_amap_block, &delete_index_info_list, &delete_sync_list, &tmp_index_info_list, TYPE_DATA_BLOCK);
	}
	DD_TEND(delete_block_ticks, start_ticks);

	DD_TSTART(start_ticks);
	retval = index_sync_start_io(&delete_sync_list, 1);
	if (unlikely(retval != 0))
		error = -1;
	DD_TEND(index_sync_ticks, start_ticks);

	DD_TSTART(start_ticks);

	if (!SLIST_EMPTY(&ddwork->amap_sync_list)) {
		pgdata_wait_for_amap(tdisk, &ddwork->amap_sync_list);
	}

	DD_TEND(amap_sync_wait_ticks, start_ticks);

	DD_TSTART(start_ticks);
	retval = index_info_wait(&ddwork->index_info_list);
	if (unlikely(retval != 0))
		error = -1;
	DD_TEND(index_info_wait_ticks, start_ticks);

	DD_TSTART(start_ticks);
	retval = __index_info_wait(&ddwork->meta_index_info_list);
	if (unlikely(retval != 0))
		error = -1;
	DD_TEND(index_info_meta_wait_ticks, start_ticks);

	DD_TSTART(start_ticks);
	retval = __index_info_wait(&delete_index_info_list);
	if (unlikely(retval != 0))
		error = -1;
	DD_TEND(index_info_meta_wait_ticks, start_ticks);

	DD_TSTART(start_ticks);
	retval = index_sync_wait(&ddwork->index_sync_list);
	if (unlikely(retval != 0))
		error = -1;
	DD_TEND(index_sync_wait_ticks, start_ticks);

	DD_TSTART(start_ticks);
	retval = index_sync_wait(&delete_sync_list);
	if (unlikely(retval != 0))
		error = -1;
	DD_TEND(index_sync_wait_ticks, start_ticks);

	DD_TSTART(start_ticks);
	if (likely(error == 0)) {
		fastlog_clear_transactions(tdisk, ddwork->pglist, ddwork->pglist_cnt, &ddwork->meta_index_info_list, ddwork->log_reserved, 0);
	}
	else {
		debug_warn("Failed to sync index list\n");
	}
	fastlog_log_list_free(&ddwork->log_list);
	DD_TEND(log_clear_ticks, start_ticks);

	DD_TSTART(start_ticks);
	handle_meta_list_sync(tdisk, &ddwork->meta_index_info_list, &ddwork->amap_sync_list);
	DD_TEND(handle_meta_sync_ticks, start_ticks);

	DD_TSTART(start_ticks);
	if (!TAILQ_EMPTY(&ddwork->meta_index_info_list))
		node_newmeta_sync_complete(tdisk, ddwork->newmeta_transaction_id);

	node_pgdata_sync_complete(tdisk, ddwork->transaction_id);
	DD_TEND(node_pgdata_sync_ticks, start_ticks);

	DD_TSTART(start_ticks);
	amap_sync_list_free(&ddwork->amap_sync_list);
	__pglist_free(ddwork->pglist, ddwork->pglist_cnt);
	index_info_list_free(&tmp_index_info_list);
	index_info_list_free_unmap(&delete_index_info_list);
	pglist_cnt_decr(ddwork->pglist_cnt);
#if 0
	index_info_list_free(&ddwork->meta_index_info_list);
	index_info_list_free(&ddwork->index_info_list);
#endif
	handle_ddspec_list(ddtable, &ddspec_list);
	DD_TEND(post_free_ticks, start_ticks);
	tdisk_put(tdisk);
	uma_zfree(ddwork_cache, ddwork);
}

static void
ddthread_process_queue(void)
{
	struct ddwork *ddwork;
#ifdef ENABLE_STATS
	uint32_t start_ticks;
#endif

	atomic_inc(&write_requests);
	while ((ddwork = ddthread_list_first()) != NULL) {
		DD_TSTART(start_ticks);
		ddthread_handle_ddwork(ddwork);
		DD_TEND(handle_ddwork_ticks, start_ticks);
		atomic_dec(&ddthread_pending);
	}
	atomic_dec(&write_requests);
}

void
ddthread_wait_for_empty(void)
{
	while (!STAILQ_EMPTY(&work_list) || atomic_read(&ddthread_pending))
		processor_yield();
}

void
ddthread_insert(struct ddwork *ddwork)
{
	chan_lock(ddthread_wait);
	STAILQ_INSERT_TAIL(&work_list, ddwork, w_list);
	chan_wakeup_one_unlocked(ddthread_wait);
	chan_unlock(ddthread_wait);
}

#ifdef FREEBSD 
static void ddthread_run(void *data)
#else
static int ddthread_run(void *data)
#endif
{
	struct ddthread *ddthread = (struct ddthread *)(data);
#ifdef ENABLE_STATS
	uint32_t start_ticks;
#endif

	thread_start();

	for (;;) {
		wait_on_chan_interruptible(ddthread_wait, !STAILQ_EMPTY(&work_list) || kernel_thread_check(&ddthread->exit_flags, DDTHREAD_EXIT));

		DD_TSTART(start_ticks);
		ddthread_process_queue();
		DD_TEND(process_queue_ticks, start_ticks);

		if (kernel_thread_check(&ddthread->exit_flags, DDTHREAD_EXIT))
			break;
	}
	thread_end();
#ifdef FREEBSD 
	kproc_exit(0);
#else
	return 0;
#endif
}

static struct ddthread *
init_ddthread(int id)
{
	struct ddthread *ddthread;
	int retval;

	ddthread = __uma_zalloc(ddthread_cache, Q_NOWAIT | Q_ZERO, sizeof(*ddthread));
	if (unlikely(!ddthread)) {
		debug_warn("Slab allocation failure\n");
		return NULL;
	}
	ddthread->id = id;

	retval = kernel_thread_create(ddthread_run, ddthread, ddthread->task, "ddthr%d", id);
	if (unlikely(retval != 0)) {
		debug_warn("Failed to run ddthread\n");
		uma_zfree(ddthread_cache, ddthread);
		return NULL;
	}
	return ddthread;
}

int
init_ddthreads(void)
{
	int i;
	struct ddthread *ddthread;

	STAILQ_INIT(&work_list);
	ddthread_wait = wait_chan_alloc("ddthread wait");

	for (i = 0; i < MAX_DDTHREADS; i++) {
		ddthread = init_ddthread(i);
		if (unlikely(!ddthread)) {
			debug_warn("Failed to init ddthreads\n");
			return -1;
		}
		SLIST_INSERT_HEAD(&ddthread_list, ddthread, d_list);
	}

	return 0;
}

void
exit_ddthreads(void)
{
	struct ddthread *ddthread;
	int err;

	while ((ddthread = SLIST_FIRST(&ddthread_list)) != NULL) {
		SLIST_REMOVE_HEAD(&ddthread_list, d_list);
		err = kernel_thread_stop(ddthread->task, &ddthread->exit_flags, ddthread_wait, DDTHREAD_EXIT);
		if (err) {
			debug_warn("Shutting down ddthread failed\n");
			continue;
		}
		uma_zfree(ddthread_cache, ddthread);
	}

	wait_chan_free(ddthread_wait);
}
