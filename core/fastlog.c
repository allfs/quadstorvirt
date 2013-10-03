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

#include "fastlog.h"
#include "ddblock.h"
#include "bdevmgr.h"
#include "tcache.h"
#include "tdisk.h"
#include "ddthread.h"
#include "log_group.h"
#include "qs_lib.h"
#include "cluster.h"
#include "node_sync.h"
#include "bdevgroup.h"

extern uint32_t log_reserve_waits;

static inline struct log_page *
free_log_page_next_rotate(struct bdevgroup *group, struct log_page *log_page)
{
	struct log_page *ret;

	ret = TAILQ_NEXT(log_page, g_list);
	if (!ret)
		ret = TAILQ_FIRST(&group->glog_list);
	return ret;
}

static inline struct log_page *
free_log_page_first(struct bdevgroup *group)
{
	return TAILQ_FIRST(&group->glog_list); 
}

static uint64_t
get_transaction_id(struct bdevgroup *group)
{
	uint64_t ret;

	ret = group->log_transaction_id;
	group->log_transaction_id += V2_LOG_ENTRIES;
	return ret;
}

static void
reset_transaction_id(struct bdevgroup *group)
{
	group->log_transaction_id = 1;
}

static inline void
setup_free_page(struct bdevgroup *group, struct log_page *next)
{
	struct raw_log_page *raw_page;

	if (!next)
		return;

	log_page_lock(next);
	log_page_write_barrier(next);
	bzero(vm_pg_address(next->metadata), PAGE_SIZE);
	raw_page = (struct raw_log_page *)(((uint8_t *)vm_pg_address(next->metadata)) + V2_LOG_OFFSET);
	raw_page->transaction_start = get_transaction_id(group);
	log_page_unlock(next);
}

static void
log_info_add(struct log_info_list *log_list, struct log_page *log_page)
{
	struct log_info *log_info;

	log_info = zalloc(sizeof(struct log_info), M_LOG_INFO, Q_WAITOK);
	log_info->log_page = log_page;
	log_group_start_writes(log_page);
	atomic_inc(&log_page->pending_writes);
	SLIST_INSERT_HEAD(log_list, log_info, l_list);
}

static void
log_info_check(struct log_info_list *log_list, struct log_page *log_page)
{
	struct log_info *log_info;

	SLIST_FOREACH(log_info, log_list, l_list) {
		if (log_info->log_page == log_page)
			return;
	}
	log_info_add(log_list, log_page);
}

struct log_page *
get_free_log_page(struct bdevgroup *group, struct log_info_list *log_list)
{
	struct log_page *next;
	struct log_page *free_page;

again:
	free_page = group->free_page;
	if (group->free_idx == V2_LOG_ENTRIES) {
		next = free_log_page_next_rotate(group, free_page);
		wait_on_chan_check(next->log_page_wait, !atomic_read(&next->pending_transactions));
		debug_check(atomic_test_bit_short(LOG_META_DATA_DIRTY, &next->flags));
		setup_free_page(group, next);
		free_page = group->free_page = next;
		group->free_idx = 0;
	}

	log_group_lock(free_page->group);
	log_page_lock(free_page);
	if (atomic_test_bit_short(LOG_META_DATA_DIRTY, &free_page->flags) || free_page->group->bint->initialized != 1) {
		log_page_unlock(free_page);
		log_group_unlock(free_page->group);
		group->free_idx = V2_LOG_ENTRIES;
		goto again;
	}

	log_info_check(log_list, free_page);
	log_page_unlock(free_page);
	log_group_unlock(free_page->group);
	return free_page;
}

void
log_page_free(struct log_page *log_page)
{
	if (log_page->metadata)
		vm_pg_free(log_page->metadata);
	log_group_remove_page(log_page->group, log_page);
	sx_free(log_page->log_lock);
	wait_chan_free(log_page->log_page_wait);
	uma_zfree(log_cache, log_page);
}

static struct log_page *
log_page_alloc(allocflags_t flags, struct log_group *group, int group_idx)
{
	struct log_page *log_page;

	log_page = __uma_zalloc(log_cache, Q_NOWAIT | Q_ZERO, sizeof(*log_page));
	if (unlikely(!log_page)) {
		debug_warn("Slab allocation failure\n");
		return NULL;
	}

	log_page->metadata = vm_pg_alloc(flags);
	if (unlikely(!log_page->metadata)) {
		debug_warn("Page allocation failure\n");
		uma_zfree(log_cache, log_page);
		return NULL;
	}

	SLIST_INIT(&log_page->io_waiters);
	log_page->log_lock = sx_alloc("log lock");
	log_page->log_page_wait = wait_chan_alloc("log page alloc");
	atomic_set(&log_page->refs, 1);
	log_page->log_group_idx = group_idx;
	log_page->group = group;
	log_group_add_page(group, log_page);
	return log_page;
}

void
fastlog_insert_transaction(struct pgdata *pgdata, struct tdisk *tdisk, struct log_page *log_page, int insert_idx)
{
	struct v2_log_entry *entry;
	uint64_t index_write_id;
	uint64_t amap_write_id;
	struct bdevint *bint;

	entry = log_page_get_v2_entry(log_page, insert_idx);
	if (pgdata->index_info) {
		bint = pgdata->index_info->index->subgroup->group->bint;
		if (bint->v2_disk)
			index_write_id = pgdata->index_info->index_write_id;
		else
			index_write_id = 0;
	}
	else
		index_write_id = 0;

	if (is_v2_tdisk(tdisk))
		amap_write_id = pgdata->amap_write_id;
	else
		amap_write_id = 0;

	v2_log_entry_set_block(entry, pgdata->amap_block, tdisk->target_id, pgdata->lba, index_write_id, amap_write_id);
	pgdata->log_offset = insert_idx;
	pgdata->log_page = log_page;
}

static void
log_page_clear_entry(struct log_page *log_page, int insert_idx)
{
	struct v2_log_entry *entry;

	entry = log_page_get_v2_entry(log_page, insert_idx);
	bzero(entry, sizeof(*entry));
}

static void
log_page_put_entry(struct log_page *log_page)
{
	if (atomic_dec_and_test(&log_page->pending_transactions)) {
#if 0
		log_page_lock(log_page);
		if (!atomic_read(&log_page->pending_transactions))
			node_log_sync_post_send(log_page);
		log_page_unlock(log_page);
#endif
		chan_wakeup(log_page->log_page_wait);
	}
}

void 
fastlog_add_transaction(struct index_info *index_info, struct tdisk *tdisk, uint64_t lba, struct log_page *log_page, int insert_idx)
{
	struct v2_log_entry *entry;
	uint64_t index_write_id;
	uint64_t amap_write_id;
	struct bdevint *bint = index_info->index->subgroup->group->bint;

	if (bint->v2_disk)
		index_write_id = index_info->index_write_id;
	else
		index_write_id = 0;

	amap_write_id = (((uint64_t)index_info->meta_type) << 14 | tdisk->target_id);
	entry = log_page_get_v2_entry(log_page, insert_idx);
	v2_log_entry_set_block(entry, index_info->block, 0, lba, index_write_id, amap_write_id);
	index_info->log_page = log_page;
	index_info->log_offset = insert_idx;
}

void
log_list_free_error(struct log_info_list *log_list)
{
	struct log_info *log_info;

	while ((log_info = SLIST_FIRST(log_list)) != NULL) {
		SLIST_REMOVE_HEAD(log_list, l_list);
		log_end_writes(log_info->log_page, NULL);
		free_iowaiter(&log_info->iowaiter);
		free(log_info, M_LOG_INFO);
	}
}

void
fastlog_log_list_free(struct log_info_list *log_list)
{
	struct log_info *log_info;

	while ((log_info = SLIST_FIRST(log_list)) != NULL) {
		SLIST_REMOVE_HEAD(log_list, l_list);
		free_iowaiter(&log_info->iowaiter);
		free(log_info, M_LOG_INFO);
	}
}

void
fastlog_clear_transactions(struct tdisk *tdisk, struct pgdata **pglist, int pglist_cnt, struct index_info_list *index_info_list, int log_reserved, int error)
{
	int i;
	struct pgdata *pgdata;
	struct index_info *index_info;
	struct log_page *log_page;
	struct bdevgroup *group = bdev_group_get_log_group(tdisk->group);

	for (i = 0; i < pglist_cnt; i++) {
		pgdata = pglist[i];
		log_page = pgdata->log_page;

		if (!log_page)
			continue;
		debug_check(pgdata->log_offset < 0);
		if (error)
			log_page_clear_entry(log_page, pgdata->log_offset);
		log_page_put_entry(log_page);
	}

	TAILQ_FOREACH(index_info, index_info_list, i_list) {
		log_page = index_info->log_page;
		if (!log_page)
			continue;
		debug_check(index_info->log_offset < 0);
		log_page_put_entry(log_page);
	}

	chan_lock(group->wait_on_log);
	group->reserved_log_entries -= log_reserved;
	chan_wakeup_unlocked(group->wait_on_log);
	chan_unlock(group->wait_on_log);
}

int
bint_create_logs(struct bdevint *bint, int rw, int max, uint32_t offset)
{
	int i;
	int error = 0;
	struct log_page *log_page;
	uint64_t b_start;
	struct tcache *tcache = NULL;
	int retval;
	int done = 0;
	struct tcache_list tcache_list;
	int group_idx = 0;
	struct log_group *group = NULL, *prev = NULL;
	struct raw_log_page_v3 *raw_page_v3;
	uint32_t group_id = 0;
	uint16_t csum;

	SLIST_INIT(&tcache_list);
	b_start = (offset >> bint->sector_shift);
	for (i = 0; i < max; i++) {
		if (!group) {
			group = log_group_alloc(bint, group_id, b_start);
			group_id++;
			if (unlikely(!group)) {
				if (tcache) {
					tcache_put(tcache);
					tcache = NULL;
				}
				error = -1;
				break;
			}
			if (prev)
				LIST_INSERT_AFTER(prev, group, g_list);
			else
				LIST_INSERT_HEAD(&bint->log_group_list, group, g_list);
			prev = group;
		}

		log_page = log_page_alloc(VM_ALLOC_ZERO, group, group_idx);
		group_idx++;
		if (group_idx == LOG_GROUP_MAX_PAGES) {
			group_idx = 0;
			group = NULL;
		}

		if (unlikely(!log_page)) {
			if (tcache) {
				tcache_put(tcache);
				tcache = NULL;
			}
			error = -1;
			break;
		}

		if (!tcache) {
			tcache = tcache_alloc(TCACHE_ALLOC_SIZE);
		}

		raw_page_v3 = (struct raw_log_page_v3 *)(((uint8_t *)vm_pg_address(log_page->metadata)) + V2_LOG_OFFSET);
		csum = calc_csum16(vm_pg_address(log_page->metadata), BINT_BMAP_SIZE - sizeof(*raw_page_v3));
		raw_page_v3->csum = csum;
		retval = tcache_add_page(tcache, log_page->metadata, log_page_b_start(log_page), log_page->group->bint, LOG_PAGE_SIZE, rw);
		if (unlikely(retval != 0)) {
			error = -1;
			tcache_put(tcache);
			tcache = NULL;
			break;
		}
		done++;
		if (done == TCACHE_ALLOC_SIZE) {
			tcache_entry_rw(tcache, rw);
			SLIST_INSERT_HEAD(&tcache_list, tcache, t_list);
			tcache = NULL;
			done = 0;
		}
		b_start += (LOG_PAGE_SIZE >> bint->sector_shift);
	}

	if (error != 0) {
		tcache_list_wait(&tcache_list);
		return error;
	}

	if (tcache) {
		tcache_entry_rw(tcache, rw);
		SLIST_INSERT_HEAD(&tcache_list, tcache, t_list);
	}

	error = tcache_list_wait(&tcache_list);
	return error;
}

struct amap_table * 
amap_table_recreate(struct tdisk *tdisk, uint64_t lba, uint64_t block)
{
	struct amap_table *amap_table;
	struct amap_table_group *group;
	struct bdevint *bint;
	struct amap_table_index *table_index;
	struct tpriv priv = { 0 };
	int retval;
	uint32_t atable_id, group_id, group_offset;
	uint32_t index_id, index_offset;

	debug_info("recreate amap table at block %llu lba %llu\n", block, lba);
	atable_id = amap_table_id(lba);
	group_id = amap_table_group_id(atable_id, &group_offset);

	debug_check(group_id >= tdisk->amap_table_group_max);
	debug_check(!tdisk->amap_table_group);

	group = tdisk->amap_table_group[group_id];
	tdisk_tail_group(tdisk, group);

	bint = bdev_find(BLOCK_BID(block));
	if (unlikely(!bint)) {
		return NULL;
	}

	amap_table = amap_table_alloc(tdisk, atable_id);
	amap_table->metadata = vm_pg_alloc(VM_ALLOC_ZERO);
	if (unlikely(!amap_table->metadata)) {
		amap_table_put(amap_table);
		return NULL;
	}

	amap_table->amap_table_block = block;
	atomic_set_bit_short(ATABLE_META_IO_PENDING, &amap_table->flags);
	atomic_set_bit_short(ATABLE_META_DATA_NEW, &amap_table->flags);

	bdev_marker(bint->b_dev, &priv);
	retval = amap_table_io(amap_table, QS_IO_WRITE);
	bdev_start(bint->b_dev, &priv);
	if (unlikely(retval != 0)) {
		amap_table_put(amap_table);
		return NULL;
	}

	wait_on_chan(amap_table->amap_table_wait, !atomic_test_bit_short(ATABLE_META_DATA_DIRTY, &amap_table->flags));
	if (atomic_test_bit_short(ATABLE_META_DATA_ERROR, &amap_table->flags)) {
		amap_table_put(amap_table);
		return NULL;
	}

	index_id = amap_table->amap_table_id >> INDEX_TABLE_GROUP_SHIFT;
	index_offset = amap_table->amap_table_id & INDEX_TABLE_GROUP_MASK;
	table_index = &tdisk->table_index[index_id];
	table_index_write(tdisk, table_index, index_id, index_offset, amap_table);

	amap_table_group_lock(group);
	amap_table_insert(group, amap_table);
	amap_table_get(amap_table);
	amap_table_group_unlock(group);
	return amap_table;
}

struct amap *
amap_recreate(struct tdisk *tdisk, struct amap_table *amap_table, uint64_t lba, uint64_t block)
{
	struct amap *amap;
	uint32_t amap_id, amap_idx;
	struct bdevint *bint;
	struct tpriv priv = { 0 };
	int retval;

	debug_info("recreate amap at block %llu lba %llu\n", block, lba);
	amap_id = amap_get_id(lba);
	amap_idx = amap_id - (amap_table->amap_table_id * AMAPS_PER_AMAP_TABLE);

	bint = bdev_find(BLOCK_BID(block));
	if (unlikely(!bint))
		return NULL;

	amap = amap_alloc(amap_table, amap_id, amap_idx);
	if (unlikely(!amap))
		return NULL;

	amap->metadata = vm_pg_alloc(VM_ALLOC_ZERO);
	if (unlikely(!amap->metadata)) {
		amap_put(amap);
		return NULL;
	}

	amap->amap_block = block;
	bdev_marker(bint->b_dev, &priv);
	retval = amap_io(amap, WRITE_ID_MAX, QS_IO_WRITE);
	bdev_start(bint->b_dev, &priv);
	if (unlikely(retval != 0)) {
		amap_put(amap);
		return NULL;
	}

	wait_on_chan(amap->amap_wait, !atomic_test_bit_short(AMAP_META_DATA_DIRTY, &amap->flags));
	if (atomic_test_bit_short(AMAP_META_DATA_ERROR, &amap->flags)) {
		amap_put(amap);
		return NULL;
	}

	set_amap_block(amap_table, amap->amap_idx, amap->amap_block);
	bdev_marker(amap_table_bint(amap_table)->b_dev, &priv);
	retval = amap_table_io(amap_table, QS_IO_WRITE);
	bdev_start(amap_table_bint(amap_table)->b_dev, &priv);
	if (unlikely(retval != 0)) {
		set_amap_block(amap_table, amap->amap_idx, 0);
		amap_put(amap);
		return NULL;
	}

	wait_on_chan(amap_table->amap_table_wait, !atomic_test_bit_short(ATABLE_META_DATA_DIRTY, &amap_table->flags));
	if (atomic_test_bit_short(ATABLE_META_DATA_ERROR, &amap_table->flags)) {
		set_amap_block(amap_table, amap->amap_idx, 0);
		amap_put(amap);
		return NULL;
	}

	amap_insert(amap_table, amap, amap_idx);
	amap_get(amap);

	return amap;
}

static int
tdisk_replay_meta_block(struct log_entry *log_entry)
{
	struct tdisk *tdisk;
	struct amap_table *amap_table;
	struct amap *amap;
	uint16_t target_id;
	uint8_t type;
	int error;

	if (!log_entry->amap_write_id)
		return 0;

	type = (uint8_t)((log_entry->amap_write_id >> 14) & 0x3);
	target_id = (uint16_t)(log_entry->amap_write_id & 0xFFF);

	tdisk = tdisk_locate(target_id);
	if (unlikely(!tdisk))
		return 0;

	amap_table = amap_table_locate(tdisk, log_entry->lba, &error);
	if (!amap_table) {
		if (type != INDEX_INFO_TYPE_AMAP_TABLE) {
			tdisk_put(tdisk);
			return 0;
		}

		amap_table = amap_table_recreate(tdisk, log_entry->lba, log_entry->new_block);
		if (!amap_table) {
			tdisk_put(tdisk);
			return -1;
		}
	}

	amap_table_check_csum(amap_table);
	if (atomic_test_bit_short(ATABLE_META_DATA_ERROR, &amap_table->flags)) {
		amap_table_put(amap_table);
		tdisk_put(tdisk);
		return -1;
	}

	if (type == INDEX_INFO_TYPE_AMAP_TABLE) {
		amap_table_put(amap_table);
		tdisk_put(tdisk);
		return 0;
	}

	amap_table_lock(amap_table);
	amap = amap_locate(amap_table, log_entry->lba, &error);
	amap_table_unlock(amap_table);
	if (!amap) {
		amap = amap_recreate(tdisk, amap_table, log_entry->lba, log_entry->new_block);
		if (!amap) {
			amap_table_put(amap_table);
			tdisk_put(tdisk);
			return -1;
		}
	}

	amap_check_csum(amap);
	if (atomic_test_bit_short(AMAP_META_DATA_ERROR, &amap->flags)) {
		amap_put(amap);
		amap_table_put(amap_table);
		tdisk_put(tdisk);
		return -1;
	}

	amap_put(amap);
	amap_table_put(amap_table);
	tdisk_put(tdisk);
	return 0;
}

static int
tdisk_replay_amap_block(struct log_entry *log_entry, struct amap_sync_list *amap_sync_list)
{
	struct tdisk *tdisk;
	struct amap_table *amap_table;
	struct amap *amap;
	uint32_t entry_id;
	int error = 0;

	tdisk = tdisk_locate(log_entry->target_id);
	if (unlikely(!tdisk)) {
		return 0;
	}

	amap_table = amap_table_locate(tdisk, log_entry->lba, &error);
	if (!amap_table) {
		tdisk_put(tdisk);
		return 0;
	}

	amap_table_check_csum(amap_table);
	if (atomic_test_bit_short(ATABLE_META_DATA_ERROR, &amap_table->flags)) {
		amap_table_put(amap_table);
		tdisk_put(tdisk);
		return -1;
	}

	amap_table_lock(amap_table);
	amap = amap_locate(amap_table, log_entry->lba, &error);
	amap_table_unlock(amap_table);
	if (!amap) {
		amap_table_put(amap_table);
		tdisk_put(tdisk);
		return 0;
	}

	amap_check_csum(amap);
	if (atomic_test_bit_short(AMAP_META_DATA_ERROR, &amap->flags)) {
		amap_put(amap);
		amap_table_put(amap_table);
		tdisk_put(tdisk);
		return -1;
	}

	debug_check(log_entry->amap_write_id && !is_v2_tdisk(tdisk));
	if (log_entry->amap_write_id && write_id_greater(amap->write_id,  log_entry->amap_write_id)) {
		debug_info("log entry amap write id %llu amap write id %llu\n", (unsigned long long)log_entry->amap_write_id, (unsigned long long)amap->write_id);
		amap_put(amap);
		amap_table_put(amap_table);
		tdisk_put(tdisk);
		return 0;
	}

	debug_info("replay amap block %u %llu\n", BLOCK_BID(log_entry->new_block), (unsigned long long)BLOCK_BLOCKNR(log_entry->new_block));
	entry_id = amap_entry_id(amap, log_entry->lba);
	amap_entry_set_block(amap, entry_id, BLOCK_BLOCKNR(log_entry->new_block), BLOCK_BID(log_entry->new_block), lba_block_bits(log_entry->new_block));
	amap_check_sync_list(amap, amap_sync_list, NULL, WRITE_ID_MAX);
	log_entry->amap = amap;
	log_entry->amap_table = amap_table;
	tdisk_put(tdisk);
	return 0;
}

static int
log_page_load_entries_v1(struct log_page *log_page, struct log_entry_list *log_entry_list)
{
	int i;
	struct write_log_entry *entry;
	struct log_entry *log_entry;
	uint64_t transaction_id;
	int done = 0;
	struct raw_log_page *raw_page;

	raw_page = (struct raw_log_page *)(((uint8_t *)vm_pg_address(log_page->metadata)) + RAW_LOG_OFFSET);
	transaction_id = raw_page->transaction_start;
	entry = log_page_get_entry(log_page, 0);
	for (i = 0; i < MAX_LOG_ENTRIES; i++, entry++) {
		if (!ENTRY_TARGET_ID(entry) && !ENTRY_NEW_BLOCK(entry))
			continue;

		log_entry = __uma_zalloc(log_entry_cache, Q_NOWAIT | Q_ZERO, sizeof(*log_entry));
		if (unlikely(!log_entry)) {
			debug_warn("Slab allocation failure\n");
			return -1;
		}

		log_entry->transaction_id = transaction_id + i;
		debug_check(!transaction_id);
		log_entry->new_block = ENTRY_NEW_BLOCK(entry);
		log_entry->lba = ENTRY_LBA(entry);
		log_entry->target_id = ENTRY_TARGET_ID(entry);
		STAILQ_INSERT_TAIL(log_entry_list, log_entry, l_list);
		done++;
	}
	debug_info("done %d\n", done);
	return done;
}

static int
log_page_load_entries_v2(struct log_page *log_page, struct log_entry_list *log_entry_list)
{
	int i;
	struct v2_log_entry *entry;
	struct log_entry *log_entry;
	uint64_t transaction_id;
	int done = 0;
	struct raw_log_page *raw_page;

	raw_page = (struct raw_log_page *)(((uint8_t *)vm_pg_address(log_page->metadata)) + V2_LOG_OFFSET);
	transaction_id = raw_page->transaction_start;
	entry = log_page_get_v2_entry(log_page, 0);
	for (i = 0; i < V2_LOG_ENTRIES; i++, entry++) {
		if (!V2_ENTRY_TARGET_ID(entry) && !V2_ENTRY_NEW_BLOCK(entry))
			continue;

		log_entry = __uma_zalloc(log_entry_cache, Q_NOWAIT | Q_ZERO, sizeof(*log_entry));
		if (unlikely(!log_entry)) {
			debug_warn("Slab allocation failure\n");
			return -1;
		}

		log_entry->transaction_id = transaction_id + i;
		debug_check(!transaction_id);
		log_entry->new_block = V2_ENTRY_NEW_BLOCK(entry);
		log_entry->lba = V2_ENTRY_LBA(entry);
		log_entry->target_id = V2_ENTRY_TARGET_ID(entry);
		log_entry->amap_write_id = V2_ENTRY_AMAP_WRITE_ID(entry);
		log_entry->index_write_id = V2_ENTRY_INDEX_WRITE_ID(entry);
		STAILQ_INSERT_TAIL(log_entry_list, log_entry, l_list);
		done++;
	}
	return done;
}

static void
log_entry_free(struct log_entry *log_entry)
{
	if (log_entry->amap)
		amap_put(log_entry->amap);

	if (log_entry->amap_table)
		amap_table_put(log_entry->amap_table);

	uma_zfree(log_entry_cache, log_entry);
}

static void
log_entry_list_free(struct log_entry_list *log_entry_list)
{
	struct log_entry *log_entry;

	while ((log_entry = STAILQ_FIRST(log_entry_list)) != NULL) {
		STAILQ_REMOVE_HEAD(log_entry_list, l_list);
		log_entry_free(log_entry);
	}

}

static int
log_entry_tdisk_valid(struct log_entry *log_entry)
{
	struct tdisk *tdisk = NULL;

	if (log_entry->target_id) {
		tdisk = tdisk_locate(log_entry->target_id);
	}
	else if (log_entry->amap_write_id) {
		uint16_t target_id;

		target_id = (uint16_t)(log_entry->amap_write_id & 0xFFF);
		tdisk = tdisk_locate(target_id);
	}

	if (tdisk) {
		tdisk_put(tdisk);
		return 1;
	}
	else
		return 0;
}

static int 
log_entries_replay(struct log_entry_list *log_list)
{
	struct bdevint *bint;
	int retval;
	struct index_info_list index_info_list;
	struct index_sync_list index_sync_list;
	struct amap_sync_list amap_sync_list;
	struct log_entry_list log_entry_list;
	struct log_entry *log_entry;
	int error = 0;
	int done = 0;

	TAILQ_INIT(&index_info_list);
	SLIST_INIT(&amap_sync_list);
	SLIST_INIT(&index_sync_list);
	STAILQ_INIT(&log_entry_list);

	while ((log_entry = STAILQ_FIRST(log_list)) != NULL) {
		STAILQ_REMOVE_HEAD(log_list, l_list);
		done++;

		if (done > 4096) {
			retval = handle_amap_sync(&amap_sync_list);
			if (unlikely(retval != 0)) {
				debug_warn("Failed to sync amaps\n");
				error = -1;
			}

			index_list_insert(&index_sync_list, &index_info_list);
			retval = index_sync_start_io(&index_sync_list, 0);
			if (unlikely(retval != 0)) {
				debug_warn("Failed to issue io for indexes\n");
				error = -1;
			}

			retval = handle_amap_sync_wait(&amap_sync_list);
			if (unlikely(retval != 0)) {
				debug_warn("Failed to sync amaps\n");
				error = -1;
			}

			retval = index_sync_wait(&index_sync_list);
			if (unlikely(retval != 0)) {
				debug_warn("Indexes write error\n");
				error = -1;
			}

			retval = index_info_wait(&index_info_list);
			if (unlikely(retval != 0)) {
				debug_warn("Indexes write error\n");
				error = -1;
			}

			done = 0;
			log_entry_list_free(&log_entry_list);
#ifdef FREEBSD
			g_waitidle();
#endif
		}

		STAILQ_INSERT_HEAD(&log_entry_list, log_entry, l_list);
		if (!log_entry_tdisk_valid(log_entry)) {
			debug_info("skipping log entry at target id %d amap write id %llu\n", log_entry->target_id, (unsigned long long)log_entry->amap_write_id);
			continue;
		}

		if (log_entry->new_block) {
			debug_info("Found entry at %u:%llu target_id %u\n", BLOCK_BID(log_entry->new_block), (unsigned long long)BLOCK_BLOCKNR(log_entry->new_block), log_entry->target_id);
			bint = bdev_find(BLOCK_BID(log_entry->new_block));
			if (unlikely(!bint)) {
				retval = node_usr_send_bid_valid(BLOCK_BID(log_entry->new_block));
				if (retval != USR_RSP_BID_INVALID) { 
					debug_warn("Cannot find bdev at bid %u\n", BLOCK_BID(log_entry->new_block));
					error = -1;
				}
				else {
					debug_info("Skipping invalid bdev at bid %u\n", BLOCK_BID(log_entry->new_block));
				}
				continue;
			}

			retval = bdev_log_replay(bint, BLOCK_BLOCKNR(log_entry->new_block), log_entry->index_write_id, lba_block_size(log_entry->new_block), &index_info_list, log_entry->target_id ? TYPE_DATA_BLOCK : TYPE_META_BLOCK);
			if (unlikely(retval != 0)) {
				debug_warn("log replay failed for %u:%llu\n", BLOCK_BID(log_entry->new_block), (unsigned long long)BLOCK_BLOCKNR(log_entry->new_block));
				error = -1;
				continue;
			}

		}

		if (log_entry->target_id) {
			debug_info("Replay amap block at %u lba %llu\n", log_entry->target_id, (unsigned long long)log_entry->lba);
			retval = tdisk_replay_amap_block(log_entry, &amap_sync_list);
			if (unlikely(retval != 0)) {
				debug_warn("Failed to replay block at %u %llu lba %llu\n", BLOCK_BID(log_entry->new_block), (unsigned long long)BLOCK_BLOCKNR(log_entry->new_block), (unsigned long long)log_entry->lba);
				error = -1;
			}
		}
		else {
			retval = tdisk_replay_meta_block(log_entry);
			if (unlikely(retval != 0)) {
				debug_warn("Failed to replay meta  block at %u %llu lba %llu\n", BLOCK_BID(log_entry->new_block), (unsigned long long)BLOCK_BLOCKNR(log_entry->new_block), (unsigned long long)log_entry->lba);
				error = -1;
			}
		}
	}

	retval = handle_amap_sync(&amap_sync_list);
	if (unlikely(retval != 0)) {
		debug_warn("Failed to sync amaps\n");
		error = -1;
	}

	index_list_insert(&index_sync_list, &index_info_list);
	retval = index_sync_start_io(&index_sync_list, 0);
	if (unlikely(retval != 0)) {
		debug_warn("Failed to issue io for indexes\n");
		error = -1;
	}

	retval = handle_amap_sync_wait(&amap_sync_list);
	if (unlikely(retval != 0)) {
		debug_warn("Failed to sync amaps\n");
		error = -1;
	}

	retval = index_sync_wait(&index_sync_list);
	if (unlikely(retval != 0)) {
		debug_warn("Indexes write error\n");
		error = -1;
	}

	retval = index_info_wait(&index_info_list);
	if (unlikely(retval != 0)) {
		debug_warn("Indexes write error\n");
		error = -1;
	}

	log_entry_list_free(&log_entry_list);
	return error;
}

struct list_container {
	struct log_page *page;
	uint64_t transaction_start;
	STAILQ_ENTRY(list_container) c_list;
};
STAILQ_HEAD(log_container_list, list_container);

static void
log_page_insert(struct log_container_list *lhead, struct list_container *cont)
{
	struct list_container *iter, *prev = NULL;

	STAILQ_FOREACH(iter, lhead, c_list ) {
		if (iter->transaction_start < cont->transaction_start) {
			prev = iter;
			continue;
		}
		debug_check(iter->transaction_start == cont->transaction_start);
		if (prev)
			STAILQ_INSERT_AFTER(lhead, prev, cont, c_list);
		else
			STAILQ_INSERT_HEAD(lhead, cont, c_list);
		return;
	}
	STAILQ_INSERT_TAIL(lhead, cont, c_list);
}

static int
__bint_check_write_logs(struct bdevint *bint, struct log_group *group, struct log_container_list *log_page_list)
{
	int i;
	struct log_page *log_page;
	struct list_container *cont;
	struct raw_log_page *raw_page;
	struct raw_log_page_v3 *raw_page_v3;
	int count = 0;

	for (i = 0; i < LOG_GROUP_MAX_PAGES; i++) {
		log_page = group->logs[i];

		raw_page_v3 = (struct raw_log_page_v3 *)(((uint8_t *)vm_pg_address(log_page->metadata)) + V2_LOG_OFFSET);
		if (bint->v2_log_format == BINT_V3_LOG_FORMAT) {
			uint16_t csum;

			csum = calc_csum16(vm_pg_address(log_page->metadata), BINT_BMAP_SIZE - sizeof(*raw_page_v3));
			if (csum != raw_page_v3->csum) {
				debug_warn("Csum mismatch expected %x got %x\n", csum, raw_page_v3->csum);
				return -1;
			}
		}

		if (group->bint->v2_log_format)
			raw_page = (struct raw_log_page *)(((uint8_t *)vm_pg_address(log_page->metadata)) + V2_LOG_OFFSET);
		else
			raw_page = (struct raw_log_page *)(((uint8_t *)vm_pg_address(log_page->metadata)) + RAW_LOG_OFFSET);
		if (!raw_page->transaction_start)
			continue;

		cont = zalloc(sizeof(*cont), M_LOG_CONT, Q_WAITOK);
		cont->page = log_page;
		cont->transaction_start = raw_page->transaction_start;
		log_page_insert(log_page_list, cont);
		count++;
	}
	return count;
}

static int 
bint_check_write_logs(struct bdevint *bint, struct log_container_list *log_page_list)
{
	int count = 0, retval;
	struct log_group *log_group;

	LIST_FOREACH(log_group, &bint->log_group_list, g_list) {
		retval = __bint_check_write_logs(bint, log_group, log_page_list);
		if (unlikely(retval < 0))
			return retval;
		count += retval;
	}

	return count;
}

static int
bint_reset_write_logs(struct bdevint *bint)
{
	int retval;

	bint_log_groups_free(bint);
	retval = bint_create_logs(bint, QS_IO_WRITE, MAX_LOG_PAGES, LOG_PAGES_OFFSET);
	debug_info("v2 disk %d v2 log format %d\n", bint->v2_disk, bint->v2_log_format);
	if (retval == 0 && bint->v2_log_format != BINT_V3_LOG_FORMAT) {
		debug_info("resetting disk to v2 log format\n");
		bint->v2_log_format = BINT_V3_LOG_FORMAT;
		atomic_set_bit(BINT_IO_PENDING, &bint->flags);
		retval = bint_sync(bint, 1);
	}
	else
		bdev_sync(bint);

	return retval;
}

static void 
sanity_check_list(struct log_entry_list *lhead)
{
	struct log_entry *iter, *prev = NULL;

	STAILQ_FOREACH(iter, lhead, l_list) {
		if (prev && prev->transaction_id >= iter->transaction_id)
			debug_warn("prev transaction id %llu iter transaction id %llu\n", (unsigned long long)prev->transaction_id, (unsigned long long)iter->transaction_id);
		prev = iter;
	}
}

int
bdev_reset_write_logs(struct bdevgroup *group)
{
	struct bdevint *bint, *master_bint;
	struct bdev_log_list *lhead = &group->bdev_log_list;
	int retval;
	int log_disks;

	if (!group->logdata)
		return 0;

	master_bint = group->master_bint; 
	if (master_bint == NULL) {
		if (!SLIST_EMPTY(lhead)) {
			debug_warn("Cannot find master disk\n");
			atomic_set(&group->log_error, 1);
		}
		return -1;
	}

	log_disks = bdev_log_list_count(group);
	if (log_disks != master_bint->log_disks) {
		debug_warn("Master disk log disk count %d actual loaded disks %d\n", master_bint->log_disks, log_disks);
		atomic_set(&group->log_error, 1);
		return -1;
	}

	master_bint->log_write = 1;
	master_bint->in_log_replay = 0;
	retval = bint_sync(master_bint, 1);
	if (unlikely(retval != 0)) {
		atomic_set(&group->log_error, 1);
		return -1;
	}

	debug_info("Reset individual disk logs\n");
	SLIST_FOREACH(bint, lhead, l_list) {
		retval = bint_reset_write_logs(bint);
		if (unlikely(retval != 0)) {
			debug_warn("Failed to reset write logs\n");
			atomic_set(&group->log_error, 1);
			return -1;
		}
	}

	debug_info("Reset master from log write mode\n");
	master_bint->log_write = 0;
	retval = bint_sync(master_bint, 1);
	if (unlikely(retval != 0)) {
		debug_warn("Failed to sync master\n");
		atomic_set(&group->log_error, 1);
		return -1;
	}
	atomic_set(&group->log_error, 0);
	reset_transaction_id(group);
	return 0;
}

static void
log_container_list_free(struct log_container_list *lhead)
{
	struct list_container *cont;

	while ((cont = STAILQ_FIRST(lhead)) != NULL) {
		STAILQ_REMOVE_HEAD(lhead, c_list);
		free(cont, M_LOG_CONT);
	}
}

void
bdev_replay_write_logs(struct bdevgroup *group)
{
	struct bdevint *bint, *master_bint;
	struct bdev_log_list *lhead = &group->bdev_log_list;
	struct log_container_list log_page_list;
	struct log_entry_list log_entry_list;
	int retval;
	int count = 0;
	struct list_container *cont;
	struct log_page *log_page;
	int log_disks;

	if (!atomic_read(&group->bdevs))
		return;

	debug_info("start pool %s bdevs %d\n", group->name, &group->bdevs);
	master_bint = group->master_bint;
	if (master_bint == NULL) {
		if (!SLIST_EMPTY(lhead)) {
			debug_warn("Cannot find master disk for pool %s\n", group->name);
			atomic_set(&group->log_error, 1);
		}
		return;
	}

	log_disks = bdev_log_list_count(group);
	if (log_disks != master_bint->log_disks) {
		debug_warn("Pool %s master disk log disk count %d actual loaded disks %d\n", group->name, master_bint->log_disks, log_disks);
		atomic_set(&group->log_error, 1);
		return;
	}

	if (master_bint->log_write) {
		debug_info("last stopped with bint in log write mode\n");
		bdev_reset_write_logs(group);
		return;
	}

	STAILQ_INIT(&log_page_list);
	SLIST_FOREACH(bint, lhead, l_list) {
		retval = bint_check_write_logs(bint, &log_page_list);
		if (retval < 0) {
			atomic_set(&group->log_error, 1);
			log_container_list_free(&log_page_list);
			return;
		}
		count += retval;
	}

	if (!count) {
		debug_info("Set master to log write mode\n");
		bdev_reset_write_logs(group);
		return;
	}

	debug_check(STAILQ_EMPTY(&log_page_list));

	STAILQ_INIT(&log_entry_list);
	STAILQ_FOREACH(cont, &log_page_list, c_list) {
		log_page = cont->page;
		bint = log_page->group->bint;
		if (bint->v2_log_format)
			retval = log_page_load_entries_v2(log_page, &log_entry_list);
		else
			retval = log_page_load_entries_v1(log_page, &log_entry_list);
		if (retval < 0) {
			atomic_set(&group->log_error, 1);
			break;
		}
		count += retval;
	}

	log_container_list_free(&log_page_list);
	if (!count || atomic_read(&group->log_error)) {
		log_entry_list_free(&log_entry_list);
		return;
	}

	debug_info("Log entries to process are %d\n", count);
	sanity_check_list(&log_entry_list);

	debug_info("Start replay log entries\n");
	retval = log_entries_replay(&log_entry_list);
	if (unlikely(retval != 0)) {
		atomic_set(&group->log_error, 1);
		return;
	}
	debug_info("Done replay log entries\n");

	debug_info("Set master to log write mode\n");
	bdev_reset_write_logs(group);
	debug_info("Done\n");
}

static void
glog_list_insert_pages(struct bdevgroup *bdevgroup, struct log_group *group)
{
	int i;
	struct log_page *log_page;

	for (i = 0; i < LOG_GROUP_MAX_PAGES; i++) {
		log_page = group->logs[i];
		TAILQ_INSERT_TAIL(&bdevgroup->glog_list, log_page, g_list);
		atomic_add(V2_LOG_ENTRIES, &bdevgroup->free_log_entries);
	}
}

struct log_group *
bint_find_log_group(struct bdevint *bint, int group_id)
{
	struct log_group *log_group;

	LIST_FOREACH(log_group, &bint->log_group_list, g_list) {
		if (log_group->group_id == group_id) {
			return log_group;
		}
	}
	debug_check(1);
	return NULL;
}

static void
__bdev_setup_first_log(struct bdevint *bint)
{
	int i;
	struct log_group *group;
	struct bdevgroup *bdevgroup = bint->group;

	for (i = 0; i < MAX_LOG_GROUPS; i++) {
		group = bint_find_log_group(bint, i);
		glog_list_insert_pages(bdevgroup, group);
	}

	bdevgroup->free_page = free_log_page_first(bdevgroup);
	setup_free_page(bdevgroup, bdevgroup->free_page);

}

static void
__bdev_setup_log_list(struct bdevgroup *bdevgroup)
{
	int i;
	struct bdevint *bint;
	struct log_group *group;

	for (i = 0; i < MAX_LOG_GROUPS; i++) {
		SLIST_FOREACH(bint, &bdevgroup->bdev_log_list, l_list) {
			if (bint->initialized <= 0)
				continue;

			group = bint_find_log_group(bint, i);
			glog_list_insert_pages(bdevgroup, group);
		}
	}
	bdevgroup->free_page = free_log_page_first(bdevgroup);
	setup_free_page(bdevgroup, bdevgroup->free_page);
}

void
bdev_setup_log_list(struct bdevgroup *group)
{
	sx_xlock(group->log_lock);
	TAILQ_INIT(&group->glog_list);
	atomic_set(&group->free_log_entries, 0);
	__bdev_setup_log_list(group);
	sx_xunlock(group->log_lock);
}

static void
log_group_log_add(struct bdevgroup *bdevgroup, struct log_group *group, struct log_group *prev_group)
{
	struct log_page *prev, *log;
	int i;

	debug_check(!group->bint->v2_log_format);
	prev = prev_group->logs[LOG_GROUP_MAX_PAGES - 1];
	for (i = 0; i < LOG_GROUP_MAX_PAGES; i++) {
		log = group->logs[i];
		TAILQ_INSERT_AFTER(&bdevgroup->glog_list, prev, log, g_list);
		atomic_add(V2_LOG_ENTRIES, &bdevgroup->free_log_entries);
		prev = log;
	}
}

static void
log_group_log_remove(struct bdevgroup *bdevgroup, struct log_group *group)
{
	struct log_page *log;
	int i;

	debug_check(!group->bint->v2_log_format);
	for (i = 0; i < LOG_GROUP_MAX_PAGES; i++) {
		log = group->logs[i];
		if (!TAILQ_ENTRY_EMPTY(log, g_list)) {
			TAILQ_REMOVE_INIT(&bdevgroup->glog_list, log, g_list);
			atomic_sub(V2_LOG_ENTRIES, &bdevgroup->free_log_entries);
		}
	}
}

int
bdev_log_remove(struct bdevint *bint, int force)
{
	struct log_group *group;
	struct bdevgroup *bdevgroup = bint->group;

	sx_xlock(bdevgroup->log_lock);
	if (bdevgroup->reserved_log_entries && bint->initialized == 1 && !force) {
		sx_xunlock(bdevgroup->log_lock);
		return -1;
	}

	if (bdevgroup->free_page && bdevgroup->free_page->group->bint == bint) {
		bdevgroup->free_page = NULL;
		bdevgroup->free_idx = 0;
	}

	LIST_FOREACH(group, &bint->log_group_list, g_list) {
		log_group_log_remove(bdevgroup, group);
	}

	if (!bdevgroup->free_page) {
		bdevgroup->free_page = free_log_page_first(bdevgroup);
		setup_free_page(bdevgroup, bdevgroup->free_page);
	}
	sx_xunlock(bdevgroup->log_lock);
	return 0;
}

void
bdev_log_add(struct bdevint *bint)
{
	struct log_group *group;
	struct log_group *prev_group;
	struct bdevint *prev;
	struct bdevgroup *bdevgroup = bint->group;
	int i;

	sx_xlock(bdevgroup->log_lock);
	if (TAILQ_EMPTY(&bdevgroup->glog_list)) {
		__bdev_setup_first_log(bint);
		bdev_log_list_insert(bint);
		sx_xunlock(bdevgroup->log_lock);
		return;
	}

	prev = SLIST_FIRST(&bdevgroup->bdev_log_list);
	for (i = 0; i < MAX_LOG_GROUPS; i++) {
		group = bint_find_log_group(bint, i);
		debug_check(!group);
		prev_group = bint_find_log_group(prev, i);
		debug_check(!prev_group);
		log_group_log_add(bdevgroup, group, prev_group);
	}
	bdev_log_list_insert(bint);
	sx_xunlock(bdevgroup->log_lock);
}

void
fastlog_reserve(struct tdisk *tdisk, struct write_list *wlist, int count)
{
	struct bdevgroup *bdevgroup = bdev_group_get_log_group(tdisk->group);

	if (atomic_test_bit(WLIST_DONE_LOG_RESERVE, &wlist->flags))
		return;

	chan_lock(bdevgroup->wait_on_log);
	while ((bdevgroup->reserved_log_entries + count) > atomic_read(&bdevgroup->free_log_entries)) {
		GLOB_INC(log_reserve_waits, 1);
		wait_on_chan_locked(bdevgroup->wait_on_log, ((bdevgroup->reserved_log_entries + count) <= atomic_read(&bdevgroup->free_log_entries)));
	}
	bdevgroup->reserved_log_entries += count;
	chan_unlock(bdevgroup->wait_on_log);
	wlist->log_reserved = count;
	atomic_set_bit(WLIST_DONE_LOG_RESERVE, &wlist->flags);
	return;
}
