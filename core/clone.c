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

#include "tdisk.h"
#include "ddthread.h"
#include "bdevgroup.h"
#include "tcache.h"
#include "rcache.h"
#include "cluster.h"
#include "vdevdefs.h"

struct clone_info_list clone_info_list = STAILQ_HEAD_INITIALIZER(clone_info_list);

uint32_t
amap_bitmap_group_offset(uint32_t amap_id)
{
	uint32_t amaps_per_group = (AMAPS_PER_AMAP_TABLE * AMAP_TABLE_PER_GROUP);
	uint32_t diff = (amap_id - amaps_per_group);
	return (diff / 32768);
}

void
amap_group_bmaps_free(struct tdisk *tdisk, uint32_t group_id)
{
	struct group_bmap_list *bmap_list;
	struct amap_group_bitmap *bmap;

	if (!tdisk->group_bmaps)
		goto skip;

	bmap_list = &tdisk->group_bmaps[group_id];
	debug_check(!bmap_list);

	while ((bmap = STAILQ_FIRST(bmap_list)) != NULL) {
		STAILQ_REMOVE_HEAD(bmap_list, b_list);
		vm_pg_free(bmap->bmap);
		free(bmap, M_GROUP_BMAP);
	}

skip:
	if (!tdisk->group_table_bmaps)
		return;

	bmap = tdisk->group_table_bmaps[group_id];
	if (bmap)  {
		vm_pg_free(bmap->bmap);
		free(bmap, M_GROUP_BMAP);
		tdisk->group_table_bmaps[group_id] = 0;
	}
}

struct amap_group_bitmap *
amap_group_table_bmap_locate(struct tdisk *tdisk, uint32_t group_id, int *error)
{
	struct amap_group_bitmap *bmap;

	*error = 0;
	if (!tdisk->group_table_bmaps)
		return NULL;

	bmap = tdisk->group_table_bmaps[group_id];

	if (bmap)
		return bmap;

	bmap = zalloc(sizeof(*bmap), M_GROUP_BMAP, Q_WAITOK);
	bmap->bmap = vm_pg_alloc(VM_ALLOC_ZERO);
	if (unlikely(!bmap->bmap)) {
		free(bmap, M_GROUP_BMAP);
		*error = -1;
		return NULL;
	}
	tdisk->group_table_bmaps[group_id] = bmap;
	return bmap;
}

struct amap_group_bitmap *
amap_group_bmap_locate(struct tdisk *tdisk, uint32_t group_id, uint32_t group_offset, int *error)
{
	struct group_bmap_list *bmap_list;
	struct amap_group_bitmap *bmap, *prev = NULL;

	*error = 0;

	if (!tdisk->group_bmaps)
		return NULL;

	bmap_list = &tdisk->group_bmaps[group_id];
	if (!bmap_list)
		return NULL;

	STAILQ_FOREACH(bmap, bmap_list, b_list) {
		if (bmap->group_offset == group_offset)
			return bmap;
		if (bmap->group_offset > group_offset)
			break;
		prev = bmap;
	}

	bmap = zalloc(sizeof(*bmap), M_GROUP_BMAP, Q_WAITOK);
	bmap->bmap = vm_pg_alloc(VM_ALLOC_ZERO);
	bmap->group_offset = group_offset;
	if (unlikely(!bmap->bmap)) {
		*error = -1;
		free(bmap, M_GROUP_BMAP);
		return NULL;
	}
	if (prev)
		STAILQ_INSERT_AFTER(bmap_list, prev, bmap, b_list);
	else
		STAILQ_INSERT_TAIL(bmap_list, bmap, b_list);
	return bmap;
}

int
bmap_bit_is_set(struct amap_group_bitmap *bmap, uint32_t bmap_offset)
{
	uint8_t *ptr = (uint8_t *)(vm_pg_address(bmap->bmap));
	int i, j;

	i = bmap_offset >> 3;
	j = bmap_offset & 0x7;
	return (ptr[i] & (1 << j));
}

void
bmap_set_bit(struct amap_group_bitmap *bmap, uint32_t bmap_offset)
{
	uint8_t *ptr = (uint8_t *)(vm_pg_address(bmap->bmap));
	int i, j;

	i = bmap_offset >> 3;
	j = bmap_offset & 0x7;
	ptr[i] |= (1 << j);
}

static struct amap_table *
clone_amap_table_get(struct tdisk *dest_tdisk, struct amap_table_group *dest_group, uint32_t group_id, uint32_t group_offset, uint32_t atable_id, struct write_list *wlist)
{
	uint64_t block;
	struct amap_table *dest_amap_table;
	struct amap_table_index *dest_table_index;
	int retval;

	dest_table_index = &dest_tdisk->table_index[group_id];
	block = get_amap_table_block(dest_table_index, group_offset);
	dest_amap_table = dest_group->amap_table[group_offset];
	if (!block && !dest_amap_table) {
		wlist_lock(wlist);
		retval = amap_table_init(dest_tdisk, dest_group, atable_id, &wlist->meta_index_info_list);
		wlist_unlock(wlist);
		if (unlikely(retval != 0)) {
			tdisk_set_clone_error(dest_tdisk);
			return NULL;
		}
		dest_amap_table = dest_group->amap_table[group_offset];
	}
	else if (!dest_amap_table) {
		dest_amap_table = amap_table_load_async(dest_tdisk, block, dest_group, group_id, atable_id);
		if (unlikely(!dest_amap_table)) {
			tdisk_set_clone_error(dest_tdisk);
			return NULL;
		}
	}
	amap_table_get(dest_amap_table);
	return dest_amap_table;
}

void
clone_data_free(struct clone_data *clone_data)
{
	if (clone_data->metadata)
		vm_pg_free(clone_data->metadata);
	if (clone_data->src_amap)
		amap_put(clone_data->src_amap);
	if (clone_data->amap) {
		amap_table_put(clone_data->amap->amap_table);
		amap_put(clone_data->amap);
	}
	wait_completion_free(clone_data->completion);
	free(clone_data, M_CLONE_DATA); 
}

struct clone_data * 
clone_data_alloc(int type)
{
	struct clone_data *clone_data;

	clone_data = zalloc(sizeof(*clone_data), M_CLONE_DATA, Q_WAITOK);
	clone_data->completion = wait_completion_alloc("clone data compl");
	clone_data->type = type;
	return clone_data;
}

static void
__amap_table_clone_check(struct tdisk *dest_tdisk, struct amap_table *src_amap_table)
{
	struct amap_group_bitmap *bmap;
	struct amap_table_group *dest_group;
	uint32_t clone_amap_id = tdisk_get_clone_amap_id(dest_tdisk);
	uint32_t clone_amap_table_id = clone_amap_id / AMAPS_PER_AMAP_TABLE;
	uint32_t group_id, group_offset;
	int error;

	if (tdisk_clone_error(dest_tdisk))
		return;

	if (src_amap_table->amap_table_id < clone_amap_table_id)
		return;

	group_id = amap_table_group_id(src_amap_table->amap_table_id, &group_offset);
	dest_group = dest_tdisk->amap_table_group[group_id];
	amap_table_group_lock(dest_group);
	bmap = amap_group_table_bmap_locate(dest_tdisk, group_id, &error);
	if (unlikely(!bmap)) {
		if (error)
			tdisk_set_clone_error(dest_tdisk);
		amap_table_group_unlock(dest_group);
		return;
	}

	if (bmap_bit_is_set(bmap, group_offset)) {
		amap_table_group_unlock(dest_group);
		return;
	}

	bmap_set_bit(bmap, group_offset);
	amap_table_group_unlock(dest_group);
}

static void
__amap_table_mirror_check(struct tdisk *dest_tdisk, struct amap_table *src_amap_table)
{
	struct amap_group_bitmap *bmap;
	struct amap_table_group *dest_group;
	uint32_t clone_amap_id = tdisk_get_clone_amap_id(dest_tdisk);
	uint32_t clone_amap_table_id = clone_amap_id / AMAPS_PER_AMAP_TABLE;
	uint32_t group_id, group_offset;
	int error;

	if (tdisk_mirror_error(dest_tdisk))
		return;

	if (src_amap_table->amap_table_id < clone_amap_table_id)
		return;

	group_id = amap_table_group_id(src_amap_table->amap_table_id, &group_offset);
	dest_group = dest_tdisk->amap_table_group[group_id];
	amap_table_group_lock(dest_group);
	bmap = amap_group_table_bmap_locate(dest_tdisk, group_id, &error);
	if (unlikely(!bmap)) {
		if (error)
			tdisk_set_mirror_error(dest_tdisk);
		amap_table_group_unlock(dest_group);
		return;
	}

	if (bmap_bit_is_set(bmap, group_offset)) {
		amap_table_group_unlock(dest_group);
		return;
	}

	bmap_set_bit(bmap, group_offset);
	amap_table_group_unlock(dest_group);
}

static void 
__amap_mirror_check(struct tdisk *src_tdisk, struct amap *src_amap, int isnew)
{
	struct amap_group_bitmap *bmap;
	struct amap_table_group *src_group;
	uint32_t group_id, group_offset, bmap_group_offset;
	uint32_t amap_group_offset;
	struct clone_data *clone_data;
	pagestruct_t *metadata;
	int error;

	if (tdisk_mirror_error(src_tdisk))
		return;

	if (src_amap->amap_id <= tdisk_get_clone_amap_id(src_tdisk))
		return;
	
	metadata = vm_pg_alloc(0);
	if (unlikely(!metadata)) {
		tdisk_set_mirror_error(src_tdisk);
		return;
	}

	group_id = amap_table_group_id(src_amap->amap_table->amap_table_id, &group_offset);
	bmap_group_offset = amap_bitmap_group_offset(src_amap->amap_id);

	src_group = src_tdisk->amap_table_group[group_id];
	amap_table_group_lock(src_group);
	bmap = amap_group_bmap_locate(src_tdisk, group_id, bmap_group_offset, &error);
	if (unlikely(!bmap)) {
		if (error)
			tdisk_set_mirror_error(src_tdisk);
		amap_table_group_unlock(src_group);
		vm_pg_free(metadata);
		return;
	}

	amap_group_offset = amap_to_bitmap_offset(src_amap->amap_id);
	if (bmap_bit_is_set(bmap, amap_group_offset)) {
		amap_table_group_unlock(src_group);
		vm_pg_free(metadata);
		return;
	}

	bmap_set_bit(bmap, amap_group_offset);
	if (isnew) {
		amap_table_group_unlock(src_group);
		vm_pg_free(metadata);
		return;
	}

	memcpy(vm_pg_address(metadata), vm_pg_address(src_amap->metadata), AMAP_SIZE);
	atomic_set_bit_short(AMAP_META_DATA_BUSY, &src_amap->flags);
	amap_get(src_amap);
	amap_table_get(src_amap->amap_table);

	clone_data = clone_data_alloc(CLONE_DATA_MIRROR);
	clone_data->async = 1;
	clone_data->amap = src_amap;
	clone_data->metadata = metadata;
	clone_data_insert(clone_data, &src_tdisk->clone_list);
	amap_table_group_unlock(src_group);
	return;
}

static void 
__amap_clone_check(struct tdisk *dest_tdisk, struct amap *src_amap, int isnew)
{
	struct amap_group_bitmap *bmap;
	struct amap_table_group *dest_group;
	struct amap_table *dest_amap_table;
	uint32_t group_id, group_offset, bmap_group_offset;
	uint32_t amap_group_offset;
	struct clone_data *clone_data;
	struct amap *dest_amap;
	uint64_t block;
	pagestruct_t *metadata;
	int error;

	if (tdisk_clone_error(dest_tdisk))
		return;

	if (src_amap->amap_id <= tdisk_get_clone_amap_id(dest_tdisk))
		return;
	
	metadata = vm_pg_alloc(0);
	if (unlikely(!metadata)) {
		tdisk_set_clone_error(dest_tdisk);
		return;
	}

	group_id = amap_table_group_id(src_amap->amap_table->amap_table_id, &group_offset);
	bmap_group_offset = amap_bitmap_group_offset(src_amap->amap_id);

	dest_group = dest_tdisk->amap_table_group[group_id];
	amap_table_group_lock(dest_group);
	bmap = amap_group_bmap_locate(dest_tdisk, group_id, bmap_group_offset, &error);
	if (unlikely(!bmap)) {
		if (error)
			tdisk_set_clone_error(dest_tdisk);
		amap_table_group_unlock(dest_group);
		vm_pg_free(metadata);
		return;
	}

	amap_group_offset = amap_to_bitmap_offset(src_amap->amap_id);
	if (bmap_bit_is_set(bmap, amap_group_offset)) {
		amap_table_group_unlock(dest_group);
		vm_pg_free(metadata);
		return;
	}

	bmap_set_bit(bmap, amap_group_offset);
	if (isnew) {
		amap_table_group_unlock(dest_group);
		vm_pg_free(metadata);
		return;
	}

	dest_amap_table = clone_amap_table_get(dest_tdisk, dest_group, group_id, group_offset, src_amap->amap_table->amap_table_id, dest_tdisk->clone_wlist);
	if (unlikely(!dest_amap_table)) {
		amap_table_group_unlock(dest_group);
		vm_pg_free(metadata);
		return;
	}

	memcpy(vm_pg_address(metadata), vm_pg_address(src_amap->metadata), AMAP_SIZE);
	atomic_set_bit_short(AMAP_META_DATA_BUSY, &src_amap->flags);
	amap_get(src_amap);

	amap_table_lock(dest_amap_table);
	block = get_amap_block(dest_amap_table, src_amap->amap_idx);
	debug_check(block);
	dest_amap = dest_amap_table->amap_index[src_amap->amap_idx];
	debug_check(dest_amap);

	wlist_lock(dest_tdisk->clone_wlist);
	dest_amap = amap_new(dest_amap_table, src_amap->amap_id, src_amap->amap_idx, &dest_tdisk->clone_wlist->meta_index_info_list, &error);
	wlist_unlock(dest_tdisk->clone_wlist);
	if (unlikely(!dest_amap)) {
		tdisk_set_clone_error(dest_tdisk);
		amap_table_unlock(dest_amap_table);
		atomic_clear_bit_short(AMAP_META_DATA_BUSY, &src_amap->flags);
		chan_wakeup_nointr(src_amap->amap_wait);
		amap_put(src_amap);
		amap_table_group_unlock(dest_group);
		vm_pg_free(metadata);
		return;
	}
	amap_get(dest_amap);
	amap_table_unlock(dest_amap_table);

	clone_data = clone_data_alloc(CLONE_DATA_CLONE);
	clone_data->async = 1;
	clone_data->amap = dest_amap;
	clone_data->src_amap = src_amap;
	clone_data->metadata = metadata;
	clone_data_insert(clone_data, &dest_tdisk->clone_list);
	amap_table_group_unlock(dest_group);
	return;
}

void
amap_table_clone_check(struct tdisk *src_tdisk, struct amap_table *src_amap_table)
{
	if (!tdisk_in_cloning(src_tdisk) && !tdisk_in_mirroring(src_tdisk))
		return;

	tdisk_clone_lock(src_tdisk);
	if (tdisk_in_cloning(src_tdisk)) {
		__amap_table_clone_check(src_tdisk->dest_tdisk, src_amap_table);
	}
	else if (!tdisk_in_sync(src_tdisk)) {
		__amap_table_mirror_check(src_tdisk, src_amap_table);
	}
	tdisk_clone_unlock(src_tdisk);
}

void
amap_clone_check(struct tdisk *src_tdisk, struct amap *src_amap, int isnew)
{
	if (!tdisk_in_cloning(src_tdisk) && !tdisk_in_mirroring(src_tdisk))
		return;

	tdisk_clone_lock(src_tdisk);
	if (tdisk_in_cloning(src_tdisk))
		__amap_clone_check(src_tdisk->dest_tdisk, src_amap, isnew);
	else if (!tdisk_in_sync(src_tdisk))
		__amap_mirror_check(src_tdisk, src_amap, isnew);
	tdisk_clone_unlock(src_tdisk);
}

static void
amap_table_index_write(struct amap_table *amap_table)
{
	struct tdisk *tdisk = amap_table->tdisk;
	int table_index_id = amap_table->amap_table_id >> INDEX_TABLE_GROUP_SHIFT;
	int table_index_offset = amap_table->amap_table_id & INDEX_TABLE_GROUP_MASK;

	table_index_write(tdisk, &tdisk->table_index[table_index_id], table_index_id, table_index_offset, amap_table);
}

static void
amap_table_sync_metadata(struct tdisk *dest_tdisk, struct amap_table *amap_table, struct iowaiter *iowaiter)
{
	struct index_sync_list index_sync_list;
	struct write_list *wlist = dest_tdisk->clone_wlist;
	struct index_info_list index_info_list;

	SLIST_INIT(&index_sync_list);
	TAILQ_INIT(&index_info_list);

	wlist_lock(wlist);
	TAILQ_CONCAT(&index_info_list, &wlist->index_info_list, i_list);
	TAILQ_CONCAT(&index_info_list, &wlist->meta_index_info_list, i_list);
	wlist_unlock(wlist);

	index_list_insert(&index_sync_list, &index_info_list);

	index_sync_start_io(&index_sync_list, 1);
	index_sync_wait(&index_sync_list);
	index_info_wait(&index_info_list);

	amap_table_end_writes(amap_table);
	amap_table_end_wait(amap_table, iowaiter);
	free_iowaiter(iowaiter);
	amap_table_index_write(amap_table);
	atomic_clear_bit_short(ATABLE_META_DATA_NEW, &amap_table->flags);
}

static int
amap_sync_metadata(struct amap *amap)
{
	struct iowaiter iowaiter;

	bzero(&iowaiter, sizeof(iowaiter));
	amap_start_writes(amap, &iowaiter);
	amap_end_writes(amap, 0);
	amap_end_wait(amap, &iowaiter);
	atomic_clear_bit_short(AMAP_META_DATA_NEW, &amap->flags);
	chan_wakeup(amap->amap_wait);
	free_iowaiter(&iowaiter);
	if (atomic_test_bit_short(AMAP_META_DATA_ERROR, &amap->flags))
		return -1;
	else
		return 0;
}

static void
pglist_hash_insert(struct tdisk *tdisk, struct index_info_list *index_info_list, struct pgdata **pglist, int pglist_cnt)
{
	struct pgdata *pgdata;
	int i;

	for (i = 0; i < pglist_cnt; i++) {
		pgdata = pglist[i];

		if (atomic_test_bit(DDBLOCK_ZERO_BLOCK, &pgdata->flags))
			continue;

		if (atomic_test_bit(DDBLOCK_ENTRY_FOUND_DUPLICATE, &pgdata->flags))
			continue;

		ddtable_hash_insert(tdisk->group, pgdata, index_info_list, NULL);
	}
}

static int
amap_clone(struct clone_data *clone_data)
{
	struct amap *amap = clone_data->amap;
	struct amap_table *amap_table = amap->amap_table;
	struct tdisk *tdisk = amap_table->tdisk;
	pagestruct_t *metadata = clone_data->metadata;
	struct write_list *wlist = tdisk->clone_wlist;
	struct pgdata_wlist pending_list;
	struct pgdata_wlist dedupe_pending_list;
	uint64_t block;
	struct index_info_list index_info_list;
	struct index_sync_list index_sync_list;
	struct pgdata_wlist read_list;
	struct bdevint *bint, *prev_bint = NULL;
	struct tcache *tcache;
	struct pgdata *pgdata, **pglist;
	int pglist_cnt, has_writes = 0;
	int i, retval;
	struct pgdata_wlist alloc_list;
	struct lba_write *lba_alloc;
	uint32_t size = 0;
	int enable_deduplication = tdisk->enable_deduplication;
	int verify_count = 0;

	SLIST_INIT(&index_sync_list);
	TAILQ_INIT(&index_info_list);
	STAILQ_INIT(&read_list);
	STAILQ_INIT(&alloc_list);
	STAILQ_INIT(&pending_list);
	STAILQ_INIT(&dedupe_pending_list);

	pglist_cnt = ENTRIES_PER_AMAP;
	pglist = pgdata_allocate_nopage(pglist_cnt, Q_NOWAIT);
	if (unlikely(!pglist)) {
		tdisk_set_clone_error(tdisk);
		return -1;
	}

	lba_alloc = tdisk_add_alloc_lba_write((amap->amap_id * LBAS_PER_AMAP), tdisk->lba_write_wait, &tdisk->lba_write_list, 0);
	tcache = tcache_alloc(pglist_cnt);

	for (i = 0; i < pglist_cnt; i++) {
		pgdata = pglist[i];
		block = amap_metadata_get_block(metadata, i); 
		if (!block) {
			atomic_set_bit(DDBLOCK_ZERO_BLOCK, &pgdata->flags);
			continue;
		}

		pgdata->amap_block = block;
		retval = tdisk_add_block_ref(tdisk->group, block, &index_info_list);
		if (retval == 0) {
			atomic_set_bit(DDBLOCK_ENTRY_FOUND_DUPLICATE, &pgdata->flags);
			atomic_set_bit(DDBLOCK_ENTRY_DONE_ALLOC, &pgdata->flags);
			atomic_set_bit(PGDATA_SKIP_DDCHECK, &pgdata->flags);
			atomic_set_bit(PGDATA_SKIP_UNCOMP, &pgdata->flags);
			amap_entry_set_block(amap, i, BLOCK_BLOCKNR(pgdata->amap_block), BLOCK_BID(pgdata->amap_block), lba_block_bits(pgdata->amap_block));
			continue;
		}

		has_writes = 1;

		if (!prev_bint || (prev_bint->bid != BLOCK_BID(block))) {
			bint = bdev_find(BLOCK_BID(block));
			if (unlikely(!bint)) {
				debug_warn("Cannot locate bint at bid %u\n", BLOCK_BID(block));
				goto err;
			}
			prev_bint = bint;
		}
		else {
			bint = prev_bint;
		}

		if (pgdata_in_read_list(tdisk, pgdata, &read_list, 0))
			continue;

		if (lba_block_size(block) == LBA_SIZE && rcache_locate(pgdata, 0))
			continue;

		retval = pgdata_alloc_page(pgdata, 0);
		if (unlikely(retval != 0)) {
			debug_warn("allocating for pgdata page failed\n");
			goto err;
		}

		retval = tcache_add_page(tcache, pgdata->page, BLOCK_BLOCKNR(block), bint, lba_block_size(block), QS_IO_READ);
		if (retval != 0)
			goto err;
	}

	if (!has_writes) {
		goto sync_index;
	}

	if (atomic_read(&tcache->bio_remain)) {
		tcache_entry_rw(tcache, QS_IO_READ);
		wait_for_done(tcache->completion);
	}

	if (atomic_test_bit_short(TCACHE_IO_ERROR, &tcache->flags))
		goto err;

	tcache_read_comp(tcache);

	tcache_put(tcache);

	if (!enable_deduplication)
		goto skip_dedupe;

	chan_lock(devq_write_wait);
	for (i = 0; i < pglist_cnt; i++) {
		pgdata = pglist[i];

		if (atomic_test_bit(DDBLOCK_ZERO_BLOCK, &pgdata->flags)) {
			wait_complete_all(pgdata->completion);
			continue;
		}

		if (atomic_test_bit(DDBLOCK_ENTRY_FOUND_DUPLICATE, &pgdata->flags)) {
			wait_complete_all(pgdata->completion);
			continue;
		}

		pgdata->flags = 0;
		STAILQ_INSERT_TAIL(&pending_write_queue, pgdata, w_list);
	}
	chan_wakeup_unlocked(devq_write_wait);
	chan_unlock(devq_write_wait);
	wait_for_pgdata(pglist, pglist_cnt);

	for (i = 0; i < pglist_cnt; i++) {
		pgdata = pglist[i];

		if (atomic_test_bit(DDBLOCK_ZERO_BLOCK, &pgdata->flags))
			continue;

		if (atomic_test_bit(DDBLOCK_ENTRY_FOUND_DUPLICATE, &pgdata->flags))
			continue;

		gdevq_dedupe_insert(tdisk, pgdata, wlist);
		STAILQ_INSERT_TAIL(&dedupe_pending_list, pgdata, w_list);
	}

	while ((pgdata = STAILQ_FIRST(&dedupe_pending_list)) != NULL) {
		STAILQ_REMOVE_HEAD(&dedupe_pending_list, w_list);
		wait_for_done(pgdata->completion);
		if (atomic_test_bit(DDBLOCK_ENTRY_INDEX_LOADING, &pgdata->flags)) {
			STAILQ_INSERT_TAIL(&pending_list, pgdata, w_list);
			TDISK_STATS_ADD(tdisk, inline_waits, 1);
		}
	}

	if (!STAILQ_EMPTY(&pending_list)) {
		check_pending_ddblocks(tdisk, &pending_list, &wlist->dedupe_list, wlist, 0, &verify_count);
	}

skip_dedupe:
	for (i = 0; i < pglist_cnt; i++) {
		pgdata = pglist[i];

		if (atomic_test_bit(DDBLOCK_ZERO_BLOCK, &pgdata->flags))
			continue;

		if (atomic_test_bit(DDBLOCK_ENTRY_FOUND_DUPLICATE, &pgdata->flags))
			continue;

		block = amap_metadata_get_block(metadata, i);
		debug_check(!block);
		pgdata->amap_block = 0;
		pgdata->write_size = lba_block_size(block);
		size += pgdata->write_size;
		STAILQ_INSERT_TAIL(&alloc_list, pgdata, w_list);
	}

	tcache = tcache_alloc(pglist_cnt);
	retval = pgdata_alloc_blocks(tdisk, NULL, &alloc_list, size, &index_info_list, lba_alloc);
	tdisk_update_alloc_lba_write(lba_alloc, tdisk->lba_write_wait, LBA_WRITE_DONE_ALLOC);

	if (unlikely(retval != 0))
		goto err;

	for (i = 0; i < pglist_cnt; i++) {
		pgdata = pglist[i];

		if (atomic_test_bit(DDBLOCK_ZERO_BLOCK, &pgdata->flags))
			continue;

		if (atomic_test_bit(DDBLOCK_ENTRY_FOUND_DUPLICATE, &pgdata->flags)) {
			amap_entry_set_block(amap, i, BLOCK_BLOCKNR(pgdata->amap_block), BLOCK_BID(pgdata->amap_block), lba_block_bits(pgdata->amap_block));
			continue;
		}

		amap_entry_set_block(amap, i, BLOCK_BLOCKNR(pgdata->amap_block), BLOCK_BID(pgdata->amap_block), lba_block_bits(pgdata->amap_block));
		if (!prev_bint || (prev_bint->bid != BLOCK_BID(pgdata->amap_block))) {
			bint = bdev_find(BLOCK_BID(pgdata->amap_block));
			if (unlikely(!bint)) {
				debug_warn("Cannot locate bint at bid %u amap block %llu\n", BLOCK_BID(pgdata->amap_block), (unsigned long long)pgdata->amap_block);
				goto err;
			}
			prev_bint = bint;
		}
		else {
			bint = prev_bint;
		}

		retval = tcache_add_page(tcache, pgdata->page, BLOCK_BLOCKNR(pgdata->amap_block), bint, lba_block_size(pgdata->amap_block), QS_IO_WRITE);
		if (retval != 0)
			goto err;
	}

	if (atomic_read(&tcache->bio_remain)) {
		tdisk_check_alloc_lba_write(lba_alloc, tdisk->lba_write_wait, &tdisk->lba_write_list, LBA_WRITE_DONE_IO);
		tcache_entry_rw(tcache, QS_IO_WRITE);
		tdisk_update_alloc_lba_write(lba_alloc, tdisk->lba_write_wait, LBA_WRITE_DONE_IO);
		wait_for_done(tcache->completion);
	}

	if (atomic_test_bit_short(TCACHE_IO_ERROR, &tcache->flags))
		goto err;

sync_index:
	tcache_put(tcache);
	tdisk_remove_alloc_lba_write(&lba_alloc, tdisk->lba_write_wait, &tdisk->lba_write_list);
	if (enable_deduplication && has_writes)
		pglist_hash_insert(tdisk, &index_info_list, pglist, pglist_cnt);
	pglist_free(pglist, pglist_cnt);
	wlist_lock(wlist);
	TAILQ_CONCAT(&wlist->index_info_list, &index_info_list, i_list);
	wlist_unlock(wlist);
	retval = amap_sync_metadata(amap);
	if (unlikely(retval != 0)) {
		tdisk_set_clone_error(tdisk);
		return -1;
	}
	return 0;
err:
	tdisk_remove_alloc_lba_write(&lba_alloc, tdisk->lba_write_wait, &tdisk->lba_write_list);

	index_list_insert(&index_sync_list, &index_info_list);
	for (i = 0; i < pglist_cnt; i++) {
		pgdata = pglist[i];

		if (atomic_test_bit(DDBLOCK_ZERO_BLOCK, &pgdata->flags))
			continue;
		if (!pgdata->amap_block)
			continue;
		if (!atomic_test_bit(DDBLOCK_ENTRY_DONE_ALLOC, &pgdata->flags))
			continue;
		process_delete_block(bdev_group_ddtable(tdisk->group), pgdata->amap_block, &index_info_list, &index_sync_list, NULL, TYPE_DATA_BLOCK);
	}
	index_sync_start_io(&index_sync_list, 1);
	index_sync_wait(&index_sync_list);
	index_info_wait(&index_info_list);

	tcache_put(tcache);
	tdisk_set_clone_error(tdisk);
	pglist_free(pglist, pglist_cnt);
	return -1;
}

struct clone_data *
clone_list_next(struct tdisk *tdisk)
{
	struct clone_data *ret = NULL, *iter;

	tdisk_lock(tdisk);
	STAILQ_FOREACH(iter, &tdisk->clone_list, c_list) {
		if (iter->queued)
			continue;
		iter->queued = 1;
		ret = iter;
		break;
	}
	if (!ret)
		atomic_clear_bit(CLONE_THREAD_START, &tdisk->clone_flags);
	tdisk_unlock(tdisk);
	return ret;
}

void
amap_clone_data(struct clone_data *clone_data)
{
	struct iowaiter iowaiter;
	struct amap *amap;
	struct amap_table *amap_table;
	uint64_t block;
	int retval;

 	amap = clone_data->amap;
	amap_table = amap->amap_table;

	bzero(&iowaiter, sizeof(iowaiter));
	amap_table_lock(amap_table);
	amap_table_start_writes(amap_table, &iowaiter);
	amap_table_unlock(amap_table);
	retval = amap_clone(clone_data);

	if (atomic_test_bit_short(AMAP_META_DATA_BUSY, &clone_data->src_amap->flags)) {
		atomic_clear_bit_short(AMAP_META_DATA_BUSY, &clone_data->src_amap->flags);
		chan_wakeup_nointr(clone_data->src_amap->amap_wait);
	}
	amap_table_lock(amap_table);
	block = get_amap_block(amap_table, amap->amap_idx);
	debug_check(block);
	amap_table_write_barrier(amap_table);
	if (retval == 0)
		set_amap_block(amap_table, amap->amap_idx, amap->amap_block);
	amap_table_unlock(amap_table);
	amap_table_sync_metadata(amap_table->tdisk, amap_table, &iowaiter);

	wait_complete_all(clone_data->completion);
}

int
clone_list_wait(struct tdisk *tdisk)
{
	struct clone_data *clone_data, *next;
	int error = 0;

	chan_lock(tdevq_wait);
	clone_data = STAILQ_FIRST(&tdisk->clone_list);
	chan_unlock(tdevq_wait);

	while (clone_data) {
		wait_for_done(clone_data->completion);
		if (clone_data->error)
			error = -1;

		chan_lock(tdevq_wait);
		STAILQ_REMOVE_HEAD(&tdisk->clone_list, q_list);
		next = STAILQ_FIRST(&tdisk->clone_list);
		chan_unlock(tdevq_wait);

		clone_data_free(clone_data);
		clone_data = next;
	}
	return error;
}

static int
amap_table_clone(struct tdisk *dest_tdisk, struct amap_table *dest_amap_table, struct amap_table *src_amap_table, struct write_list *wlist, uint32_t group_id)
{
	struct amap *dest_amap;
	struct amap *src_amap;
	uint64_t block;
	struct clone_data *clone_data;
	struct amap_table_group *dest_group;
	struct amap_group_bitmap *bmap = NULL;
	uint32_t amap_id, bmap_group_offset;
	pagestruct_t *metadata;
	uint32_t amap_max, todo;
	int i, set;
	int done = 0, error;

	dest_group = dest_tdisk->amap_table_group[group_id];
	amap_id = src_amap_table->amap_table_id * AMAPS_PER_AMAP_TABLE;
	amap_max = tdisk_max_amaps(dest_tdisk);
	todo = min_t(uint32_t, AMAPS_PER_AMAP_TABLE, amap_max - amap_id);

	for (i = 0; i < todo; i++, amap_id++) {
		metadata = vm_pg_alloc(0);
		if (unlikely(!metadata)) {
			tdisk_set_clone_error(dest_tdisk);
			return -1;
		}

		amap_table_lock(src_amap_table);
		block = get_amap_block(src_amap_table, i);
		if (!block)  {
			amap_table_unlock(src_amap_table);
			tdisk_set_clone_amap_id(dest_tdisk, amap_id);
			vm_pg_free(metadata);
			continue;
		}

		src_amap = src_amap_table->amap_index[i];
		if (!src_amap) {
			src_amap = amap_load_async(src_amap_table, amap_id, i, block);
			if (unlikely(!src_amap)) {
				amap_table_unlock(src_amap_table);
				tdisk_set_clone_error(dest_tdisk);
				vm_pg_free(metadata);
				return -1;
			}
		}

		amap_get(src_amap);
		amap_table_unlock(src_amap_table);

		wait_on_chan_check(src_amap->amap_wait, !atomic_test_bit_short(AMAP_META_DATA_READ_DIRTY, &src_amap->flags));
		if (atomic_test_bit_short(AMAP_META_DATA_ERROR, &src_amap->flags)) {
			tdisk_set_clone_error(dest_tdisk);
			amap_put(src_amap);
			vm_pg_free(metadata);
			return -1;
		}

		bmap_group_offset = amap_bitmap_group_offset(amap_id);
		amap_table_group_lock(dest_group);
		if (!bmap || bmap_group_offset != bmap->group_offset) {
			bmap = amap_group_bmap_locate(dest_tdisk, group_id, bmap_group_offset, &error);
			if (unlikely(!bmap)) {
				tdisk_set_clone_error(dest_tdisk);
				amap_table_group_unlock(dest_group);
				amap_put(src_amap);
				debug_warn("Cannot get bmap for %i group offset %u\n", group_id, bmap_group_offset);
				vm_pg_free(metadata);
				return -1;
			}
		}

		set = bmap_bit_is_set(bmap, amap_to_bitmap_offset(amap_id));
		if (set) {
			tdisk_set_clone_amap_id(dest_tdisk, amap_id);
			amap_table_group_unlock(dest_group);
			amap_put(src_amap);
			vm_pg_free(metadata);
			continue;
		}

		memcpy(vm_pg_address(metadata), vm_pg_address(src_amap->metadata), AMAP_SIZE); 
		atomic_set_bit_short(AMAP_META_DATA_BUSY, &src_amap->flags);
		bmap_set_bit(bmap, amap_to_bitmap_offset(amap_id));
		amap_table_group_unlock(dest_group);

		amap_table_lock(dest_amap_table);
		block = get_amap_block(dest_amap_table, i);
		debug_check(block);
		dest_amap = dest_amap_table->amap_index[i];
		debug_check(dest_amap);

		dest_amap = amap_new(dest_amap_table, amap_id, i, &wlist->meta_index_info_list, &error);
		if (unlikely(!dest_amap)) {
			tdisk_set_clone_error(dest_tdisk);
			amap_table_unlock(dest_amap_table);
			atomic_clear_bit_short(AMAP_META_DATA_BUSY, &src_amap->flags);
			chan_wakeup_nointr(src_amap->amap_wait);
			amap_put(src_amap);
			vm_pg_free(metadata);
			return -1;
		}
		amap_get(dest_amap);

		amap_table_get(dest_amap_table);
		clone_data = clone_data_alloc(CLONE_DATA_CLONE);
		clone_data->amap = dest_amap;
		clone_data->src_amap = src_amap;
		clone_data->metadata = metadata;
		clone_data_insert(clone_data, &dest_tdisk->clone_list);
		amap_table_unlock(dest_amap_table);

		done++;
		if (done == MAX_AMAP_CLONE_THREADS) {
			clone_list_wait(dest_tdisk);
			done = 0;
		}
		tdisk_set_clone_amap_id(dest_tdisk, amap_id);
	}

	clone_list_wait(dest_tdisk);
	return tdisk_clone_error(dest_tdisk);
}

static int
amap_table_group_clone(struct tdisk *dest_tdisk, struct tdisk *src_tdisk, struct amap_table_group *dest_group, struct amap_table_group *src_group, uint32_t group_id)
{
	struct amap_table *src_amap_table, *dest_amap_table;
	struct amap_table_index *src_table_index;
	uint64_t block;
	uint32_t atable_id;
	struct write_list *wlist = dest_tdisk->clone_wlist;
	struct amap_group_bitmap *bmap;
	int i, retval, error;

	atable_id = group_id << AMAP_TABLE_GROUP_SHIFT;
	src_table_index = &src_tdisk->table_index[group_id];
	debug_check(dest_group->amap_table_max != src_group->amap_table_max);

	amap_table_group_lock(dest_group);
	bmap = amap_group_table_bmap_locate(dest_tdisk, group_id, &error);
	amap_table_group_unlock(dest_group);
	if (unlikely(!bmap))
		return -1;

	for (i = 0; i < src_group->amap_table_max; i++, atable_id++) {
		amap_table_group_lock(src_group);
		block = get_amap_table_block(src_table_index, i);
		src_amap_table = src_group->amap_table[i];
		if (!block && !src_amap_table) {
			amap_table_group_unlock(src_group);
			continue;
		}

		if (!src_amap_table) {
			src_amap_table = amap_table_load_async(src_tdisk, block, src_group, group_id, atable_id);
			if (unlikely(!src_amap_table)) {
				amap_table_group_unlock(src_group);
				return -1;
			}
		}

		amap_table_get(src_amap_table);
		amap_table_group_unlock(src_group);

		amap_table_group_lock(dest_group);

		if (bmap_bit_is_set(bmap, i)) {
			amap_table_group_unlock(dest_group);
			amap_table_put(src_amap_table);
			continue;
		}

		dest_amap_table = clone_amap_table_get(dest_tdisk, dest_group, group_id, i, atable_id, wlist);
		if (unlikely(!dest_amap_table)) {
			amap_table_group_unlock(dest_group);
			amap_table_put(src_amap_table);
			return -1;
		}

		amap_table_group_unlock(dest_group);

		wait_on_chan_check(src_amap_table->amap_table_wait, !atomic_test_bit_short(ATABLE_META_DATA_READ_DIRTY, &src_amap_table->flags));
		wait_on_chan_check(dest_amap_table->amap_table_wait, !atomic_test_bit_short(ATABLE_META_DATA_READ_DIRTY, &dest_amap_table->flags));
		retval = amap_table_clone(dest_tdisk, dest_amap_table, src_amap_table, wlist, group_id);
		amap_table_group_lock(dest_group);
		amap_table_put(dest_amap_table);
		if (atomic_read(&dest_amap_table->refs) == 1)
			amap_table_remove(dest_group, dest_amap_table);
		amap_table_group_unlock(dest_group);
		amap_table_put(src_amap_table);
		if (unlikely(retval != 0)) {
			clone_list_wait(dest_tdisk);
			return -1;
		}
	}
	return 0;
}

void 
tdisk_clone_setup(struct tdisk *tdisk, struct tdisk *src_tdisk, int in_sync, struct clone_info *clone_info)
{
	int i;
	struct group_bmap_list *bmap_list;

	tdisk->clone_wlist = write_list_alloc(tdisk);
	tdisk->clone_info = clone_info;
	tdisk->group_table_bmaps = zalloc(tdisk->amap_table_group_max * sizeof( struct amap_group_bitmap *), M_CLONE_AMAP_TABLE, Q_WAITOK);
	tdisk->group_bmaps = zalloc(tdisk->amap_table_group_max * sizeof(*bmap_list), M_CLONE_AMAP, Q_WAITOK);
	for (i = 0; i < tdisk->amap_table_group_max; i++) {
		bmap_list = &tdisk->group_bmaps[i];
		STAILQ_INIT(bmap_list);
	}

	if (src_tdisk) {
		src_tdisk->dest_tdisk = tdisk;
		tdisk_set_in_cloning(src_tdisk);
		tdisk_set_in_cloning(tdisk);
	}
	else {
		tdisk_set_in_mirroring(tdisk);
		if (in_sync)
			tdisk_set_in_sync(tdisk);
	}
}

void
tdisk_clone_cleanup(struct tdisk *tdisk, struct tdisk *src_tdisk)
{
	int i;

	if (src_tdisk) {
		src_tdisk->dest_tdisk = NULL;
		tdisk_clear_in_cloning(src_tdisk);
	}

	for (i = 0; i < tdisk->amap_table_group_max; i++) {
		amap_group_bmaps_free(tdisk, i);
	}

	if (tdisk->group_table_bmaps) {
		free(tdisk->group_table_bmaps, M_CLONE_AMAP_TABLE);
		tdisk->group_table_bmaps = NULL;
	}

	if (tdisk->group_bmaps) {
		free(tdisk->group_bmaps, M_CLONE_AMAP);
		tdisk->group_bmaps = NULL;
	}

	if (tdisk->clone_wlist) {
		write_list_free(tdisk->clone_wlist);
		tdisk->clone_wlist = NULL;
	}

	tdisk->clone_info = NULL;

	tdisk_clear_in_cloning(tdisk);
	tdisk_clear_in_mirroring(tdisk);
	tdisk_clear_in_sync(tdisk);
	tdisk_reset_clone_amap_id(tdisk, 0);
}

#ifdef FREEBSD 
static void tdisk_clone_thr(void *data)
#else
static int tdisk_clone_thr(void *data)
#endif
{
	struct clone_info *clone_info = data;
	struct tdisk *tdisk = clone_info->dest_tdisk;
	struct tdisk *src_tdisk = clone_info->src_tdisk;
	int i;
	int retval = 0;
	struct amap_table_group *src_group, *dest_group;
	int status;
#ifdef ENABLE_STATS
	uint32_t start_ticks;
#endif

	TDISK_TSTART(start_ticks);
	tdisk_clone_lock(src_tdisk);
	tdisk_clone_setup(tdisk, src_tdisk, 0, clone_info);
	tdisk_clone_unlock(src_tdisk);
	debug_check(tdisk->end_lba != src_tdisk->end_lba);
	debug_check(tdisk->amap_table_group_max != src_tdisk->amap_table_group_max);
	for (i = 0; i < tdisk->amap_table_group_max; i++) {
		dest_group = tdisk->amap_table_group[i];
		debug_check(!dest_group);

		src_group = src_tdisk->amap_table_group[i];
		debug_check(!src_group);

		retval = amap_table_group_clone(tdisk, src_tdisk, dest_group, src_group, i);
		if (unlikely(retval != 0)) {
			tdisk_set_clone_error(tdisk);
			break;
		}

		tdisk_clone_lock(tdisk);
		amap_group_bmaps_free(tdisk, i);
		tdisk_clone_unlock(tdisk);
	}

	atomic_set_bit(VDISK_SYNC_START, &tdisk->flags);
	tdisk_sync(tdisk, 0);
	TDISK_TEND(tdisk, clone_ticks, start_ticks);
	debug_info("clone_ticks: %u\n", tdisk->clone_ticks);
	status = tdisk_clone_error(tdisk) ? 1 : 0;
	tdisk_clone_lock(src_tdisk);
	tdisk_clone_cleanup(tdisk, src_tdisk);
	tdisk_clone_unlock(src_tdisk);
	tdisk_put(src_tdisk);

	sx_xlock(clone_info_lock);
	STAILQ_REMOVE(&clone_info_list, clone_info, clone_info, i_list);
	sx_xunlock(clone_info_lock);
	node_usr_send_job_completed(clone_info->job_id, status);
	free(clone_info, M_CLONE_INFO);
	if (status == 0) {
		cbs_new_device(tdisk, 1);
	}
	tdisk_start_resize_thread(tdisk);
	tdisk_put(tdisk);

#ifdef FREEBSD 
	kproc_exit(0);
#else
	return 0;
#endif
}

int
vdisk_clone_cancel(struct clone_config *config)
{
	struct clone_info *iter;
	struct tdisk *dest_tdisk;

	sx_xlock(clone_info_lock);
	STAILQ_FOREACH(iter, &clone_info_list, i_list) {
		if (iter->op != OP_CLONE)
			continue;

		dest_tdisk = iter->dest_tdisk;
		if (dest_tdisk->target_id != config->dest_target_id)
			continue;
		tdisk_set_clone_error(dest_tdisk);
		break;
	}
	sx_xunlock(clone_info_lock);
	return 0;
}

int
vdisk_clone_status(struct clone_config *config)
{
	struct clone_info *iter;
	struct tdisk *dest_tdisk;
	uint32_t amap_max;

	sx_xlock(clone_info_lock);
	STAILQ_FOREACH(iter, &clone_info_list, i_list) {
		if (iter->op != OP_CLONE)
			continue;

		dest_tdisk = iter->dest_tdisk;
		if (dest_tdisk->target_id != config->dest_target_id)
			continue;
		if (tdisk_clone_error(dest_tdisk)) {
			config->status = CLONE_STATUS_ERROR;
		}
		else {
			config->status = CLONE_STATUS_INPROGRESS;
			amap_max = tdisk_max_amaps(dest_tdisk);
			config->progress = (tdisk_get_clone_amap_id(dest_tdisk) * 100) / amap_max; 
		}
		sx_xunlock(clone_info_lock);
		return 0;
	}
	sx_xunlock(clone_info_lock);

	dest_tdisk = tdisk_locate(config->dest_target_id);

	if (unlikely(!dest_tdisk))
		return -1;

	if (tdisk_clone_error(dest_tdisk))
		config->status = CLONE_STATUS_ERROR;
	else
		config->status = CLONE_STATUS_SUCCESSFUL;
	tdisk_put(dest_tdisk);
	return 0;
}

int
vdisk_clone(struct clone_config *config)
{
	struct tdisk *dest_tdisk;
	struct tdisk *src_tdisk;
	struct clone_info *clone_info;
	int retval;

	if (unlikely(config->src_target_id >= TL_MAX_DEVICES))
		return -1;

	if (unlikely(config->dest_target_id >= TL_MAX_DEVICES))
		return -1;

	dest_tdisk = tdisk_locate(config->dest_target_id);
	if (unlikely(!dest_tdisk))
		return -1;

	if (tdisk_in_cloning(dest_tdisk) || tdisk_in_mirroring(dest_tdisk)) {
		debug_warn("dest vdisk %s busy, possibly another replication/cloning in progress\n", tdisk_name(dest_tdisk));
		tdisk_put(dest_tdisk);
		return -1;
	}

	src_tdisk = tdisk_locate(config->src_target_id);
	if (unlikely(!src_tdisk)) {
		tdisk_put(dest_tdisk);
		return -1;
	}

	if (tdisk_in_cloning(src_tdisk) || tdisk_in_mirroring(src_tdisk)) {
		debug_warn("source vdisk %s busy, possibly another replication/cloning in progress\n", tdisk_name(src_tdisk));
		tdisk_put(dest_tdisk);
		tdisk_put(src_tdisk);
		return -1;
	}

	tdisk_stop_delete_thread(dest_tdisk);

	clone_info = zalloc(sizeof(*clone_info), M_CLONE_INFO, Q_WAITOK);
	clone_info->dest_tdisk = dest_tdisk;
	clone_info->src_tdisk = src_tdisk;
	clone_info->op = OP_CLONE;
	clone_info->job_id = config->job_id;

	sx_xlock(clone_info_lock);
	STAILQ_INSERT_TAIL(&clone_info_list, clone_info, i_list);
	retval = kernel_thread_create(tdisk_clone_thr, clone_info, clone_info->task, "clonethr");
	if (unlikely(retval != 0)) {
		STAILQ_REMOVE(&clone_info_list, clone_info, clone_info, i_list);
		tdisk_put(src_tdisk);
		tdisk_put(dest_tdisk);
		free(clone_info, M_CLONE_INFO);
	}
	sx_xunlock(clone_info_lock);
	return retval;
}

void
clone_info_list_complete(void)
{
	struct clone_info *clone_info;

	sx_xlock(clone_info_lock);
	STAILQ_FOREACH(clone_info, &clone_info_list, i_list) {
		if (clone_info->op == OP_CLONE)
			tdisk_set_clone_error(clone_info->dest_tdisk);
		else
			tdisk_set_mirror_error(clone_info->src_tdisk);
	}
	sx_xunlock(clone_info_lock);

	while (!STAILQ_EMPTY(&clone_info_list))
		pause("clone info psg", 2000);
}

