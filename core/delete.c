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
#include "tcache.h"
#include "rcache.h"
#include "cluster.h"
#include "vdevdefs.h"
#include "ddthread.h"
#include "bdevgroup.h"
#include "qs_lib.h"

#define MAX_AMAP_DELETE_THREADS		51

static void
merge_wlist_indexes(struct tdisk *tdisk, struct index_info_list *index_info_list)
{
	struct write_list *wlist = tdisk->clone_wlist;

	__wlist_lock(wlist);
	TAILQ_CONCAT(&wlist->index_info_list, index_info_list, i_list);
	__wlist_unlock(wlist);
}


static void 
amap_delete(struct clone_data *clone_data)
{
	int i;
	uint64_t block;
	struct amap *amap = clone_data->amap;
	struct tdisk *tdisk = amap->amap_table->tdisk;
	pagestruct_t *metadata;
	int empty = 1;
	struct index_info_list index_info_list;
	struct bdevint *bint;
	struct tpriv priv = { 0 };
#ifdef ENABLE_STATS
	uint32_t start_ticks;
#endif

	debug_info("amap id %u\n", amap->amap_id);
	for (i = 0; i < ENTRIES_PER_AMAP; i++) {
		block = amap_entry_get_block(amap, i); 
		if (!block)
			continue;
		empty = 0;
	}

	if (empty)
		return;

	TAILQ_INIT(&index_info_list);
	metadata = amap->metadata;
	amap->metadata = vm_pg_alloc(VM_ALLOC_ZERO);
	if (unlikely(!amap->metadata)) {
		amap->metadata = metadata;
		clone_data->error = 1;
		return;
	}

	TDISK_TSTART(start_ticks);
	atomic_set_bit_short(AMAP_META_IO_PENDING, &amap->flags);
	bint = amap_bint(amap);
	bdev_marker(bint->b_dev, &priv);
	amap_io(amap, 0, QS_IO_WRITE);
	bdev_start(bint->b_dev, &priv);
	wait_on_chan(amap->amap_wait, !atomic_test_bit_short(AMAP_META_DATA_DIRTY, &amap->flags));
	TDISK_TEND(tdisk, amap_delete_iowait_ticks, start_ticks);

	if (atomic_test_bit_short(AMAP_META_DATA_ERROR, &amap->flags)) {
		vm_pg_free(amap->metadata);
		amap->metadata = metadata;
		clone_data->error = 1;
		return;
	}

	for (i = 0; i < ENTRIES_PER_AMAP; i++) {
		block = amap_metadata_get_block(metadata, i); 
		if (!block)
			continue;

		TDISK_TSTART(start_ticks);
		debug_info("delete block %llu at i %d\n", (unsigned long long)block, i);
		process_delete_block(bdev_group_ddtable(tdisk->group), block, &index_info_list, NULL, NULL, TYPE_DATA_BLOCK);
		TDISK_TEND(tdisk, process_delete_block_ticks, start_ticks);
	}
	vm_pg_free(metadata);
	merge_wlist_indexes(tdisk, &index_info_list);
}

static void
__sync_wlist_indexes(struct tdisk *tdisk)
{
	struct write_list *wlist = tdisk->clone_wlist;
#ifdef ENABLE_STATS
	uint32_t start_ticks;
#endif

	TDISK_TSTART(start_ticks);
	index_sync_start_io(&wlist->index_sync_list, 1);
	index_sync_wait(&wlist->index_sync_list);
	index_info_wait(&wlist->index_info_list);
	TDISK_TEND(tdisk, sync_wlist_ticks, start_ticks);
}

static void
sync_wlist_indexes(struct tdisk *tdisk)
{
	struct write_list *wlist = tdisk->clone_wlist;

	index_list_insert(&wlist->index_sync_list, &wlist->index_info_list);
	__sync_wlist_indexes(tdisk);
}

void
amap_delete_data(struct clone_data *clone_data)
{
	struct amap *amap = clone_data->amap;
#ifdef ENABLE_STATS
	uint32_t start_ticks;
	struct tdisk *tdisk = amap->amap_table->tdisk;
#endif

	TDISK_TSTART(start_ticks);
	amap_lock(amap);
	amap_delete(clone_data);
	amap_unlock(amap);
	TDISK_TEND(tdisk, amap_delete_ticks, start_ticks);

	wait_complete_all(clone_data->completion);
}

static int
amap_table_delete(struct tdisk *tdisk, struct amap_table *amap_table, uint64_t start_lba)
{
	struct amap *amap;
	struct clone_data *clone_data;
	struct write_list *wlist = tdisk->clone_wlist;
	uint64_t block;
	uint32_t amap_id, amap_max, todo;
	uint32_t start_amap_id;
	uint64_t amap_lba_start;
	int done = 0, i, error;
	pagestruct_t *metadata;
	struct bdevint *bint;
	struct tpriv priv = { 0 };
#ifdef ENABLE_STATS
	uint32_t start_ticks;
#endif

	debug_info("amap table id %u\n", amap_table->amap_table_id);
	start_amap_id = amap_get_id(start_lba);
	amap_lba_start = (start_amap_id * LBAS_PER_AMAP);
	if (amap_lba_start != start_lba)
		start_amap_id++;

	amap_id = amap_table->amap_table_id * AMAPS_PER_AMAP_TABLE;
	amap_max = tdisk_max_amaps(tdisk);
	todo = min_t(uint32_t, AMAPS_PER_AMAP_TABLE, amap_max - amap_id);

	debug_info("amap id %u todo %d start amap id %u\n", amap_id, todo, start_amap_id);
	if ((amap_id + todo) <= start_amap_id)
		return 0;

	for (i = 0; i < todo; i++, amap_id++) {
		if (amap_id < start_amap_id)
			continue;

		block = get_amap_block(amap_table, i);
		if (!block)
			continue;

		amap = amap_table->amap_index[i];
		if (!amap) {
			amap = amap_load_async(amap_table, amap_id, i, block);
			if (unlikely(!amap))
				return -1;
		}
	}

	for (i = 0; i < todo; i++, amap_id++) {
		if (amap_id < start_amap_id)
			continue;

		block = get_amap_block(amap_table, i);
		if (!block)
			continue;

		amap = amap_table->amap_index[i];
		debug_check(!amap);
		wait_on_chan(amap->amap_wait, !atomic_test_bit_short(AMAP_META_DATA_READ_DIRTY, &amap->flags) && !atomic_test_bit_short(AMAP_META_DATA_DIRTY, &amap->flags));
		amap_check_csum(amap);
		if (atomic_test_bit_short(AMAP_META_DATA_ERROR, &amap->flags))
			return -1;

		clone_data = clone_data_alloc(CLONE_DATA_DELETE);
		amap_get(amap);
		amap_table_get(amap_table);
		clone_data->amap = amap;
		clone_data_insert(clone_data, &tdisk->clone_list);
		done++;

		if (done == MAX_AMAP_DELETE_THREADS) {
			error = clone_list_wait(NULL, tdisk);
			sync_wlist_indexes(tdisk);
			done = 0;
			if (error || (atomic_test_bit(VDISK_DELETE_EXIT, &tdisk->flags) && (i < (todo - 1)))) {
				if (error)
					return -1;
				else
					return -2;
			}
		}
	}

	error = clone_list_wait(NULL, tdisk);
	sync_wlist_indexes(tdisk);
	if (error)
		return -1;

	if (start_lba)
		return 0;

	metadata = amap_table->metadata;
	amap_table->metadata = vm_pg_alloc(VM_ALLOC_ZERO);
	if (unlikely(!amap_table->metadata)) {
		amap_table->metadata = metadata;
		return -1;
	}

	TDISK_TSTART(start_ticks);
	atomic_set_bit_short(ATABLE_META_IO_PENDING, &amap_table->flags);
	bint = amap_table_bint(amap_table);
	bdev_marker(bint->b_dev, &priv);
	amap_table_io(amap_table, QS_IO_WRITE);
	bdev_start(bint->b_dev, &priv);
	wait_on_chan(amap_table->amap_table_wait, !atomic_test_bit_short(ATABLE_META_DATA_DIRTY, &amap_table->flags));
	TDISK_TEND(tdisk, amap_table_delete_iowait_ticks, start_ticks);

	if (atomic_test_bit_short(ATABLE_META_DATA_ERROR, &amap_table->flags)) {
		vm_pg_free(amap_table->metadata);
		amap_table->metadata = metadata;
		return -1;
	}

	for (i = 0; i < todo; i++) {
		block = get_amap_block_metadata(metadata, i);
		if (!block)
			continue;
		debug_info("delete amap block %llu at i %d\n", (unsigned long long)block, i);
		process_delete_block(bdev_group_ddtable(tdisk->group), block, &wlist->index_info_list, &wlist->index_sync_list, NULL, TYPE_META_BLOCK);
	}

	__sync_wlist_indexes(tdisk);
	vm_pg_free(metadata);

	return 0;
}
static int
amap_table_group_delete(struct tdisk *tdisk, struct amap_table_group *group, uint32_t group_id, uint64_t start_lba)
{
	struct amap_table *amap_table;
	struct amap_table_index *table_index;
	uint32_t atable_id;
	uint64_t block;
	int i, retval;
	struct write_list *wlist = tdisk->clone_wlist;
	pagestruct_t *metadata;
	uint32_t start_atable_id;
#ifdef ENABLE_STATS
	uint32_t start_ticks;
#endif

	debug_info("group id %u table max %d\n", group_id, group->amap_table_max);
	atable_id = group_id << AMAP_TABLE_GROUP_SHIFT;
	start_atable_id = amap_table_id(start_lba);
	debug_info("atable id %u start atable id %u\n", atable_id, start_atable_id);
	if ((atable_id + group->amap_table_max) <= start_atable_id)
		return 0;

	table_index = &tdisk->table_index[group_id];

	for (i = 0; i < group->amap_table_max; i++, atable_id++) {
		if (atable_id < start_atable_id)
			continue;

		if (atomic_test_bit(VDISK_DELETE_EXIT, &tdisk->flags)) {
			return -2;
		}
		amap_table_group_lock(group);
		block = get_amap_table_block(table_index, i);
		if (!block) {
			amap_table_group_unlock(group);
			continue;
		}

		amap_table = group->amap_table[i];
		if (!amap_table) {
			amap_table = amap_table_load_async(tdisk, block, group, group_id, atable_id);
			if (unlikely(!amap_table)) {
				amap_table_group_unlock(group);
				return -1;
			}
		}

		wait_on_chan(amap_table->amap_table_wait, !atomic_test_bit_short(ATABLE_META_DATA_READ_DIRTY, &amap_table->flags) && !atomic_test_bit_short(ATABLE_META_DATA_DIRTY, &amap_table->flags));
		amap_table_check_csum(amap_table);
		if (atomic_test_bit_short(ATABLE_META_DATA_ERROR, &amap_table->flags)) {
			amap_table_group_unlock(group);
			return -1;
		}
		amap_table_get(amap_table);
		amap_table_group_unlock(group);

		TDISK_TSTART(start_ticks);
		atomic_inc(&write_requests);
		amap_table_lock(amap_table);
		retval = amap_table_delete(tdisk, amap_table, start_lba);
		amap_table_unlock(amap_table);
		atomic_dec(&write_requests);
		TDISK_TEND(tdisk, amap_table_delete_ticks, start_ticks);

		amap_table_group_lock(group);
		amap_table_put(amap_table);
		debug_check(atomic_read(&amap_table->refs) > 1);
		amap_table_remove(group, amap_table);
		amap_table_group_unlock(group);
		

		if (unlikely(retval != 0))
			return retval;
	}

	if (start_lba)
		return 0;

	metadata = table_index->metadata;
	table_index->metadata = vm_pg_alloc(VM_ALLOC_ZERO);
	if (unlikely(!table_index->metadata)) {
		table_index->metadata = metadata;
		return -1;
	}

	retval = qs_lib_bio_lba(table_index->bint, table_index->b_start, table_index->metadata, QS_IO_WRITE, TYPE_TDISK_INDEX);
	if (retval != 0) {
		vm_pg_free(table_index->metadata);
		table_index->metadata = metadata;
		return -1;
	}

	for (i = 0; i < group->amap_table_max; i++, atable_id++) {
		uint64_t *ptr = (uint64_t *)(vm_pg_address(metadata));

		block = ptr[i];
		if (!block)
			continue;
		debug_info("delete amap table block %llu at i %d\n", (unsigned long long)block, i);
		process_delete_block(bdev_group_ddtable(tdisk->group), block, &wlist->index_info_list, &wlist->index_sync_list, NULL, TYPE_META_BLOCK);
	}
	vm_pg_free(metadata);
	__sync_wlist_indexes(tdisk);
	return 0;
}

struct tdisk_delete_info {
	struct tdisk *tdisk;
	uint64_t start_lba;
};

#ifdef FREEBSD 
static void tdisk_delete_thread(void *data)
#else
static int tdisk_delete_thread(void *data)
#endif
{
	struct tdisk_delete_info *delete_info = data;
	struct tdisk *tdisk = delete_info->tdisk;
	struct amap_table_index *table_index;
	struct write_list *wlist;
	struct amap_table_group *group;
	pagestruct_t *metadata;
	uint64_t block;
	int i, retval;
	int error = -1;
	uint32_t target_id = tdisk->target_id;
	uint32_t atable_id, group_id, group_offset;
#ifdef ENABLE_STATS
	uint32_t start_ticks;
#endif

	thread_start();

	wlist = write_list_alloc(tdisk);
	tdisk->clone_wlist = wlist;

	atable_id = amap_table_id(delete_info->start_lba);
	group_id = amap_table_group_id(atable_id, &group_offset);

	debug_info("table group max %d group_id %u atable id %u\n", tdisk->amap_table_group_max, group_id, atable_id);
	for (i = group_id; i < tdisk->amap_table_group_max; i++) {
		group = tdisk->amap_table_group[i];

		TDISK_TSTART(start_ticks);
		retval = amap_table_group_delete(tdisk, group, i, delete_info->start_lba);
		TDISK_TEND(tdisk, amap_table_group_delete_ticks, start_ticks);
		if (unlikely(retval != 0)) {
			if (retval != -2)
				debug_warn("delete of table group at %d failed\n", i);
			goto exit;
		}
		if (atomic_test_bit(VDISK_DELETE_EXIT, &tdisk->flags)) {
			debug_info("tdisk %s delete exit set\n", tdisk_name(tdisk));
			error = -2;
			goto exit;
		}
	}

	if (delete_info->start_lba) {
		atomic_clear_bit(VDISK_IN_RESIZE, &tdisk->flags);
		atomic_set_bit(VDISK_SYNC_START, &tdisk->flags);
		tdisk_sync(tdisk, 0);
		goto exit;
	}

	metadata = tdisk->metadata;
	tdisk->metadata = vm_pg_alloc(VM_ALLOC_ZERO);
	if (unlikely(!tdisk->metadata)) {
		tdisk->metadata = metadata;
		goto exit;
	}

	retval = tdisk_sync(tdisk, 1);
	if (unlikely(retval != 0)) {
		debug_warn("tdisk %s sync failed\n", tdisk_name(tdisk));
		vm_pg_free(tdisk->metadata);
		tdisk->metadata = metadata;
		goto exit;
	}

	debug_info("table index max %d\n", tdisk->table_index_max);
	for (i = 0; i < tdisk->table_index_max; i++) {
		table_index = &tdisk->table_index[i];
		SET_BLOCK(block, table_index->b_start, table_index->bint->bid);
		debug_info("delete table index block %llu at i %d\n", (unsigned long long)block, i);
		process_delete_block(bdev_group_ddtable(tdisk->group), block, &wlist->index_info_list, &wlist->index_sync_list, NULL, TYPE_META_BLOCK);
	}
	__sync_wlist_indexes(tdisk);
	vm_pg_free(metadata);
	error = 0;
	atomic_set_bit(VDISK_DONE_DELETE, &tdisk->flags);
exit:
	write_list_free(wlist);
	tdisk->clone_wlist = NULL;
	debug_info("send deleted for %u error %d\n", target_id, error);
	if (!delete_info->start_lba)
		node_usr_send_vdisk_deleted(target_id, error);

	thread_end();

	free(delete_info, M_QUADSTOR);
	wait_on_chan_interruptible(tdisk->delete_wait, kernel_thread_check(&tdisk->flags, VDISK_DELETE_EXIT));
#ifdef FREEBSD 
	kproc_exit(0);
#else
	return 0;
#endif
}

int
vdisk_delete(struct tdisk *tdisk, uint64_t start_offset)
{
	int retval;
	struct tdisk_delete_info *delete_info;
	uint64_t start_lba;

	start_lba = start_offset >> LBA_SHIFT;
	if (start_offset & LBA_MASK)
		start_lba++;

	delete_info = zalloc(sizeof(*delete_info), M_QUADSTOR, Q_WAITOK);
	delete_info->tdisk = tdisk;
	delete_info->start_lba = start_lba;

	retval = kernel_thread_create(tdisk_delete_thread, delete_info, tdisk->delete_task, "tddlt%u", tdisk->target_id);
	if (unlikely(retval != 0)) {
		free(delete_info, M_QUADSTOR);
		return -1;
	}
	return 0;
}

