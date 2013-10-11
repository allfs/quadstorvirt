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
#include "sense.h"
#include "vdevdefs.h"
#include "qs_lib.h"
#include "bdevmgr.h"
#include "ddtable.h"
#include "ddthread.h"
#include "tcache.h"
#include "fastlog.h"
#include "log_group.h"
#include "rcache.h"
#include "gdevq.h"
#include "reservation.h"
#include <exportdefs.h>
#include "cluster.h"
#include "node_sync.h"
#include "node_ha.h"
#include "bdevgroup.h"
#include "node_mirror.h"

#ifdef ENABLE_STATS
#define PRINT_STAT(x,y)	printf(x" %llu \n", (unsigned long long)tdisk->y); pause("psg", 10);
#else
#define PRINT_STAT(x,y) do {} while(0)
#endif

static int ctio_realloc_pglist(struct qsio_scsiio *ctio, struct pgdata *ref_page, uint32_t num_blocks, uint8_t *hash, unsigned long flags);

uint32_t cached_amaps;
uint32_t cached_amap_tables;
atomic_t num_tdisks;

extern struct tdisk *tdisks[];
extern mtx_t *tdisk_lookup_lock;
struct tdisk *tdisk_lookup[TL_MAX_DEVICES];
static void tdisk_added(void);
static void tdisk_removed(void);

void
tdisk_remove(int tl_id, int target_id)
{
	mtx_lock(tdisk_lookup_lock);
	tdisk_lookup[target_id] = NULL;
	tdisks[tl_id] = NULL;
	mtx_unlock(tdisk_lookup_lock);
	tdisk_removed();
}

void
tdisk_insert(struct tdisk *tdisk, int tl_id, int target_id)
{
	mtx_lock(tdisk_lookup_lock);
	tdisks[tl_id] = tdisk;
	tdisk_lookup[target_id] = tdisk;
	mtx_unlock(tdisk_lookup_lock);
	tdisk_added();
}

static void
calc_amap_cache_count(void)
{
	uint64_t availmem;
	int entry_size;
	int tdisk_count = max_t(int, atomic_read(&num_tdisks), 1);

	entry_size = sizeof(struct amap) + AMAP_SIZE;
 	availmem = qs_availmem;
	availmem = availmem/entry_size;
	cached_amaps = (availmem * CACHED_AMAPS_PERCENTAGE)/100;
	cached_amaps = (cached_amaps / tdisk_count); 

	entry_size = sizeof(struct amap_table) + AMAP_TABLE_SIZE;
 	availmem = qs_availmem;
	availmem = availmem/entry_size;
	cached_amap_tables = (availmem * CACHED_AMAP_TABLES_PERCENTAGE)/100;
	cached_amap_tables = (cached_amap_tables / tdisk_count); 
	debug_info("cached_amaps %u cached_amap_tables %u tdisk count %d num tdisks %d\n", cached_amaps, cached_amap_tables, tdisk_count, atomic_read(&num_tdisks));
}

static void
tdisk_removed(void)
{
	atomic_dec(&num_tdisks);
	calc_amap_cache_count();
}

static void
tdisk_added(void)
{
	atomic_inc(&num_tdisks);
	calc_amap_cache_count();
}

static void
amap_table_group_free(struct amap_table_group *group)
{
	struct amap_table *amap_table;
	int i;

	if (group->amap_table) {
		for (i = 0; i < group->amap_table_max; i++) {
			amap_table = group->amap_table[i];
			if (!amap_table)
				continue;
			if (unlikely(atomic_read(&amap_table->refs) > 1))
				debug_warn("amap table refs %d\n", atomic_read(&amap_table->refs));
			amap_table_put(amap_table);
		}
		uma_zfree(fourk_cache, group->amap_table);
	}

	if (group->group_write_bmap)
		uma_zfree(group_write_bmap_cache, group->group_write_bmap);
	sx_free(group->group_lock);
	uma_zfree(amap_table_group_cache, group);
}

void
tdisk_reset_stats(uint32_t target_id)
{
#ifdef ENABLE_STATS
	struct tdisk *tdisk;
	uint8_t *ptr;
	int todo = sizeof(struct tdisk) - offsetof(struct tdisk, pgalloc_hits);

	tdisk = tdisk_locate(target_id);
	if (!tdisk)
		return;

	ptr  = (uint8_t *)(tdisk) + offsetof(struct tdisk, pgalloc_hits);
	tdisk_print_stats(tdisk);
	bzero(ptr, todo);
	tdisk_put(tdisk);
#endif
}

void
tdisk_print_stats(struct tdisk *tdisk)
{
#ifdef CUSTOM_BIO_STATS
	PRINT_STAT("read_bio_size_exceeded", read_bio_size_exceeded);
	PRINT_STAT("read_bio_vecs_exceeded", read_bio_vecs_exceeded);
	PRINT_STAT("read_bio_is_cloned", read_bio_is_cloned);
	PRINT_STAT("read_bio_merge_failed", read_bio_merge_failed);
	PRINT_STAT("read_bio_retried_segments", read_bio_retried_segments);
	PRINT_STAT("write_bio_size_exceeded", write_bio_size_exceeded);
	PRINT_STAT("write_bio_vecs_exceeded", write_bio_vecs_exceeded);
	PRINT_STAT("write_bio_is_cloned", write_bio_is_cloned);
	PRINT_STAT("write_bio_merge_failed", write_bio_merge_failed);
	PRINT_STAT("write_bio_retried_segments", write_bio_retried_segments);
#endif

	PRINT_STAT("process_delete_block_ticks", process_delete_block_ticks);
	PRINT_STAT("process_delete_block_wlist_ticks", process_delete_block_wlist_ticks);
	PRINT_STAT("process_delete_block_amap_ticks", process_delete_block_amap_ticks);
	PRINT_STAT("process_delete_block_amap_table_ticks", process_delete_block_amap_table_ticks);
	PRINT_STAT("delete_ticks", delete_ticks);
	PRINT_STAT("sync_wlist_ticks", sync_wlist_ticks);
	PRINT_STAT("sync_wlist_merge_ticks", sync_wlist_merge_ticks);
	PRINT_STAT("amap_table_group_delete_ticks", amap_table_group_delete_ticks);
	PRINT_STAT("amap_table_delete_ticks", amap_table_delete_ticks);
	PRINT_STAT("amap_table_delete_iowait_ticks", amap_table_delete_iowait_ticks);
	PRINT_STAT("amap_delete_ticks", amap_delete_ticks);
	PRINT_STAT("amap_delete_iowait_ticks", amap_delete_iowait_ticks);

	PRINT_STAT("read_total", read_total);
	PRINT_STAT("from_read_list", from_read_list);
	PRINT_STAT("from_rcache", from_rcache);
	PRINT_STAT("remote_reads", remote_reads);
	PRINT_STAT("local_reads", local_reads);

	PRINT_STAT("mirror_write_setup_bytes", mirror_write_setup_bytes);
	PRINT_STAT("mirror_write_setup_orig_bytes", mirror_write_setup_orig_bytes);
	PRINT_STAT("mirror_check_io_bytes", mirror_check_io_bytes);
	PRINT_STAT("mirror_write_done_bytes", mirror_write_done_bytes);
	PRINT_STAT(" mirror_write_post_pre_bytes",  mirror_write_post_pre_bytes);

	PRINT_STAT("mirror_write_setup_start_ticks", mirror_write_setup_start_ticks);
	PRINT_STAT("mirror_check_verify_ticks", mirror_check_verify_ticks);
	PRINT_STAT("mirror_check_comp_ticks", mirror_check_comp_ticks);
	PRINT_STAT("mirror_check_io_ticks", mirror_check_io_ticks);
	PRINT_STAT("mirror_write_post_ticks", mirror_write_post_ticks);
	PRINT_STAT("mirror_write_done_pre_ticks", mirror_write_done_pre_ticks);
	PRINT_STAT("mirror_write_done_post_ticks", mirror_write_done_post_ticks);

	PRINT_STAT("read_setup_ticks", read_setup_ticks);
	PRINT_STAT("read_io_ticks", read_io_ticks);
	PRINT_STAT("remote_read_io_ticks", remote_read_io_ticks);
	PRINT_STAT("read_io_done_ticks", read_io_done_ticks);
	PRINT_STAT("node_cmd_read_ticks", node_cmd_read_ticks);
	PRINT_STAT("write_setup_ticks", write_setup_ticks);
	PRINT_STAT("write_done_ticks", write_done_ticks);
	PRINT_STAT("node_cmd_write_ticks", node_cmd_write_ticks);

	PRINT_STAT("index_sync_start_io_ticks", index_sync_start_io_ticks);
	PRINT_STAT("index_sync_wait_ticks", index_sync_wait_ticks);
	PRINT_STAT("amap_free_alloc_ticks", amap_free_alloc_ticks);
	PRINT_STAT("amap_table_free_alloc_ticks", amap_table_free_alloc_ticks);
	PRINT_STAT("amap_table_group_free_alloc_ticks", amap_table_group_free_alloc_ticks);
	PRINT_STAT("pgalloc_hits", pgalloc_hits);
	PRINT_STAT("pgalloc_misses", pgalloc_misses);
	PRINT_STAT("amap_barrier_ticks", amap_barrier_ticks);
	PRINT_STAT("amap_table_barrier_ticks", amap_table_barrier_ticks);
	PRINT_STAT("amap_table_index_barrier_ticks", amap_table_index_barrier_ticks);

	PRINT_STAT("amap_start_write_ticks", amap_start_write_ticks);
	PRINT_STAT("amap_end_write_ticks", amap_end_write_ticks);
	PRINT_STAT("amap_do_io_ticks", amap_do_io_ticks);
	PRINT_STAT("amap_end_wait_ticks", amap_end_wait_ticks);
	PRINT_STAT("amap_table_end_wait_ticks", amap_table_end_wait_ticks);

	PRINT_STAT("add_lba_write_ticks", add_lba_write_ticks);
	PRINT_STAT("scan_write_ticks", scan_write_ticks);
	PRINT_STAT("wait_for_pgdata_ticks", wait_for_pgdata_ticks);
	PRINT_STAT("scan_dedupe_ticks", scan_dedupe_ticks);
	PRINT_STAT("check_pending_ddblocks_ticks", check_pending_ddblocks_ticks);
	PRINT_STAT("lba_unmapped_write_ticks", lba_unmapped_write_ticks);
	PRINT_STAT("alloc_pgdata_ticks", alloc_pgdata_ticks);
	PRINT_STAT("alloc_pgdata_wait_ticks", alloc_pgdata_wait_ticks);
	PRINT_STAT("pgdata_alloc_blocks_ticks", pgdata_alloc_blocks_ticks);
	PRINT_STAT("alloc_block_ticks", alloc_block_ticks);
	PRINT_STAT("check_table_ticks", check_table_ticks);
	PRINT_STAT("sync_list_start_ticks", sync_list_start_ticks);
	PRINT_STAT("fastlog_get_ticks", fastlog_get_ticks);
	PRINT_STAT("scan_write_dedupe_setup_ticks", scan_write_dedupe_setup_ticks);
	PRINT_STAT("scan_write_add_alloc_lba_ticks", scan_write_add_alloc_lba_ticks);
	PRINT_STAT("scan_write_update_alloc_lba_ticks", scan_write_update_alloc_lba_ticks);
	PRINT_STAT("wait_pending_ddblocks_ticks", wait_pending_ddblocks_ticks);
	PRINT_STAT("verify_ddblocks_ticks", verify_ddblocks_ticks);
	PRINT_STAT("calc_alloc_size_ticks", calc_alloc_size_ticks);
	PRINT_STAT("wait_amap_io_ticks", wait_amap_io_ticks);
	PRINT_STAT("sync_list_end_ticks", sync_list_end_ticks);
	PRINT_STAT("amap_sync_list_end_ticks", amap_sync_list_end_ticks);
	PRINT_STAT("fastlog_add_ticks", fastlog_add_ticks);

	PRINT_STAT("lba_unmapped_ticks", lba_unmapped_ticks);
	PRINT_STAT("amap_load_ticks", amap_load_ticks);
	PRINT_STAT("amap_new_ticks", amap_new_ticks);
	PRINT_STAT("amap_alloc_block_ticks", amap_alloc_block_ticks);
	PRINT_STAT("amap_locate_ticks", amap_locate_ticks);
	PRINT_STAT("amap_check_syncticks", amap_check_sync_ticks);
	PRINT_STAT("amap_table_init_ticks", amap_table_init_ticks);
	PRINT_STAT("amap_table_load_ticks", amap_table_load_ticks);
	PRINT_STAT("amap_table_locate_ticks", amap_table_locate_ticks);
	PRINT_STAT("amap_table_get_amap_ticks", amap_table_get_amap_ticks);
	PRINT_STAT("get_amap_block_ticks", get_amap_block_ticks);
	PRINT_STAT("set_amap_block_ticks", set_amap_block_ticks);
	PRINT_STAT("read_ticks", read_ticks);
	PRINT_STAT("post_read_io_ticks", post_read_io_ticks);
	PRINT_STAT("read_free_amaps_ticks", read_free_amaps_ticks);
	PRINT_STAT("read_amap_block_ticks", read_amap_block_ticks);
	PRINT_STAT("pgdata_read_list_ticks", pgdata_read_list_ticks);
	PRINT_STAT("tcache_read_add_page_ticks", tcache_read_add_page_ticks);
	PRINT_STAT("sync_cache_ticks", sync_cache_ticks);
	PRINT_STAT("sync_cache16_ticks", sync_cache16_ticks);
	PRINT_STAT("write_ticks", write_ticks);
	PRINT_STAT("write_same_ticks", write_same_ticks);
	PRINT_STAT("unmap_ticks", unmap_ticks);
	PRINT_STAT("extended_copy_read_ticks", extended_copy_read_ticks);
	PRINT_STAT("unmap_cmds", unmap_cmds);
	PRINT_STAT("wsame_cmds", wsame_cmds);
	PRINT_STAT("wsame_unmap_cmds", wsame_unmap_cmds);
	PRINT_STAT("xcopy_cmds", xcopy_cmds);
	PRINT_STAT("post_write_ticks", post_write_ticks);
	PRINT_STAT("post_io_ticks", post_io_ticks);
	PRINT_STAT("read_amap_wait_ticks", read_amap_wait_ticks);
	PRINT_STAT("amap_wait_ticks", amap_wait_ticks);
	PRINT_STAT("check_table_read_ticks", check_table_read_ticks);
	PRINT_STAT("wait_for_amap_ticks", wait_for_amap_ticks);
	PRINT_STAT("table_index_write_ticks", table_index_write_ticks);
	PRINT_STAT("wait_for_amap_sync_ticks", wait_for_amap_sync_ticks);
	PRINT_STAT("amap_write_wait_ticks", amap_write_wait_ticks);
	PRINT_STAT("entry_rw_ticks", entry_rw_ticks);
	PRINT_STAT("wait_meta_index_ticks", wait_meta_index_ticks);
	PRINT_STAT("wait_index_ticks", wait_index_ticks);
	PRINT_STAT("wait_log_ticks", wait_log_ticks);
	PRINT_STAT("sync_amap_list_ticks", sync_amap_list_ticks);
	PRINT_STAT("fastlog_insert_ticks", fastlog_insert_ticks);
	PRINT_STAT("amap_write_setup_ticks", amap_write_setup_ticks);
	PRINT_STAT("tcache_wait_ticks", tcache_wait_ticks);
	PRINT_STAT("tcache_setup_ticks", tcache_setup_ticks);
	PRINT_STAT("log_list_end_writes_ticks", log_list_end_writes_ticks);
	PRINT_STAT("tcache_read_wait_ticks", tcache_read_wait_ticks);
	PRINT_STAT("biot_read_count", biot_read_count);
	PRINT_STAT("biot_write_count", biot_write_count);
	PRINT_STAT("lba_read_count", lba_read_count);
	PRINT_STAT("xcopy_unaligned", xcopy_unaligned);
	PRINT_STAT("xcopy_aligned", xcopy_aligned);
	PRINT_STAT("xcopy_ref_hits", xcopy_ref_hits);
	PRINT_STAT("xcopy_ref_misses", xcopy_ref_misses);
	PRINT_STAT("lba_write_count", lba_write_count);
	PRINT_STAT("inread_list", inread_list);
	PRINT_STAT("read_count", read_count);
	PRINT_STAT("write_count", write_count);
	PRINT_STAT("tag_simple", tag_simple);
	PRINT_STAT("tag_ordered", tag_ordered);
	PRINT_STAT("tag_head", tag_head);
	PRINT_STAT("inline_amap_writes", inline_amap_writes);
	PRINT_STAT("post_amap_writes", post_amap_writes);
	PRINT_STAT("amap_new", amap_new);
	PRINT_STAT("amap_load", amap_load);
	PRINT_STAT("amap_table_new", amap_table_new);
	PRINT_STAT("amap_table_load", amap_table_load);
	PRINT_STAT("amap_writes", amap_writes);
	PRINT_STAT("amap_reads", amap_reads);
	PRINT_STAT("amap_table_writes", amap_table_writes);
	PRINT_STAT("amap_table_reads", amap_table_reads);
	PRINT_STAT("amap_wait", amap_wait);
	PRINT_STAT("amap_hits", amap_hits);
	PRINT_STAT("amap_misses", amap_misses);
	PRINT_STAT("read_incache", read_incache);
	PRINT_STAT("fast_log_misses", fast_log_misses);
	PRINT_STAT("fast_log_hits", fast_log_hits);
	PRINT_STAT("write_page_misses", write_page_misses);
	PRINT_STAT("write_bstart_misses", write_bstart_misses);
	PRINT_STAT("write_bint_misses", write_bint_misses);
	PRINT_STAT("read_page_misses", read_page_misses);
	PRINT_STAT("read_bstart_misses", read_bstart_misses);
	PRINT_STAT("read_bint_misses", read_bint_misses);
	PRINT_STAT("pgdata_wait_cnt", pgdata_wait_cnt);
	PRINT_STAT("pgdata_wait_ticks", pgdata_wait_ticks);
}

void
tdisk_stop_delete_thread(struct tdisk *tdisk)
{
	tdisk_mirror_lock(tdisk);
	if (tdisk->delete_task) {
		kernel_thread_stop(tdisk->delete_task, &tdisk->flags, tdisk->delete_wait, VDISK_DELETE_EXIT);
		tdisk->delete_task = NULL;
	}
	tdisk_mirror_unlock(tdisk);
}

void
tdisk_stop_threads(struct tdisk *tdisk)
{
	if (tdisk->sync_task) {
		kernel_thread_stop(tdisk->sync_task, &tdisk->flags, tdisk->sync_wait, VDISK_SYNC_EXIT);
		tdisk->sync_task = NULL;
	}

	if (tdisk->free_task) {
		kernel_thread_stop(tdisk->free_task, &tdisk->flags, tdisk->free_wait, VDISK_FREE_EXIT);
		tdisk->free_task = NULL;
	}

	if (tdisk->load_task) {
		kernel_thread_stop(tdisk->load_task, &tdisk->flags, tdisk->load_wait, VDISK_LOAD_EXIT);
		tdisk->load_task = NULL;
	}

	if (tdisk->attach_task) {
		kernel_thread_stop(tdisk->attach_task, &tdisk->flags, tdisk->attach_wait, VDISK_ATTACH_EXIT);
		tdisk->attach_task = NULL;
	}

	if (tdisk->delete_task) {
		kernel_thread_stop(tdisk->delete_task, &tdisk->flags, tdisk->delete_wait, VDISK_DELETE_EXIT);
		tdisk->delete_task = NULL;
	}
}

void
tdisk_state_reset(struct tdisk *tdisk)
{
	struct amap_table_group *group;
	struct amap_table_index *table_index;
	int i;

	tdisk_stop_threads(tdisk);

	if (tdisk->amap_table_group) {
		for (i = 0; i < tdisk->amap_table_group_max; i++) {
			group = tdisk->amap_table_group[i];
			if (!group)
				continue;
			amap_table_group_free(group);
		}
		free(tdisk->amap_table_group, M_AMAPTABLEGROUP);
		tdisk->amap_table_group = NULL;
	}

	if (tdisk->table_index) {
		for (i = 0; i < tdisk->table_index_max; i++) {
			table_index = &tdisk->table_index[i];
			if (table_index->metadata)
				vm_pg_free(table_index->metadata);
			if (table_index->table_index_lock)
				sx_free(table_index->table_index_lock);
			if (table_index->table_index_wait)
				wait_chan_free(table_index->table_index_wait);
		}
		free(tdisk->table_index, M_TABLEINDEX);
		tdisk->table_index = NULL;
	}

	TAILQ_INIT(&tdisk->group_list);
	atomic_set(&tdisk->amap_count, 0);
	atomic_set(&tdisk->amap_table_count, 0);
}

void
tdisk_free(struct tdisk *tdisk)
{
	tdisk_state_reset(tdisk);

	tdisk_print_stats(tdisk);
	if (tdisk->metadata) {
		vm_pg_free(tdisk->metadata);
		tdisk->metadata = NULL;
	}

	debug_check(atomic_read(&tdisk->mirror_cmds));
	device_free_all_initiators(&tdisk->istate_list);
	device_free_all_initiators(&tdisk->sync_istate_list);
	persistent_reservation_clear(&tdisk->reservation.registration_list);
	persistent_reservation_clear(&tdisk->sync_reservation.registration_list);
	sx_free(tdisk->tdisk_lock);
	sx_free(tdisk->mirror_lock);
	sx_free(tdisk->clone_lock);
	sx_free(tdisk->bmap_lock);
	mtx_free(tdisk->group_list_lock);
	mtx_free(tdisk->stats_lock);
	sx_free(tdisk->reservation_lock);
	wait_chan_free(tdisk->mirror_wait);
	wait_chan_free(tdisk->free_wait);
	wait_chan_free(tdisk->sync_wait);
	wait_chan_free(tdisk->load_wait);
	wait_chan_free(tdisk->attach_wait);
	wait_chan_free(tdisk->delete_wait);
	wait_chan_free(tdisk->lba_wait);
	wait_chan_free(tdisk->lba_write_wait);
	wait_chan_free(tdisk->lba_read_wait);
	wait_chan_free(tdisk->clone_wait);
	uma_zfree(tdisk_cache, tdisk);
}

extern struct mdaemon_info mdaemon_info;

static int
char_to_int(char tmp)
{
	if (tmp >= '0' && tmp <= '9')
		return (tmp - '0');
	else
		return ((tmp - 'a') + 10);
}

static void
convert_serialnumber_to_hash(unsigned char *hash, char *serialnumber)
{
	int val1, val2;
	int i, j;

	for (i = 0, j = 0; i < 32; i+=2, j++) {
		val1 = char_to_int(serialnumber[i]);
		val2 = char_to_int(serialnumber[i+1]);
		hash[j] = (val1 << 4) | val2;
	}
}

static void
tdisk_init_inquiry_data(struct inquiry_data *inquiry)
{
	bzero(inquiry, sizeof(*inquiry));
	inquiry->device_type = T_DIRECT;
	inquiry->version = ANSI_VERSION_SCSI3_SPC3; /* Current supported version. Need to do it a better way */
	inquiry->response_data = RESPONSE_DATA | HISUP_MASK; 
	inquiry->additional_length = STANDARD_INQUIRY_LEN - 5; /* n - 4 */
	inquiry->protect = 0x8; /* 3PC */
	inquiry->linked = 0x2; /* CMDQUE */
	sys_memset(&inquiry->vendor_id, ' ', 8);
	memcpy(&inquiry->vendor_id, VENDOR_ID_QUADSTOR, strlen(VENDOR_ID_QUADSTOR));
	sys_memset(&inquiry->product_id, ' ', 16);
	memcpy(&inquiry->product_id, PRODUCT_ID_QUADSTOR_SAN, strlen(PRODUCT_ID_QUADSTOR_SAN));
	memcpy(&inquiry->revision_level, PRODUCT_REVISION_QUADSTOR, strlen(PRODUCT_REVISION_QUADSTOR));
#if 0
	inquiry->vd1 = htobe16(0x0320); /* SBC 2 No version claimed */
	inquiry->vd2 = htobe16(0x0300); /* SPC 3 No version claimed */
	inquiry->vd3 = htobe16(0x0060); /* SAM 3 No version claimed */
#endif
}

void
tdisk_init(struct tdisk *tdisk)
{
	SLIST_INIT(&tdisk->istate_list);
	SLIST_INIT(&tdisk->sync_istate_list);
	TAILQ_INIT(&tdisk->lba_list);
	TAILQ_INIT(&tdisk->lba_write_list);
	TAILQ_INIT(&tdisk->lba_read_list);
	SLIST_INIT(&tdisk->ecopy_list);
	TAILQ_INIT(&tdisk->group_list);
	SLIST_INIT(&tdisk->reservation.registration_list);
	SLIST_INIT(&tdisk->sync_reservation.registration_list);
	tdisk->tdisk_lock = sx_alloc("tdisk lock");
	tdisk->mirror_lock = sx_alloc("tdisk mirror lock");
	tdisk->clone_lock = sx_alloc("tdisk clone lock");
	tdisk->bmap_lock = sx_alloc("tdisk write bmap lock");
	tdisk->group_list_lock = mtx_alloc("tdisk group lock");
	tdisk->stats_lock = mtx_alloc("tdisk stats lock");
	tdisk->reservation_lock = sx_alloc("tdisk reservation lock");
	tdisk->mirror_wait = wait_chan_alloc("tdisk mirror wait");
	tdisk->free_wait = wait_chan_alloc("tdisk free wait");
	tdisk->sync_wait = wait_chan_alloc("tdisk sync wait");
	tdisk->load_wait = wait_chan_alloc("tdisk load wait");
	tdisk->attach_wait = wait_chan_alloc("tdisk attach wait");
	tdisk->delete_wait = wait_chan_alloc("tdisk delete wait");
	tdisk->lba_wait = wait_chan_alloc("tdisk lba wait");
	tdisk->lba_write_wait = wait_chan_alloc("tdisk lba write wait");
	tdisk->lba_read_wait = wait_chan_alloc("tdisk lba write wait");

	STAILQ_INIT(&tdisk->clone_list);
	tdisk->clone_wait = wait_chan_alloc("tdisk clone wait");
	atomic_set(&tdisk->refs, 1);
}

static void
tdisk_init_caching_mode_page(struct caching_mode_page *page)
{
	bzero(page, sizeof(*page));
	page->page_code = CACHING_MODE_PAGE;
	page->page_length = 0x12; 
	page->rcd |= 0x10;
#if 0
	page->rcd = 0x1;
	page->rcd |= 0x4; /* Write cache enabled */
#endif
	page->disable_prefetch_transfer_length = htobe16(0xffff);
	page->minimum_prefetch = htobe16(0xff);
	page->maximum_prefetch = htobe16(0xffff);
	page->maximum_prefetch_ceiling = htobe16(0xffff);
}

static void
tdisk_init_logical_block_provisioning_page(struct tdisk *tdisk, struct logical_block_provisioning_page *page)
{
	bzero(page, sizeof(*page));
	page->device_type = T_DIRECT;
	page->page_code = LOGICAL_BLOCK_PROVISIONING_VPD_PAGE;
	page->page_length = htobe16(0x04);
	if (tdisk->lba_shift == LBA_SHIFT)
		page->threshold_exponent = THRESHOLD_SET_SIZE;
	else
		page->threshold_exponent = THRESHOLD_SET_SIZE_LEGACY;
	page->dp = 0x01;
	page->dp |= 0x02; /* ANC_SUP */
	page->dp |= 0x40; /* LBPWS */
	page->dp |= 0x80; /* LBPU */ 
	page->provisioning_type = 0; /* Thin Provisioning */
}

static void
tdisk_init_block_limits_page(struct tdisk *tdisk, struct block_limits_page *page)
{
	bzero(page, sizeof(*page));
	page->device_type = T_DIRECT;
	page->page_code = BLOCK_LIMITS_VPD_PAGE;
	page->page_length = htobe16(0x3C);
	page->maximum_compare_write_length = 128;
	if (tdisk->lba_shift == LBA_SHIFT) {
		page->maximum_transfer_length = htobe32(TDISK_MAXIMUM_TRANSFER_LENGTH); /* 2 MB */
		page->optimal_transfer_length = htobe32(TDISK_OPTIMAL_TRANSFER_LENGTH); /* 128 K */
		page->maximum_unmap_lba_count = htobe32(TDISK_UNMAP_LBA_COUNT); /* 2 MB */
	}
	else {
		page->maximum_transfer_length = htobe32(TDISK_MAXIMUM_TRANSFER_LENGTH_LEGACY); /* 2 MB */
		page->optimal_transfer_length = htobe32(TDISK_OPTIMAL_TRANSFER_LENGTH_LEGACY); /* 128 K */
		page->maximum_unmap_lba_count = htobe32(TDISK_UNMAP_LBA_COUNT_LEGACY); /* 2 MB */
	}
	page->maximum_unmap_block_descriptor_count = htobe32(TDISK_MAXIMUM_UNMAP_BLOCK_DESCRIPTOR_COUNT);
	if (tdisk->lba_shift != LBA_SHIFT)
		page->optimal_unmap_granularity = htobe32(8);
}

void
tdisk_initialize(struct tdisk *tdisk, char *serialnumber)
{
	char hash[16];

	debug_check(!serialnumber[0]);
	strcpy(tdisk->unit_identifier.serial_number, serialnumber);
	convert_serialnumber_to_hash(hash, serialnumber);
	device_init_unit_identifier(&tdisk->unit_identifier, VENDOR_ID_QUADSTOR, PRODUCT_ID_QUADSTOR_SAN, strlen(tdisk->unit_identifier.serial_number));
	device_init_naa_identifier(&tdisk->naa_identifier, hash);
}

static int
tdisk_start_delete(struct tdisk *tdisk)
{
	int retval;

	tdisk_stop_threads(tdisk);

	atomic_set_bit(VDISK_IN_DELETE, &tdisk->flags);
	atomic_set_bit(VDISK_SYNC_START, &tdisk->flags);
	retval = tdisk_sync(tdisk, 0);
	if (unlikely(retval != 0))
		return -1;

	retval = vdisk_delete(tdisk, 0);
	return retval;
}

struct tdisk *
tdisk_locate(uint16_t target_id)
{
	struct tdisk *tdisk;

	if (unlikely(target_id >= TL_MAX_DEVICES)) {
		debug_warn("Invalid target disk id %u\n", target_id);
		return NULL;
	}

	mtx_lock(tdisk_lookup_lock);
	tdisk = tdisk_lookup[target_id];
	if (tdisk)
		tdisk_get(tdisk);
	mtx_unlock(tdisk_lookup_lock);
	return tdisk;
}

struct tdisk *
tdisk_locate_remove(uint16_t target_id)
{
	struct tdisk *tdisk;

	if (unlikely(target_id >= TL_MAX_DEVICES)) {
		debug_warn("Invalid target disk id %u\n", target_id);
		return NULL;
	}

	mtx_lock(tdisk_lookup_lock);
	tdisk = tdisk_lookup[target_id];
	tdisk_lookup[target_id] = NULL;
	mtx_unlock(tdisk_lookup_lock);
	return tdisk;
}

int
target_disk_reset_stats(struct tdisk_info *tdisk_info, unsigned long arg)
{
	struct tdisk *tdisk;
	int retval;

	if (!atomic_read(&kern_inited))
		return -1;

	if (tdisk_info->tl_id >= TL_MAX_DEVICES) {
		return -1;
	}

	tdisk = tdisks[tdisk_info->tl_id];
	if (!tdisk)
		return -1; 

	bzero(&tdisk->stats, sizeof(tdisk->stats));
	atomic_set_bit(VDISK_SYNC_START, &tdisk->flags);
	memcpy(&tdisk_info->stats, &tdisk->stats, sizeof(tdisk->stats));
#ifdef FREEBSD
	memcpy((void *)arg, tdisk_info, offsetof(struct tdisk_info, q_entry));
	retval = 0;
#else
	retval = copyout(tdisk_info, (void *)arg, offsetof(struct tdisk_info, q_entry));
#endif
	return retval;
}

int
target_disk_stats(struct tdisk_info *tdisk_info, unsigned long arg)
{
	struct tdisk *tdisk;
	int retval;

	if (!atomic_read(&kern_inited))
		return -1;

	if (tdisk_info->tl_id >= TL_MAX_DEVICES) {
		return -1;
	}

	tdisk = tdisks[tdisk_info->tl_id];
	if (!tdisk)
		return -1; 

	memcpy(&tdisk_info->stats, &tdisk->stats, sizeof(tdisk->stats));
	memcpy(&tdisk_info->mirror_state, &tdisk->mirror_state, sizeof(tdisk->mirror_state));
	tdisk_info->enable_deduplication = tdisk->enable_deduplication;
	tdisk_info->enable_compression = tdisk->enable_compression;
	tdisk_info->enable_verify = tdisk->enable_verify;
	tdisk_info->threshold = tdisk->threshold;
	tdisk_info->size = tdisk->end_lba << tdisk->lba_shift;
	if (tdisk_clone_error(tdisk))
		tdisk_info->clone_error = 1;
	
	if (tdisk_mirror_error(tdisk))
		tdisk_info->mirror_error = 1;

#ifdef FREEBSD
	memcpy((void *)arg, tdisk_info, offsetof(struct tdisk_info, q_entry));
	retval = 0;
#else
	retval = copyout(tdisk_info, (void *)arg, offsetof(struct tdisk_info, q_entry));
#endif
	return retval;
}

static int
tdisk_modify_serialnumber(struct tdisk *tdisk, struct tdisk_info *tdisk_info)
{
	int retval;

	tdisk_lock(tdisk);
	tdisk_initialize(tdisk, tdisk_info->serialnumber);
	if (tdisk->remote) {
		tdisk_unlock(tdisk);
		return 0;
	}

	atomic_set_bit(VDISK_SYNC_START, &tdisk->flags);
	retval = __tdisk_sync(tdisk, 0);
	tdisk_unlock(tdisk);
	return retval;
}

int
target_modify_disk(struct tdisk_info *tdisk_info, unsigned long arg)
{
	struct tdisk *tdisk;
	struct vdisk_update_spec spec;
	int retval;

	if (!atomic_read(&kern_inited))
		return -1;

	if (tdisk_info->tl_id >= TL_MAX_DEVICES) {
		return -1;
	}

	tdisk = tdisks[tdisk_info->tl_id];
	if (!tdisk)
		return -1; 

	/* Check if we are modifying the serial number */
	if (memcmp(tdisk_info->serialnumber, tdisk->unit_identifier.serial_number, 32)) {
		retval = tdisk_modify_serialnumber(tdisk, tdisk_info);
		if (unlikely(retval != 0))
			return retval;
	}

	if (tdisk->enable_deduplication == tdisk_info->enable_deduplication &&
	    tdisk->enable_compression == tdisk_info->enable_compression &&
	    tdisk->enable_verify == tdisk_info->enable_verify &&
	    tdisk->threshold == tdisk_info->threshold) {
		return 0;
	}

	spec.enable_deduplication = tdisk_info->enable_deduplication;
	spec.enable_compression = tdisk_info->enable_compression;
	spec.enable_verify = tdisk_info->enable_verify;
	spec.threshold = tdisk_info->threshold;
	spec.end_lba = tdisk->end_lba;

	retval = tdisk_mirror_update_properties(tdisk, &spec);
	if (unlikely(retval != 0))
		return -1;

	tdisk_lock(tdisk);
	tdisk->enable_deduplication = tdisk_info->enable_deduplication;
	tdisk->enable_compression = tdisk_info->enable_compression;
	tdisk->enable_verify = tdisk_info->enable_verify;
	tdisk->threshold = tdisk_info->threshold;
	if (tdisk->remote) {
		tdisk_unlock(tdisk);
		return 0;
	}
	atomic_set_bit(VDISK_SYNC_START, &tdisk->flags);
	retval = __tdisk_sync(tdisk, 0);
	tdisk_unlock(tdisk);
	return retval;
}

int
target_delete_disk_post(struct tdisk_info *tdisk_info, unsigned long arg)
{
	struct tdisk *tdisk;

	debug_info("delete for %d\n", tdisk_info->tl_id);
	if (!atomic_read(&kern_inited))
		return -1;

	if (tdisk_info->tl_id >= TL_MAX_DEVICES) {
		return -1;
	}

	tdisk = tdisks[tdisk_info->tl_id];
	if (!tdisk)
		return -1; 

	if (atomic_read(&tdisk->group->log_error))
		return -1;

	tdisk_remove(tdisk_info->tl_id, tdisk->target_id);
	tdisk_put(tdisk);
	return 0;
}

int
target_delete_disk(struct tdisk_info *tdisk_info, unsigned long arg)
{
	struct tdisk *tdisk;

	if (!atomic_read(&kern_inited))
		return -1;

	if (tdisk_info->tl_id >= TL_MAX_DEVICES) {
		return -1;
	}

	tdisk = tdisks[tdisk_info->tl_id];
	if (!tdisk)
		return -1; 

	if (tdisk_info->free_alloc && atomic_test_bit(VDISK_DONE_DELETE, &tdisk->flags)) {
		debug_warn("VDisk %s already deleted\n", tdisk_name(tdisk));
		return -1;
	}

	if (atomic_read(&tdisk->group->log_error))
		return -1;

	cbs_disable_device(tdisk);
	device_wait_all_initiators(&tdisk->istate_list);

	cbs_remove_device(tdisk);

	while (atomic_read(&tdisk->refs) > 1)
		processor_yield();

	target_clear_fc_rules(tdisk->target_id);

	node_tdisk_delete_send(tdisk);

	if (tdisk_info->free_alloc) {
		tdisk_mirror_remove(tdisk, 0);
	}
	else {
		tdisk_mirror_exit(tdisk);
	}

	if (!tdisk_info->free_alloc) {
		tdisk_remove(tdisk_info->tl_id, tdisk->target_id);
		tdisk_put(tdisk);
	}
	else {
		tdisk_start_delete(tdisk);
	}
	return 0;
}

static struct amap_table *
group_table_first(struct amap_table_group *group)
{
	struct amap_table *amap_table = NULL;

	amap_table_group_lock(group);
	amap_table = TAILQ_FIRST(&group->table_list);
	if (amap_table)
		group_tail_amap_table(group, amap_table);
	amap_table_group_unlock(group);
	return amap_table;
}

static struct amap_table_group *
tdisk_group_first(struct tdisk *tdisk)
{
	struct amap_table_group *group;

	mtx_lock(tdisk->group_list_lock);
	group = TAILQ_FIRST(&tdisk->group_list);
	TAILQ_REMOVE(&tdisk->group_list, group, g_list);
	TAILQ_INSERT_TAIL(&tdisk->group_list, group, g_list);
	mtx_unlock(tdisk->group_list_lock);
	return group;
}

void
amap_table_remove(struct amap_table_group *group, struct amap_table *amap_table)
{
	uint32_t group_offset = amap_table_group_offset(amap_table);

	group->amap_table[group_offset] = NULL;
	TAILQ_REMOVE(&group->table_list, amap_table, t_list);
	atomic_dec(&amap_table->tdisk->amap_table_count);
	amap_table_put(amap_table);
}

static int
amap_busy(struct amap *amap)
{
	if (atomic_read(&amap->refs) > 1 || atomic_test_bit_short(AMAP_META_IO_PENDING, &amap->flags) || atomic_test_bit_short(AMAP_META_DATA_NEW, &amap->flags))
		return 1;
	else
		return 0;
}
static int 
amap_table_free_unused(struct amap_table *amap_table)
{
	struct amap *amap;
	int i, empty = 1;

	for (i = 0; i < AMAPS_PER_AMAP_TABLE; i++) {
		amap = amap_table->amap_index[i];
		if (!amap)
			continue;
		empty = 0;
		if (amap_busy(amap))
			continue;
		amap_table->amap_index[i] = NULL;
		amap_put(amap);
		atomic_dec(&amap_table->tdisk->amap_count);
		if (atomic_read(&amap_table->tdisk->amap_count) <= cached_amaps && atomic_read(&amap_table->tdisk->amap_table_count) <= cached_amap_tables)
			break;
	}
	return empty;
}

#define TDISK_SET_PROP(tdk,tdkvar,rwindex,rwbt)			\
do {								\
	if (tdk->tdkvar)					\
		atomic_set_bit(rwbt, &rwindex->flags);		\
	else							\
		atomic_clear_bit(rwbt, &rwindex->flags);	\
} while (0)

#define TDISK_GET_PROP(tdk,tdkvar,rwindex,rwbt)			\
do {								\
	if (atomic_test_bit(rwbt, &rwindex->flags))		\
		tdk->tdkvar = 1;				\
	else							\
		tdk->tdkvar = 0;				\
} while (0)

static void
raw_index_set_name(struct raw_index_data *raw_data, uint8_t *name)
{
	int name_len, min_len;

	name_len = strlen(name) + 1;
	min_len = min_t(int, sizeof(raw_data->name), name_len);
	memcpy(raw_data->name, name, min_len);
	name_len -= min_len;
	if (!name_len)
		return;
	name += min_len;
	memcpy(raw_data->ext_name, name, name_len);
}

int
__tdisk_sync(struct tdisk *tdisk, int free_alloc)
{
	pagestruct_t *page;
	struct raw_index_data *raw_data;
	uint64_t index_b_start;
	int retval;

	page = vm_pg_alloc(VM_ALLOC_ZERO);
	if (unlikely(!page)) {
		debug_warn("Page allocation failure\n");
		return -1;
	}

	atomic_clear_bit(VDISK_SYNC_START, &tdisk->flags);
	memcpy(vm_pg_address(page), vm_pg_address(tdisk->metadata), PAGE_SIZE);

	if (!free_alloc)
		node_tdisk_sync_send(tdisk);

	if (free_alloc)
		goto skip;

	raw_data = (struct raw_index_data *)(vm_pg_address(page));
	if (tdisk_clone_error(tdisk))
		atomic_set_bit(VDISK_CLONE_ERROR, &raw_data->flags);
	if (atomic_test_bit(V2_VDISK, &tdisk->flags))
		atomic_set_bit(V2_VDISK, &raw_data->flags);
	if (atomic_test_bit(VDISK_IN_DELETE, &tdisk->flags))
		atomic_set_bit(VDISK_IN_DELETE, &raw_data->flags);
	if (atomic_test_bit(VDISK_IN_RESIZE, &tdisk->flags))
		atomic_set_bit(VDISK_IN_RESIZE, &raw_data->flags);
	else
		atomic_clear_bit(VDISK_IN_RESIZE, &raw_data->flags);
	atomic_set_bit(VDISK_ENABLE_PROPERTIES, &raw_data->flags);
	TDISK_SET_PROP(tdisk, enable_deduplication, raw_data, VDISK_ENABLE_DEDUPLICATION);
	TDISK_SET_PROP(tdisk, enable_compression, raw_data, VDISK_ENABLE_COMPRESSION);
	TDISK_SET_PROP(tdisk, enable_verify, raw_data, VDISK_ENABLE_VERIFY);
	memcpy(raw_data->serialnumber, tdisk->unit_identifier.serial_number, 32);
	raw_index_set_name(raw_data, tdisk->name);
	raw_data->threshold = tdisk->threshold;
	memcpy(&raw_data->stats, &tdisk->stats, sizeof(tdisk->stats));
	memcpy(&raw_data->mirror_state, &tdisk->mirror_state, sizeof(tdisk->mirror_state));
	atomic_clear_bit(MIRROR_FLAGS_WRITE_BITMAP_VALID, &raw_data->mirror_state.mirror_flags);
skip:
	index_b_start = bdev_get_disk_index_block(tdisk_bint(tdisk), tdisk->target_id);
	retval = qs_lib_bio_lba(tdisk_bint(tdisk), index_b_start, page, QS_IO_WRITE, TYPE_TDISK_INDEX);
	vm_pg_free(page);

	if (unlikely(retval != 0))
		debug_warn("disk index sync failed for %u\n", tdisk->target_id);

	return retval;
}

int 
tdisk_sync(struct tdisk *tdisk, int free_alloc)
{
	int retval;

	tdisk_lock(tdisk);
	if (!free_alloc && !atomic_test_bit(VDISK_SYNC_START, &tdisk->flags)) {
		tdisk_unlock(tdisk);
		return 0;
	}

	retval = __tdisk_sync(tdisk, free_alloc);
	tdisk_unlock(tdisk);
	return retval;
}

#ifdef FREEBSD 
void tdisk_sync_thread(void *data)
#else
int tdisk_sync_thread(void *data)
#endif
{
	struct tdisk *tdisk = (struct tdisk *)(data);

	thread_start();

	for(;;)
	{
#if 0
		wait_on_chan_interruptible(tdisk->sync_wait, atomic_test_bit(VDISK_SYNC_START, &tdisk->flags) || kernel_thread_check(&tdisk->flags, VDISK_SYNC_EXIT));
#endif

		wait_on_chan_timeout(tdisk->sync_wait, kernel_thread_check(&tdisk->flags, VDISK_SYNC_EXIT), 10000);

		if (node_in_standby()) {
			if (kernel_thread_check(&tdisk->flags, VDISK_SYNC_EXIT))
				break;
			atomic_clear_bit(VDISK_SYNC_START, &tdisk->flags);
			continue;
		}

		if (!atomic_test_bit(VDISK_FREE_ALLOC, &tdisk->flags))
			tdisk_sync(tdisk, 0);
		if (kernel_thread_check(&tdisk->flags, VDISK_SYNC_EXIT))
			break;
		if (atomic_test_bit(VDISK_MIRROR_LOAD_DONE, &tdisk->flags))
			tdisk_mirror_checks(tdisk);
	}

	thread_end();
#ifdef FREEBSD 
	kproc_exit(0);
#else
	return 0;
#endif
}

void
tdisk_tail_group(struct tdisk *tdisk, struct amap_table_group *group)
{
	mtx_lock(tdisk->group_list_lock);
	TAILQ_REMOVE(&tdisk->group_list, group, g_list);
	TAILQ_INSERT_TAIL(&tdisk->group_list, group, g_list);
	mtx_unlock(tdisk->group_list_lock);
}

#ifdef FREEBSD 
void tdisk_free_thread(void *data)
#else
int tdisk_free_thread(void *data)
#endif
{
	struct tdisk *tdisk = (struct tdisk *)(data);
	struct amap_table_group *group, *start_group;
	struct amap_table *amap_table, *start_amap_table;
	int empty;

	for(;;)
	{
		wait_on_chan_interruptible(tdisk->free_wait, atomic_test_bit(VDISK_FREE_START, &tdisk->flags) || kernel_thread_check(&tdisk->flags, VDISK_FREE_EXIT));
		atomic_clear_bit(VDISK_FREE_START, &tdisk->flags);
		start_group = NULL;

again:
		if (kernel_thread_check(&tdisk->flags, VDISK_FREE_EXIT))
			break;

		group = tdisk_group_first(tdisk);
		if (!start_group)
			start_group = group;
		else if (group == start_group) {
			if (atomic_read(&tdisk->amap_count) > cached_amaps || atomic_read(&tdisk->amap_table_count) > cached_amap_tables) {
				atomic_set_bit(VDISK_FREE_START, &tdisk->flags);
				pause("psg", 1000);
			}

			continue;
		}

		amap_table = group_table_first(group);
		start_amap_table = NULL;
		while (amap_table && (atomic_read(&tdisk->amap_count) > cached_amaps || atomic_read(&tdisk->amap_table_count) > cached_amap_tables) && !kernel_thread_check(&tdisk->flags, VDISK_FREE_EXIT)) {
			if (!start_amap_table)
				start_amap_table = amap_table;
			else if (start_amap_table == amap_table)
				break;

			amap_table_group_lock(group);
			amap_table_lock(amap_table);
			empty = amap_table_free_unused(amap_table);
			amap_table_unlock(amap_table);
			if (empty && atomic_read(&tdisk->amap_table_count) > cached_amap_tables) {
				if (atomic_read(&amap_table->refs) == 1) {
					amap_table_remove(group, amap_table);
					if (amap_table == start_amap_table)
						start_amap_table = NULL;
				}
			}
			amap_table_group_unlock(group);
			amap_table = group_table_first(group);
		}

		if (atomic_read(&tdisk->amap_count) > cached_amaps || atomic_read(&tdisk->amap_table_count) > cached_amap_tables) {
			goto again;
		}
	}
#ifdef FREEBSD 
	kproc_exit(0);
#else
	return 0;
#endif
}

#ifdef FREEBSD 
static void tdisk_attach_thread(void *data)
#else
static int tdisk_attach_thread(void *data)
#endif
{
	struct tdisk *tdisk = data;
	int retval;

	retval = tdisk_mirror_load(tdisk);
	if (retval == 0) {
		cbs_new_device(tdisk, 1);
		if (node_type_controller() && node_sync_enabled()) {
			tdisk_lock(tdisk);
			retval = __node_tdisk_sync_send(tdisk);
			if (retval == 0)
				atomic_set_bit(VDISK_SYNC_ENABLED, &tdisk->flags);
			tdisk_unlock(tdisk);
		}
	}
	atomic_set_bit(VDISK_MIRROR_LOAD_DONE, &tdisk->flags);
	wait_on_chan_interruptible(tdisk->attach_wait, kernel_thread_check(&tdisk->flags, VDISK_ATTACH_EXIT));

#ifdef FREEBSD 
	kproc_exit(0);
#else
	return 0;
#endif
}

int
target_attach_disk(struct tdisk_info *tdisk_info, unsigned long arg)
{
	struct tdisk *tdisk;
	int retval;

	if (!atomic_read(&kern_inited))
		return -1;

	if (tdisk_info->tl_id >= TL_MAX_DEVICES) {
		debug_warn("Invalid tl_id %d\n", tdisk_info->tl_id);
		return -1;
	}

	tdisk = tdisks[tdisk_info->tl_id];
	if (!tdisk) {
		debug_warn("Invalid tl_id %d\n", tdisk_info->tl_id);
		return -1;
	}

	if (atomic_read(&tdisk->group->log_error))
		return -1;

	tdisk_start_resize_thread(tdisk);
	retval = kernel_thread_create(tdisk_attach_thread, tdisk, tdisk->attach_task, "tdatt%u", tdisk->bus);
	if (unlikely(retval != 0))
		return -1;

	return 0;
#if 0
	retval = tdisk_mirror_load(tdisk);
	if (retval == 0) {
		cbs_new_device(tdisk, 0);
		tdisk_info->iscsi_tid = tdisk->iscsi_tid;
		tdisk_info->vhba_id = tdisk->vhba_id;
	}
	else {
		debug_info("mirror load failed, not attaching tdisk\n");
		tdisk_info->iscsi_tid = -1;
		tdisk_info->vhba_id = -1;
	}
#ifdef FREEBSD
	memcpy((void *)arg, tdisk_info, offsetof(struct tdisk_info, q_entry));
#else
	retval = copyout(tdisk_info, (void *)arg, offsetof(struct tdisk_info, q_entry));
	if (unlikely(retval != 0)) {
		target_delete_disk(tdisk_info, arg);
		return -1;
	}
#endif
	return 0;
#endif
}

int
target_load_disk(struct tdisk_info *tdisk_info, unsigned long arg)
{
	struct tdisk *tdisk;
	int tl_id;
	int retval;

	if (!atomic_read(&kern_inited))
		return -1;

	tl_id = get_next_device_id();
	if (tl_id < 0) {
		debug_warn("Failed to get a new device id\n");
		return -1;
	}

	tdisk = __uma_zalloc(tdisk_cache, Q_NOWAIT | Q_ZERO, sizeof(*tdisk));
	if (unlikely(!tdisk)) {
		debug_warn("Slab allocation failure\n");
		return -1;
	}
	tdisk_init(tdisk);
	tdisk->target_id = tdisk_info->target_id;

	tdisk->group = bdev_group_locate(tdisk_info->group_id, NULL);
	if (unlikely(!tdisk->group)) {
		debug_warn("Cannot locate pool at id %u\n", tdisk_info->group_id);
		tdisk_put(tdisk);
		return -1;
	}

#if 0
	if (atomic_read(&tdisk->group->log_error)) {
		tdisk_put(tdisk);
		return -1;
	}
#endif

	retval = tdisk_load_index(tdisk, tdisk_info);
	if (unlikely(retval != 0)) {
		debug_warn("Load index failed\n");
		tdisk_put(tdisk);
		return retval;
	}

	strcpy(tdisk->name, tdisk_info->name);
	tdisk->lba_shift = tdisk_info->lba_shift; 
	if (!tdisk->lba_shift)
		tdisk->lba_shift = LBA_SHIFT;
	tdisk->end_lba = (tdisk_info->size >> tdisk->lba_shift);

	tdisk_initialize(tdisk, tdisk_info->serialnumber);

	tdisk->bus = tl_id;
	tdisk_info->tl_id = tl_id;
	tdisk_info->v2_format = is_v2_tdisk(tdisk);
	tdisk_insert(tdisk, tl_id, tdisk_info->target_id);

	retval = kernel_thread_create(tdisk_free_thread, tdisk, tdisk->free_task, "tdfreet%u", tl_id);
	if (unlikely(retval != 0)) {
		tdisk_put(tdisk);
		return -1;
	}

	retval = kernel_thread_create(tdisk_sync_thread, tdisk, tdisk->sync_task, "tdsynct%u", tl_id);
	if (unlikely(retval != 0)) {
		tdisk_put(tdisk);
		return -1;
	}

#ifdef FREEBSD
	memcpy((void *)arg, tdisk_info, offsetof(struct tdisk_info, q_entry));
#else
	retval = copyout(tdisk_info, (void *)arg, offsetof(struct tdisk_info, q_entry));
	if (unlikely(retval != 0)) {
		target_delete_disk(tdisk_info, arg);
		return -1;
	}
#endif
	return 0;
}

struct amap_table *
amap_table_alloc(struct tdisk *tdisk, uint32_t amap_table_id)
{
	struct amap_table *amap_table;

	amap_table = __uma_zalloc(amap_table_cache, Q_NOWAIT | Q_ZERO, sizeof(*amap_table));
	if (unlikely(!amap_table)) {
		debug_warn("Slab allocation failure\n");
		return NULL;
	}

	amap_table->amap_index = __uma_zalloc(amap_index_cache, Q_NOWAIT | Q_ZERO, (AMAPS_PER_AMAP_TABLE * sizeof(struct amap *)));
	if (unlikely(!amap_table->amap_index)) {
		debug_warn("Memory allocation failure\n");
		uma_zfree(amap_table_cache, amap_table);
		return NULL;
	}

	amap_table->tdisk = tdisk;
	amap_table->amap_table_id = amap_table_id;
	atomic_set(&amap_table->refs, 1);
	amap_table->amap_table_lock = sx_alloc("amap table lock");
	amap_table->amap_table_wait = wait_chan_alloc("amap table wait");
	SLIST_INIT(&amap_table->io_waiters);
	return amap_table;
}

static struct amap_table_group *
amap_table_group_alloc(struct tdisk *tdisk, uint32_t group_offset, uint32_t amap_table_max)
{
	struct amap_table_group *group;

	group = tdisk->amap_table_group[group_offset];
	if (group) {
		group->amap_table_max = amap_table_max;
		return group;
	}

	debug_info("alloc group at %u amap table max %u\n", group_offset, amap_table_max);
	group = __uma_zalloc(amap_table_group_cache, Q_NOWAIT | Q_ZERO, sizeof(*group));
	if (unlikely(!group)) {
		debug_warn("Slab allocation failure\n");
		return NULL;
	}

	group->amap_table_max = amap_table_max;
	group->amap_table = __uma_zalloc(fourk_cache, Q_NOWAIT | Q_ZERO, 4096);
	if (unlikely(!group->amap_table)) {
		debug_warn("Slab allocation failure\n");
		uma_zfree(amap_table_group_cache, group);
		return NULL;
	}

	group->group_lock = sx_alloc("amap group lock");
	TAILQ_INIT(&group->table_list);
	tdisk->amap_table_group[group_offset] = group;
	TAILQ_INSERT_TAIL(&tdisk->group_list, group, g_list);
	return group;
}

int 
__tdisk_alloc_amap_groups(struct tdisk *tdisk, uint32_t amap_table_max)
{
	int idx = 0;
	uint32_t remaining;

	remaining = amap_table_max;

	while (remaining)
	{
		struct amap_table_group *group;
		uint32_t min;

		min = min_t(uint32_t, AMAP_TABLE_PER_GROUP, remaining);
		group = amap_table_group_alloc(tdisk, idx, min);
		if (unlikely(!group)) {
			return -1;
		}

		idx++;
		remaining -= min;
	}
	return 0;
}

uint64_t
tdisk_max_size(struct tdisk *tdisk)
{
	struct raw_index_data *raw_data;

	raw_data = (struct raw_index_data *)(vm_pg_address(tdisk->metadata));
	debug_info("raw data max size %llu size %llu\n", (unsigned long long)raw_data->max_size, (unsigned long long)raw_data->size);
	if (raw_data->max_size)
		return raw_data->max_size;
	else
		return raw_data->size;
}

static int 
tdisk_alloc_amap_groups(struct tdisk *tdisk)
{
	uint64_t size = tdisk_max_size(tdisk);
	uint64_t end_lba = size >> LBA_SHIFT;
	uint32_t table_index_max;
	int retval;

	tdisk->amap_table_max = end_lba / LBAS_PER_AMAP_TABLE;
	if (end_lba % LBAS_PER_AMAP_TABLE)
		tdisk->amap_table_max++;

	table_index_max = tdisk->amap_table_max >> INDEX_TABLE_GROUP_SHIFT; 
	if (tdisk->amap_table_max & INDEX_TABLE_GROUP_MASK)
		table_index_max++; 

	tdisk->table_index_max = table_index_max;
	tdisk->table_index = zalloc(INDEX_TABLE_PAD_MAX * sizeof(struct amap_table_index), M_TABLEINDEX, Q_NOWAIT);
	if (unlikely(!tdisk->table_index)) {
		debug_warn("Memory allocation failure\n");
		return -1;
	}
 
	tdisk->amap_table_group_max = tdisk->amap_table_max >> AMAP_TABLE_GROUP_SHIFT;
	if (tdisk->amap_table_max & AMAP_TABLE_GROUP_MASK)
		tdisk->amap_table_group_max++;

	tdisk->amap_table_group = zalloc(INDEX_TABLE_PAD_MAX * sizeof(struct amap_table_group *), M_AMAPTABLEGROUP, Q_NOWAIT);
	if (unlikely(!tdisk->amap_table_group)) {
		debug_warn("Memory allocation failure\n");
		return -1;
	}

	debug_info("amap table max %u table index max %u table group max %u\n", tdisk->amap_table_max, tdisk->table_index_max, tdisk->amap_table_group_max);
	retval = __tdisk_alloc_amap_groups(tdisk, tdisk->amap_table_max);
	if (unlikely(retval != 0))
		return -1;

	debug_info("index table max %u amap table max %u amap table group max %u\n", tdisk->table_index_max, tdisk->amap_table_max, tdisk->amap_table_group_max);
	return 0;
}

#ifdef FREEBSD 
static void tdisk_load_thread(void *data)
#else
static int tdisk_load_thread(void *data)
#endif
{
	struct tdisk *tdisk = data;
	struct amap_table_index *table_index;
	struct amap_table *amap_table;
	uint64_t size = tdisk->end_lba << tdisk->lba_shift;
	uint64_t end_lba;
	uint32_t atable_id;
	uint32_t amap_table_max;
	int i;

	thread_start();

	if (tdisk_mirroring_configured(tdisk)) {
		if (tdisk_mirroring_need_resync(tdisk) && !tdisk_mirror_master(tdisk))
			goto skip;
	}

	atable_id = 0;

	end_lba = size >> LBA_SHIFT;
	amap_table_max = end_lba / LBAS_PER_AMAP_TABLE;
	while (atomic_read(&tdisk->amap_table_count) < (cached_amap_tables / 2) && atable_id < amap_table_max && !kernel_thread_check(&tdisk->flags, VDISK_LOAD_EXIT)) {
		struct amap_table_group *group;
		uint32_t group_id, group_offset;
		uint64_t block;
		struct tpriv priv = { 0 };

		group_id = amap_table_group_id(atable_id, &group_offset);
		group = tdisk->amap_table_group[group_id];
		tdisk_tail_group(tdisk, group);
		table_index = &tdisk->table_index[group_id];
		amap_table_group_lock(group);
		if (group->amap_table[group_offset]) {
			atable_id++;
			amap_table_group_unlock(group);
			continue;
		}

		block = get_amap_table_block(table_index, group_offset);
		if (!block) {
			atable_id++;
			amap_table_group_unlock(group);
			continue;
		}

		amap_table = amap_table_load(tdisk, block, group, atable_id, &priv);
		if (amap_table) {
			bdev_start(amap_table_bint(amap_table)->b_dev, &priv);
		}
		amap_table_group_unlock(group);
		atable_id++;
	}

	for (i = 0; i < atable_id && !kernel_thread_check(&tdisk->flags, VDISK_LOAD_EXIT); i++) {
		struct amap_table_group *group;
		uint32_t group_id, group_offset;
		uint64_t block;
		uint32_t amap_id;
		uint32_t amap_idx;

#ifdef FREEBSD
		if ((i % 1024) == 0) {
			g_waitidle();
		}
#endif

		group_id = amap_table_group_id(i, &group_offset);
		group = tdisk->amap_table_group[group_id];
		tdisk_tail_group(tdisk, group);

		amap_table_group_lock(group);
		amap_table = group->amap_table[group_offset];
		if (amap_table)
			amap_table_get(amap_table);
		amap_table_group_unlock(group);

		if (!amap_table)
			continue;

		if (atomic_test_bit_short(ATABLE_META_DATA_INVALID, &amap_table->flags))
			continue;

		wait_on_chan_check(amap_table->amap_table_wait, !atomic_test_bit_short(ATABLE_META_DATA_READ_DIRTY, &amap_table->flags));
		amap_table_lock(amap_table);
		amap_table_check_csum(amap_table);

		if (atomic_test_bit_short(ATABLE_META_DATA_ERROR, &amap_table->flags)) {
			amap_table_unlock(amap_table);
			amap_table_group_lock(group);
			amap_table_put(amap_table);
			if (atomic_read(&amap_table->refs) == 1)
				amap_table_remove(group, amap_table);
			amap_table_group_unlock(group);
			continue;
		}

 		amap_id = i * AMAPS_PER_AMAP_TABLE;
		amap_idx = 0;
		while (atomic_read(&tdisk->amap_count) < (cached_amaps / 4) && !kernel_thread_check(&tdisk->flags, VDISK_LOAD_EXIT)) {
			if (amap_idx == AMAPS_PER_AMAP_TABLE)
				break;

			if (amap_table->amap_index[amap_idx]) {
				goto next_amap;
			}

			block = get_amap_block(amap_table, amap_idx);
			if (!block) {
				goto next_amap;
			}

			amap_load(amap_table, amap_id, amap_idx, block, NULL);
next_amap:
			amap_id++;
			amap_idx++;
		}
		amap_table_unlock(amap_table);
		amap_table_put(amap_table);
	}

skip:
	wait_on_chan_interruptible(tdisk->load_wait, kernel_thread_check(&tdisk->flags, VDISK_LOAD_EXIT));

	thread_end();
#ifdef FREEBSD 
	kproc_exit(0);
#else
	return 0;
#endif
}

static void
tdisk_load_amaps_start(struct tdisk *tdisk)
{
	int retval;

	retval = kernel_thread_create(tdisk_load_thread, tdisk, tdisk->load_task, "tdloadt%u", tdisk->bus);
	if (unlikely(retval != 0))
		debug_warn("Cannot create vdisk load thread\n");
}

void
tdisk_load_amaps(void)
{
	struct tdisk *tdisk;
	int i;

	for (i = 0; i < TL_MAX_DEVICES; i++) {
		tdisk = tdisks[i];
		if (!tdisk)
			continue;
		tdisk_load_amaps_start(tdisk);
	}
}

int
tdisk_load_index(struct tdisk *tdisk, struct tdisk_info *tdisk_info)
{
	struct raw_index_data *raw_data;
	pagestruct_t *page;
	uint64_t b_start;
	int i;
	int retval;
	struct amap_table_index *table_index;
	uint64_t index_b_start;

	if (unlikely(!tdisk_bint(tdisk))) {
		debug_warn("Cannot find start disk for %u \n", tdisk->target_id);
		return -1;
	}

	index_b_start = bdev_get_disk_index_block(tdisk_bint(tdisk), tdisk->target_id);

	page = vm_pg_alloc(0);
	if (unlikely(!page)) {
		debug_warn("mem alloc page failed\n");
		return -1;
	}

	retval = qs_lib_bio_lba(tdisk_bint(tdisk), index_b_start, page, QS_IO_READ, TYPE_TDISK_INDEX);
	if (unlikely(retval != 0)) {
		debug_warn("Cannot load meta data at %u:%llu\n", tdisk_bint(tdisk)->bid, (unsigned long long)index_b_start);
		vm_pg_free(page);
		return -1;
	}

	tdisk->metadata = page;

	raw_data = (struct raw_index_data *)(vm_pg_address(page));
	if (memcmp(raw_data->magic, DISK_INDEX_MAGIC, strlen(DISK_INDEX_MAGIC))) {
		debug_warn("Magic mismatch tdisk %s pool %s\n", tdisk_name(tdisk), tdisk->group->name);
		retval = zero_memcmp((uint64_t *)vm_pg_address(page));
		if (!retval)
			return -2;
		else
			return -1;
	}

	if(tdisk_info) {
		memcpy(tdisk_info->serialnumber, raw_data->serialnumber, sizeof(raw_data->serialnumber));
		tdisk_info->lba_shift = raw_data->lba_shift;
		if (!tdisk_info->lba_shift)
			tdisk_info->lba_shift = LBA_SHIFT;
		tdisk_info->size = raw_data->size;
		tdisk_info->threshold = raw_data->threshold;
	}
	memcpy(&tdisk->stats, &raw_data->stats, sizeof(tdisk->stats));
	memcpy(&tdisk->mirror_state, &raw_data->mirror_state, sizeof(tdisk->mirror_state));
	if (atomic_test_bit(VDISK_CLONE_ERROR, &raw_data->flags))
		tdisk_set_clone_error(tdisk);
	if (atomic_test_bit(V2_VDISK, &raw_data->flags))
		atomic_set_bit(V2_VDISK, &tdisk->flags);
	if (atomic_test_bit(VDISK_IN_DELETE, &raw_data->flags))
		atomic_set_bit(VDISK_IN_DELETE, &tdisk->flags);
	if (atomic_test_bit(VDISK_IN_RESIZE, &raw_data->flags))
		atomic_set_bit(VDISK_IN_RESIZE, &tdisk->flags);
	tdisk->threshold = raw_data->threshold;
	if (atomic_test_bit(VDISK_ENABLE_PROPERTIES, &raw_data->flags)) {
		TDISK_GET_PROP(tdisk, enable_deduplication, raw_data, VDISK_ENABLE_DEDUPLICATION);
		TDISK_GET_PROP(tdisk, enable_compression, raw_data, VDISK_ENABLE_COMPRESSION);
		TDISK_GET_PROP(tdisk, enable_verify, raw_data, VDISK_ENABLE_VERIFY);
		if (tdisk_info) {
			tdisk_info->enable_deduplication = tdisk->enable_deduplication;
			tdisk_info->enable_compression = tdisk->enable_compression;
			tdisk_info->enable_verify = tdisk->enable_verify;
		}
	}
	else if (tdisk_info) {
		tdisk->enable_deduplication = tdisk_info->enable_deduplication;
		tdisk->enable_compression = tdisk_info->enable_compression;
		tdisk->enable_verify = tdisk_info->enable_verify;
	}

	retval = tdisk_alloc_amap_groups(tdisk);
	if (unlikely(retval != 0))
		return -1;

	for (i = 0; i < tdisk->table_index_max; i++) {
		struct bdevint *bint;

		bint = bdev_find(BLOCK_BID(raw_data->table_pad[i]));
		if (unlikely(!bint)) {
			debug_warn("%d Cannot find bid at %u tdisk bid %u\n", i, BLOCK_BID(raw_data->table_pad[i]), tdisk_bint(tdisk)->bid);
			return -1;
		}
		b_start = BLOCK_BLOCKNR(raw_data->table_pad[i]);

		table_index = &tdisk->table_index[i];
		table_index->b_start = b_start;
		table_index->bint = bint;
		table_index->metadata = vm_pg_alloc(0);
		if (unlikely(!table_index->metadata))
			return -1;

		table_index->table_index_lock = sx_alloc("table index lock");
		table_index->table_index_wait = wait_chan_alloc("table index wait");
		retval = qs_lib_bio_lba(table_index->bint, table_index->b_start, table_index->metadata, QS_IO_READ, TYPE_TDISK_INDEX);
		if (unlikely(retval != 0))
			return -1;
	}
	return 0;
}

char *
tdisk_name(struct tdisk *tdisk)
{
	return tdisk->name;
}

static int
tdisk_initialize_index(struct tdisk *tdisk, uint8_t *name)
{
	struct raw_index_data *raw_data;
	pagestruct_t *page;
	uint64_t b_start;
	int retval = 0;
	int i;
	struct amap_table_index *table_index;
	uint64_t index_b_start;

	if (unlikely(!tdisk_bint(tdisk)))
	{
		debug_warn("Could not allocate disk index\n");
		return -1;
	}

	index_b_start = bdev_get_disk_index_block(tdisk_bint(tdisk), tdisk->target_id);

	page = vm_pg_alloc(VM_ALLOC_ZERO);
	if (unlikely(!page))
		return -1;

	tdisk->metadata = page;
	raw_data = (struct raw_index_data *)(vm_pg_address(page));
	memcpy(raw_data->magic, DISK_INDEX_MAGIC, strlen(DISK_INDEX_MAGIC));
	raw_index_set_name(raw_data, name);
	memcpy(raw_data->serialnumber, tdisk->unit_identifier.serial_number, 32);
	raw_data->group_id = tdisk->group->group_id;
	raw_data->target_id = tdisk->target_id;
	raw_data->size = tdisk->end_lba << tdisk->lba_shift;
	raw_data->lba_shift = tdisk->lba_shift;
	raw_data->threshold = tdisk->threshold;
	atomic_set_bit(V2_VDISK, &raw_data->flags);
	atomic_set_bit(VDISK_ENABLE_PROPERTIES, &raw_data->flags);
	TDISK_SET_PROP(tdisk, enable_deduplication, raw_data, VDISK_ENABLE_DEDUPLICATION);
	TDISK_SET_PROP(tdisk, enable_compression, raw_data, VDISK_ENABLE_COMPRESSION);
	TDISK_SET_PROP(tdisk, enable_verify, raw_data, VDISK_ENABLE_VERIFY);
	mark_v2_tdisk(tdisk);

	retval = tdisk_alloc_amap_groups(tdisk);
	if (unlikely(retval != 0))
		return -1;

	for (i = 0; i < tdisk->table_index_max; i++) 
	{
		struct bdevint *bint;
		struct index_info index_info;

		bzero(&index_info, sizeof(index_info));
		b_start = bdev_alloc_block(tdisk->group, BINT_INDEX_META_SIZE, &bint, &index_info, TYPE_META_BLOCK);
		if (unlikely(!b_start)) {
			debug_warn("Failed to alloc block for amap table %d\n", i);
			retval = -1;
			break;
		}

		index_info_sync(index_info.index, &index_info);
		free_iowaiter(&index_info.iowaiter);
		index_put(index_info.index);

		SET_BLOCK(raw_data->table_pad[i], b_start, bint->bid);
		table_index = &tdisk->table_index[i];
		table_index->b_start = b_start;
		table_index->bint = bint;
		table_index->metadata = vm_pg_alloc(VM_ALLOC_ZERO);
		if (unlikely(!table_index->metadata)) {
			retval = -1;
			break;
		}

		table_index->table_index_lock = sx_alloc("table index lock");
		table_index->table_index_wait = wait_chan_alloc("table index wait");
		retval = qs_lib_bio_lba(table_index->bint, table_index->b_start, table_index->metadata, QS_IO_WRITE, TYPE_TDISK_INDEX);
		if (unlikely(retval != 0)) {
			debug_warn("Failed to sync amap table i %d\n", i);
			break;
		}
	}

	if (unlikely(retval != 0)) {
		return -1;
	}

	retval = qs_lib_bio_lba(tdisk_bint(tdisk), index_b_start, page, QS_IO_WRITE, TYPE_TDISK_INDEX);

	if (unlikely(retval != 0))
		debug_warn("disk index sync failed for %u\n", tdisk->target_id);

	return retval;
}

static void 
tdisk_update_peers(struct tdisk *tdisk, uint64_t new_size, int reduc)
{
	struct vdisk_update_spec spec;

	node_tdisk_update_send(tdisk);

	if (reduc) {
		spec.enable_deduplication = tdisk->enable_deduplication;
		spec.enable_compression = tdisk->enable_compression;
		spec.enable_verify = tdisk->enable_verify;
		spec.threshold = tdisk->threshold;
		spec.end_lba = new_size >> tdisk->lba_shift;
		tdisk_mirror_update_properties(tdisk, &spec);
	}
	else {
		tdisk_mirror_resize(tdisk, new_size);
	}
}

int
tdisk_reinitialize_index_reduc(struct tdisk *tdisk, uint64_t new_size)
{
	struct raw_index_data *raw_data;
	pagestruct_t *page;
	uint64_t new_end_lba;
	struct lba_write *lba_write;
	uint64_t index_b_start;
	int retval;

	debug_info("new size %llu old size %llu\n", (unsigned long long)new_size, (unsigned long long)(tdisk->end_lba << tdisk->lba_shift));
	new_end_lba = new_size >> tdisk->lba_shift;

	page = vm_pg_alloc(VM_ALLOC_ZERO);
	if (unlikely(!page))
		return -1;

	/* Flush all pending commands */
	lba_write = tdisk_add_lba_write(tdisk, 0, 1, 0, QS_IO_WRITE, 1);

	tdisk_lock(tdisk);
	memcpy(vm_pg_address(page), vm_pg_address(tdisk->metadata), LBA_SIZE);

	raw_data = (struct raw_index_data *)(vm_pg_address(page));
	if (!raw_data->max_size)
		raw_data->max_size = raw_data->size;
	raw_data->size = new_size;

	index_b_start = bdev_get_disk_index_block(tdisk_bint(tdisk), tdisk->target_id);

	atomic_set_bit(VDISK_IN_RESIZE, &raw_data->flags);
	atomic_set_bit(VDISK_IN_RESIZE, &tdisk->flags);
	retval = qs_lib_bio_lba(tdisk_bint(tdisk), index_b_start, page, QS_IO_WRITE, TYPE_TDISK_INDEX);
	if (unlikely(retval != 0)) {
		debug_warn("disk index sync failed for %u\n", tdisk->target_id);
		vm_pg_free(page);
	}
	else {
		debug_info("setting new parameters for tdisk\n");

		vm_pg_free(tdisk->metadata);
		tdisk->metadata = page;
		tdisk->end_lba = new_end_lba;
	}
	
	tdisk_unlock(tdisk);
	tdisk_remove_lba_write(tdisk, &lba_write);
	return 0;
}

int
tdisk_reinitialize_index(struct tdisk *tdisk, uint64_t new_size, int update_size)
{
	struct raw_index_data *raw_data;
	struct lba_write *lba_write;
	pagestruct_t *page;
	struct amap_table_index *table_index;
	uint64_t end_lba = new_size >> LBA_SHIFT;
	uint64_t b_start, index_b_start;
	int retval = 0, i, need_update = 0;
	uint32_t table_index_max, amap_table_max, amap_table_group_max;

	debug_info("new size %llu end lba %llu tdisk end lba %llu\n", (unsigned long long)new_size, (unsigned long long)end_lba, (unsigned long long)tdisk->end_lba);
	page = vm_pg_alloc(VM_ALLOC_ZERO);
	if (unlikely(!page))
		return -1;

	/* Flush all pending commands */
	lba_write = tdisk_add_lba_write(tdisk, 0, 1, 0, QS_IO_WRITE, 1);

	tdisk_lock(tdisk);
	memcpy(vm_pg_address(page), vm_pg_address(tdisk->metadata), LBA_SIZE);

	raw_data = (struct raw_index_data *)(vm_pg_address(page));
	debug_info("before end lba %llu raw size %llu max size %llu\n", (unsigned long long)tdisk->end_lba, (unsigned long long)raw_data->size, (unsigned long long)raw_data->max_size);
	amap_table_max = end_lba / LBAS_PER_AMAP_TABLE;
	if (end_lba % LBAS_PER_AMAP_TABLE)
		amap_table_max++;

	table_index_max = amap_table_max >> INDEX_TABLE_GROUP_SHIFT; 
	if (amap_table_max & INDEX_TABLE_GROUP_MASK)
		table_index_max++; 

	amap_table_group_max = amap_table_max >> AMAP_TABLE_GROUP_SHIFT;
	if (amap_table_max & AMAP_TABLE_GROUP_MASK)
		amap_table_group_max++;

	if (raw_data->max_size && raw_data->max_size >= new_size) { 
		debug_info("skipping\n");
		goto skip;
	}

	debug_info("need update\n");
	need_update = 1;

	debug_info("tdisk table index max %u table index max %u\n", tdisk->table_index_max, table_index_max);
	debug_info("tdisk amap table  max %u amap table  max %u\n", tdisk->amap_table_max, amap_table_max);
	for (i = tdisk->table_index_max; i < table_index_max; i++) {
		struct bdevint *bint;
		struct index_info index_info;

		bzero(&index_info, sizeof(index_info));
		b_start = bdev_alloc_block(tdisk->group, BINT_INDEX_META_SIZE, &bint, &index_info, TYPE_META_BLOCK);
		if (unlikely(!b_start)) {
			debug_warn("Failed to alloc block for amap table %d\n", i);
			retval = -1;
			break;
		}

		index_info_sync(index_info.index, &index_info);
		free_iowaiter(&index_info.iowaiter);
		index_put(index_info.index);

		SET_BLOCK(raw_data->table_pad[i], b_start, bint->bid);
		table_index = &tdisk->table_index[i];
		table_index->b_start = b_start;
		table_index->bint = bint;
		table_index->metadata = vm_pg_alloc(VM_ALLOC_ZERO);
		if (unlikely(!table_index->metadata)) {
			retval = -1;
			break;
		}

		table_index->table_index_lock = sx_alloc("table index lock");
		table_index->table_index_wait = wait_chan_alloc("table index wait");
		retval = qs_lib_bio_lba(table_index->bint, table_index->b_start, table_index->metadata, QS_IO_WRITE, TYPE_TDISK_INDEX);
		if (unlikely(retval != 0)) {
			debug_warn("Failed to sync amap table i %d\n", i);
			break;
		}
	}

	if (unlikely(retval != 0)) {
		tdisk_unlock(tdisk);
		vm_pg_free(page);
		tdisk_remove_lba_write(tdisk, &lba_write);
		return -1;
	}

	retval = __tdisk_alloc_amap_groups(tdisk, amap_table_max);
	if (unlikely(retval != 0)) {
		tdisk_unlock(tdisk);
		vm_pg_free(page);
		tdisk_remove_lba_write(tdisk, &lba_write);
		return -1;
	}

skip:
	index_b_start = bdev_get_disk_index_block(tdisk_bint(tdisk), tdisk->target_id);
	if (update_size)
		raw_data->size = new_size;
	raw_data->max_size = new_size;

	retval = qs_lib_bio_lba(tdisk_bint(tdisk), index_b_start, page, QS_IO_WRITE, TYPE_TDISK_INDEX);
	if (unlikely(retval != 0)) {
		debug_warn("disk index sync failed for %u\n", tdisk->target_id);
		vm_pg_free(page);
	}
	else {
		debug_info("setting new parameters for tdisk\n");
		vm_pg_free(tdisk->metadata);
		tdisk->metadata = page;
		debug_info("tdisk amap table max %u table index max %u table group max %u end_lba %llu\n", tdisk->amap_table_max, tdisk->table_index_max, tdisk->amap_table_group_max, (unsigned long long)tdisk->end_lba);
		debug_info("amap table max %u table index max %u table group max %u end lba %llu\n", amap_table_max, table_index_max, amap_table_group_max, (unsigned long long)end_lba);
		debug_info("need update %d\n", need_update);
		if (need_update) {
			tdisk->amap_table_max = amap_table_max;
			tdisk->table_index_max = table_index_max;
			tdisk->amap_table_group_max = amap_table_group_max;
		}
		if (update_size)
			tdisk->end_lba = (new_size >> tdisk->lba_shift);
	}

	debug_info("after end lba %llu raw size %llu max size %llu\n", (unsigned long long)tdisk->end_lba, (unsigned long long)raw_data->size, (unsigned long long)raw_data->max_size);
	tdisk_unlock(tdisk);
	tdisk_remove_lba_write(tdisk, &lba_write);
	return retval;
}

void
tdisk_start_resize_thread(struct tdisk *tdisk)
{
	uint64_t cur_size;

	if (!atomic_test_bit(VDISK_IN_RESIZE, &tdisk->flags))
		return;

	tdisk_mirror_lock(tdisk);
	if (tdisk->delete_task) {
		tdisk_mirror_unlock(tdisk);
		return;
	}
	cur_size = tdisk->end_lba << tdisk->lba_shift;
	debug_info("starting resize for cur size %llu\n", (unsigned long long)cur_size);
	vdisk_delete(tdisk, cur_size);
	tdisk_mirror_unlock(tdisk);
}

int
target_set_role(struct tdisk_info *tdisk_info, unsigned long arg)
{
	struct tdisk *tdisk;

	if (!atomic_read(&kern_inited))
		return -1;

	if (tdisk_info->tl_id >= TL_MAX_DEVICES)
		return -1;

	tdisk = tdisks[tdisk_info->tl_id];
	if (!tdisk)
		return -1; 

	debug_info("tdisk current role %s to set to %s\n", mirror_role_str(tdisk->mirror_state.mirror_role), mirror_role_str(tdisk_info->mirror_state.mirror_role));
	return tdisk_mirror_set_role(tdisk, tdisk_info->mirror_state.mirror_role);
}

int
target_rename_disk(struct tdisk_info *tdisk_info, unsigned long arg)
{
	char prev_name[TDISK_MAX_NAME_LEN];
	struct tdisk *tdisk;
	int retval;

	if (!atomic_read(&kern_inited))
		return -1;

	if (tdisk_info->tl_id >= TL_MAX_DEVICES)
		return -1;

	tdisk = tdisks[tdisk_info->tl_id];
	if (!tdisk)
		return -1; 

	tdisk_lock(tdisk);
	atomic_set_bit(VDISK_SYNC_START, &tdisk->flags);
	strcpy(prev_name, tdisk->name);
	strcpy(tdisk->name, tdisk_info->name);
	retval = __tdisk_sync(tdisk, 0);
	if (unlikely(retval != 0)) {
		strcpy(tdisk->name, prev_name);
	}
	tdisk_unlock(tdisk);
	return retval;
}

int
target_resize_disk(struct tdisk_info *tdisk_info, unsigned long arg)
{
	struct tdisk *tdisk;
	int retval;
	uint64_t cur_size;
	int reduc;

	if (!atomic_read(&kern_inited))
		return -1;

	if (tdisk_info->tl_id >= TL_MAX_DEVICES) {
		return -1;
	}

	tdisk = tdisks[tdisk_info->tl_id];
	if (!tdisk)
		return -1; 

	if (tdisk_mirroring_configured(tdisk) && !tdisk_mirror_master(tdisk)) {
		debug_warn("Cannot resize on slave node\n");
		return -1;
	}

	tdisk_stop_delete_thread(tdisk);

	cur_size = tdisk->end_lba << tdisk->lba_shift;

	if (tdisk_info->size > cur_size) {
		retval = tdisk_reinitialize_index(tdisk, tdisk_info->size, 1);
		reduc = 0;
	} else {
		retval = tdisk_reinitialize_index_reduc(tdisk, tdisk_info->size);
		reduc = 1;
	}

	if (retval == 0)
		tdisk_update_peers(tdisk, tdisk_info->size, reduc);

	if (unlikely(retval != 0)) {
		debug_warn("reinitialize index failed\n");
		return -1;
	}
	else
		cbs_update_device(tdisk);

	tdisk_start_resize_thread(tdisk);
	return 0;
}

int
target_new_disk(struct tdisk_info *tdisk_info, unsigned long arg)
{
	struct tdisk *tdisk;
	int tl_id, retval;
	struct bdevgroup *group;

	if (!atomic_read(&kern_inited))
		return -1;

	if (tdisk_info->size > MAX_TARGET_SIZE) {
		debug_warn("Maxium target size exceeded\n");
		return -1;
	}

	group = bdev_group_locate(tdisk_info->group_id, NULL);
	if (unlikely(!group)) {
		debug_warn("Cannot locate tdisk pool at %u\n", tdisk_info->group_id);
		return -1;
	}

	if (atomic_read(&group->log_error)) {
		return -1;
	}

	tl_id = get_next_device_id();
	if (tl_id < 0) {
		debug_warn("Failed to get a new device id\n");
		return -1;
	}

	tdisk = __uma_zalloc(tdisk_cache, Q_NOWAIT | Q_ZERO, sizeof(*tdisk));
	if (unlikely(!tdisk))
	{
		debug_warn("Slab allocation failure\n");
		return -1;
	}
	tdisk_init(tdisk);

	strcpy(tdisk->name, tdisk_info->name);
	tdisk->group = group;
	tdisk->enable_deduplication = tdisk_info->enable_deduplication;
	tdisk->enable_compression = tdisk_info->enable_compression;
	tdisk->enable_verify = tdisk_info->enable_verify;
	tdisk->threshold = tdisk_info->threshold;
	tdisk->lba_shift = tdisk_info->lba_shift;
	if (!tdisk->lba_shift)
		tdisk->lba_shift = LBA_SHIFT;
	tdisk->end_lba = (tdisk_info->size >> tdisk->lba_shift);
	tdisk->target_id = tdisk_info->target_id;
	tdisk_initialize(tdisk, tdisk_info->serialnumber);

	retval = tdisk_initialize_index(tdisk, tdisk_info->name);
	if (unlikely(retval != 0)) {
		debug_warn("initialize index failed\n");
		tdisk_put(tdisk);
		return -1;
	}

	retval = kernel_thread_create(tdisk_free_thread, tdisk, tdisk->free_task, "tdfreet%u", tl_id);
	if (unlikely(retval != 0)) {
		tdisk_put(tdisk);
		return -1;
	}

	retval = kernel_thread_create(tdisk_sync_thread, tdisk, tdisk->sync_task, "tdsynct%u", tl_id);
	if (unlikely(retval != 0)) {
		tdisk_put(tdisk);
		return -1;
	}

	tdisk->bus = tl_id;
	tdisk_insert(tdisk, tl_id, tdisk_info->target_id);

	if (tdisk_info->attach) {
		cbs_new_device(tdisk, 0);
		tdisk_info->iscsi_tid = tdisk->iscsi_tid;
		tdisk_info->vhba_id = tdisk->vhba_id;
	}

	tdisk_info->tl_id = tl_id;
	tdisk_info->v2_format = is_v2_tdisk(tdisk);
	memcpy(tdisk_info->serialnumber, tdisk->unit_identifier.serial_number, 32);
	atomic_set_bit(VDISK_SYNC_START, &tdisk->flags);
	tdisk_sync(tdisk, 0);
#ifdef FREEBSD
	memcpy((void *)arg, tdisk_info, offsetof(struct tdisk_info, q_entry));
#else
	retval = copyout(tdisk_info, (void *)arg, offsetof(struct tdisk_info, q_entry));
	if (unlikely(retval != 0)) {
		tdisk_info->free_alloc = 1;
		target_delete_disk(tdisk_info, arg);
		return -1;
	}
#endif
	return 0;
}

int
tdisk_cmd_persistent_reserve_in(struct tdisk *tdisk, struct qsio_scsiio *ctio)
{
	uint8_t *cdb = ctio->cdb;
	uint8_t service_action;
	uint16_t allocation_length;
	int retval;

	service_action = (cdb[1] & 0x1F);
	allocation_length = be16toh(*((uint16_t*)(&cdb[7])));

	debug_info("service action %x allocation length %d\n", service_action, allocation_length);
	if (allocation_length < 8)
	{
		ctio_construct_sense(ctio, SSD_CURRENT_ERROR, SSD_KEY_ILLEGAL_REQUEST, 0, INVALID_FIELD_IN_CDB_ASC, INVALID_FIELD_IN_CDB_ASCQ);  
		return 0;
	}

	tdisk_reservation_lock(tdisk);
	if (service_action == SERVICE_ACTION_READ_KEYS)
	{
		retval = persistent_reservation_read_keys(ctio, allocation_length, &tdisk->reservation);
	}
	else if (service_action == SERVICE_ACTION_READ_RESERVATIONS)
	{
		retval = persistent_reservation_read_reservations(ctio, allocation_length, &tdisk->reservation);
	}
	else if (service_action == SERVICE_ACTION_READ_CAPABILITIES)
	{
		retval = persistent_reservation_read_capabilities(ctio, allocation_length);
	}
	else if (service_action == SERVICE_ACTION_READ_FULL)
	{
		retval = persistent_reservation_read_full(ctio, allocation_length, &tdisk->reservation);
	} 
	else
	{
		ctio_construct_sense(ctio, SSD_CURRENT_ERROR, SSD_KEY_ILLEGAL_REQUEST, 0, INVALID_FIELD_IN_CDB_ASC, INVALID_FIELD_IN_CDB_ASCQ);  
		retval = 0;
	}
	tdisk_reservation_unlock(tdisk);
	return retval;
}

int
tdisk_cmd_persistent_reserve_out(struct tdisk *tdisk, struct qsio_scsiio *ctio)
{
	uint8_t *cdb = ctio->cdb;
	uint8_t service_action;
	uint8_t scope;
	uint32_t parameter_list_length;
	int retval;

	retval = tdisk_mirror_cmd_generic(tdisk, ctio, 1);
	if (retval) {
		ctio_free_data(ctio);
		return 0;
	}

	scope = READ_NIBBLE_HIGH(cdb[2]);

	if (scope)
	{
		ctio_free_data(ctio);
		ctio_construct_sense(ctio, SSD_CURRENT_ERROR, SSD_KEY_ILLEGAL_REQUEST, 0, INVALID_FIELD_IN_CDB_ASC, INVALID_FIELD_IN_CDB_ASCQ);  
		return 0;
	}

	service_action = (cdb[1] & 0x1F);

	parameter_list_length = be32toh(*(uint32_t *)(&cdb[5]));

	if (parameter_list_length != 24)
	{
		ctio_free_data(ctio);
		ctio_construct_sense(ctio, SSD_CURRENT_ERROR, SSD_KEY_ILLEGAL_REQUEST, 0,  PARAMETER_LIST_LENGTH_ERROR_ASC,  PARAMETER_LIST_LENGTH_ERROR_ASCQ);
		return 0;
	}

	debug_info("scope %x service action %x parameter list length %d\n", scope, service_action, parameter_list_length);
	tdisk_reservation_lock(tdisk);
	switch(service_action)
	{
		case SERVICE_ACTION_REGISTER:
			retval = persistent_reservation_handle_register(tdisk, ctio);
			break;
		case SERVICE_ACTION_REGISTER_IGNORE:
			retval = persistent_reservation_handle_register_and_ignore(tdisk, ctio);
			break;
		case SERVICE_ACTION_RESERVE:
			retval = persistent_reservation_handle_reserve(tdisk, ctio);
			break;
		case SERVICE_ACTION_RELEASE:
			retval = persistent_reservation_handle_release(tdisk, ctio);
			break;
		case SERVICE_ACTION_CLEAR:
			retval = persistent_reservation_handle_clear(tdisk, ctio);
			break;
		case SERVICE_ACTION_PREEMPT:
			retval = persistent_reservation_handle_preempt(tdisk, ctio, 0);
			break;
		case SERVICE_ACTION_PREEMPT_ABORT:
			retval = persistent_reservation_handle_preempt(tdisk, ctio, 1);
			break;
		default:
			ctio_construct_sense(ctio, SSD_CURRENT_ERROR, SSD_KEY_ILLEGAL_REQUEST, 0, INVALID_FIELD_IN_CDB_ASC, INVALID_FIELD_IN_CDB_ASCQ);  
			retval = 0;
	}
	tdisk_reservation_unlock(tdisk);

	ctio_free_data(ctio);
	return retval;
}

int
tdisk_cmd_reserve(struct tdisk *tdisk, struct qsio_scsiio *ctio)
{
	tdisk_reservation_lock(tdisk);
	if (tdisk_cmd_access_ok(tdisk, ctio) != 0) {
		tdisk_reservation_unlock(tdisk);
		ctio->scsi_status = SCSI_STATUS_RESERV_CONFLICT;
		return 0;
	}
	tdisk->reservation.is_reserved = 1;
	tdisk->reservation.type = RESERVATION_TYPE_RESERVE;
	port_fill(tdisk->reservation.i_prt, ctio->i_prt);
	port_fill(tdisk->reservation.t_prt, ctio->t_prt);
	tdisk->reservation.init_int = ctio->init_int;
	node_reservation_sync_send(tdisk, &tdisk->reservation);
	tdisk_reservation_unlock(tdisk);
	return 0;
}

int
tdisk_cmd_release(struct tdisk *tdisk, struct qsio_scsiio *ctio)
{
	tdisk_reservation_lock(tdisk);
	if (iid_equal(tdisk->reservation.i_prt, tdisk->reservation.t_prt, tdisk->reservation.init_int, ctio->i_prt, ctio->t_prt, ctio->init_int))
	{
		tdisk->reservation.is_reserved = 0;
		node_reservation_sync_send(tdisk, &tdisk->reservation);
	}
	tdisk_reservation_unlock(tdisk);
	return 0;
}

int
tdisk_cmd_request_sense(struct tdisk *tdisk, struct qsio_scsiio *ctio)
{
	struct initiator_state *istate;

	istate = ctio->istate;
	debug_check(!istate);

	tdisk_reservation_lock(tdisk);
	device_request_sense(ctio, istate);
	tdisk_reservation_unlock(tdisk);
	return 0;
}

static void
copy_current_caching_mode_page(uint8_t *buffer, int min_len)
{
	struct caching_mode_page page;

	tdisk_init_caching_mode_page(&page);
	memcpy(buffer, &page, min_len);
	return;
}

struct disconnect_reconnect_page disreconn_page = {
	.page_code = DISCONNECT_RECONNECT_PAGE,
	.page_length = 0xE,
};

static inline void
copy_current_disconnect_reconnect_page(uint8_t *buffer, int min_len)
{
	memcpy(buffer, &disreconn_page, min_len);
	return;
}

struct logical_block_provisioning_mode_page lbp_mode_page =  {
	.page_code = LOGICAL_BLOCK_PROVISIONING_MODE_PAGE,
	.subpage_code = 0x2,
	.page_length = 0x14,
	.situa = 0x1,
};

static void
copy_current_logical_block_provisioning_mode_page(struct tdisk *tdisk, uint8_t *buffer, int min_len, int threshold)
{
	struct logical_block_provisioning_mode_page tmp_page;
	struct threshold_descriptor *desc;
	int set_size = tdisk->lba_shift == LBA_SHIFT ? THRESHOLD_SET_SIZE : THRESHOLD_SET_SIZE_LEGACY;
	uint64_t count = align_size(((tdisk->end_lba << tdisk->lba_shift) / 100) * threshold, 1 << set_size);
	uint64_t set = (count >> tdisk->lba_shift) >> set_size;

	bzero(&tmp_page, sizeof(tmp_page));
	memcpy(&tmp_page, &lbp_mode_page, offsetof(struct logical_block_provisioning_mode_page, desc));
	desc = &tmp_page.desc;
	desc->threshold_type = 0x80;
	desc->threshold_resource = 0x01;
	desc->threshold_count = htobe32(set);
	memcpy(buffer, &tmp_page, min_len);
}

struct rw_error_recovery_page rw_error_recovery_page = {
	.page_code = READ_WRITE_ERROR_RECOVERY_PAGE,
	.page_length = 0x0A,
	.tpere = 0x80,
};

static void
copy_current_rw_error_recovery_page(uint8_t *buffer, int min_len)
{
	memcpy(buffer, &rw_error_recovery_page, min_len);
	return;
}

struct control_mode_page control_mode_page = {
	.page_code = CONTROL_MODE_PAGE,
	.page_length = 0x0A,
	.tst = 0x20,
	.tas = 0x40,
};

static void
copy_current_control_mode_page(uint8_t *buffer, int min_len)
{
	memcpy(buffer, &control_mode_page, min_len);
	return;
}

static int
mode_sense_current_values(struct tdisk *tdisk, uint8_t *buffer, uint16_t allocation_length, uint8_t page_code, int *start_offset)
{
	int offset = *start_offset;
	int avail = 0;
	int min_len;
	int threshold = tdisk->threshold;

	if (page_code == ALL_PAGES || page_code == CACHING_MODE_PAGE) {
		min_len = min_t(int, sizeof(struct caching_mode_page), allocation_length - offset);
		if (min_len > 0) {
			copy_current_caching_mode_page(buffer+offset, min_len);
			offset += min_len;
		}
		avail += sizeof(struct caching_mode_page);
	}

	if (page_code == ALL_PAGES || page_code == CONTROL_MODE_PAGE) {
		min_len = min_t(int, sizeof(struct control_mode_page), allocation_length - offset); 
		if (min_len > 0) {
			copy_current_control_mode_page(buffer+offset, min_len);
			offset += min_len;
		}
		avail += sizeof(struct control_mode_page);
	}

	if (threshold && (page_code == ALL_PAGES || page_code == LOGICAL_BLOCK_PROVISIONING_MODE_PAGE)) {
		min_len = min_t(int, sizeof(struct logical_block_provisioning_mode_page), allocation_length - offset); 
		if (min_len > 0) {
			copy_current_logical_block_provisioning_mode_page(tdisk, buffer+offset, min_len, threshold);
			offset += min_len;
		}
		avail += sizeof(struct logical_block_provisioning_mode_page);
	}

	if (page_code == ALL_PAGES || page_code == READ_WRITE_ERROR_RECOVERY_PAGE) {
		min_len = min_t(int, sizeof(struct rw_error_recovery_page), allocation_length - offset); 
		if (min_len > 0) {
			copy_current_rw_error_recovery_page(buffer+offset, min_len);
			offset += min_len;
		}
		avail += sizeof(struct rw_error_recovery_page);
	}

	*start_offset = offset;
	return avail;
}

static inline int
mode_sense_changeable_values(struct tdisk *tdisk, uint8_t *buffer, uint16_t allocation_length, uint8_t page_code, int *start_offset)
{
	return mode_sense_current_values(tdisk, buffer, allocation_length, page_code, start_offset);
}

static int
mode_sense_default_values(struct tdisk *tdisk, uint8_t *buffer, uint16_t allocation_length, uint8_t page_code, int *start_offset)
{
	return mode_sense_current_values(tdisk, buffer, allocation_length, page_code, start_offset);
}

static int
mode_sense_saved_values(struct tdisk *tdisk, uint8_t *buffer, uint16_t allocation_length, uint8_t page_code, int *start_offset)
{
	return mode_sense_current_values(tdisk, buffer, allocation_length, page_code, start_offset);
}

static int
mode_sense_block_descriptor(struct tdisk *tdisk, uint8_t *buffer, uint16_t allocation_length, int *start_offset)
{
	int offset = *start_offset;
	int min_len;
	uint32_t *ptr;
	uint64_t blocks;

	min_len = min_t(int, 8, allocation_length - offset);
	if (min_len > 0) {
		ptr = (uint32_t *)(buffer+offset);
		blocks = tdisk->end_lba;
		ptr[0] = (blocks > 0xFFFFFFFFULL) ? 0xFFFFFFFFU : htobe32(blocks - 1);
		ptr[1] = htobe32(1U << tdisk->lba_shift);
		offset += min_len;
	}

	*start_offset = offset;
	return 0;
}

int
tdisk_cmd_mode_sense6(struct tdisk *tdisk, struct qsio_scsiio *ctio)
{
	uint8_t *cdb = ctio->cdb;
	uint8_t dbd;
	uint8_t pc, page_code;
	uint8_t allocation_length;
	int offset;
	struct mode_parameter_header6 *header;
	int avail;

	dbd = READ_BIT(cdb[1], 3);
	pc = cdb[2] >> 6;
	page_code = (cdb[2] & 0x3F);

	debug_info("page code %x dbd %d\n", page_code, dbd);
	allocation_length = cdb[4];
	if (!allocation_length)
	{
		return 0;
	}

	if (allocation_length < (sizeof(struct mode_parameter_header6) - offsetof(struct mode_parameter_header6, medium_type)))
	{
		ctio_construct_sense(ctio, SSD_CURRENT_ERROR, SSD_KEY_ILLEGAL_REQUEST, 0, INVALID_FIELD_IN_CDB_ASC, INVALID_FIELD_IN_CDB_ASCQ);  
		return 0;
	}


	ctio_allocate_buffer(ctio, allocation_length, Q_NOWAIT);
	if (unlikely(!ctio->data_ptr))
	{
		return -1;
	}

	bzero(ctio->data_ptr, allocation_length);
	/* Check if we can atleast send back the mode parameter header */
	header = (struct mode_parameter_header6 *)ctio->data_ptr;
	offset = min_t(int, allocation_length, sizeof(struct mode_parameter_header6));
 	avail = sizeof(struct mode_parameter_header6);
	if (!dbd)
	{
		mode_sense_block_descriptor(tdisk, ctio->data_ptr, allocation_length, &offset);
		header->block_descriptor_length = sizeof(struct mode_parameter_block_descriptor);
		avail += sizeof(struct mode_parameter_block_descriptor);
	}
	else
	{
		header->block_descriptor_length = 0;
	}

	switch (pc) {
		case MODE_SENSE_CURRENT_VALUES:
			avail += mode_sense_current_values(tdisk, ctio->data_ptr, allocation_length, page_code, &offset);
			break;
		case MODE_SENSE_CHANGEABLE_VALUES:
			break;
		case MODE_SENSE_DEFAULT_VALUES:
			avail += mode_sense_default_values(tdisk, ctio->data_ptr, allocation_length, page_code, &offset);
			break;
		case MODE_SENSE_SAVED_VALUES:
			avail += mode_sense_saved_values(tdisk, ctio->data_ptr, allocation_length, page_code, &offset);
			break;
	}

	header->mode_data_length = avail - offsetof(struct mode_parameter_header6, medium_type);
	ctio->dxfer_len = offset;
#ifdef ENABLE_DEBUG
	print_buffer(ctio->data_ptr, ctio->dxfer_len);
#endif
	return 0;
}

int
tdisk_cmd_mode_sense10(struct tdisk *tdisk, struct qsio_scsiio *ctio)
{
	uint8_t *cdb = ctio->cdb;
	uint8_t dbd;
	uint8_t pc, page_code;
	uint16_t allocation_length;
	int offset;
	struct mode_parameter_header10 *header;
	int avail;

	dbd = READ_BIT(cdb[1], 3);
	pc = cdb[2] >> 6;
	page_code = (cdb[2] & 0x3F);

	debug_info("page code %x dbd %d\n", page_code, dbd);
	allocation_length = be16toh(*(uint16_t *)(&cdb[7]));
	if (!allocation_length)
	{
		return 0;
	}

	if (allocation_length < (sizeof(struct mode_parameter_header10) - offsetof(struct mode_parameter_header10, medium_type)))
	{
		ctio_construct_sense(ctio, SSD_CURRENT_ERROR, SSD_KEY_ILLEGAL_REQUEST, 0, INVALID_FIELD_IN_CDB_ASC, INVALID_FIELD_IN_CDB_ASCQ);  
		return 0;
	}


	ctio_allocate_buffer(ctio, allocation_length, Q_NOWAIT);
	if (unlikely(!ctio->data_ptr))
	{
		return -1;
	}

	bzero(ctio->data_ptr, allocation_length);
	/* Check if we can atleast send back the mode parameter header */
	header = (struct mode_parameter_header10 *)ctio->data_ptr;
	offset = min_t(int, allocation_length, sizeof(struct mode_parameter_header10));
 	avail = sizeof(struct mode_parameter_header10);
	if (!dbd)
	{
		mode_sense_block_descriptor(tdisk, ctio->data_ptr, allocation_length, &offset);
		header->block_descriptor_length = htobe16(sizeof(struct mode_parameter_block_descriptor));
		avail += sizeof(struct mode_parameter_block_descriptor);
	}
	else
	{
		header->block_descriptor_length = 0;
	}

	switch (pc) {
		case MODE_SENSE_CURRENT_VALUES:
			avail += mode_sense_current_values(tdisk, ctio->data_ptr, allocation_length, page_code, &offset);
			break;
		case MODE_SENSE_CHANGEABLE_VALUES:
			break;
		case MODE_SENSE_DEFAULT_VALUES:
			avail += mode_sense_default_values(tdisk, ctio->data_ptr, allocation_length, page_code, &offset);
			break;
		case MODE_SENSE_SAVED_VALUES:
			avail += mode_sense_saved_values(tdisk, ctio->data_ptr, allocation_length, page_code, &offset);
			break;
	}

	header->mode_data_length = htobe16(avail - offsetof(struct mode_parameter_header10, medium_type));
	ctio->dxfer_len = offset;
#ifdef ENABLE_DEBUG
	print_buffer(ctio->data_ptr, ctio->dxfer_len);
#endif
	return 0;
}

int
tdisk_cmd_service_action_in(struct tdisk *tdisk, struct qsio_scsiio *ctio)
{
	uint8_t *cdb = ctio->cdb;
	uint8_t pmi;
	uint8_t service_action;
	uint64_t lba;
	uint32_t allocation_length;
	uint32_t *ptr;
	uint64_t *ptr64;
	uint8_t *ptr8;
	uint64_t blocks;

	lba = be64toh(*((uint64_t *)(&cdb[2])));
	allocation_length = be32toh(*((uint32_t *)(&cdb[10])));
	pmi = cdb[8] & 0x1;
	service_action = cdb[1] & 0x1F;

	if (!allocation_length)
		return 0;

	if ((lba && !pmi) || (service_action != 0x10)) {
		ctio_construct_sense(ctio, SSD_CURRENT_ERROR, SSD_KEY_ILLEGAL_REQUEST, 0, INVALID_FIELD_IN_CDB_ASC, INVALID_FIELD_IN_CDB_ASCQ);
		return 0;
	}

	ctio_allocate_buffer(ctio, 32, Q_NOWAIT);
	if (unlikely(!ctio->data_ptr))
		return -1;

	bzero(ctio->data_ptr, 32);
	ptr = (uint32_t *)ctio->data_ptr;
	ptr64 = (uint64_t *)ctio->data_ptr;
	blocks = tdisk->end_lba;
	ptr64[0] = htobe64(blocks - 1);
	ptr[2] = htobe32(1U << tdisk->lba_shift);
	ptr8 = ctio->data_ptr;
	ptr8[14] = 0x80; /* LBPME/TPE */
	ptr8[14] |= 0x40; /* LBPRZ/TPRZ */
	ctio->dxfer_len = allocation_length;
	return 0;
}

int
tdisk_cmd_read_capacity(struct tdisk *tdisk, struct qsio_scsiio *ctio)
{
	uint8_t *cdb = ctio->cdb;
	uint8_t pmi;
	uint32_t lba;
	uint32_t *ptr;
	uint64_t blocks;

	lba = be32toh(*((uint32_t *)(&cdb[2])));
	pmi = cdb[8] & 0x1;

	if (lba && !pmi) {
		ctio_construct_sense(ctio, SSD_CURRENT_ERROR, SSD_KEY_ILLEGAL_REQUEST, 0, INVALID_FIELD_IN_CDB_ASC, INVALID_FIELD_IN_CDB_ASCQ);
		return 0;
	}

	ctio_allocate_buffer(ctio, 8, Q_NOWAIT);
	if (unlikely(!ctio->data_ptr))
		return -1;

	bzero(ctio->data_ptr, 8);
	ptr = (uint32_t *)ctio->data_ptr;
	blocks = tdisk->end_lba;
	ptr[0] = (blocks > 0xFFFFFFFFULL) ? 0xFFFFFFFFU : htobe32(blocks - 1);
	ptr[1] = htobe32(1U << tdisk->lba_shift);
	return 0;
}

static int
tdisk_serial_number(struct tdisk *tdisk, uint8_t *buffer, int allocation_length)
{
	struct serial_number_page *page = (struct serial_number_page *)buffer;
	int min_len;

	page->device_type = T_DIRECT; /* peripheral qualifier */
	page->page_code = UNIT_SERIAL_NUMBER_PAGE;
	page->page_length =  32;
	memcpy(page->serial_number, tdisk->unit_identifier.serial_number, 32);

	min_len = min_t(int, allocation_length, sizeof(*page) + 32);
	return min_len;
}

static int
tdisk_device_identification(struct tdisk *tdisk, uint8_t *buffer, int allocation_length)
{
	struct device_identification_page *page = (struct device_identification_page *)buffer;
	struct logical_unit_identifier *unit_identifier;
	struct logical_unit_naa_identifier *naa_identifier;
	int idlength, t10_idlength, naa_idlength;
	int min_len;

	t10_idlength = tdisk->unit_identifier.identifier_length + sizeof(struct device_identifier);
	naa_idlength = tdisk->naa_identifier.identifier_length + sizeof(struct device_identifier);
	idlength = t10_idlength + naa_idlength;
	page->device_type = T_DIRECT;
	page->page_code = DEVICE_IDENTIFICATION_PAGE;
	page->page_length = idlength;

	unit_identifier = (struct logical_unit_identifier *)(buffer+sizeof(*page));
	memcpy(unit_identifier, &tdisk->unit_identifier, t10_idlength);

	naa_identifier = (struct logical_unit_naa_identifier *)(buffer+sizeof(*page)+t10_idlength);
	memcpy(naa_identifier, &tdisk->naa_identifier, naa_idlength);

	min_len = min_t(int, allocation_length, idlength + sizeof(*page));
	return min_len;
}

struct extended_inquiry_page extended_inquiry = {
	.device_type = T_DIRECT,
	.page_code = EXTENDED_INQUIRY_VPD_PAGE,
	.page_length = 0x3C,
	.simpsup = (0x01 | 0x02 | 0x04), /* Simple, Ordered, Head of Queue commands */
};

static int
tdisk_copy_extended_inquiry_vpd_page(uint8_t *buffer, int allocation_length)
{
	int min_len;

	min_len = min_t(int, allocation_length, sizeof(extended_inquiry));
	memcpy(buffer, &extended_inquiry, min_len);
	return min_len;
}

static int
tdisk_copy_logical_block_provisioning_vpd_page(struct tdisk *tdisk, uint8_t *buffer, int allocation_length)
{
	int min_len;
	struct logical_block_provisioning_page page;

	min_len = min_t(int, allocation_length, sizeof(page));
	tdisk_init_logical_block_provisioning_page(tdisk, &page);
	memcpy(buffer, &page, min_len);
	return min_len;
}

static int
tdisk_copy_block_device_characteristics_vpd_page(uint8_t *buffer, int allocation_length)
{
	struct block_device_characteristics_page tmp;
	int min_len;

	bzero(&tmp, sizeof(tmp));
	tmp.device_type = T_DIRECT;
	tmp.page_code = BLOCK_DEVICE_CHARACTERISTICS_VPD_PAGE;
	tmp.page_length = 0x3C;
	tmp.medium_rotation_rate = htobe16(0x3A98); /* NON-SSD type */
	tmp.form_factor = 0x3; /* 2.5 inch */

	min_len = min_t(int, allocation_length, sizeof(tmp));
	memcpy(buffer, &tmp, min_len);
	return min_len;
}

static int
tdisk_copy_block_limits_vpd_page(struct tdisk *tdisk, uint8_t *buffer, int allocation_length)
{
	int min_len;
	struct block_limits_page page;

	min_len = min_t(int, allocation_length, sizeof(page));
	tdisk_init_block_limits_page(tdisk, &page);
	memcpy(buffer, &page, min_len);
	return min_len;
}

struct evpd_page_info evpd_info  = {
	.num_pages = 0x07,
	.page_code[0] = VITAL_PRODUCT_DATA_PAGE,
	.page_code[1] = UNIT_SERIAL_NUMBER_PAGE,
	.page_code[2] = DEVICE_IDENTIFICATION_PAGE,
	.page_code[3] = EXTENDED_INQUIRY_VPD_PAGE,
	.page_code[4] = BLOCK_LIMITS_VPD_PAGE,
	.page_code[5] = BLOCK_DEVICE_CHARACTERISTICS_VPD_PAGE,
	.page_code[6] = LOGICAL_BLOCK_PROVISIONING_VPD_PAGE,
};

static int 
tdisk_copy_vital_product_page_info(uint8_t *buffer, int allocation_length)
{
	struct vital_product_page *page = (struct vital_product_page *)buffer;
	int i;

	bzero(page, sizeof(*page));
	page->device_type = T_DIRECT;
	page->page_code = 0x00;
	page->page_length = evpd_info.num_pages;

	for (i = 0; i < evpd_info.num_pages; i++) {
		page->page_type[i] = evpd_info.page_code[i];
	}

	return min_t(int, allocation_length, evpd_info.num_pages + sizeof(*page));
}

static int
tdisk_evpd_inquiry_data(struct tdisk *tdisk, struct qsio_scsiio *ctio, uint8_t page_code, uint16_t allocation_length)
{
	int retval;
	int max_allocation_length;

	max_allocation_length = max_t(int, 128, allocation_length);
	ctio_allocate_buffer(ctio, max_allocation_length, Q_NOWAIT);
	if (unlikely(!ctio->data_ptr))
		return -1;

	bzero(ctio->data_ptr, max_allocation_length);

	debug_info("page code %x\n", page_code);
	switch (page_code) {
	case UNIT_SERIAL_NUMBER_PAGE:
		retval = tdisk_serial_number(tdisk, ctio->data_ptr, allocation_length);
		break;
	case DEVICE_IDENTIFICATION_PAGE:
		retval = tdisk_device_identification(tdisk, ctio->data_ptr, allocation_length);
		break;
	case VITAL_PRODUCT_DATA_PAGE:
		retval = tdisk_copy_vital_product_page_info(ctio->data_ptr, allocation_length);
		break;
	case BLOCK_LIMITS_VPD_PAGE:
		retval = tdisk_copy_block_limits_vpd_page(tdisk, ctio->data_ptr, allocation_length);
		break;
	case BLOCK_DEVICE_CHARACTERISTICS_VPD_PAGE:
		retval = tdisk_copy_block_device_characteristics_vpd_page(ctio->data_ptr, allocation_length);
		break;
	case LOGICAL_BLOCK_PROVISIONING_VPD_PAGE:
		retval = tdisk_copy_logical_block_provisioning_vpd_page(tdisk, ctio->data_ptr, allocation_length);
		break;
	case EXTENDED_INQUIRY_VPD_PAGE:
		retval = tdisk_copy_extended_inquiry_vpd_page(ctio->data_ptr, allocation_length);
		break;
	default:
		debug_info("Invalid page code %x\n", page_code);
		ctio_free_data(ctio);
		ctio_construct_sense(ctio, SSD_CURRENT_ERROR, SSD_KEY_ILLEGAL_REQUEST, 0, INVALID_FIELD_IN_CDB_ASC, INVALID_FIELD_IN_CDB_ASCQ);
		retval = 0;
	}

	ctio->dxfer_len = retval;
#ifdef ENABLE_DEBUG
	print_buffer(ctio->data_ptr, ctio->dxfer_len);
#endif
	return 0;
}

static int
tdisk_standard_inquiry_data(struct qsio_scsiio *ctio, uint16_t allocation_length)
{
	uint16_t min_len;
	struct inquiry_data inquiry;

	min_len = min_t(uint16_t, allocation_length, sizeof(inquiry));
	ctio_allocate_buffer(ctio, min_len, Q_NOWAIT);
	if (unlikely(!ctio->data_ptr))
	{
		return -1;
	}

	tdisk_init_inquiry_data(&inquiry);
	ctio->scsi_status = SCSI_STATUS_OK;
	memcpy(ctio->data_ptr, &inquiry, min_len);
	return 0;
}

int
tdisk_cmd_inquiry(struct tdisk *tdisk, struct qsio_scsiio *ctio)
{
	uint8_t *cdb = ctio->cdb;
	int retval;
	uint16_t allocation_length;
	uint8_t evpd, page_code;

	evpd = READ_BIT(cdb[1], 0);

	page_code = cdb[2];
	allocation_length = be16toh(*(uint16_t *)(&cdb[3]));

	if (!evpd && page_code)
	{
		ctio_construct_sense(ctio, SSD_CURRENT_ERROR, SSD_KEY_ILLEGAL_REQUEST, 0, INVALID_FIELD_IN_CDB_ASC, INVALID_FIELD_IN_CDB_ASCQ);  
		return 0;
	}

	if (!allocation_length)
		return 0;

	if (!evpd)
		retval = tdisk_standard_inquiry_data(ctio, allocation_length);
	else
		retval = tdisk_evpd_inquiry_data(tdisk, ctio, page_code, allocation_length);

	if (ctio->dxfer_len && ctio->init_int == TARGET_INT_ISCSI && ctio->ccb_h.target_lun)
	{
		ctio->data_ptr[0] = 0x7F; /* Invalid LUN */
		ctio->dxfer_len = 1;
	}
	return retval;
}

int
tdisk_cmd_test_unit_ready(struct tdisk *tdisk, struct qsio_scsiio *ctio)
{
	if (!atomic_read(&kern_inited) || !tdisk_mirror_ready(tdisk)) {
		ctio_construct_sense(ctio, SSD_CURRENT_ERROR, SSD_KEY_NOT_READY, 0, LOGICAL_UNIT_IS_IN_PROCESS_OF_BECOMING_READY_ASC, LOGICAL_UNIT_IS_IN_PROCESS_OF_BECOMING_READY_ASCQ);
	}
	return 0;
}

void
amap_table_insert(struct amap_table_group *group, struct amap_table *amap_table)
{
	struct tdisk *tdisk = amap_table->tdisk;
	uint32_t group_offset = amap_table_group_offset(amap_table);

	group->amap_table[group_offset] = amap_table;
	TAILQ_INSERT_TAIL(&group->table_list, amap_table, t_list);
	atomic_inc(&tdisk->amap_table_count);
	if (atomic_read(&tdisk->amap_table_count) > cached_amap_tables) {
		atomic_set_bit(VDISK_FREE_START, &tdisk->flags);
		chan_wakeup_one_nointr(tdisk->free_wait);
	}
}

int
amap_table_init(struct tdisk *tdisk, struct amap_table_group *group, int atable_id, struct index_info_list *meta_index_info_list)
{
	uint64_t b_start;
	struct bdevint *bint;
	struct amap_table *amap_table;
	struct index_info *index_info;

	amap_table = amap_table_alloc(tdisk, atable_id);
	if (unlikely(!amap_table)) {
		debug_warn("Failed to alloc amap table\n");
		return -1;
	}

	index_info = index_info_alloc();
	if (unlikely(!index_info)) {
		debug_warn("Failed to alloc for index_info\n");
		amap_table_put(amap_table);
		return -1;
	}

	amap_table->metadata = vm_pg_alloc(VM_ALLOC_ZERO);
	if (unlikely(!amap_table->metadata)) {
		index_put(index_info->index);
		index_info_free(index_info);
		amap_table_put(amap_table);
		return -1;
	}

	b_start = bdev_alloc_block(tdisk->group, AMAP_TABLE_SIZE, &bint, index_info, TYPE_META_BLOCK);
	if (unlikely(!b_start)) {
		debug_warn("Getting a new block segment failed\n");
		index_info_free(index_info);
		amap_table_put(amap_table);
		pause("outofspc", OUT_OF_SPACE_PAUSE);
		return ERR_CODE_NOSPACE;
	}

	SET_BLOCK(amap_table->amap_table_block, b_start, bint->bid);
	atomic_set_bit_short(ATABLE_CSUM_CHECK_DONE, &amap_table->flags);
	index_info->block = amap_table->amap_table_block;
	index_info->meta_type = INDEX_INFO_TYPE_AMAP_TABLE;
	TAILQ_INSERT_HEAD(meta_index_info_list, index_info, i_list);

	atomic_set_bit_short(ATABLE_META_IO_PENDING, &amap_table->flags);
	atomic_set_bit_short(ATABLE_META_DATA_NEW, &amap_table->flags);
	amap_table_insert(group, amap_table);
	TDISK_INC(tdisk, amap_table_new, 1);
	return 0;
}

struct amap_table * 
amap_table_load_async(struct tdisk *tdisk, uint64_t block, struct amap_table_group *group, uint32_t group_id, int atable_id)
{
	struct amap_table_index *table_index;
	struct amap_table *amap_table, *ret_amap_table;
	struct tpriv priv = { 0 };
	uint32_t group_offset = atable_id & AMAP_TABLE_GROUP_MASK;
	int i;

	ret_amap_table = amap_table_load(tdisk, block, group, atable_id, &priv);
	if (unlikely(!ret_amap_table))
		return NULL;

	for (i = 0; i < AMAP_TABLE_ASYNC_COUNT; i++) {
		group_offset++;
		atable_id++;
		if (group_offset == group->amap_table_max) {
			break;
		}

		amap_table = group->amap_table[group_offset];
		if (amap_table) {
			group_tail_amap_table(group, amap_table);
			continue;
		}

		table_index = &tdisk->table_index[group_id];
		block = get_amap_table_block(table_index, group_offset);
		if (!block)
			continue;
		amap_table_load(tdisk, block, group, atable_id, NULL);
	}

	bdev_start(amap_table_bint(ret_amap_table)->b_dev, &priv);
	return ret_amap_table;
}

struct amap_table * 
amap_table_load(struct tdisk *tdisk, uint64_t block, struct amap_table_group *group, int atable_id, struct tpriv *priv)
{
	struct bdevint *bint;
	struct amap_table *amap_table;
	int retval;

	amap_table = amap_table_alloc(tdisk, atable_id);
	if (unlikely(!amap_table)) {
		debug_warn("Failed to alloc amap table\n");
		return NULL;
	}

	bint = bdev_find(BLOCK_BID(block));
	if (unlikely(!bint)) {
		debug_warn("Cannot find bint at %u\n", BLOCK_BID(block));
		return NULL;
	}

	amap_table->amap_table_block = block;
	amap_table->metadata = vm_pg_alloc(0);
	if (unlikely(!amap_table->metadata)) {
		amap_table_put(amap_table);
		return NULL;
	}

	if (priv)
		bdev_marker(bint->b_dev, priv);
	retval = amap_table_io(amap_table, QS_IO_READ);
	if (unlikely(retval != 0)) {
		if (priv && priv->data)
			bdev_start(bint->b_dev, priv);
		amap_table_put(amap_table);
		return NULL;
	}
	tdisk_bmap_lock(tdisk);
	if (group->group_write_bmap) {
		uint32_t group_offset = atable_id & AMAP_TABLE_GROUP_MASK;
		int i, j;

		i = group_offset / 8;
		j = group_offset % 8;
		if (group->group_write_bmap->bmap[i] & (1 << j))
			atomic_set_bit_short(ATABLE_WRITE_BMAP_INVALID, &amap_table->flags);
	}
	tdisk_bmap_unlock(tdisk);
	amap_table_insert(group, amap_table);
	TDISK_INC(tdisk, amap_table_load, 1);
	return amap_table;
}

struct amap *
amap_load_async(struct amap_table *amap_table, uint32_t amap_id, uint32_t amap_idx, uint64_t block)
{
	struct amap *amap;
	int i;
	struct tpriv priv = { 0 };

	amap = amap_load(amap_table, amap_id, amap_idx, block, &priv);
	if (unlikely(!amap))
		return NULL;

	TDISK_INC(amap_table->tdisk, amap_load, 1);

	for (i = 0; i < AMAP_ASYNC_COUNT; i++) {
		amap_idx++;
		amap_id++;
		if (amap_idx == AMAPS_PER_AMAP_TABLE) {
			bdev_start(amap_bint(amap)->b_dev, &priv);
			return amap;
		}

		if (amap_table->amap_index[amap_idx])
			continue;

		block = get_amap_block(amap_table, amap_idx);
		if (!block)
			continue;

		amap_load(amap_table, amap_id, amap_idx, block, NULL);
	}
	bdev_start(amap_bint(amap)->b_dev, &priv);
	return amap;
}

struct amap_table *
amap_table_locate(struct tdisk *tdisk, uint64_t lba, int *error)
{
	uint32_t group_id, group_offset, atable_id;
	struct amap_table *amap_table;
	struct amap_table_group *group;
	struct amap_table_index *table_index;
	uint64_t block;

	atable_id = amap_table_id(lba);
	group_id = amap_table_group_id(atable_id, &group_offset);
	group = tdisk->amap_table_group[group_id];
	amap_table_group_lock(group);
	amap_table = group->amap_table[group_offset]; 

	if (!amap_table) {
		table_index = &tdisk->table_index[group_id];
		block = get_amap_table_block(table_index, group_offset);
		if (!block) {
			amap_table_group_unlock(group);
			return NULL;
		}

		amap_table = amap_table_load(tdisk, block, group, atable_id, NULL);
		if (unlikely(!amap_table)) {
			*error = -1;
			amap_table_group_unlock(group);
			return NULL;
		}
	}
	amap_table_get(amap_table);
	amap_table_group_unlock(group);
	wait_on_chan_check(amap_table->amap_table_wait, !atomic_test_bit_short(ATABLE_META_DATA_READ_DIRTY, &amap_table->flags));
	return amap_table;
}

int
lba_unmapped(struct tdisk *tdisk, uint64_t lba, struct pgdata *pgdata, struct amap_table_list *table_list, struct amap_table *prev_amap_table, struct amap *prev_amap)
{
	struct amap_table *amap_table;
	struct amap_table_group *group;
	struct amap *amap;
	struct amap_table_index *table_index;
	uint64_t block;
	uint32_t atable_id;
	uint32_t group_id, group_offset;
	uint32_t amap_id;
	uint32_t amap_idx;

	atable_id = amap_table_id(lba);

	if (prev_amap_table && atable_id == prev_amap_table->amap_table_id) {
		amap_table = prev_amap_table;
		amap_table_get(amap_table);
		goto skip_atable_locate;
	}

	group_id = amap_table_group_id(atable_id, &group_offset);

	debug_check(group_id >= tdisk->amap_table_group_max);
	group = tdisk->amap_table_group[group_id];
	tdisk_tail_group(tdisk, group);

	debug_check(group_offset >= group->amap_table_max);
	amap_table_group_lock(group);
	amap_table = group->amap_table[group_offset]; 

	if (!amap_table) {
		uint64_t block;

		table_index = &tdisk->table_index[group_id];
		block = get_amap_table_block(table_index, group_offset);
		if (!block) {
			amap_table_group_unlock(group);
			return 1;
		}

		amap_table = amap_table_load_async(tdisk, block, group, group_id, atable_id);
		if (unlikely(!amap_table)) {
			amap_table_group_unlock(group);
			return -1;
		}
		amap_table_get(amap_table);
		pgdata->amap_table = amap_table;
		STAILQ_INSERT_TAIL(table_list, pgdata, t_list);
		amap_table_group_unlock(group);
		return 0;
	}
	else {
		group_tail_amap_table(group, amap_table);
	}
	amap_table_get(amap_table);
	amap_table_group_unlock(group);

skip_atable_locate:
	if (atomic_test_bit_short(ATABLE_META_DATA_READ_DIRTY, &amap_table->flags)) {
		pgdata->amap_table = amap_table;
		STAILQ_INSERT_TAIL(table_list, pgdata, t_list);
		return 0;
	}

	debug_check(!amap_table_bstart(amap_table) || !amap_table_bint(amap_table));
	amap_id = amap_get_id(lba);

	if (prev_amap && amap_id == prev_amap->amap_id) {
		amap = prev_amap;
		amap_get(amap);
		goto skip_amap_locate;
	}

	amap_idx = amap_id - (atable_id * AMAPS_PER_AMAP_TABLE);

	amap_table_lock(amap_table);
	amap_table_check_csum(amap_table);
	if (atomic_test_bit_short(ATABLE_META_DATA_ERROR, &amap_table->flags)) {
		debug_warn("Metadata error for amap table\n");
		amap_table_unlock(amap_table);
		amap_table_put(amap_table);
		return -1;
	}

	amap = amap_table->amap_index[amap_idx];
	if (!amap) {
		block = get_amap_block(amap_table, amap_idx);
		if (!block) {
			debug_info("amap table data of amap idx is zero\n");
			amap_table_unlock(amap_table);
			amap_table_put(amap_table);
			return 1;
		}

		amap = amap_load_async(amap_table, amap_id, amap_idx, block);
		if (unlikely(!amap)) {
			debug_warn("address map load failed\n");
			amap_table_unlock(amap_table);
			amap_table_put(amap_table);
			return -1;
		}
	}
	else {
		TDISK_INC(amap_table->tdisk, amap_hits, 1);
	}
	amap_get(amap);
	amap_table_unlock(amap_table);

skip_amap_locate:
	pgdata->amap_table = amap_table;
	pgdata->amap = amap;
	return 0;
}

struct amap *
amap_locate(struct amap_table *amap_table, uint64_t lba, int *error)
{
	uint32_t amap_id, amap_idx;
	struct amap *amap;
	uint64_t block;
	struct tpriv priv = { 0 };

	amap_id = amap_get_id(lba);
	amap_idx = amap_id - (amap_table->amap_table_id * AMAPS_PER_AMAP_TABLE); 

	amap = amap_table->amap_index[amap_idx];
	if (amap) {
		amap_get(amap);
		wait_on_chan_check(amap->amap_wait, !atomic_test_bit_short(AMAP_META_DATA_READ_DIRTY, &amap->flags));
		return amap;
	}

	block = get_amap_block(amap_table, amap_idx);
	if (!block)
		return NULL;

	amap = amap_load(amap_table, amap_id, amap_idx, block, &priv);
	if (unlikely(!amap)) {
		*error = -1;
		return NULL;
	}
	bdev_start(amap_bint(amap)->b_dev, &priv);
	amap_get(amap);
	wait_on_chan_check(amap->amap_wait, !atomic_test_bit_short(AMAP_META_DATA_READ_DIRTY, &amap->flags));
	return amap;
}

static int
amap_table_get_amap(struct amap_table *amap_table, uint32_t amap_id, uint32_t amap_idx, struct amap **ret_amap, int rw, struct index_info_list *meta_index_info_list, int unmap)
{
	struct amap *amap;
	uint64_t block;
#ifdef ENABLE_STATS
	uint32_t start_ticks;
#endif
	int error;

	amap = amap_table->amap_index[amap_idx];
	if (amap) {
		TDISK_INC(amap_table->tdisk, amap_hits, 1);
	}
	else {
		block = get_amap_block(amap_table, amap_idx);
		if (!block) {
			if (rw == QS_IO_READ || unmap) {
				*ret_amap = NULL;
				return 0;
			}

			TDISK_TSTART(start_ticks);
			amap = amap_new(amap_table, amap_id, amap_idx, meta_index_info_list, &error);
			TDISK_TEND(amap_table->tdisk, amap_new_ticks, start_ticks);
			if (unlikely(!amap)) {
				debug_warn("address map create failed\n");
				*ret_amap = NULL;
				return error;
			}
			amap_clone_check(amap_table->tdisk, amap, 1);
			TDISK_INC(amap_table->tdisk, amap_new, 1);
		} 
		else {
			TDISK_TSTART(start_ticks);
			amap = amap_load_async(amap_table, amap_id, amap_idx, block);
			TDISK_TEND(amap_table->tdisk, amap_load_ticks, start_ticks);
			if (unlikely(!amap)) {
				debug_warn("address map load failed\n");
				*ret_amap = NULL;
				return -1;
			}
			TDISK_INC(amap_table->tdisk, amap_load, 1);
		}
	}

	amap_get(amap);

	*ret_amap = amap;
	return 0;
}

int
pgdata_check_table_list(struct amap_table_list *table_list, struct index_info_list *meta_index_info_list, struct amap_sync_list *amap_sync_list, int rw, uint64_t write_id)
{
	struct pgdata *pgdata;
	struct amap_table *amap_table;
	struct amap *amap;
	uint32_t amap_id, amap_idx;
	int retval;

	while ((pgdata = STAILQ_FIRST(table_list)) != NULL) {
		STAILQ_REMOVE_HEAD(table_list, t_list);
		amap_table = pgdata->amap_table;
		wait_on_chan_check(amap_table->amap_table_wait, !atomic_test_bit_short(ATABLE_META_DATA_READ_DIRTY, &amap_table->flags));

		amap_id = amap_get_id(pgdata->lba);
		amap_idx = amap_id - (amap_table->amap_table_id * AMAPS_PER_AMAP_TABLE); 
		amap_table_lock(amap_table);
		amap_table_check_csum(amap_table);
		if (atomic_test_bit_short(ATABLE_META_DATA_ERROR, &amap_table->flags)) {
			debug_warn("meta data error for amap table at id %u\n", amap_table->amap_table_id);
			amap_table_unlock(amap_table);
			return -1;
		}

		retval = amap_table_get_amap(amap_table, amap_id, amap_idx, &amap, rw, meta_index_info_list, 0);
		amap_table_unlock(amap_table);
		if (unlikely(retval < 0)) {
			debug_warn("Failed to get amap at %u\n", amap_id);
			return retval;
		}

		pgdata->amap = amap;
		if (amap_sync_list && amap) {
			amap_check_sync_list(amap, amap_sync_list, pgdata, write_id);
		}
	}
	return 0;
}

static int
lba_unmapped_write(struct tdisk *tdisk, uint64_t lba, struct pgdata *pgdata, struct write_list *wlist, struct amap_table *prev_amap_table, struct amap *prev_amap, struct amap_sync_list *amap_sync_list, uint64_t write_id)
{
	struct amap_table *amap_table;
	struct amap_table_group *group;
	struct amap *amap;
	uint32_t atable_id;
	uint32_t amap_id;
	uint32_t group_id, group_offset;
	uint32_t amap_idx;
	int retval;
#ifdef ENABLE_STATS
	uint32_t start_ticks;
	uint32_t tmp_ticks;
#endif

	atable_id = amap_table_id(lba);
	if (prev_amap_table && atable_id == prev_amap_table->amap_table_id) {
		amap_table = prev_amap_table;
		amap_table_get(amap_table);
		goto skip_atable_locate;
	}

	if (unlikely(atable_id >= tdisk->amap_table_max)) {
		debug_warn("Invalid amap table id %u\n", atable_id);
		return -1;
	}

	group_id = amap_table_group_id(atable_id, &group_offset);
	group = tdisk->amap_table_group[group_id];
	tdisk_tail_group(tdisk, group);

	TDISK_TSTART(start_ticks);
	amap_table_group_lock(group);
	amap_table = group->amap_table[group_offset]; 

	if (!amap_table) {
		struct amap_table_index *table_index;
		uint64_t block;

		table_index = &tdisk->table_index[group_id];
		block = get_amap_table_block(table_index, group_offset);
		if (!block) {
			if (atomic_test_bit(DDBLOCK_ZERO_BLOCK, &pgdata->flags)) {
				amap_table_group_unlock(group);
				return 0;
			}
			TDISK_TSTART(tmp_ticks);
			retval = amap_table_init(tdisk, group, atable_id, &wlist->meta_index_info_list);
			TDISK_TEND(tdisk, amap_table_init_ticks, tmp_ticks);
			if (unlikely(retval != 0)) {
				amap_table_group_unlock(group);
				debug_warn("Failed to init amap table at %u:%u\n", group_id, group_offset);
				return -1;
			}
			amap_table = group->amap_table[group_offset];
			amap_table_clone_check(tdisk, amap_table);
		}
		else {
			TDISK_TSTART(tmp_ticks);
			amap_table = amap_table_load_async(tdisk, block, group, group_id, atable_id);
			TDISK_TEND(tdisk, amap_table_load_ticks, tmp_ticks);
			if (unlikely(!amap_table)) {
				amap_table_group_unlock(group);
				debug_warn("Failed to load amap table at %u:%u\n", group_id, group_offset);
				return -1;
			}
			amap_table_get(amap_table);
			pgdata->amap_table = amap_table;
			STAILQ_INSERT_TAIL(&wlist->table_list, pgdata, t_list);
			amap_table_group_unlock(group);
			return 0;
		}
	}
	else {
		group_tail_amap_table(group, amap_table);
	}
	amap_table_get(amap_table);
	amap_table_group_unlock(group);
	TDISK_TEND(tdisk, amap_table_locate_ticks, start_ticks);

skip_atable_locate:
	if (atomic_test_bit_short(ATABLE_META_DATA_READ_DIRTY, &amap_table->flags)) {
		pgdata->amap_table = amap_table;
		STAILQ_INSERT_TAIL(&wlist->table_list, pgdata, t_list);
		return 0;
	}

	amap_id = amap_get_id(lba);

	if (prev_amap && amap_id == prev_amap->amap_id) {
		amap = prev_amap;
		amap_get(amap);
		goto skip_amap_locate;
	}

	amap_idx = amap_id - (atable_id * AMAPS_PER_AMAP_TABLE); 

	TDISK_TSTART(start_ticks);
	TDISK_TSTART(tmp_ticks);
	amap_table_lock(amap_table);
	amap_table_check_csum(amap_table);
	if (atomic_test_bit_short(ATABLE_META_DATA_ERROR, &amap_table->flags)) {
		debug_warn("Metadata error for amap table\n");
		amap_table_unlock(amap_table);
		amap_table_put(amap_table);
		return -1;
	}

	retval = amap_table_get_amap(amap_table, amap_id, amap_idx, &amap, QS_IO_WRITE, &wlist->meta_index_info_list, atomic_test_bit(DDBLOCK_ZERO_BLOCK, &pgdata->flags));
	amap_table_unlock(amap_table);

	TDISK_TEND(tdisk, amap_table_get_amap_ticks, tmp_ticks);
	if (unlikely(retval < 0)) {
		amap_table_put(amap_table);
		debug_warn("Failed to get amap at %u:%u\n", amap_id, amap_idx);
		return retval;
	}

	TDISK_TEND(tdisk, amap_locate_ticks, start_ticks);
skip_amap_locate:
	pgdata->amap_table = amap_table;
	pgdata->amap = amap;
	TDISK_TSTART(start_ticks);
	if (amap) {
		amap_check_sync_list(amap, amap_sync_list, pgdata, write_id);
	}
	TDISK_TEND(tdisk, amap_check_sync_ticks, start_ticks);
	return 0;
}

void
pgdata_free_amaps(struct pgdata **pglist, int pglist_cnt)
{
	int i;
	struct pgdata *pgdata;

	for (i = 0; i < pglist_cnt; i++) {
		pgdata = pglist[i];
		pgdata_cleanup(pgdata);
	}
}

static inline int
skip_uncomp(struct pgdata *pgdata)
{
	if (atomic_test_bit(PGDATA_SKIP_UNCOMP, &pgdata->flags)
		|| atomic_test_bit(PGDATA_NEED_REMOTE_IO, &pgdata->flags)
		|| atomic_test_bit(PGDATA_FROM_RCACHE, &pgdata->flags)) 
		return 1;
	else
		return 0;
}

static void
pgdata_copy_from_read_list(struct pgdata *pgdata, struct pgdata_wlist *read_list)
{
	struct pgdata *pgtmp;

	STAILQ_FOREACH(pgtmp, read_list, t_list) {
		if (pgtmp->amap_block == pgdata->amap_block) {
			pgdata_copy_ref(pgdata, pgtmp);
			return;
		}
	}
	debug_check(1);
}

#ifdef FREEBSD
static int 
is_bogus_page(struct pgdata **pglist, int pglist_cnt, pagestruct_t *page, int idx)
{
	struct pgdata *pgdata;
	int i;

	for (i = 0; i < pglist_cnt; i++) {
		if (i == idx)
			continue;
		pgdata = pglist[i];
		if (pgdata->page == page)
			return 1;
	}
	return 0;
}
#endif

int 
pgdata_post_read_io(struct pgdata **pglist, int pglist_cnt, struct rcache_entry_list *rcache_list, int enable_rcache, int norefs, int save_comp)
{
	struct pgdata *pgdata, *comp_pgdata;
	pagestruct_t *uncomp_page;
	uint32_t block_size;
	int retval, i;
	struct pgdata_wlist read_list;

	STAILQ_INIT(&read_list);
	for (i = 0; i < pglist_cnt; i++) {
		pgdata = pglist[i];
		if (!pgdata->amap_block) {
			debug_check(!atomic_test_bit(DDBLOCK_ZERO_BLOCK, &pgdata->flags));
			pgdata_cleanup(pgdata);
			continue;
		}

		if (atomic_test_bit(PGDATA_FROM_READ_LIST, &pgdata->flags)) {
			pgdata_copy_from_read_list(pgdata, &read_list);
			pgdata_cleanup(pgdata);
			continue;
		}

		STAILQ_INSERT_TAIL(&read_list, pgdata, t_list);
		if (skip_uncomp(pgdata)) {
			pgdata_cleanup(pgdata);
			continue;
		}

		block_size = lba_block_size(pgdata->amap_block);
		if (block_size == LBA_SIZE) {
			if (enable_rcache)
				rcache_add_to_list(rcache_list, pgdata);
			pgdata_cleanup(pgdata);
			continue;
		}

		uncomp_page = vm_pg_alloc(0);
		if (unlikely(!uncomp_page)) {
			debug_warn("Cannot allocate uncompressed page\n");
			return -1;
		}

		retval = qs_inflate_block(pgdata->page, block_size, uncomp_page);
		if (unlikely(retval != 0)) {
			vm_pg_free(uncomp_page);
#ifdef FREEBSD
			if (norefs && is_bogus_page(pglist, pglist_cnt, pgdata->page, i)) {
				pgdata_cleanup(pgdata);
				continue;
			}
#endif
			debug_warn("Failed to decompress page lba %llu size %d amap block %llu\n", (unsigned long long)pgdata->lba, block_size, (unsigned long long)pgdata->amap_block);
			return -1;
		}
		comp_pgdata = NULL;
		if (save_comp) {
			comp_pgdata = __uma_zalloc(pgdata_cache, Q_WAITOK | Q_ZERO, sizeof(*comp_pgdata));
			comp_pgdata->completion = wait_completion_alloc("pgdata compl");
			comp_pgdata->page = pgdata->page;
			comp_pgdata->pg_len = block_size;
			pgdata->page = uncomp_page;
		}
		else if (!norefs) {
			pgdata_free_page(pgdata);
			pgdata->page = uncomp_page;
		}
		else {
			pgdata_copy_page_ref(pgdata, uncomp_page);
			vm_pg_free(uncomp_page);
		}
		pgdata->pg_len = LBA_SIZE;
		if (enable_rcache)
			rcache_add_to_list(rcache_list, pgdata);
		pgdata_cleanup(pgdata);
		pgdata->comp_pgdata = comp_pgdata;
	}
	return 0;
}

int
pgdata_in_read_list(struct tdisk *tdisk, struct pgdata *pgdata, struct pgdata_wlist *read_list, int copy)
{
	struct pgdata *pgtmp;

	STAILQ_FOREACH(pgtmp, read_list, t_list) {
		if (pgtmp->amap_block == pgdata->amap_block) {
			debug_check(!pgtmp->page);
			if (!copy) {
				pgdata_free_page(pgdata);
				pgdata_add_ref(pgdata, pgtmp);
			}
			else {
				atomic_set_bit(PGDATA_FROM_READ_LIST, &pgdata->flags);
			}
			atomic_set_bit(SKIP_RCACHE_INSERT, &pgdata->flags);
			if (atomic_test_bit(PGDATA_SKIP_UNCOMP, &pgtmp->flags))
				atomic_set_bit(PGDATA_SKIP_UNCOMP, &pgdata->flags);
			TDISK_INC(tdisk, read_incache, 1);
			return 1;
		}
	}

	STAILQ_INSERT_TAIL(read_list, pgdata, t_list);
	return 0;
}

static void 
__free_block_refs(struct tdisk *tdisk, struct index_info_list *ref_index_info_list)
{
	struct index_info *index_info;
	struct index_sync_list index_sync_list;
	struct index_info_list index_info_list;

	TAILQ_INIT(&index_info_list);
	SLIST_INIT(&index_sync_list);

	index_list_insert(&index_sync_list, ref_index_info_list);
	TAILQ_FOREACH(index_info, ref_index_info_list, i_list) {
		process_delete_block(bdev_group_ddtable(tdisk->group), index_info->block, &index_info_list, &index_sync_list, NULL, TYPE_DATA_BLOCK);
	}

	index_sync_start_io(&index_sync_list, 1);
	index_sync_wait(&index_sync_list);
	index_info_wait(&index_info_list);
	index_info_wait(ref_index_info_list);
	return;
}

void
free_block_refs(struct tdisk *tdisk, struct index_info_list *index_info_list)
{
	if (!TAILQ_EMPTY(index_info_list))
		__free_block_refs(tdisk, index_info_list);
}

int
tdisk_add_block_ref(struct bdevgroup *group, uint64_t block, struct index_info_list *index_info_list)
{
	struct bdevint *bint;
	uint64_t index_id;
	struct bintindex *index;
	struct index_info *index_info;
	uint32_t entry_id;
	int retval;

	bint = bdev_find(BLOCK_BID(block));
	if (unlikely(!bint)) {
		debug_warn("Failed to find bdev at %u\n", BLOCK_BID(block));
		return -1;
	}

	if (bint->group != group)
		return -1;

	index_id = index_id_from_block(bint, BLOCK_BLOCKNR(block), &entry_id);
	index = bint_get_index(bint, index_id);
	if (unlikely(!index)) {
		debug_warn("Cannot get a index at index_id %llu\n", (unsigned long long)index_id);
		return -1;
	}

	index_info = index_info_alloc();
	if (unlikely(!index_info)) {
		debug_warn("Failed to alloc for index_info\n");
		index_put(index);
		return -1;
	}

	wait_on_chan_check(index->index_wait, !atomic_test_bit(META_DATA_READ_DIRTY, &index->flags));
	index_lock(index);
	index_check_load(index);
	if (atomic_test_bit(META_DATA_ERROR, &index->flags)) {
		index_unlock(index);
		index_put(index);
		index_info_free(index_info);
		return -1;
	}

	index_write_barrier(bint, index);
	retval = bint_ref_block(bint, index, entry_id, lba_block_size(block), index_info, 0ULL);
	index_unlock(index);
	index_put(index);
	if (unlikely(retval != 0)) {
		index_info_free(index_info);
		return -1;
	}

	index_info->block = block;
	TAILQ_INSERT_TAIL(index_info_list, index_info, i_list);
	return 0;
}
 
static int
lba_in_range(struct lba_write *first, struct lba_write *second)
{
	if (first->lba_end <= second->lba_start)
		return 0;

	if (second->lba_end <= first->lba_start)
		return 0;

	return 1;
}

void
tdisk_remove_lba_write(struct tdisk *tdisk, struct lba_write **ptr_lba_write)
{
	struct lba_write *lba_write = *ptr_lba_write;

	if (!lba_write)
		return;
	chan_lock(tdisk->lba_wait);
	TAILQ_REMOVE(&tdisk->lba_list, lba_write, l_list);
	chan_wakeup_unlocked(tdisk->lba_wait);
	chan_unlock(tdisk->lba_wait);
	uma_zfree(lba_write_cache, lba_write);
	*ptr_lba_write = NULL;
}

struct lba_write * 
tdisk_add_lba_write(struct tdisk *tdisk, uint64_t lba, uint32_t transfer_length, int cw, int dir, int sync_wait)
{
	struct lba_write *lba_write, *iter;
	uint64_t lba_diff;
	int pglist_cnt;

#if 0
	if (tdisk->lba_shift == LBA_SHIFT && !cw)
		return NULL;
#endif

	lba_write = __uma_zalloc(lba_write_cache, Q_WAITOK | Q_ZERO, sizeof(*lba_write));
	if (tdisk->lba_shift != LBA_SHIFT) {
		lba_diff = (lba - (lba & ~0x7ULL));
		transfer_length += lba_diff;
		lba -= lba_diff;
		lba >>= 3;
		if (lba_diff || (transfer_length & 0x7) || cw) {
			debug_info("lba diff %llu transfer_length %u cw %d\n", (unsigned long long)lba_diff, transfer_length, cw);
		}
	}

	pglist_cnt = transfer_length_to_pglist_cnt(tdisk->lba_shift, transfer_length);
	lba_write->lba_start = lba;
	lba_write->lba_end = lba + pglist_cnt;
	lba_write->dir = dir;
	lba_write->cw = cw;
	lba_write->sync_wait = sync_wait;

	chan_lock(tdisk->lba_wait);
	TAILQ_INSERT_TAIL(&tdisk->lba_list, lba_write, l_list);
again:
	TAILQ_FOREACH(iter, &tdisk->lba_list, l_list) {
		if (iter == lba_write)
			break;

		if (iter->sync_wait) {
			if (!sync_wait) {
				wait_on_chan_uncond(tdisk->lba_wait);
				goto again;
			}
			else
				continue;
		}
#if 0
		if (!iter->unaligned && !lba_write->unaligned)
			continue;
#endif
		if (!lba_in_range(lba_write, iter) && !sync_wait)
			continue;
		if (lba_write->dir == QS_IO_READ && iter->dir == QS_IO_READ && !sync_wait)
			continue;

		wait_on_chan_uncond(tdisk->lba_wait);
		goto again;
	}
	chan_unlock(tdisk->lba_wait);
	return lba_write;
}

int 
__tdisk_cmd_ref_int(struct tdisk *tdisk, struct tdisk *dest_tdisk, struct qsio_scsiio *ctio, struct pgdata ***ret_pglist, int *ret_pglist_cnt, uint64_t lba, uint32_t transfer_length, struct index_info_list *index_info_list, int mirror_enabled, int use_refs)
{
	uint32_t i;
	int retval;
	struct pgdata *pgtmp, **pglist = NULL;
	struct bdevint *bint = NULL, *prev_bint = NULL;
	struct amap *amap = NULL;
	struct amap_table *amap_table = NULL;
	struct amap_table_list table_list;
	struct pgdata_wlist read_list;
	struct tcache *tcache;
	uint32_t entry_id;
	uint64_t amap_entry_block;
#ifdef ENABLE_STATS
	uint32_t start_ticks;
#endif
	int pglist_cnt;

	debug_info("lba %llu transfer length %u\n", (unsigned long long)lba, transfer_length);

	if (reached_eom(tdisk, lba, transfer_length)) {
		ctio_construct_sense(ctio, SSD_CURRENT_ERROR, SSD_KEY_ILLEGAL_REQUEST, 0, LOGICAL_BLOCK_ADDRESS_OUT_OF_RANGE_ASC, LOGICAL_BLOCK_ADDRESS_OUT_OF_RANGE_ASCQ);
		return -1;
	}

	TDISK_INC(tdisk, lba_read_count, transfer_length);
	TDISK_INC(tdisk, read_count, 1);
	TDISK_STATS_ADD(tdisk, read_size, (transfer_length << tdisk->lba_shift));

	debug_check(tdisk_get_lba_diff(tdisk, lba));
	lba = tdisk_get_lba_real(tdisk, lba);

	pglist_cnt = transfer_length_to_pglist_cnt(tdisk->lba_shift, transfer_length);

	tcache = tcache_alloc(pglist_cnt);

	pglist = pgdata_allocate_nopage(pglist_cnt, Q_NOWAIT); 
	if (unlikely(!pglist)) {
		tcache_put(tcache);
		ctio_construct_sense(ctio, SSD_CURRENT_ERROR, SSD_KEY_HARDWARE_ERROR, 0, INTERNAL_TARGET_FAILURE_ASC, INTERNAL_TARGET_FAILURE_ASCQ);
		return -1;
	}

	STAILQ_INIT(&table_list);
	STAILQ_INIT(&read_list);

	for (i = 0; i < pglist_cnt; i++, lba++) {
		pgtmp =  pglist[i];
		debug_check(!pgtmp);
		pgtmp->lba = lba;
		TDISK_TSTART(start_ticks);
		retval = lba_unmapped(tdisk, lba, pgtmp, &table_list, amap_table, amap);
		TDISK_TEND(tdisk, lba_unmapped_ticks, start_ticks);
		if (retval < 0) {
			goto err;
		}
		amap_table = pgtmp->amap_table;
		amap = pgtmp->amap;
	}

	TDISK_TSTART(start_ticks);
	retval = pgdata_check_table_list(&table_list, index_info_list, NULL, QS_IO_READ, 0);
	TDISK_TEND(tdisk, check_table_read_ticks, start_ticks);
	if (unlikely(retval != 0))
		goto err;

	for (i = 0; i < pglist_cnt; i++) {
		pgtmp =  pglist[i];

		amap = pgtmp->amap;
		if (!amap) {
			pgdata_free_page(pgtmp);
			atomic_set_bit(DDBLOCK_ZERO_BLOCK, &pgtmp->flags);
			atomic_set_bit(PGDATA_SKIP_DDCHECK, &pgtmp->flags);
			atomic_set_bit(PGDATA_SKIP_UNCOMP, &pgtmp->flags);
			continue;
		}

		TDISK_TSTART(start_ticks);
		wait_on_chan_check(amap->amap_wait, !atomic_test_bit_short(AMAP_META_DATA_READ_DIRTY, &amap->flags));
		TDISK_TEND(tdisk, read_amap_wait_ticks, start_ticks);
		entry_id = amap_entry_id(amap, pgtmp->lba);
		debug_check(entry_id >= ENTRIES_PER_AMAP);
		TDISK_TSTART(start_ticks);
		if (!atomic_test_bit_short(AMAP_CSUM_CHECK_DONE, &amap->flags)) {
			amap_lock(amap);
			amap_check_csum(amap);
			amap_unlock(amap);
		}

		if (atomic_test_bit_short(AMAP_META_DATA_ERROR, &amap->flags)) {
			goto err;
		}

		amap_read_lock(amap);
		amap_entry_block = amap_entry_get_block(amap, entry_id);
		amap_read_unlock(amap);

		TDISK_TEND(tdisk, read_amap_block_ticks, start_ticks);

		if (!amap_entry_block) {
			pgdata_free_page(pgtmp);
			atomic_set_bit(DDBLOCK_ZERO_BLOCK, &pgtmp->flags);
			atomic_set_bit(PGDATA_SKIP_DDCHECK, &pgtmp->flags);
			atomic_set_bit(PGDATA_SKIP_UNCOMP, &pgtmp->flags);
			continue;
		}

		pgtmp->amap_block = amap_entry_block;
		retval = tdisk_add_block_ref(dest_tdisk->group, amap_entry_block, index_info_list);
		if (retval == 0) {
			TDISK_INC(tdisk, xcopy_ref_hits, 1);
			atomic_set_bit(DDBLOCK_ENTRY_FOUND_DUPLICATE, &pgtmp->flags);
			atomic_set_bit(DDBLOCK_ENTRY_DONE_ALLOC, &pgtmp->flags);
			atomic_set_bit(PGDATA_SKIP_DDCHECK, &pgtmp->flags);
			atomic_set_bit(PGDATA_SKIP_UNCOMP, &pgtmp->flags);
			if (!mirror_enabled || use_refs) {
				pgdata_free_page(pgtmp);
				continue;
			}
		}
		else
			TDISK_INC(tdisk, xcopy_ref_misses, 1);

		retval = pgdata_alloc_page(pgtmp, 0);
		if (unlikely(retval != 0)) {
			debug_warn("allocating for pgdata page failed\n");
			goto err;
		}

		debug_info("amap entry block %llu bid %u\n", (unsigned long long)BLOCK_BLOCKNR(amap_entry_block), BLOCK_BID(amap_entry_block));
		if (!prev_bint || (prev_bint->bid != BLOCK_BID(amap_entry_block))) {
			bint = bdev_find(BLOCK_BID(amap_entry_block));
			if (unlikely(!bint)) {
				debug_warn("Cannot locate bint at bid %u\n", BLOCK_BID(amap_entry_block));
				goto err;
			}
			prev_bint = bint;
		}
		else {
			bint = prev_bint;
		}

		TDISK_TSTART(start_ticks);
		if (pgdata_in_read_list(tdisk, pgtmp, &read_list, 0)) {
			TDISK_INC(tdisk, inread_list, 1);
			TDISK_TEND(tdisk, pgdata_read_list_ticks, start_ticks);
			continue;
		}
		TDISK_TEND(tdisk, pgdata_read_list_ticks, start_ticks);

		if (rcache_locate(pgtmp, 0))
			continue;

		debug_info("lba %llu block %llu size %u\n", (unsigned long long)pgtmp->lba, (unsigned long long)(BLOCK_BLOCKNR(amap_entry_block)), lba_block_size(amap_entry_block));
		TDISK_TSTART(start_ticks);
		retval = tcache_add_page(tcache, pgtmp->page, BLOCK_BLOCKNR(amap_entry_block), bint, lba_block_size(amap_entry_block), QS_IO_READ);
		TDISK_TEND(tdisk, tcache_read_add_page_ticks, start_ticks);
		if (unlikely(retval != 0)) {
			debug_warn("Failed to add page to tcache\n");
			goto err;
		}
	}

	if (!atomic_read(&tcache->bio_remain))
		goto skip_io;

	TDISK_TSTART(start_ticks);
	TDISK_INC(tdisk, biot_read_count, atomic_read(&tcache->bio_remain));
	TDISK_INC(tdisk, read_page_misses, tcache->page_misses);
	TDISK_INC(tdisk, read_bstart_misses, tcache->bstart_misses);
	TDISK_INC(tdisk, read_bint_misses, tcache->bint_misses);
#ifdef CUSTOM_BIO_STATS
	TDISK_INC(tdisk, read_bio_is_cloned, tcache->bio_is_cloned); 
	TDISK_INC(tdisk, read_bio_size_exceeded, tcache->bio_size_exceeded); 
	TDISK_INC(tdisk, read_bio_vecs_exceeded, tcache->bio_vecs_exceeded); 
	TDISK_INC(tdisk, read_bio_merge_failed, tcache->bio_merge_failed);
	TDISK_INC(tdisk, read_bio_retried_segments, tcache->bio_retried_segments);
#endif
	tcache_entry_rw(tcache, QS_IO_READ);

	wait_for_done(tcache->completion);
	TDISK_TEND(tdisk, tcache_read_wait_ticks, start_ticks);

	if (atomic_test_bit_short(TCACHE_IO_ERROR, &tcache->flags))
		goto err;

	tcache_read_comp(tcache);
skip_io:
	TDISK_TSTART(start_ticks);
	retval = pgdata_post_read_io(pglist, pglist_cnt, NULL, 0, 0, 0);
	TDISK_TEND(tdisk, post_read_io_ticks, start_ticks);
	if (unlikely(retval != 0)) {
		goto err;
	}

	tcache_put(tcache);
	*ret_pglist = pglist;
	*ret_pglist_cnt = pglist_cnt;
	return 0;
err:
	tcache_put(tcache);
	free_block_refs(tdisk, index_info_list);
	pgdata_free_amaps(pglist, pglist_cnt);
	pglist_free(pglist, pglist_cnt);
	ctio_construct_sense(ctio, SSD_CURRENT_ERROR, SSD_KEY_HARDWARE_ERROR, 0, INTERNAL_TARGET_FAILURE_ASC, INTERNAL_TARGET_FAILURE_ASCQ);
	return -1;
}

static int
tdisk_need_mirror_read(struct tdisk *tdisk, struct qsio_scsiio *ctio, struct lba_write *lba_write)
{
	if (!tdisk_mirroring_configured(tdisk) || tdisk_mirror_master(tdisk) || ctio_in_sync(ctio))
		return 0;

	if (!tdisk_mirroring_need_resync(tdisk))
		return 0;
	else
		return 1;
}

static int 
__tdisk_cmd_read_int(struct tdisk *tdisk, struct qsio_scsiio *ctio, struct pgdata ***ret_pglist, int *ret_pglist_cnt, uint64_t lba, uint32_t transfer_length, int enable_rcache, struct lba_write *lba_write)
{
	uint32_t i;
	int retval;
	struct pgdata *pgtmp, **pglist = *ret_pglist;
	struct bdevint *bint = NULL, *prev_bint = NULL;
	struct amap *amap = NULL;
	struct amap_table *amap_table = NULL;
	struct amap_table_list table_list;
	struct index_info_list index_info_list;
	struct pgdata_wlist read_list;
	struct rcache_entry_list rcache_list;
	struct tcache *tcache;
	uint32_t entry_id;
	uint64_t amap_entry_block;
#ifdef ENABLE_STATS
	uint32_t start_ticks;
#endif
	int pglist_cnt;
	int norefs = 0;
	struct lba_write *lba_alloc = NULL;
	struct lba_write *read_lba_write = NULL;

	debug_info("lba %llu transfer length %u\n", (unsigned long long)lba, transfer_length);

	if (reached_eom(tdisk, lba, transfer_length)) {
		ctio_construct_sense(ctio, SSD_CURRENT_ERROR, SSD_KEY_ILLEGAL_REQUEST, 0, LOGICAL_BLOCK_ADDRESS_OUT_OF_RANGE_ASC, LOGICAL_BLOCK_ADDRESS_OUT_OF_RANGE_ASCQ);
		return -1;
	}

	if (!lba_write)
		read_lba_write = tdisk_add_lba_write(tdisk, lba, transfer_length, 0, QS_IO_READ, 0);

	if (tdisk_need_mirror_read(tdisk, ctio, read_lba_write)) {
		tdisk_remove_lba_write(tdisk, &read_lba_write);
		retval = __tdisk_mirror_read(tdisk, ctio, ret_pglist, ret_pglist_cnt, lba, transfer_length);
		if (retval < 0)
			return retval;
		else
			return 0;
	}

	TDISK_INC(tdisk, lba_read_count, transfer_length);
	TDISK_INC(tdisk, read_count, 1);
	TDISK_STATS_ADD(tdisk, read_size, (transfer_length << tdisk->lba_shift));

	if (tdisk->lba_shift != LBA_SHIFT) {
		uint64_t lba_diff;

		lba_diff = (lba - (lba & ~0x7ULL));
		transfer_length += lba_diff;
		lba -= lba_diff;
		lba >>= 3;
	}

	pglist_cnt = transfer_length_to_pglist_cnt(tdisk->lba_shift, transfer_length);
	if (pglist)
		debug_check(pglist_cnt != *ret_pglist_cnt);

	tcache = tcache_alloc(pglist_cnt);

	if (!pglist) {
		pglist = pgdata_allocate_nopage(pglist_cnt, Q_NOWAIT); 
		if (unlikely(!pglist)) {
			tcache_put(tcache);
			tdisk_remove_lba_write(tdisk, &read_lba_write);
			ctio_construct_sense(ctio, SSD_CURRENT_ERROR, SSD_KEY_HARDWARE_ERROR, 0, INTERNAL_TARGET_FAILURE_ASC, INTERNAL_TARGET_FAILURE_ASCQ);
			return -1;
		}
		norefs = 0;
	}
	else {
		debug_check(!ctio_norefs(ctio));
		norefs = 1;
	}

	STAILQ_INIT(&table_list);
	TAILQ_INIT(&index_info_list);
	STAILQ_INIT(&read_list);
	TAILQ_INIT(&rcache_list);

	for (i = 0; i < pglist_cnt; i++, lba++) {
		pgtmp =  pglist[i];
		pgtmp->lba = lba;
		TDISK_TSTART(start_ticks);
		retval = lba_unmapped(tdisk, lba, pgtmp, &table_list, amap_table, amap);
		TDISK_TEND(tdisk, lba_unmapped_ticks, start_ticks);
		if (retval < 0) {
			goto err;
		}
		amap_table = pgtmp->amap_table;
		amap = pgtmp->amap;
	}

	TDISK_TSTART(start_ticks);
	retval = pgdata_check_table_list(&table_list, &index_info_list, NULL, QS_IO_READ, 0);
	TDISK_TEND(tdisk, check_table_read_ticks, start_ticks);
	if (unlikely(retval != 0))
		goto err;

	lba_alloc = tdisk_add_alloc_lba_write(lba, tdisk->lba_read_wait, &tdisk->lba_read_list, 0);
	for (i = 0; i < pglist_cnt; i++) {
		pgtmp =  pglist[i];

		amap = pgtmp->amap;
		if (!amap) {
			if (enable_rcache) {
				pgdata_free_page(pgtmp);
				pgdata_add_ref(pgtmp, &pgzero);
			} else {
				retval = pgdata_alloc_page(pgtmp, 0);
				if (unlikely(retval != 0)) {
					debug_warn("allocating for pgdata page failed\n");
					goto err;
				}
				pgdata_zero_page(pgtmp);
			}
			atomic_set_bit(DDBLOCK_ZERO_BLOCK, &pgtmp->flags);
			continue;
		}

		TDISK_TSTART(start_ticks);
		wait_on_chan_check(amap->amap_wait, !atomic_test_bit_short(AMAP_META_DATA_READ_DIRTY, &amap->flags));
		TDISK_TEND(tdisk, read_amap_wait_ticks, start_ticks);
		entry_id = amap_entry_id(amap, pgtmp->lba);
		debug_check(entry_id >= ENTRIES_PER_AMAP);
		TDISK_TSTART(start_ticks);
		if (!atomic_test_bit_short(AMAP_CSUM_CHECK_DONE, &amap->flags)) {
			amap_lock(amap);
			amap_check_csum(amap);
			amap_unlock(amap);
		}

		if (atomic_test_bit_short(AMAP_META_DATA_ERROR, &amap->flags)) {
			goto err;
		}

		amap_read_lock(amap);
		amap_entry_block = amap_entry_get_block(amap, entry_id);
		amap_read_unlock(amap);
		TDISK_TEND(tdisk, read_amap_block_ticks, start_ticks);

		if (!amap_entry_block) {
			if (enable_rcache) {
				pgdata_free_page(pgtmp);
				pgdata_add_ref(pgtmp, &pgzero);
			} else {
				retval = pgdata_alloc_page(pgtmp, 0);
				if (unlikely(retval != 0)) {
					debug_warn("allocating for pgdata page failed\n");
					goto err;
				}
				pgdata_zero_page(pgtmp);
			}
			atomic_set_bit(DDBLOCK_ZERO_BLOCK, &pgtmp->flags);
			continue;
		}
		pgtmp->amap_block = amap_entry_block;

		debug_info("amap entry block %llu bid %u\n", (unsigned long long)BLOCK_BLOCKNR(amap_entry_block), BLOCK_BID(amap_entry_block));
		if (!prev_bint || (prev_bint->bid != BLOCK_BID(amap_entry_block))) {
			bint = bdev_find(BLOCK_BID(amap_entry_block));
			if (unlikely(!bint)) {
				debug_warn("Cannot locate bint at bid %u\n", BLOCK_BID(amap_entry_block));
				goto err;
			}
			prev_bint = bint;
		}
		else {
			bint = prev_bint;
		}

		retval = pgdata_alloc_page(pgtmp, 0);
		if (unlikely(retval != 0)) {
			debug_warn("allocating for pgdata page failed\n");
			goto err;
		}

		TDISK_TSTART(start_ticks);
		if (pgdata_in_read_list(tdisk, pgtmp, &read_list, !enable_rcache)) {
			TDISK_INC(tdisk, inread_list, 1);
			TDISK_TEND(tdisk, pgdata_read_list_ticks, start_ticks);
			continue;
		}
		TDISK_TEND(tdisk, pgdata_read_list_ticks, start_ticks);

		if (rcache_locate(pgtmp, !enable_rcache)) {
			continue;
		}

		debug_info("lba %llu block %llu size %u\n", (unsigned long long)pgtmp->lba, (unsigned long long)(BLOCK_BLOCKNR(amap_entry_block)), lba_block_size(amap_entry_block));
		TDISK_TSTART(start_ticks);
		retval = tcache_add_page(tcache, pgtmp->page, BLOCK_BLOCKNR(amap_entry_block), bint, lba_block_size(amap_entry_block), QS_IO_READ);
		TDISK_TEND(tdisk, tcache_read_add_page_ticks, start_ticks);
		if (unlikely(retval != 0)) {
			debug_warn("Failed to add page to tcache\n");
			goto err;
		}
	}

	if (!atomic_read(&tcache->bio_remain))
		goto skip_io;

	TDISK_TSTART(start_ticks);
	TDISK_INC(tdisk, biot_read_count, atomic_read(&tcache->bio_remain));
	TDISK_INC(tdisk, read_page_misses, tcache->page_misses);
	TDISK_INC(tdisk, read_bstart_misses, tcache->bstart_misses);
	TDISK_INC(tdisk, read_bint_misses, tcache->bint_misses);
#ifdef CUSTOM_BIO_STATS
	TDISK_INC(tdisk, read_bio_is_cloned, tcache->bio_is_cloned); 
	TDISK_INC(tdisk, read_bio_size_exceeded, tcache->bio_size_exceeded); 
	TDISK_INC(tdisk, read_bio_vecs_exceeded, tcache->bio_vecs_exceeded); 
	TDISK_INC(tdisk, read_bio_merge_failed, tcache->bio_merge_failed);
	TDISK_INC(tdisk, read_bio_retried_segments, tcache->bio_retried_segments);
#endif
	tdisk_check_alloc_lba_write(lba_alloc, tdisk->lba_read_wait, &tdisk->lba_read_list, LBA_WRITE_DONE_IO);
	tcache_entry_rw(tcache, QS_IO_READ);
	tdisk_update_alloc_lba_write(lba_alloc, tdisk->lba_read_wait, LBA_WRITE_DONE_IO);

	wait_for_done(tcache->completion);
	TDISK_TEND(tdisk, tcache_read_wait_ticks, start_ticks);

	if (atomic_test_bit_short(TCACHE_IO_ERROR, &tcache->flags))
		goto err;

	tcache_read_comp(tcache);

skip_io:
	tdisk_remove_alloc_lba_write(&lba_alloc, tdisk->lba_read_wait, &tdisk->lba_read_list);
	TDISK_TSTART(start_ticks);
	retval = pgdata_post_read_io(pglist, pglist_cnt, &rcache_list, enable_rcache, norefs, 0);
	TDISK_TEND(tdisk, post_read_io_ticks, start_ticks);
	if (enable_rcache)
		rcache_list_insert(&rcache_list);
	tdisk_remove_lba_write(tdisk, &read_lba_write);
	if (unlikely(retval != 0)) {
		goto err;
	}

	tcache_put(tcache);
	*ret_pglist = pglist;
	*ret_pglist_cnt = pglist_cnt;
	return 0;
err:
	tdisk_remove_alloc_lba_write(&lba_alloc, tdisk->lba_read_wait, &tdisk->lba_read_list);
	tdisk_remove_lba_write(tdisk, &read_lba_write);
	tcache_put(tcache);
	pgdata_free_amaps(pglist, pglist_cnt);
	if (!norefs)
		pglist_free(pglist, pglist_cnt);
	else {
		pglist_free_norefs(*ret_pglist, *ret_pglist_cnt);
		ctio->dxfer_len = 0;
		ctio->pglist_cnt = 0;
		ctio->data_ptr = NULL;
		ctio_clear_norefs(ctio);
		*ret_pglist = NULL;
		*ret_pglist_cnt = 0;
	}
	rcache_list_free(&rcache_list);
	ctio_construct_sense(ctio, SSD_CURRENT_ERROR, SSD_KEY_HARDWARE_ERROR, 0, INTERNAL_TARGET_FAILURE_ASC, INTERNAL_TARGET_FAILURE_ASCQ);
	return -1;
}

void
ctio_fix_pglist_len(struct qsio_scsiio *ctio)
{
	int dxfer_len = ctio->dxfer_len;
	int i;
	struct pgdata *pgdata, **pglist;

	pglist = (struct pgdata **)ctio->data_ptr;
	for (i = 0; i < ctio->pglist_cnt; i++) {
		pgdata = pglist[i];
		if (i == (ctio->pglist_cnt - 1)) {
			pgdata->pg_len = dxfer_len;
			break;
		}
		dxfer_len -= pgdata->pg_len;
	}
}

static void
__tdisk_cmd_read(struct tdisk *tdisk, struct qsio_scsiio *ctio, uint64_t lba, uint32_t transfer_length)
{
	struct pgdata **pglist;
	int retval;
	int pglist_cnt;

	pglist = (struct pgdata **)ctio->data_ptr;
	pglist_cnt = ctio->pglist_cnt;

	retval = __tdisk_cmd_read_int(tdisk, ctio, &pglist, &pglist_cnt, lba, transfer_length, !ctio_norefs(ctio), NULL);
	if (unlikely(retval != 0)) {
		ctio_free_data(ctio);
		device_send_ccb(ctio);
		return;
	}
	ctio->data_ptr = (void *)pglist;
	ctio->pglist_cnt = pglist_cnt;
	ctio->dxfer_len = transfer_length << tdisk->lba_shift;

	if (ctio->dxfer_len && tdisk->lba_shift != LBA_SHIFT) {
		uint64_t lba_diff;
		int pg_offset;
		struct pgdata *pgdata;

		lba_diff = (lba - (lba & ~0x7ULL));
		pg_offset = (lba_diff << tdisk->lba_shift);
		pgdata = pglist[0];
		pgdata->pg_offset = pg_offset;
		pgdata->pg_len -= pg_offset;

		if (lba_diff || (ctio->dxfer_len & LBA_MASK))
			ctio_fix_pglist_len(ctio);
	}

	device_send_ccb(ctio);
}

struct amap_sync *
amap_sync_alloc(struct amap *amap, uint64_t write_id)
{
	struct amap_sync *amap_sync;

	amap_sync = __uma_zalloc(amap_sync_cache, Q_WAITOK | Q_ZERO, sizeof(*amap_sync));
	STAILQ_INIT(&amap_sync->pgdata_list);
	amap_get(amap);
	amap_sync->amap = amap;
	amap_sync->write_id = write_id;
	return amap_sync;
}

static void
pgdata_cancel(struct tdisk *tdisk, struct pgdata **pglist, int pglist_cnt, struct amap_sync_list *amap_sync_list, struct index_sync_list *index_sync_list, struct index_info_list *index_info_list)
{
	struct pgdata *pgdata;
	struct amap *amap;
	uint32_t entry_id;
	int i;

	for (i = 0; i < pglist_cnt; i++) {
		pgdata = pglist[i];
		if (!atomic_test_bit(PGDATA_DONE_AMAP_UPDATE, &pgdata->flags)) {
			if (!pgdata->amap_block)
				continue;

			debug_info("old block %llu new block %llu\n", (unsigned long long)BLOCK_BLOCKNR(pgdata->old_amap_block), (unsigned long long)BLOCK_BLOCKNR(pgdata->amap_block));
			process_delete_block(bdev_group_ddtable(tdisk->group), pgdata->amap_block, index_info_list, index_sync_list, NULL, TYPE_DATA_BLOCK);
			continue;
		}
		amap = pgdata->amap;
		debug_check(!amap);
		entry_id = amap_entry_id(amap, pgdata->lba);
		amap_lock(amap);
		debug_info("old block %llu new block %llu\n", BLOCK_BLOCKNR(pgdata->old_amap_block), BLOCK_BLOCKNR(pgdata->amap_block));
		if (amap_entry_get_block(amap, entry_id) != pgdata->amap_block) {
			amap_unlock(amap);
			continue;
		}
		amap_write_barrier(amap);
		amap_entry_set_block(amap, entry_id, pgdata->old_amap_block);
		if (write_id_greater(amap->write_id, pgdata->amap_write_id)) {
			atomic_set_bit_short(AMAP_META_IO_PENDING, &amap->flags);
			amap_check_sync_list(amap, amap_sync_list, NULL, WRITE_ID_MAX);
		}
		amap_unlock(amap);
		process_delete_block(bdev_group_ddtable(tdisk->group), pgdata->amap_block, index_info_list, index_sync_list, NULL, TYPE_DATA_BLOCK);
	}
}

void
amap_sync_list_free_error(struct amap_sync_list *lhead)
{
	struct amap_sync *amap_sync;
	struct amap *amap;
	struct amap_sync_list tmp_list;

	SLIST_INIT(&tmp_list);

	while ((amap_sync = SLIST_FIRST(lhead)) != NULL) {
		SLIST_REMOVE_HEAD(lhead, s_list);
		amap = amap_sync->amap;
		amap_lock(amap);
		if (iowaiter_done_io(&amap_sync->iowaiter)) {
			amap_unlock(amap);
			SLIST_INSERT_HEAD(&tmp_list, amap_sync, s_list);
			continue;
		}

		SLIST_REMOVE(&amap->io_waiters, &amap_sync->iowaiter, iowaiter, w_list);
		amap_unlock(amap);
		amap_end_writes_noio(amap, amap_sync->write_id);
		amap_put(amap);
		free_iowaiter(&amap_sync->iowaiter);
		uma_zfree(amap_sync_cache, amap_sync);
	}

	while ((amap_sync = SLIST_FIRST(&tmp_list)) != NULL) {
		SLIST_REMOVE_HEAD(&tmp_list, s_list);
		amap = amap_sync->amap;
		debug_check(!iowaiter_done_io(&amap_sync->iowaiter));
		iowaiter_end_wait(&amap_sync->iowaiter);
		amap_put(amap);
		free_iowaiter(&amap_sync->iowaiter);
		uma_zfree(amap_sync_cache, amap_sync);
	}
}

void
sync_amap_list_pre(struct tdisk *tdisk, struct write_list *wlist)
{
	struct amap_sync *amap_sync;
	struct amap *amap;
	iodev_t *prev_b_dev = NULL;
	struct tpriv priv = { 0 };
	int done_io;

	if (atomic_test_bit(WLIST_DONE_AMAP_SYNC, &wlist->flags))
		return;

	bzero(&priv, sizeof(priv));
	SLIST_FOREACH(amap_sync, &wlist->amap_sync_list, s_list) {
		amap = amap_sync->amap;
		done_io = amap_end_writes(amap, amap_sync->write_id);
		TDISK_INC(tdisk, inline_amap_writes, 1);
		if (!done_io)
			continue;
		if (prev_b_dev && amap_bint(amap)->b_dev != prev_b_dev) {
			if (!priv.data)
				bdev_start(prev_b_dev, &priv);
		}
		else if (!prev_b_dev) {
			bdev_marker(amap_bint(amap)->b_dev, &priv);
		}
		prev_b_dev = amap_bint(amap)->b_dev;
	}
	if (prev_b_dev)
		bdev_start(prev_b_dev, &priv);
	atomic_set_bit(WLIST_DONE_AMAP_SYNC, &wlist->flags);

}

static void
sync_amap_list_post(struct tdisk *tdisk, struct write_list *wlist)
{
	struct amap_sync *amap_sync;

	SLIST_FOREACH(amap_sync, &wlist->amap_sync_list, s_list) {
		iowaiter_wait_for_done_io(&amap_sync->iowaiter);
	}
}

static int 
__pgdata_amap_io(struct tdisk *tdisk, struct amap_sync *amap_sync)
{
	uint64_t entry_block;
	struct amap *amap;
	struct pgdata *pgdata;
	uint32_t entry_id;
#ifdef ENABLE_STATS
	uint32_t start_ticks;
#endif
	int has_updates = 0;

	amap = amap_sync->amap;
	TDISK_TSTART(start_ticks);
	amap_lock(amap);
	amap_write_barrier(amap);
	amap_clone_check(tdisk, amap, 0);
	STAILQ_FOREACH(pgdata, &amap_sync->pgdata_list, a_list) {
		entry_id = amap_entry_id(amap, pgdata->lba);
		entry_block = amap_entry_get_block(amap, entry_id);
		if (!entry_block && !pgdata->amap_block) {
			debug_check(!atomic_test_bit(DDBLOCK_ZERO_BLOCK, &pgdata->flags));
			continue;
		}

		has_updates = 1;
		pgdata->old_amap_block = entry_block;
		pgdata->amap_write_id = amap->write_id;
		amap_entry_set_block(amap, entry_id, pgdata->amap_block);
		atomic_set_bit(PGDATA_DONE_AMAP_UPDATE, &pgdata->flags);
	}
	amap_unlock(amap);
	TDISK_TEND(tdisk, amap_write_setup_ticks, start_ticks);
	return has_updates;
}

struct amap *
amap_locate_by_block(uint64_t block, struct amap_sync_list *amap_sync_list)
{
	struct amap_sync *amap_sync;
	struct amap *amap;

	SLIST_FOREACH(amap_sync, amap_sync_list, s_list) {
		amap = amap_sync->amap;

		if (amap->amap_block == block)
			return amap;
	}
	debug_check(1);
	return NULL;
}

struct amap_table *
amap_table_locate_by_block(uint64_t block, struct amap_sync_list *amap_sync_list)
{
	struct amap_sync *amap_sync;
	struct amap *amap;
	struct amap_table *amap_table;

	SLIST_FOREACH(amap_sync, amap_sync_list, s_list) {
		amap = amap_sync->amap;
		amap_table = amap->amap_table;

		if (amap_table->amap_table_block == block)
			return amap_table;
	}
	debug_check(1);
	return NULL;
}

static int
amap_allocated_by_thr(struct amap *amap, struct write_list *wlist)
{
	struct index_info *index_info;

	TAILQ_FOREACH(index_info, &wlist->meta_index_info_list, i_list) {
		if (index_info->meta_type != INDEX_INFO_TYPE_AMAP)
			continue;
		if (index_info->block != amap->amap_block)
			continue;
		return 1;
	}
	return 0;
}

static int
amap_table_allocated_by_thr(struct amap_table *amap_table, struct write_list *wlist)
{
	struct index_info *index_info;

	TAILQ_FOREACH(index_info, &wlist->meta_index_info_list, i_list) {
		if (index_info->meta_type != INDEX_INFO_TYPE_AMAP_TABLE)
			continue;
		if (index_info->block != amap_table->amap_table_block)
			continue;
		return 1;
	}
	return 0;
}

static void 
index_info_calc_count(struct write_list *wlist, int *ret_amap_table_count, int *ret_amap_count)
{
	struct index_info *index_info;
	int amap_count = 0;
	int amap_table_count = 0;

	TAILQ_FOREACH(index_info, &wlist->meta_index_info_list, i_list) {
		if (index_info->meta_type == INDEX_INFO_TYPE_AMAP)
			amap_count++;
		else
			amap_table_count++;
	}
	*ret_amap_table_count = amap_table_count;
	*ret_amap_count = amap_count;
}

static void
tdisk_handle_meta_log(struct tdisk *tdisk, struct write_list *wlist, int error)
{
	struct bdevgroup *group = bdev_group_get_log_group(tdisk->group);
	struct log_page *log_page;
	struct index_info *index_info;
	struct amap_table *amap_table;
	struct amap_sync *amap_sync;
	struct amap *amap;
#ifdef ENABLE_STATS
	uint32_t start_ticks;
#endif
	int amap_table_count, amap_count;

	index_info_calc_count(wlist, &amap_table_count, &amap_count);

	if (!amap_table_count)
		goto skip_amap_table_insert;

	sx_xlock(group->log_lock);
	log_page = get_free_log_page(group, &wlist->log_list);
	TDISK_TSTART(start_ticks);
	TAILQ_FOREACH(index_info, &wlist->meta_index_info_list, i_list) {
		if (index_info->meta_type != INDEX_INFO_TYPE_AMAP_TABLE)
			continue;
		if (group->free_idx == V2_LOG_ENTRIES)
			log_page = get_free_log_page(group, &wlist->log_list);
		amap_table = amap_table_locate_by_block(index_info->block, &wlist->amap_sync_list);
		fastlog_add_transaction(index_info, tdisk, amap_table_get_lba_start(amap_table->amap_table_id), log_page, group->free_idx);
		atomic_set_bit_short(ATABLE_META_LOG_DONE, &amap_table->flags);
		chan_wakeup(amap_table->amap_table_wait);
		atomic_inc(&log_page->pending_transactions);
		group->free_idx++;
	}
	TDISK_TEND(tdisk, fastlog_add_ticks, start_ticks);
	sx_xunlock(group->log_lock);

skip_amap_table_insert:
	SLIST_FOREACH(amap_sync, &wlist->amap_sync_list, s_list) {
		amap = amap_sync->amap;
		amap_table = amap->amap_table;
		if (atomic_test_bit_short(ATABLE_META_DATA_NEW, &amap_table->flags)) {
			if (!amap_table_allocated_by_thr(amap_table, wlist))
				wait_on_chan(amap_table->amap_table_wait, atomic_test_bit_short(ATABLE_META_LOG_DONE, &amap_table->flags));
		}
	}

	if (!amap_count)
		goto skip_amap_insert;

	sx_xlock(group->log_lock);
	log_page = get_free_log_page(group, &wlist->log_list);
	TDISK_TSTART(start_ticks);
	TAILQ_FOREACH(index_info, &wlist->meta_index_info_list, i_list) {
		if (index_info->meta_type != INDEX_INFO_TYPE_AMAP)
			continue;

		if (group->free_idx == V2_LOG_ENTRIES)
			log_page = get_free_log_page(group, &wlist->log_list);
		amap = amap_locate_by_block(index_info->block, &wlist->amap_sync_list);
		fastlog_add_transaction(index_info, tdisk, amap_get_lba_start(amap->amap_id), log_page, group->free_idx);
		atomic_set_bit_short(AMAP_META_LOG_DONE, &amap->flags);
		chan_wakeup(amap->amap_wait);
		atomic_inc(&log_page->pending_transactions);
		group->free_idx++;
	}
	TDISK_TEND(tdisk, fastlog_add_ticks, start_ticks);
	sx_xunlock(group->log_lock);

skip_amap_insert:
	SLIST_FOREACH(amap_sync, &wlist->amap_sync_list, s_list) {
		amap = amap_sync->amap;
		if (atomic_test_bit_short(AMAP_META_DATA_NEW, &amap->flags)) {
			if (!amap_allocated_by_thr(amap, wlist))
				wait_on_chan(amap->amap_wait, atomic_test_bit_short(AMAP_META_LOG_DONE, &amap->flags));
		}
	}
}

int
pgdata_amap_io(struct tdisk *tdisk, struct write_list *wlist)
{
	struct amap_sync *amap_sync, *tvar;
	struct amap *amap;
	struct pgdata *pgdata;
#ifdef ENABLE_STATS
	uint32_t start_ticks;
#endif
	struct bdevgroup *group = bdev_group_get_log_group(tdisk->group);
	struct log_page *log_page;
	int retval, has_updates;

	if (SLIST_EMPTY(&wlist->amap_sync_list))
		return 0;

	SLIST_FOREACH(amap_sync, &wlist->amap_sync_list, s_list) {
		amap = amap_sync->amap;
		if (atomic_test_bit_short(AMAP_META_DATA_READ_DIRTY, &amap->flags)) {
			TDISK_INC(tdisk, amap_wait, 1);
			TDISK_TSTART(start_ticks);
			wait_on_chan_check(amap->amap_wait, !atomic_test_bit_short(AMAP_META_DATA_READ_DIRTY, &amap->flags));
			TDISK_TEND(tdisk, amap_wait_ticks, start_ticks);
		}

		if (!atomic_test_bit_short(AMAP_CSUM_CHECK_DONE, &amap->flags)) {
			amap_lock(amap);
			amap_check_csum(amap);
			amap_unlock(amap);
		}

		if (atomic_test_bit_short(AMAP_META_DATA_ERROR, &amap->flags)) {
			return -1;
		}
	}

	has_updates = 0;
	SLIST_FOREACH(amap_sync, &wlist->amap_sync_list, s_list) {
		retval = __pgdata_amap_io(tdisk, amap_sync);
		if (retval)
			has_updates = 1;
	}

	if (!has_updates && TAILQ_EMPTY(&wlist->meta_index_info_list)) {
		wlist->nowrites_amap_sync_list.slh_first = wlist->amap_sync_list.slh_first;
		SLIST_INIT(&wlist->amap_sync_list);
		return 0;
	}

	tdisk_handle_meta_log(tdisk, wlist, 0);

	sx_xlock(group->log_lock);
	log_page = get_free_log_page(group, &wlist->log_list);
	TDISK_TSTART(start_ticks);
	SLIST_FOREACH_SAFE(amap_sync, &wlist->amap_sync_list, s_list, tvar) {
		amap = amap_sync->amap;
		has_updates = 0;
		STAILQ_FOREACH(pgdata, &amap_sync->pgdata_list, a_list) {
			if (!atomic_test_bit(PGDATA_DONE_AMAP_UPDATE, &pgdata->flags))
				continue;

			if (group->free_idx == V2_LOG_ENTRIES)
				log_page = get_free_log_page(group, &wlist->log_list);
			fastlog_insert_transaction(pgdata, tdisk, log_page, group->free_idx);
			group->free_idx++;
			atomic_inc(&log_page->pending_transactions);
			has_updates = 1;
		}

		if (!has_updates && !atomic_test_bit_short(AMAP_META_DATA_NEW, &amap->flags)) {
			SLIST_REMOVE(&wlist->amap_sync_list, amap_sync, amap_sync, s_list);
			amap_sync_list_insert_tail(&wlist->nowrites_amap_sync_list, amap_sync);
		}
	}
	TDISK_TEND(tdisk, fastlog_insert_ticks, start_ticks);
	sx_xunlock(group->log_lock);

	atomic_set_bit(WLIST_DONE_LOG_START, &wlist->flags);

#if 0
	TDISK_TSTART(start_ticks);
	log_list_end_writes(&wlist->log_list);
	TDISK_TEND(tdisk, log_list_end_writes_ticks, start_ticks);
#endif

	return 0;
}

void
table_index_write(struct tdisk *tdisk, struct amap_table_index *table_index, uint32_t index_id, uint32_t index_offset, struct amap_table *amap_table)
{
	struct bio_meta bio_meta;
#ifdef ENABLE_STATS
	uint32_t start_ticks;
#endif
	uint64_t block;

	TDISK_TSTART(start_ticks);
	sx_xlock(table_index->table_index_lock);
	block = get_amap_table_block(table_index, index_offset);
	if (!block) {
		amap_table_index_write_barrier(tdisk, table_index);
		set_amap_table_block(table_index, index_offset, amap_table->amap_table_block);
		bio_meta_init(&bio_meta);
		qs_lib_bio_page(table_index->bint, table_index->b_start, BINT_INDEX_META_SIZE, table_index->metadata, NULL, &bio_meta, QS_IO_WRITE, TYPE_TDISK_INDEX);
		node_table_index_sync_send(tdisk, table_index, index_id);
		atomic_set_bit(META_DATA_DIRTY, &table_index->flags);
		sx_xunlock(table_index->table_index_lock);
		wait_for_bio_meta(&bio_meta);
		bio_meta_destroy(&bio_meta);
		atomic_clear_bit(META_DATA_DIRTY, &table_index->flags);
		chan_wakeup(table_index->table_index_wait);
		debug_check(!atomic_test_bit_short(ATABLE_META_DATA_NEW, &amap_table->flags));
		atomic_clear_bit_short(ATABLE_META_DATA_NEW, &amap_table->flags);
		chan_wakeup(amap_table->amap_table_wait);
	}
	else {
		sx_xunlock(table_index->table_index_lock);
		debug_check(block != amap_table->amap_table_block);
		wait_on_chan_check(amap_table->amap_table_wait, !atomic_test_bit_short(ATABLE_META_DATA_NEW, &amap_table->flags));
	}
	TDISK_TEND(tdisk, table_index_write_ticks, start_ticks);
}

static void
amap_table_sync_list_index_write(struct tdisk *tdisk, struct amap_table_sync_list *sync_list)
{
	struct amap_table_sync *amap_table_sync;
	struct amap_table *amap_table;
	struct amap_table_index *table_index;
	uint32_t index_id, index_offset;

	while ((amap_table_sync = STAILQ_FIRST(sync_list)) != NULL) {
		STAILQ_REMOVE_HEAD(sync_list, w_list);
		amap_table = amap_table_sync->amap_table;
		index_id = amap_table->amap_table_id >> INDEX_TABLE_GROUP_SHIFT;
		index_offset = amap_table->amap_table_id & INDEX_TABLE_GROUP_MASK;
		table_index = &tdisk->table_index[index_id];
		table_index_write(tdisk, table_index, index_id, index_offset, amap_table);
		free(amap_table_sync, M_AMAP_TABLE_SYNC);
	}
}

static void
amap_table_sync_list_end_wait(struct amap_table_sync_list *sync_list)
{
	struct amap_table_sync *amap_table_sync;

	STAILQ_FOREACH(amap_table_sync, sync_list, w_list) {
		amap_table_end_wait(amap_table_sync->amap_table, &amap_table_sync->iowaiter);
		free_iowaiter(&amap_table_sync->iowaiter);
	}
}

static void
amap_table_sync_list_end_writes(struct amap_table_sync_list *sync_list)
{
	struct amap_table_sync *amap_table_sync;

	STAILQ_FOREACH(amap_table_sync, sync_list, w_list) {
		amap_table_end_writes(amap_table_sync->amap_table);
	}
}

static void
amap_table_sync_list_add(struct amap_table *amap_table, struct amap_table_sync_list *sync_list)
{
	struct amap_table_sync *amap_table_sync;

	STAILQ_FOREACH(amap_table_sync, sync_list, w_list) {
		if (amap_table_sync->amap_table == amap_table)
			return;
	}
	amap_table_sync = zalloc(sizeof(*amap_table_sync), M_AMAP_TABLE_SYNC, Q_WAITOK);
	amap_table_sync->amap_table = amap_table;
	amap_table_start_writes(amap_table, &amap_table_sync->iowaiter);
	STAILQ_INSERT_TAIL(sync_list, amap_table_sync, w_list);
}

void
pgdata_wait_for_amap(struct tdisk *tdisk, struct amap_sync_list *amap_sync_list)
{
	struct amap *amap;
	struct amap_table *amap_table;
	struct amap_sync *amap_sync;
	uint64_t block;
	struct amap_table_sync_list amap_table_sync_list;
	STAILQ_HEAD(, amap_sync) amap_wait_list;
	STAILQ_HEAD(, amap_sync) amap_list;
#ifdef ENABLE_STATS
	uint32_t start_ticks;
#endif

	STAILQ_INIT(&amap_table_sync_list);
	STAILQ_INIT(&amap_list);
	STAILQ_INIT(&amap_wait_list);
	SLIST_FOREACH(amap_sync, amap_sync_list, s_list) {
		amap = amap_sync->amap;
		TDISK_TSTART(start_ticks);
		amap_end_wait(amap, &amap_sync->iowaiter);
		TDISK_TEND(tdisk, amap_end_wait_ticks, start_ticks);

		amap_table = amap->amap_table;
		amap_table_lock(amap_table);
		block = get_amap_block(amap_table, amap->amap_idx);
		debug_check(!block && !atomic_test_bit_short(AMAP_META_DATA_NEW, &amap->flags));
		if (block) {
			amap_table_unlock(amap_table);
 			if (atomic_test_bit_short(AMAP_META_DATA_NEW, &amap->flags))
				STAILQ_INSERT_TAIL(&amap_wait_list, amap_sync, w_list);
			continue;
		}

		amap_table_sync_list_add(amap_table, &amap_table_sync_list);
		amap_table_write_barrier(amap_table);
		set_amap_block(amap_table, amap->amap_idx, amap->amap_block);

		amap_table_unlock(amap_table);
		STAILQ_INSERT_TAIL(&amap_list, amap_sync, w_list);
	}

	TDISK_TSTART(start_ticks);
	amap_table_sync_list_end_writes(&amap_table_sync_list);
	amap_table_sync_list_end_wait(&amap_table_sync_list);

	TDISK_TEND(tdisk, amap_table_end_wait_ticks, start_ticks);

	STAILQ_FOREACH(amap_sync, &amap_list, w_list) {
		amap = amap_sync->amap;
		atomic_clear_bit_short(AMAP_META_DATA_NEW, &amap->flags);
		chan_wakeup(amap->amap_wait);
	}

	STAILQ_FOREACH(amap_sync, &amap_wait_list, w_list) {
		amap = amap_sync->amap;
		wait_on_chan_check(amap->amap_wait, !atomic_test_bit_short(AMAP_META_DATA_NEW, &amap->flags));
	}

	amap_table_sync_list_index_write(tdisk, &amap_table_sync_list);
}

void
pgdata_cleanup(struct pgdata *pgdata)
{
	if (pgdata->amap) {
		amap_put(pgdata->amap);
		pgdata->amap = NULL;
	}

	if (pgdata->amap_table) {
		amap_table_put(pgdata->amap_table);
		pgdata->amap_table = NULL;
	}

	if (pgdata->comp_pgdata) {
		pgdata_free(pgdata->comp_pgdata);
		pgdata->comp_pgdata = NULL;
	}
}

void
pglist_check_free(struct pgdata **pglist, int pglist_cnt, int norefs)
{
	int i;

	for (i = 0; i < pglist_cnt; i++) {
		struct pgdata *pgtmp = pglist[i];

		pgdata_cleanup(pgtmp);
		if (!norefs)
			pgdata_free(pgtmp);
		else
			pgdata_free_norefs(pgtmp);
	}
	free(pglist, M_PGLIST);
}

void
ctio_check_free_data(struct qsio_scsiio *ctio)
{
	if (!ctio->dxfer_len)
		return;

	if (ctio->pglist_cnt)
		pglist_check_free((void *)ctio->data_ptr, ctio->pglist_cnt, ctio_norefs(ctio));
	else
		free(ctio->data_ptr, M_CTIODATA);

	ctio->data_ptr = NULL;
	ctio->dxfer_len = 0;
	ctio->pglist_cnt = 0;
}

void wlist_release_log_reserved(struct tdisk *tdisk, struct write_list *wlist)
{
	struct bdevgroup *group;

	group = bdev_group_get_log_group(tdisk->group);
	chan_lock(group->wait_on_log);
	group->reserved_log_entries -= wlist->log_reserved;
	chan_wakeup_unlocked(group->wait_on_log);
	chan_unlock(group->wait_on_log);
}

static void
pglist_reset_pages(struct pgdata **pglist, int pglist_cnt)
{
	int i;

	for (i = 0; i < pglist_cnt; i++) {
		struct pgdata *pgtmp = pglist[i];
		pgtmp->page = NULL;
	}
}

void
pgdata_post_write(struct tdisk *tdisk, struct pgdata **pglist, int pglist_cnt, struct write_list *wlist)
{
	struct ddwork *ddwork;
#ifdef ENABLE_STATS
	uint32_t start_ticks;
#endif

	TDISK_TSTART(start_ticks);
	tdisk_mirror_write_done_post(tdisk, wlist);
	TDISK_TEND(tdisk, mirror_write_done_post_ticks, start_ticks);

	sync_amap_list_post(tdisk, wlist);

	tdisk_remove_lba_write(tdisk, &wlist->lba_write);

	if (SLIST_EMPTY(&wlist->amap_sync_list))
		goto reset;

	ddwork = __uma_zalloc(ddwork_cache, Q_WAITOK | Q_ZERO, sizeof(*ddwork));
	tdisk_get(tdisk);
	ddwork->tdisk = tdisk;
	ddwork->log_list.slh_first = wlist->log_list.slh_first;
	ddwork->pglist = pglist;
	ddwork->pglist_cnt = pglist_cnt;
	ddwork->log_reserved = wlist->log_reserved;
	ddwork->transaction_id = wlist->transaction_id;
	ddwork->newmeta_transaction_id = wlist->newmeta_transaction_id;
	TAILQ_INIT(&ddwork->index_info_list);
	TAILQ_CONCAT(&ddwork->index_info_list, &wlist->index_info_list, i_list);
	TAILQ_INIT(&ddwork->meta_index_info_list);
	TAILQ_CONCAT(&ddwork->meta_index_info_list, &wlist->meta_index_info_list, i_list);
	ddwork->amap_sync_list.slh_first = wlist->amap_sync_list.slh_first;

#if 0
	SLIST_INIT(&ddwork->index_sync_list);
	DD_TSTART(start_ticks);
	index_list_insert(&ddwork->index_sync_list, &ddwork->index_list);
	DD_TEND(index_list_insert_ticks, start_ticks);

	DD_TSTART(start_ticks);
	index_list_insert(&ddwork->index_sync_list, &ddwork->meta_index_list);
	DD_TEND(index_list_meta_insert_ticks, start_ticks);

	DD_TSTART(start_ticks);
	index_sync_start_io(&ddwork->index_sync_list, 1);
	DD_TEND(index_sync_ticks, start_ticks);
#endif

	ddthread_insert(ddwork);
	return;
reset:
	if (atomic_test_bit(WLIST_DONE_NEWMETA_SYNC_START, &wlist->flags))
		node_newmeta_sync_complete(tdisk, wlist->newmeta_transaction_id);
	node_pgdata_sync_complete(tdisk, wlist->transaction_id);
	pglist_cnt_decr(pglist_cnt);
	wlist_release_log_reserved(tdisk, wlist);
	fastlog_log_list_free(&wlist->log_list);
	pglist_check_free(pglist, pglist_cnt, 0);
	return;
}

static void
pgdata_reset_ddblock(struct pgdata *pgdata, struct write_list *wlist)
{
	struct index_info *index_info = pgdata->index_info, *new;
	struct bintindex *index = index_info->index;
	struct bdevint *bint = index->subgroup->group->bint;
	uint32_t entry_id;
	int freed;

	index_id_from_block(bint, BLOCK_BLOCKNR(pgdata->amap_block), &entry_id);
	new = index_info_alloc();
	index_get(index);
	new->index = index;
	index_lock(index);
	index_check_load(index);
	index_write_barrier(bint, index);
	bint_free_block(bint, index, entry_id, lba_block_size(pgdata->amap_block), &freed, TYPE_DATA_BLOCK, 0);
	index_add_iowaiter(index, &new->iowaiter);
	index_unlock(index);
	TAILQ_INSERT_TAIL(&wlist->index_info_list, new, i_list);
	pgdata->index_info = NULL;
	pgdata->amap_block = 0;
	pgdata->flags = 0;
	atomic_set_bit(DDBLOCK_DEDUPE_DISABLED, &pgdata->flags);
}

static int
tdisk_verify_block(struct tdisk *tdisk, struct pgdata *pgdata, struct write_list *wlist, int verify_count, struct pgdata_wlist *verify_list)
{
	struct pgdata pgtmp;
	int retval;
	int cmp;
	struct tcache *tcache;
	struct bdevint *bint;

	pgtmp.amap_block = pgdata->amap_block;
	pgdata_add_page_ref(&pgtmp, pgdata->page);
	retval = rcache_locate(&pgtmp, 0);
	if (retval) {
		cmp = memcmp((uint8_t *)pgdata_page_address(&pgtmp), (uint8_t *)pgdata_page_address(pgdata), LBA_SIZE);
		vm_pg_free(pgtmp.page);
		if (!cmp) {
			TDISK_STATS_ADD(tdisk, verify_hits, 1);
			return 1;
		}
		debug_info("verify failed for %llu\n", (unsigned long long)BLOCK_BLOCKNR(pgdata->amap_block));
		pgdata_reset_ddblock(pgdata, wlist);
		pgdata->flags = 0;
		TDISK_STATS_ADD(tdisk, verify_misses, 1);
		return 0;
	}
	vm_pg_free(pgtmp.page);

	tcache = wlist->read_tcache;
	if (!tcache) {
		tcache = wlist->read_tcache = tcache_alloc(verify_count);
	}

	bint = bdev_find(BLOCK_BID(pgdata->amap_block));
	if (unlikely(!bint)) {
		debug_warn("Cannot find bdev at %u\n", BLOCK_BID(pgdata->amap_block));
		pgdata_reset_ddblock(pgdata, wlist);
		TDISK_STATS_ADD(tdisk, verify_errors, 1);
		return 0;
	}

	pgdata->verify_page = vm_pg_alloc(0);
	if (unlikely(!pgdata->verify_page)) {
		debug_warn("Page allocation failure\n");
		pgdata_reset_ddblock(pgdata, wlist);
		TDISK_STATS_ADD(tdisk, verify_errors, 1);
		return 0;
	}

	retval = tcache_add_page(tcache, pgdata->verify_page, BLOCK_BLOCKNR(pgdata->amap_block), bint, lba_block_size(pgdata->amap_block), QS_IO_READ);
	if (unlikely(retval != 0)) {
		debug_warn("Failed to add page to tcache\n");
		vm_pg_free(pgdata->verify_page);
		pgdata_reset_ddblock(pgdata, wlist);
		TDISK_STATS_ADD(tdisk, verify_errors, 1);
		return 0;
	}
	STAILQ_INSERT_TAIL(verify_list, pgdata, w_list);
	return 0;
}

void
verify_ddblocks(struct tdisk *tdisk, struct pgdata_wlist *dedupe_list, struct write_list *wlist, int verify_count, int enable_rcache)
{
	struct pgdata *pgdata;
	struct tcache *tcache;
	struct pgdata_wlist verify_list;
	struct rcache_entry_list rcache_list;
	int cmp;
	uint32_t block_size;

	STAILQ_INIT(&verify_list);
	TAILQ_INIT(&rcache_list);
	while ((pgdata = STAILQ_FIRST(dedupe_list)) != NULL) {
		STAILQ_REMOVE_HEAD(dedupe_list, w_list);
		tdisk_verify_block(tdisk, pgdata, wlist, verify_count, &verify_list);
	}

	tcache = wlist->read_tcache;
	if (!tcache) {
		debug_check(!STAILQ_EMPTY(&verify_list));
		return;
	}

	if (!atomic_read(&tcache->bio_remain)) {
		debug_check(!STAILQ_EMPTY(&verify_list));
		tcache_put(tcache);
		wlist->read_tcache = NULL;
		return;
	}
	tcache_entry_rw(tcache, QS_IO_READ);
	wait_for_done(tcache->completion);
	if (atomic_test_bit_short(TCACHE_IO_ERROR, &tcache->flags))
		goto err;

	tcache_read_comp(tcache);

	while ((pgdata = STAILQ_FIRST(&verify_list)) != NULL) {
		STAILQ_REMOVE_HEAD(&verify_list, w_list);
		block_size = lba_block_size(pgdata->amap_block);
		if (block_size != LBA_SIZE) {
			pagestruct_t *uncomp_page;
			int retval;

			uncomp_page = vm_pg_alloc(0);
			if (unlikely(!uncomp_page)) {
				debug_warn("Page allocation failure\n");
				vm_pg_free(pgdata->verify_page);
				pgdata_reset_ddblock(pgdata, wlist);
				TDISK_STATS_ADD(tdisk, verify_errors, 1);
				continue;
			}

			retval = qs_inflate_block(pgdata->verify_page, block_size, uncomp_page);
			vm_pg_free(pgdata->verify_page);
			if (unlikely(retval != 0)) {
				vm_pg_free(uncomp_page);
				pgdata_reset_ddblock(pgdata, wlist);
				TDISK_STATS_ADD(tdisk, verify_errors, 1);
				continue;
			}
			pgdata->verify_page = uncomp_page;
		}
		cmp = memcmp((uint8_t *)pgdata_page_address(pgdata), (uint8_t *)vm_pg_address(pgdata->verify_page), LBA_SIZE);
		vm_pg_free(pgdata->verify_page);
		if (!cmp) {
			TDISK_STATS_ADD(tdisk, verify_hits, 1);
			if (enable_rcache)
				rcache_add_to_list(&rcache_list, pgdata);
			continue;
		}
		debug_info("verify failed for %llu\n", (unsigned long long)BLOCK_BLOCKNR(pgdata->amap_block));
		TDISK_STATS_ADD(tdisk, verify_misses, 1);
		pgdata_reset_ddblock(pgdata, wlist);
	}
	tcache_put(tcache);
	if (!TAILQ_EMPTY(&rcache_list))
		rcache_list_insert(&rcache_list);
	wlist->read_tcache = NULL;
	return;
err:
	tcache_put(tcache);
	wlist->read_tcache = NULL;
	while ((pgdata = STAILQ_FIRST(&verify_list)) != NULL) {
		STAILQ_REMOVE_HEAD(&verify_list, w_list);
		vm_pg_free(pgdata->verify_page);
		pgdata_reset_ddblock(pgdata, wlist);
	}
}

void 
check_pending_ddblocks(struct tdisk *tdisk, struct pgdata_wlist *pending_list, struct pgdata_wlist *dedupe_list, struct write_list *wlist, int verify_data, int *verify_count)
{
	struct ddblock_info *info;
	struct bintindex *index; 
	struct pgdata *pgdata;

	while ((pgdata = STAILQ_FIRST(pending_list)) != NULL) {
		STAILQ_REMOVE_HEAD(pending_list, w_list);
		info = pgdata->ddblock_info;
		pgdata->ddblock_info = NULL;
		debug_check(!info);

		index = info->index_info->index;
		index_info_free(info->index_info);
		free(info, M_DDBLOCK_INFO);
		pgdata->flags = 0;
		wait_on_chan(index->index_wait, !atomic_test_bit(META_DATA_READ_DIRTY, &index->flags));
		if (atomic_test_bit(META_DATA_ERROR, &index->flags)) {
			index_put(index);
			atomic_set_bit(DDBLOCK_DEDUPE_DISABLED, &pgdata->flags);
			continue;
		}

		scan_dedupe_data(tdisk->group, pgdata, wlist);
		debug_check(atomic_test_bit(DDBLOCK_ENTRY_INDEX_LOADING, &pgdata->flags));
		index_put(index);
		if (atomic_test_bit(DDBLOCK_ENTRY_FOUND_DUPLICATE, &pgdata->flags)) {
			if (verify_data)
				STAILQ_INSERT_TAIL(dedupe_list, pgdata, w_list);
			*(verify_count) += 1;
		}
	}
}

void
tdisk_update_alloc_lba_write(struct lba_write *lba_alloc, wait_chan_t *chan, int flag)
{
	chan_lock(chan);
	atomic_set_bit(flag, &lba_alloc->flags);
	chan_wakeup_unlocked(chan);
	chan_unlock(chan);

}

void
tdisk_remove_alloc_lba_write(struct lba_write **ptr_lba_alloc, wait_chan_t *chan, struct lba_list *lhead)
{
	struct lba_write *lba_alloc = *ptr_lba_alloc;

	if (!lba_alloc)
		return;

	chan_lock(chan);
	TAILQ_REMOVE(lhead, lba_alloc, l_list);
	chan_wakeup_unlocked(chan);
	chan_unlock(chan);
	uma_zfree(lba_write_cache, lba_alloc);
	*ptr_lba_alloc = NULL;
}

struct lba_write * 
tdisk_add_alloc_lba_write(uint64_t lba_start, wait_chan_t *chan, struct lba_list *lhead, int flags)
{
	struct lba_write *iter, *lba_alloc;

	lba_alloc = __uma_zalloc(lba_write_cache, Q_WAITOK | Q_ZERO, sizeof(*lba_alloc));
	lba_alloc->lba_start = lba_start;
	lba_alloc->flags = flags;

	chan_lock(chan);
	TAILQ_FOREACH(iter, lhead, l_list) {
		if (iter->lba_start < lba_alloc->lba_start) {
			continue;
		}
		TAILQ_INSERT_BEFORE(iter, lba_alloc, l_list);
		chan_unlock(chan);
		return lba_alloc;
	}
	TAILQ_INSERT_TAIL(lhead, lba_alloc, l_list);
	chan_unlock(chan);
	return lba_alloc;
}

void
tdisk_check_alloc_lba_write(struct lba_write *lba_alloc, wait_chan_t *chan, struct lba_list *lhead, int flag)
{
	struct lba_write *iter;
#ifdef ENABLE_STATS
	uint32_t start_ticks;
	unsigned long elapsed;
#endif

	TDISK_TSTART(start_ticks);
	chan_lock(chan);
again:
	TAILQ_FOREACH(iter, lhead, l_list) {
		if (iter == lba_alloc)
			break;

		if ((iter->lba_start + 256) < lba_alloc->lba_start)
			continue;

		if (!atomic_test_bit(flag, &iter->flags)) {
			wait_on_chan_uncond(chan);
			goto again;
		}
	}
	chan_unlock(chan);
#ifdef ENABLE_STATS
	elapsed = get_elapsed(start_ticks);
	if (ticks_to_msecs(elapsed) > 20000) {
		debug_warn("Exceeded 20secs for flag %d elapsed %lu\n", flag, elapsed);
	} 
#endif
}

static void
tdisk_check_threshold(struct tdisk *tdisk, struct qsio_scsiio *ctio)
{
	struct bdevgroup *group;
	uint64_t avail, threshold_min, threshold_cur, threshold_max;
	struct initiator_state *istate;
	int set_size = tdisk->lba_shift == LBA_SHIFT ? THRESHOLD_SET_SIZE : THRESHOLD_SET_SIZE_LEGACY;
	int retval;
	struct usr_notify notify_msg;

	if (!tdisk->threshold || !ctio || ctio->init_int == TARGET_INT_MIRROR || ctio_in_sync(ctio))
		return;

	group = tdisk->group;
	avail = bdev_group_get_avail(group);

	threshold_min = ((tdisk->end_lba << tdisk->lba_shift) / 100) * tdisk->threshold;
	threshold_max = threshold_min + ((set_size << tdisk->lba_shift) >> 1);
	istate = ctio->istate;
	if (avail > threshold_max) {
		atomic16_set(&istate->threshold_ua, 0);
		return;
	}

	threshold_cur = ((tdisk->end_lba << tdisk->lba_shift) / 100) * (tdisk->threshold - (atomic16_read(&istate->threshold_ua) * 2));
	if (avail > threshold_cur)
		return;

	tdisk_reservation_lock(tdisk);
	if (atomic16_read(&istate->threshold_ua) > THRESHOLD_UA_MAX) {
		tdisk_reservation_unlock(tdisk);
		return;
	}

	retval = device_find_sense(istate, SSD_KEY_UNIT_ATTENTION, THIN_PROVISIONING_SOFT_THRESHOLD_REACHED_ASC, THIN_PROVISIONING_SOFT_THRESHOLD_REACHED_ASCQ);
	if (retval == 0) {
		tdisk_reservation_unlock(tdisk);
		return;
	}

	bzero(&notify_msg, sizeof(notify_msg));
	sprintf(notify_msg.notify_msg, "%llu %d",  (unsigned long long)avail, tdisk->threshold);
	node_usr_notify_msg(USR_NOTIFY_VDISK_THRESHOLD, tdisk->target_id, &notify_msg);
	atomic16_inc(&istate->threshold_ua);
	device_add_sense(ctio->istate, SSD_CURRENT_ERROR, SSD_KEY_UNIT_ATTENTION, offsetof(struct logical_block_provisioning_mode_page, desc), THIN_PROVISIONING_SOFT_THRESHOLD_REACHED_ASC, THIN_PROVISIONING_SOFT_THRESHOLD_REACHED_ASCQ);
	tdisk_reservation_unlock(tdisk);
}

int
pgdata_alloc_blocks(struct tdisk *tdisk, struct qsio_scsiio *ctio, struct pgdata_wlist *alloc_list, uint32_t size, struct index_info_list *index_info_list, struct lba_write *lba_alloc)
{
#ifdef ENABLE_STATS
	uint32_t start_ticks;
#endif
	int retval;
	struct pgdata *pgdata;
	uint64_t b_start;
	struct bdevint *ret_bint = NULL;
	struct bdevint *bint;
	struct index_info *index_info;

	TDISK_TSTART(start_ticks);
	tdisk_check_alloc_lba_write(lba_alloc, tdisk->lba_write_wait, &tdisk->lba_write_list, LBA_WRITE_DONE_ALLOC);
	TDISK_TEND(tdisk, alloc_pgdata_wait_ticks, start_ticks);

	TDISK_TSTART(start_ticks);
	retval = bdev_alloc_for_pgdata(tdisk, alloc_list, index_info_list, size, &ret_bint);
	TDISK_TEND(tdisk, alloc_pgdata_ticks, start_ticks);
	if (unlikely(retval != 0)) {
		debug_warn("alloc for pgdata size %u failed\n", size);
		return retval;
	}

	if (STAILQ_EMPTY(alloc_list)) {
		TDISK_INC(tdisk, pgalloc_hits, 1);
		tdisk_check_threshold(tdisk, ctio);
		return 0;
	}

	TDISK_INC(tdisk, pgalloc_misses, 1);
	while ((pgdata = STAILQ_FIRST(alloc_list)) != NULL) { 
		STAILQ_REMOVE_HEAD(alloc_list, w_list);
		index_info = index_info_alloc();
		if (unlikely(!index_info)) {
			debug_warn("Failed to alloc for index_info\n");
			return -1;
		}

		TDISK_TSTART(start_ticks);
		if (ret_bint) {
			int meta_shift = bint_meta_shift(ret_bint);
			uint32_t sector_size = (1U << meta_shift);

			if (pgdata->write_size < sector_size) {
				if (pgdata->comp_pgdata) {
					pgdata_free(pgdata->comp_pgdata);
					pgdata->comp_pgdata = NULL;
				}
				pgdata->write_size = LBA_SIZE;
			}
			b_start = __bdev_alloc_block(ret_bint, pgdata->write_size, index_info, TYPE_DATA_BLOCK);
			bint = ret_bint;
		}
		else {
			if (pgdata->comp_pgdata) {
				pgdata_free(pgdata->comp_pgdata);
				pgdata->comp_pgdata = NULL;
			}
			pgdata->write_size = LBA_SIZE;
			b_start = bdev_alloc_block(tdisk->group, pgdata->write_size, &bint, index_info, TYPE_DATA_BLOCK);
			ret_bint = bint;
		}
		TDISK_TEND(tdisk, alloc_block_ticks, start_ticks);
		if (unlikely(!b_start)) {
			index_info_free(index_info);
			debug_warn("bdev alloc block failed for size %u\n", pgdata->write_size);
			pause("outofspc", OUT_OF_SPACE_PAUSE);
			return ERR_CODE_NOSPACE;
		}
		SET_BLOCK(pgdata->amap_block, b_start, bint->bid);
		SET_BLOCK_SIZE(pgdata->amap_block, pgdata->write_size);
		index_info->block = pgdata->amap_block;
		TAILQ_INSERT_TAIL(index_info_list, index_info, i_list);
		atomic_set_bit(DDBLOCK_ENTRY_DONE_ALLOC, &pgdata->flags);
		debug_info("bstart %llu bid %u\n", (unsigned long long)b_start, bint->bid);
		pgdata->index_info = index_info;
	}
	tdisk_check_threshold(tdisk, ctio);
	return 0;
}

int
scan_write_data(struct tdisk *tdisk, struct qsio_scsiio *ctio, uint64_t lba, struct pgdata **pglist, int pglist_cnt, struct write_list *wlist, struct lba_write **lba_alloc, int remote, int *need_remote_comp, uint64_t amap_write_id, int in_xcopy)
{
	struct pgdata *pgdata;
	struct pgdata_wlist alloc_list;
	struct pgdata_wlist pending_list;
	struct pgdata_wlist dedupe_pending_list;
	struct amap_table *amap_table = NULL;
	struct amap *amap = NULL;
	int i;
	int retval;
	uint32_t block_size;
	uint32_t size = 0;
	int enable_compression = tdisk->enable_compression && atomic_read(&tdisk->group->comp_bdevs);
	int verify_data = tdisk->enable_verify;
	int verify_count = 0;
#ifdef ENABLE_STATS
	uint32_t start_ticks, tmp_ticks;
#endif

	size = 0;
	STAILQ_INIT(&alloc_list);
	STAILQ_INIT(&pending_list);
	STAILQ_INIT(&dedupe_pending_list);

	TDISK_TSTART(start_ticks);
	fastlog_reserve(tdisk, wlist, ((pglist_cnt << 1) + 4));
	TDISK_TEND(tdisk, fastlog_get_ticks, start_ticks);

	TDISK_TSTART(start_ticks);
	*lba_alloc = tdisk_add_alloc_lba_write(lba, tdisk->lba_write_wait, &tdisk->lba_write_list, 0);
	TDISK_TEND(tdisk, scan_write_add_alloc_lba_ticks, start_ticks);

	TDISK_TSTART(tmp_ticks);
	for (i = 0; i < pglist_cnt; i++, lba++) {
		pgdata = pglist[i];
		pgdata->lba = lba;

		TDISK_TSTART(start_ticks);
		if (!atomic_test_bit(PGDATA_HASH_CHECK_DONE, &pgdata->flags))
			wait_for_done(pgdata->completion);
		TDISK_TEND(tdisk, wait_for_pgdata_ticks, start_ticks);

		if (i && !amap && amap_get_id(lba) == amap_get_id(lba - 1) && atomic_test_bit(DDBLOCK_ZERO_BLOCK, &pgdata->flags)) {
			DD_INC(zero_blocks, 1);
			if (!atomic_test_bit(DDBLOCK_UNMAP_BLOCK, &pgdata->flags)) {
				TDISK_STATS_ADD(tdisk, blocks_deduped, 1);
				TDISK_STATS_ADD(tdisk, zero_blocks, 1);
				TDISK_STATS_ADD(tdisk, inline_deduped, 1);
			}
			continue;
		}

		TDISK_TSTART(start_ticks);
		retval = lba_unmapped_write(tdisk, lba, pgdata, wlist, amap_table, amap, &wlist->amap_sync_list, amap_write_id);
		TDISK_TEND(tdisk, lba_unmapped_write_ticks, start_ticks);
		if (unlikely(retval < 0)) {
			wait_for_pgdata(pglist, pglist_cnt);
			while ((pgdata = STAILQ_FIRST(&dedupe_pending_list)) != NULL) {
				STAILQ_REMOVE_HEAD(&dedupe_pending_list, w_list);
				wait_for_done(pgdata->completion);
			}
			debug_warn("lba unmapped write failed\n");
			return retval;
		}

		amap_table = pgdata->amap_table;
		amap = pgdata->amap;

		if (atomic_test_bit(DDBLOCK_ZERO_BLOCK, &pgdata->flags)) {
			DD_INC(zero_blocks, 1);
			if (!atomic_test_bit(DDBLOCK_UNMAP_BLOCK, &pgdata->flags)) {
				TDISK_STATS_ADD(tdisk, blocks_deduped, 1);
				TDISK_STATS_ADD(tdisk, zero_blocks, 1);
				TDISK_STATS_ADD(tdisk, inline_deduped, 1);
			}
			continue;
		}

		if (atomic_test_bit(PGDATA_SKIP_DDCHECK, &pgdata->flags))
			continue;

		if (atomic_test_bit(DDBLOCK_DEDUPE_DISABLED, &pgdata->flags)) {
			if (enable_compression) {
				if (!remote)
					gdevq_comp_insert(pgdata);
				else
					*need_remote_comp = 1;
			}
			continue;
		}


#ifndef SERIALIZED_DEDUPE
		gdevq_dedupe_insert(tdisk, pgdata, wlist);
		STAILQ_INSERT_TAIL(&dedupe_pending_list, pgdata, w_list);
#else
		TDISK_TSTART(start_ticks);
		scan_dedupe_data(bdev_group_ddtable(tdisk->group), pgdata, wlist);
		TDISK_TEND(tdisk, scan_dedupe_ticks, start_ticks);

		if (atomic_test_bit(DDBLOCK_ENTRY_INDEX_LOADING, &pgdata->flags)) {
			STAILQ_INSERT_TAIL(&pending_list, pgdata, w_list);
			TDISK_STATS_ADD(tdisk, inline_waits, 1);
		}
		else if (atomic_test_bit(DDBLOCK_ENTRY_FOUND_DUPLICATE, &pgdata->flags) && verify_data) {
			if (verify_data)
				STAILQ_INSERT_TAIL(&wlist->dedupe_list, pgdata, w_list);
			verify_count++;
		}
		else if (enable_compression && !atomic_test_bit(DDBLOCK_ZERO_BLOCK, &pgdata->flags) && !atomic_test_bit(DDBLOCK_ENTRY_FOUND_DUPLICATE, &pgdata->flags)) {
			if (!remote)
				gdevq_comp_insert(pgdata);
			else
				*need_remote_comp = 1;
		}
#endif
	}
	TDISK_TEND(tdisk, scan_write_dedupe_setup_ticks, tmp_ticks);

	TDISK_TSTART(start_ticks);
	while ((pgdata = STAILQ_FIRST(&dedupe_pending_list)) != NULL) {
		STAILQ_REMOVE_HEAD(&dedupe_pending_list, w_list);
		wait_for_done(pgdata->completion);
		if (atomic_test_bit(DDBLOCK_ENTRY_INDEX_LOADING, &pgdata->flags)) {
			STAILQ_INSERT_TAIL(&pending_list, pgdata, w_list);
			TDISK_STATS_ADD(tdisk, inline_waits, 1);
		}
		else if (atomic_test_bit(DDBLOCK_ENTRY_FOUND_DUPLICATE, &pgdata->flags) && verify_data) {
			if (verify_data)
				STAILQ_INSERT_TAIL(&wlist->dedupe_list, pgdata, w_list);
			verify_count++;
		}
		else if (enable_compression && !atomic_test_bit(DDBLOCK_ZERO_BLOCK, &pgdata->flags) && !atomic_test_bit(DDBLOCK_ENTRY_FOUND_DUPLICATE, &pgdata->flags)) {
			if (!remote)
				gdevq_comp_insert(pgdata);
			else
				*need_remote_comp = 1;
		}
	}
	TDISK_TEND(tdisk, wait_pending_ddblocks_ticks, start_ticks);

	TDISK_TSTART(start_ticks);
	if (!STAILQ_EMPTY(&pending_list)) {
		check_pending_ddblocks(tdisk, &pending_list, &wlist->dedupe_list, wlist, verify_data, &verify_count);
	}
	TDISK_TEND(tdisk, check_pending_ddblocks_ticks, start_ticks);

	TDISK_TSTART(start_ticks);
	if (!STAILQ_EMPTY(&wlist->dedupe_list)) {
		if (remote && !in_xcopy)
			goto skip_alloc;

		verify_ddblocks(tdisk, &wlist->dedupe_list, wlist, verify_count, !ctio_norefs(ctio));
	}
	TDISK_TEND(tdisk, verify_ddblocks_ticks, start_ticks);

	if (remote && *need_remote_comp)
		goto skip_alloc;

	TDISK_TSTART(start_ticks);
	for (i = 0; i < pglist_cnt; i++) {
		pgdata = pglist[i];
		if (atomic_test_bit(DDBLOCK_ZERO_BLOCK, &pgdata->flags))
			continue;

		if (atomic_test_bit(DDBLOCK_ENTRY_FOUND_DUPLICATE, &pgdata->flags)) {
			TDISK_STATS_ADD(tdisk, blocks_deduped, 1);
			TDISK_STATS_ADD(tdisk, inline_deduped, 1);
			continue;
		}

		block_size = LBA_SIZE;
		if (atomic_test_bit(PGDATA_COMP_ENABLED, &pgdata->flags)) {
			wait_for_done(pgdata->completion);
			if (pgdata->comp_pgdata) {
				block_size = pgdata->comp_pgdata->pg_len;
				TDISK_STATS_ADD(tdisk, compression_hits, 1);
			}
			else {
				TDISK_STATS_ADD(tdisk, compression_misses, 1);
			}
		}

		pgdata->write_size = block_size;
		size += block_size;
		STAILQ_INSERT_TAIL(&alloc_list, pgdata, w_list);
	}
	TDISK_TEND(tdisk, calc_alloc_size_ticks, start_ticks);

	if (!size) {
		TDISK_TSTART(start_ticks);
		tdisk_update_alloc_lba_write(*lba_alloc, tdisk->lba_write_wait, LBA_WRITE_DONE_ALLOC);
		TDISK_TEND(tdisk, scan_write_update_alloc_lba_ticks, start_ticks);
		goto skip_alloc;
	}

	TDISK_TSTART(start_ticks);
	retval = pgdata_alloc_blocks(tdisk, ctio, &alloc_list, size, &wlist->index_info_list, *lba_alloc);
	TDISK_TEND(tdisk, pgdata_alloc_blocks_ticks, start_ticks);

	TDISK_TSTART(start_ticks);
	tdisk_update_alloc_lba_write(*lba_alloc, tdisk->lba_write_wait, LBA_WRITE_DONE_ALLOC);
	TDISK_TEND(tdisk, scan_write_update_alloc_lba_ticks, start_ticks);
	if (unlikely(retval != 0)) {
		debug_warn("pgdata alloc blocks failed for size %u\n", size);
		return retval;
	}

skip_alloc:

	TDISK_TSTART(start_ticks);
	retval = pgdata_check_table_list(&wlist->table_list, &wlist->meta_index_info_list, &wlist->amap_sync_list, QS_IO_WRITE, amap_write_id);
	TDISK_TEND(tdisk, check_table_ticks, start_ticks);
	if (unlikely(retval != 0)) {
		debug_warn("pgdata check table list failed\n");
		return retval;
	}

	 if (remote && (*need_remote_comp || !STAILQ_EMPTY(&wlist->dedupe_list)))
		return 0;

	return retval;
}

atomic_t gpglist_cnt;
atomic_t gpglist_need_wait;

int
check_unaligned_data(struct tdisk *tdisk, struct qsio_scsiio *ctio, uint64_t *ret_lba, uint32_t transfer_length, int cw, int *cw_status, uint32_t *cw_offset, struct write_list *wlist)
{
	uint32_t size;
	struct pgdata **dest_pglist = NULL, **src_pglist, *pgdest, *pgsrc, *pgcmp;
	int dest_pglist_cnt = 0;
	int i, dest_idx, retval, dest_offset, min_len, src_offset;
	int cmp_idx, cmp_offset;
	uint64_t lba_diff;
	int todo;
	uint64_t lba = *ret_lba;
	int cw_failed = 0, cw_failed_set = 0;

	size = transfer_length << tdisk->lba_shift;

	if (tdisk->lba_shift == LBA_SHIFT) {
		if (!cw)
			return 0;
		lba_diff = 0;
		goto skip;
	}

	lba_diff = tdisk_get_lba_diff(tdisk, lba);

	if (!lba_diff && !(size & LBA_MASK) && !cw) {
		lba >>= 3;
		*ret_lba = lba;
		return 0;
	}

	if (lba_diff || (size & LBA_MASK)) {
		atomic_set_bit(WLIST_UNALIGNED_WRITE, &wlist->flags);
	}

	TDISK_STATS_ADD(tdisk, unaligned_size, transfer_length << tdisk->lba_shift);
	lba -= lba_diff;
	transfer_length += lba_diff;

skip:
	retval = __tdisk_cmd_read_int(tdisk, ctio, &dest_pglist, &dest_pglist_cnt, lba, transfer_length, 0, wlist->lba_write);
	if (unlikely(retval != 0))
		return -1;

	dest_idx = 0;
	dest_offset = (lba_diff << tdisk->lba_shift);
	src_pglist = (struct pgdata **)(ctio->data_ptr);
	todo = size;
	if (!cw) {
		src_offset = 0;
		i = 0;
	}
	else {
		ctio_idx_offset(size, &i, &src_offset);
	}

	cmp_idx = 0;
	cmp_offset = 0;
	while (i < ctio->pglist_cnt) {
		pgdest = dest_pglist[dest_idx];
		pgsrc = src_pglist[i];
		pgcmp = src_pglist[cmp_idx];
		wait_for_done(pgsrc->completion);
		if (pgcmp != pgsrc)
			wait_for_done(pgcmp->completion);

		min_len = min_t(int, pgdest->pg_len - dest_offset, pgsrc->pg_len - src_offset);
		min_len = min_t(int, min_len, pgcmp->pg_len - cmp_offset);

		if (min_len > todo)
			min_len = todo;

		if (cw) {
			retval = memcmp(((uint8_t *)pgdata_page_address(pgdest)) + dest_offset, (((uint8_t *)pgdata_page_address(pgcmp)) + cmp_offset), min_len);
			if (retval && !cw_failed_set) {
				cw_failed = (size - todo);
				cw_failed_set = 1;
			}
		}

		if (tdisk->lba_shift != LBA_SHIFT)
			memcpy(((uint8_t *)pgdata_page_address(pgdest)) + dest_offset, (((uint8_t *)pgdata_page_address(pgsrc)) + src_offset), min_len);

		todo -= min_len;
		dest_offset += min_len;
		if (dest_offset == pgdest->pg_len) {
			dest_offset = 0;
			dest_idx++;
		}

		src_offset += min_len;
		if (src_offset == pgsrc->pg_len) {
			src_offset = 0;
			i++;
		}

		cmp_offset += min_len;
		if (cmp_offset == pgcmp->pg_len) {
			cmp_offset = 0;
			cmp_idx++;
		}

		wait_complete_all(pgdest->completion);
		pgdest->flags = 0;
		atomic_set_bit(DDBLOCK_DEDUPE_DISABLED, &pgdest->flags);
		pgdest->amap_block = 0;
		pgdest->lba = 0;

		if (!todo)
			break;
	}

	if (tdisk->lba_shift == LBA_SHIFT) {
		pglist_free(dest_pglist, dest_pglist_cnt);
		*cw_status = cw_failed_set;
		*cw_offset = cw_failed;
		return 0;
	}

	if (!ctio_norefs(ctio)) {
		pglist_free(src_pglist, ctio->pglist_cnt);
	}
	else {
		pglist_free_norefs(src_pglist, ctio->pglist_cnt);
		ctio_clear_norefs(ctio);
	}
	ctio->data_ptr = (void *)dest_pglist;
	ctio->pglist_cnt = dest_pglist_cnt;
	ctio->dxfer_len = size;
	lba >>= 3;
	*ret_lba = lba;
	*cw_status = cw_failed_set;
	*cw_offset = cw_failed;
	return 0;
}

int
tdisk_lba_write_setup(struct tdisk *tdisk, struct qsio_scsiio *ctio, struct write_list *wlist, uint64_t lba, uint32_t transfer_length, int cw, int sync_wait, uint32_t xchg_id)
{
#ifdef ENABLE_STATS
	uint32_t start_ticks;
#endif
	int retval;
	int master;

	if (!tdisk_mirroring_configured(tdisk) || (!ctio_in_mirror(ctio) && ctio_in_sync(ctio))) {
		TDISK_TSTART(start_ticks);
		if (!ctio_remote_locked(ctio))
			wlist->lba_write = tdisk_add_lba_write(tdisk, lba, transfer_length, cw, QS_IO_WRITE, sync_wait);
		else
			wlist->lba_write = tdisk_add_lba_write(tdisk, lba, transfer_length, cw, QS_IO_WRITE, sync_wait);
		TDISK_TEND(tdisk, add_lba_write_ticks, start_ticks);
		return 0;
	}

	master = tdisk_mirror_master(tdisk);
	if (master) {
		TDISK_TSTART(start_ticks);
		wlist->lba_write = tdisk_add_lba_write(tdisk, lba, transfer_length, cw, QS_IO_WRITE, sync_wait);
		TDISK_TEND(tdisk, add_lba_write_ticks, start_ticks);
	}

	TDISK_TSTART(start_ticks);
	retval = tdisk_mirror_write_setup(tdisk, ctio, wlist, lba, transfer_length, cw, xchg_id);
	TDISK_TEND(tdisk, mirror_write_setup_start_ticks, start_ticks);

	if (retval != 0) {
		if (master)
			tdisk_remove_lba_write(tdisk, &wlist->lba_write);
		return -1;
	}

	if (!master) {
		TDISK_TSTART(start_ticks);
		if (!tdisk_mirror_master(tdisk))
			wlist->lba_write = tdisk_add_lba_write(tdisk, lba, transfer_length, cw, QS_IO_WRITE, sync_wait);
		else
			wlist->lba_write = tdisk_add_lba_write(tdisk, lba, transfer_length, cw, QS_IO_WRITE, sync_wait);
		TDISK_TEND(tdisk, add_lba_write_ticks, start_ticks);
	}
	return 0;
}

void
tdisk_write_error(struct tdisk *tdisk, struct qsio_scsiio *ctio, struct write_list *wlist, int ignore_mirror)
{
	struct index_sync_list index_sync_list;
	struct amap_sync_list amap_sync_list;
	struct index_info_list index_info_list;

	tdisk_remove_alloc_lba_write(&wlist->lba_alloc, tdisk->lba_write_wait, &tdisk->lba_write_list);

	SLIST_INIT(&amap_sync_list);
	SLIST_INIT(&index_sync_list);
	TAILQ_INIT(&index_info_list);

	if (!atomic_test_bit(WLIST_DONE_LOG_START, &wlist->flags) && !TAILQ_EMPTY(&wlist->meta_index_info_list)) {
		tdisk_handle_meta_log(tdisk, wlist, 1);
		atomic_set_bit(WLIST_DONE_LOG_START, &wlist->flags);
	}

	pgdata_cancel(tdisk, (struct pgdata **)(ctio->data_ptr), ctio->pglist_cnt, &amap_sync_list, &index_sync_list, &index_info_list);

	amap_sync_list_free_error(&wlist->amap_sync_list);
	amap_sync_list_free_error(&wlist->nowrites_amap_sync_list);
	handle_amap_sync(&amap_sync_list);
	handle_amap_sync_wait(&amap_sync_list);
	index_sync_start_io(&index_sync_list, 1);

	if (atomic_test_bit(WLIST_DONE_NEWMETA_SYNC_START, &wlist->flags))
		node_newmeta_sync_complete(tdisk, wlist->newmeta_transaction_id);

	if (atomic_test_bit(WLIST_DONE_PGDATA_SYNC_START, &wlist->flags))
		node_pgdata_sync_complete(tdisk, wlist->transaction_id);

	index_info_list_free_error(&wlist->index_info_list, 1);
	index_info_list_free_error(&wlist->meta_index_info_list, 0);

	if (atomic_test_bit(WLIST_DONE_LOG_END, &wlist->flags)) {
		log_list_end_wait(&wlist->log_list);
		log_list_start_writes(&wlist->log_list);
	}

	fastlog_clear_transactions(tdisk, (struct pgdata **)(ctio->data_ptr), ctio->pglist_cnt, &wlist->meta_index_info_list, wlist->log_reserved, 1);
	index_info_list_free(&wlist->meta_index_info_list);

	if (atomic_test_bit(WLIST_DONE_LOG_START, &wlist->flags)) {
		log_list_end_writes(&wlist->log_list);
		log_list_end_wait(&wlist->log_list);
	}
	fastlog_log_list_free(&wlist->log_list);

	if (!ignore_mirror)
		tdisk_mirror_write_error(tdisk, ctio, wlist);
	if (wlist->lba_write)
		tdisk_remove_lba_write(tdisk, &wlist->lba_write);
	pglist_cnt_decr(ctio->pglist_cnt);
	pgdata_free_amaps((struct pgdata **)(ctio->data_ptr), ctio->pglist_cnt);
	index_sync_wait(&index_sync_list);
	index_info_wait(&index_info_list);
}

static int
__tdisk_cmd_write(struct tdisk *tdisk, struct qsio_scsiio *ctio, uint64_t lba, uint32_t transfer_length, int sendstatus, int cw, struct index_info_list *prev_index_info_list, int unmap, int sync_wait, uint32_t xchg_id)
{
	struct pgdata *pgtmp, **pglist, *pgwrite;
	struct bdevint *bint, *prev_bint = NULL;
	struct tcache *tcache = NULL;
	struct write_list wlist;
	uint32_t i;
	int retval;
	int pglist_cnt;
	int cw_status;
	uint32_t cw_offset;
	int ignore_mirror = 0;
#ifdef ENABLE_STATS
	uint32_t start_ticks;
#endif
	uint8_t error_code = SSD_KEY_HARDWARE_ERROR;
	uint8_t asc = INTERNAL_TARGET_FAILURE_ASC;
	uint8_t ascq = INTERNAL_TARGET_FAILURE_ASCQ;

	/* transfer length should never be zero here */

	debug_info("cdb %x lba %llu transfer length %u\n", ctio->cdb[0], (unsigned long long)(lba), transfer_length);
	if (reached_eom(tdisk, lba, transfer_length)) {
		debug_warn("Invalid write at EOM for lba %llu transfer length %u shift %d\n", (unsigned long long)lba, transfer_length, tdisk->lba_shift);
		wait_for_pgdata((struct pgdata **)ctio->data_ptr, ctio->pglist_cnt);
		ctio_free_data(ctio);
		ctio_construct_sense(ctio, SSD_CURRENT_ERROR, SSD_KEY_ILLEGAL_REQUEST, 0, LOGICAL_BLOCK_ADDRESS_OUT_OF_RANGE_ASC, LOGICAL_BLOCK_ADDRESS_OUT_OF_RANGE_ASCQ);
		device_send_ccb(ctio);
		return -1;
	}

	if (node_in_standby()) {
		debug_warn("Invalid write to %s when node in standby\n", tdisk_name(tdisk));
		wait_for_pgdata((struct pgdata **)ctio->data_ptr, ctio->pglist_cnt);
		ctio_free_data(ctio);
		ctio->scsi_status = SCSI_STATUS_BUSY;
		device_send_ccb(ctio);
		return -1;
	}

	bzero(&wlist, sizeof(wlist));

	TDISK_TSTART(start_ticks);
	fastlog_reserve(tdisk, &wlist, (((ctio->pglist_cnt + 2) << 1) + 4));
	TDISK_TEND(tdisk, fastlog_get_ticks, start_ticks);

	retval = tdisk_lba_write_setup(tdisk, ctio, &wlist, lba, transfer_length, cw, sync_wait, xchg_id);
	if (unlikely(retval != 0)) {
		debug_warn("lba write setup failed for lba %llu transfer length %u cw %d xchg_id %llx cmd %x\n", (unsigned long long)lba, transfer_length, cw, (unsigned long long)xchg_id, ctio->cdb[0]);
		wlist_release_log_reserved(tdisk, &wlist);
		wait_for_pgdata((struct pgdata **)ctio->data_ptr, ctio->pglist_cnt);
		ctio_check_free_data(ctio);
		if (retval < 0) {
			device_send_ccb(ctio);
			return retval;
		}
		else {
			if (sendstatus)
				device_send_ccb(ctio);
			return 0;
		}
	}

	if (tdisk->lba_shift != LBA_SHIFT || cw) {
		cw_status = 0;
		cw_offset = 0;
		retval = check_unaligned_data(tdisk, ctio, &lba, transfer_length, cw, &cw_status, &cw_offset, &wlist);
		if (unlikely(retval != 0)) {
			wlist_release_log_reserved(tdisk, &wlist);
			wait_for_pgdata((struct pgdata **)ctio->data_ptr, ctio->pglist_cnt);
			tdisk_remove_lba_write(tdisk, &wlist.lba_write);
			if (!ctio_in_sync(ctio) || ctio_in_mirror(ctio))
				tdisk_mirror_write_error(tdisk, ctio, &wlist);
			ctio_check_free_data(ctio);
			ctio_construct_sense(ctio, SSD_CURRENT_ERROR, SSD_KEY_HARDWARE_ERROR, 0, INTERNAL_TARGET_FAILURE_ASC, INTERNAL_TARGET_FAILURE_ASCQ);
			device_send_ccb(ctio);
			return -1;
		}

		if (cw && cw_status) {
			wlist_release_log_reserved(tdisk, &wlist);
			wait_for_pgdata((struct pgdata **)ctio->data_ptr, ctio->pglist_cnt);
			tdisk_remove_lba_write(tdisk, &wlist.lba_write);
			if (!ctio_in_sync(ctio) || ctio_in_mirror(ctio))
				tdisk_mirror_write_error(tdisk, ctio, &wlist);
			ctio_check_free_data(ctio);
			ctio_construct_sense(ctio, SSD_CURRENT_ERROR, SSD_KEY_MISCOMPARE, cw_offset, MISCOMPARE_DURING_VERIFY_OPERATION_ASC, MISCOMPARE_DURING_VERIFY_OPERATION_ASCQ);
			ctio_set_sense_info_valid(ctio);
			TDISK_STATS_ADD(tdisk, cw_misses, 1);
			device_send_ccb(ctio);
			return -1;
		}
		else if (cw) {
			TDISK_STATS_ADD(tdisk, cw_hits, 1);
		}
	}

	pglist_cnt = ctio->pglist_cnt;
	TDISK_TSTART(start_ticks);
	pglist_cnt_incr(pglist_cnt);
	TDISK_TEND(tdisk, pgdata_wait_ticks, start_ticks);

	if (!unmap) {
		TDISK_INC(tdisk, lba_write_count, transfer_length);
		TDISK_INC(tdisk, write_count, 1);
		TDISK_STATS_ADD(tdisk, write_size, (transfer_length << tdisk->lba_shift));
	}

	tcache = tcache_alloc(pglist_cnt);
	pglist = (struct pgdata **)(ctio->data_ptr);
	write_list_init(tdisk, &wlist);
	if (prev_index_info_list)
		TAILQ_CONCAT(&wlist.index_info_list, prev_index_info_list, i_list);

	TDISK_TSTART(start_ticks);
	retval = scan_write_data(tdisk, ctio, lba, pglist, pglist_cnt, &wlist, &wlist.lba_alloc, 0, NULL, 0, ctio_in_xcopy(ctio));
	TDISK_TEND(tdisk, scan_write_ticks, start_ticks);
	sx_free(wlist.wlist_lock);

	if (unlikely(retval != 0)) {
		debug_warn("scan write data failed for lba %llu transfer length %u\n", (unsigned long long)lba, transfer_length);
		if (retval != ERR_CODE_NOSPACE)
			goto err;
		error_code = SSD_KEY_DATA_PROTECT;
		asc = SPACE_ALLOCATION_FAILED_WRITE_PROTECT_ASC;
		ascq = SPACE_ALLOCATION_FAILED_WRITE_PROTECT_ASCQ;
		goto err;
	}

	if (wlist.msg)
		tdisk_remove_alloc_lba_write(&wlist.lba_alloc, tdisk->lba_write_wait, &tdisk->lba_write_list);

	TDISK_TSTART(start_ticks);
	retval = tdisk_mirror_check_verify(tdisk, ctio, &wlist);
	TDISK_TEND(tdisk, mirror_check_verify_ticks, start_ticks);
	if (unlikely(retval != 0)) {
		if (retval > 0) {
			ctio_check_free_data(ctio);
			if (sendstatus)
				device_send_ccb(ctio);
			return 0;
		}
		ignore_mirror = 1;
		debug_warn("tdisk mirror check verify failed\n");
		goto err;
	}

	TDISK_TSTART(start_ticks);
	retval = tdisk_mirror_check_comp(tdisk, ctio, &wlist);
	TDISK_TEND(tdisk, mirror_check_comp_ticks, start_ticks);
	if (unlikely(retval != 0)) {
		ignore_mirror = 1;
		debug_warn("tdisk mirror check comp failed\n");
		goto err;
	}

	if (SLIST_EMPTY(&wlist.amap_sync_list)) {
		tdisk_remove_alloc_lba_write(&wlist.lba_alloc, tdisk->lba_write_wait, &tdisk->lba_write_list);
		goto sync_amap_post;
	}

	if (!wlist.lba_alloc) {
		int flags = 0;
		atomic_set_bit(LBA_WRITE_DONE_ALLOC, &flags);
		wlist.lba_alloc = tdisk_add_alloc_lba_write(lba, tdisk->lba_write_wait, &tdisk->lba_write_list, flags);
	}

	TDISK_TSTART(start_ticks);
	for (i = 0; i < pglist_cnt; i++) {
		pgtmp =  pglist[i];
		debug_info("write size %u\n", pgtmp->write_size);
		if (!pgtmp->write_size)
			continue;

		TDISK_STATS_ADD(tdisk, uncompressed_size, LBA_SIZE);
		if (pgtmp->comp_pgdata) {
			pgwrite = pgtmp->comp_pgdata;
			TDISK_STATS_ADD(tdisk, compressed_size, pgtmp->write_size);
		}
		else {
			pgwrite = pgtmp;
		}

		debug_check(!pgtmp->amap_block);
		if (!prev_bint || (prev_bint->bid != BLOCK_BID(pgtmp->amap_block))) {
			bint = bdev_find(BLOCK_BID(pgtmp->amap_block));
			if (unlikely(!bint)) {
				debug_warn("Cannot locate bint at bid %u amap block %llu\n", BLOCK_BID(pgtmp->amap_block), (unsigned long long)pgtmp->amap_block);
				goto err;
			}
			prev_bint = bint;
		}
		else {
			bint = prev_bint;
		}

		debug_info("lba %llu block %llu size %u\n", (unsigned long long)pgtmp->lba, (unsigned long long)(BLOCK_BLOCKNR(pgtmp->amap_block)), pgwrite->pg_len);
		retval = tcache_add_page(tcache, pgwrite->page, BLOCK_BLOCKNR(pgtmp->amap_block), bint, pgwrite->pg_len, QS_IO_WRITE);
		if (unlikely(retval != 0))
			goto err;
	}
	TDISK_INC(tdisk, biot_write_count, atomic_read(&tcache->bio_remain));
	TDISK_INC(tdisk, write_page_misses, tcache->page_misses);
	TDISK_INC(tdisk, write_bstart_misses, tcache->bstart_misses);
	TDISK_INC(tdisk, write_bint_misses, tcache->bint_misses);
	TDISK_TEND(tdisk, tcache_setup_ticks, start_ticks);

	TDISK_TSTART(start_ticks);
	if (atomic_read(&tcache->bio_remain)) {
		tdisk_check_alloc_lba_write(wlist.lba_alloc, tdisk->lba_write_wait, &tdisk->lba_write_list, LBA_WRITE_DONE_IO);
		tcache_entry_rw(tcache, QS_IO_WRITE);
	}
	else
		wait_complete(tcache->completion);
	TDISK_TEND(tdisk, entry_rw_ticks, start_ticks);
	tdisk_remove_alloc_lba_write(&wlist.lba_alloc, tdisk->lba_write_wait, &tdisk->lba_write_list);

	TDISK_TSTART(start_ticks);
	wait_for_done(tcache->completion);
	TDISK_TEND(tdisk, tcache_wait_ticks, start_ticks);

	if (atomic_test_bit_short(TCACHE_IO_ERROR, &tcache->flags))
		goto err;
sync_amap_post:

	TDISK_TSTART(start_ticks);
	retval = tdisk_mirror_check_io(tdisk, ctio, &wlist);
	TDISK_TEND(tdisk, mirror_check_io_ticks, start_ticks);
	if (unlikely(retval != 0)) {
		ignore_mirror = 1;
		debug_warn("tdisk mirror check io failed\n");
		goto err;
	}

	TDISK_TSTART(start_ticks);
	retval = tdisk_mirror_write_post_pre(tdisk, ctio, &wlist);
	TDISK_TEND(tdisk, mirror_write_post_ticks, start_ticks);
	if (unlikely(retval != 0)) {
		ignore_mirror = 1;
		debug_warn("tdisk mirror write post pre failed\n");
		goto err;
	}

	TDISK_TSTART(start_ticks);
	retval = pgdata_amap_io(tdisk, &wlist);
	TDISK_TEND(tdisk, wait_amap_io_ticks, start_ticks);
	if (unlikely(retval != 0))
		goto err;

	node_newmeta_sync_start(tdisk, &wlist);
	node_pgdata_sync_start(tdisk, &wlist, pglist, pglist_cnt);

	TDISK_TSTART(start_ticks);
	log_list_end_writes(&wlist.log_list);
	atomic_set_bit(WLIST_DONE_LOG_END, &wlist.flags);
	TDISK_TEND(tdisk, log_list_end_writes_ticks, start_ticks);

	TDISK_TSTART(start_ticks);
	log_list_end_wait(&wlist.log_list);
	TDISK_TEND(tdisk, wait_log_ticks, start_ticks);

	amap_sync_list_free_error(&wlist.nowrites_amap_sync_list);
	sync_amap_list_pre(tdisk, &wlist);

	tcache_put(tcache);
	tcache = NULL;
	TDISK_TSTART(start_ticks);
	retval = tdisk_mirror_write_done_pre(tdisk, ctio, &wlist);
	TDISK_TEND(tdisk, mirror_write_done_pre_ticks, start_ticks);
	if (unlikely(retval != 0)) {
		ignore_mirror = 1;
		debug_warn("tdisk mirror write done pre failed\n");
		goto err;
	}

	pglist = (struct pgdata **)ctio->data_ptr;
	ctio->data_ptr = NULL;
	ctio->pglist_cnt = 0;
	ctio->dxfer_len = 0;
	if (ctio_norefs(ctio))
		pglist_reset_pages(pglist, pglist_cnt);
	if (sendstatus) {
		node_pgdata_sync_client_done(tdisk, wlist.transaction_id);
		device_send_ccb(ctio);
	}

	TDISK_TSTART(start_ticks);
	pgdata_post_write(tdisk, pglist, pglist_cnt, &wlist);
	TDISK_TEND(tdisk, post_write_ticks, start_ticks);

#if 0
	TDISK_TSTART(start_ticks);
	tdisk_mirror_write_done_post(tdisk, ctio, &wlist);
	TDISK_TEND(tdisk, mirror_write_done_post_ticks, start_ticks);
#endif

	return 0;

err:
	wait_for_pgdata((struct pgdata **)ctio->data_ptr, ctio->pglist_cnt);
	if (tcache)
		tcache_put(tcache);
	tdisk_write_error(tdisk, ctio, &wlist, ignore_mirror);
	ctio_check_free_data(ctio);
	ctio_construct_sense(ctio, SSD_CURRENT_ERROR, error_code, 0, asc, ascq);
	device_send_ccb(ctio);
	return -1;
}

static void 
tdisk_cmd_read16(struct tdisk *tdisk, struct qsio_scsiio *ctio)
{
	uint8_t *cdb = ctio->cdb;
	uint64_t lba;
	uint32_t transfer_length;

	lba = be64toh(*(uint64_t *)(&cdb[2]));
	transfer_length = be32toh(*(uint32_t *)(&cdb[10]));
	if (!transfer_length) {
		ctio_free_data(ctio);
		device_send_ccb(ctio);
		return;
	}

	atomic_inc(&write_requests);
	__tdisk_cmd_read(tdisk, ctio, lba, transfer_length);
	atomic_dec(&write_requests);
}

static void 
tdisk_cmd_read12(struct tdisk *tdisk, struct qsio_scsiio *ctio)
{
	uint8_t *cdb = ctio->cdb;
	uint64_t lba;
	uint32_t transfer_length;

	lba = be32toh(*(uint32_t *)(&cdb[2]));
	transfer_length = be32toh(*(uint32_t *)(&cdb[6]));
	if (!transfer_length) {
		ctio_free_data(ctio);
		device_send_ccb(ctio);
		return;
	}

	atomic_inc(&write_requests);
	__tdisk_cmd_read(tdisk, ctio, lba, transfer_length);
	atomic_dec(&write_requests);
}

static void 
tdisk_cmd_read10(struct tdisk *tdisk, struct qsio_scsiio *ctio)
{
	uint8_t *cdb = ctio->cdb;
	uint64_t lba;
	uint32_t transfer_length;

	lba = be32toh(*(uint32_t *)(&cdb[2]));
	transfer_length = be16toh(*(uint16_t *)(&cdb[7]));
	if (!transfer_length) {
		ctio_free_data(ctio);
		device_send_ccb(ctio);
		return;
	}

	atomic_inc(&write_requests);
	__tdisk_cmd_read(tdisk, ctio, lba, transfer_length);
	atomic_dec(&write_requests);
}

static void 
tdisk_cmd_read6(struct tdisk *tdisk, struct qsio_scsiio *ctio)
{
	uint8_t *cdb = ctio->cdb;
	uint64_t lba;
	uint32_t transfer_length;

	lba = READ_24((cdb[1] & 0x1F), cdb[2], cdb[3]);
	transfer_length = cdb[4];
	if (!transfer_length) {
		/* snm limit this to block limits VPD */
		transfer_length = 256;
	}

	atomic_inc(&write_requests);
	__tdisk_cmd_read(tdisk, ctio, lba, transfer_length);
	atomic_dec(&write_requests);
}

void
tdisk_cmd_compare_and_write(struct tdisk *tdisk, struct qsio_scsiio *ctio)
{
	uint8_t *cdb = ctio->cdb;
	uint64_t lba;
	uint8_t transfer_length;

	lba = be64toh(*(uint64_t *)(&cdb[2]));
	transfer_length = cdb[13];

	debug_info("lba %llu transfer_length %d\n", (unsigned long long)lba, transfer_length);
	if (!transfer_length) {
		ctio_free_data(ctio);
		device_send_ccb(ctio);
		return;
	}

	atomic_inc(&write_requests);
#if 0
	retval = tdisk_mirror_cmd_generic2(tdisk, ctio);
	if (!retval)
		__tdisk_cmd_write(tdisk, ctio, lba, transfer_length, 1, 1, NULL, 0, 0, 0);
#endif
	__tdisk_cmd_write(tdisk, ctio, lba, transfer_length, 1, 1, NULL, 0, 0, 0);
	atomic_dec(&write_requests);
}

static void 
tdisk_cmd_write16(struct tdisk *tdisk, struct qsio_scsiio *ctio)
{
	uint8_t *cdb = ctio->cdb;
	uint64_t lba;
	uint32_t transfer_length;

	lba = be64toh(*(uint64_t *)(&cdb[2]));
	transfer_length = be32toh(*(uint32_t *)(&cdb[10]));
	if (!transfer_length) {
		ctio_free_data(ctio);
		device_send_ccb(ctio);
		return;
	}

	atomic_inc(&write_requests);
	__tdisk_cmd_write(tdisk, ctio, lba, transfer_length, 1, 0, NULL, 0, 0, 0);
	atomic_dec(&write_requests);
}

static void 
tdisk_cmd_write12(struct tdisk *tdisk, struct qsio_scsiio *ctio)
{
	uint8_t *cdb = ctio->cdb;
	uint64_t lba;
	uint32_t transfer_length;

	lba = be32toh(*(uint32_t *)(&cdb[2]));
	transfer_length = be32toh(*(uint32_t *)(&cdb[6]));
	if (!transfer_length) {
		ctio_free_data(ctio);
		device_send_ccb(ctio);
		return;
	}

	atomic_inc(&write_requests);
	__tdisk_cmd_write(tdisk, ctio, lba, transfer_length, 1, 0, NULL, 0, 0, 0);
	atomic_dec(&write_requests);
}

static void 
tdisk_cmd_write10(struct tdisk *tdisk, struct qsio_scsiio *ctio)
{
	uint8_t *cdb = ctio->cdb;
	uint64_t lba;
	uint32_t transfer_length;

	lba = be32toh(*(uint32_t *)(&cdb[2]));
	transfer_length = be16toh(*(uint16_t *)(&cdb[7]));
	if (!transfer_length) {
		ctio_free_data(ctio);
		device_send_ccb(ctio);
		return;
	}

	atomic_inc(&write_requests);
	__tdisk_cmd_write(tdisk, ctio, lba, transfer_length, 1, 0, NULL, 0, 0, 0);
	atomic_dec(&write_requests);
}

static int
ctio_realloc_pglist_pbdata(struct qsio_scsiio *ctio, struct pgdata *ref_page, uint32_t num_blocks, uint64_t lba, uint8_t pbdata)
{
	int retval;
	int i;
	struct pgdata **pglist, *pgdata;
	uint8_t *src, *dest;

	retval = pgdata_allocate_data(ctio, num_blocks, Q_NOWAIT);
	if (unlikely(retval != 0))
		return -1;

	src = (uint8_t *)pgdata_page_address(ref_page);
	pglist = (struct pgdata **)(ctio->data_ptr);
	for (i = 0; i < num_blocks; i++) {
		pgdata = pglist[i];
		dest = (uint8_t *)pgdata_page_address(pgdata);
		memcpy(dest, src, LBA_SIZE);
		if (pbdata)
			*((uint64_t *)(dest)) = htobe64(lba);
		else
			*((uint32_t *)(dest)) = htobe32(lba & 0xFFFFFFFF);
		ddblock_hash_compute(pgdata);
		mark_complete(pgdata);
	}
	return 0;
}

static int
ctio_realloc_pglist(struct qsio_scsiio *ctio, struct pgdata *ref_page, uint32_t num_blocks, uint8_t *hash, unsigned long flags)
{
	int i;
	struct pgdata **pglist, *pgtmp;

	pglist = pgdata_allocate_pglist(num_blocks, Q_NOWAIT);
	if (unlikely(!pglist)) {
		debug_warn("Memory allocation failure\n");
		return -1;
	}

	for (i = 0; i < num_blocks; i++) {
		pgtmp = __uma_zalloc(pgdata_cache, Q_NOWAIT | Q_ZERO, sizeof(*pgtmp));
		if (unlikely(!pgtmp)) {
			debug_warn("Slab allocation failure\n");
			pglist_free(pglist, i);
			return -1;
		}
		pgtmp->completion = wait_completion_alloc("pgdata compl");
		mark_complete(pgtmp);
		pglist[i] = pgtmp;
		pgtmp->pg_len = LBA_SIZE;
		pgdata_add_ref(pgtmp, ref_page);
		pgtmp->flags = flags;
		if (hash)
			memcpy(pgtmp->hash, hash, SHA256_DIGEST_LENGTH);
	}
	ctio->data_ptr = (void *)pglist;
	ctio->pglist_cnt = num_blocks;
	ctio->dxfer_len = num_blocks * LBA_SIZE;
	return 0;
}
 
static void
__tdisk_cmd_write_same(struct tdisk *tdisk, struct qsio_scsiio *ctio, uint64_t lba, uint64_t num_blocks, uint8_t pbdata, uint8_t lbdata, uint8_t unmap)
{
	struct pgdata **pglist;
	struct pgdata *pgtmp;
	int retval;
	uint32_t todo;
	int pglist_cnt;
	int min_blocks = (tdisk->lba_shift == LBA_SHIFT) ? TDISK_UNMAP_LBA_COUNT : TDISK_UNMAP_LBA_COUNT_LEGACY;
	
	TDISK_INC(tdisk, wsame_cmds, 1);
	if (!num_blocks) {
		num_blocks = (tdisk->end_lba - lba);
		if (!num_blocks) {
			ctio_free_data(ctio);
			goto send;
		}
	}

	if (((pbdata || lbdata) && (tdisk->lba_shift != LBA_SHIFT))) {
		ctio_free_data(ctio);
		ctio_construct_sense(ctio, SSD_CURRENT_ERROR, SSD_KEY_HARDWARE_ERROR, 0, INTERNAL_TARGET_FAILURE_ASC, INTERNAL_TARGET_FAILURE_ASCQ);
		goto send;
	}

	pglist = (struct pgdata **)(ctio->data_ptr);
	pgtmp = pglist[0];

	if (tdisk->lba_shift != LBA_SHIFT) {
		uint8_t *ptr;
		uint64_t lba_align;
		uint64_t lba_diff;

		ptr = (uint8_t *)pgdata_page_address(pgtmp);
		if (memcmp(ptr, pgzero_addr, (1U << tdisk->lba_shift))) {
			ctio_free_data(ctio);
			ctio_construct_sense(ctio, SSD_CURRENT_ERROR, SSD_KEY_HARDWARE_ERROR, 0, INTERNAL_TARGET_FAILURE_ASC, INTERNAL_TARGET_FAILURE_ASCQ);
			goto send;
		}
		bzero(ptr, LBA_SIZE);
		pgtmp->pg_len = LBA_SIZE;

		lba_align = align_size(lba, 8);

		lba_diff = lba_align - lba;
		num_blocks -= lba_diff;
		lba = lba_align;
		num_blocks = (num_blocks & ~0x7U);
	}
 
	ctio->data_ptr = NULL;
	ctio->dxfer_len = ctio->pglist_cnt = 0;
	ddblock_hash_compute(pgtmp);
	if (unmap) {
		atomic_set_bit(DDBLOCK_ZERO_BLOCK, &pgtmp->flags);
		atomic_set_bit(DDBLOCK_UNMAP_BLOCK, &pgtmp->flags);
	}

	while (num_blocks) {
		todo = min_t(uint32_t, num_blocks, min_blocks);

		pglist_cnt = transfer_length_to_pglist_cnt(tdisk->lba_shift, todo);
		if (unmap)
			TDISK_STATS_ADD(tdisk, unmap_blocks, pglist_cnt);
		else
			TDISK_STATS_ADD(tdisk, wsame_blocks, pglist_cnt);

		if (!pbdata && !lbdata) {
			retval = ctio_realloc_pglist(ctio, pgtmp, pglist_cnt, pgtmp->hash, pgtmp->flags);
		}
		else {
			retval = ctio_realloc_pglist_pbdata(ctio, pgtmp, pglist_cnt, lba, pbdata);
		}

		if (unlikely(retval != 0)) {
			pglist_free(pglist, 1);
			ctio_construct_sense(ctio, SSD_CURRENT_ERROR, SSD_KEY_HARDWARE_ERROR, 0, INTERNAL_TARGET_FAILURE_ASC, INTERNAL_TARGET_FAILURE_ASCQ);
			goto send;
		}
		atomic_inc(&write_requests);
		retval = __tdisk_cmd_write(tdisk, ctio, lba, todo, 0, 0, NULL, 0, 0, 0);
		atomic_dec(&write_requests);
		if (unlikely(retval != 0)) /* cmd_write would have sent non zero status */ {
			pglist_free(pglist, 1);
			return;
		}
		num_blocks -= todo;
		lba += todo;
	}
	pglist_free(pglist, 1);
send:
	device_send_ccb(ctio);
}

void
tdisk_cmd_write_same(struct tdisk *tdisk, struct qsio_scsiio *ctio)
{
	uint8_t *cdb = ctio->cdb;
	uint64_t lba;
	uint32_t num_blocks;
	uint8_t pbdata, lbdata, unmap;

	lba = be32toh(*(uint32_t *)(&cdb[2]));
	num_blocks = be16toh(*(uint16_t *)(&cdb[7]));

	lbdata = (cdb[1] >> 1) & 0x1;
	pbdata = (cdb[1] >> 2) & 0x1;
	unmap = (cdb[1] >> 3) & 0x1;

	debug_info("lba %llu num_blocks %u lbdata %d pbdata %d unmap %d\n", (unsigned long long)lba, num_blocks, lbdata, pbdata, unmap);
	if (reached_eom(tdisk, lba, num_blocks)) {
		ctio_free_data(ctio);
		ctio_construct_sense(ctio, SSD_CURRENT_ERROR, SSD_KEY_ILLEGAL_REQUEST, 0, LOGICAL_BLOCK_ADDRESS_OUT_OF_RANGE_ASC, LOGICAL_BLOCK_ADDRESS_OUT_OF_RANGE_ASCQ);
		device_send_ccb(ctio);
		return;
	}

	if (pbdata && lbdata) {
		ctio_free_data(ctio);
		ctio_construct_sense(ctio, SSD_CURRENT_ERROR, SSD_KEY_ILLEGAL_REQUEST, 0, INVALID_FIELD_IN_CDB_ASC, INVALID_FIELD_IN_CDB_ASCQ);
		device_send_ccb(ctio);
		return;
	}

#if 0
	retval = tdisk_mirror_cmd_generic2(tdisk, ctio);
	if (!retval)
		__tdisk_cmd_write_same(tdisk, ctio, lba, num_blocks, pbdata, lbdata, unmap);
#endif
	__tdisk_cmd_write_same(tdisk, ctio, lba, num_blocks, pbdata, lbdata, unmap);
}

void
tdisk_cmd_write_same16(struct tdisk *tdisk, struct qsio_scsiio *ctio)
{
	uint8_t *cdb = ctio->cdb;
	uint64_t lba;
	uint32_t num_blocks;
	uint8_t pbdata, lbdata, unmap;

	lba = be64toh(*(uint64_t *)(&cdb[2]));
	num_blocks = be32toh(*(uint32_t *)(&cdb[10]));
	lbdata = (cdb[1] >> 1) & 0x1;
	pbdata = (cdb[1] >> 2) & 0x1;
	unmap = (cdb[1] >> 3) & 0x1;
	if (unmap)
		TDISK_INC(tdisk, wsame_unmap_cmds, 1);

	debug_info("lba %llu num_blocks %u lbdata %d pbdata %d unmap %d\n", (unsigned long long)lba, num_blocks, lbdata, pbdata, unmap);
	if (reached_eom(tdisk, lba, num_blocks)) {
		ctio_free_data(ctio);
		ctio_construct_sense(ctio, SSD_CURRENT_ERROR, SSD_KEY_ILLEGAL_REQUEST, 0, LOGICAL_BLOCK_ADDRESS_OUT_OF_RANGE_ASC, LOGICAL_BLOCK_ADDRESS_OUT_OF_RANGE_ASCQ);
		device_send_ccb(ctio);
		return;
	}

	if (pbdata && lbdata) {
		ctio_free_data(ctio);
		ctio_construct_sense(ctio, SSD_CURRENT_ERROR, SSD_KEY_ILLEGAL_REQUEST, 0, INVALID_FIELD_IN_CDB_ASC, INVALID_FIELD_IN_CDB_ASCQ);
		device_send_ccb(ctio);
		return;
	}

#if 0
	retval = tdisk_mirror_cmd_generic2(tdisk, ctio);
	if (!retval)
		__tdisk_cmd_write_same(tdisk, ctio, lba, num_blocks, pbdata, lbdata, unmap);
#endif
	__tdisk_cmd_write_same(tdisk, ctio, lba, num_blocks, pbdata, lbdata, unmap);
}

static void
read_pgdata(struct pgdata **pglist, int *ret_idx, int *ret_offset, uint8_t *dest, int dest_len)
{
	struct pgdata *pgdata;
	int idx = *ret_idx;
	int offset = *ret_offset;
	int min_len;

	pgdata = pglist[idx];
	min_len = min_t(int, dest_len, pgdata->pg_len - offset);
	memcpy(dest, (uint8_t *)pgdata_page_address(pgdata) + offset, min_len);
	offset += min_len;
	dest_len -= min_len;
	if (offset == pgdata->pg_len) {
		idx++;
		offset = 0;
	}

	if (!dest_len) {
		*ret_idx = idx;
		*ret_offset = offset;
		return;
	}

	dest += min_len;
	pgdata = pglist[idx];
	debug_check(offset);
	memcpy(dest, (uint8_t *)pgdata_page_address(pgdata), dest_len);
	*ret_idx = idx;
	*ret_offset = dest_len;
}

static struct tdisk *
target_descriptor_locate_tdisk(struct target_descriptor_common *target_desc)
{
	/* Assume NAA which fits within 28 bytes */
	struct tdisk *tdisk;
	int i;
	struct logical_unit_naa_identifier *naa_identifier;

	/* Binary */
	if ((target_desc->desc_param[0] & 0xF) != 0x01)
		return NULL;

	if ((target_desc->desc_param[1] & 0xF) != UNIT_IDENTIFIER_NAA)
		return NULL; 

	naa_identifier = (struct logical_unit_naa_identifier *)(target_desc->desc_param);
	for (i = 0; i < TL_MAX_DEVICES; i++) {
		tdisk = tdisks[i];
		if (!tdisk)
			continue;

		if (tdisk->naa_identifier.identifier_length != naa_identifier->identifier_length)
			continue;
		if (memcmp(tdisk->naa_identifier.naa_id, naa_identifier->naa_id, naa_identifier->identifier_length))
			continue;
		tdisk_get(tdisk);
		return tdisk;
	}
	return NULL;
}

static int
tdisk_parse_target_descriptors(struct qsio_scsiio *ctio, struct extended_copy *ecopy, int *ret_idx, int *ret_offset, int num_descriptors)
{
	int avail;
	int idx = *ret_idx;
	int offset = *ret_offset;
	int descriptor_len;
	int i;
	struct target_descriptor_common *common;

	avail = ctio->dxfer_len - offset;
	descriptor_len = num_descriptors * 32;
	if (avail < descriptor_len) {
		ctio_free_data(ctio);
		ctio_construct_sense(ctio, SSD_CURRENT_ERROR, SSD_KEY_ILLEGAL_REQUEST, 0, INVALID_FIELD_IN_PARAMETER_LIST_ASC, INVALID_FIELD_IN_PARAMETER_LIST_ASCQ);
		return -1;
	}

	for (i = 0; i < num_descriptors; i++) {
		common = zalloc(sizeof(*common), M_ECOPY, Q_WAITOK);
		read_pgdata((struct pgdata **)ctio->data_ptr, &idx, &offset, (uint8_t *)common, 32);
		common->id = i;
		common->tdisk = target_descriptor_locate_tdisk(common);
		SLIST_INSERT_HEAD(&ecopy->target_list, common, t_list);
	}

	*ret_idx = idx;
	*ret_offset = offset;
	return 0;
}

static int
tdisk_parse_segment_descriptors(struct qsio_scsiio *ctio, struct extended_copy *ecopy, int *ret_idx, int *ret_offset)
{
	int avail;
	int idx = *ret_idx;
	int offset = *ret_offset;
	struct segment_descriptor_common *common, *prev = NULL;
	int desc_length;

	avail = ctio->dxfer_len - offset;
	while (avail) {
		common = zalloc(sizeof(*common), M_ECOPY, Q_WAITOK);
		read_pgdata((struct pgdata **)ctio->data_ptr, &idx, &offset, (uint8_t *)common, 8);
		avail -= 8;
		desc_length = be16toh(common->desc_length);
		if ((desc_length - 4) > avail) {
			ctio_free_data(ctio);
			ctio_construct_sense(ctio, SSD_CURRENT_ERROR, SSD_KEY_ILLEGAL_REQUEST, 0, INVALID_FIELD_IN_PARAMETER_LIST_ASC, INVALID_FIELD_IN_PARAMETER_LIST_ASCQ);
			return -1;
		}
		common->desc = malloc(desc_length - 4, M_ECOPY, Q_WAITOK);
		read_pgdata((struct pgdata **)ctio->data_ptr, &idx, &offset, common->desc, desc_length - 4);	
		if (prev)
			SLIST_INSERT_AFTER(prev, common, s_list);
		else
			SLIST_INSERT_HEAD(&ecopy->segment_list, common, s_list);
		prev = common;
		avail -= (desc_length - 4);
	}

	*ret_idx = idx;
	*ret_offset = offset;
	return 0;
}

static struct extended_copy *
extended_copy_locate(struct tdisk *tdisk, uint8_t list_identifier)
{
	struct extended_copy *ecopy;

	SLIST_FOREACH(ecopy, &tdisk->ecopy_list, e_list) {
		if (ecopy->list_identifier == list_identifier)
			return ecopy;
	}
	return NULL;
}

static int
tdisk_parse_extended_copy_param(struct qsio_scsiio *ctio, struct extended_copy *ecopy)
{
	struct extended_copy_parameter_list *param;
	struct pgdata **pglist, *pgdata;
	int offset;
	int idx;
	int retval;
	int num_descriptors;
	uint16_t target_desc_length;
	uint32_t segment_desc_length;

	debug_check(!ctio->pglist_cnt);
	pglist = (struct pgdata **)(ctio->data_ptr);
	pgdata = pglist[0];

	param = (struct extended_copy_parameter_list *)pgdata_page_address(pgdata);

	offset = sizeof(struct extended_copy_parameter_list);
	idx = 0;

	ecopy->list_identifier = param->list_identifier;
	target_desc_length = be16toh(param->target_descriptor_list_length);
	if (target_desc_length & 0x1F) {
		debug_warn("Invalid target desc length %d\n", target_desc_length);
		ctio_construct_sense(ctio, SSD_CURRENT_ERROR, SSD_KEY_ILLEGAL_REQUEST, 0, INVALID_FIELD_IN_PARAMETER_LIST_ASC, INVALID_FIELD_IN_PARAMETER_LIST_ASCQ);
		return -1;
	}

	num_descriptors = target_desc_length >> 5; 

	retval = tdisk_parse_target_descriptors(ctio, ecopy, &idx, &offset, num_descriptors);
	if (unlikely(retval != 0)) {
		debug_warn("Failed to parse target descriptors\n");
		return -1;
	}

	segment_desc_length = be32toh(param->segment_descriptor_list_length);
	if (segment_desc_length != (ctio->dxfer_len - offset)) {
		debug_warn("Invalid segment desc length %d dxfer len %d offset %d\n", segment_desc_length, ctio->dxfer_len, offset);
		ctio_construct_sense(ctio, SSD_CURRENT_ERROR, SSD_KEY_ILLEGAL_REQUEST, 0, INVALID_FIELD_IN_PARAMETER_LIST_ASC, INVALID_FIELD_IN_PARAMETER_LIST_ASCQ);
		return -1;
	}

	retval = tdisk_parse_segment_descriptors(ctio, ecopy, &idx, &offset);
	if (unlikely(retval != 0)) {
		debug_warn("Failed to parse segment descriptors\n");
		return -1;
	}

	return 0;
}

static void
extended_copy_free(struct extended_copy *ecopy)
{
	struct segment_descriptor_common *common;
	struct target_descriptor_common *tcommon;

	while ((tcommon = SLIST_FIRST(&ecopy->target_list)) != NULL) {
		SLIST_REMOVE_HEAD(&ecopy->target_list, t_list);
		if (tcommon->tdisk)
			tdisk_put(tcommon->tdisk);
		free(tcommon, M_ECOPY);
	}

	while ((common = SLIST_FIRST(&ecopy->segment_list)) != NULL) {
		SLIST_REMOVE_HEAD(&ecopy->segment_list, s_list);
		if (common->desc)
			free(common->desc, M_ECOPY);
		free(common, M_ECOPY);
	}
	free(ecopy, M_ECOPY);
}

static int 
remap_pglist_for_write(struct pgdata ***ret_pglist,  int *ret_pglist_cnt, uint32_t size)
{
	struct pgdata **pglist = *ret_pglist;
	int pglist_cnt = *ret_pglist_cnt;
	struct pgdata **dest_pglist;
	int dest_pglist_cnt;
	int idx, min_len, offset, src_offset, i;
	struct pgdata *src, *dest;

	dest_pglist_cnt = size >> LBA_SHIFT;
	if (size & LBA_MASK)
		dest_pglist_cnt++;

	dest_pglist = pgdata_allocate(dest_pglist_cnt, Q_WAITOK);
	if (unlikely(!dest_pglist)) {
		pglist_free(pglist, pglist_cnt);
		return -1;
	}

	idx = 0;
	offset = 0;
	src_offset = 0;
	for (i = 0; i < pglist_cnt;) {
		src = pglist[i];
		dest = dest_pglist[idx];
		min_len = min_t(int, src->pg_len - src_offset, dest->pg_len - offset);
		min_len = min_t(int, min_len, size);

		memcpy((uint8_t *)pgdata_page_address(dest) + offset, (uint8_t *)pgdata_page_address(src) + src->pg_offset + src_offset, min_len);
		offset += min_len;
		if (offset == dest->pg_len) {
			idx++;
			offset = 0;
		}

		src_offset += min_len;
		if (src_offset == src->pg_len) {
			i++;
			src_offset = 0;
		}
		size -= min_len;
		if (!size)
			break;
	}
	pglist_free(pglist, pglist_cnt);
	*ret_pglist = dest_pglist;
	*ret_pglist_cnt = dest_pglist_cnt;
	return 0;
}

static struct target_descriptor_common *
target_descriptor_locate(struct extended_copy *ecopy, uint16_t target_index)
{
	struct target_descriptor_common *common;

	SLIST_FOREACH(common, &ecopy->target_list, t_list) {
		if (common->id == target_index)
			return common;
	}
	return NULL;
}

void 
pglist_calc_hash(struct tdisk *tdisk, struct pgdata **pglist, int pglist_cnt, int mirror_enabled, int use_refs)
{
	int i;
	struct pgdata *pgdata;
	int enable_deduplication = tdisk->enable_deduplication;
	int has_writes = 0;

	chan_lock(devq_write_wait);
	for (i = 0; i < pglist_cnt; i++) {
		pgdata = pglist[i];
		pgdata->lba = 0;
		if (atomic_test_bit(PGDATA_SKIP_DDCHECK, &pgdata->flags)) {
			if (atomic_test_bit(DDBLOCK_ZERO_BLOCK, &pgdata->flags)) {
				wait_complete_all(pgdata->completion);
				continue;
			}

			if (mirror_enabled && !use_refs) {
				if (pgdata->pg_len == LBA_SIZE && enable_deduplication) {
					STAILQ_INSERT_TAIL(&pending_write_queue, pgdata, w_list);
					has_writes = 1;
				} else {
					atomic_set_bit(DDBLOCK_DEDUPE_DISABLED, &pgdata->flags);
					wait_complete_all(pgdata->completion);
				}
				continue;
			}
			debug_check(!atomic_test_bit(DDBLOCK_ZERO_BLOCK, &pgdata->flags) && !atomic_test_bit(DDBLOCK_ENTRY_FOUND_DUPLICATE, &pgdata->flags));
			wait_complete_all(pgdata->completion);
			continue;
		}

		pgdata->amap_block = 0;
		if (pgdata->pg_len == LBA_SIZE && enable_deduplication) {
			STAILQ_INSERT_TAIL(&pending_write_queue, pgdata, w_list);
			has_writes = 1;
		} else {
			atomic_set_bit(DDBLOCK_DEDUPE_DISABLED, &pgdata->flags);
			wait_complete_all(pgdata->completion);
		}
	}
	if (has_writes) {
		chan_wakeup_unlocked(devq_write_wait);
	}
	chan_unlock(devq_write_wait);
}

static int
extended_copy_get_tdisks(struct tdisk *tdisk, struct extended_copy *ecopy, struct segment_descriptor_common *common, struct tdisk **ret_dest_tdisk, struct tdisk **ret_src_tdisk)
{
	struct target_descriptor_common *target_desc;
	struct tdisk *dest_tdisk, *src_tdisk;

	target_desc = target_descriptor_locate(ecopy, be16toh(common->src_target_index));
	if (!target_desc)
		return -1;

	src_tdisk = target_desc->tdisk;
	if (!src_tdisk || src_tdisk != tdisk)
		return -1;

	target_desc = target_descriptor_locate(ecopy, be16toh(common->dest_target_index));
	if (!target_desc)
		return -1;

	dest_tdisk = target_desc->tdisk;
	if (!dest_tdisk)
		return -1;

	if (src_tdisk->lba_shift != dest_tdisk->lba_shift)
		return -1;

	*ret_dest_tdisk = dest_tdisk;
	*ret_src_tdisk = src_tdisk;
	return 0;
}

static int
is_unaligned_extended_copy(struct tdisk *src_tdisk, uint64_t src_lba, uint64_t dest_lba, uint64_t size)
{
	uint64_t lba_diff;
	int unaligned;

	if (src_tdisk->lba_shift == LBA_SHIFT)
		unaligned = 0;
	else {
		lba_diff = (src_lba - (src_lba & ~0x7ULL));
		if (!lba_diff && !(size & LBA_MASK)) {
			lba_diff = (dest_lba - (dest_lba & ~0x7ULL));
			if (!lba_diff && !(size & LBA_MASK))
				unaligned = 0;
			else
				unaligned = 1;
		}
		else
			unaligned = 1;
	}
	return unaligned;
}

static void 
extended_copy_mirror_check(struct tdisk *src_tdisk, struct qsio_scsiio *ctio, struct tdisk *dest_tdisk, uint64_t src_lba, uint64_t dest_lba, uint32_t num_blocks, int *mirror_enabled, int *use_refs, uint32_t *xchg_id)
{
	int retval;

	if (tdisk_mirroring_configured(dest_tdisk))
		*mirror_enabled = 1;

	if (!tdisk_mirroring_configured(src_tdisk))
		return;

	if (src_tdisk->mirror_state.mirror_ipaddr != dest_tdisk->mirror_state.mirror_ipaddr)
		return;

	if (tdisk_mirroring_disabled(src_tdisk) || tdisk_mirroring_disabled(dest_tdisk))
		return;

	if (tdisk_mirroring_need_resync(src_tdisk) || tdisk_mirroring_need_resync(dest_tdisk))
		return;

	retval = tdisk_mirror_extended_copy_read(src_tdisk, ctio, dest_tdisk, src_lba, dest_lba, num_blocks, xchg_id);
	if (unlikely(retval != 0))
		return;

	*use_refs = 1;
}

static int 
extended_copy_run(struct tdisk *tdisk, struct qsio_scsiio *ctio, struct extended_copy *ecopy)
{
	struct segment_descriptor_common *common;
	struct segment_descriptor_b2b *b2b;
	struct tdisk *dest_tdisk = NULL, *src_tdisk = NULL;
	uint16_t num_blocks;
	uint64_t src_lba;
	uint64_t dest_lba;
	int unaligned, retval;
	uint64_t lba_diff;
	uint32_t size;
	struct pgdata **pglist;
	int pglist_cnt;
	struct index_info_list index_info_list;
	int mirror_enabled, use_refs;
	uint32_t xchg_id;
	struct lba_write *lba_write;

	TAILQ_INIT(&index_info_list);
	SLIST_FOREACH(common, &ecopy->segment_list, s_list) {
		if (common->type_code != 0x02)
			continue;

		retval = extended_copy_get_tdisks(tdisk, ecopy, common, &dest_tdisk, &src_tdisk);
		if (unlikely(retval != 0)) {
			ctio_construct_sense(ctio, SSD_CURRENT_ERROR, SSD_KEY_ILLEGAL_REQUEST, 0, UNREACHABLE_COPY_TARGET_ASC, UNREACHABLE_COPY_TARGET_ASCQ);
			return 0;
		}

		b2b = (struct segment_descriptor_b2b *)(common->desc);
		num_blocks = be16toh(b2b->num_blocks);
		if (!num_blocks)
			continue;

		size = num_blocks << src_tdisk->lba_shift;
		if (size > TDISK_XCOPY_SEGMENT_LENGTH_MAX) {
			debug_warn("extended copy size %u exceeds max %u\n", size, TDISK_XCOPY_SEGMENT_LENGTH_MAX);
			ctio_construct_sense(ctio, SSD_CURRENT_ERROR, SSD_KEY_ILLEGAL_REQUEST, 0, UNREACHABLE_COPY_TARGET_ASC, UNREACHABLE_COPY_TARGET_ASCQ);
			return 0;
		}

		TDISK_STATS_ADD(src_tdisk, xcopy_read, size);
		TDISK_STATS_ADD(dest_tdisk, xcopy_write, size);
		src_lba = be64toh(b2b->src_lba);
		dest_lba = be64toh(b2b->dest_lba);
		debug_info("src lba %llu dest lba %llu num_blocks %u\n", (unsigned long long)src_lba, (unsigned long long)dest_lba, num_blocks);

		unaligned = is_unaligned_extended_copy(src_tdisk, src_lba, dest_lba, size);
		xchg_id = 0;
		mirror_enabled = 0;
		use_refs = 0;
		lba_write = tdisk_add_lba_write(src_tdisk, src_lba, num_blocks, 0, QS_IO_READ, 0);
		if (!unaligned) {
			extended_copy_mirror_check(src_tdisk, ctio, dest_tdisk, src_lba, dest_lba, num_blocks, &mirror_enabled, &use_refs, &xchg_id);
			retval = __tdisk_cmd_ref_int(src_tdisk, dest_tdisk, ctio, &pglist, &pglist_cnt, src_lba, num_blocks, &index_info_list, mirror_enabled, use_refs);
			tdisk_remove_lba_write(src_tdisk, &lba_write);
			if (unlikely(retval != 0))
				return 0;
			TDISK_INC(src_tdisk, xcopy_aligned, pglist_cnt);
		}
		else {
			pglist = NULL;
			pglist_cnt = 0;
			retval = __tdisk_cmd_read_int(src_tdisk, ctio, &pglist, &pglist_cnt, src_lba, num_blocks, 0, lba_write);
			tdisk_remove_lba_write(src_tdisk, &lba_write);
			if (unlikely(retval != 0))
				return 0;
			TDISK_INC(src_tdisk, xcopy_unaligned, pglist_cnt);

			if (src_tdisk->lba_shift != LBA_SHIFT) {
				int pg_offset;
				struct pgdata *pgdata;

				lba_diff = (src_lba - (src_lba & ~0x7ULL));
				pg_offset = (lba_diff << src_tdisk->lba_shift);
				pgdata = pglist[0];
				pgdata->pg_offset = pg_offset;
				pgdata->pg_len -= pg_offset;
				if (pg_offset) {
					retval = remap_pglist_for_write(&pglist, &pglist_cnt, size);
					if (unlikely(retval != 0)) {
						return 0;
					}
				}
			}
		}

		ctio->dxfer_len = size;
		ctio->data_ptr = (void *)pglist;
		ctio->pglist_cnt = pglist_cnt;
		pglist_calc_hash(dest_tdisk, pglist, pglist_cnt, mirror_enabled, use_refs);
		retval = __tdisk_cmd_write(dest_tdisk, ctio, dest_lba, num_blocks, 0, 0, &index_info_list, 0, 0, xchg_id);
		if (unlikely(retval != 0)) {
			free_block_refs(tdisk, &index_info_list);
			return -1;
		}
		debug_check(!TAILQ_EMPTY(&index_info_list));
	}

	return 0;
}

void
tdisk_cmd_extended_copy_read(struct tdisk *tdisk, struct qsio_scsiio *ctio)
{
	uint8_t *cdb = ctio->cdb;
	uint32_t parameter_list_length;
	struct extended_copy *ecopy;
	int retval = 0;

	TDISK_INC(tdisk, xcopy_cmds, 1);
	parameter_list_length = be32toh(*(uint32_t *)(&cdb[10]));
	if (!parameter_list_length) {
		ctio_free_data(ctio);
		goto send;
	}

	if (parameter_list_length < sizeof(struct extended_copy_parameter_list)) {
		ctio_free_data(ctio);
		goto send;
	}

	retval = tdisk_mirror_cmd_generic2(tdisk, ctio);
	if (retval)
		return;

	ecopy = zalloc(sizeof(*ecopy), M_ECOPY, Q_WAITOK);
	SLIST_INIT(&ecopy->target_list);
	SLIST_INIT(&ecopy->segment_list);

	tdisk_lock(tdisk);
	retval = tdisk_parse_extended_copy_param(ctio, ecopy);
	if (unlikely(retval != 0)) {
		extended_copy_free(ecopy);
		tdisk_unlock(tdisk);
		ctio_free_data(ctio);
		retval = 0;
		goto send;
	}

	SLIST_INSERT_HEAD(&tdisk->ecopy_list, ecopy, e_list);
	tdisk_unlock(tdisk);

	ctio_free_data(ctio);
	atomic_inc(&write_requests);
	retval = extended_copy_run(tdisk, ctio, ecopy);
	atomic_dec(&write_requests);

	tdisk_lock(tdisk);
	SLIST_REMOVE(&tdisk->ecopy_list, ecopy, extended_copy, e_list);
	extended_copy_free(ecopy);
	tdisk_unlock(tdisk);

send:
	if (retval == 0)
		device_send_ccb(ctio);
}

static int
copy_results_operating_parameters(struct tdisk *tdisk, struct qsio_scsiio *ctio, uint32_t allocation_length)
{
	int min_len;
	struct operating_parameters params;

	min_len = min_t(int, sizeof(params), allocation_length);
	ctio_allocate_buffer(ctio, min_len, Q_NOWAIT);
	if (unlikely(!ctio->data_ptr))
	{
		return -1;
	}

	bzero(&params, sizeof(params));
	params.avail_data = htobe32(sizeof(params) - 4);
	params.rsvd1[0] = 0x1;
	params.max_target_descriptor_count = htobe16(2);
	params.max_segment_descriptor_count = htobe16(1);
	params.max_descriptor_list_length = htobe32(65535);
	params.max_segment_length = htobe32(TDISK_XCOPY_SEGMENT_LENGTH);
	params.max_concurrent_copies = 0xFF;
	params.rsvd2[2] = 0xFF;
	params.rsvd2[3] = 0xFF;
	params.data_segment_granularity = tdisk->lba_shift;
	params.implemented_desc_list_length = 2;
	params.desc_type_codes[0] = 0x02; /* block to block without held data */
	params.desc_type_codes[1] = 0xE4; /* Identification target descriptor */
	memcpy(ctio->data_ptr, &params, min_len);
	return 0;
}

static inline int
copy_results_copy_status(struct tdisk *tdisk, struct qsio_scsiio *ctio, uint16_t allocation_length, uint8_t list_identifier)
{
	struct extended_copy *ecopy;
	struct copy_status status;
	int min_len;

	min_len = min_t(int, sizeof(status), allocation_length);
	ctio_allocate_buffer(ctio, min_len, Q_NOWAIT);
	if (unlikely(!ctio->data_ptr))
	{
		return -1;
	}

	tdisk_lock(tdisk);
	ecopy = extended_copy_locate(tdisk, list_identifier);
	if (!ecopy) {
		ctio_construct_sense(ctio, SSD_CURRENT_ERROR, SSD_KEY_ILLEGAL_REQUEST, 0, INVALID_FIELD_IN_CDB_ASC, INVALID_FIELD_IN_CDB_ASCQ);
		tdisk_unlock(tdisk);
		return 0;
	}

	bzero(&status, sizeof(status));
	status.avail_data = htobe32(8);
	status.copy_status = ecopy->copy_status;
	status.segments_processed = htobe16(ecopy->segments_processed);
	status.transfer_count = htobe32(ecopy->transfer_count);
	tdisk_unlock(tdisk);
	memcpy(ctio->data_ptr, &status, min_len);
	return 0;
}

int 
tdisk_cmd_receive_copy_results(struct tdisk *tdisk, struct qsio_scsiio *ctio)
{
	uint8_t *cdb = ctio->cdb;
	uint32_t allocation_length;
	uint8_t service_action;
#if 0
	uint8_t list_identifier;
#endif
	int retval;

	service_action = cdb[1] & 0x1F;
	allocation_length = be32toh(*((uint32_t *)(&cdb[10])));
#if 0
	list_identifier = cdb[2];
#endif

	switch (service_action) {
#if 0
		case COPY_STATUS:
			retval = copy_results_copy_status(tdisk, ctio, allocation_length, list_identifier);
			break;
#endif
		case OPERATING_PARAMETERS:
			retval = copy_results_operating_parameters(tdisk, ctio, allocation_length);
			break;
		case COPY_STATUS:
		case RECEIVE_DATA:
		case FAILED_SEGMENT_STATUS:
			retval = 0;
			ctio_construct_sense(ctio, SSD_CURRENT_ERROR, SSD_KEY_ILLEGAL_REQUEST, 0, INVALID_FIELD_IN_CDB_ASC, INVALID_FIELD_IN_CDB_ASCQ);
			break;
		default:
			retval = 0;
			break;
	}
	return retval;
}

void
tdisk_cmd_unmap(struct tdisk *tdisk, struct qsio_scsiio *ctio)
{
	uint8_t *cdb = ctio->cdb;
	uint16_t parameter_list_length;
	uint8_t *buffer, *orig_buffer = NULL;
	uint16_t data_length;
	uint16_t block_descriptor_length;
	struct unmap_block_descriptor *desc;
	uint64_t lba;
	uint32_t num_blocks;
	int retval, dxfer_len;
	unsigned long flags;
	int pglist_cnt;

	parameter_list_length = be16toh(*(uint16_t *)(&cdb[7]));
	debug_info("parameter list length %d\n", parameter_list_length);
	if (parameter_list_length <= 4 ) {
		ctio_free_data(ctio);
		goto send;
	}

	TDISK_INC(tdisk, unmap_cmds, 1);

#if 0
	retval = tdisk_mirror_cmd_generic(tdisk, ctio);
	if (retval)
		return;
#endif

	orig_buffer = buffer = ctio->data_ptr;
	dxfer_len = ctio->dxfer_len;
	ctio->data_ptr = NULL;
	ctio->dxfer_len = 0;

	data_length = be16toh(*((uint16_t *)(buffer)));
	block_descriptor_length = be16toh(*((uint16_t *)(buffer + 2)));
	debug_info("data length %d block descriptor length %d\n", data_length, block_descriptor_length);

	if (!block_descriptor_length) {
		ctio_free_data(ctio);
		goto send;
	}

	if (((data_length + 2) != dxfer_len) || ((block_descriptor_length + 8) != dxfer_len)) {
		debug_warn("ctio dxfer len %d data length %d block descriptor length %d\n", dxfer_len, data_length, block_descriptor_length);
		ctio_free_data(ctio);
		ctio_construct_sense(ctio, SSD_CURRENT_ERROR, SSD_KEY_ILLEGAL_REQUEST, 0, INVALID_FIELD_IN_CDB_ASC, INVALID_FIELD_IN_CDB_ASCQ);
		goto send;
	}

	/* Support only one descriptor */
#if 0
	if (block_descriptor_length != sizeof(struct unmap_block_descriptor)) {
		goto send;
	}
#endif
	debug_info("num block descriptors %d\n", (int)(block_descriptor_length/sizeof(struct unmap_block_descriptor)));

	buffer += 8;
	while (block_descriptor_length >= sizeof(struct unmap_block_descriptor)) {
		desc = (struct unmap_block_descriptor *)(buffer);
		lba = be64toh(desc->lba);
		num_blocks = be32toh(desc->num_blocks);
		buffer += sizeof(struct unmap_block_descriptor);
		block_descriptor_length -= sizeof(struct unmap_block_descriptor);

		debug_info("lba %llu num_blocks %u\n", (unsigned long long)lba, num_blocks);
		if ((tdisk->lba_shift == LBA_SHIFT && num_blocks > TDISK_UNMAP_LBA_COUNT) ||
		    (tdisk->lba_shift != LBA_SHIFT && num_blocks > TDISK_UNMAP_LBA_COUNT_LEGACY)) {
			debug_warn("lba %llu num blocks %u\n", (unsigned long long)lba, num_blocks);
			ctio_construct_sense(ctio, SSD_CURRENT_ERROR, SSD_KEY_ILLEGAL_REQUEST, 0, INVALID_FIELD_IN_PARAMETER_LIST_ASC, INVALID_FIELD_IN_PARAMETER_LIST_ASCQ);
			goto send;
		}

		if (reached_eom(tdisk, lba, num_blocks)) {
			ctio_construct_sense(ctio, SSD_CURRENT_ERROR, SSD_KEY_ILLEGAL_REQUEST, 0, LOGICAL_BLOCK_ADDRESS_OUT_OF_RANGE_ASC, LOGICAL_BLOCK_ADDRESS_OUT_OF_RANGE_ASCQ);
			goto send;
		}

		if (tdisk->lba_shift != LBA_SHIFT) {
			uint64_t lba_align;
			uint64_t lba_diff;

			lba_align = align_size(lba, 8);

			lba_diff = lba_align - lba;
			num_blocks -= lba_diff;
			lba = lba_align;
			num_blocks = (num_blocks & ~0x7U);
			pglist_cnt = transfer_length_to_pglist_cnt(tdisk->lba_shift, num_blocks);
		}
		else {
			pglist_cnt = num_blocks;
		}

		if (!pglist_cnt)
			continue;

		flags = 0;
		atomic_set_bit(DDBLOCK_ZERO_BLOCK, &flags);
		atomic_set_bit(DDBLOCK_UNMAP_BLOCK, &flags);
		TDISK_STATS_ADD(tdisk, unmap_blocks, pglist_cnt);

		retval = ctio_realloc_pglist(ctio, &pgzero, pglist_cnt, NULL, flags);
		if (unlikely(retval != 0)) {
			debug_warn("Memory allocation failure\n");
			ctio_construct_sense(ctio, SSD_CURRENT_ERROR, SSD_KEY_HARDWARE_ERROR, 0, INTERNAL_TARGET_FAILURE_ASC, INTERNAL_TARGET_FAILURE_ASCQ);
			goto send;
		}

		atomic_inc(&write_requests);
		retval = __tdisk_cmd_write(tdisk, ctio, lba, num_blocks, 0, 0, NULL, 1, 0, 0);
		atomic_dec(&write_requests);
		if (unlikely(retval != 0)) {
			debug_warn("unmap failed for lba %llu num blocks %u\n", (unsigned long long)lba, num_blocks);
			free(orig_buffer, M_CTIODATA);
			return;
		}
	}
send:
	device_send_ccb(ctio);
	if (orig_buffer)
		free(orig_buffer, M_CTIODATA);
}

static void 
tdisk_cmd_write6(struct tdisk *tdisk, struct qsio_scsiio *ctio)
{
	uint8_t *cdb = ctio->cdb;
	uint64_t lba;
	uint32_t transfer_length;

	lba = READ_24((cdb[1] & 0x1F), cdb[2], cdb[3]);
	transfer_length = cdb[4];
	if (!transfer_length) {
		/* snm limit this to block limits VPD */
		transfer_length = 256;
	}

	atomic_inc(&write_requests);
	__tdisk_cmd_write(tdisk, ctio, lba, transfer_length, 1, 0, NULL, 0, 0, 0);
	atomic_dec(&write_requests);
}

static void 
__tdisk_flush_lba_write(struct tdisk *tdisk, uint64_t lba, uint32_t transfer_length)
{
	struct lba_write *lba_write;

	lba_write = tdisk_add_lba_write(tdisk, lba, transfer_length, 0, QS_IO_WRITE, 0);
	tdisk_remove_lba_write(tdisk, &lba_write);
}

int
tdisk_cmd_verify(struct tdisk *tdisk, struct qsio_scsiio *ctio)
{
	uint8_t *cdb = ctio->cdb;
	uint64_t lba;
	uint32_t transfer_length;

	lba = be32toh(*(uint32_t *)(&cdb[2]));
	transfer_length = be16toh(*(uint16_t *)(&cdb[7]));

	debug_info("lba %llu transfer length %u\n", lba, transfer_length);
	__tdisk_flush_lba_write(tdisk, lba, transfer_length);
	return 0;
}

int
tdisk_cmd_verify12(struct tdisk *tdisk, struct qsio_scsiio *ctio)
{
	uint8_t *cdb = ctio->cdb;
	uint64_t lba;
	uint32_t transfer_length;

	lba = be32toh(*(uint32_t *)(&cdb[2]));
	transfer_length = be32toh(*(uint32_t *)(&cdb[6]));

	debug_info("lba %llu transfer length %u\n", lba, transfer_length);
	__tdisk_flush_lba_write(tdisk, lba, transfer_length);
	return 0;
}

int
tdisk_cmd_verify16(struct tdisk *tdisk, struct qsio_scsiio *ctio)
{
	uint8_t *cdb = ctio->cdb;
	uint64_t lba;
	uint32_t transfer_length;

	lba = be64toh(*(uint64_t *)(&cdb[2]));
	transfer_length = be32toh(*(uint32_t *)(&cdb[10]));

	debug_info("lba %llu transfer length %u\n", lba, transfer_length);
	__tdisk_flush_lba_write(tdisk, lba, transfer_length);
	return 0;
}

int
tdisk_cmd_sync_cache(struct tdisk *tdisk, struct qsio_scsiio *ctio)
{
	uint8_t *cdb = ctio->cdb;
	uint64_t lba;
	uint32_t transfer_length;

	lba = be32toh(*(uint32_t *)(&cdb[2]));
	transfer_length = be16toh(*(uint16_t *)(&cdb[7]));

	debug_info("sync cache for lba %llu transfer length %u\n", lba, transfer_length);
	__tdisk_flush_lba_write(tdisk, lba, transfer_length);
	return 0;
}

int
tdisk_cmd_sync_cache16(struct tdisk *tdisk, struct qsio_scsiio *ctio)
{
	uint8_t *cdb = ctio->cdb;
	uint64_t lba;
	uint32_t transfer_length;

	lba = be64toh(*(uint64_t *)(&cdb[2]));
	transfer_length = be32toh(*(uint32_t *)(&cdb[10]));

	debug_info("sync cache for lba %llu transfer length %u\n", lba, transfer_length);
	__tdisk_flush_lba_write(tdisk, lba, transfer_length);
	return 0;
}

int
tdisk_cmd_report_luns(struct tdisk *tdisk, struct qsio_scsiio *ctio)
{
	int length;
	int num_luns = 1;
	uint32_t allocation_length;

	allocation_length = be32toh(*((uint32_t *)(&ctio->cdb[6])));
	if (allocation_length < 16) {
		ctio_construct_sense(ctio, SSD_CURRENT_ERROR, SSD_KEY_ILLEGAL_REQUEST, 0, INVALID_FIELD_IN_CDB_ASC, INVALID_FIELD_IN_CDB_ASCQ);  
		return 0;
	}
	length = 8 + num_luns * 8;
	ctio_allocate_buffer(ctio, length, Q_NOWAIT);
	if (unlikely(!ctio->data_ptr))
	{
		return -1;
	}

	bzero(ctio->data_ptr, length);
	if (ctio->init_int == TARGET_INT_FC)
	{
		__write_lun(tdisk->bus, ctio->data_ptr+8);
	}
	ctio->scsi_status = SCSI_STATUS_OK;
	*((uint32_t *)ctio->data_ptr) = htobe32(length - 8);
	return 0;
}

int
tdisk_cmd_access_ok(struct tdisk *tdisk, struct qsio_scsiio *ctio)
{
	uint8_t *cdb = ctio->cdb;
	struct reservation *reservation = &tdisk->reservation;
	uint8_t write_excl = 0;
	uint8_t excl_access = 0;
	uint8_t write_excl_ro = 0;
	uint8_t excl_access_ro = 0;
	uint8_t registered = 0;
	struct registration *tmp;

	if (device_reserved(ctio, reservation) == 0)
	{
		return 0;
	}

	if (reservation->type == RESERVATION_TYPE_RESERVE)
	{
		switch (cdb[0])
		{
			case LOG_SELECT:
			case MODE_SELECT_6:
			case MODE_SELECT_10:
			case MODE_SENSE_6:
			case MODE_SENSE_10:
			case PERSISTENT_RESERVE_IN:
			case PERSISTENT_RESERVE_OUT:
			case TEST_UNIT_READY:
			case RESERVE:
			case READ_6:
			case READ_10:
			case READ_12:
			case READ_16:
			case WRITE_6:
			case WRITE_10:
			case WRITE_12:
			case WRITE_16:
			case UNMAP:
			case EXTENDED_COPY:
			case RECEIVE_COPY_RESULTS:
			case COMPARE_AND_WRITE:
			case WRITE_SAME:
			case WRITE_SAME_16:
			case SYNCHRONIZE_CACHE:
			case SYNCHRONIZE_CACHE_16:
			case VERIFY:
			case VERIFY_12:
			case VERIFY_16:
				return -1; /* conflict */
			case INQUIRY:
			case LOG_SENSE:
			case REPORT_LUNS:
			case RELEASE:
				return 0; 
		}
		return 0;
	}

	SLIST_FOREACH(tmp, &reservation->registration_list, r_list) {
		if (iid_equal(tmp->i_prt, tmp->t_prt, tmp->init_int, ctio->i_prt, ctio->t_prt, ctio->init_int))
		{
			registered = 1;
			break;
		}
	}

	switch (reservation->persistent_type)
	{
		case RESERVATION_TYPE_WRITE_EXCLUSIVE:
			write_excl = 1;
			break;
		case RESERVATION_TYPE_EXCLUSIVE_ACCESS:
			excl_access = 1;
			break;
		case RESERVATION_TYPE_WRITE_EXCLUSIVE_RO:
		case RESERVATION_TYPE_WRITE_EXCLUSIVE_AR:
			write_excl_ro = 1;
			break;
		case RESERVATION_TYPE_EXCLUSIVE_ACCESS_RO:
		case RESERVATION_TYPE_EXCLUSIVE_ACCESS_AR:
			excl_access_ro = 1;
			break;
	}

	debug_info("cmd %x write_excl %d excl_access %d write_excl_ro %d excl_access_ro %d registered %d\n", cdb[0], write_excl, excl_access, write_excl_ro, excl_access_ro, registered);
	switch(cdb[0])
	{
		case LOG_SELECT:
		case MODE_SENSE_6:
		case MODE_SENSE_10:
		case MODE_SELECT_6:
		case MODE_SELECT_10:
		case TEST_UNIT_READY:
		case WRITE_6:
		case WRITE_10:
		case WRITE_12:
		case WRITE_16:
		case UNMAP:
		case EXTENDED_COPY:
		case RECEIVE_COPY_RESULTS:
		case COMPARE_AND_WRITE:
		case WRITE_SAME:
		case WRITE_SAME_16:
		case SYNCHRONIZE_CACHE:
		case SYNCHRONIZE_CACHE_16:
			if (write_excl || excl_access)
			{
				return -1;
			}
			if ((write_excl_ro || excl_access_ro) && !registered)
			{
				return -1;
			}
			return 0;
		case READ_6:
		case READ_10:
		case READ_12:
		case READ_16:
		case VERIFY:
		case VERIFY_12:
		case VERIFY_16:
			if (excl_access)
			{
				return -1;
			}
			if (excl_access_ro && !registered)
			{
				return -1;
			}
			return 0;
		case INQUIRY:
		case PERSISTENT_RESERVE_IN:
		case PERSISTENT_RESERVE_OUT:
		case REPORT_LUNS:
			return 0;
		case RELEASE:
		case RESERVE:
			return -1;
	}

	return 0;
}

int
tdisk_check_cmd(uint8_t op)
{
	switch(op)
	{
		case TEST_UNIT_READY:
		case INQUIRY:
		case RESERVE:
		case RELEASE:
		case PERSISTENT_RESERVE_IN:
		case PERSISTENT_RESERVE_OUT:
		case REQUEST_SENSE:
		case READ_CAPACITY:
		case SERVICE_ACTION_IN:
		case MODE_SENSE_6:
		case MODE_SENSE_10:
		case READ_6:
		case READ_10:
		case READ_12:
		case READ_16:
		case WRITE_SAME:
		case WRITE_SAME_16:
		case UNMAP:
		case EXTENDED_COPY:
		case RECEIVE_COPY_RESULTS:
		case COMPARE_AND_WRITE:
		case WRITE_6:
		case WRITE_10:
		case WRITE_12:
		case WRITE_16:
		case REPORT_LUNS:
		case VERIFY:
		case VERIFY_12:
		case VERIFY_16:
		case SYNCHRONIZE_CACHE:
		case SYNCHRONIZE_CACHE_16:
			return 0;
	}
	debug_info("Invalid cmd %x\n", op);
	return -1;
}

#ifdef ENABLE_STATS
static void
tdisk_update_ctio_stats(struct tdisk *tdisk, struct qsio_scsiio *ctio)
{
	switch (ctio->task_attr) {
		case MSG_SIMPLE_TASK:
			TDISK_INC(tdisk, tag_simple, 1);
			break;
		case MSG_ORDERED_TASK:
			TDISK_INC(tdisk, tag_ordered, 1);
			break;
		case MSG_HEAD_OF_QUEUE_TASK:
			TDISK_INC(tdisk, tag_head, 1);
			break;
		default:
			debug_warn("task attr %x\n", ctio->task_attr);
			break;
	}
}
#endif

void
tdisk_proc_cmd(void *disk, void *iop)
{
	struct tdisk *tdisk = disk;
	struct qsio_scsiio *ctio = iop;
	uint8_t *cdb = ctio->cdb;
	int retval = 0;
	struct initiator_state *istate;
	struct sense_info *sinfo;
#ifdef ENABLE_STATS
	uint32_t start_ticks;
#endif

#ifdef ENABLE_STATS
	tdisk_update_ctio_stats(tdisk, ctio);
#endif
	debug_info("cmd %x\n", cdb[0]);
#ifdef ENABLE_DEBUG
	if (cdb[0])
	{
		print_cdb(cdb);
	}
#endif

	if (node_in_standby() || !vdisk_ready(tdisk) || !tdisk_mirror_ready(tdisk)) {
		if (is_write_cmd(ctio))
			wait_for_pgdata((struct pgdata **)ctio->data_ptr, ctio->pglist_cnt);
		ctio_free_data(ctio);
		ctio->scsi_status = SCSI_STATUS_BUSY;
		goto out;
	}

	if (atomic_read(&tdisk->group->log_error) && is_write_cmd(ctio)) {
		wait_for_pgdata((struct pgdata **)ctio->data_ptr, ctio->pglist_cnt);
		ctio_free_data(ctio);
		ctio_construct_sense(ctio, SSD_CURRENT_ERROR, SSD_KEY_DATA_PROTECT, 0, SPACE_ALLOCATION_FAILED_WRITE_PROTECT_ASC, SPACE_ALLOCATION_FAILED_WRITE_PROTECT_ASCQ);
		goto out;
	}

	istate = ctio->istate;

	if (!istate) {
		if (is_write_cmd(ctio))
			wait_for_pgdata((struct pgdata **)ctio->data_ptr, ctio->pglist_cnt);
		ctio_free_data(ctio);
		ctio_construct_sense(ctio, SSD_CURRENT_ERROR, SSD_KEY_ILLEGAL_REQUEST, 0, LOGICAL_UNIT_NOT_SUPPORTED_ASC, LOGICAL_UNIT_NOT_SUPPORTED_ASCQ);
		goto out;
	}

	switch(cdb[0])
	{
		case INQUIRY:
		case REPORT_LUNS:
		case REQUEST_SENSE:
			break;
		default:
			if (SLIST_EMPTY(&istate->sense_list))
				break;
			tdisk_reservation_lock(tdisk);
			sinfo = device_get_sense(istate);
			tdisk_reservation_unlock(tdisk);
			if (!sinfo)
				break;
			device_move_sense(ctio, sinfo);
			if (is_write_cmd(ctio))
				wait_for_pgdata((struct pgdata **)ctio->data_ptr, ctio->pglist_cnt);
			ctio_free_data(ctio);
			goto out;
	}

	if (tdisk->reservation.is_reserved) {
		tdisk_reservation_lock(tdisk);
		retval = tdisk_cmd_access_ok(tdisk, ctio);
		tdisk_reservation_unlock(tdisk);
		if (retval != 0) {
			if (is_write_cmd(ctio))
				wait_for_pgdata((struct pgdata **)ctio->data_ptr, ctio->pglist_cnt);
			ctio_free_data(ctio);
			ctio->scsi_status = SCSI_STATUS_RESERV_CONFLICT;
			goto out;
		}
	}

	switch(cdb[0]) {
		case TEST_UNIT_READY:
			retval = tdisk_cmd_test_unit_ready(tdisk, ctio);	
			break;
		case INQUIRY:
			retval = tdisk_cmd_inquiry(tdisk, ctio);
			break;
		case RESERVE:
			retval = tdisk_cmd_reserve(tdisk, ctio);
			break;
		case RELEASE:
			retval = tdisk_cmd_release(tdisk, ctio);
			break;
		case PERSISTENT_RESERVE_IN:
			retval = tdisk_cmd_persistent_reserve_in(tdisk, ctio);
			break;
		case PERSISTENT_RESERVE_OUT:
			retval = tdisk_cmd_persistent_reserve_out(tdisk, ctio);
			break;
		case REQUEST_SENSE:
			retval = tdisk_cmd_request_sense(tdisk, ctio);
			break;
		case READ_CAPACITY:
			retval = tdisk_cmd_read_capacity(tdisk, ctio);
			break;
		case SERVICE_ACTION_IN:
			retval = tdisk_cmd_service_action_in(tdisk, ctio);
			break;
		case MODE_SENSE_6:
			retval = tdisk_cmd_mode_sense6(tdisk, ctio);
			break;
		case MODE_SENSE_10:
			retval = tdisk_cmd_mode_sense10(tdisk, ctio);
			break;
		case READ_6:
			TDISK_TSTART(start_ticks);
			tdisk_cmd_read6(tdisk, ctio);
			TDISK_TEND(tdisk, read_ticks, start_ticks);
			goto skip_send;
			break;
		case READ_10:
			TDISK_TSTART(start_ticks);
			tdisk_cmd_read10(tdisk, ctio);
			TDISK_TEND(tdisk, read_ticks, start_ticks);
			goto skip_send;
			break;
		case READ_12:
			TDISK_TSTART(start_ticks);
			tdisk_cmd_read12(tdisk, ctio);
			TDISK_TEND(tdisk, read_ticks, start_ticks);
			goto skip_send;
			break;
		case READ_16:
			TDISK_TSTART(start_ticks);
			tdisk_cmd_read16(tdisk, ctio);
			TDISK_TEND(tdisk, read_ticks, start_ticks);
			goto skip_send;
			break;
		case WRITE_SAME:
			TDISK_TSTART(start_ticks);
			tdisk_cmd_write_same(tdisk, ctio);
			TDISK_TEND(tdisk, write_same_ticks, start_ticks);
			goto skip_send;
			break;
		case WRITE_SAME_16:
			TDISK_TSTART(start_ticks);
			tdisk_cmd_write_same16(tdisk, ctio);
			TDISK_TEND(tdisk, write_same_ticks, start_ticks);
			goto skip_send;
			break;
		case UNMAP:
			TDISK_TSTART(start_ticks);
			tdisk_cmd_unmap(tdisk, ctio);
			TDISK_TEND(tdisk, unmap_ticks, start_ticks);
			goto skip_send;
			break;
		case EXTENDED_COPY:
			TDISK_TSTART(start_ticks);
			tdisk_cmd_extended_copy_read(tdisk, ctio);
			TDISK_TEND(tdisk, extended_copy_read_ticks, start_ticks);
			goto skip_send;
			break;
		case RECEIVE_COPY_RESULTS:
			retval = tdisk_cmd_receive_copy_results(tdisk, ctio);
			break;
		case COMPARE_AND_WRITE:
			TDISK_TSTART(start_ticks);
			tdisk_cmd_compare_and_write(tdisk, ctio);
			TDISK_TEND(tdisk, compare_write_ticks, start_ticks);
			goto skip_send;
			break;
		case WRITE_6:
			TDISK_TSTART(start_ticks);
			tdisk_cmd_write6(tdisk, ctio);
			TDISK_TEND(tdisk, write_ticks, start_ticks);
			goto skip_send;
			break;
		case WRITE_10:
			TDISK_TSTART(start_ticks);
			tdisk_cmd_write10(tdisk, ctio);
			TDISK_TEND(tdisk, write_ticks, start_ticks);
			goto skip_send;
			break;
		case WRITE_12:
			TDISK_TSTART(start_ticks);
			tdisk_cmd_write12(tdisk, ctio);
			TDISK_TEND(tdisk, write_ticks, start_ticks);
			goto skip_send;
			break;
		case WRITE_16:
			TDISK_TSTART(start_ticks);
			tdisk_cmd_write16(tdisk, ctio);
			TDISK_TEND(tdisk, write_ticks, start_ticks);
			goto skip_send;
			break;
		case REPORT_LUNS:
			retval = tdisk_cmd_report_luns(tdisk, ctio);
			break;
		case VERIFY:
			retval = tdisk_cmd_verify(tdisk, ctio);
			break;
		case VERIFY_12:
			retval = tdisk_cmd_verify12(tdisk, ctio);
			break;
		case VERIFY_16:
			retval = tdisk_cmd_verify16(tdisk, ctio);
			break;
		case SYNCHRONIZE_CACHE:
			TDISK_TSTART(start_ticks);
			retval = tdisk_cmd_sync_cache(tdisk, ctio);
			TDISK_TEND(tdisk, sync_cache_ticks, start_ticks);
			break;
		case SYNCHRONIZE_CACHE_16:
			TDISK_TSTART(start_ticks);
			retval = tdisk_cmd_sync_cache16(tdisk, ctio);
			TDISK_TEND(tdisk, sync_cache16_ticks, start_ticks);
			break;
		default:
			debug_info("Invalid cdb %x\n", cdb[0]);
			ctio_free_data(ctio);
			ctio_construct_sense(ctio, SSD_CURRENT_ERROR, SSD_KEY_ILLEGAL_REQUEST, 0, INVALID_COMMAND_OPERATION_CODE_ASC, INVALID_COMMAND_OPERATION_CODE_ASCQ);
			retval = 0;
			break;
	}

	if (unlikely(retval != 0)) {
		debug_check(ctio->dxfer_len);
		ctio_free_data(ctio);
		ctio_construct_sense(ctio, SSD_CURRENT_ERROR, SSD_KEY_HARDWARE_ERROR, 0, INTERNAL_TARGET_FAILURE_ASC, INTERNAL_TARGET_FAILURE_ASCQ);
	}

out:
	debug_info("end cmd %x\n", cdb[0]);
#ifdef ENABLE_DEBUG
	if (cdb[0])
	{
		print_buffer(ctio->data_ptr, ctio->dxfer_len);
	}
#endif
	device_send_ccb(ctio);
skip_send:
	return;
}

void
tdisk_reset(struct tdisk *tdisk, uint64_t i_prt[], uint64_t t_prt[], uint8_t init_int)
{
	struct initiator_state *iter;

	tdisk_reservation_lock(tdisk);
	chan_lock(devq_wait);
	SLIST_FOREACH(iter, &tdisk->istate_list, i_list) {
		istate_abort_tasks(iter, i_prt, t_prt, init_int, 1);
	}
	gdevq_abort_tasks(tdisk, i_prt, t_prt, init_int);
	chan_unlock(devq_wait);

	if (tdisk->reservation.is_reserved && tdisk->reservation.type == RESERVATION_TYPE_RESERVE)
	{
		tdisk->reservation.is_reserved = 0;
		tdisk->reservation.type = 0;
	}
	device_unit_attention(tdisk, 1, i_prt, t_prt, init_int, BUS_RESET_ASC, BUS_RESET_ASCQ, 1);
	node_istate_sense_state_send(tdisk);
	tdisk_reservation_unlock(tdisk);
	device_unblock_queues(tdisk);
}

static int 
amap_table_group_clear_write_bitmap(struct amap_table_group *group)
{
	struct amap_table *amap_table;

	if (!group->group_write_bmap)
		return 0;

	TAILQ_FOREACH(amap_table, &group->table_list, t_list) {
		atomic_clear_bit_short(ATABLE_WRITE_BMAP_INVALID, &amap_table->flags);
		if (amap_table->write_bmap) {
			uma_zfree(write_bmap_cache, amap_table->write_bmap);
			amap_table->write_bmap = NULL;
		}
	}
	uma_zfree(group_write_bmap_cache, group->group_write_bmap);
	group->group_write_bmap = NULL;
	return 1;
}

int
tdisk_clear_write_bitmap(struct tdisk *tdisk)
{
	struct amap_table_group *group;
	int done = 0;
	int i, retval; 

	if (!tdisk->amap_table_group)
		return 0;

	tdisk_bmap_lock(tdisk);
	for (i = 0; i < tdisk->amap_table_group_max; i++) {
		group = tdisk->amap_table_group[i];
		if (!group)
			continue;

		retval = amap_table_group_clear_write_bitmap(group);
		if (retval)
			done++;
	}
	tdisk_bmap_unlock(tdisk);
	return done;
}
