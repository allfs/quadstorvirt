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

#ifndef QSTOR_TDISK_H_
#define QSTOR_TDISK_H_

#include "coredefs.h"
#include "scsidefs.h" 
#include "reservation.h" 
#include "amap.h" 
#include "ddtable.h" 
#include "../common/commondefs.h" 
#include "fastlog.h" 
#include "rcache.h"

struct caching_mode_page {
	uint8_t page_code;
	uint8_t page_length;
	uint8_t rcd;
	uint8_t write_retention_priority;
	uint16_t disable_prefetch_transfer_length;
	uint16_t minimum_prefetch;
	uint16_t maximum_prefetch;
	uint16_t maximum_prefetch_ceiling;
	uint8_t nv_dis;
	uint8_t number_of_cache_segments;
	uint16_t cache_segment_size;
	uint8_t rsvd1;
	uint8_t  obs1;
	uint8_t  obs2;
	uint8_t  obs3;
} __attribute__ ((__packed__));

#define AMAP_TABLE_ARRAY_MAX	8

#define CACHED_AMAPS_PERCENTAGE		6
#define CACHED_AMAP_TABLES_PERCENTAGE	1
#define CACHED_AMAP
#define AMAP_ASYNC_COUNT	2
#define AMAP_TABLE_ASYNC_COUNT	1

struct amap_table_index {
	uint64_t b_start;
	struct bdevint *bint;
	pagestruct_t *metadata;
	sx_t *table_index_lock;
	wait_chan_t *table_index_wait;
	int flags;
};

static inline uint64_t
get_amap_table_block(struct amap_table_index *table_index, uint32_t table_idx)
{
	uint64_t *ptr = (uint64_t *)(vm_pg_address(table_index->metadata));
	return ptr[table_idx];
}

static inline void
set_amap_table_block(struct amap_table_index *table_index, uint32_t table_idx, uint64_t block)
{
	uint64_t *ptr = (uint64_t *)(vm_pg_address(table_index->metadata));
	ptr[table_idx] = block;
}

enum {
	LBA_WRITE_DONE_ALLOC = 0x1,
	LBA_WRITE_DONE_IO = 0x2,
};

struct lba_write {
	uint64_t lba_start;
	uint64_t lba_end;
	int flags;
	uint8_t cw;
	uint8_t sync_wait;
	uint8_t remote_locked;
	uint8_t dir;
	TAILQ_ENTRY(lba_write) l_list;
};
TAILQ_HEAD(lba_list, lba_write);

#define THRESHOLD_UA_MAX		4
#define THRESHOLD_UA_INTERVAL		5000
#define THRESHOLD_SET_SIZE		8 	/* 1 MB */
#define THRESHOLD_SET_SIZE_LEGACY	11 	/* 1 MB */
#define OUT_OF_SPACE_PAUSE		3000

struct initiator_state {
	mtx_t *istate_lock;
	struct ctio_list queue_list;
	uint32_t ordered;
	uint32_t head;
	uint32_t queued;
	uint32_t pending;
	uint64_t i_prt[2];
	uint64_t t_prt[2];
	uint16_t r_prt;
	uint8_t init_int;
	uint8_t disallowed;
	atomic16_t blocked;
	atomic16_t threshold_ua;
	atomic_t refs;
	uint32_t timestamp;
	uint32_t threshold_ua_timestamp;
	SLIST_ENTRY(initiator_state) i_list;
	SLIST_HEAD(, sense_info) sense_list;
	wait_chan_t *istate_wait;
};

SLIST_HEAD(istate_list, initiator_state);

enum {
	CLONE_DATA_CLONE,
	CLONE_DATA_MIRROR,
	CLONE_DATA_DELETE,
	CLONE_DATA_RESIZE,
};

struct clone_data {
	struct amap *amap;
	struct amap *src_amap;
	struct write_list *wlist;
	pagestruct_t *metadata;
	wait_compl_t *completion;
	struct qsio_scsiio *ctio;
	uint8_t async;
	uint8_t queued;
	uint8_t error;
	uint8_t type;
	uint32_t num_blocks;
	uint64_t lba;
	struct job_stats stats;
	STAILQ_ENTRY(clone_data) c_list;
	STAILQ_ENTRY(clone_data) q_list;
};
STAILQ_HEAD(clone_data_list, clone_data);

struct clone_info {
	struct tdisk *dest_tdisk;
	struct tdisk *src_tdisk;
	struct node_comm *comm;
	kproc_t *task;
	uint64_t job_id;
	uint32_t dest_target_id;
	uint32_t start_ticks;
	uint8_t  op;
	uint8_t  attach;
	uint8_t  in_sync;
	uint8_t  mirror_role;
	char mirror_vdisk[TDISK_MAX_NAME_LEN];
	char mirror_group[GROUP_MAX_NAME_LEN];
	struct job_stats stats;
	STAILQ_ENTRY(clone_info) i_list;
};
STAILQ_HEAD(clone_info_list, clone_info);

#define JOB_STATS_ADD(clninf,count,val)					\
do {									\
	atomic64_add(val, (atomic64_t *)&clninf->stats.count);		\
} while (0)

#define JOB_STATS_ADD32(clninf,count,val)					\
do {									\
	atomic_add(val, (atomic_t *)&clninf->stats.count);		\
} while (0)


struct node_comm;
struct clone_thr {
	int flags;
	struct tdisk *tdisk;
	kproc_t *task;
	struct node_comm *comm;
	struct clone_info *clone_info;
	STAILQ_ENTRY(clone_thr) t_list;
};
STAILQ_HEAD(clone_thr_list, clone_thr);

#define tdisk_set_in_sync(tdk)		(atomic_set_bit(VDISK_IN_SYNC, &(tdk)->flags))
#define tdisk_clear_in_sync(tdk)	(atomic_clear_bit(VDISK_IN_SYNC, &(tdk)->flags))
#define tdisk_in_sync(tdk)		(atomic_test_bit(VDISK_IN_SYNC, &(tdk)->flags))

#define tdisk_set_in_mirroring(tdk)	(atomic_set_bit(VDISK_IN_MIRRORING, &(tdk)->flags))
#define tdisk_clear_in_mirroring(tdk)	(atomic_clear_bit(VDISK_IN_MIRRORING, &(tdk)->flags))
#define tdisk_in_mirroring(tdk)		(atomic_test_bit(VDISK_IN_MIRRORING, &(tdk)->flags))
#define tdisk_set_in_cloning(tdk)	(atomic_set_bit(VDISK_IN_CLONING, &(tdk)->flags))
#define tdisk_clear_in_cloning(tdk)	(atomic_clear_bit(VDISK_IN_CLONING, &(tdk)->flags))
#define tdisk_in_cloning(tdk)		(atomic_test_bit(VDISK_IN_CLONING, &(tdk)->flags))
#define tdisk_set_mirror_error(tdk)	(atomic_set_bit(VDISK_MIRROR_ERROR, &(tdk)->flags))
#define tdisk_clear_mirror_error(tdk)	(atomic_clear_bit(VDISK_MIRROR_ERROR, &(tdk)->flags))
#define tdisk_mirror_error(tdk)		(atomic_test_bit(VDISK_MIRROR_ERROR, &(tdk)->flags))
#define tdisk_set_clone_error(tdk)	(atomic_set_bit(VDISK_CLONE_ERROR, &(tdk)->flags))
#define tdisk_clone_error(tdk)		(atomic_test_bit(VDISK_CLONE_ERROR, &(tdk)->flags))

enum {
	/* written to disk */
	V2_VDISK,
	VDISK_MIRROR_ERROR,
	VDISK_CLONE_ERROR,
	VDISK_ENABLE_PROPERTIES,
	VDISK_ENABLE_DEDUPLICATION,
	VDISK_ENABLE_COMPRESSION,
	VDISK_ENABLE_VERIFY,
	VDISK_IN_DELETE,
	VDISK_IN_RESIZE,

	/* In memory */
	VDISK_FREE_START,
	VDISK_FREE_EXIT,
	VDISK_SYNC_START,
	VDISK_SYNC_EXIT,
	VDISK_LOAD_EXIT,
	VDISK_ATTACH_EXIT,
	VDISK_DELETE_EXIT,
	VDISK_IN_CLONING,
	VDISK_IN_MIRRORING,
	VDISK_ATTACHED,
	VDISK_DISABLED,
	VDISK_FREE_ALLOC,
	VDISK_IN_SYNC,
	VDISK_MIRROR_LOAD_DONE,
	VDISK_DONE_DELETE,
	VDISK_SYNC_ENABLED,
};

struct tdisk {
	pagestruct_t *metadata;
	uint8_t enable_compression : 1;
	uint8_t enable_deduplication : 1;
	uint8_t enable_verify : 1;
	uint8_t force_inline : 1;
	uint8_t remote : 1;
	uint8_t pad : 3;
	uint8_t lba_shift;
	uint8_t table_index_max;
	uint8_t threshold;
	uint16_t target_id;
	uint16_t bus;
	int iscsi_tid;
	int vhba_id;
	void *hpriv;
	uint64_t end_lba;

	mtx_t *group_list_lock;
	mtx_t *stats_lock;
	sx_t *reservation_lock;
	sx_t *tdisk_lock;
	atomic_t amap_count;
	atomic_t amap_table_count;
	atomic_t refs;
	int flags;
	wait_chan_t *free_wait;
	wait_chan_t *sync_wait;
	wait_chan_t *load_wait;
	wait_chan_t *attach_wait;
	wait_chan_t *delete_wait;
	wait_chan_t *lba_wait;
	wait_chan_t *lba_write_wait;
	wait_chan_t *lba_read_wait;
	kproc_t *free_task;
	kproc_t *sync_task;
	kproc_t *load_task;
	kproc_t *attach_task;
	kproc_t *delete_task;
	struct istate_list istate_list;
	struct istate_list sync_istate_list;
	struct lba_list lba_list;
	struct lba_list lba_write_list;
	struct lba_list lba_read_list;
	SLIST_HEAD(, extended_copy) ecopy_list;
	struct tdisk *dest_tdisk;
	struct clone_data_list clone_list;
	struct write_list *clone_wlist;
	struct clone_info *clone_info;
	wait_chan_t *clone_wait;
	sx_t *clone_lock;
	sx_t *bmap_lock;
	int clone_flags;
	uint32_t clone_amap_id;
	struct group_bmap_list *group_bmaps; 
	struct amap_group_bitmap **group_table_bmaps;
	struct logical_unit_identifier unit_identifier;
	struct logical_unit_naa_identifier naa_identifier;
	struct reservation reservation;
	struct reservation sync_reservation;

	/* amap related stuff */
	struct bdevgroup *group;
	struct amap_table_group **amap_table_group;
	TAILQ_HEAD(, amap_table_group) group_list;
	struct amap_table_index *table_index;
	uint32_t amap_table_group_max;
	uint32_t amap_table_max;
	struct tdisk_stats stats;
	char name[TDISK_MAX_NAME_LEN];

	/* Mirror stuff */
	struct node_comm *mirror_comm;
	sx_t *mirror_lock;
	wait_chan_t *mirror_wait;
	struct mirror_state mirror_state;
	atomic_t mirror_cmds;
	atomic_t clone_busy;

#ifdef ENABLE_STATS
	uint64_t read_total;
	uint64_t from_read_list;
	uint64_t from_rcache;
	uint64_t remote_reads;
	uint64_t local_reads;

	uint32_t process_delete_block_ticks;
	uint32_t process_delete_block_wlist_ticks;
	uint32_t process_delete_block_amap_ticks;
	uint32_t process_delete_block_amap_table_ticks;
	uint32_t delete_ticks;
	uint32_t sync_wlist_ticks;
	uint32_t sync_wlist_merge_ticks;
	uint32_t amap_table_group_delete_ticks;
	uint32_t amap_table_delete_ticks;
	uint32_t amap_table_delete_iowait_ticks;
	uint32_t amap_delete_ticks;
	uint32_t amap_delete_iowait_ticks;

	uint32_t read_setup_ticks;
	uint32_t read_io_ticks;
	uint32_t remote_read_io_ticks;
	uint32_t read_io_done_ticks;
	uint32_t node_cmd_read_ticks;
	uint32_t write_setup_ticks;
	uint32_t write_done_ticks;
	uint32_t node_cmd_write_ticks;

	uint32_t unmap_cmds;
	uint32_t wsame_cmds;
	uint32_t wsame_unmap_cmds;
	uint32_t xcopy_cmds;
	uint32_t pgalloc_hits;
	uint32_t pgalloc_misses;
	uint32_t amap_barrier_ticks;
	uint32_t amap_table_barrier_ticks;
	uint32_t amap_table_index_barrier_ticks;
	uint32_t get_amap_block_ticks;
	uint32_t set_amap_block_ticks;
	uint32_t check_table_read_ticks;
	uint32_t read_amap_wait_ticks;
	uint32_t amap_wait_ticks;
	uint32_t amap_new_ticks;
	uint32_t amap_alloc_block_ticks;
	uint32_t amap_load_ticks;
	uint32_t entry_rw_ticks;
	uint32_t wait_index_ticks;
	uint32_t wait_log_ticks;
	uint32_t sync_amap_list_ticks;
	uint32_t fastlog_insert_ticks;
	uint32_t amap_write_setup_ticks;
	uint32_t wait_meta_index_ticks;
	uint32_t amap_table_locate_ticks;
	uint32_t amap_table_load_ticks;
	uint32_t amap_table_init_ticks;
	uint32_t amap_table_get_amap_ticks;
	uint32_t amap_locate_ticks;
	uint32_t amap_check_sync_ticks;
	uint32_t add_lba_write_ticks;
	uint32_t scan_write_ticks;
	uint32_t wait_for_pgdata_ticks;
	uint32_t scan_dedupe_ticks;
	uint32_t check_pending_ddblocks_ticks;
	uint32_t lba_unmapped_write_ticks;
	uint32_t alloc_block_ticks;
	uint32_t alloc_pgdata_ticks;
	uint32_t alloc_pgdata_wait_ticks;
	uint32_t pgdata_alloc_blocks_ticks;
	uint32_t check_table_ticks;
	uint32_t sync_list_start_ticks;
	uint32_t fastlog_get_ticks;
	uint32_t scan_write_dedupe_setup_ticks;
	uint32_t scan_write_add_alloc_lba_ticks;
	uint32_t scan_write_update_alloc_lba_ticks;
	uint32_t wait_pending_ddblocks_ticks;
	uint32_t verify_ddblocks_ticks;
	uint32_t calc_alloc_size_ticks;
	uint32_t wait_amap_io_ticks;
	uint32_t sync_list_end_ticks;
	uint32_t amap_sync_list_end_ticks;
	uint32_t fastlog_add_ticks;

	uint32_t mirror_write_setup_orig_bytes;
	uint32_t mirror_write_setup_bytes;
	uint32_t mirror_check_io_bytes;
	uint32_t mirror_write_done_bytes;
	uint32_t mirror_write_post_pre_bytes;

	uint32_t mirror_write_setup_start_ticks;
	uint32_t mirror_check_verify_ticks;
	uint32_t mirror_check_comp_ticks;
	uint32_t mirror_check_io_ticks;
	uint32_t mirror_write_post_ticks;
	uint32_t mirror_write_done_pre_ticks;
	uint32_t mirror_write_done_post_ticks;

	uint32_t lba_unmapped_ticks;
	uint32_t read_ticks;
	uint32_t mirror_ticks;
	uint32_t clone_ticks;
	uint32_t mirror_amap_setup_read_ticks;
	uint32_t mirror_hash_compute_ticks;
	uint32_t mirror_write_setup_ticks;
	uint32_t mirror_verify_setup_ticks;
	uint32_t mirror_comp_setup_ticks;
	uint32_t mirror_write_io_ticks;
	uint32_t post_read_io_ticks;
	uint32_t read_free_amaps_ticks;
	uint32_t read_amap_block_ticks;
	uint32_t pgdata_read_list_ticks;
	uint32_t tcache_read_add_page_ticks;
	uint32_t sync_cache_ticks;
	uint32_t sync_cache16_ticks;
	uint32_t write_ticks;
	uint32_t write_same_ticks;
	uint32_t unmap_ticks;
	uint32_t extended_copy_read_ticks;
	uint32_t compare_write_ticks;
	uint32_t post_write_ticks;
	uint32_t post_io_ticks;
	uint32_t wait_for_amap_ticks;
	uint32_t table_index_write_ticks;
	uint32_t wait_for_amap_sync_ticks;
	uint32_t amap_write_wait_ticks;
	uint32_t tcache_wait_ticks;
	uint32_t tcache_setup_ticks;
	uint32_t log_list_end_writes_ticks;
	uint32_t tcache_read_wait_ticks;
	uint32_t write_add_page_ticks;
	uint32_t read_add_page_ticks;
	uint32_t biot_read_count;
	uint32_t biot_write_count;
	uint32_t fast_log_misses;
	uint32_t fast_log_hits;
	uint32_t write_page_misses;
	uint32_t write_bstart_misses;
	uint32_t write_bint_misses;
	uint32_t read_page_misses;
	uint32_t read_bstart_misses;
	uint32_t read_bint_misses;
	uint64_t lba_write_count;
	uint64_t write_count;
	uint64_t inread_list;
	uint64_t read_count;
	uint64_t lba_read_count;
	uint64_t xcopy_unaligned;
	uint64_t xcopy_aligned;
	uint64_t xcopy_ref_hits;
	uint64_t xcopy_ref_misses;
	uint32_t amap_start_write_ticks;
	uint32_t amap_end_write_ticks;
	uint32_t amap_do_io_ticks;
	uint32_t amap_end_wait_ticks;
	uint32_t amap_table_end_wait_ticks;
	uint32_t amap_table_free_alloc_ticks;
	uint32_t amap_table_group_free_alloc_ticks;
	uint32_t amap_free_alloc_ticks;
	uint32_t index_sync_start_io_ticks;
	uint32_t index_sync_wait_ticks;

	uint32_t tag_simple;
	uint32_t tag_ordered;
	uint32_t tag_head;
	uint32_t tag_aca;

	uint32_t inline_amap_writes;
	uint32_t post_amap_writes;
	uint32_t read_incache;
	uint32_t amap_new;
	uint32_t amap_load;
	uint32_t amap_table_new;
	uint32_t amap_table_load;
	uint32_t amap_writes;
	uint32_t amap_table_writes;
	uint32_t amap_table_reads;
	uint32_t amap_reads;
	uint32_t amap_wait;
	uint32_t amap_hits;
	uint32_t amap_misses;
	uint32_t pgdata_wait_cnt;
	uint32_t pgdata_wait_ticks;

#ifdef CUSTOM_BIO_STATS
	uint32_t write_bio_size_exceeded;
	uint32_t write_bio_vecs_exceeded;
	uint32_t write_bio_is_cloned;
	uint32_t write_bio_merge_failed;
	uint32_t write_bio_retried_segments;
	uint32_t read_bio_size_exceeded;
	uint32_t read_bio_vecs_exceeded;
	uint32_t read_bio_is_cloned;
	uint32_t read_bio_merge_failed;
	uint32_t read_bio_retried_segments;
#endif
#endif
};

#define tdisk_bint(tdk)		((tdk)->group->master_bint)

#define tdisk_clone_lock(tdk)		(sx_xlock((tdk)->clone_lock))
#define tdisk_clone_unlock(tdk)					\
do {									\
	debug_check(!sx_xlocked((tdk)->clone_lock));		\
	sx_xunlock((tdk)->clone_lock);				\
} while (0)

#define tdisk_bmap_lock(tdk)		(sx_xlock((tdk)->bmap_lock))
#define tdisk_bmap_unlock(tdk)					\
do {									\
	debug_check(!sx_xlocked((tdk)->bmap_lock));		\
	sx_xunlock((tdk)->bmap_lock);				\
} while (0)

#define tdisk_mirror_lock(tdk)		(sx_xlock((tdk)->mirror_lock))
#define tdisk_mirror_unlock(tdk)					\
do {									\
	debug_check(!sx_xlocked((tdk)->mirror_lock));		\
	sx_xunlock((tdk)->mirror_lock);				\
} while (0)

#define tdisk_reservation_lock(tdk)		(sx_xlock((tdk)->reservation_lock))
#define tdisk_reservation_unlock(tdk)					\
do {									\
	debug_check(!sx_xlocked((tdk)->reservation_lock));		\
	sx_xunlock((tdk)->reservation_lock);				\
} while (0)

#define tdisk_lock(tdk)		(sx_xlock((tdk)->tdisk_lock))
#define tdisk_unlock(tdk)					\
do {								\
	debug_check(!sx_xlocked((tdk)->tdisk_lock));		\
	sx_xunlock((tdk)->tdisk_lock);				\
} while (0)

static inline void
mark_v2_tdisk(struct tdisk *tdisk)
{
	atomic_set_bit(V2_VDISK, &tdisk->flags);
}

static inline int
is_v2_tdisk(struct tdisk *tdisk)
{
	return (atomic_test_bit(V2_VDISK, &tdisk->flags) != 0);
}

char * tdisk_name(struct tdisk *tdisk);

static inline void
amap_table_check_csum(struct amap_table *amap_table)
{
	uint64_t csum, raw_csum;
	struct raw_amap_table *raw_amap_table;

	if (atomic_test_bit_short(ATABLE_CSUM_CHECK_DONE, &amap_table->flags))
		return;

	if (atomic_test_bit_short(ATABLE_META_DATA_ERROR, &amap_table->flags))
		return;

	raw_amap_table = (struct raw_amap_table *)(((uint8_t *)vm_pg_address(amap_table->metadata)) + RAW_AMAP_TABLE_OFFSET);

	if (is_v2_tdisk(amap_table->tdisk)) {
		csum = calc_csum16(vm_pg_address(amap_table->metadata), AMAP_TABLE_SIZE - sizeof(uint64_t));
		raw_csum = raw_amap_table->csum & 0xFFFF;
	}
	else { 
		csum = calc_csum(vm_pg_address(amap_table->metadata), AMAP_TABLE_SIZE - sizeof(uint64_t));
		raw_csum = raw_amap_table->csum;
	}

	if (raw_csum != csum) {
		debug_warn("Metadata csum mismatch for amap table at %llu %u tdisk %s\n", (unsigned long long)(amap_table_bstart(amap_table)), amap_table_bint(amap_table)->bid, tdisk_name(amap_table->tdisk));
		atomic_set_bit_short(ATABLE_META_DATA_ERROR, &amap_table->flags);
	}
	atomic_set_bit_short(ATABLE_CSUM_CHECK_DONE, &amap_table->flags);
}

static inline void
amap_check_csum(struct amap *amap)
{
	uint64_t csum, raw_csum;
	struct raw_amap *raw_amap;

	if (atomic_test_bit_short(AMAP_CSUM_CHECK_DONE, &amap->flags))
		return;

	if (atomic_test_bit_short(AMAP_META_DATA_ERROR, &amap->flags))
		return;

	raw_amap = (struct raw_amap *)(((uint8_t *)vm_pg_address(amap->metadata)) + RAW_AMAP_OFFSET);

	if (is_v2_tdisk(amap->amap_table->tdisk)) {
		csum = calc_csum16(vm_pg_address(amap->metadata), AMAP_SIZE - sizeof(uint64_t));
		raw_csum = raw_amap->csum & 0xFFFF;
		amap->write_id = raw_amap->csum >> 16;
	}
	else {
		csum = calc_csum(vm_pg_address(amap->metadata), AMAP_SIZE - sizeof(uint64_t));
		raw_csum = raw_amap->csum;
		amap->write_id = 1;
	}

	if (raw_csum != csum) {
		debug_warn("Metadata csum mismatch for amap at %llu %u tdisk %s raw csum %llx csum %llx\n", (unsigned long long)(amap_bstart(amap)), amap_bint(amap)->bid, tdisk_name(amap->amap_table->tdisk), (unsigned long long)raw_csum, (unsigned long long)csum);
		atomic_set_bit_short(AMAP_META_DATA_ERROR, &amap->flags);
	}
	atomic_set_bit_short(AMAP_CSUM_CHECK_DONE, &amap->flags);
}

struct tdisk_info;
int target_load_disk(struct tdisk_info *tdisk_info, unsigned long arg);
int target_attach_disk(struct tdisk_info *tdisk_info, unsigned long arg);
int target_delete_disk(struct tdisk_info *tdisk_info, unsigned long arg);
int target_delete_disk_post(struct tdisk_info *tdisk_info, unsigned long arg);
int target_delete_disk_stub(struct tdisk_info *tdisk_info, unsigned long arg);
int target_disable_disk_stub(struct tdisk_info *tdisk_info, unsigned long arg);
int target_modify_disk(struct tdisk_info *tdisk_info, unsigned long arg);
int target_new_disk(struct tdisk_info *tdisk_info, unsigned long arg);
int target_resize_disk(struct tdisk_info *tdisk_info, unsigned long arg);
int target_rename_disk(struct tdisk_info *tdisk_info, unsigned long arg);
int target_set_role(struct tdisk_info *tdisk_info, unsigned long arg);
int target_new_disk_stub(struct tdisk_info *tdisk_info, unsigned long arg);
int target_disk_stats(struct tdisk_info *tdisk_info, unsigned long arg);
int target_disk_reset_stats(struct tdisk_info *tdisk_info, unsigned long arg);
int tdisk_check_cmd(uint8_t op);
void tdisk_free(struct tdisk *tdisk);

#define tdisk_get(tdk)	atomic_inc(&(tdk)->refs)

#define tdisk_put(tdk)					\
do {							\
	if (atomic_dec_and_test(&(tdk)->refs))		\
		tdisk_free(tdk);			\
} while (0)

void tdisk_reset(struct tdisk *tdisk, uint64_t i_prt[], uint64_t t_prt[], uint8_t init_int);
void pgdata_cleanup(struct pgdata *pgdata);
void ctio_check_free_data(struct qsio_scsiio *ctio);

#define TDISK_STATS_ADD(tdk,count,val)					\
do {									\
	atomic64_add(val, (atomic64_t *)&tdk->stats.count);		\
	if (!atomic_test_bit(VDISK_SYNC_START, &tdk->flags)) {		\
		atomic_set_bit(VDISK_SYNC_START, &tdk->flags);		\
	}								\
} while (0)

#ifdef ENABLE_STATS
#define TDISK_TSTART(sjiff)	(sjiff = ticks)
#define TDISK_TEND(tdk,count,sjiff)				\
do {								\
	mtx_lock(tdk->stats_lock);				\
	tdk->count += (ticks - sjiff);	\
	mtx_unlock(tdk->stats_lock);			\
} while (0)

#define TDISK_INC(tdk,count,val)					\
do {									\
	mtx_lock(tdk->stats_lock);					\
	tdk->count += val;						\
	mtx_unlock(tdk->stats_lock);					\
} while (0)

#define TDISK_DEC(tdk,count,val)					\
do {									\
	tdk->count -= val;						\
} while (0)
#else
#define TDISK_TSTART(sjiff)		do {} while (0)
#define TDISK_TEND(tdk,count,sjiff)	do {} while (0)
#define TDISK_INC(tdk,count,val)	do {} while (0)
#define TDISK_DEC(tdk,count,val)	do {} while (0)
#endif

static inline int
pgdata_amap_entry_valid(struct pgdata *pgdata)
{
	struct amap *amap;
	uint32_t entry_id;
	uint64_t amap_block;
	
	amap = pgdata->amap;
	if (!amap)
		return 1;
	entry_id = amap_entry_id(amap, pgdata->lba);
	amap_block = amap_entry_get_block(amap, entry_id);
	return (amap_block == pgdata->amap_block);
}

static inline uint64_t
get_amap_block_metadata(pagestruct_t *metadata, uint32_t amap_idx)
{
	uint64_t block;

	block = BMAP_GET_BLOCK(((uint64_t *)vm_pg_address(metadata)), amap_idx, AMAP_TABLE_BLOCK_BITS);
	return block;
}

static inline uint64_t
get_amap_block(struct amap_table *amap_table, uint32_t amap_idx)
{
	uint64_t block;
#ifdef ENABLE_STATS
	uint32_t start_ticks;
#endif

	TDISK_TSTART(start_ticks);
	block = BMAP_GET_BLOCK(((uint64_t *)vm_pg_address(amap_table->metadata)), amap_idx, AMAP_TABLE_BLOCK_BITS);
	TDISK_TEND(amap_table->tdisk, get_amap_block_ticks, start_ticks);
	return block;
}

static inline void
set_amap_block(struct amap_table *amap_table, uint32_t amap_idx, uint64_t block)
{
#ifdef ENABLE_STATS
	uint32_t start_ticks;
#endif

	TDISK_TSTART(start_ticks);
	BMAP_SET_BLOCK(((uint64_t *)vm_pg_address(amap_table->metadata)), amap_idx, block, AMAP_TABLE_BLOCK_BITS);
	TDISK_TEND(amap_table->tdisk, set_amap_block_ticks, start_ticks);
}

static inline void
amap_write_barrier(struct amap *amap)
{
#ifdef ENABLE_STATS
	struct tdisk *tdisk = amap->amap_table->tdisk;
	uint32_t start_ticks;
#endif
	pagestruct_t *page, *tmp;

	debug_check(!atomic_test_bit_short(AMAP_CSUM_CHECK_DONE, &amap->flags));
	if (!atomic_test_bit_short(AMAP_META_DATA_DIRTY, &amap->flags) || atomic_test_bit_short(AMAP_META_DATA_CLONED, &amap->flags))
		return;

	TDISK_TSTART(start_ticks);
	page = vm_pg_alloc(0);
	if (unlikely(!page)) {
		wait_on_chan(amap->amap_wait, !atomic_test_bit_short(AMAP_META_DATA_DIRTY, &amap->flags));
	}
	else {
		tmp = amap->metadata;
		memcpy(vm_pg_address(page), vm_pg_address(tmp), AMAP_SIZE);
		amap->metadata = page;
		atomic_set_bit_short(AMAP_META_DATA_CLONED, &amap->flags);
		vm_pg_free(tmp);
	}
	TDISK_TEND(tdisk, amap_barrier_ticks, start_ticks);
}

static inline void
amap_table_write_barrier(struct amap_table *amap_table)
{
#ifdef ENABLE_STATS
	struct tdisk *tdisk = amap_table->tdisk;
	uint32_t start_ticks;
#endif
	pagestruct_t *page, *tmp;

	debug_check(!atomic_test_bit_short(ATABLE_CSUM_CHECK_DONE, &amap_table->flags));
	if (!atomic_test_bit_short(ATABLE_META_DATA_DIRTY, &amap_table->flags) || atomic_test_bit_short(ATABLE_META_DATA_CLONED, &amap_table->flags))
		return;

	TDISK_TSTART(start_ticks);
	page = vm_pg_alloc(0);
	if (unlikely(!page)) {
		wait_on_chan(amap_table->amap_table_wait, !atomic_test_bit_short(ATABLE_META_DATA_DIRTY, &amap_table->flags));
	}
	else {
		tmp = amap_table->metadata;
		memcpy(vm_pg_address(page), vm_pg_address(tmp), AMAP_TABLE_SIZE);
		amap_table->metadata = page;
		atomic_set_bit_short(ATABLE_META_DATA_CLONED, &amap_table->flags);
		vm_pg_free(tmp);
	}
	TDISK_TEND(tdisk, amap_table_barrier_ticks, start_ticks);
}

static inline void
amap_table_index_write_barrier(struct tdisk *tdisk, struct amap_table_index *amap_table_index)
{
#ifdef ENABLE_STATS
	uint32_t start_ticks;
#endif

	TDISK_TSTART(start_ticks);
	wait_on_chan_check(amap_table_index->table_index_wait, !atomic_test_bit(META_DATA_DIRTY, &amap_table_index->flags));
	TDISK_TEND(tdisk, amap_table_index_barrier_ticks, start_ticks);
}

struct amap_sync {
	struct amap *amap;
	uint64_t write_id;
	SLIST_ENTRY(amap_sync) s_list;
	STAILQ_ENTRY(amap_sync) w_list;
	STAILQ_HEAD(, pgdata) pgdata_list;
	struct iowaiter iowaiter;
};
SLIST_HEAD(amap_sync_list, amap_sync);

struct amap_table_sync {
	struct amap_table *amap_table;
	STAILQ_ENTRY(amap_table_sync) w_list;
	struct iowaiter iowaiter;
};
STAILQ_HEAD(amap_table_sync_list, amap_table_sync);

static inline void
amap_sync_list_insert_tail(struct amap_sync_list *amap_sync_list, struct amap_sync *amap_sync)
{
	struct amap_sync *iter, *prev = NULL;

	SLIST_FOREACH(iter, amap_sync_list, s_list) {
		prev = iter;
	}

	if (prev)
		SLIST_INSERT_AFTER(prev, amap_sync, s_list);
	else
		SLIST_INSERT_HEAD(amap_sync_list, amap_sync, s_list);
}

STAILQ_HEAD(amap_table_list, pgdata);

enum {
	WLIST_DONE_LOG_START,
	WLIST_DONE_LOG_END,
	WLIST_DONE_LOG_POST,
	WLIST_UNALIGNED_WRITE,
	WLIST_DONE_POST_PRE,
	WLIST_DONE_PGDATA_SYNC_START,
	WLIST_DONE_NEWMETA_SYNC_START,
	WLIST_DONE_AMAP_SYNC,
	WLIST_DONE_LOG_RESERVE,
};

enum {
	MIRROR_STATUS_REMOTE_DONE,
};

struct write_list {
	uint64_t transaction_id;
	uint64_t newmeta_transaction_id;
	uint64_t start_lba;
	struct amap_table_list table_list;
	struct index_sync_list index_sync_list;
	struct index_info_list index_info_list;
	struct index_info_list meta_index_info_list;
	struct pgdata_wlist dedupe_list;
	struct amap_sync_list amap_sync_list;
	struct amap_sync_list nowrites_amap_sync_list;
	struct log_info_list log_list;
	struct tcache *read_tcache;
	sx_t *wlist_lock;
	struct tdisk *tdisk;
	struct node_msg *msg;
	struct lba_write *lba_alloc;
	struct lba_write *lba_write;
	int log_reserved;
	int flags;
};

static inline void
write_list_free(struct write_list *wlist)
{
	if (wlist->wlist_lock)
		sx_free(wlist->wlist_lock);
	free(wlist, M_WLIST);
}

static inline void
write_list_init(struct tdisk *tdisk, struct write_list *wlist)
{
	STAILQ_INIT(&wlist->table_list);
	STAILQ_INIT(&wlist->dedupe_list);
	SLIST_INIT(&wlist->index_sync_list);
	TAILQ_INIT(&wlist->index_info_list);
	TAILQ_INIT(&wlist->meta_index_info_list);
	SLIST_INIT(&wlist->amap_sync_list);
	SLIST_INIT(&wlist->nowrites_amap_sync_list);
	SLIST_INIT(&wlist->log_list);
	wlist->wlist_lock = sx_alloc("wlist lock");
	wlist->tdisk = tdisk;
	wlist->transaction_id = 0;
	wlist->newmeta_transaction_id = 0;
}

void tdisk_remove_lba_write(struct tdisk *tdisk, struct lba_write **lba_write);

static inline struct write_list *
write_list_alloc(struct tdisk *tdisk)
{
	struct write_list *wlist;

	wlist = zalloc(sizeof(*wlist), M_WLIST, Q_WAITOK);
	write_list_init(tdisk, wlist);
	return wlist;
}

static inline void
__amap_start_writes(struct amap *amap, struct iowaiter *iowaiter)
{
	atomic_inc(&amap->pending_writes);
	init_iowaiter(iowaiter);
	SLIST_INSERT_HEAD(&amap->io_waiters, iowaiter, w_list);
}

#define amap_start_writes __amap_start_writes

static inline int 
amap_end_writes(struct amap *amap, uint64_t write_id)
{
	int done_io;

	wait_on_chan_check(amap->amap_wait, !atomic_test_bit_short(AMAP_META_DATA_DIRTY, &amap->flags));

	amap_lock(amap);
	if (atomic_dec_and_test(&amap->pending_writes)) {
		atomic_set_bit_short(AMAP_META_IO_PENDING, &amap->flags);
		atomic_clear_bit_short(AMAP_META_IO_NEEDED, &amap->flags);
		amap_io(amap, write_id, QS_IO_WRITE);
		done_io = 1;
	}
	else {
		atomic_set_bit_short(AMAP_META_IO_NEEDED, &amap->flags);
		done_io = 0;
	}
	amap_unlock(amap);
	return done_io;
}

static inline void
amap_end_writes_noio(struct amap *amap, uint64_t write_id)
{
again:
	amap_lock(amap);
	if (atomic_test_bit_short(AMAP_META_IO_NEEDED, &amap->flags) && atomic_test_bit_short(AMAP_META_DATA_DIRTY, &amap->flags)) {
		amap_unlock(amap);
		wait_on_chan(amap->amap_wait, !atomic_test_bit_short(AMAP_META_DATA_DIRTY, &amap->flags));
		goto again;
	}
	if (atomic_dec_and_test(&amap->pending_writes)) {
		if (atomic_test_bit_short(AMAP_META_IO_NEEDED, &amap->flags)) {
			atomic_set_bit_short(AMAP_META_IO_PENDING, &amap->flags);
			atomic_clear_bit_short(AMAP_META_IO_NEEDED, &amap->flags);
			amap_io(amap, write_id, QS_IO_WRITE);
		}
	}
	amap_unlock(amap);
}

#define amap_end_wait(amp, iwaitr)	iowaiter_end_wait((iwaitr))

static inline void
amap_table_start_writes(struct amap_table *amap_table, struct iowaiter *iowaiter)
{
	atomic_inc(&amap_table->pending_writes);
	init_iowaiter(iowaiter);
	SLIST_INSERT_HEAD(&amap_table->io_waiters, iowaiter, w_list);
}

static inline void
amap_table_end_writes(struct amap_table *amap_table)
{
	wait_on_chan_check(amap_table->amap_table_wait, !atomic_test_bit_short(ATABLE_META_DATA_DIRTY, &amap_table->flags));

	amap_table_lock(amap_table);
	if (atomic_dec_and_test(&amap_table->pending_writes)) {
		atomic_set_bit_short(ATABLE_META_IO_PENDING, &amap_table->flags);
		amap_table_io(amap_table, QS_IO_WRITE);
	}
	amap_table_unlock(amap_table);
}

#define amap_table_end_wait(ampt, iwaitr)	iowaiter_end_wait((iwaitr))

static inline void
amap_sync_free(struct amap_sync *amap_sync)
{
	amap_put(amap_sync->amap);
	free_iowaiter(&amap_sync->iowaiter);
	uma_zfree(amap_sync_cache, amap_sync);
}

static inline void
amap_sync_list_free(struct amap_sync_list *sync_list)
{
	struct amap_sync *amap_sync;

	while ((amap_sync = SLIST_FIRST(sync_list)) != NULL) {
		SLIST_REMOVE_HEAD(sync_list, s_list);
		amap_sync_free(amap_sync);
	}
}

struct amap_table * amap_table_locate(struct tdisk *tdisk, uint64_t lba, int *error);
struct amap *amap_locate(struct amap_table *amap_table, uint64_t lba, int *error);
struct tdisk * tdisk_locate(uint16_t target_id);
struct tdisk * tdisk_locate_remove(uint16_t target_id);
struct amap_sync * amap_sync_alloc(struct amap *amap, uint64_t write_id);
void tdisk_reset_stats(uint32_t target_id);
void tdisk_print_stats(struct tdisk *tdisk);
void tdisk_load_amaps(void);
void tdisk_proc_cmd(void *disk, void *iop);

extern atomic_t gpglist_cnt;
extern atomic_t gpglist_need_wait;
extern uint32_t max_pglist_cnt;
extern wait_chan_t *gpglist_wait;

static inline void
pglist_cnt_incr(int transfer_length)
{
#if 0
	while ((atomic_read(&gpglist_cnt) + transfer_length) > max_pglist_cnt) {
		chan_lock(gpglist_wait);
		if ((atomic_read(&gpglist_cnt) + transfer_length) > max_pglist_cnt)  {
			atomic_set(&gpglist_need_wait, 1);
			wait_on_chan_uncond(gpglist_wait);
		}
		chan_unlock(gpglist_wait);
	}
	atomic_add(transfer_length, &gpglist_cnt);
#endif
}

static inline void
pglist_cnt_decr(int transfer_length)
{
#if 0
	debug_check(atomic_read(&gpglist_cnt) < transfer_length);
	atomic_sub(transfer_length, &gpglist_cnt);
	if (atomic_read(&gpglist_need_wait)) {
		chan_lock(gpglist_wait);
		atomic_set(&gpglist_need_wait, 0);
		chan_wakeup_unlocked(gpglist_wait);
		chan_unlock(gpglist_wait);
	}
#endif
}

/* Extended copy definitions */
struct extended_copy_parameter_list {
	uint8_t list_identifier;
	uint8_t priority;
	uint16_t target_descriptor_list_length;
	uint32_t rsvd1;
	uint32_t segment_descriptor_list_length;
	uint32_t inline_data_length;
} __attribute__ ((__packed__));

struct target_descriptor_common {
	uint8_t type_code;
	uint8_t device_type;
	uint16_t rel_init_port;
	uint8_t desc_param[24];
	uint8_t type_param[4];
	int id;
	struct tdisk *tdisk;
	SLIST_ENTRY(target_descriptor_common) t_list;
};

struct segment_descriptor_common {
	uint8_t type_code;
	uint8_t dc;
	uint16_t desc_length;
	uint16_t src_target_index;
	uint16_t dest_target_index;
	uint8_t *desc;
	struct tdisk *dest_tdisk;
	SLIST_ENTRY(segment_descriptor_common) s_list;
};

struct extended_copy {
	SLIST_HEAD(, target_descriptor_common) target_list;
	SLIST_HEAD(, segment_descriptor_common) segment_list;
	SLIST_ENTRY(extended_copy) e_list;
	uint16_t segments_processed;
	uint8_t list_identifier;
	uint8_t copy_status;
	uint32_t transfer_count;
};

struct segment_descriptor_b2b {
	uint16_t reserved;
	uint16_t num_blocks;
	uint64_t src_lba;
	uint64_t dest_lba;
} __attribute__ ((__packed__));

enum {
	COPY_STATUS 		= 0x00,
	RECEIVE_DATA		= 0x01,
	OPERATING_PARAMETERS	= 0x03,
	FAILED_SEGMENT_STATUS	= 0x04,
};

struct copy_status {
	uint32_t avail_data;
	uint8_t copy_status;
	uint16_t segments_processed;
	uint8_t transfer_units_counts;
	uint32_t transfer_count;
} __attribute__ ((__packed__));

struct operating_parameters {
	uint32_t avail_data;
	uint8_t rsvd1[4];
	uint16_t max_target_descriptor_count;
	uint16_t max_segment_descriptor_count;
	uint32_t max_descriptor_list_length;
	uint32_t max_segment_length;
	uint32_t max_inline_data_length;
	uint32_t held_data_limit;
	uint32_t max_stream_device_transfer_size;
	uint8_t rsvd2[4];
	uint8_t max_concurrent_copies;
	uint8_t data_segment_granularity;
	uint8_t inline_data_granularity;
	uint8_t held_data_granularity;
	uint8_t rsvd3[3];
	uint8_t implemented_desc_list_length;
	uint8_t desc_type_codes[2];
} __attribute__ ((__packed__));

static inline int
reached_eom(struct tdisk *tdisk, uint64_t lba, uint32_t transfer_length)
{
	if ((lba >= tdisk->end_lba) || (lba + transfer_length) > tdisk->end_lba)
		return 1;
	else
		return 0;
}

int tdisk_cmd_access_ok(struct tdisk *tdisk, struct qsio_scsiio *ctio);
int tdisk_cmd_test_unit_ready(struct tdisk *tdisk, struct qsio_scsiio *ctio);
int tdisk_cmd_inquiry(struct tdisk *tdisk, struct qsio_scsiio *ctio);
int tdisk_cmd_request_sense(struct tdisk *tdisk, struct qsio_scsiio *ctio);
int tdisk_cmd_read_capacity(struct tdisk *tdisk, struct qsio_scsiio *ctio);
int tdisk_cmd_service_action_in(struct tdisk *tdisk, struct qsio_scsiio *ctio);
int tdisk_cmd_mode_sense6(struct tdisk *tdisk, struct qsio_scsiio *ctio);
int tdisk_cmd_mode_sense10(struct tdisk *tdisk, struct qsio_scsiio *ctio);
int tdisk_cmd_report_luns(struct tdisk *tdisk, struct qsio_scsiio *ctio);
int tdisk_cmd_verify(struct tdisk *tdisk, struct qsio_scsiio *ctio);
int tdisk_cmd_verify12(struct tdisk *tdisk, struct qsio_scsiio *ctio);
int tdisk_cmd_verify16(struct tdisk *tdisk, struct qsio_scsiio *ctio);
int tdisk_cmd_reserve(struct tdisk *tdisk, struct qsio_scsiio *ctio);
int tdisk_cmd_release(struct tdisk *tdisk, struct qsio_scsiio *ctio);
int tdisk_cmd_persistent_reserve_in(struct tdisk *tdisk, struct qsio_scsiio *ctio);
int tdisk_cmd_persistent_reserve_out(struct tdisk *tdisk, struct qsio_scsiio *ctio);
void tdisk_cmd_write_same(struct tdisk *tdisk, struct qsio_scsiio *ctio);
void tdisk_cmd_write_same16(struct tdisk *tdisk, struct qsio_scsiio *ctio);
void tdisk_cmd_unmap(struct tdisk *tdisk, struct qsio_scsiio *ctio);
void tdisk_cmd_extended_copy_read(struct tdisk *tdisk, struct qsio_scsiio *ctio);
int tdisk_cmd_receive_copy_results(struct tdisk *tdisk, struct qsio_scsiio *ctio);
int __tdisk_cmd_ref_int(struct tdisk *tdisk, struct tdisk *dest_tdisk, struct qsio_scsiio *ctio, struct pgdata ***ret_pglist, int *ret_pglist_cnt, uint64_t lba, uint32_t transfer_length, struct index_info_list *index_info_list, int mirror_enabled, int use_refs);
void tdisk_cmd_compare_and_write(struct tdisk *tdisk, struct qsio_scsiio *ctio);
int tdisk_cmd_sync_cache(struct tdisk *tdisk, struct qsio_scsiio *ctio);
int tdisk_cmd_sync_cache16(struct tdisk *tdisk, struct qsio_scsiio *ctio);

int pgdata_alloc_blocks(struct tdisk *tdisk, struct qsio_scsiio *ctio, struct pgdata_wlist *alloc_list, uint32_t size, struct index_info_list *index_info_list, struct lba_write *lba_alloc);
void tdisk_remove_alloc_lba_write(struct lba_write **lba_alloc, wait_chan_t *chan, struct lba_list *lhead);
void sync_amap_list_pre(struct tdisk *tdisk, struct write_list *wlist);
void pgdata_wait_for_amap(struct tdisk *tdisk, struct amap_sync_list *amap_sync_list);
void tdisk_check_alloc_lba_write(struct lba_write *lba_alloc, wait_chan_t *chan, struct lba_list *lhead, int flag);
struct lba_write * tdisk_add_lba_write(struct tdisk *tdisk, uint64_t lba, uint32_t transfer_length, int cw, int dir, int sync_wait);
int scan_write_data(struct tdisk *tdisk, struct qsio_scsiio *ctio, uint64_t lba, struct pgdata **pglist, int pglist_cnt, struct write_list *wlist, struct lba_write **lba_alloc, int remote, int *need_remote_compression, uint64_t amap_counter, int in_xcopy);
void amap_sync_list_free_error(struct amap_sync_list *lhead);
void pgdata_free_amaps(struct pgdata **pglist, int pglist_cnt);
int pgdata_in_read_list(struct tdisk *tdisk, struct pgdata *pgdata, struct pgdata_wlist *read_list, int copy);
int lba_unmapped(struct tdisk *tdisk, uint64_t lba, struct pgdata *pgdata, struct amap_table_list *table_list, struct amap_table *prev_amap_table, struct amap *prev_amap);
int pgdata_check_table_list(struct amap_table_list *table_list, struct index_info_list *meta_index_info_list, struct amap_sync_list *amap_sync_list, int rw, uint64_t write_id);
void tdisk_init(struct tdisk *tdisk);
void tdisk_initialize(struct tdisk *tdisk, char *serialnumber);
struct lba_write * tdisk_add_alloc_lba_write(uint64_t lba_start, wait_chan_t *chan, struct lba_list *lhead, int flags);
void tdisk_update_alloc_lba_write(struct lba_write *lba_alloc, wait_chan_t *chan, int flag);
int tdisk_add_block_ref(struct bdevgroup *group, uint64_t block, struct index_info_list *index_info_list);
struct amap_table * amap_table_load_async(struct tdisk *tdisk, uint64_t block, struct amap_table_group *group, uint32_t group_id, int atable_id);
int amap_table_init(struct tdisk *tdisk, struct amap_table_group *group, int atable_id, struct index_info_list *meta_index_info_list);
struct amap * amap_load_async(struct amap_table *amap_table, uint32_t amap_id, uint32_t amap_idx, uint64_t block);
void amap_clone_check(struct tdisk *src_tdisk, struct amap *src_amap, int isnew);
void amap_table_clone_check(struct tdisk *src_tdisk, struct amap_table *amap_table);

void table_index_write(struct tdisk *tdisk, struct amap_table_index *table_index, uint32_t index_id, uint32_t index_offset, struct amap_table *amap_table);
void pgdata_post_write(struct tdisk *tdisk, struct pgdata **pglist, int pglist_cnt, struct write_list *wlist);
int pgdata_amap_io(struct tdisk *tdisk, struct write_list *wlist);
void ctio_fix_pglist_len(struct qsio_scsiio *ctio);
void verify_ddblocks(struct tdisk *tdisk, struct pgdata_wlist *dedupe_list, struct write_list *wlist, int verify_count, int enable_rcache);
int pgdata_post_read_io(struct pgdata **pglist, int pglist_cnt, struct rcache_entry_list *rcache_list, int enable_rcache, int norefs, int save_comp);
struct amap_table * amap_table_alloc(struct tdisk *tdisk, uint32_t amap_table_id);
struct amap_table * amap_table_load(struct tdisk *tdisk, uint64_t block, struct amap_table_group *group, int atable_id, struct tpriv *priv);
void amap_table_insert(struct amap_table_group *group, struct amap_table *amap_table);
void tdisk_tail_group(struct tdisk *tdisk, struct amap_table_group *group);
int tdisk_load_index(struct tdisk *tdisk, struct tdisk_info *tdisk_info);

static inline int
is_unaligned_write(struct tdisk *tdisk, uint64_t lba, uint32_t transfer_length)
{
	uint32_t size;
	uint64_t lba_diff;

	if (tdisk->lba_shift == LBA_SHIFT)
		return 0;

	size = transfer_length << tdisk->lba_shift;
	lba_diff = (lba - (lba & ~0x7ULL));

	if (!lba_diff && !(size & LBA_MASK))
		return 0;
	else
		return 1;
}

static inline uint64_t
tdisk_get_lba_diff(struct tdisk *tdisk, uint64_t lba)
{
	if (tdisk->lba_shift != LBA_SHIFT) {
		uint64_t lba_diff;
		lba_diff = (lba - (lba & ~0x7ULL));
		return lba_diff;
	}
	else
		return 0;
}
static inline uint64_t
tdisk_get_lba_emulated(struct tdisk *tdisk, uint64_t lba)
{
	if (tdisk->lba_shift != LBA_SHIFT)
		return (lba << 3);
	else
		return lba;
}

static inline uint64_t
tdisk_get_lba_real(struct tdisk *tdisk, uint64_t lba)
{
	if (tdisk->lba_shift != LBA_SHIFT)
		return (lba >> 3);
	else
		return lba;
}
static inline uint32_t 
tdisk_max_amaps(struct tdisk *tdisk)
{
	uint64_t amap_max;
	uint64_t end_lba;

	end_lba = tdisk_get_lba_real(tdisk, tdisk->end_lba);
	amap_max = (end_lba / ((uint64_t)LBAS_PER_AMAP));
	if (end_lba % LBAS_PER_AMAP)
		amap_max++;
	return (uint32_t)(amap_max);
}

/* replication defs */
int tdisk_start_send(struct tdisk *tdisk, struct node_config *config);
int vdisk_clone(struct clone_config *clone_config);
int vdisk_mirror(struct clone_config *clone_config);
int vdisk_delete(struct tdisk *tdisk, uint64_t start_lba);
int __vdisk_mirror(struct clone_config *clone_config, int internal);
int vdisk_clone_status(struct clone_config *cloneconfig);
int vdisk_clone_cancel(struct clone_config *cloneconfig);
int vdisk_mirror_status(struct clone_config *cloneconfig);
int vdisk_mirror_cancel(struct clone_config *cloneconfig);
int vdisk_mirror_remove(struct clone_config *cloneconfig);
int tdisk_sync(struct tdisk *tdisk, int free_alloc);
int __tdisk_sync(struct tdisk *tdisk, int free_alloc);
void tdisk_stop_threads(struct tdisk *tdisk);
void tdisk_stop_delete_thread(struct tdisk *tdisk);
void tdisk_start_resize_thread(struct tdisk *tdisk);
void tdisk_insert(struct tdisk *tdisk, int tl_id, int target_id);
void tdisk_remove(int tl_id, int target_id);
void amap_table_remove(struct amap_table_group *group, struct amap_table *amap_table);
void tdisk_state_reset(struct tdisk *tdisk);
int __tdisk_alloc_amap_groups(struct tdisk *tdisk, uint32_t amap_table_max);
int tdisk_reinitialize_index_reduc(struct tdisk *tdisk, uint64_t new_size);

static inline void
group_tail_amap_table(struct amap_table_group *group, struct amap_table *amap_table)
{
	TAILQ_REMOVE(&group->table_list, amap_table, t_list);
	TAILQ_INSERT_TAIL(&group->table_list, amap_table, t_list);
}

#define __wlist_lock(wlst) sx_xlock((wlst)->wlist_lock)
#define __wlist_unlock(wlst) sx_xunlock((wlst)->wlist_lock)

#define wlist_lock(wlst)			\
do {						\
	if (wlst)				\
		__wlist_lock(wlst);		\
} while (0)

#define wlist_unlock(wlst)			\
do {						\
	if (wlst)				\
		__wlist_unlock(wlst);		\
} while (0)

extern struct tdisk *tdisk_lookup[];

#ifdef FREEBSD 
void tdisk_sync_thread(void *data);
void tdisk_free_thread(void *data);
#else
int tdisk_sync_thread(void *data);
int tdisk_free_thread(void *data);
#endif

void tdisk_write_error(struct tdisk *tdisk, struct qsio_scsiio *ctio, struct write_list *wlist, int ignore_mirror);
void tdisk_write_error_post(struct tdisk *tdisk, struct qsio_scsiio *ctio, struct write_list *wlist);
int check_unaligned_data(struct tdisk *tdisk, struct qsio_scsiio *ctio, uint64_t *ret_lba, uint32_t transfer_length, int cw, int *cw_status, uint32_t *cw_offset, struct write_list *wlist);
int tdisk_lba_write_setup(struct tdisk *tdisk, struct qsio_scsiio *ctio, struct write_list *wlist, uint64_t lba, uint32_t transfer_length, int cw, int sync_wait, uint32_t xchg_id);

static inline uint32_t
tdisk_get_clone_amap_id(struct tdisk *tdisk)
{
	uint32_t ret;

	mtx_lock(tdisk->stats_lock);
	ret = tdisk->clone_amap_id;
	mtx_unlock(tdisk->stats_lock);
	return ret;
}

static inline void
tdisk_reset_clone_amap_id(struct tdisk *tdisk, uint32_t amap_id)
{
	mtx_lock(tdisk->stats_lock);
	tdisk->clone_amap_id = amap_id;
	mtx_unlock(tdisk->stats_lock);
}

static inline void
tdisk_set_clone_amap_id(struct tdisk *tdisk, uint32_t amap_id)
{
	mtx_lock(tdisk->stats_lock);
	if (amap_id >= tdisk->clone_amap_id)
		tdisk->clone_amap_id = amap_id;
	mtx_unlock(tdisk->stats_lock);
}

int tdisk_reinitialize_index(struct tdisk *tdisk, uint64_t new_size, int update_size);
uint64_t tdisk_max_size(struct tdisk *tdisk);
void amap_clone_data(struct clone_data *clone_data);
void amap_mirror_data(struct clone_data *clone_data);
void amap_delete_data(struct clone_data *clone_data);
void amap_resize_data(struct clone_data *clone_data);
static inline int
vdisk_ready(struct tdisk *tdisk)
{
	if (atomic_test_bit(VDISK_DISABLED, &tdisk->flags) || atomic_test_bit(VDISK_IN_DELETE, &tdisk->flags) || !atomic_test_bit(VDISK_ATTACHED, &tdisk->flags))
		return 0;
	else
		return 1;
}
void free_block_refs(struct tdisk *tdisk, struct index_info_list *index_info_list);
void pglist_calc_hash(struct tdisk *tdisk, struct pgdata **pglist, int pglist_cnt, int mirror_enabled, int use_refs);
void check_pending_ddblocks(struct tdisk *tdisk, struct pgdata_wlist *pending_list, struct pgdata_wlist *dedupe_list, struct write_list *wlist, int verify_data, int *verify_count);
struct amap * amap_locate_by_block(uint64_t block, struct amap_sync_list *amap_sync_list);
struct amap_table * amap_table_locate_by_block(uint64_t block, struct amap_sync_list *amap_sync_list);

void wlist_release_log_reserved(struct tdisk *tdisk, struct write_list *wlist);
void pglist_check_free(struct pgdata **pglist, int pglist_cnt, int norefs);

#endif
