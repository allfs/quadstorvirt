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

#include "amap.h"
#include "bdevmgr.h"
#include "tdisk.h"
#include "gdevq.h"
#include "qs_lib.h"
#include "cluster.h"
#include "node_sync.h"
#include "node_ha.h"

void
amap_table_free_amaps(struct amap_table *amap_table)
{
	int i;
	struct amap *amap;
	struct tdisk *tdisk = amap_table->tdisk;

	for (i = 0; i < AMAPS_PER_AMAP_TABLE; i++) {
		amap = amap_table->amap_index[i];
		if (!amap)
			continue;

		amap_table->amap_index[i] = NULL;
		wait_on_chan(amap->amap_wait, !atomic_test_bit_short(AMAP_META_DATA_READ_DIRTY, &amap->flags));
		debug_check(atomic_read(&amap->refs) > 1);
		amap_put(amap);
		debug_check(atomic_read(&tdisk->amap_count) <= 0);
		atomic_dec(&tdisk->amap_count);
	}
}

void
amap_table_free(struct amap_table *amap_table)
{
	wait_on_chan(amap_table->amap_table_wait, !atomic_test_bit_short(ATABLE_META_DATA_READ_DIRTY, &amap_table->flags));
	amap_table_free_amaps(amap_table);

	if (amap_table->write_bmap)
		uma_zfree(write_bmap_cache, amap_table->write_bmap);

	if (amap_table->metadata)
		vm_pg_free(amap_table->metadata);

	uma_zfree(amap_index_cache, amap_table->amap_index);
	sx_free(amap_table->amap_table_lock);
	wait_chan_free(amap_table->amap_table_wait);
	uma_zfree(amap_table_cache, amap_table);
}

void
amap_free(struct amap *amap)
{
#if 0
	debug_check(atomic_test_bit_short(AMAP_META_IO_PENDING, &amap->flags) && !node_in_standby());
	debug_check(atomic_test_bit_short(AMAP_META_DATA_DIRTY, &amap->flags));
#endif
	if (amap->metadata)
		vm_pg_free(amap->metadata);
	wait_chan_free(amap->amap_wait);
	sx_free(amap->amap_lock);
	uma_zfree(amap_cache, amap);
}

#ifdef FREEBSD 
void static amap_table_end_bio(bio_t *bio)
#else
void static amap_table_end_bio(bio_t *bio, int err)
#endif
{
	struct aio_meta *aio_meta = (struct aio_meta *)bio_get_caller(bio);
	struct amap_table *amap_table = (struct amap_table *)aio_meta->priv;
#ifdef FREEBSD
	int err = bio->bio_error;
#endif

	if (unlikely(err))
		atomic_set_bit_short(ATABLE_META_DATA_ERROR, &amap_table->flags);

	if (bio_get_command(bio) == QS_IO_WRITE) {
		complete_io_waiters(&aio_meta->io_waiters_post);
		atomic_clear_bit_short(ATABLE_META_DATA_DIRTY, &amap_table->flags);
	} else {
		atomic_clear_bit_short(ATABLE_META_DATA_READ_DIRTY, &amap_table->flags);
	}

	chan_wakeup(amap_table->amap_table_wait);
	amap_table_put(amap_table);
	bio_free_page(bio);
	g_destroy_bio(bio);
	uma_zfree(aio_meta_cache, aio_meta);
}

#ifdef FREEBSD 
void static amap_end_bio(bio_t *bio)
#else
void static amap_end_bio(bio_t *bio, int err)
#endif
{
	struct aio_meta *aio_meta = (struct aio_meta *)bio_get_caller(bio);
	struct amap *amap = (struct amap *)aio_meta->priv;
#ifdef FREEBSD
	int err = bio->bio_error;
#endif

	if (unlikely(err))
		atomic_set_bit_short(AMAP_META_DATA_ERROR, &amap->flags);

	if (bio_get_command(bio) == QS_IO_WRITE) {
		complete_io_waiters(&aio_meta->io_waiters_post);
		atomic_clear_bit_short(AMAP_META_DATA_DIRTY, &amap->flags);
	}
	else {
		atomic_clear_bit_short(AMAP_META_DATA_READ_DIRTY, &amap->flags);
	}

	chan_wakeup(amap->amap_wait);
	amap_put(amap);
	bio_free_page(bio);
	g_destroy_bio(bio);
	uma_zfree(aio_meta_cache, aio_meta);
}

static inline void
amap_table_write_csum(struct amap_table *amap_table)
{
	uint64_t csum;
	struct raw_amap_table *raw_amap_table;

	raw_amap_table = (struct raw_amap_table *)(((uint8_t *)vm_pg_address(amap_table->metadata)) + RAW_AMAP_TABLE_OFFSET);
	if (is_v2_tdisk(amap_table->tdisk)) {
		csum = calc_csum16(vm_pg_address(amap_table->metadata), AMAP_TABLE_SIZE - sizeof(uint64_t));
		raw_amap_table->csum &= ~0xFFFFULL;
		raw_amap_table->csum |= csum;
	}
	else {
		csum = calc_csum(vm_pg_address(amap_table->metadata), AMAP_TABLE_SIZE - sizeof(uint64_t));
		raw_amap_table->csum = csum;
	}
}

int
amap_table_io(struct amap_table *amap_table, int rw)
{
	int retval;
	struct aio_meta *aio_meta;

	if (rw == QS_IO_WRITE) {
		debug_check(atomic_test_bit_short(ATABLE_META_DATA_DIRTY, &amap_table->flags));
		amap_table_write_csum(amap_table);
		node_amap_table_sync_send(amap_table);
		atomic_set_bit_short(ATABLE_META_DATA_DIRTY, &amap_table->flags);
		atomic_clear_bit_short(ATABLE_META_IO_PENDING, &amap_table->flags);
		atomic_clear_bit_short(ATABLE_META_DATA_CLONED, &amap_table->flags);
		TDISK_INC(amap_table->tdisk, amap_table_writes, 1);
	}
	else {
		atomic_set_bit_short(ATABLE_META_DATA_READ_DIRTY, &amap_table->flags);
		TDISK_INC(amap_table->tdisk, amap_table_reads, 1);
	}

	aio_meta = __uma_zalloc(aio_meta_cache, Q_WAITOK, sizeof(*aio_meta)); 
	aio_meta->priv = amap_table;
	SLIST_INIT(&aio_meta->io_waiters_post);

	iowaiters_move(&aio_meta->io_waiters_post, &amap_table->io_waiters); 
	amap_table_get(amap_table);

	retval = qs_lib_bio_page(amap_table_bint(amap_table), amap_table_bstart(amap_table), AMAP_TABLE_SIZE, amap_table->metadata, amap_table_end_bio, aio_meta, rw, TYPE_AMAP_TABLE);
	if (unlikely(retval != 0)) {
		debug_warn("Failed to load amap table at %llu bid %u\n", (unsigned long long)amap_table_bstart(amap_table), amap_table_bint(amap_table)->bid);
		atomic_clear_bit_short(ATABLE_META_DATA_DIRTY, &amap_table->flags);
		atomic_clear_bit_short(ATABLE_META_DATA_READ_DIRTY, &amap_table->flags);
		atomic_set_bit_short(ATABLE_META_DATA_ERROR, &amap_table->flags);
		complete_io_waiters(&aio_meta->io_waiters_post);
		chan_wakeup(amap_table->amap_table_wait);
		amap_table_put(amap_table);
		uma_zfree(aio_meta_cache, aio_meta);
	}
	return retval;
}

atomic_t write_id_skip;

void
mirror_clear_write_id_skip(void)
{
	mtx_lock(glbl_lock);
	atomic_set(&write_id_skip, 0);
	mtx_unlock(glbl_lock);

}

void
mirror_set_write_id_skip(void)
{
	mtx_lock(glbl_lock);
	if (!atomic_read(&write_id_skip))
		atomic_set(&write_id_skip, (MAX_GDEVQ_THREADS * 4));
	mtx_unlock(glbl_lock);
}

static uint32_t
mirror_get_write_id_skip(void)
{
	uint32_t ret;

	if (!atomic_read(&write_id_skip))
		return 1;

	mtx_lock(glbl_lock);
	ret = atomic_read(&write_id_skip);
	if (ret)
		atomic_set(&write_id_skip, 0);
	else
		ret = 1;
	mtx_unlock(glbl_lock);
	return ret;
}

static inline void
amap_write_csum(struct amap *amap, uint64_t write_id)
{
	uint64_t csum;
	struct raw_amap *raw_amap;

	raw_amap = (struct raw_amap *)(((uint8_t *)vm_pg_address(amap->metadata)) + RAW_AMAP_OFFSET);
	if (is_v2_tdisk(amap->amap_table->tdisk)) {
		csum = calc_csum16(vm_pg_address(amap->metadata), AMAP_SIZE - sizeof(uint64_t));
		if (!write_id)
			write_id = write_id_incr(amap->write_id, mirror_get_write_id_skip());
		else if (write_id == WRITE_ID_MAX)
			write_id = amap->write_id;
		csum |= (write_id << 16);
	}
	else {
		write_id = write_id_incr(amap->write_id, mirror_get_write_id_skip());
		csum = calc_csum(vm_pg_address(amap->metadata), AMAP_SIZE - sizeof(uint64_t));
	}
	amap->write_id = write_id;
	raw_amap->csum = csum;
}

int
amap_io(struct amap *amap, uint64_t write_id, int rw)
{
	int retval;
	struct aio_meta *aio_meta;

	if (rw == QS_IO_WRITE) {
		debug_check(atomic_test_bit_short(AMAP_META_DATA_DIRTY, &amap->flags));
		TDISK_INC(amap->amap_table->tdisk, amap_writes, 1);
		amap_write_csum(amap, write_id);
		node_amap_sync_send(amap);
		atomic_set_bit_short(AMAP_META_DATA_DIRTY, &amap->flags);
		atomic_clear_bit_short(AMAP_META_IO_PENDING, &amap->flags);
		atomic_clear_bit_short(AMAP_META_DATA_CLONED, &amap->flags);
	}
	else {
		atomic_set_bit_short(AMAP_META_DATA_READ_DIRTY, &amap->flags);
		TDISK_INC(amap->amap_table->tdisk, amap_reads, 1);
	}

	mark_io_waiters(&amap->io_waiters);

	aio_meta = __uma_zalloc(aio_meta_cache, Q_WAITOK, sizeof(*aio_meta)); 
	aio_meta->priv = amap;
	SLIST_INIT(&aio_meta->io_waiters_post);
	iowaiters_move(&aio_meta->io_waiters_post, &amap->io_waiters); 

	amap_get(amap);

	retval = qs_lib_bio_page(amap_bint(amap), amap_bstart(amap), AMAP_SIZE, amap->metadata, amap_end_bio, aio_meta, rw, TYPE_AMAP);
	if (unlikely(retval != 0)) {
		debug_warn("Failed to load amap at %llu bid %u\n", (unsigned long long)amap_bstart(amap), amap_bint(amap)->bid);
		atomic_clear_bit_short(AMAP_META_DATA_DIRTY, &amap->flags);
		atomic_clear_bit_short(AMAP_META_DATA_READ_DIRTY, &amap->flags);
		atomic_set_bit_short(AMAP_META_DATA_ERROR, &amap->flags);
		complete_io_waiters(&aio_meta->io_waiters_post);
		chan_wakeup(amap->amap_wait);
		amap_put(amap);
		uma_zfree(aio_meta_cache, aio_meta);
	}
	return retval;
}

extern uint32_t cached_amaps;

void
amap_insert(struct amap_table *amap_table, struct amap *amap, uint32_t amap_idx)
{
	struct tdisk *tdisk = amap_table->tdisk;

	debug_check(amap_table->amap_index[amap_idx]);
	amap_table->amap_index[amap_idx] = amap;
	atomic_inc(&tdisk->amap_count);
	if (atomic_read(&tdisk->amap_count) > cached_amaps) {
		atomic_set_bit(VDISK_FREE_START, &tdisk->flags);
		chan_wakeup_one_nointr(tdisk->free_wait);
	}
}

struct amap *
amap_alloc(struct amap_table *amap_table, uint32_t amap_id, uint32_t amap_idx)
{
	struct amap *amap;

	amap = __uma_zalloc(amap_cache, Q_NOWAIT | Q_ZERO, sizeof(*amap));
	if (unlikely(!amap)) {
		debug_warn("Memory allocation failure\n");
		return NULL;
	}

	amap->amap_wait = wait_chan_alloc("amap wait");
	amap->amap_lock = sx_alloc("amap lock");
	SLIST_INIT(&amap->io_waiters);
	atomic_set(&amap->refs, 1);

	amap->amap_id = amap_id;
	amap->amap_idx = amap_idx;
	amap->amap_table = amap_table;
	return amap;
}

struct amap *
amap_load(struct amap_table *amap_table, uint32_t amap_id, uint32_t amap_idx, uint64_t block, struct tpriv *priv)
{
	struct amap *amap;
	int retval;

	amap = amap_alloc(amap_table, amap_id, amap_idx);
	if (unlikely(!amap))
		return NULL;

	amap->metadata = vm_pg_alloc(0);
	if (unlikely(!amap->metadata)) {
		amap_put(amap);
		return NULL;
	}

	amap->amap_block = block;
	if (unlikely(!amap_bint(amap))) {
		debug_warn("Cannot find bint at %u\n", BLOCK_BID(block));
		amap_put(amap);
		return NULL;
	}

	if (priv)
		bdev_marker(amap_bint(amap)->b_dev, priv);
	retval = amap_io(amap, 0, QS_IO_READ);
	if (unlikely(retval != 0)) {
		if (priv && priv->data)
			bdev_start(amap_bint(amap)->b_dev, priv);
		amap_put(amap);
		return NULL;
	}

	amap_insert(amap_table, amap, amap_idx);
	return amap;
}

struct amap *
amap_new(struct amap_table *amap_table, uint32_t amap_id, uint32_t amap_idx, struct index_info_list *index_info_list, int *error)
{
	struct amap *amap;
	uint64_t b_start;
	struct bdevint *bint;
	struct index_info *index_info;
#ifdef ENABLE_STATS
	uint32_t start_ticks;
#endif

	*error = -1;
	index_info = index_info_alloc();
	if (unlikely(!index_info))
		return NULL;

	amap = amap_alloc(amap_table, amap_id, amap_idx);
	if (unlikely(!amap)) {
		index_info_free(index_info);
		return NULL;
	}

	amap->metadata = vm_pg_alloc(VM_ALLOC_ZERO);
	if (unlikely(!amap->metadata)) {
		index_info_free(index_info);
		amap_put(amap);
		return NULL;
	}

	TDISK_TSTART(start_ticks);
	b_start = bdev_alloc_block(amap_table->tdisk->group, AMAP_SIZE, &bint, index_info, TYPE_META_BLOCK);
	TDISK_TEND(amap_table->tdisk, amap_alloc_block_ticks, start_ticks);

	if (unlikely(!b_start)) {
		debug_warn("Allocating a new amap block failed for %s\n", tdisk_name(amap_table->tdisk));
		amap_put(amap);
		index_info_free(index_info);
		*error = ERR_CODE_NOSPACE;
		pause("outofspc", OUT_OF_SPACE_PAUSE);
		return NULL;
	}

	index_info->b_start = b_start; 
	index_info->meta_type = INDEX_INFO_TYPE_AMAP;
	TAILQ_INSERT_TAIL(index_info_list, index_info, i_list);

	amap->write_id = 1;
	SET_BLOCK(amap->amap_block, b_start, bint->bid);
	atomic_set_bit_short(AMAP_META_IO_PENDING, &amap->flags);
	atomic_set_bit_short(AMAP_META_DATA_NEW, &amap->flags);
	atomic_set_bit_short(AMAP_CSUM_CHECK_DONE, &amap->flags);

	amap_insert(amap_table, amap, amap_idx);
	return amap;
}
