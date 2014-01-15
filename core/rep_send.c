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

#include "cluster.h"
#include "tdisk.h"
#include "tcache.h"
#include "rcache.h"
#include "gdevq.h"
#include "../common/cluster_common.h" 
#include "node_sock.h"
#include "vdevdefs.h"
#include "node_mirror.h"

extern struct clone_info_list clone_info_list;

int
rep_client_sock_init(struct node_comm *comm, int sock_count)
{
	int i, retval = 0;

	for (i = 0; i < sock_count; i++) {
		retval = node_sock_connect(comm, node_client_recv, RECEIVER_DATA_PORT, "ndsockr");
		if (unlikely(retval != 0)) {
			debug_warn("Connect to remote peer failed for sock %d\n", i);
			break;
		}
		if (i && (i % 16) == 0)
			pause("psg", 150);
	}
	return retval;
}

static int
node_resp_status(struct node_msg *msg, struct node_sock *sock)
{
	struct node_msg *resp;
	struct raw_node_msg *raw;

	resp = msg->resp;

	if (unlikely(!resp)) {
		debug_warn("Failed to recv resp for msg id %llx cmd %x\n", (unsigned long long)msg->raw->msg_id, msg->raw->msg_cmd);
		return -1;
	}

	raw = resp->raw;
	if (raw->msg_status == NODE_STATUS_OK)
		return 0;

	switch (raw->msg_status) {
	case NODE_STATUS_AMAP_NOT_FOUND:
	case NODE_STATUS_AMAP_NEEDS_SYNC:
		return 0;

	case NODE_STATUS_TARGET_NOT_FOUND:
	case NODE_STATUS_INVALID_MSG:
	case NODE_STATUS_UNREGISTERED_NODE:
	case NODE_STATUS_MEM_ALLOC_FAILURE:
		node_sock_read_error(sock);
	case NODE_STATUS_SCSI_SENSE:
	case NODE_STATUS_ERROR:
	default:
		return -1;
	}
	debug_warn("For msg id %llx cmd %x received status %x\n", (unsigned long long)msg->raw->msg_id, msg->raw->msg_cmd, raw->msg_status);
	return -1;
}

static int
amap_setup_read(struct clone_data *clone_data, struct tdisk *tdisk, pagestruct_t *metadata, struct pgdata ***ret_pglist, uint64_t lba, int pglist_cnt)
{
	struct pgdata **pglist, *pgtmp;
	struct tcache *tcache;
	struct pgdata_wlist read_list;
	struct lba_write *lba_alloc;
	struct amap_table_list table_list;
	struct bdevint *prev_bint = NULL, *bint;
	struct rcache_entry_list rcache_list;
	int i, retval;

	STAILQ_INIT(&read_list);
	STAILQ_INIT(&table_list);
	TAILQ_INIT(&rcache_list);

	pglist = pgdata_allocate_nopage(pglist_cnt, Q_NOWAIT);
	if (unlikely(!pglist)) {
		debug_warn("Memory allocation for pglist cnt %d\n", pglist_cnt);
		return -1;
	}

	tcache = tcache_alloc(pglist_cnt);
	lba_alloc = tdisk_add_alloc_lba_write(lba, tdisk->lba_read_wait, &tdisk->lba_read_list, 0);
	for (i = 0; i < pglist_cnt; i++, lba++) {
		pgtmp =  pglist[i];
		pgtmp->lba = lba;
		pgtmp->amap_block = amap_metadata_get_block(metadata, i);
		if (!pgtmp->amap_block) {
			atomic_set_bit(DDBLOCK_ZERO_BLOCK, &pgtmp->flags);
			continue;
		}

		JOB_STATS_ADD(clone_data, mapped_blocks, 1);
		if (!prev_bint || (prev_bint->bid != BLOCK_BID(pgtmp->amap_block))) {
			bint = bdev_find(BLOCK_BID(pgtmp->amap_block));
			if (unlikely(!bint)) {
				debug_warn("Cannot locate bint at bid %u\n", BLOCK_BID(pgtmp->amap_block));
				goto err;
			}
			prev_bint = bint;
		}
		else {
			bint = prev_bint;
		}

		if (pgdata_in_read_list(tdisk, pgtmp, &read_list, 0))
			continue;

		if (rcache_locate(pgtmp, 0))
			continue;

		retval = pgdata_alloc_page(pgtmp, 0);
		if (unlikely(retval != 0)) {
			debug_warn("allocating for pgdata page failed\n");
			goto err;
		}

		JOB_STATS_ADD(clone_data, blocks_read, 1);
		JOB_STATS_ADD(clone_data, bytes_read, lba_block_size(pgtmp->amap_block));
		retval = tcache_add_page(tcache, pgtmp->page, BLOCK_BLOCKNR(pgtmp->amap_block), bint, lba_block_size(pgtmp->amap_block), QS_IO_READ);
		if (unlikely(retval != 0)) {
			debug_warn("Failed to add page to tcache\n");
			goto err;
		}

	}

	if (atomic_read(&tcache->bio_remain)) {
		tdisk_check_alloc_lba_write(lba_alloc, tdisk->lba_read_wait, &tdisk->lba_read_list, LBA_WRITE_DONE_IO);
		tcache_entry_rw(tcache, QS_IO_READ);
		tdisk_update_alloc_lba_write(lba_alloc, tdisk->lba_read_wait, LBA_WRITE_DONE_IO);
		wait_for_done(tcache->completion);
	}

	tdisk_remove_alloc_lba_write(&lba_alloc, tdisk->lba_read_wait, &tdisk->lba_read_list);
	if (atomic_test_bit_short(TCACHE_IO_ERROR, &tcache->flags)) {
		debug_warn("tcache read io error\n");
		goto err;
	}
	tcache_read_comp(tcache);

	retval = pgdata_post_read_io(pglist, pglist_cnt, &rcache_list, 1, 0, 0);
	if (unlikely(retval != 0)) {
		debug_warn("pgdata post read io failed\n");
		goto err;
	}

	rcache_list_insert(&rcache_list);
	tcache_put(tcache);
	*ret_pglist = pglist;
	return 0;
err:
	tdisk_remove_alloc_lba_write(&lba_alloc, tdisk->lba_read_wait, &tdisk->lba_read_list);
	rcache_list_free(&rcache_list);
	tcache_put(tcache);
	pglist_free(pglist, pglist_cnt);
	return -1;
}

int
node_send_write_io(struct clone_data *clone_data, struct qsio_scsiio *ctio, struct node_comm *comm, struct node_sock *sock, struct node_msg *msg, struct pgdata **pglist, int pglist_cnt, int timeout, int async)
{
	struct pgdata_read_spec *source_spec;
	struct pgdata *pgtmp;
	int i, retval, need_remote_io = 0;

	source_spec = pgdata_read_spec_ptr(msg->raw);
	for (i = 0; i < pglist_cnt; i++, source_spec++) {
		pgtmp = pglist[i];

		if (!source_spec->amap_block)
			continue;

		if (atomic_test_bit_short(DDBLOCK_ENTRY_FOUND_DUPLICATE, &source_spec->flags)) {
			if (clone_data)
				JOB_STATS_ADD(clone_data, deduped_blocks, 1);
			continue;
		}

		if (clone_data) {
			JOB_STATS_ADD(clone_data, blocks_written, 1);
			JOB_STATS_ADD(clone_data, bytes_written, lba_block_size(source_spec->amap_block));
		}
		atomic_set_bit(PGDATA_NEED_REMOTE_IO, &pgtmp->flags);
		need_remote_io++;
	}

	debug_check(!need_remote_io);
	retval = node_cmd_remote_write_io(comm, sock, ctio, msg,  pglist, pglist_cnt, timeout, async);
	if (unlikely(retval != 0)) {
		debug_warn("remote write io failed\n");
	}

	return retval;
}

static int 
amap_mirror(struct clone_data *clone_data, struct tdisk *tdisk, struct amap *amap, struct node_comm *comm, uint32_t dest_target_id)
{
	struct node_sock *sock;
	struct amap_spec *amap_spec;
	uint64_t lba;
	int error = 0, retval;
	pagestruct_t *metadata;
	struct node_msg *msg = NULL;
	struct raw_node_msg *raw;
	struct qsio_scsiio *ctio = NULL;
	struct pgdata **pglist = NULL, *pgdata;
	struct lba_write *read_lba_write = NULL;
	uint64_t end_lba, read_lba;
	int pglist_cnt;
	int enable_deduplication = tdisk->enable_deduplication;
	uint32_t transfer_length;
	int dxfer_len, i;
	int timeout = recv_config.mirror_connect_timeout ? recv_config.mirror_connect_timeout : NODE_GET_SOCK_TIMEOUT; 

	uint32_t start_ticks;

	lba = amap_get_lba_start(amap->amap_id);
	pglist_cnt = LBAS_PER_AMAP;
	end_lba = tdisk_get_lba_real(tdisk, tdisk->end_lba);

	if ((lba + pglist_cnt) > end_lba)
		pglist_cnt = end_lba - lba;
	debug_check(!pglist_cnt);

	if (tdisk->lba_shift != LBA_SHIFT) {
		read_lba = lba << 3;
		transfer_length = pglist_cnt << 3;
	}
	else {
		read_lba = lba;
		transfer_length = pglist_cnt;
	}

	read_lba_write = tdisk_add_lba_write(tdisk, read_lba, transfer_length, 0, QS_IO_WRITE, 0);
	tdisk_set_clone_amap_id(tdisk, amap->amap_id);

	sock = node_comm_get_sock(comm, timeout); /* waits till a sock is free */
	if (unlikely(!sock)) {
		debug_warn("Cannot get a node sock for amap %u\n", amap->amap_id);
		tdisk_remove_lba_write(tdisk, &read_lba_write);
		return -1;
	}

	metadata = vm_pg_alloc(0);
	if (unlikely(!metadata)) {
		debug_warn("Metadata allocation failure for amap %u\n", amap->amap_id);
		tdisk_remove_lba_write(tdisk, &read_lba_write);
		node_sock_finish(sock);
		return -1;
	}

	amap_lock(amap);
	amap_check_csum(amap);
	if (atomic_test_bit_short(AMAP_META_DATA_ERROR, &amap->flags)) {
		debug_warn("loading amap failed for amap %u\n", amap->amap_id);
		amap_unlock(amap);
		error = -1;
		goto out;
	}

	debug_info("amap id %u write id %llu\n", amap->amap_id, (unsigned long long)amap->write_id);
	memcpy(vm_pg_address(metadata), vm_pg_address(amap->metadata), AMAP_SIZE);
	atomic_set_bit_short(AMAP_META_DATA_BUSY, &amap->flags);
	amap_unlock(amap);

	msg = node_msg_alloc(sizeof(*amap_spec));
	bzero(msg->raw, sizeof(*amap_spec) + sizeof(*raw));
	amap_spec = amap_spec_ptr(msg->raw);
	amap_spec->lba = lba;
	amap_spec->write_id = amap->write_id;

	msg->mirror = 1;
	msg->raw->dxfer_len = sizeof(*amap_spec);
	msg->raw->msg_cmd = NODE_MSG_AMAP_CHECK;
	msg->raw->msg_id = node_transaction_id();
	msg->raw->target_id = dest_target_id;
	retval = node_send_msg(sock, msg, msg->raw->msg_id, 1);
	if (unlikely(retval != 0)) {
		debug_warn("Communicating with remote failed for amap %u\n", amap->amap_id);
		error = -1;
		goto out;
	}

	node_msg_wait(msg, sock, mirror_send_timeout);
	retval = node_resp_status(msg, sock);
	if (unlikely(retval != 0)) {
		debug_warn("Failed to get a response from remote\n");
		error = -1;
		goto out;
	}

	if (msg->resp->raw->msg_status == NODE_STATUS_OK) { /* No need to sync */
		error = 0;
		goto out;
	}

	start_ticks = ticks;
	retval = amap_setup_read(clone_data, tdisk, metadata, &pglist, lba, pglist_cnt);
	JOB_STATS_ADD32(clone_data, read_msecs, ticks_to_msecs(get_elapsed(start_ticks)));
	if (unlikely(retval != 0)) {
		debug_warn("amap setup read failed for lba %llu\n", (unsigned long long)lba);
		error = -1;
		goto out;
	}

	start_ticks = ticks;
	chan_lock(devq_write_wait);
	for (i = 0; i < pglist_cnt; i++) {
		pgdata = pglist[i];
		if (!pgdata->amap_block) {
			wait_complete_all(pgdata->completion);
			continue;
		}

		if (enable_deduplication)
			STAILQ_INSERT_TAIL(&pending_write_queue, pgdata, w_list);
		else {
			atomic_set_bit(DDBLOCK_DEDUPE_DISABLED, &pgdata->flags);
			wait_complete_all(pgdata->completion);
		}
	}
	if (enable_deduplication) {
		chan_wakeup_unlocked(devq_write_wait);
	}
	chan_unlock(devq_write_wait);

	wait_for_pgdata(pglist, pglist_cnt);
	JOB_STATS_ADD32(clone_data, hash_compute_msecs, ticks_to_msecs(get_elapsed(start_ticks)));

	start_ticks = ticks;
	ctio = ctio_new(Q_NOWAIT);
	if (unlikely(!ctio)) {
		debug_warn("Allocating a new ctio failed\n");
		pglist_free(pglist, pglist_cnt);
		error = -1;
		goto out;
	}
	ctio->task_attr = MSG_SIMPLE_TASK;
	ctio->pglist_cnt = pglist_cnt;
	ctio->data_ptr = (void *)pglist;
	ctio->dxfer_len = (pglist_cnt << LBA_SHIFT);
	ctio->init_int = TARGET_INT_MIRROR;
	ctio->i_prt[0] = comm->controller_ipaddr;
	ctio->t_prt[0] = comm->node_ipaddr;

	transfer_length = pglist_cnt;
	if (tdisk->lba_shift != LBA_SHIFT) {
		lba <<= 3;
		transfer_length <<= 3;
	}

	dxfer_len = sizeof(struct scsi_cmd_spec) + sizeof(struct pgdata_spec) * ctio->pglist_cnt;
	node_msg_free(msg);
	msg = node_msg_alloc(dxfer_len);
	raw = msg->raw;
	bzero(raw, dxfer_len + sizeof(*raw));
	raw->target_id = dest_target_id;
	raw->dxfer_len = dxfer_len;
	raw->msg_id = node_transaction_id();
	msg->mirror = 1;

	retval = node_write_setup(comm, sock, msg, ctio, lba, transfer_length, amap->write_id, 0, mirror_send_timeout, NODE_MSG_WRITE_MIRROR_CMD);
	if (unlikely(retval != 0)) {
		debug_warn("node write setup failed for lba %llu retval %d\n", (unsigned long long)lba, retval);
		error = -1;
		goto out;
	}

	if (node_cmd_status(msg) == NODE_CMD_NEED_VERIFY) {
		retval = node_verify_setup(comm, sock, msg, ctio, mirror_send_timeout, 0);
		if (unlikely(retval != 0)) {
			debug_warn("node verify setup failed for lba %llu\n", (unsigned long long)lba);
			error = -1;
			goto out;
		}
	}

	if (node_cmd_status(msg) == NODE_CMD_NEED_COMP) {
		retval = node_comp_setup(comm, sock, msg, ctio, mirror_send_timeout, 0);
		if (unlikely(retval != 0)) {
			debug_warn("node comp setup failed for lba %llu\n", (unsigned long long)lba);
			error = -1;
			goto out;
		}
	}

	if (node_cmd_status(msg) == NODE_CMD_NEED_IO) {
		retval = node_send_write_io(clone_data, ctio, comm, sock, msg, pglist, pglist_cnt, mirror_send_timeout, 0);
		if (unlikely(retval != 0)) {
			debug_warn("node send write io failed for lba %llu\n", (unsigned long long)lba);
			error = -1;
			goto out;
		}
	}
	else {
		JOB_STATS_ADD(clone_data, deduped_blocks, clone_data->stats.mapped_blocks);
	}

	node_cmd_write_done(ctio, comm, sock, msg, mirror_send_timeout);
	JOB_STATS_ADD32(clone_data, write_msecs, ticks_to_msecs(get_elapsed(start_ticks)));

out:
	tdisk_remove_lba_write(tdisk, &read_lba_write);

	node_sock_finish(sock);
	if (ctio) {
		ctio_pglist_cleanup(ctio);
		ctio_free(ctio);
	}
	if (msg)
		node_msg_free(msg);
	vm_pg_free(metadata);
	return error;
}

void
amap_mirror_data(struct clone_data *clone_data)
{
	struct clone_info *clone_info;
	struct amap *amap;
	struct tdisk *tdisk;
	int retval;

 	amap = clone_data->amap;
	tdisk = amap->amap_table->tdisk;
	clone_info = tdisk->clone_info;
	debug_check(!clone_info);
	debug_check(!clone_info->comm);
	retval = amap_mirror(clone_data, tdisk, amap, clone_info->comm, clone_info->dest_target_id);

	if (atomic_test_bit_short(AMAP_META_DATA_BUSY, &amap->flags)) {
		atomic_clear_bit_short(AMAP_META_DATA_BUSY, &amap->flags);
		chan_wakeup_nointr(amap->amap_wait);
	}

	if (retval != 0)	
		tdisk_set_mirror_error(tdisk);
	wait_complete_all(clone_data->completion);
}

static int
amap_write_bmap_check(struct tdisk *tdisk, struct amap_table *amap_table, int idx)
{
	struct mirror_state *mirror_state;
	struct write_bmap *write_bmap;
	int i, j;

	if (atomic_test_bit_short(ATABLE_WRITE_BMAP_INVALID, &amap_table->flags))
		return 0;

	mirror_state = &tdisk->mirror_state;
	if (!atomic_test_bit(MIRROR_FLAGS_WRITE_BITMAP_VALID, &mirror_state->mirror_flags))
		return 0;

	write_bmap = amap_table->write_bmap;
	if (!write_bmap)
		return 1;

	i = idx / 8;
	j = idx % 8; 
	if (!(write_bmap->bmap[i] & (1 << j)))
		return 1;
	else
		return 0;
}

static int
amap_table_mirror(struct clone_info *clone_info, struct tdisk *tdisk, struct amap_table *amap_table, uint32_t group_id)
{
	struct amap *amap;
	uint64_t block;
	struct clone_data *clone_data;
	struct amap_group_bitmap *bmap = NULL;
	pagestruct_t *metadata;
	uint32_t amap_id, bmap_group_offset;
	uint32_t amap_max, todo;
	int i, set;
	int done = 0, error, retval;

	amap_id = amap_table->amap_table_id * AMAPS_PER_AMAP_TABLE;
	amap_max = tdisk_max_amaps(tdisk);
	todo = min_t(uint32_t, AMAPS_PER_AMAP_TABLE, amap_max - amap_id);

	for (i = 0; i < todo; i++, amap_id++) {
		if (tdisk_in_sync(tdisk)) {
			tdisk_bmap_lock(tdisk);
			retval = amap_write_bmap_check(tdisk, amap_table, i);
			tdisk_bmap_unlock(tdisk);
			if (retval) {
				tdisk_set_clone_amap_id(tdisk, amap_id);
				continue;
			}
		}

		metadata = vm_pg_alloc(0);
		if (unlikely(!metadata)) {
			tdisk_set_mirror_error(tdisk);
			debug_warn("page allocation failure\n");
			return -1;
		}

		amap_table_lock(amap_table);
		amap = amap_table->amap_index[i];
		if (!amap) {
			block = get_amap_block(amap_table, i);
			if (!block) {
				amap_table_unlock(amap_table);
				tdisk_set_clone_amap_id(tdisk, amap_id);
				vm_pg_free(metadata);
				continue;
			}

			amap = amap_load_async(amap_table, amap_id, i, block);
			if (unlikely(!amap)) {
				amap_table_unlock(amap_table);
				tdisk_set_mirror_error(tdisk);
				vm_pg_free(metadata);
				debug_warn("Cannot load amap at amap_id %u block %llu\n", amap_id, (unsigned long long)block);
				return -1;
			}
		}

		amap_get(amap);
		amap_table_unlock(amap_table);

		wait_on_chan_check(amap->amap_wait, !atomic_test_bit_short(AMAP_META_DATA_READ_DIRTY, &amap->flags));
		if (atomic_test_bit_short(AMAP_META_DATA_ERROR, &amap->flags)) {
			tdisk_set_mirror_error(tdisk);
			amap_put(amap);
			vm_pg_free(metadata);
			debug_warn("Metadata error for amap at amap_id %u\n", amap_id);
			return -1;
		}

		if (tdisk_in_sync(tdisk))
			goto skip_bmap_check;

		bmap_group_offset = amap_bitmap_group_offset(amap_id);
		tdisk_bmap_lock(tdisk);
		if (!bmap || bmap_group_offset != bmap->group_offset) {
			bmap = amap_group_bmap_locate(tdisk, group_id, bmap_group_offset, &error);
			if (unlikely(!bmap)) {
				tdisk_set_mirror_error(tdisk);
				tdisk_bmap_unlock(tdisk);
				amap_put(amap);
				debug_warn("Cannot get bmap for %i group offset %u\n", group_id, bmap_group_offset);
				vm_pg_free(metadata);
				return -1;
			}
		}

		set = bmap_bit_is_set(bmap, amap_to_bitmap_offset(amap_id));
		tdisk_bmap_unlock(tdisk);
		if (set) {
			tdisk_set_clone_amap_id(tdisk, amap_id);
			amap_put(amap);
			vm_pg_free(metadata);
			continue;
		}
skip_bmap_check:
		memcpy(vm_pg_address(metadata), vm_pg_address(amap->metadata), AMAP_SIZE); 
		atomic_set_bit_short(AMAP_META_DATA_BUSY, &amap->flags);

		amap_table_get(amap_table);
		clone_data = clone_data_alloc(CLONE_DATA_MIRROR);
		clone_data->amap = amap;
		clone_data->metadata = metadata;
		clone_data_insert(clone_data, &tdisk->clone_list);

		done++;
		if (done == MAX_AMAP_MIRROR_THREADS) {
			clone_list_wait(clone_info, tdisk);
			done = 0;
			if (tdisk_mirror_error(tdisk)) {
				debug_warn("clone list wait, tdisk mirror error\n");
				return -1;
			}
		}
	}

	clone_list_wait(clone_info, tdisk);
	if (tdisk_mirror_error(tdisk))
		debug_warn("clone list wait, tdisk mirror error\n");
	return tdisk_mirror_error(tdisk);
}

static int
amap_table_write_bmap_check(struct tdisk *tdisk, struct amap_table_group *group, int idx)
{
	struct mirror_state *mirror_state;
	struct group_write_bmap *group_write_bmap;
	int i, j;

	mirror_state = &tdisk->mirror_state;
	if (!atomic_test_bit(MIRROR_FLAGS_WRITE_BITMAP_VALID, &mirror_state->mirror_flags))
		return 0;

	group_write_bmap = group->group_write_bmap;
	if (!group_write_bmap)
		return 1;

	i = idx / 8;
	j = idx % 8; 
	if (!(group_write_bmap->bmap[i] & (1 << j)))
		return 1;
	else
		return 0;
}

static int
amap_table_group_mirror(struct clone_info *clone_info, struct tdisk *tdisk, struct amap_table_group *group, uint32_t group_id, uint32_t amap_table_max)
{
	struct amap_table *amap_table;
	struct amap_table_index *table_index;
	uint64_t block;
	uint32_t atable_id;
	struct amap_group_bitmap *bmap;
	int i, retval, error;

	tdisk_bmap_lock(tdisk);
	bmap = amap_group_table_bmap_locate(tdisk, group_id, &error);
	tdisk_bmap_unlock(tdisk);
	if (unlikely(!bmap))
		return -1;

	atable_id = group_id << AMAP_TABLE_GROUP_SHIFT;
	table_index = &tdisk->table_index[group_id];

	for (i = 0; i < amap_table_max; i++, atable_id++) {
		amap_table_group_lock(group);
		tdisk_bmap_lock(tdisk);
		if (tdisk_in_sync(tdisk)) {
			retval = amap_table_write_bmap_check(tdisk, group, i);
			if (retval) {
				tdisk_bmap_unlock(tdisk);
				amap_table_group_unlock(group);
				continue;
			}
		}
		else if (bmap_bit_is_set(bmap, i)) {
			tdisk_bmap_unlock(tdisk);
			amap_table_group_unlock(group);
			continue;
		}
		tdisk_bmap_unlock(tdisk);

		block = get_amap_table_block(table_index, i);
		amap_table = group->amap_table[i];
		if (!block && !amap_table) {
			amap_table_group_unlock(group);
			continue;
		}

		if (!amap_table) {
			amap_table = amap_table_load_async(tdisk, block, group, group_id, atable_id);
			if (unlikely(!amap_table)) {
				amap_table_group_unlock(group);
				debug_warn("Cannot load amap table at id %u block %llu\n", atable_id, (unsigned long long)block);
				return -1;
			}
		}

		amap_table_get(amap_table);
		amap_table_group_unlock(group);

		wait_on_chan_check(amap_table->amap_table_wait, !atomic_test_bit_short(ATABLE_META_DATA_READ_DIRTY, &amap_table->flags));
		retval = amap_table_mirror(clone_info, tdisk, amap_table, group_id);
		amap_table_put(amap_table);
		if (unlikely(retval != 0)) {
			clone_list_wait(clone_info, tdisk);
			debug_warn("amap table mirror failed at id %u block %llu\n", atable_id, (unsigned long long)block);
			return -1;
		}
	}
	return 0;
}

static SLIST_HEAD(, node_comm) rep_comm_list = SLIST_HEAD_INITIALIZER(rep_comm_list);

static struct node_comm *
rep_comm_locate(uint32_t dest_ipaddr, uint32_t src_ipaddr)
{
	struct node_comm *comm;

	debug_info("dest ipaddr %u src ipaddr %u\n", dest_ipaddr, src_ipaddr);
	SLIST_FOREACH(comm, &rep_comm_list, c_list) {
		debug_info("comm controller ipaddr %u comm node ipaddr %u\n", comm->controller_ipaddr, comm->node_ipaddr);
		if (comm->controller_ipaddr == dest_ipaddr && comm->node_ipaddr == src_ipaddr) {
			node_comm_get(comm);
			return comm;
		}
	}

	comm = node_comm_alloc(node_rep_send_hash, dest_ipaddr, src_ipaddr);
	SLIST_INSERT_HEAD(&rep_comm_list, comm, c_list);
	return comm;
}

void
rep_comm_put(struct node_comm *comm, int mirror_job)
{
	debug_check(!comm);
	sx_xlock(rep_comm_lock);
	if (mirror_job) {
		node_comm_lock(comm);
		atomic_dec(&comm->jobs);
		node_comm_unlock(comm);
	}
	if (atomic_dec_and_test(&comm->refs)) {
		SLIST_REMOVE(&rep_comm_list, comm, node_comm, c_list);
		node_comm_free(comm);
	}
	sx_xunlock(rep_comm_lock);
}

struct node_comm *
rep_comm_get(uint32_t dest_ipaddr, uint32_t src_ipaddr, int mirror_job)
{
	struct node_comm *comm;
	int retval;
	int free_sock_count;
	int num_socks;

	sx_xlock(rep_comm_lock);
	comm = rep_comm_locate(dest_ipaddr, src_ipaddr);
	node_comm_lock(comm);
	free_sock_count = node_comm_free_sock_count(comm);
	if (mirror_job)
		atomic_inc(&comm->jobs);
	num_socks = (atomic_read(&comm->jobs) * MAX_AMAP_MIRROR_THREADS) + MAX_GDEVQ_THREADS;

	retval = 0;
	if (free_sock_count < num_socks)
		retval = rep_client_sock_init(comm, num_socks - free_sock_count);
	node_comm_unlock(comm);

	sx_xunlock(rep_comm_lock);
	if (unlikely(retval != 0)) {
		debug_warn("mirror sock init failed for dest ipaddr %u src ipaddr %u\n", dest_ipaddr, src_ipaddr);
		rep_comm_put(comm, mirror_job);
		return NULL;
	}
	return comm;
}

#ifdef FREEBSD 
static void rep_send_thr(void *data)
#else
static int rep_send_thr(void *data)
#endif
{
	struct clone_info *clone_info = data;
	struct node_comm *comm;
	struct tdisk *tdisk = clone_info->src_tdisk;
	struct amap_table_group *group;
	struct usr_job job_info;
	uint64_t size = tdisk->end_lba << tdisk->lba_shift;
	uint64_t end_lba;
	uint32_t amap_table_max, amap_table_group_max, min;
	int retval, i, status;

	comm = rep_comm_get(clone_info->stats.dest_ipaddr, clone_info->stats.src_ipaddr, 1);
	if (unlikely(!comm)) {
		tdisk_set_mirror_error(tdisk);
		goto exit;
	}

	clone_info->comm = comm;
	tdisk_clone_lock(tdisk);
	tdisk_clone_setup(tdisk, NULL, clone_info);
	tdisk_clone_unlock(tdisk);
	end_lba = size >> LBA_SHIFT;
	amap_table_max = end_lba / LBAS_PER_AMAP_TABLE;
	if (end_lba % LBAS_PER_AMAP_TABLE)
		amap_table_max++;
	amap_table_group_max = amap_table_max >> AMAP_TABLE_GROUP_SHIFT;
	if (amap_table_max & AMAP_TABLE_GROUP_MASK)
		amap_table_group_max++;

	for (i = 0; i < amap_table_group_max; i++) {
		group = tdisk->amap_table_group[i];
		debug_check(!group);

		min = min_t(uint32_t, AMAP_TABLE_PER_GROUP, amap_table_max);
		amap_table_max -= min;
		retval = amap_table_group_mirror(clone_info, tdisk, group, i, min);
		if (unlikely(retval != 0)) {
			debug_warn("amap table group mirror failed for %d\n", i);
			tdisk_set_mirror_error(tdisk);
			break;
		}

		tdisk_clone_lock(tdisk);
		tdisk_bmap_lock(tdisk);
		amap_group_bmaps_free(tdisk, i);
		tdisk_bmap_unlock(tdisk);
		tdisk_clone_unlock(tdisk);
	}

exit:
	debug_info("mirror_amap_setup_read_ticks: %u\n", tdisk->mirror_amap_setup_read_ticks);
	debug_info("mirror_hash_compute_ticks: %u\n", tdisk->mirror_hash_compute_ticks);
	debug_info("mirror_write_setup_ticks: %u\n", tdisk->mirror_write_setup_ticks);
	debug_info("mirror_verify_setup_ticks: %u\n", tdisk->mirror_verify_setup_ticks);
	debug_info("mirror_comp_setup_ticks: %u\n", tdisk->mirror_comp_setup_ticks);
	debug_info("mirror_write_io_ticks: %u\n", tdisk->mirror_write_io_ticks);
	debug_info("mirror_ticks: %u\n", tdisk->mirror_ticks);
	status = tdisk_mirror_error(tdisk) ? 1 : 0;
	if (tdisk_in_sync(tdisk))
		tdisk_mirror_end(tdisk);
	tdisk_clone_lock(tdisk);
	tdisk_clone_cleanup(tdisk, NULL);
	tdisk_clone_unlock(tdisk);
	tdisk_start_resize_thread(tdisk);
	tdisk_put(tdisk);

	sx_xlock(clone_info_lock);
	STAILQ_REMOVE(&clone_info_list, clone_info, clone_info, i_list);
	sx_xunlock(clone_info_lock);
	clone_info->stats.elapsed_msecs = ticks_to_msecs(get_elapsed(clone_info->start_ticks));
	job_info.job_id = clone_info->job_id;
	memcpy(&job_info.stats, &clone_info->stats, sizeof(clone_info->stats));
	node_usr_send_job_completed(&job_info, status);
	free(clone_info, M_CLONE_INFO);
	if (comm)
		rep_comm_put(comm, 1);
#ifdef FREEBSD 
	kproc_exit(0);
#else
	return 0;
#endif
}

int
vdisk_mirror_cancel(struct clone_config *config)
{
	struct clone_info *iter;
	struct tdisk *src_tdisk;

	sx_xlock(clone_info_lock);
	STAILQ_FOREACH(iter, &clone_info_list, i_list) {
		if (iter->op != OP_MIRROR)
			continue;

		src_tdisk = iter->src_tdisk;
		if (src_tdisk->target_id != config->src_target_id)
			continue;
		tdisk_set_mirror_error(src_tdisk);
		break;
	}
	sx_xunlock(clone_info_lock);
	return 0;
}

int
vdisk_mirror_remove(struct clone_config *config)
{
	struct tdisk *tdisk;
	int retval;

	if (unlikely(config->src_target_id >= TL_MAX_DEVICES)) {
		debug_warn("Invalid src target id %u\n", config->src_target_id);
		return -1;
	}

	tdisk = tdisk_locate(config->src_target_id);
	if (unlikely(!tdisk)) {
		debug_warn("Cannot locate src vdisk at id %u\n", config->src_target_id);
		return -1;
	}

	retval = tdisk_mirror_remove(tdisk, 1);
	tdisk_put(tdisk);
	return retval;
}

int
vdisk_mirror_status(struct clone_config *config)
{
	struct clone_info *iter;
	struct tdisk *src_tdisk;
	uint32_t amap_max;

	sx_xlock(clone_info_lock);
	STAILQ_FOREACH(iter, &clone_info_list, i_list) {
		if (iter->op != OP_MIRROR)
			continue;

		src_tdisk = iter->src_tdisk;
		if (src_tdisk->target_id != config->src_target_id)
			continue;

		if (tdisk_mirror_error(src_tdisk)) {
			config->status = MIRROR_STATUS_ERROR;
		}
		else {
			config->status = MIRROR_STATUS_INPROGRESS;
			amap_max = tdisk_max_amaps(src_tdisk);
			config->progress = (tdisk_get_clone_amap_id(src_tdisk) * 100) / amap_max; 
		}
		iter->stats.elapsed_msecs = ticks_to_msecs(get_elapsed(iter->start_ticks));
		memcpy(&config->stats, &iter->stats, sizeof(iter->stats));
		sx_xunlock(clone_info_lock);
		return 0;
	}
	sx_xunlock(clone_info_lock);

	src_tdisk = tdisk_locate(config->src_target_id);

	if (unlikely(!src_tdisk)) {
		debug_warn("Cannot locate source vdisk at id %u\n", config->src_target_id);
		return -1;
	}

	if (tdisk_mirror_error(src_tdisk))
		config->status = MIRROR_STATUS_ERROR;
	else
		config->status = MIRROR_STATUS_SUCCESSFUL;
	tdisk_put(src_tdisk);
	return 0;
}

static int
vdisk_can_be_mirrored(struct tdisk *tdisk, struct clone_config *config, int internal)
{
	if (internal || !tdisk_mirroring_configured(tdisk))
		return 1;

	if (tdisk->mirror_state.mirror_ipaddr == config->dest_ipaddr) {
		sprintf(config->errmsg, "Synchronous mirroring configured for %s and destination of current mirror operation is the same the synchronous mirror\n", tdisk_name(tdisk));
		return 0;
	}

	if (tdisk_mirroring_disabled(tdisk)) {
		if (tdisk_mirror_master(tdisk))
			return 1;
		sprintf(config->errmsg, "Synchronous mirroring configured for %s, vdisk is in slave role but mirroring is currently disabled\n", tdisk_name(tdisk));
		return 0;
	}

	if (tdisk_mirroring_need_resync(tdisk)) {
		sprintf(config->errmsg, "Synchronous mirroring configured for %s, mirror resync needed/expected\n", tdisk_name(tdisk));
		return 0;
	}

	return 1;
}

int
__vdisk_mirror(struct clone_config *config, int internal)
{
	struct tdisk *tdisk;
	struct clone_info *clone_info;
	int retval;

	if (config->attach && node_type_controller()) {
		sprintf(config->errmsg, "Synchronous mirroring cannot be enabled on a controller node\n");
		return -1;
	}

	if (unlikely(config->src_target_id >= TL_MAX_DEVICES)) {
		sprintf(config->errmsg, "Invalid src target id %u\n", config->src_target_id);
		return -1;
	}

	if (unlikely(config->dest_target_id >= TL_MAX_DEVICES)) {
		sprintf(config->errmsg, "Invalid dest target id %u\n", config->dest_target_id);
		return -1;
	}

	tdisk = tdisk_locate(config->src_target_id);
	if (unlikely(!tdisk)) {
		sprintf(config->errmsg, "Cannot locate src disk at id %u\n", config->src_target_id);
		return -1;
	}

	if (!is_v2_tdisk(tdisk)) {
		sprintf(config->errmsg, "source vdisk %s is of an older format\n", tdisk_name(tdisk));
		tdisk_put(tdisk);
		return -1;
	}

	if (tdisk_in_mirroring(tdisk) || tdisk_in_cloning(tdisk) || tdisk_in_sync(tdisk)) {
		sprintf(config->errmsg, "vdisk %s busy, possibly another replication/cloning in progress\n", tdisk_name(tdisk));
		tdisk_put(tdisk);
		return -1;
	}

	if (tdisk_clone_error(tdisk)) {
		sprintf(config->errmsg, "vdisk %s is a clone and cloning had failed\n", tdisk_name(tdisk));
		tdisk_put(tdisk);
		return -1;
	}

	if (!vdisk_can_be_mirrored(tdisk, config, internal)) {
		tdisk_put(tdisk);
		return -1;
	}

	tdisk_stop_delete_thread(tdisk);

	tdisk_reset_clone_amap_id(tdisk, 0);
	tdisk_clear_mirror_error(tdisk);

	clone_info = zalloc(sizeof(*clone_info), M_CLONE_INFO, Q_WAITOK);
	clone_info->start_ticks = ticks;
	clone_info->src_tdisk = tdisk;
	clone_info->stats.src_ipaddr = config->src_ipaddr;
	clone_info->stats.dest_ipaddr = config->dest_ipaddr;
	clone_info->dest_target_id = config->dest_target_id;
	clone_info->op = OP_MIRROR;
	clone_info->attach = config->attach;
	clone_info->in_sync = (config->attach || internal);
	clone_info->mirror_role = config->mirror_role;
	clone_info->job_id = config->job_id;
	strcpy(clone_info->mirror_vdisk, config->mirror_vdisk);
	strcpy(clone_info->mirror_group, config->mirror_group);

	if (config->attach) {
		retval = tdisk_mirror_setup(tdisk, clone_info, config->sys_rid);
		if (unlikely(retval != 0)) {
			sprintf(config->errmsg, "Mirror setup failed for %s\n", tdisk_name(tdisk));
			debug_warn("Mirror setup failed for %s\n", tdisk_name(tdisk));
			goto err;
		}
	}
	STAILQ_INSERT_TAIL(&clone_info_list, clone_info, i_list);
	retval = kernel_thread_create(rep_send_thr, clone_info, clone_info->task, "clonethr");
	if (unlikely(retval != 0)) {
		sprintf(config->errmsg, "Creating a new mirroring thread failed\n");
		STAILQ_REMOVE(&clone_info_list, clone_info, clone_info, i_list);
		if (config->attach)
			tdisk_mirror_remove(tdisk, 0);
		goto err;
	}
	return 0;
err:
	tdisk_put(tdisk);
	free(clone_info, M_CLONE_INFO);
	return -1;
}

int
vdisk_mirror(struct clone_config *config)
{
	int retval;

	sx_xlock(clone_info_lock);
	retval = __vdisk_mirror(config, 0);
	sx_xunlock(clone_info_lock);
	return retval;
}
