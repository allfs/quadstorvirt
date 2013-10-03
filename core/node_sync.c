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
#include "log_group.h"
#include "rcache.h"
#include "reservation.h"
#include "gdevq.h"
#include "../common/cluster_common.h" 
#include "node_sock.h"
#include "vdevdefs.h"
#include "ddthread.h"
#include "node_sync.h"
#include "node_ha.h"
#include "bdevgroup.h"

struct qs_sync_thr {
	kproc_t *task;
	SLIST_ENTRY(qs_sync_thr) d_list;
	int exit_flags;
	int id;
};

atomic_t sync_status;
extern struct node_config master_config;
struct node_sync_post_list pending_post_queue = STAILQ_HEAD_INITIALIZER(pending_post_queue);
STAILQ_HEAD(, client_node) client_node_list = STAILQ_HEAD_INITIALIZER(client_node_list);
static SLIST_HEAD(, qs_sync_thr) sync_thr_list = SLIST_HEAD_INITIALIZER(sync_thr_list);
wait_chan_t *sync_post_wait;
int sync_post_flags;
atomic_t nonsync_pending_writes;
extern sx_t *sync_lock;

#define node_sync_lock()		(sx_xlock(sync_lock))
#define node_sync_unlock()				\
do {							\
	debug_check(!sx_xlocked(sync_lock));		\
	sx_xunlock(sync_lock);				\
} while (0)

struct client_node {
	uint32_t ipaddr;
	STAILQ_ENTRY(client_node) c_list;
};


struct bint_spec {
	uint64_t free;
	uint64_t usize;
	uint16_t bid;
	uint16_t csum;
	uint8_t log_disk;
	uint8_t ddmaster;
	uint8_t ddbits;
	uint8_t log_disks;
	uint8_t initialized;
	uint8_t log_write;
	uint8_t enable_comp;
	uint8_t sector_shift;
	uint8_t v2_disk;
	uint8_t v2_log_format;
	uint8_t rid_set;
	int32_t group_flags;
	uint64_t availmem;
	struct bint_stats bint_stats;
	char mrid[TL_RID_MAX];
} __attribute__ ((__packed__));

struct node_comm *sync_comm;

int
node_sync_get_status(void)
{
	return atomic_read(&sync_status);
}

void
node_sync_set_status(int status)
{
	atomic_set(&sync_status, status);
}

void
node_sync_disable(void)
{
	node_sync_lock();
	if (node_sync_get_status() == NODE_SYNC_ERROR) {
		node_sync_unlock();
		return;
	}

	node_sync_set_status(NODE_SYNC_ERROR);
	node_ha_disable();
	node_sync_unlock();
}

static int
node_bint_sync_enabled(struct bdevint *bint)
{
	if (atomic_test_bit(BINT_SYNC_ENABLED, &bint->flags))
		return 1;
	else
		return 0;
}

int
node_tdisk_sync_enabled(struct tdisk *tdisk)
{
	if (!atomic_test_bit(VDISK_SYNC_ENABLED, &tdisk->flags) || !atomic_test_bit(VDISK_ATTACHED, &tdisk->flags))
		return 0;

	/* dest of a clone check */
	if (tdisk_in_cloning(tdisk) && !tdisk->dest_tdisk)
		return 0;
	else
		return 1; 
}

static int
node_ddtable_sync_enabled(struct ddtable *ddtable)
{
	if (atomic_test_bit(DDTABLE_SYNC_ENABLED, &ddtable->flags))
		return 1;
	else
		return 0;
}

int
node_sync_need_resync(void)
{
	return (node_sync_get_status() == NODE_SYNC_NEED_RESYNC);
}

int
node_sync_inprogress(void)
{
	return (node_sync_get_status() == NODE_SYNC_INPROGRESS);
}

int
node_sync_enabled(void)
{
	if (!sync_comm)
		return 0;

	if (node_sync_get_status() == NODE_SYNC_ERROR || node_sync_get_status() == NODE_SYNC_NEED_RESYNC)
		return 0;

	if (node_sync_get_status() == NODE_SYNC_INPROGRESS || node_sync_get_status() == NODE_SYNC_DONE)
		return 1;
	else
		return 0;
}

struct node_comm *
node_sync_comm_get(void)
{
	struct node_comm *comm = NULL;

	node_sync_lock();
	if (sync_comm) {
		comm = sync_comm;
		node_comm_get(comm);
	}
	node_sync_unlock();
	return comm;
}

struct node_msg *
node_sync_msg_alloc(int dxfer_len, int msg_cmd)
{
	struct node_msg *msg;
	struct raw_node_msg *raw;

	msg = node_msg_alloc(dxfer_len);
	raw = msg->raw;
	bzero(raw, sizeof(*raw) + dxfer_len);
	raw->dxfer_len = dxfer_len;
	raw->msg_cmd = msg_cmd;
	raw->msg_id = node_transaction_id();
	return msg;
}

static int
node_resp_status(struct node_msg *msg)
{
	struct node_msg *resp;
	struct raw_node_msg *raw;

	resp = msg->resp;

	if (unlikely(!resp)) {
		return -1;
	}

	raw = resp->raw;
	if (raw->msg_status == NODE_STATUS_OK)
		return 0;
	else {
		debug_info("for cmd %d raw msg status %d\n", raw->msg_cmd, raw->msg_status);
		return raw->msg_status;
	}
}

static void
node_sync_post_insert(struct node_sync_post *post)
{
	chan_lock(sync_post_wait);
	STAILQ_INSERT_TAIL(&pending_post_queue, post, s_list);
	chan_wakeup_unlocked(sync_post_wait);
	chan_unlock(sync_post_wait);
}

static struct amap_table *
amap_table_create(struct tdisk *tdisk, struct amap_table_group *group, int atable_id, uint64_t amap_table_block)
{
	struct amap_table *amap_table;
	struct bdevint *bint;

	bint = bdev_find(BLOCK_BID(amap_table_block));
	if (unlikely(!bint)) {
		return NULL;
	}

	amap_table = amap_table_alloc(tdisk, atable_id);
	amap_table->metadata = vm_pg_alloc(VM_ALLOC_ZERO);
	if (unlikely(!amap_table->metadata)) {
		amap_table_put(amap_table);
		return NULL;
	}
	amap_table->amap_table_block = amap_table_block;
	atomic_set_bit_short(ATABLE_META_DATA_INVALID, &amap_table->flags);
	amap_table_insert(group, amap_table);
	return amap_table;
}
 
static struct amap *
amap_create(struct amap_table *amap_table, uint32_t amap_id, uint32_t amap_idx, uint64_t block)
{
	struct amap *amap;
	struct bdevint *bint;

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
	atomic_set_bit_short(ATABLE_META_DATA_INVALID, &amap_table->flags);
	amap_insert(amap_table, amap, amap_idx);
	return amap;
}

void
node_newmeta_sync_complete_recv(struct node_sock *sock, struct raw_node_msg *raw)
{
	struct tdisk *tdisk;
	struct node_msg *msg;

	tdisk = tdisk_locate(raw->target_id);
	if (unlikely(!tdisk)) {
		debug_warn("node cmd request for unknown tdisk %d\n", raw->target_id);
		node_error_resp_msg(sock, raw, NODE_STATUS_TARGET_NOT_FOUND);
		return;
	}

	msg = node_ha_meta_lookup(raw->msg_id);
	if (unlikely(!msg)) {
		debug_warn("Cannot locate msg at id %llu\n", (unsigned long long)raw->msg_id);
		node_error_resp_msg(sock, raw, NODE_STATUS_INVALID_MSG);
		tdisk_put(tdisk);
		return;
	}

	node_msg_free(msg);
	raw->dxfer_len = 0;
	node_resp_msg(sock, raw, NODE_STATUS_OK);
	tdisk_put(tdisk);
}

void
node_pgdata_sync_complete_recv(struct node_sock *sock, struct raw_node_msg *raw)
{
	struct tdisk *tdisk;
	struct node_msg *msg;

	tdisk = tdisk_locate(raw->target_id);
	if (unlikely(!tdisk)) {
		debug_warn("node cmd request for unknown tdisk %d\n", raw->target_id);
		node_error_resp_msg(sock, raw, NODE_STATUS_TARGET_NOT_FOUND);
		return;
	}

	msg = node_ha_lookup(raw->msg_id);
	if (unlikely(!msg)) {
		debug_warn("Cannot locate msg at id %llu\n", (unsigned long long)raw->msg_id);
		node_error_resp_msg(sock, raw, NODE_STATUS_INVALID_MSG);
		tdisk_put(tdisk);
		return;
	}

	node_msg_free(msg);
	raw->dxfer_len = 0;
	node_resp_msg(sock, raw, NODE_STATUS_OK);
	tdisk_put(tdisk);
}

void
node_pgdata_sync_client_done_recv(struct node_sock *sock, struct raw_node_msg *raw)
{
	struct tdisk *tdisk;
	struct node_msg *msg;

	tdisk = tdisk_locate(raw->target_id);
	if (unlikely(!tdisk)) {
		debug_warn("node cmd request for unknown tdisk %d\n", raw->target_id);
		node_error_resp_msg(sock, raw, NODE_STATUS_TARGET_NOT_FOUND);
		return;
	}

	msg = node_ha_lookup(raw->msg_id);
	if (unlikely(!msg)) {
		debug_warn("Cannot locate msg at id %llu\n", (unsigned long long)raw->msg_id);
		node_error_resp_msg(sock, raw, NODE_STATUS_INVALID_MSG);
		tdisk_put(tdisk);
		return;
	}

	msg->raw->msg_cmd = NODE_MSG_PGDATA_SYNC_CLIENT_DONE; 
	node_ha_hash_insert(msg, raw->msg_id);
	raw->dxfer_len = 0;
	node_resp_msg(sock, raw, NODE_STATUS_OK);
	tdisk_put(tdisk);
}

void
node_newmeta_sync_start_recv(struct node_sock *sock, struct raw_node_msg *raw)
{
	struct tdisk *tdisk;
	struct node_msg *msg;
	int retval;
	uint16_t csum;

	tdisk = tdisk_locate(raw->target_id);
	if (unlikely(!tdisk)) {
		debug_warn("node cmd request for unknown tdisk %d\n", raw->target_id);
		node_error_resp_msg(sock, raw, NODE_STATUS_TARGET_NOT_FOUND);
		return;
	}

	msg = node_msg_alloc(raw->dxfer_len);
	memcpy(msg->raw, raw, sizeof(*raw));

	retval = node_sock_read_nofail(sock, msg->raw->data, msg->raw->dxfer_len);
	if (unlikely(retval != 0)) {
		node_msg_free(msg);
		tdisk_put(tdisk);
		return;
	}

	csum = net_calc_csum16(msg->raw->data, msg->raw->dxfer_len);
	if (unlikely(csum != msg->raw->data_csum)) {
		debug_warn("data csum mismatch %x %x\n", csum, msg->raw->data_csum);
		node_sock_read_error(sock);
		node_msg_free(msg);
		tdisk_put(tdisk);
		return;
	}

	node_ha_meta_hash_insert(msg, msg->raw->msg_id);
	raw->dxfer_len = 0;
	node_resp_msg(sock, raw, NODE_STATUS_OK);
	tdisk_put(tdisk);
}

void
node_pgdata_sync_start_recv(struct node_sock *sock, struct raw_node_msg *raw)
{
	struct tdisk *tdisk;
	struct node_msg *msg;
	int retval;
	uint16_t csum;

	tdisk = tdisk_locate(raw->target_id);
	if (unlikely(!tdisk)) {
		debug_warn("node cmd request for unknown tdisk %d\n", raw->target_id);
		node_error_resp_msg(sock, raw, NODE_STATUS_TARGET_NOT_FOUND);
		return;
	}

	msg = node_msg_alloc(raw->dxfer_len);
	memcpy(msg->raw, raw, sizeof(*raw));

	retval = node_sock_read_nofail(sock, msg->raw->data, msg->raw->dxfer_len);
	if (unlikely(retval != 0)) {
		node_msg_free(msg);
		tdisk_put(tdisk);
		return;
	}

	csum = net_calc_csum16(msg->raw->data, msg->raw->dxfer_len);
	if (unlikely(csum != msg->raw->data_csum)) {
		debug_warn("data csum mismatch %x %x\n", csum, msg->raw->data_csum);
		node_sock_read_error(sock);
		node_msg_free(msg);
		tdisk_put(tdisk);
		return;
	}

	node_ha_hash_insert(msg, msg->raw->msg_id);
	raw->dxfer_len = 0;
	node_resp_msg(sock, raw, NODE_STATUS_OK);
	tdisk_put(tdisk);
}

void
node_reservation_sync_recv(struct node_sock *sock, struct raw_node_msg *raw)
{
	struct tdisk *tdisk;
	struct reservation_spec reservation_spec;
	struct reservation *reservation;
	int retval;

	tdisk = tdisk_locate(raw->target_id);
	if (unlikely(!tdisk)) {
		debug_warn("node cmd request for unknown tdisk %d\n", raw->target_id);
		node_error_resp_msg(sock, raw, NODE_STATUS_TARGET_NOT_FOUND);
		return;
	}

	debug_check(raw->dxfer_len != sizeof(reservation_spec));
	retval = node_sock_read_nofail(sock, &reservation_spec, sizeof(reservation_spec));
	if (unlikely(retval != 0)) {
		tdisk_put(tdisk);
		return;
	}

	reservation = &tdisk->sync_reservation;
	tdisk_reservation_lock(tdisk);
	reservation_spec_copy(reservation, &reservation_spec);
	tdisk_reservation_unlock(tdisk);
	raw->dxfer_len = 0;
	node_resp_msg(sock, raw, NODE_STATUS_OK);
	tdisk_put(tdisk);
}

void
node_registration_sync_recv(struct node_sock *sock, struct raw_node_msg *raw)
{
	struct tdisk *tdisk;
	struct registration_spec registration_spec;
	int retval;

	tdisk = tdisk_locate(raw->target_id);
	if (unlikely(!tdisk)) {
		debug_warn("node cmd request for unknown tdisk %d\n", raw->target_id);
		node_error_resp_msg(sock, raw, NODE_STATUS_TARGET_NOT_FOUND);
		return;
	}

	debug_check(raw->dxfer_len != sizeof(registration_spec));
	retval = node_sock_read_nofail(sock, &registration_spec, sizeof(registration_spec));
	if (unlikely(retval != 0)) {
		tdisk_put(tdisk);
		return;
	}

	if (registration_spec.op == REGISTRATION_OP_ADD)
		registration_spec_add(tdisk, &tdisk->sync_reservation, &registration_spec);
	else
		registration_spec_remove(tdisk, &tdisk->sync_reservation, &registration_spec);
	raw->dxfer_len = 0;
	node_resp_msg(sock, raw, NODE_STATUS_OK);
	tdisk_put(tdisk);
}

void
node_registration_clear_sync_recv(struct node_sock *sock, struct raw_node_msg *raw)
{
	struct tdisk *tdisk;
	struct reservation_spec reservation_spec;
	int retval;

	tdisk = tdisk_locate(raw->target_id);
	if (unlikely(!tdisk)) {
		debug_warn("node cmd request for unknown tdisk %d\n", raw->target_id);
		node_error_resp_msg(sock, raw, NODE_STATUS_TARGET_NOT_FOUND);
		return;
	}

	debug_check(raw->dxfer_len != sizeof(reservation_spec));
	retval = node_sock_read_nofail(sock, &reservation_spec, sizeof(reservation_spec));
	if (unlikely(retval != 0)) {
		tdisk_put(tdisk);
		return;
	}

	registration_spec_clear(tdisk, &reservation_spec);
	raw->dxfer_len = 0;
	node_resp_msg(sock, raw, NODE_STATUS_OK);
	tdisk_put(tdisk);
}

void
node_tdisk_delete_recv(struct node_sock *sock, struct raw_node_msg *raw)
{
	struct tdisk *tdisk;

	tdisk = tdisk_locate(raw->target_id);
	if (tdisk)
		atomic_set_bit(VDISK_DISABLED, &tdisk->flags);

	raw->dxfer_len = 0;
	node_resp_msg(sock, raw, NODE_STATUS_OK);
	if (tdisk)
		tdisk_put(tdisk);
}

void
node_tdisk_update_recv(struct node_sock *sock, struct raw_node_msg *raw)
{
	struct tdisk *tdisk;
	pagestruct_t *page;
	struct tdisk_spec tdisk_spec;
	int status, retval;

	tdisk = tdisk_locate(raw->target_id);
	if (unlikely(!tdisk)) {
		debug_warn("node cmd request for unknown tdisk %d\n", raw->target_id);
		node_error_resp_msg(sock, raw, NODE_STATUS_TARGET_NOT_FOUND);
		return;
	}

	debug_check(raw->dxfer_len != sizeof(tdisk_spec));
	retval = node_sock_read_nofail(sock, &tdisk_spec, sizeof(tdisk_spec));
	if (unlikely(retval != 0)) {
		tdisk_put(tdisk);
		return;
	}

	page = vm_pg_alloc(0);
	if (unlikely(!page)) {
		status = NODE_STATUS_MEM_ALLOC_FAILURE;
		node_msg_discard_data(sock, LBA_SIZE); 
		goto send;
	}

	retval = node_sock_read_nofail(sock, vm_pg_address(page), LBA_SIZE);
	if (unlikely(retval != 0)) {
		vm_pg_free(page);
		tdisk_put(tdisk);
		return;
	}

	if (tdisk_spec.csum != calc_csum16(vm_pg_address(page), LBA_SIZE)) {
		vm_pg_free(page);
		node_sock_read_error(sock);
		tdisk_put(tdisk);
		return;
	}

	retval = __tdisk_alloc_amap_groups(tdisk, tdisk_spec.amap_table_max);
	if (unlikely(retval != 0)) {
		status = NODE_STATUS_MEM_ALLOC_FAILURE;
		vm_pg_free(page);
		goto send;
	}

	tdisk_lock(tdisk);
	vm_pg_free(tdisk->metadata);
	tdisk->metadata = page;
	tdisk->amap_table_max = tdisk_spec.amap_table_max;
	tdisk->table_index_max = tdisk_spec.table_index_max;
	tdisk->amap_table_group_max = tdisk_spec.amap_table_group_max;
	tdisk->end_lba = tdisk_spec.end_lba;
	tdisk_unlock(tdisk);
	status = NODE_STATUS_OK;
send:
	raw->dxfer_len = 0;
	node_resp_msg(sock, raw, status);
	tdisk_put(tdisk);

}

void
node_tdisk_sync_recv(struct node_sock *sock, struct raw_node_msg *raw)
{
	struct tdisk *tdisk;
	pagestruct_t *page;
	struct tdisk_spec tdisk_spec;
	int status, retval;

	tdisk = tdisk_locate(raw->target_id);
	if (unlikely(!tdisk)) {
		debug_warn("node cmd request for unknown tdisk %d\n", raw->target_id);
		node_error_resp_msg(sock, raw, NODE_STATUS_TARGET_NOT_FOUND);
		return;
	}

	debug_check(raw->dxfer_len != sizeof(tdisk_spec));
	retval = node_sock_read_nofail(sock, &tdisk_spec, sizeof(tdisk_spec));
	if (unlikely(retval != 0)) {
		tdisk_put(tdisk);
		return;
	}

	page = vm_pg_alloc(0);
	if (unlikely(!page)) {
		status = NODE_STATUS_MEM_ALLOC_FAILURE;
		node_msg_discard_data(sock, LBA_SIZE); 
		goto send;
	}

	retval = node_sock_read_nofail(sock, vm_pg_address(page), LBA_SIZE);
	if (unlikely(retval != 0)) {
		vm_pg_free(page);
		tdisk_put(tdisk);
		return;
	}

	if (tdisk_spec.csum != calc_csum16(vm_pg_address(page), LBA_SIZE)) {
		vm_pg_free(page);
		node_sock_read_error(sock);
		tdisk_put(tdisk);
		return;
	}

	tdisk_lock(tdisk);
	if (!tdisk->metadata) {
		debug_check(tdisk->free_task);
		retval = kernel_thread_create(tdisk_free_thread, tdisk, tdisk->free_task, "tdfreet%u", tdisk->bus);
		if (unlikely(retval != 0)) {
			status = NODE_STATUS_ERROR;
			tdisk_unlock(tdisk);
			vm_pg_free(page);
			goto send;
		}

		debug_check(tdisk->sync_task);
		retval = kernel_thread_create(tdisk_sync_thread, tdisk, tdisk->sync_task, "tdsynct%u", tdisk->bus);
		if (unlikely(retval != 0)) {
			status = NODE_STATUS_ERROR;
			tdisk_unlock(tdisk);
			vm_pg_free(page);
			goto send;
		}

		retval = tdisk_load_index(tdisk, NULL);
		if (unlikely(retval != 0)) {
			status = NODE_STATUS_ERROR;
			tdisk_unlock(tdisk);
			vm_pg_free(page);
			goto send;
		}
	}

	vm_pg_free(tdisk->metadata);
	tdisk->metadata = page;
	tdisk_unlock(tdisk);
	status = NODE_STATUS_OK;
send:
	raw->dxfer_len = 0;
	node_resp_msg(sock, raw, status);
	tdisk_put(tdisk);
}

void
node_amap_meta_sync_recv(struct node_sock *sock, struct raw_node_msg *raw)
{
	struct tdisk *tdisk;
	struct amap_spec amap_spec;
	struct amap_table *amap_table;
	struct amap_table_group *group;
	struct amap *amap;
	int retval, status;
	uint32_t atable_id, group_id, group_offset, amap_id, amap_idx;

	tdisk = tdisk_locate(raw->target_id);
	if (unlikely(!tdisk)) {
		debug_warn("node cmd request for unknown tdisk %d\n", raw->target_id);
		node_error_resp_msg(sock, raw, NODE_STATUS_TARGET_NOT_FOUND);
		return;
	}

	debug_check(raw->dxfer_len != sizeof(amap_spec));
	retval = node_sock_read_nofail(sock, &amap_spec, sizeof(amap_spec));
	if (unlikely(retval != 0)) {
		tdisk_put(tdisk);
		return;
	}

	atable_id = amap_table_id(amap_spec.lba);
	group_id = amap_table_group_id(atable_id, &group_offset);

	group = tdisk->amap_table_group[group_id];
	tdisk_tail_group(tdisk, group);

	amap_table_group_lock(group);
	amap_table = group->amap_table[group_offset];
	if (!amap_table) {
		amap_table_group_unlock(group);
		goto out;
	}
	group_tail_amap_table(group, amap_table);
	amap_table_get(amap_table);
	amap_table_group_unlock(group);

	amap_id = amap_get_id(amap_spec.lba);
	amap_idx = amap_id - (amap_table->amap_table_id * AMAPS_PER_AMAP_TABLE);

	amap_table_lock(amap_table);
	amap = amap_table->amap_index[amap_idx];
	if (!amap) {
		amap_table_unlock(amap_table);
		amap_table_put(amap_table);
		goto out;
	}

	amap_get(amap);
	amap_table_unlock(amap_table);

	amap_lock(amap);
	atomic_clear_bit_short(AMAP_META_DATA_NEW, &amap->flags);
	amap_unlock(amap);
	amap_put(amap);
	amap_table_put(amap_table);
out:
	status = NODE_STATUS_OK;
	raw->dxfer_len = 0;
	node_resp_msg(sock, raw, status);
	tdisk_put(tdisk);
	return;

}

void
node_amap_sync_post_recv(struct node_sock *sock, struct raw_node_msg *raw)
{
	struct tdisk *tdisk;
	struct amap_spec amap_spec;
	struct amap_table *amap_table;
	struct amap_table_group *group;
	struct amap *amap;
	int retval, status;
	uint32_t atable_id, group_id, group_offset, amap_id, amap_idx;

	tdisk = tdisk_locate(raw->target_id);
	if (unlikely(!tdisk)) {
		debug_warn("node cmd request for unknown tdisk %d\n", raw->target_id);
		node_error_resp_msg(sock, raw, NODE_STATUS_TARGET_NOT_FOUND);
		return;
	}

	debug_check(raw->dxfer_len != sizeof(amap_spec));
	retval = node_sock_read_nofail(sock, &amap_spec, sizeof(amap_spec));
	if (unlikely(retval != 0)) {
		tdisk_put(tdisk);
		return;
	}

	atable_id = amap_table_id(amap_spec.lba);
	group_id = amap_table_group_id(atable_id, &group_offset);

	group = tdisk->amap_table_group[group_id];
	tdisk_tail_group(tdisk, group);

	amap_table_group_lock(group);
	amap_table = group->amap_table[group_offset];
	debug_check(!amap_table);
	group_tail_amap_table(group, amap_table);
	amap_table_get(amap_table);
	amap_table_group_unlock(group);

	amap_id = amap_get_id(amap_spec.lba);
	amap_idx = amap_id - (amap_table->amap_table_id * AMAPS_PER_AMAP_TABLE);

	amap_table_lock(amap_table);
	amap = amap_table->amap_index[amap_idx];
	debug_check(!amap);
	amap_get(amap);
	amap_table_unlock(amap_table);

	amap_lock(amap);
	if (amap->write_id == amap_spec.write_id) {
		debug_check(!atomic_test_bit_short(AMAP_META_IO_PENDING, &amap->flags));
		atomic_clear_bit_short(AMAP_META_IO_PENDING, &amap->flags);
	}
	amap_unlock(amap);
	amap_put(amap);
	amap_table_put(amap_table);
	status = NODE_STATUS_OK;
	raw->dxfer_len = 0;
	node_resp_msg(sock, raw, status);
	tdisk_put(tdisk);
	return;
}

void 
node_amap_sync_recv(struct node_sock *sock, struct raw_node_msg *raw)
{
	struct tdisk *tdisk;
	struct amap_spec amap_spec;
	struct amap_table *amap_table;
	struct amap_table_group *group;
	struct amap *amap;
	pagestruct_t *page;
	int retval, status;
	uint32_t atable_id, group_id, group_offset, amap_id, amap_idx;

	tdisk = tdisk_locate(raw->target_id);
	if (unlikely(!tdisk)) {
		debug_warn("node cmd request for unknown tdisk %d\n", raw->target_id);
		node_error_resp_msg(sock, raw, NODE_STATUS_TARGET_NOT_FOUND);
		return;
	}

	debug_check(raw->dxfer_len != sizeof(amap_spec));
	retval = node_sock_read_nofail(sock, &amap_spec, sizeof(amap_spec));
	if (unlikely(retval != 0)) {
		tdisk_put(tdisk);
		return;
	}

	debug_check(!amap_spec.write_id);
	page = vm_pg_alloc(0);
	if (unlikely(!page)) {
		status = NODE_STATUS_MEM_ALLOC_FAILURE;
		node_msg_discard_data(sock, LBA_SIZE); 
		goto send;
	}

	retval = node_sock_read_nofail(sock, vm_pg_address(page), LBA_SIZE);
	if (unlikely(retval != 0)) {
		vm_pg_free(page);
		tdisk_put(tdisk);
		return;
	}

	if (amap_spec.csum != calc_csum16(vm_pg_address(page), LBA_SIZE)) {
		vm_pg_free(page);
		node_sock_read_error(sock);
		tdisk_put(tdisk);
		return;
	}

	atable_id = amap_table_id(amap_spec.lba);
	group_id = amap_table_group_id(atable_id, &group_offset);

	debug_check(group_id >= tdisk->amap_table_group_max);
	debug_check(!tdisk->amap_table_group);

	group = tdisk->amap_table_group[group_id];
	tdisk_tail_group(tdisk, group);

	amap_table_group_lock(group);
	amap_table = group->amap_table[group_offset];
	if (!amap_table) {
		amap_table = amap_table_create(tdisk, group, atable_id, amap_spec.amap_table_block);
		if (unlikely(!amap_table)) {
			amap_table_group_unlock(group);
			status = NODE_STATUS_MEM_ALLOC_FAILURE;
			vm_pg_free(page);
			goto send;
		}
	}
	group_tail_amap_table(group, amap_table);
	amap_table_get(amap_table);
	amap_table_group_unlock(group);

	amap_id = amap_get_id(amap_spec.lba);
	amap_idx = amap_id - (amap_table->amap_table_id * AMAPS_PER_AMAP_TABLE);

	amap_table_lock(amap_table);
	amap = amap_table->amap_index[amap_idx];
	if (!amap) {
		amap = amap_create(amap_table, amap_id, amap_idx, amap_spec.block);
		if (unlikely(!amap))  {
			amap_table_unlock(amap_table);
			amap_table_put(amap_table);
			status = NODE_STATUS_MEM_ALLOC_FAILURE;
			vm_pg_free(page);
			goto send;
		}
	}

	amap_get(amap);
	amap_table_unlock(amap_table);
	amap_lock(amap);
	debug_check(amap->write_id == amap_spec.write_id);
	if (!write_id_greater(amap->write_id, amap_spec.write_id)) {
		vm_pg_free(amap->metadata);
		amap->metadata = page;
		amap->write_id = amap_spec.write_id;
		atomic_clear_bit_short(AMAP_META_DATA_INVALID, &amap->flags);
		atomic_set_bit_short(AMAP_META_IO_PENDING, &amap->flags);
		atomic_set_bit_short(AMAP_CSUM_CHECK_DONE, &amap->flags);
		if (atomic_test_bit_short(AMAP_META_DATA_NEW, &amap_spec.flags))
			atomic_set_bit_short(AMAP_META_DATA_NEW, &amap->flags);
	}
	else {
		vm_pg_free(page);
	}
	amap_unlock(amap);
	amap_put(amap);
	amap_table_put(amap_table);
	status = NODE_STATUS_OK;
send:
	raw->dxfer_len = 0;
	node_resp_msg(sock, raw, status);
	tdisk_put(tdisk);
	return;
}

void
node_amap_table_meta_sync_recv(struct node_sock *sock, struct raw_node_msg *raw)
{
	struct tdisk *tdisk;
	struct amap_table_spec amap_table_spec;
	struct amap_table *amap_table;
	struct amap_table_group *group;
	int retval, status;
	uint32_t atable_id, group_id, group_offset;

	tdisk = tdisk_locate(raw->target_id);
	if (unlikely(!tdisk)) {
		debug_warn("node cmd request for unknown tdisk %d\n", raw->target_id);
		node_error_resp_msg(sock, raw, NODE_STATUS_TARGET_NOT_FOUND);
		return;
	}

	debug_check(raw->dxfer_len != sizeof(amap_table_spec));
	retval = node_sock_read_nofail(sock, &amap_table_spec, sizeof(amap_table_spec));
	if (unlikely(retval != 0)) {
		tdisk_put(tdisk);
		return;
	}

	atable_id = amap_table_id(amap_table_spec.lba);
	group_id = amap_table_group_id(atable_id, &group_offset);

	group = tdisk->amap_table_group[group_id];
	tdisk_tail_group(tdisk, group);

	amap_table_group_lock(group);
	amap_table = group->amap_table[group_offset];
	if (!amap_table) {
		amap_table_group_unlock(group);
		goto out;
	}
	group_tail_amap_table(group, amap_table);
	amap_table_get(amap_table);
	amap_table_group_unlock(group);

	amap_table_lock(amap_table);
	atomic_clear_bit_short(ATABLE_META_DATA_NEW, &amap_table->flags);
	amap_table_unlock(amap_table);
	amap_table_put(amap_table);
out:
	status = NODE_STATUS_OK;
	raw->dxfer_len = 0;
	node_resp_msg(sock, raw, status);
	tdisk_put(tdisk);
	return;
}

void
node_amap_table_sync_post_recv(struct node_sock *sock, struct raw_node_msg *raw)
{
	struct tdisk *tdisk;
	struct amap_table_spec amap_table_spec;
	struct amap_table *amap_table;
	struct amap_table_group *group;
	int retval, status;
	uint32_t atable_id, group_id, group_offset;

	tdisk = tdisk_locate(raw->target_id);
	if (unlikely(!tdisk)) {
		debug_warn("node cmd request for unknown tdisk %d\n", raw->target_id);
		node_error_resp_msg(sock, raw, NODE_STATUS_TARGET_NOT_FOUND);
		return;
	}

	debug_check(raw->dxfer_len != sizeof(amap_table_spec));
	retval = node_sock_read_nofail(sock, &amap_table_spec, sizeof(amap_table_spec));
	if (unlikely(retval != 0)) {
		tdisk_put(tdisk);
		return;
	}

	atable_id = amap_table_id(amap_table_spec.lba);
	group_id = amap_table_group_id(atable_id, &group_offset);

	group = tdisk->amap_table_group[group_id];
	tdisk_tail_group(tdisk, group);

	amap_table_group_lock(group);
	amap_table = group->amap_table[group_offset];
	debug_check(!amap_table);
	group_tail_amap_table(group, amap_table);
	amap_table_get(amap_table);
	amap_table_group_unlock(group);

	amap_table_lock(amap_table);
	if (amap_table->write_id == amap_table_spec.write_id) {
		debug_check(!atomic_test_bit_short(ATABLE_META_IO_PENDING, &amap_table->flags));
		atomic_clear_bit_short(ATABLE_META_IO_PENDING, &amap_table->flags);
	}
	amap_table_unlock(amap_table);
	amap_table_put(amap_table);
	status = NODE_STATUS_OK;
	raw->dxfer_len = 0;
	node_resp_msg(sock, raw, status);
	tdisk_put(tdisk);
	return;
}

void
node_table_index_sync_recv(struct node_sock *sock, struct raw_node_msg *raw)
{
	struct tdisk *tdisk;
	pagestruct_t *page;
	struct amap_table_index *table_index;
	struct table_index_spec table_index_spec;
	int status, retval;

	tdisk = tdisk_locate(raw->target_id);
	if (unlikely(!tdisk)) {
		debug_warn("node cmd request for unknown tdisk %d\n", raw->target_id);
		node_error_resp_msg(sock, raw, NODE_STATUS_TARGET_NOT_FOUND);
		return;
	}

	debug_check(raw->dxfer_len != sizeof(table_index_spec));
	retval = node_sock_read_nofail(sock, &table_index_spec, sizeof(table_index_spec));
	if (unlikely(retval != 0)) {
		tdisk_put(tdisk);
		return;
	}

	page = vm_pg_alloc(0);
	if (unlikely(!page)) {
		status = NODE_STATUS_MEM_ALLOC_FAILURE;
		node_msg_discard_data(sock, LBA_SIZE); 
		goto send;
	}

	retval = node_sock_read_nofail(sock, vm_pg_address(page), LBA_SIZE);
	if (unlikely(retval != 0)) {
		vm_pg_free(page);
		tdisk_put(tdisk);
		return;
	}

	if (table_index_spec.csum != calc_csum16(vm_pg_address(page), LBA_SIZE)) {
		vm_pg_free(page);
		node_sock_read_error(sock);
		tdisk_put(tdisk);
		return;
	}

	debug_check(table_index_spec.table_index_id >= tdisk->table_index_max);
	table_index = &tdisk->table_index[table_index_spec.table_index_id];
	sx_xlock(table_index->table_index_lock);
	vm_pg_free(table_index->metadata);
	table_index->metadata = page;
	sx_xunlock(table_index->table_index_lock);
	status = NODE_STATUS_OK;
send:
	raw->dxfer_len = 0;
	node_resp_msg(sock, raw, status);
	tdisk_put(tdisk);
	return;
}

void
node_amap_table_sync_recv(struct node_sock *sock, struct raw_node_msg *raw)
{
	struct tdisk *tdisk;
	struct amap_table_spec amap_table_spec;
	struct amap_table *amap_table;
	struct amap_table_group *group;
	pagestruct_t *page;
	int retval, status;
	uint32_t atable_id, group_id, group_offset;

	tdisk = tdisk_locate(raw->target_id);
	if (unlikely(!tdisk)) {
		debug_warn("node cmd request for unknown tdisk %d\n", raw->target_id);
		node_error_resp_msg(sock, raw, NODE_STATUS_TARGET_NOT_FOUND);
		return;
	}

	debug_check(raw->dxfer_len != sizeof(amap_table_spec));
	retval = node_sock_read_nofail(sock, &amap_table_spec, sizeof(amap_table_spec));
	if (unlikely(retval != 0)) {
		tdisk_put(tdisk);
		return;
	}

	debug_check(!amap_table_spec.write_id);
	page = vm_pg_alloc(0);
	if (unlikely(!page)) {
		status = NODE_STATUS_MEM_ALLOC_FAILURE;
		node_msg_discard_data(sock, LBA_SIZE); 
		goto send;
	}

	retval = node_sock_read_nofail(sock, vm_pg_address(page), LBA_SIZE);
	if (unlikely(retval != 0)) {
		vm_pg_free(page);
		tdisk_put(tdisk);
		return;
	}

	if (amap_table_spec.csum != calc_csum16(vm_pg_address(page), LBA_SIZE)) {
		vm_pg_free(page);
		node_sock_read_error(sock);
		tdisk_put(tdisk);
		return;
	}

	atable_id = amap_table_id(amap_table_spec.lba);
	group_id = amap_table_group_id(atable_id, &group_offset);

	group = tdisk->amap_table_group[group_id];
	tdisk_tail_group(tdisk, group);

	amap_table_group_lock(group);
	amap_table = group->amap_table[group_offset];
	if (!amap_table) {
		amap_table = amap_table_create(tdisk, group, atable_id, amap_table_spec.block);
		if (unlikely(!amap_table))  {
			amap_table_group_unlock(group);
			status = NODE_STATUS_MEM_ALLOC_FAILURE;
			vm_pg_free(page);
			goto send;
		}
	}
	group_tail_amap_table(group, amap_table);
	amap_table_get(amap_table);
	amap_table_group_unlock(group);

	amap_table_lock(amap_table);
	debug_check(amap_table->write_id == amap_table_spec.write_id);
	if (!write_id_greater(amap_table->write_id, amap_table_spec.write_id)) { 
		vm_pg_free(amap_table->metadata);
		amap_table->metadata = page;
		amap_table->write_id = amap_table_spec.write_id;
		atomic_clear_bit_short(ATABLE_META_DATA_INVALID, &amap_table->flags);
		atomic_set_bit_short(ATABLE_META_IO_PENDING, &amap_table->flags);
		atomic_set_bit_short(ATABLE_CSUM_CHECK_DONE, &amap_table->flags);
		if (atomic_test_bit_short(ATABLE_META_DATA_NEW, &amap_table_spec.flags))
			atomic_set_bit_short(ATABLE_META_DATA_NEW, &amap_table->flags);
	}
	else {
		vm_pg_free(page);
	}
	if (atomic_test_bit_short(ATABLE_META_DATA_INVALID, &amap_table->flags))
		debug_warn("amap table write id %llu amap table spec write id %llu\n", (unsigned long long)amap_table->write_id, (unsigned long long)amap_table_spec.write_id);
	amap_table_unlock(amap_table);
	amap_table_put(amap_table);
	status = NODE_STATUS_OK;
send:
	raw->dxfer_len = 0;
	node_resp_msg(sock, raw, status);
	tdisk_put(tdisk);
	return;
}

static int
node_sync_send_page(struct node_msg *msg, pagestruct_t *page, int len, int timeout, int noresp)
{
	struct raw_node_msg *raw = msg->raw;
	struct node_comm *comm;
	struct node_sock *sock;
	int retval;

	comm = node_sync_comm_get();
	if (unlikely(!comm)) {
		node_sync_disable();
		return -1;
	}

	node_msg_compute_csum(msg->raw);
	sock = node_comm_get_sock(comm, NODE_GET_SOCK_TIMEOUT); /* waits till a sock is free */
	if (unlikely(!sock)) {
		debug_warn("Cannot get a free node sock cmd %d\n", raw->msg_cmd);
		node_comm_put(comm);
		node_sync_disable();
		return -1;
	}

	if (!noresp)
		node_cmd_hash_insert(comm->node_hash, msg, raw->msg_id);
	if (len)
		node_sock_start(sock);
	GLOB_INC(sync_send_bytes, (raw->dxfer_len + sizeof(*raw)));
	retval = node_sock_write(sock, raw);
	if (unlikely(retval != 0)) {
		if (len)
			node_sock_end(sock);
		if (!noresp)
			node_cmd_hash_remove(comm->node_hash, msg, raw->msg_id);
		node_sock_finish(sock);
		debug_warn("Communicating with remote failed cmd %d\n", raw->msg_cmd);
		node_comm_put(comm);
		node_sync_disable();
		return -1;
	}

	if (len) {
		GLOB_INC(sync_page_send_bytes, len);
		retval = node_sock_write_page(sock, page, len);
		node_sock_end(sock);
		if (unlikely(retval != 0)) {
			if (!noresp)
				node_cmd_hash_remove(comm->node_hash, msg, raw->msg_id);
			node_sock_finish(sock);
			debug_warn("Communicating with remote failed cmd %d\n", raw->msg_cmd);
			node_comm_put(comm);
			node_sync_disable();
			return -1;
		}
	}

	if (noresp) {
		node_sock_finish(sock);
		node_comm_put(comm);
		return 0;
	}

	node_msg_wait(msg, sock, timeout);
	retval = node_resp_status(msg);
	node_sock_finish(sock);
	node_comm_put(comm);
	if (unlikely(retval != 0)) {
		if (retval == NODE_STATUS_IS_MASTER)
			kern_panic("Invalid state, peer assumed master role, while we are still master\n");

		debug_warn("Failed to get a response from remote cmd %d retval %d msg timestamp %llu current %llu sock flags %d state %d\n", raw->msg_cmd, retval, (unsigned long long)msg->timestamp, (unsigned long long)ticks, sock->flags, sock->state);
		node_sync_disable();
		return -1;
	}
	return 0;
}

static struct log_page *
log_page_locate(struct log_spec *log_spec)
{
	struct bdevint *bint;
	struct log_group *group;
	struct log_page *log_page;

	bint = bdev_find(log_spec->bid);
	if (unlikely(!bint))
		return NULL;

	group = bint_find_log_group(bint, log_spec->group_id);
	debug_check(!group);
	if (unlikely(!group))
		return NULL;

	log_page = group->logs[log_spec->log_group_idx];
	return log_page;
}

void
node_log_sync_recv(struct node_sock *sock, struct raw_node_msg *raw)
{
	struct log_spec log_spec;
	struct log_page *log_page;
	int retval, status;
	pagestruct_t *page;

	retval = node_sock_read_nofail(sock, &log_spec, sizeof(log_spec));
	if (unlikely(retval != 0)) {
		return;
	}

	debug_check(!log_spec.write_id);
	log_page = log_page_locate(&log_spec);
	if (!log_page) {
		status = NODE_STATUS_INVALID_MSG;
		node_msg_discard_data(sock, LBA_SIZE); 
		goto send;
	}

	page = vm_pg_alloc(0);
	if (unlikely(!page)) {
		status = NODE_STATUS_MEM_ALLOC_FAILURE;
		node_msg_discard_data(sock, LBA_SIZE); 
		goto send;
	}

	retval = node_sock_read_nofail(sock, vm_pg_address(page), LBA_SIZE);
	if (unlikely(retval != 0)) {
		vm_pg_free(page);
		return;
	}

	if (log_spec.csum != calc_csum16(vm_pg_address(page), LBA_SIZE)) {
		vm_pg_free(page);
		node_sock_read_error(sock);
		return;
	}

	log_page_lock(log_page);
	debug_check(log_page->write_id == log_spec.write_id);
	if (!write_id_greater(log_page->write_id, log_spec.write_id)) {
		vm_pg_free(log_page->metadata);
		log_page->metadata = page;
		log_page->write_id = log_spec.write_id;
		atomic_set_bit_short(LOG_META_IO_PENDING, &log_page->flags);
	}
	else {
		vm_pg_free(page);
	}
	log_page_unlock(log_page);
	status = NODE_STATUS_OK;
send:
	raw->dxfer_len = 0;
	node_resp_msg(sock, raw, status);
	return;
}

void
node_log_sync_post_recv(struct node_sock *sock, struct raw_node_msg *raw)
{
	struct log_spec log_spec;
	struct log_page *log_page;
	int retval, status;

	retval = node_sock_read_nofail(sock, &log_spec, sizeof(log_spec));
	if (unlikely(retval != 0)) {
		return;
	}

	log_page = log_page_locate(&log_spec);
	if (!log_page) {
		status = NODE_STATUS_INVALID_MSG;
		goto send;
	}

	log_page_lock(log_page);
	if (log_spec.write_id == log_page->write_id) {
		debug_check(!atomic_test_bit_short(LOG_META_IO_PENDING, &log_page->flags));
		atomic_clear_bit_short(LOG_META_IO_PENDING, &log_page->flags);
	}
	log_page_unlock(log_page);
	status = NODE_STATUS_OK;
send:
	raw->dxfer_len = 0;
	node_resp_msg(sock, raw, status);
	return;
}

void
node_bintindex_sync_post_recv(struct node_sock *sock, struct raw_node_msg *raw)
{
	struct bintindex_spec bintindex_spec;
	struct bdevint *bint;
	struct bintindex *index;
	struct index_group *group;
	struct index_subgroup *subgroup;
	int retval, status;
	uint32_t subgroup_offset;

	retval = node_sock_read_nofail(sock, &bintindex_spec, sizeof(bintindex_spec));
	if (unlikely(retval != 0)) {
		return;
	}
	debug_check(!bintindex_spec.write_id);

	bint = bdev_find(bintindex_spec.bid);
	if (unlikely(!bint)) {
		status = NODE_STATUS_INVALID_MSG;
		goto send;
	}

	debug_check(bintindex_spec.group_id >= bint->max_index_groups);
	group = bint->index_groups[bintindex_spec.group_id];

	debug_check(bintindex_spec.subgroup_id >= group->max_subgroups);
	subgroup = group->subgroups[bintindex_spec.subgroup_id];

	index_subgroup_id(bintindex_spec.index_id, &subgroup_offset); 
	sx_xlock(subgroup->subgroup_lock);
	index = subgroup_get_index(subgroup, bintindex_spec.index_id, 0);
	sx_xunlock(subgroup->subgroup_lock);
	if (unlikely(!index)) {
		status = NODE_STATUS_MEM_ALLOC_FAILURE;
		goto send;
	}

	index_lock(index);
	if (index->write_id == bintindex_spec.write_id) {
		debug_check(!atomic_test_bit(META_IO_PENDING, &index->flags));
		atomic_clear_bit(META_IO_PENDING, &index->flags);
	}
	index_unlock(index);
	index_put(index);
	status = NODE_STATUS_OK;
send:
	raw->dxfer_len = 0;
	node_resp_msg(sock, raw, status);
}

void
node_bintindex_sync_recv(struct node_sock *sock, struct raw_node_msg *raw)
{
	struct bintindex_spec bintindex_spec;
	struct bdevint *bint;
	struct bintindex *index;
	struct index_group *group;
	struct index_subgroup *subgroup;
	int retval, status;
	pagestruct_t *page;
	uint32_t subgroup_offset;

	retval = node_sock_read_nofail(sock, &bintindex_spec, sizeof(bintindex_spec));
	if (unlikely(retval != 0)) {
		return;
	}
	debug_check(!bintindex_spec.write_id);

	bint = bdev_find(bintindex_spec.bid);
	if (unlikely(!bint)) {
		status = NODE_STATUS_INVALID_MSG;
		node_msg_discard_data(sock, LBA_SIZE); 
		goto send;
	}

	page = vm_pg_alloc(0);
	if (unlikely(!page)) {
		status = NODE_STATUS_MEM_ALLOC_FAILURE;
		node_msg_discard_data(sock, LBA_SIZE); 
		goto send;
	}

	retval = node_sock_read_nofail(sock, vm_pg_address(page), LBA_SIZE);
	if (unlikely(retval != 0)) {
		vm_pg_free(page);
		return;
	}

	if (bintindex_spec.csum != calc_csum16(vm_pg_address(page), LBA_SIZE)) {
		vm_pg_free(page);
		node_sock_read_error(sock);
		return;
	}

	debug_check(bintindex_spec.group_id >= bint->max_index_groups);
	debug_check(!bint->index_groups);
	group = bint->index_groups[bintindex_spec.group_id];
	debug_check(!group);
	debug_check(bintindex_spec.subgroup_id >= group->max_subgroups);
	subgroup = group->subgroups[bintindex_spec.subgroup_id];

	index_subgroup_id(bintindex_spec.index_id, &subgroup_offset); 
	sx_xlock(subgroup->subgroup_lock);
	index = subgroup_get_index(subgroup, bintindex_spec.index_id, 0);
	sx_xunlock(subgroup->subgroup_lock);

	if (unlikely(!index)) {
		status = NODE_STATUS_MEM_ALLOC_FAILURE;
		vm_pg_free(page);
		goto send;
	}
	index_lock(index);
	debug_check(index->write_id == bintindex_spec.write_id);
	if (!write_id_greater(index->write_id, bintindex_spec.write_id)) {
		vm_pg_free(index->metadata);
		index->metadata = page;
		index->write_id = bintindex_spec.write_id;
		atomic_clear_bit(META_IO_READ_PENDING, &index->flags);
		atomic_clear_bit(META_LOAD_DONE, &index->flags);
		atomic_set_bit(META_IO_PENDING, &index->flags);
		atomic_set_bit(META_CSUM_CHECK_DONE, &index->flags);
	}
	else {
		vm_pg_free(page);
	}
	index_unlock(index);
	index_put(index);
	status = NODE_STATUS_OK;
send:
	raw->dxfer_len = 0;
	node_resp_msg(sock, raw, status);
}

static struct index_lookup *
ilookup_locate(struct ilookup_spec *ilookup_spec)
{
	struct bdevint *bint;
	struct index_group *group;

	bint = bdev_find(ilookup_spec->bid);
	if (unlikely(!bint))
		return NULL;

	debug_check(ilookup_spec->group_id >= bint->max_index_groups);
	group = bint->index_groups[ilookup_spec->group_id];
	return group->index_lookup;
}

void
node_index_lookup_sync_recv(struct node_sock *sock, struct raw_node_msg *raw)
{
	struct ilookup_spec ilookup_spec;
	struct index_lookup *ilookup;
	int retval, status;
	pagestruct_t *page;

	retval = node_sock_read_nofail(sock, &ilookup_spec, sizeof(ilookup_spec));
	if (unlikely(retval != 0)) {
		return;
	}

	ilookup = ilookup_locate(&ilookup_spec);
	if (!ilookup) {
		status = NODE_STATUS_INVALID_MSG;
		node_msg_discard_data(sock, LBA_SIZE); 
		goto send;
	}

	page = vm_pg_alloc(0);
	if (unlikely(!page)) {
		status = NODE_STATUS_MEM_ALLOC_FAILURE;
		node_msg_discard_data(sock, LBA_SIZE); 
		goto send;
	}

	retval = node_sock_read_nofail(sock, vm_pg_address(page), LBA_SIZE);
	if (unlikely(retval != 0)) {
		vm_pg_free(page);
		return;
	}

	if (ilookup_spec.csum != calc_csum16(vm_pg_address(page), LBA_SIZE)) {
		vm_pg_free(page);
		node_sock_read_error(sock);
		return;
	}

	mtx_lock(ilookup->lookup_lock);
	vm_pg_free(ilookup->metadata);
	ilookup->metadata = page;
	mtx_unlock(ilookup->lookup_lock);
	status = NODE_STATUS_OK;
send:
	raw->dxfer_len = 0;
	node_resp_msg(sock, raw, status);
	return;
}

static struct ddtable_ddlookup_node *
ddlookup_locate(struct ddtable *ddtable, struct ddlookup_spec *ddlookup_spec, pagestruct_t *metadata, int alloc, int *done_alloc)
{
	struct ddtable_node *node;
	struct ddtable_ddlookup_node *ddlookup = NULL, *child = NULL, *last = NULL;
	struct ddlookup_list *ddlookup_list;


	node = node_get(ddtable, BLOCK_BLOCKNR(ddlookup_spec->block));
	ddlookup = node_ddlookup(node, BLOCK_BLOCKNR(ddlookup_spec->block));
	if (ddlookup) {
		if (!ddlookup->ddlookup_list && ddlookup_spec->hash_id >= 0) {
			ddlookup_list = ddlookup_list_get(ddtable, ddlookup_spec->hash_id);
			ddlookup->ddlookup_list = ddlookup_list;
		}
		node_unlock(node);
		return ddlookup;
	}

	ddlookup = ddtable_ddlookup_node_alloc(VM_ALLOC_ZERO);
	if (unlikely(!ddlookup)) {
		node_unlock(node);
		return NULL;
	}

	ddlookup->b_start = BLOCK_BLOCKNR(ddlookup_spec->block);
	ddlookup->write_id = ddlookup_spec->write_id;
	ddlookup->metadata = metadata;
	atomic_set_bit_short(DDLOOKUP_DONE_LOAD, &ddlookup->flags);
	ddlookup->num_entries = ddlookup_spec->num_entries;
	ddtable_ddlookup_node_dirty(ddtable, ddlookup);
	ddtable_ddlookup_node_get(ddlookup);
	ddtable_check_count(ddtable);
	DD_INC(sync_load, 1);
	if (ddlookup_spec->hash_id >= 0) {
		ddlookup_list = ddlookup_list_get(ddtable, ddlookup_spec->hash_id);
		ddlookup_list_lock(ddlookup_list);
		SLIST_FOREACH(child, &ddlookup_list->lhead, p_list) {
			last = child;
			if (child->b_start == ddlookup_spec->prev_b_start)
				break;
		}
		if (child)
			SLIST_INSERT_AFTER(child, ddlookup, p_list);
		else if (last)
			SLIST_INSERT_AFTER(last, ddlookup, p_list);
		else
			SLIST_INSERT_HEAD(&ddlookup_list->lhead, ddlookup, p_list); 
		ddlookup_list_unlock(ddlookup_list);
	}
	node_insert(ddtable, node, ddlookup);
	node_unlock(node);

	*done_alloc = 1;
	return ddlookup;
}

void
node_ddlookup_sync_post_recv(struct node_sock *sock, struct raw_node_msg *raw)
{
	struct ddlookup_spec ddlookup_spec;
	struct ddtable_ddlookup_node *ddlookup;
	struct ddtable *ddtable;
	struct bdevgroup *group;
	int retval, status;

	retval = node_sock_read_nofail(sock, &ddlookup_spec, sizeof(ddlookup_spec));
	if (unlikely(retval != 0)) {
		return;
	}

	group = bdev_group_locate(ddlookup_spec.group_id, NULL);
	if (!group || !atomic_read(&group->ddtable.inited)) {
		status = NODE_STATUS_INVALID_MSG;
		goto send;
	}

	ddtable = bdev_group_ddtable(group);
	ddlookup = ddlookup_locate(ddtable, &ddlookup_spec, 0, 0, NULL);
	if (unlikely(!ddlookup)) {
		status = NODE_STATUS_OK;
		goto send;
	}

	node_ddlookup_lock(ddlookup);
	if (ddlookup->write_id == ddlookup_spec.write_id) {
		debug_check(!atomic_test_bit_short(DDLOOKUP_META_IO_PENDING, &ddlookup->flags));
		atomic_clear_bit_short(DDLOOKUP_META_IO_PENDING, &ddlookup->flags);
		atomic_clear_bit_short(DDLOOKUP_META_DATA_NEEDS_SYNC, &ddlookup->flags);
		ddtable_decr_sync_count(ddtable, ddlookup);
	}
	node_ddlookup_unlock(ddlookup);
	ddtable_ddlookup_node_put(ddlookup);
	status = NODE_STATUS_OK;

send:
	raw->dxfer_len = 0;
	node_resp_msg(sock, raw, status);
}

void
node_ddlookup_sync_recv(struct node_sock *sock, struct raw_node_msg *raw)
{
	struct ddlookup_spec ddlookup_spec;
	struct ddtable_ddlookup_node *ddlookup;
	struct bdevgroup *group;
	struct ddtable *ddtable;
	int retval, status, done_alloc = 0;
	pagestruct_t *page;

	retval = node_sock_read_nofail(sock, &ddlookup_spec, sizeof(ddlookup_spec));
	if (unlikely(retval != 0)) {
		return;
	}

	group = bdev_group_locate(ddlookup_spec.group_id, NULL);
	if (unlikely(!group)) {
		status = NODE_STATUS_INVALID_MSG;
		node_msg_discard_data(sock, LBA_SIZE); 
		goto send;
	}

	ddtable = bdev_group_ddtable(group);
	page = vm_pg_alloc(0);
	if (unlikely(!page)) {
		status = NODE_STATUS_MEM_ALLOC_FAILURE;
		node_msg_discard_data(sock, LBA_SIZE); 
		goto send;
	}

	retval = node_sock_read_nofail(sock, vm_pg_address(page), LBA_SIZE);
	if (unlikely(retval != 0)) {
		vm_pg_free(page);
		return;
	}

	if (ddlookup_spec.csum != calc_csum16(vm_pg_address(page), LBA_SIZE)) {
		vm_pg_free(page);
		node_sock_read_error(sock);
		return;
	}

	ddlookup = ddlookup_locate(ddtable, &ddlookup_spec, page, 1, &done_alloc);
	if (!ddlookup) {
		vm_pg_free(page);
		status = NODE_STATUS_INVALID_MSG;
		goto send;
	}

	if (done_alloc) {
		ddtable_ddlookup_node_put(ddlookup);
		status = NODE_STATUS_OK;
		goto send;
	}

	if (atomic_test_bit_short(DDLOOKUP_META_DATA_READ_DIRTY, &ddlookup->flags))
		wait_on_chan(ddlookup->ddlookup_wait, !atomic_test_bit_short(DDLOOKUP_META_DATA_READ_DIRTY, &ddlookup->flags));

	node_ddlookup_lock(ddlookup);
	if (!write_id_greater(ddlookup->write_id, ddlookup_spec.write_id)) { 
		vm_pg_free(ddlookup->metadata);
		ddlookup->metadata = page;
		ddlookup->write_id = ddlookup_spec.write_id;
		atomic_set_bit_short(DDLOOKUP_DONE_LOAD, &ddlookup->flags);
		ddlookup->num_entries = ddlookup_spec.num_entries;
		ddtable_ddlookup_node_dirty(ddtable, ddlookup);
	}
	else {
		vm_pg_free(page);
	}
	node_ddlookup_unlock(ddlookup);
	ddtable_ddlookup_node_put(ddlookup);
	status = NODE_STATUS_OK;
send:
	raw->dxfer_len = 0;
	node_resp_msg(sock, raw, status);
	return;
}

void
node_bint_delete_recv(struct node_sock *sock, struct raw_node_msg *raw)
{
	struct bint_spec bint_spec;
	struct bdevint *bint; 
	int retval;

	retval = node_sock_read_nofail(sock, &bint_spec, sizeof(bint_spec));
	if (unlikely(retval != 0)) {
		return;
	}

	sx_xlock(gchain_lock);
	bint = bdev_find(bint_spec.bid);
	if (!bint)
		goto out;

	if (bint->log_disk) {
		struct bdevgroup *bdevgroup = bint->group;

		debug_check(bdevgroup->reserved_log_entries);
		bdev_log_remove(bint, 1);
		bdev_log_list_remove(bint, 1);
	}

	bdev_list_remove(bint);
	if (bint->ddmaster)
		ddtable_exit(&bint->group->ddtable);

	bint_free(bint, 0);
out:
	sx_xunlock(gchain_lock);

	raw->dxfer_len = 0;
	node_resp_msg(sock, raw, NODE_STATUS_OK);

}

void
node_bint_sync_recv(struct node_sock *sock, struct raw_node_msg *raw)
{
	struct bint_spec bint_spec;
	struct bdevint *bint; 
	int retval, status;
	int ddbits;

	retval = node_sock_read_nofail(sock, &bint_spec, sizeof(bint_spec));
	if (unlikely(retval != 0)) {
		return;
	}

	bint = bdev_find(bint_spec.bid);
	if (!bint) {
		debug_warn("Cannot find bid at %u\n", bint_spec.bid);
		status = NODE_STATUS_INVALID_MSG;
		goto send;
	}

	if (atomic_test_bit(BINT_LOAD_DONE, &bint->flags))
		goto setstats;

	if (bint->sector_shift != bint_spec.sector_shift) {
		debug_warn("sector shift mismatch %u %u\n", bint->sector_shift, bint_spec.sector_shift);
		status = NODE_STATUS_ERROR;
		goto send;
	}
	if (bint_spec.ddmaster) {
		ddbits = calc_ddbits();
		if (node_type_master() && ddbits < bint_spec.ddbits) {
			debug_warn("HA node has insuffient memory to operate as as a standby node\n");
			status = NODE_STATUS_ERROR;
			goto send;
		}
	}

	debug_info("bint spec ddmaster %d\n", bint_spec.ddmaster);
	bint->ddmaster = bint_spec.ddmaster;
	bint->ddbits = bint_spec.ddbits;
	bint->log_disk = bint_spec.log_disk;
	bint->group_flags = bint_spec.group_flags;
	bint->log_disks = bint_spec.log_disks;
	bint->v2_disk = bint_spec.v2_disk;
	bint->v2_log_format = bint_spec.v2_log_format;
	bint->rid_set = bint_spec.rid_set;
	memcpy(bint->mrid, bint_spec.mrid, sizeof(bint->mrid));

	if (bint_is_group_master(bint))
		bint_set_group_master(bint);

	if (bint->log_disk) {
		retval = bint_create_logs(bint, QS_IO_READ, MAX_LOG_PAGES, LOG_PAGES_OFFSET);
		if (unlikely(retval != 0)) {
			debug_warn("Failed to create/load log pages\n");
			status = NODE_STATUS_ERROR;
			goto send;
		}
		bdev_log_list_insert(bint);
		atomic_inc(&ddtable_global.cur_log_disks);
	}

	if (bint->ddmaster) {
		debug_info("load ddtable\n");
		retval = ddtable_load(&bint->group->ddtable, bint);
		if (unlikely(retval != 0)) {
			debug_warn("Failed to create/load ddtable\n");
			status = NODE_STATUS_ERROR;
			goto send;
		}
		calc_mem_restrictions(bint_spec.availmem);
		calc_rcache_bits();
	}

	bint->enable_comp = bint_spec.enable_comp;
	__bint_set_free(bint, bint_spec.free);
	bint->usize = bint_spec.usize;
	bint_initialize_blocks(bint, 0);
	retval = bint_initialize_groups(bint, 0, 0);
	if (unlikely(retval != 0)) {
		status = NODE_STATUS_ERROR;
		goto send;
	}

	retval = kernel_thread_create(bint_sync_thread, bint, bint->sync_task, "synct%u", bint->bid);
	if (unlikely(retval != 0)) {
		status = NODE_STATUS_ERROR;
		goto send;
	}

	retval = kernel_thread_create(bint_load_thread, bint, bint->load_task, "loadt%u", bint->bid);
	if (unlikely(retval != 0)) {
		status = NODE_STATUS_ERROR;
		goto send;
	}

	retval = kernel_thread_create(bint_free_thread, bint, bint->free_task, "bintfreet%u", bint->bid);
	if (unlikely(retval != 0)) {
		status = NODE_STATUS_ERROR;
		goto send;
	}

setstats:
	bint_lock(bint);
	bint->initialized = 1;
	__bint_set_free(bint, bint_spec.free);
	atomic_set_bit(BINT_LOAD_DONE, &bint->flags);
	memcpy(&bint->stats, &bint_spec.bint_stats, sizeof(bint->stats));
	bint_unlock(bint);
	status = NODE_STATUS_OK;

	if (bint_is_ha_disk(bint))
		bdev_group_set_ha_bint(bint);
	else
		bdev_group_clear_ha_bint(bint);
send:
	raw->dxfer_len = 0;
	node_resp_msg(sock, raw, status);
	return;
}

static int
__node_ddlookup_sync_send(struct ddtable *ddtable, struct ddtable_ddlookup_node *ddlookup, int32_t hash_id, uint64_t prev_b_start)
{
	struct ddlookup_spec *ddlookup_spec;
	struct node_msg *msg;
	int retval;
#ifdef ENABLE_STATS
	uint32_t start_ticks;
#endif

	GLOB_TSTART(start_ticks);
	msg = node_sync_msg_alloc(sizeof(*ddlookup_spec), NODE_MSG_DDLOOKUP_SYNC);
	ddlookup_spec = (struct ddlookup_spec *)(msg->raw->data);
	ddlookup->write_id = write_id_incr(ddlookup->write_id, 1);
	ddlookup_spec->write_id = ddlookup->write_id;
	ddlookup_spec->hash_id = hash_id;
	ddlookup_spec->group_id = ddtable->bint->group->group_id;
	ddlookup_spec->prev_b_start = prev_b_start;
	ddlookup_spec->num_entries = ddlookup->num_entries;
	SET_BLOCK(ddlookup_spec->block, ddlookup->b_start, ddtable->bint->bid);
	ddlookup_spec->csum = calc_csum16(vm_pg_address(ddlookup->metadata), LBA_SIZE); 
	retval = node_sync_send_page(msg, ddlookup->metadata, LBA_SIZE, node_sync_timeout, 0);
	node_msg_free(msg);
	GLOB_TEND(ddlookup_sync_ticks, start_ticks);
	GLOB_INC(ddlookup_sync_count, 1);
	if (retval == 0)
		atomic_clear_bit_short(DDLOOKUP_META_DATA_NEEDS_SYNC, &ddlookup->flags);
	return retval;
}
 
static void
node_sync_post_ddlookup_insert(struct ddtable *ddtable, struct ddtable_ddlookup_node *ddlookup)
{
	struct node_ddlookup_sync_post *ddlookup_post;
	struct node_sync_post *post;

	ddlookup_post = zalloc(sizeof(*ddlookup_post), M_QUADSTOR, M_WAITOK);
	ddlookup_post->ddlookup = ddlookup;
	ddlookup_post->ddtable = ddtable;

	post = __uma_zalloc(node_sync_post_cache, Q_WAITOK | Q_ZERO, sizeof(*post));
	ddtable_ddlookup_node_get(ddlookup);
	post->write_id = ddlookup->write_id;
	post->priv = ddlookup_post;
	post->type = NODE_SYNC_TYPE_DDLOOKUP;
	atomic_inc(&ddtable->inited);
	node_sync_post_insert(post);
}

int
node_ddlookup_sync_send(struct ddtable *ddtable, struct ddtable_ddlookup_node *ddlookup, int32_t hash_id, uint64_t prev_b_start)
{
	int retval = 0;

	if (!node_sync_enabled() || !node_ddtable_sync_enabled(ddtable)) {
		atomic_clear_bit_short(DDLOOKUP_META_DATA_NEEDS_SYNC, &ddlookup->flags);
		return 0;
	}

	if (atomic_test_bit_short(DDLOOKUP_META_DATA_NEEDS_SYNC, &ddlookup->flags)) {
		retval =  __node_ddlookup_sync_send(ddtable, ddlookup, hash_id, prev_b_start);
		atomic_clear_bit_short(DDLOOKUP_META_DATA_NEEDS_SYNC, &ddlookup->flags);
	}
	if (retval == 0)
		node_sync_post_ddlookup_insert(ddtable, ddlookup);
	return retval;
}

static void
node_sync_post_log_insert(struct log_page *log_page, struct tcache *tcache)
{
	struct node_sync_post *post;

	post = __uma_zalloc(node_sync_post_cache, Q_WAITOK | Q_ZERO, sizeof(*post));
	post->priv = log_page;
	post->write_id = log_page->write_id;
	post->type = NODE_SYNC_TYPE_LOG;
	init_iowaiter(&post->iowaiter);
	SLIST_INSERT_HEAD(&tcache->io_waiters, &post->iowaiter, w_list);
	atomic_inc(&log_page->group->bint->post_writes);
	log_page_get(log_page);
	node_sync_post_insert(post);
}

int
node_log_sync_send(struct log_page *log_page, struct tcache *tcache)
{
	struct log_spec *log_spec;
	struct node_msg *msg;
	int retval;
#ifdef ENABLE_STATS
	uint32_t start_ticks;
#endif

	GLOB_TSTART(start_ticks);
	if (!node_sync_enabled() || !node_bint_sync_enabled(log_page->group->bint)) {
		if (node_sync_enabled())
			log_page->write_id = write_id_incr(log_page->write_id, 1);
		return 0;
	}

	msg = node_sync_msg_alloc(sizeof(*log_spec), NODE_MSG_LOG_SYNC);
	log_spec = (struct log_spec *)(msg->raw->data);
	log_page->write_id = write_id_incr(log_page->write_id, 1);
	log_spec->write_id = log_page->write_id;
	log_spec->bid = log_page->group->bint->bid;
	log_spec->group_id = log_page->group->group_id;
	log_spec->log_group_idx = log_page->log_group_idx;
	log_spec->csum = calc_csum16(vm_pg_address(log_page->metadata), LBA_SIZE); 
	retval = node_sync_send_page(msg, log_page->metadata, LBA_SIZE, node_sync_timeout, 0);
	node_msg_free(msg);
	if (retval == 0 && tcache)
		node_sync_post_log_insert(log_page, tcache);
	GLOB_TEND(log_sync_ticks, start_ticks);
	GLOB_INC(log_sync_count, 1);
	return retval;
}

int
node_log_sync_post_send(struct log_page *log_page)
{
	struct log_spec *log_spec;
	struct node_msg *msg;
	int retval;
#ifdef ENABLE_STATS
	uint32_t start_ticks;
#endif

	GLOB_TSTART(start_ticks);
	if (!node_sync_enabled() || !node_bint_sync_enabled(log_page->group->bint))
		return 0;

	msg = node_sync_msg_alloc(sizeof(*log_spec), NODE_MSG_LOG_SYNC_POST);
	log_spec = (struct log_spec *)(msg->raw->data);
	log_spec->write_id = log_page->write_id;
	log_spec->bid = log_page->group->bint->bid;
	log_spec->group_id = log_page->group->group_id;
	log_spec->log_group_idx = log_page->log_group_idx;
	retval = node_sync_send_page(msg, NULL, 0, node_sync_timeout, 0);
	node_msg_free(msg);
	GLOB_TEND(log_sync_post_ticks, start_ticks);
	GLOB_INC(log_sync_post_count, 1);
	return retval;
}

int
node_index_lookup_sync_send(struct index_group *group, pagestruct_t *page)
{
	struct ilookup_spec *ilookup_spec;
	struct node_msg *msg;
	int retval;
#ifdef ENABLE_STATS
	uint32_t start_ticks;
#endif

	GLOB_TSTART(start_ticks);
	if (!node_sync_enabled() || !node_bint_sync_enabled(group->bint))
		return 0;

	msg = node_sync_msg_alloc(sizeof(*ilookup_spec), NODE_MSG_INDEX_LOOKUP_SYNC);
	ilookup_spec = (struct ilookup_spec *)(msg->raw->data);
	ilookup_spec->bid = group->bint->bid;
	ilookup_spec->group_id = group->group_id;
	ilookup_spec->csum = calc_csum16(vm_pg_address(page), LBA_SIZE); 

	retval = node_sync_send_page(msg, page, LBA_SIZE, node_sync_timeout, 0);
	node_msg_free(msg);
	GLOB_TEND(index_lookup_sync_ticks, start_ticks);
	GLOB_INC(index_lookup_sync_count, 1);
	return retval;
}

static void
node_sync_post_bintindex_insert(struct bintindex *index, struct tcache *tcache)
{
	struct node_sync_post *post;

	post = __uma_zalloc(node_sync_post_cache, Q_WAITOK | Q_ZERO, sizeof(*post));
	index_get(index);
	post->priv = index;
	post->write_id = index->write_id;
	post->type = NODE_SYNC_TYPE_BINTINDEX;
	init_iowaiter(&post->iowaiter);
	SLIST_INSERT_HEAD(&tcache->io_waiters, &post->iowaiter, w_list);
	atomic_inc(&index->subgroup->group->bint->post_writes);
	node_sync_post_insert(post);
}

int
node_bintindex_sync_send(struct bintindex *index, struct tcache *tcache, pagestruct_t *metadata, uint64_t write_id)
{
	struct index_subgroup *subgroup = index->subgroup;
	struct index_group *group = subgroup->group;
	struct bdevint *bint = group->bint;
	struct bintindex_spec *bintindex_spec;
	struct node_msg *msg;
	int retval;
#ifdef ENABLE_STATS
	uint32_t start_ticks;
#endif

	GLOB_TSTART(start_ticks);
	if (!node_sync_enabled() || !node_bint_sync_enabled(bint))
		return 0;

	msg = node_sync_msg_alloc(sizeof(*bintindex_spec), NODE_MSG_BINT_INDEX_SYNC);
	bintindex_spec = (struct bintindex_spec *)(msg->raw->data);
	bintindex_spec->write_id = write_id;
	bintindex_spec->bid = bint->bid;
	bintindex_spec->group_id = group->group_id;
	bintindex_spec->subgroup_id = subgroup->subgroup_id;
	bintindex_spec->index_id = index->index_id;
	bintindex_spec->csum = calc_csum16(vm_pg_address(metadata), LBA_SIZE); 
	retval = node_sync_send_page(msg, metadata, LBA_SIZE, node_sync_timeout, 0);
	node_msg_free(msg);
	if (retval == 0)
		node_sync_post_bintindex_insert(index, tcache);
	GLOB_TEND(index_sync_ticks, start_ticks);
	GLOB_INC(index_sync_count, 1);
	return retval;
}

static void
node_sync_post_amap_insert(struct amap *amap)
{
	struct node_sync_post *post;

	post = __uma_zalloc(node_sync_post_cache, Q_WAITOK | Q_ZERO, sizeof(*post));
	amap_get(amap);
	tdisk_get(amap->amap_table->tdisk);
	post->priv = amap;
	post->write_id = amap->write_id;
	post->type = NODE_SYNC_TYPE_AMAP;
	init_iowaiter(&post->iowaiter);
	SLIST_INSERT_HEAD(&amap->io_waiters, &post->iowaiter, w_list);
	node_sync_post_insert(post);
}

int
node_amap_sync_send(struct amap *amap)
{
	struct tdisk *tdisk = amap->amap_table->tdisk;
	struct amap_spec *amap_spec;
	struct node_msg *msg;
	uint64_t lba;
	int retval;
#ifdef ENABLE_STATS
	uint32_t start_ticks;
#endif

	GLOB_TSTART(start_ticks);
	if (!node_sync_enabled() || !node_tdisk_sync_enabled(tdisk))
		return 0;

	lba = amap_get_lba_start(amap->amap_id);
	msg = node_sync_msg_alloc(sizeof(*amap_spec), NODE_MSG_AMAP_SYNC);
	amap_spec = (struct amap_spec *)(msg->raw->data);
	amap_spec->write_id = amap->write_id;
	amap_spec->lba = lba;
	amap_spec->block = amap->amap_block;
	amap_spec->amap_table_block = amap->amap_table->amap_table_block;
	amap_spec->flags = amap->flags;
	amap_spec->csum = calc_csum16(vm_pg_address(amap->metadata), LBA_SIZE); 
	msg->raw->target_id = amap->amap_table->tdisk->target_id;

	retval = node_sync_send_page(msg, amap->metadata, AMAP_SIZE, node_sync_timeout, 0);
	node_msg_free(msg);
	if (retval == 0)
		node_sync_post_amap_insert(amap);
	GLOB_TEND(amap_sync_ticks, start_ticks);
	GLOB_INC(amap_sync_count, 1);
	return retval;
}

int
node_amap_meta_sync_send(struct amap *amap)
{
	struct tdisk *tdisk = amap->amap_table->tdisk;
	struct amap_spec *amap_spec;
	struct node_msg *msg;
	uint64_t lba;
	int retval;
#ifdef ENABLE_STATS
	uint32_t start_ticks;
#endif

	GLOB_TSTART(start_ticks);
	if (!node_sync_enabled() || !node_tdisk_sync_enabled(tdisk))
		return 0;

	lba = amap_get_lba_start(amap->amap_id);
	msg = node_sync_msg_alloc(sizeof(*amap_spec), NODE_MSG_AMAP_META_SYNC);
	amap_spec = (struct amap_spec *)(msg->raw->data);
	amap_spec->lba = lba;
	amap_spec->block = amap->amap_block;
	amap_spec->amap_table_block = amap->amap_table->amap_table_block;
	amap_spec->flags = amap->flags;
	msg->raw->target_id = amap->amap_table->tdisk->target_id;

	retval = node_sync_send_page(msg, NULL, 0, node_sync_timeout, 0);
	node_msg_free(msg);
	GLOB_TEND(amap_meta_sync_ticks, start_ticks);
	GLOB_INC(amap_meta_sync_ticks, 1);
	return retval;
}

static void
node_sync_post_amap_table_insert(struct amap_table *amap_table)
{
	struct node_sync_post *post;

	post = __uma_zalloc(node_sync_post_cache, Q_WAITOK | Q_ZERO, sizeof(*post));
	amap_table_get(amap_table);
	tdisk_get(amap_table->tdisk);
	post->priv = amap_table;
	post->write_id = amap_table->write_id;
	post->type = NODE_SYNC_TYPE_AMAP_TABLE;
	init_iowaiter(&post->iowaiter);
	SLIST_INSERT_HEAD(&amap_table->io_waiters, &post->iowaiter, w_list);
	node_sync_post_insert(post);
}

static int
__node_table_index_sync_send(struct tdisk *tdisk, struct amap_table_index *table_index, uint32_t table_index_id)
{
	struct table_index_spec *table_index_spec;
	struct node_msg *msg;
	int retval;
#ifdef ENABLE_STATS
	uint32_t start_ticks;
#endif

	GLOB_TSTART(start_ticks);
	msg = node_sync_msg_alloc(sizeof(*table_index_spec), NODE_MSG_TABLE_INDEX_SYNC);
	table_index_spec = (struct table_index_spec *)(msg->raw->data);
	table_index_spec->table_index_id = table_index_id;
	table_index_spec->csum = calc_csum16(vm_pg_address(table_index->metadata), LBA_SIZE); 

	msg->raw->target_id = tdisk->target_id;
	retval = node_sync_send_page(msg, table_index->metadata, LBA_SIZE, node_sync_timeout, 0);
	node_msg_free(msg);
	GLOB_TEND(table_index_sync_ticks, start_ticks);
	GLOB_INC(table_index_sync_ticks, 1);
	return retval;
}

int
node_table_index_sync_send(struct tdisk *tdisk, struct amap_table_index *table_index, uint32_t table_index_id)
{
	if (!node_sync_enabled() || !node_tdisk_sync_enabled(tdisk))
		return 0;

	return __node_table_index_sync_send(tdisk, table_index, table_index_id);
}

int
node_reservation_sync_send(struct tdisk *tdisk, struct reservation *reservation)
{
	struct reservation_spec *reservation_spec;
	struct node_msg *msg;
	int retval;
#ifdef ENABLE_STATS
	uint32_t start_ticks;
#endif

	GLOB_TSTART(start_ticks);
	if (!node_sync_enabled() || !node_tdisk_sync_enabled(tdisk))
		return 0;

	msg = node_sync_msg_alloc(sizeof(*reservation_spec), NODE_MSG_RESERVATION_SYNC);
	reservation_spec = (struct reservation_spec *)(msg->raw->data);
	reservation_spec_fill(reservation, reservation_spec);

	msg->raw->target_id = tdisk->target_id;
	retval = node_sync_send_page(msg, NULL, 0, node_sync_timeout, 0);
	node_msg_free(msg);
	GLOB_TEND(reservation_sync_ticks, start_ticks);
	GLOB_INC(reservation_sync_count, 1);
	return retval;
}

static int
node_sense_state_send(struct tdisk *tdisk, struct initiator_state *istate, struct node_msg *msg)
{
	struct raw_node_msg *raw;
	struct istate_spec *istate_spec;
	struct sense_spec *sense_spec;
	struct sense_info *iter;
	struct qs_sense_data *sense_data;
	int retval, i;
#ifdef ENABLE_STATS
	uint32_t start_ticks;
#endif

	GLOB_TSTART(start_ticks);
	if (!node_sync_enabled() || !node_tdisk_sync_enabled(tdisk))
		return 0;

	mtx_lock(istate->istate_lock);
	if (SLIST_EMPTY(&istate->sense_list)) {
		mtx_unlock(istate->istate_lock);
		return 0;
	}

	raw = msg->raw;
	bzero(raw->data, raw->dxfer_len);
	istate_spec = (struct istate_spec *)(raw->data);
	port_fill(istate_spec->i_prt, istate->i_prt);
	port_fill(istate_spec->t_prt, istate->t_prt);
	istate_spec->r_prt = istate->r_prt;
	istate_spec->init_int = istate->init_int;

	sense_spec = &istate_spec->sense_spec[0];
	i = 0;
	SLIST_FOREACH(iter, &istate->sense_list, s_list) {
		sense_data = &iter->sense_data;
		sense_spec->error_code = sense_data->error_code;
		sense_spec->flags = sense_data->flags;
		sense_spec->asc = sense_data->add_sense_code;
		sense_spec->ascq = sense_data->add_sense_code_qual;
		sense_spec->info =  *((uint32_t *)sense_data->info); 
		sense_spec++;
		i++;
		if (i == MAX_UNIT_ATTENTIONS)
			break;
	}
	mtx_unlock(istate->istate_lock);

	msg->raw->target_id = tdisk->target_id;
	retval = node_sync_send_page(msg, NULL, 0, node_sync_timeout, 0);
	GLOB_TEND(sense_state_sync_ticks, start_ticks);
	GLOB_INC(sense_state_sync_count, 1);
	return retval;
}
 
void
node_sense_state_recv(struct node_sock *sock, struct raw_node_msg *raw)
{
	struct tdisk *tdisk;
	struct istate_spec istate_spec;
	struct initiator_state *istate;
	struct sense_spec *sense_spec;
	int i, retval;

	tdisk = tdisk_locate(raw->target_id);
	if (unlikely(!tdisk)) {
		debug_warn("node cmd request for unknown tdisk %d\n", raw->target_id);
		node_error_resp_msg(sock, raw, NODE_STATUS_TARGET_NOT_FOUND);
		return;
	}

	debug_check(raw->dxfer_len != sizeof(istate_spec));
	retval = node_sock_read_nofail(sock, &istate_spec, sizeof(istate_spec));
	if (unlikely(retval != 0)) {
		tdisk_put(tdisk);
		return;
	}

	tdisk_reservation_lock(tdisk);
	istate = __device_get_initiator_state(tdisk, istate_spec.i_prt, istate_spec.t_prt, istate_spec.r_prt, istate_spec.init_int, 1, 1);
	if (!istate)
		goto skip;
	istate_sense_list_free(istate);
	sense_spec = &istate_spec.sense_spec[0];
	for (i = 0; i < MAX_UNIT_ATTENTIONS; i++, sense_spec++) {
		if (!sense_spec->error_code)
			break;
		device_add_sense(istate, sense_spec->error_code, sense_spec->flags, sense_spec->info, sense_spec->asc, sense_spec->ascq);
	}
	istate_put(istate);
skip:
	tdisk_reservation_unlock(tdisk);
	raw->dxfer_len = 0;
	node_resp_msg(sock, raw, NODE_STATUS_OK);
	tdisk_put(tdisk);
	return;
}

void
node_istate_clear_recv(struct node_sock *sock, struct raw_node_msg *raw)
{
	struct tdisk *tdisk;

	tdisk = tdisk_locate(raw->target_id);
	if (unlikely(!tdisk)) {
		debug_warn("node cmd request for unknown tdisk %d\n", raw->target_id);
		node_error_resp_msg(sock, raw, NODE_STATUS_TARGET_NOT_FOUND);
		return;
	}

	tdisk_reservation_lock(tdisk);
	device_free_all_initiators(&tdisk->sync_istate_list);
	tdisk_reservation_unlock(tdisk);
	raw->dxfer_len = 0;
	node_resp_msg(sock, raw, NODE_STATUS_OK);
	tdisk_put(tdisk);
	return;
}

int
node_istate_sense_state_send(struct tdisk *tdisk)
{
	struct node_msg *msg;
	struct initiator_state *istate;
	int retval;
#ifdef ENABLE_STATS
	uint32_t start_ticks;
#endif

	GLOB_TSTART(start_ticks);
	if (!node_sync_enabled() || !node_tdisk_sync_enabled(tdisk))
		return 0;

	msg = node_sync_msg_alloc(0, NODE_MSG_ISTATE_CLEAR);
	msg->raw->target_id = tdisk->target_id;

	retval = node_sync_send_page(msg, NULL, 0, node_sync_timeout, 0);
	node_msg_free(msg);
	if (unlikely(retval != 0))
		return -1;

	msg = node_sync_msg_alloc(sizeof(struct istate_spec), NODE_MSG_SENSE_STATE);

	retval = 0;
	device_free_stale_initiators(&tdisk->istate_list);
	SLIST_FOREACH(istate, &tdisk->istate_list, i_list) {
		retval = node_sense_state_send(tdisk, istate, msg);
		if (retval != 0)
			break;
	}
	node_msg_free(msg);
	GLOB_TEND(istate_clear_sync_ticks, ticks);
	GLOB_INC(istate_clear_sync_count, 1);
	return retval;
}

int
node_registration_sync_send(struct tdisk *tdisk, struct registration *registration, int op)
{
	struct registration_spec *registration_spec;
	struct node_msg *msg;
	int retval;
#ifdef ENABLE_STATS
	uint32_t start_ticks;
#endif

	GLOB_TSTART(start_ticks);
	if (!node_sync_enabled() || !node_tdisk_sync_enabled(tdisk))
		return 0;

	msg = node_sync_msg_alloc(sizeof(*registration_spec), NODE_MSG_REGISTRATION_SYNC);
	registration_spec = (struct registration_spec *)(msg->raw->data);
	registration_spec->key = registration->key;
	port_fill(registration_spec->i_prt, registration->i_prt);
	port_fill(registration_spec->t_prt, registration->t_prt);
	registration_spec->r_prt = registration->r_prt;
	registration_spec->init_int = registration->init_int;
	strcpy(registration_spec->init_name, registration->init_name);
	registration_spec->op = op;
	reservation_spec_fill(&tdisk->reservation, &registration_spec->reservation_spec);

	msg->raw->target_id = tdisk->target_id;
	retval = node_sync_send_page(msg, NULL, 0, node_sync_timeout, 0);
	node_msg_free(msg);
	GLOB_TEND(registration_sync_ticks, start_ticks);
	GLOB_INC(registration_sync_count, 1);
	return retval;
}
 
int
node_registration_clear_sync_send(struct tdisk *tdisk)
{
	struct reservation_spec *reservation_spec;
	struct node_msg *msg;
	int retval;
#ifdef ENABLE_STATS
	uint32_t start_ticks;
#endif

	GLOB_TSTART(start_ticks);
	if (!node_sync_enabled() || !node_tdisk_sync_enabled(tdisk))
		return 0;

	msg = node_sync_msg_alloc(sizeof(*reservation_spec), NODE_MSG_REGISTRATION_CLEAR_SYNC);
	reservation_spec = (struct reservation_spec *)(msg->raw->data);
	reservation_spec_fill(&tdisk->reservation, reservation_spec);

	msg->raw->target_id = tdisk->target_id;
	retval = node_sync_send_page(msg, NULL, 0, node_sync_timeout, 0);
	node_msg_free(msg);
	GLOB_TEND(registration_clear_sync_ticks, start_ticks);
	GLOB_TEND(registration_clear_sync_count, 1);
	return retval;
}
 
int
node_amap_table_sync_send(struct amap_table *amap_table)
{
	struct tdisk *tdisk = amap_table->tdisk;
	struct amap_table_spec *amap_table_spec;
	struct node_msg *msg;
	uint64_t lba;
	int retval;
#ifdef ENABLE_STATS
	uint32_t start_ticks;
#endif

	GLOB_TSTART(start_ticks);
	if (!node_sync_enabled() || !node_tdisk_sync_enabled(tdisk))
		return 0;

	lba = amap_table_get_lba_start(amap_table->amap_table_id);
	msg = node_sync_msg_alloc(sizeof(*amap_table_spec), NODE_MSG_AMAP_TABLE_SYNC);
	amap_table_spec = (struct amap_table_spec *)(msg->raw->data);
	amap_table->write_id = write_id_incr(amap_table->write_id, 1);
	amap_table_spec->write_id = amap_table->write_id;
	amap_table_spec->lba = lba;
	amap_table_spec->block = amap_table->amap_table_block;
	amap_table_spec->flags = amap_table->flags;
	amap_table_spec->csum = calc_csum16(vm_pg_address(amap_table->metadata), LBA_SIZE); 

	msg->raw->target_id = amap_table->tdisk->target_id;
	retval = node_sync_send_page(msg, amap_table->metadata, AMAP_SIZE, node_sync_timeout, 0);
	node_msg_free(msg);
	if (retval == 0)
		node_sync_post_amap_table_insert(amap_table);
	GLOB_TEND(amap_table_sync_ticks, start_ticks);
	GLOB_INC(amap_table_sync_count, 1);
	return retval;
}

int
node_amap_table_meta_sync_send(struct amap_table *amap_table)
{
	struct tdisk *tdisk = amap_table->tdisk;
	struct amap_table_spec *amap_table_spec;
	struct node_msg *msg;
	uint64_t lba;
	int retval;
#ifdef ENABLE_STATS
	uint32_t start_ticks;
#endif

	GLOB_TSTART(start_ticks);
	if (!node_sync_enabled() || !node_tdisk_sync_enabled(tdisk))
		return 0;

	lba = amap_table_get_lba_start(amap_table->amap_table_id);
	msg = node_sync_msg_alloc(sizeof(*amap_table_spec), NODE_MSG_AMAP_TABLE_META_SYNC);
	amap_table_spec = (struct amap_table_spec *)(msg->raw->data);
	amap_table_spec->lba = lba;
	amap_table_spec->block = amap_table->amap_table_block;
	amap_table_spec->flags = amap_table->flags;

	msg->raw->target_id = amap_table->tdisk->target_id;
	retval = node_sync_send_page(msg, NULL, 0, node_sync_timeout, 0);
	node_msg_free(msg);
	GLOB_TEND(amap_table_meta_sync_ticks, start_ticks);
	GLOB_INC(amap_table_meta_sync_count, 1);
	return retval;
}

int
__node_tdisk_sync_send(struct tdisk *tdisk)
{
	struct tdisk_spec *tdisk_spec;
	struct node_msg *msg;
	int retval;
#ifdef ENABLE_STATS
	uint32_t start_ticks;
#endif

	GLOB_TSTART(start_ticks);
	msg = node_sync_msg_alloc(sizeof(*tdisk_spec), NODE_MSG_TDISK_SYNC);
	tdisk_spec = (struct tdisk_spec *)(msg->raw->data);
	tdisk_spec->csum = calc_csum16(vm_pg_address(tdisk->metadata), LBA_SIZE); 
	msg->raw->target_id = tdisk->target_id;
	retval = node_sync_send_page(msg, tdisk->metadata, LBA_SIZE, node_sync_timeout, 0);
	node_msg_free(msg);
	GLOB_TEND(tdisk_sync_ticks, start_ticks);
	GLOB_INC(tdisk_sync_count, 1);
	return retval;
}

int
node_tdisk_update_send(struct tdisk *tdisk)
{
	struct tdisk_spec *tdisk_spec;
	struct node_msg *msg;
	int retval;

	if (!node_sync_enabled() || !node_tdisk_sync_enabled(tdisk))
		return 0;

	msg = node_sync_msg_alloc(sizeof(*tdisk_spec), NODE_MSG_TDISK_UPDATE);
	tdisk_spec = (struct tdisk_spec *)(msg->raw->data);
	tdisk_spec->csum = calc_csum16(vm_pg_address(tdisk->metadata), LBA_SIZE); 
	tdisk_spec->amap_table_group_max = tdisk->amap_table_group_max;
	tdisk_spec->table_index_max = tdisk->table_index_max;
	tdisk_spec->amap_table_max = tdisk->amap_table_max;
	tdisk_spec->end_lba = tdisk->end_lba;
	msg->raw->target_id = tdisk->target_id;
	retval = node_sync_send_page(msg, tdisk->metadata, LBA_SIZE, node_sync_timeout, 0);
	node_msg_free(msg);
	return retval;

}

int
node_tdisk_sync_send(struct tdisk *tdisk)
{
	if (!node_sync_enabled() || !node_tdisk_sync_enabled(tdisk))
		return 0;

	return __node_tdisk_sync_send(tdisk);
}

static int
__node_tdisk_delete_send(struct tdisk *tdisk)
{
	struct node_msg *msg;
	int retval;

	msg = node_sync_msg_alloc(0, NODE_MSG_TDISK_DELETE);
	msg->raw->target_id = tdisk->target_id;
	retval = node_sync_send_page(msg, NULL, 0, node_sync_timeout, 0);
	node_msg_free(msg);
	atomic_clear_bit(VDISK_SYNC_ENABLED, &tdisk->flags);
	return retval;
}

int
node_tdisk_delete_send(struct tdisk *tdisk)
{

	if (!node_sync_enabled() || !node_tdisk_sync_enabled(tdisk))
		return 0;

	return __node_tdisk_delete_send(tdisk);

}

int
node_newmeta_sync_complete(struct tdisk *tdisk, uint64_t transaction_id)
{
	struct node_msg *msg;
	int retval;
#ifdef ENABLE_STATS
	uint32_t start_ticks;
#endif

	GLOB_TSTART(start_ticks);
	if (!transaction_id || !node_sync_enabled() || !node_tdisk_sync_enabled(tdisk)) {
		if (!transaction_id) {
			debug_check(!atomic_read(&nonsync_pending_writes));
			atomic_dec(&nonsync_pending_writes);
		}
		return 0;
	}

	msg = node_msg_alloc(0);
	bzero(msg->raw, sizeof(*(msg->raw)));
	msg->raw->dxfer_len = 0;
	msg->raw->msg_cmd = NODE_MSG_NEWMETA_SYNC_COMPLETE;
	msg->raw->msg_id = transaction_id;
	msg->raw->target_id = tdisk->target_id;

	retval = node_sync_send_page(msg, NULL, 0, node_sync_timeout, 0);
	node_msg_free(msg);
	GLOB_TEND(pgdata_sync_complete_ticks, start_ticks);
	GLOB_INC(pgdata_sync_complete_count, 1);
	return retval;

}

int
node_pgdata_sync_complete(struct tdisk *tdisk, uint64_t transaction_id)
{
	struct node_msg *msg;
	int retval;
#ifdef ENABLE_STATS
	uint32_t start_ticks;
#endif

	GLOB_TSTART(start_ticks);
	if (!transaction_id || !node_sync_enabled() || !node_tdisk_sync_enabled(tdisk)) {
		if (!transaction_id) {
			debug_check(!atomic_read(&nonsync_pending_writes));
			atomic_dec(&nonsync_pending_writes);
		}
		return 0;
	}

	msg = node_msg_alloc(0);
	bzero(msg->raw, sizeof(*(msg->raw)));
	msg->raw->dxfer_len = 0;
	msg->raw->msg_cmd = NODE_MSG_PGDATA_SYNC_COMPLETE;
	msg->raw->msg_id = transaction_id;
	msg->raw->target_id = tdisk->target_id;

	retval = node_sync_send_page(msg, NULL, 0, node_sync_timeout, 0);
	node_msg_free(msg);
	GLOB_TEND(pgdata_sync_complete_ticks, start_ticks);
	GLOB_INC(pgdata_sync_complete_count, 1);
	return retval;
}

int
node_pgdata_sync_client_done(struct tdisk *tdisk, uint64_t transaction_id)
{
	struct node_msg *msg;
	int retval;
#ifdef ENABLE_STATS
	uint32_t start_ticks;
#endif

	GLOB_TSTART(start_ticks);
	if (!transaction_id || !node_sync_enabled() || !node_tdisk_sync_enabled(tdisk))
		return 0;

	msg = node_msg_alloc(0);
	bzero(msg->raw, sizeof(*(msg->raw)));
	msg->raw->dxfer_len = 0;
	msg->raw->msg_cmd = NODE_MSG_PGDATA_SYNC_CLIENT_DONE;
	msg->raw->msg_id = transaction_id;
	msg->raw->target_id = tdisk->target_id;

	retval = node_sync_send_page(msg, NULL, 0, node_sync_timeout, 0);
	node_msg_free(msg);
	GLOB_TEND(pgdata_sync_client_done_ticks, start_ticks);
	GLOB_INC(pgdata_sync_client_done_count, 1);
	return retval;
}

static int
index_list_count(struct index_info_list *index_info_list)
{
	struct index_info *index_info;
	int count = 0;

	TAILQ_FOREACH(index_info, index_info_list, i_list) {
		count++;
	}
	return count;
}

int
node_newmeta_sync_start(struct tdisk *tdisk, struct write_list *wlist)
{
	struct node_msg *msg;
	struct index_info *index_info;
	struct newmeta_spec *newmeta_spec;
	struct amap *amap;
	struct amap_table *amap_table;
	int retval, count;

	if (TAILQ_EMPTY(&wlist->meta_index_info_list))
		return 0;

	atomic_set_bit(WLIST_DONE_NEWMETA_SYNC_START, &wlist->flags);
	debug_check(wlist->newmeta_transaction_id);
	if (!node_sync_enabled() || !node_tdisk_sync_enabled(tdisk)) {
		atomic_inc(&nonsync_pending_writes);
		return 0;
	}

	count = index_list_count(&wlist->meta_index_info_list);
	msg = node_sync_msg_alloc((sizeof(*newmeta_spec) * count), NODE_MSG_NEWMETA_SYNC_START);
	msg->raw->target_id = tdisk->target_id;

	newmeta_spec = (struct newmeta_spec *)(msg->raw->data);
	TAILQ_FOREACH(index_info, &wlist->meta_index_info_list, i_list) {
		if (index_info->meta_type == INDEX_INFO_TYPE_AMAP) {
			amap = amap_locate_by_block(index_info->block, &wlist->amap_sync_list);
			newmeta_spec->lba = amap_get_lba_start(amap->amap_id);
		}
		else if (index_info->meta_type == INDEX_INFO_TYPE_AMAP_TABLE) {
			amap_table = amap_table_locate_by_block(index_info->block, &wlist->amap_sync_list);
			newmeta_spec->lba = amap_table_get_lba_start(amap_table->amap_table_id);
		}
		newmeta_spec->block = index_info->block;
		newmeta_spec->meta_type = index_info->meta_type;
		newmeta_spec++;
	}

	retval = node_sync_send_page(msg, NULL, 0, node_sync_timeout, 0);
	if (retval == 0)
		wlist->newmeta_transaction_id = msg->raw->msg_id;
	else
		atomic_inc(&nonsync_pending_writes);
	node_msg_free(msg);
	return retval;

}

int
node_pgdata_sync_start(struct tdisk *tdisk, struct write_list *wlist, struct pgdata **pglist, int pglist_cnt)
{
	struct node_msg *msg;
	struct pgdata_write_spec *write_spec;
	struct pgdata_write_spec_header *write_spec_header;
	struct pgdata *pgdata;
	int i, retval;
#ifdef ENABLE_STATS
	uint32_t start_ticks;
#endif

	GLOB_TSTART(start_ticks);
	atomic_set_bit(WLIST_DONE_PGDATA_SYNC_START, &wlist->flags);
	debug_check(wlist->transaction_id);
	if (!node_sync_enabled() || !node_tdisk_sync_enabled(tdisk)) {
		atomic_inc(&nonsync_pending_writes);
		return 0;
	}

	msg = node_sync_msg_alloc((sizeof(*write_spec) * pglist_cnt) + sizeof(*write_spec_header), NODE_MSG_PGDATA_SYNC_START);
	msg->raw->target_id = tdisk->target_id;

	write_spec_header = (struct pgdata_write_spec_header *)(msg->raw->data);
	write_spec = (struct pgdata_write_spec *)(msg->raw->data + sizeof(*write_spec_header));
	pgdata = pglist[0];
	write_spec_header->lba = pgdata->lba;
	for (i = 0; i < pglist_cnt; i++, write_spec++) {
		pgdata = pglist[i];
		write_spec->amap_block = pgdata->amap_block;
		write_spec->old_amap_block = pgdata->old_amap_block;
		write_spec->amap_write_id = pgdata->amap_write_id;
		if (pgdata->index_info)
			write_spec->index_write_id = pgdata->index_info->index_write_id;
	}

	retval = node_sync_send_page(msg, NULL, 0, node_sync_timeout, 0);
	if (retval == 0)
		wlist->transaction_id = msg->raw->msg_id;
	else
		atomic_inc(&nonsync_pending_writes);
	node_msg_free(msg);
	GLOB_TEND(pgdata_sync_start_ticks, start_ticks);
	GLOB_INC(pgdata_sync_start_count, 1);
	return retval;
}

int
__node_bint_sync_send(struct bdevint *bint)
{
	struct bint_spec *bint_spec;
	struct node_msg *msg;
	int retval;
	int timeout = node_sync_timeout;
#ifdef ENABLE_STATS
	uint32_t start_ticks;
#endif

	GLOB_TSTART(start_ticks);
	msg = node_sync_msg_alloc(sizeof(*bint_spec), NODE_MSG_BINT_SYNC);
	bint_lock(bint);
	bint_spec = (struct bint_spec *)(msg->raw->data);
	bint_spec->bid = bint->bid;
	bint_spec->ddmaster = bint->ddmaster;
	if (bint->ddmaster)
		bint_spec->availmem = qs_availmem;
	bint_spec->ddbits = bint->ddbits;
	bint_spec->log_disks = bint->log_disks;
	bint_spec->log_disk = bint->log_disk;
	bint_spec->group_flags = bint->group_flags;
	bint_spec->log_write = bint->log_write;
	bint_spec->enable_comp = bint->enable_comp;
	bint_spec->free = atomic64_read(&bint->free);
	bint_spec->usize = bint->usize;
	bint_spec->sector_shift = bint->sector_shift;
	bint_spec->v2_disk = bint->v2_disk;
	bint_spec->v2_log_format = bint->v2_log_format;
	bint_spec->rid_set = bint->rid_set;
	memcpy(bint_spec->mrid, bint->mrid, sizeof(bint->mrid));
	memcpy(&bint_spec->bint_stats, &bint->stats, sizeof(bint->stats));
	bint_unlock(bint);

	if (bint->ddmaster)
		timeout += NODE_DDTABLES_SYNC_TIMEOUT;
	if (bint->log_disk)
		timeout += NODE_LOGS_SYNC_TIMEOUT;

	retval = node_sync_send_page(msg, NULL, 0, timeout, 0);
	node_msg_free(msg);
	GLOB_TEND(bint_sync_ticks, start_ticks);
	GLOB_INC(bint_sync_ticks, 1);
	return retval;
}

static int
__node_bint_delete_send(struct bdevint *bint)
{
	struct bint_spec *bint_spec;
	struct node_msg *msg;
	int retval;

	msg = node_sync_msg_alloc(sizeof(*bint_spec), NODE_MSG_BINT_DELETE);
	bint_spec = (struct bint_spec *)(msg->raw->data);
	bint_spec->bid = bint->bid;
	retval = node_sync_send_page(msg, NULL, 0, node_sync_timeout, 0);
	node_msg_free(msg);
	atomic_clear_bit(BINT_SYNC_ENABLED, &bint->flags);
	return retval;
}

int
node_bint_delete_send(struct bdevint *bint)
{
	if (!node_sync_enabled() || !node_bint_sync_enabled(bint))
		return 0;
	return __node_bint_delete_send(bint);
}

int
node_bint_sync_send(struct bdevint *bint)
{
	if (!node_sync_enabled() || !node_bint_sync_enabled(bint))
		return 0;
	return __node_bint_sync_send(bint);
}

static void
node_sync_clear_log_write_ids(struct bdevint *bint)
{
	struct log_group *group;
	struct log_page *log_page;
	int i;

	if (!bint->log_disk)
		return;

	LIST_FOREACH(group, &bint->log_group_list, g_list) {
		for (i = 0; i < LOG_GROUP_MAX_PAGES; i++) {
			log_page = group->logs[i];
			debug_check(!log_page);
			if (!log_page)
				continue;
			log_page_lock(log_page);
			log_page->write_id = 0;
			log_page_unlock(log_page);
		}
	}
}

int
node_sync_setup_logs(struct bdevint *bint)
{
	struct log_group *group;
	struct log_page *log_page;
	int i, error = 0;

	LIST_FOREACH(group, &bint->log_group_list, g_list) {
		for (i = 0; i < LOG_GROUP_MAX_PAGES; i++) {
			log_page = group->logs[i];
			debug_check(!log_page);
			if (!log_page)
				continue;
			if (!log_page->write_id && !atomic_test_bit_short(LOG_META_DATA_DIRTY, &log_page->flags))
				continue;
			error = node_log_sync_send(log_page, NULL);
			if (unlikely(error != 0))
				break;
		}
	}
	return error;
}

int
node_sync_setup_index_lookups(struct bdevint *bint)
{
	struct index_group *group;
	int i, error = 0;
	pagestruct_t *page;
	struct index_lookup *ilookup;

	page = vm_pg_alloc(0);
	if (unlikely(!page))
		return -1;
	for (i = 0; i < bint->max_index_groups; i++) {
		group = bint->index_groups[i];
		if (!group)
			continue;

		ilookup = group->index_lookup;
		mtx_lock(ilookup->lookup_lock);
		memcpy(vm_pg_address(page), vm_pg_address(ilookup->metadata), LBA_SIZE);
		mtx_unlock(ilookup->lookup_lock);

		error = node_index_lookup_sync_send(group, page);
		if (unlikely(error != 0))
			 break; 
	}
	vm_pg_free(page);
	return error;
}

void
ddtable_wait_sync_busy(struct ddtable *ddtable)
{
	if (!ddtable->sync_wait)
		return;

	wait_on_chan_interruptible(ddtable->sync_wait, !atomic_test_bit(DDTABLE_IN_SYNC_THR, &ddtable->flags));
}

void
ddtable_mark_sync_busy(struct bdevint *bint)
{
	struct ddtable *ddtable;

	if (!bint->ddmaster)
		return;

	ddtable = bdev_group_ddtable(bint->group);
	debug_check(!ddtable->sync_wait);
	atomic_set_bit(DDTABLE_IN_SYNC, &ddtable->flags);
	ddtable_wait_sync_busy(ddtable);
}

void
ddtable_unmark_sync_busy(struct bdevint *bint)
{
	struct ddtable *ddtable;

	if (!bint->ddmaster)
		return;

	ddtable = bdev_group_ddtable(bint->group);
	atomic_clear_bit(DDTABLE_IN_SYNC, &ddtable->flags);
	atomic_set_bit(DDTABLE_SYNC_START, &ddtable->flags);
	chan_wakeup_nointr(ddtable->sync_wait);
}

static int
node_sync_setup_ddtables(struct ddtable *ddtable)
{
	struct ddtable_ddlookup_node *ddlookup, *next;
	int error = 0;

	ddlookup = ddtable_sync_list_first(ddtable);
	while (ddlookup) {
		if (atomic_test_bit_short(DDLOOKUP_META_IO_READ_PENDING, &ddlookup->flags) || 
		    atomic_test_bit_short(DDLOOKUP_META_DATA_READ_DIRTY, &ddlookup->flags) ||
		    atomic_test_bit_short(DDLOOKUP_META_DATA_ERROR, &ddlookup->flags))
			goto skip;

		wait_on_chan_check(ddlookup->ddlookup_wait, !atomic_test_bit_short(DDLOOKUP_META_DATA_BUSY, &ddlookup->flags));
		node_ddlookup_lock(ddlookup);
		error = __node_ddlookup_sync_send(ddtable, ddlookup, -1, 0ULL);
		node_ddlookup_unlock(ddlookup);
		if (unlikely(error != 0)) {
			ddtable_ddlookup_node_put(ddlookup);
			break;
		}
skip:
		next = ddtable_sync_list_next(ddtable, ddlookup);
		ddtable_ddlookup_node_put(ddlookup);
		ddlookup = next;
	}
	return error;
}

void
node_sync_mark_sync_enabled(void)
{
	struct bdevint *bint;
	struct tdisk *tdisk;
	struct ddtable *ddtable;
	int i;

	for (i = 0; i < TL_MAX_DISKS; i++) {
		sx_xlock(gchain_lock);
		bint = bint_list[i];
		sx_xunlock(gchain_lock);
		if (!bint || bint->initialized <= 0)
			continue;
		atomic_set_bit(BINT_SYNC_ENABLED, &bint->flags);
		if (!bint->ddmaster)
			continue;
		ddtable = bdev_group_ddtable(bint->group);
		atomic_set_bit(DDTABLE_SYNC_ENABLED, &ddtable->flags);
	}

	for (i = 0; i < TL_MAX_DEVICES; i++) {
		tdisk = tdisk_lookup[i];
		if (!tdisk)
			continue;
		atomic_set_bit(VDISK_SYNC_ENABLED, &tdisk->flags);
	}
}

void
node_sync_pre(void)
{
	struct bdevint *bint;
	struct tdisk *tdisk;
	struct ddtable *ddtable;
	int i;

	for (i = 0; i < TL_MAX_DISKS; i++) {
		sx_xlock(gchain_lock);
		bint = bint_list[i];
		sx_xunlock(gchain_lock);
		if (!bint || bint->initialized <= 0)
			continue;
		atomic_clear_bit(BINT_SYNC_ENABLED, &bint->flags);
		node_sync_clear_log_write_ids(bint);
		if (!bint->ddmaster)
			continue;
		ddtable = bdev_group_ddtable(bint->group);
		atomic_clear_bit(DDTABLE_SYNC_ENABLED, &ddtable->flags);
	}

	for (i = 0; i < TL_MAX_DEVICES; i++) {
		tdisk = tdisk_lookup[i];
		if (!tdisk)
			continue;
		atomic_clear_bit(VDISK_SYNC_ENABLED, &tdisk->flags);
	}
}

extern struct node_comm *root;

void
__node_client_notify_ha_status(uint32_t ipaddr, int enabled)
{
	struct node_comm *comm;
	struct node_sock *sock;
	struct node_msg *msg;
	int retval;

	if (ipaddr == master_config.controller_ipaddr)
		return;

	comm = node_comm_alloc(node_sync_hash, ipaddr, master_config.node_ipaddr);
	retval = node_sock_connect(comm, node_client_recv, NODE_CLIENT_NOTIFY_PORT, "ndsockha");
	if (unlikely(retval != 0)) {
		debug_warn("Cannot connect to client\n");
		goto out;
	}

	sock = node_comm_get_sock(comm, NODE_GET_SOCK_TIMEOUT_FAST); /* waits till a sock is free */
	if (unlikely(!sock)) {
		debug_warn("Cannot get a free node sock\n");
		goto out;
	}

	debug_info("ipaddr %u enabled %d\n", ipaddr, enabled);
	if (enabled)
		msg = node_sync_msg_alloc(0, NODE_MSG_HA_ENABLED);
	else
		msg = node_sync_msg_alloc(0, NODE_MSG_HA_DISABLED);

	node_msg_compute_csum(msg->raw);
	node_cmd_hash_insert(comm->node_hash, msg, msg->raw->msg_id);
	retval = node_sock_write(sock, msg->raw);
	if (unlikely(retval != 0)) {
		node_cmd_hash_remove(comm->node_hash, msg, msg->raw->msg_id);
		debug_warn("Communicating with remote failed\n");
	}
	else
		node_msg_wait(msg, sock, HA_NOTIFY_TIMEOUT);
	node_sock_finish(sock);
	node_msg_free(msg);
out:
	node_comm_put(comm);
	return;
}

void
node_client_notify_ha_status(int enabled)
{
	struct node_comm *comm;

	node_comm_lock(root);
	SLIST_FOREACH(comm, &root->comm_list, c_list) {
		debug_info("notify clients with ha status %d\n", enabled);
		if (atomic_test_bit(NODE_COMM_UNREGISTERED, &comm->flags))
			continue;
		__node_client_notify_ha_status(comm->node_ipaddr, enabled);
	}
	node_comm_unlock(root);

}

static int
node_sync_setup_tdisk_index(struct tdisk *tdisk)
{
	struct amap_table_index *table_index;
	int i;
	int retval;

	for (i = 0; i < tdisk->table_index_max; i++) {
		table_index = &tdisk->table_index[i];
		sx_xlock(table_index->table_index_lock);
		retval = __node_table_index_sync_send(tdisk, table_index, i);
		sx_xunlock(table_index->table_index_lock);
		if (unlikely(retval != 0))
			return retval;
	}
	return 0;
}

int
node_sync_setup_bdevs_for_takeover(void)
{
	struct bdevint *bint;
	struct tdisk *tdisk;
	int i;

	for (i = 0; i < TL_MAX_DISKS; i++) {
		sx_xlock(gchain_lock);
		bint = bint_list[i];
		sx_xunlock(gchain_lock);

		if (!bint || bint->initialized <= 0)
			continue;

		bint_sync(bint, 1);
		bint_group_sync(bint);
	}

	for (i = 0; i < TL_MAX_DEVICES; i++) {
		tdisk = tdisk_lookup[i];
		if (!tdisk)
			continue;

		tdisk_sync(tdisk, 0);
	}
	return 0;
}

int
node_sync_setup_bdevs(void)
{
	struct bdevint *bint;
	struct tdisk *tdisk;
	int i, error = 0;
	struct node_comm *comm;
	struct ddtable *ddtable;

	debug_info("syncing client registration\n");
	node_comm_lock(root);
	SLIST_FOREACH(comm, &root->comm_list, c_list) {
		if (atomic_test_bit(NODE_COMM_UNREGISTERED, &comm->flags))
			continue;
		node_sync_register_send(comm, 1);
	}
	node_comm_unlock(root);

	for (i = 0; i < TL_MAX_DISKS; i++) {
		sx_xlock(gchain_lock);
		bint = bint_list[i];
		sx_xunlock(gchain_lock);

		if (!bint || bint->initialized <= 0)
			continue;

		debug_info("mark ddtable busy\n");
		ddtable_mark_sync_busy(bint);

		debug_info("sync send for bint at %u\n",i);
		error = __node_bint_sync_send(bint);
		if (unlikely(error != 0)) {
			ddtable_unmark_sync_busy(bint);
			goto out;
		}
		atomic_set_bit(BINT_SYNC_ENABLED, &bint->flags);

		debug_info("setup index lookups\n");
		error = node_sync_setup_index_lookups(bint);
		if (unlikely(error != 0)) {
			ddtable_unmark_sync_busy(bint);
			goto out;
		}

		if (bint->ddmaster) {
			debug_info("setup ddtables\n");
			ddtable = bdev_group_ddtable(bint->group);
			error = node_sync_setup_ddtables(ddtable);
			debug_info("done setup ddtables\n");
			ddtable_unmark_sync_busy(bint);
			if (unlikely(error != 0))
				goto out;
			atomic_set_bit(DDTABLE_SYNC_ENABLED, &ddtable->flags);
		}
	}

	debug_info("syncing logs\n");
	sx_xlock(gchain_lock);
	for (i = 0; i < TL_MAX_DISKS; i++) {
		bint = bint_list[i];

		if (!bint || bint->initialized <= 0 || !bint->log_disk)
			continue;
		error = node_sync_setup_logs(bint);
		if (unlikely(error != 0)) {
			sx_xunlock(gchain_lock);
			goto out;
		}
	}
	sx_xunlock(gchain_lock);
	debug_info("done syncing logs\n");

	for (i = 0; i < TL_MAX_DEVICES; i++) {
		tdisk = tdisk_lookup[i];
		if (!tdisk)
			continue;

		tdisk_lock(tdisk);
		error = __node_tdisk_sync_send(tdisk);
		tdisk_unlock(tdisk);
		if (unlikely(error != 0))
			 break;

		error = node_sync_setup_tdisk_index(tdisk);
		if (unlikely(error != 0))
			 break;

		atomic_set_bit(VDISK_SYNC_ENABLED, &tdisk->flags);
	}

out:
	while (error == 0 && node_sync_get_status() != NODE_SYNC_ERROR && atomic_read(&nonsync_pending_writes) > 0) {
		debug_info("non sync pending writes %d\n", atomic_read(&nonsync_pending_writes));
		pause("psg", 50);
	}

	if (error == 0 && node_sync_get_status() != NODE_SYNC_ERROR) {
		node_ha_enable();
	}
	else {
		node_ha_disable();
		error = -1;
	}

	node_client_notify_ha_status(error == 0);
	debug_info("end\n");
	return error;
}

static void
client_node_list_free(void)
{
	struct client_node *iter;

	node_sync_lock();
	while ((iter = STAILQ_FIRST(&client_node_list)) != NULL) {
		STAILQ_REMOVE_HEAD(&client_node_list, c_list);
		free(iter, M_CLIENT_NODE);
	}
	node_sync_unlock();
}

static void
__node_sync_comm_exit(int graceful)
{
	if (sync_comm) {
		while (atomic_read(&sync_comm->refs) > 1)
			pause("psg", 20);
		if (!graceful)
			atomic_clear_bit(NODE_COMM_LINGER, &sync_comm->flags);
		node_comm_put(sync_comm);
		sync_comm = NULL;
	}
}

void
node_sync_comm_exit(int graceful)
{
	node_sync_lock();
	__node_sync_comm_exit(graceful);
	node_sync_unlock();
}

void
node_sync_exit(void)
{
	node_sync_comm_exit(1);
	client_node_list_free();
}

static int
__node_sync_comm_init(uint32_t remote_ipaddr, uint32_t node_ipaddr)
{
	int retval, i;

	__node_sync_comm_exit(1);

	sync_comm = node_comm_alloc(node_sync_hash, remote_ipaddr, node_ipaddr);

	for (i = 0; i < MAX_GDEVQ_THREADS + 1; i++) { /* 1 for ha thr */
		retval = node_sock_connect(sync_comm, node_client_recv, CONTROLLER_SYNC_PORT, "ndsocksn"); 
		if (unlikely(retval != 0))
			goto err;
		if (!i) {
			retval = node_comm_register(sync_comm, node_sync_timeout);
			if (unlikely(retval != 0))
				goto err;
		}

		if ((i % 8) == 0)
			pause("psg", 50);
	}
	return 0;
err:
	node_comm_put(sync_comm);
	sync_comm = NULL;
	return -1;
}

int
node_sync_comm_init(uint32_t remote_ipaddr, uint32_t node_ipaddr)
{
	int retval;

	node_sync_lock();
	retval = __node_sync_comm_init(remote_ipaddr, node_ipaddr);
	node_sync_unlock();
	return retval;
}

static int
node_sync_status(int msg_cmd)
{
	struct node_msg *msg;
	struct raw_node_msg *raw;
	struct node_sock *sock;
	int retval;
	struct node_comm *comm;

	comm = node_sync_comm_get();
	if (!comm)
		return -1;

	sock = node_comm_get_sock(comm, NODE_GET_SOCK_TIMEOUT);
	if (!sock) {
		node_comm_put(comm);
		return -1;
	}

	msg = node_msg_alloc(0);
	raw = msg->raw;
	bzero(raw, sizeof(*raw));
	raw->msg_id = node_transaction_id();
	raw->msg_cmd = msg_cmd;
	raw->dxfer_len = 0;
	retval = node_send_msg(sock, msg, raw->msg_id, 1);
	if (unlikely(retval != 0)) {
		node_comm_put(comm);
		node_msg_free(msg);
		return -1;
	}

	node_msg_wait(msg, sock, node_sync_timeout);
	retval = node_resp_status(msg);
	node_msg_free(msg);
	node_sock_finish(sock);
	node_comm_put(comm);
	return retval;
}

static void
client_node_add(struct comm_spec *comm_spec)
{
	struct client_node *iter;

	node_sync_lock();
	STAILQ_FOREACH(iter, &client_node_list, c_list) {
		if (iter->ipaddr == comm_spec->ipaddr) {
			node_sync_unlock();
			return;
		}
	}

	debug_info("Adding client node %u\n", comm_spec->ipaddr);
	iter = zalloc(sizeof(*iter), M_CLIENT_NODE, Q_WAITOK);
	iter->ipaddr = comm_spec->ipaddr;
	STAILQ_INSERT_HEAD(&client_node_list, iter, c_list);
	node_sync_unlock();
}

static void
client_node_remove(struct comm_spec *comm_spec)
{
	struct client_node *iter, *prev = NULL;

	node_sync_lock();
	STAILQ_FOREACH(iter, &client_node_list, c_list) {
		if (iter->ipaddr != comm_spec->ipaddr) {
			prev = iter;
			continue;
		}

		debug_info("Removing client node %u\n", comm_spec->ipaddr);
		if (prev)
			STAILQ_REMOVE_AFTER(&client_node_list, prev, c_list);
		else
			STAILQ_REMOVE_HEAD(&client_node_list, c_list);
		free(iter, M_CLIENT_NODE);
		break;
	}
	node_sync_unlock();
}

static void
node_sync_notify(struct client_node *client_node, int graceful, struct queue_list *msg_list)
{
	struct node_comm *comm;
	struct node_sock *sock;
	struct node_msg *msg;
	int retval;
	struct ha_config *ha_config;

	if (client_node->ipaddr == master_config.controller_ipaddr)
		return;

	debug_info("notify client %u\n", client_node->ipaddr);
	comm = node_comm_alloc(node_sync_hash, client_node->ipaddr, master_config.node_ipaddr);
	retval = node_sock_connect(comm, node_client_recv, NODE_CLIENT_NOTIFY_PORT, "ndsocknt");
	if (unlikely(retval != 0)) {
		debug_warn("Cannot connect to client\n");
		node_comm_put(comm);
		return;
	}

	sock = node_comm_get_sock(comm, NODE_GET_SOCK_TIMEOUT); /* waits till a sock is free */
	if (unlikely(!sock)) {
		debug_warn("Cannot get a free node sock\n");
		node_comm_put(comm);
		return;
	}

	msg = node_sync_msg_alloc(sizeof(*ha_config), NODE_MSG_HA_SWITCH); 
	ha_config = (struct ha_config *)(msg->raw->data);
	ha_config->ipaddr = master_config.node_ipaddr;
	ha_config->graceful = graceful;

	node_msg_compute_csum(msg->raw);
	node_cmd_hash_insert(comm->node_hash, msg, msg->raw->msg_id);
	retval = node_sock_write(sock, msg->raw);
	if (unlikely(retval != 0)) {
		node_cmd_hash_remove(comm->node_hash, msg, msg->raw->msg_id);
		debug_warn("Communicating with remote failed\n");
		node_sock_finish(sock);
		node_msg_free(msg);
		node_comm_put(comm);
		return;
	}
	msg->sock = sock;
	TAILQ_INSERT_TAIL(msg_list, msg, q_list);
}

void
node_sync_notify_takeover(int graceful)
{
	struct client_node *iter;
	struct queue_list msg_list;
	struct node_msg *msg;
	struct node_comm *comm;

	TAILQ_INIT(&msg_list);
	node_sync_lock();
	while ((iter = STAILQ_FIRST(&client_node_list)) != NULL) {
		STAILQ_REMOVE_HEAD(&client_node_list, c_list);
		node_sync_notify(iter, graceful, &msg_list);
		free(iter, M_CLIENT_NODE);
	}

	while ((msg = TAILQ_FIRST(&msg_list)) != NULL) {
		TAILQ_REMOVE(&msg_list, msg, q_list);
		node_msg_wait(msg, msg->sock, HA_NOTIFY_TIMEOUT);
		comm = msg->sock->comm;
		node_sock_finish(msg->sock);
		node_comm_put(comm);
		node_msg_free(msg);
	}
	node_sync_unlock();
}

void
node_sync_relinquish_status(struct node_sock *sock, struct raw_node_msg *raw)
{
	int status;

	if (node_in_transition())
		status = NODE_STATUS_INITIALIZING;
	else if (node_get_role() == NODE_ROLE_MASTER)
		status = NODE_STATUS_OK;
	else
		status = NODE_STATUS_ERROR;
	raw->dxfer_len = 0;
	node_resp_msg(sock, raw, status);
}

void
node_sync_relinquish_recv(struct node_sock *sock, struct raw_node_msg *raw)
{
	struct ha_config ha_config;
	int status, retval;

	node_master_sync_wait();

	raw->dxfer_len = 0;
	if (node_sync_get_status() != NODE_SYNC_DONE) {
		node_resp_msg(sock, raw, NODE_STATUS_ERROR);
		return;
	}

	retval = node_ha_takeover_pre(&ha_config, 1, 0);
	if (retval != 0)
		status = NODE_STATUS_ERROR;
	else
		status = NODE_STATUS_OK;

	node_resp_msg(sock, raw, status);

	if (retval == 0)
		node_ha_takeover(&ha_config, 1);
	node_sync_comm_exit(1);
}

void
node_sync_takeover_recv(struct node_sock *sock, struct raw_node_msg *raw)
{
	if (node_sync_get_status() != NODE_SYNC_DONE) {
		node_resp_msg(sock, raw, NODE_STATUS_ERROR);
		return;
	}

	node_set_in_transition();
	node_set_role(NODE_ROLE_STANDBY);
	wait_for_ha_busy();
	mdevq_wait_for_empty();
	node_master_pending_writes_wait();
	master_queue_wait_for_empty();
	ddthread_wait_for_empty();
	bdev_groups_ddtable_wait_sync_busy();
	sync_post_wait_for_empty();
	node_sync_setup_bdevs_for_takeover();
	node_clear_in_transition();
	raw->dxfer_len = 0;
	if (!node_sync_enabled()) {
		debug_warn("node sync disabled\n");
		node_resp_msg(sock, raw, NODE_STATUS_ERROR);
	}
	else {
#if 0
		node_sync_force_restart();
#endif
		node_resp_msg(sock, raw, NODE_STATUS_OK);
	}
}

void
node_sync_register_recv(struct node_sock *sock, struct raw_node_msg *raw)
{
	struct comm_spec comm_spec;
	int retval;

	debug_check(raw->dxfer_len != sizeof(comm_spec));
	retval = node_sock_read_nofail(sock, &comm_spec, sizeof(comm_spec));
	if (unlikely(retval != 0)) {
		return;
	}

	if (comm_spec.node_register)
		client_node_add(&comm_spec);
	else
		client_node_remove(&comm_spec);

	raw->dxfer_len = 0;
	node_resp_msg(sock, raw, NODE_STATUS_OK);
}

int
node_sync_register_send(struct node_comm *comm, int node_register)
{
	struct comm_spec *comm_spec;
	struct node_msg *msg;
	int retval;

	if (!node_sync_enabled())
		return 0;

	msg = node_sync_msg_alloc(sizeof(*comm_spec), NODE_MSG_COMM_SYNC);
	comm_spec = (struct comm_spec *)(msg->raw->data);
	comm_spec->ipaddr = comm->node_ipaddr; 
	comm_spec->node_register = node_register;
	retval = node_sync_send_page(msg, NULL, 0, node_sync_timeout, 0);
	node_msg_free(msg);
	return retval;
}

void
node_sync_disable_recv(struct node_sock *sock, struct raw_node_msg *raw)
{
	node_sync_disable();
	sync_post_wait_for_empty();
	raw->dxfer_len = 0;
	node_resp_msg(sock, raw, NODE_STATUS_OK);
}

int
node_sync_disable_send(void)
{
	struct node_msg *msg;

	if (!node_sync_enabled())
		return 0;

	msg = node_sync_msg_alloc(0, NODE_MSG_SYNC_DISABLE);
	node_sync_send_page(msg, NULL, 0, node_sync_timeout, 0);
	node_msg_free(msg);
	node_sync_disable();
	return 0;
}

int
node_sync_relinquish_send(void)
{
	struct node_msg *msg;
	struct raw_node_msg *raw;
	struct node_sock *sock;
	struct node_comm *comm;
	int retval;

	if (!node_sync_enabled())
		return 0;

	node_master_sync_wait();
	comm = node_sync_comm_get();
	if (unlikely(!comm)) {
		debug_warn("Cannot get sync comm\n");
		return -1;
	}

	sock = node_comm_get_sock(comm, NODE_GET_SOCK_TIMEOUT);
	if (unlikely(!sock)) {
		node_comm_put(comm);
		debug_warn("Cannot get sync sock\n");
		return -1;
	}

	msg = node_msg_alloc(0);
	raw = msg->raw;
	bzero(raw, sizeof(*raw));
	raw->msg_id = node_transaction_id();
	raw->msg_cmd = NODE_MSG_HA_RELINQUISH;
	raw->dxfer_len = 0;
	retval = node_send_msg(sock, msg, raw->msg_id, 1);
	if (unlikely(retval != 0)) {
		node_sock_finish(sock);
		node_comm_put(comm);
		node_msg_free(msg);
		return -1;
	}

	node_msg_wait(msg, sock, NODE_SYNC_RELINQUISH_TIMEOUT);
	retval = node_resp_status(msg);
	node_msg_free(msg);
	if (unlikely(retval != 0)) {
		node_sock_finish(sock);
		node_comm_put(comm);
		return retval;
	}

	debug_info("relinquish send successful\n");
	while (1) {
		retval = node_sync_status(NODE_MSG_HA_RELINQUISH_STATUS);
		if (retval == NODE_STATUS_INITIALIZING) {
			pause("psg", 2000);
			continue;
		}
		else if (retval == NODE_STATUS_OK) {
			break;
		}
		else
			break;
	}
	node_sock_finish(sock);
	node_comm_put(comm);
	debug_info("retval %d\n", retval);
	return (retval != NODE_STATUS_OK);
}

int
node_sync_takeover_send(void)
{
	struct node_msg *msg;
	int retval;

	if (!node_sync_enabled())
		return -1;

	msg = node_sync_msg_alloc(0, NODE_MSG_HA_TAKEOVER);
	retval = node_sync_send_page(msg, NULL, 0, NODE_SYNC_TIMEOUT_LONG_LONG, 0);
	node_msg_free(msg);
	return retval;
}

int
node_sync_takeover_post_send(void)
{
	struct node_msg *msg;
	int retval;

	debug_check(!node_sync_enabled());
	if (!node_sync_enabled())
		return -1;

	msg = node_sync_msg_alloc(0, NODE_MSG_HA_TAKEOVER_POST);
	retval = node_sync_send_page(msg, NULL, 0, NODE_SYNC_TIMEOUT_LONG_LONG, 0);
	node_msg_free(msg);
	return retval;
}

#if 0
static void
node_log_group_reset(struct log_group *log_group)
{
	struct log_page *log_page;
	int i;

	for (i = 0; i < LOG_GROUP_MAX_PAGES; i++) {
		log_page = log_group->logs[i];
		log_page->write_id = 0;
	}
}

static void
node_logs_reset(struct bdevint *bint)
{
	struct log_group *log_group;

	LIST_FOREACH(log_group, &bint->log_group_list, g_list) {
		node_log_group_reset(log_group);
	}
}
#endif

static void
node_bint_index_reset(struct bdevint *bint)
{
	struct bintindex *index;

	if (bint->v2_disk)
		return;

	bint_lock(bint);
	TAILQ_FOREACH(index, &bint->index_list, b_list) {
		index->write_id = 0;
	}
	bint_unlock(bint);
}

static void
node_bdevs_index_reset(void)
{
	struct bdevint *bint;
	int i;

	sx_xlock(gchain_lock);
	for (i = 0; i < TL_MAX_DISKS; i++) {
		bint = bint_list[i];
		if (!bint || bint->initialized <= 0)
			continue;
		node_bint_index_reset(bint);
		node_sync_clear_log_write_ids(bint);
	}
	sx_xunlock(gchain_lock);
}

static void
node_amap_table_reset(struct amap_table *amap_table)
{
	struct amap *amap;
	int i;

	if (is_v2_tdisk(amap_table->tdisk)) {
		amap_table->write_id = 0;
		return;
	}

	for (i = 0; i < AMAPS_PER_AMAP_TABLE; i++) {
		amap = amap_table->amap_index[i];
		if (!amap)
			continue;
		amap->write_id = 0;
	}
	amap_table->write_id = 0;
}

static void
node_amap_table_group_reset(struct amap_table_group *group)
{
	struct amap_table *amap_table;

	TAILQ_FOREACH(amap_table, &group->table_list, t_list) {
		amap_table_lock(amap_table);
		node_amap_table_reset(amap_table);
		amap_table_unlock(amap_table);
	}
}

static void
node_tdisk_amaps_reset(struct tdisk *tdisk)
{
	struct amap_table_group *group;
	int i;

	if (tdisk->amap_table_group) {
		for (i = 0; i < tdisk->amap_table_group_max; i++) {
			group = tdisk->amap_table_group[i];
			if (!group)
				continue;
			amap_table_group_lock(group);
			node_amap_table_group_reset(group);
			amap_table_group_unlock(group);
		}
	}

	device_free_all_initiators(&tdisk->sync_istate_list);
	tdisk_reservation_lock(tdisk);
	persistent_reservation_clear(&tdisk->sync_reservation.registration_list);
	tdisk_reservation_unlock(tdisk);
}

static void
node_tdisks_amaps_reset(void)
{
	struct tdisk *tdisk;
	int i;

	for (i = 0; i < TL_MAX_DEVICES; i++) {
		tdisk = tdisk_lookup[i];
		if (!tdisk)
			continue;
		node_tdisk_amaps_reset(tdisk);
	}
}

void
node_sync_takeover_post_recv(struct node_sock *sock, struct raw_node_msg *raw)
{
	node_bdevs_index_reset();
	node_tdisks_amaps_reset();
	raw->dxfer_len = 0;
	node_resp_msg(sock, raw, NODE_STATUS_OK);
}

static void
node_bint_reset(struct bdevint *bint)
{
	if (bint->log_disk) {
		struct bdevgroup *bdevgroup = bint->group;

		debug_check(bdevgroup->reserved_log_entries);
		bdev_log_remove(bint, 1);
		bdev_log_list_remove(bint, 1);
	}

	if (bint->ddmaster)
		ddtable_exit(&bint->group->ddtable);

	bint_reset(bint);
	atomic_clear_bit(BINT_LOAD_DONE, &bint->flags);
}

static void
node_bdevs_reset(void)
{
	struct bdevint *bint;
	int i;

	sx_xlock(gchain_lock);
	for (i = 0; i < TL_MAX_DISKS; i++) {
		bint = bint_list[i];
		if (!bint || bint->initialized <= 0)
			continue;
		node_bint_reset(bint);
	}
	sx_xunlock(gchain_lock);
}

static void
node_tdisk_reset(struct tdisk *tdisk)
{
	tdisk_state_reset(tdisk);
	if (tdisk->metadata) {
		vm_pg_free(tdisk->metadata);
		tdisk->metadata = NULL;
	}

	device_free_all_initiators(&tdisk->sync_istate_list);
	tdisk_reservation_lock(tdisk);
	persistent_reservation_clear(&tdisk->sync_reservation.registration_list);
	tdisk_reservation_unlock(tdisk);
}

static void
node_tdisks_reset(void)
{
	struct tdisk *tdisk;
	int i;

	for (i = 0; i < TL_MAX_DEVICES; i++) {
		tdisk = tdisk_lookup[i];
		if (!tdisk)
			continue;
		node_tdisk_reset(tdisk);
	}
}

void
__node_sync_force_restart(void)
{
	if (node_sync_get_status() == NODE_SYNC_NEED_RESYNC)
		return;

	debug_info("rcache reset\n");
	rcache_reset();

	debug_info("ha hash cancel\n");
	node_ha_meta_hash_cancel();
	node_ha_hash_cancel();
	debug_info("bdevs reset\n");
	node_bdevs_reset();
	debug_info("tdisks reset\n");
	node_tdisks_reset();
	debug_info("tdisks reset done\n");

	node_sync_set_status(NODE_SYNC_NEED_RESYNC);
	return;
}

void
node_sync_force_restart(void)
{
	node_sync_lock();
	__node_sync_force_restart();
	node_sync_unlock();
}

int
__node_sync_start(void)
{
	struct node_msg *msg;
	struct raw_node_msg *raw;
	struct node_sock *sock;
	struct node_comm *comm;
	int retval;

	node_sync_set_status(NODE_SYNC_INPROGRESS);
	comm = node_sync_comm_get();
	if (unlikely(!comm)) {
		debug_warn("Cannot get sync comm\n");
		return -1;
	}

	sock = node_comm_get_sock(comm, NODE_GET_SOCK_TIMEOUT);
	if (unlikely(!sock)) {
		node_comm_put(comm);
		debug_warn("Cannot get sync sock\n");
		return -1;
	}

	msg = node_msg_alloc(0);
	raw = msg->raw;
	bzero(raw, sizeof(*raw));
	raw->msg_id = node_transaction_id();
	raw->msg_cmd = NODE_MSG_SYNC_START; 
	raw->dxfer_len = 0;
	retval = node_send_msg(sock, msg, raw->msg_id, 1);
	if (unlikely(retval != 0)) {
		node_sock_finish(sock);
		node_comm_put(comm);
		node_msg_free(msg);
		node_sync_set_status(NODE_SYNC_NEED_RESYNC);
		return -1;
	}

	node_msg_wait(msg, sock, node_sync_timeout);
	retval = node_resp_status(msg);
	node_msg_free(msg);
	if (unlikely(retval != 0)) {
		node_sock_finish(sock);
		node_comm_put(comm);
		if (retval == NODE_STATUS_BUSY) {
			node_sync_set_status(NODE_SYNC_NEED_RESYNC);
			return -1;
		}
		debug_warn("Receiving sync start message response failed retval %d\n", retval);
		node_sync_set_status(NODE_SYNC_ERROR);
		return retval;
	}

	retval = 0;
	while (node_sync_get_status() != NODE_SYNC_DONE) {
		retval = node_sync_status(NODE_MSG_SYNC_STATUS);
		if (retval == NODE_STATUS_INITIALIZING) {
			node_sync_set_status(NODE_SYNC_INPROGRESS);
			pause("psg", 2000);
			continue;
		}
		else if (retval == NODE_STATUS_OK) {
			node_sync_set_status(NODE_SYNC_DONE);
			break;
		}
		else
			break;
	}
	node_sock_finish(sock);
	node_comm_put(comm);
	if (retval != NODE_STATUS_OK)
		node_sync_disable();
	debug_info("sync status %d\n", node_sync_get_status());
	return (node_sync_get_status() != NODE_SYNC_DONE);
}

int
node_sync_comm_check(uint32_t remote_ipaddr, uint32_t node_ipaddr)
{
	int retval = 0;

	node_sync_lock();
	if (!sync_comm)
		retval = __node_sync_comm_init(remote_ipaddr, node_ipaddr);
	node_sync_unlock();
	return retval;
}

int
node_sync_start(uint32_t remote_ipaddr, uint32_t node_ipaddr)
{
	int retval = 0;

	retval = node_sync_comm_check(remote_ipaddr, node_ipaddr);
	if (unlikely(retval != 0))
		return retval;
	return __node_sync_start();
}

void
sync_post_wait_for_empty(void)
{
	while (!STAILQ_EMPTY(&pending_post_queue))
		processor_yield();
}

static inline struct node_sync_post *
get_next_sync_post(void)
{
	struct node_sync_post *post;

	chan_lock(sync_post_wait);
	post = STAILQ_FIRST(&pending_post_queue);
	if (post)
		STAILQ_REMOVE_HEAD(&pending_post_queue, s_list);
	chan_unlock(sync_post_wait);
	return post;
}

static void
handle_bintindex_sync_post(struct node_sync_post *post)
{
	struct bintindex *index = post->priv;
	struct index_subgroup *subgroup = index->subgroup;
	struct index_group *group = subgroup->group;
	struct bdevint *bint = group->bint;
	struct bintindex_spec *bintindex_spec;
	struct node_msg *msg;
#ifdef ENABLE_STATS
	uint32_t start_ticks;
#endif

	GLOB_TSTART(start_ticks);
	if (!node_sync_enabled() || !node_bint_sync_enabled(bint)) {
		index_put(index);
		atomic_dec(&bint->post_writes);
		return;
	}

	index_lock(index);
	debug_check(index->write_id < post->write_id);
	if (index->write_id != post->write_id) {
		index_unlock(index);
		index_put(index);
		atomic_dec(&bint->post_writes);
		return;
	}


	msg = node_sync_msg_alloc(sizeof(*bintindex_spec), NODE_MSG_BINT_INDEX_SYNC_POST);
	bintindex_spec = (struct bintindex_spec *)(msg->raw->data);
	bintindex_spec->write_id = post->write_id;
	bintindex_spec->bid = bint->bid;
	bintindex_spec->group_id = group->group_id;
	bintindex_spec->subgroup_id = subgroup->subgroup_id;
	bintindex_spec->index_id = index->index_id;

	node_sync_send_page(msg, NULL, 0, node_sync_timeout, 0);
	index_unlock(index);
	index_put(index);
	atomic_dec(&bint->post_writes);
	node_msg_free(msg);
	GLOB_TEND(index_sync_post_ticks, start_ticks);
	GLOB_INC(index_sync_post_count, 1);
}

static void
handle_ddlookup_sync_post(struct node_sync_post *post)
{
	struct node_ddlookup_sync_post *ddlookup_post = post->priv;
	struct ddtable_ddlookup_node *ddlookup = ddlookup_post->ddlookup;
	struct ddtable *ddtable = ddlookup_post->ddtable;
	struct ddlookup_spec *ddlookup_spec;
	struct node_msg *msg;
#ifdef ENABLE_STATS
	uint32_t start_ticks;
#endif

	GLOB_TSTART(start_ticks);
	if (!node_sync_enabled() || !node_ddtable_sync_enabled(ddtable)) {
		ddtable_ddlookup_node_put(ddlookup);
		atomic_dec(&ddtable->inited);
		free(ddlookup_post, M_QUADSTOR);
		return;
	}

	node_ddlookup_lock(ddlookup);
	ddtable_ddlookup_node_wait(ddlookup);
	debug_check(ddlookup->write_id < ddlookup_post->write_id);
	if (ddlookup->write_id != ddlookup_post->write_id) {
		node_ddlookup_unlock(ddlookup);
		ddtable_ddlookup_node_put(ddlookup);
		atomic_dec(&ddtable->inited);
		free(ddlookup_post, M_QUADSTOR);
		return;
	}

	msg = node_sync_msg_alloc(sizeof(*ddlookup_spec), NODE_MSG_DDLOOKUP_SYNC_POST);
	ddlookup_spec = (struct ddlookup_spec *)(msg->raw->data);
	ddlookup_spec->hash_id = -1;
	ddlookup_spec->group_id = ddtable->bint->group->group_id;
	SET_BLOCK(ddlookup_spec->block, ddlookup->b_start, ddtable->bint->bid);
	node_sync_send_page(msg, NULL, 0, node_sync_timeout, 0);
	chan_wakeup_nointr(ddlookup->ddlookup_wait);
	node_ddlookup_unlock(ddlookup);
	ddtable_ddlookup_node_put(ddlookup);
	node_msg_free(msg);
	atomic_dec(&ddtable->inited);
	free(ddlookup_post, M_QUADSTOR);
	GLOB_TEND(ddlookup_sync_post_ticks, start_ticks);
	GLOB_INC(ddlookup_sync_post_count, 1);
}

static void
handle_log_sync_post(struct node_sync_post *post)
{
	struct log_page *log_page = post->priv;
	struct bdevint *bint = log_page->group->bint;
	struct log_spec *log_spec;
	struct node_msg *msg;
#ifdef ENABLE_STATS
	uint32_t start_ticks;
#endif

	GLOB_TSTART(start_ticks);

	if (!node_sync_enabled() || !node_bint_sync_enabled(log_page->group->bint)) {
		log_page_put(log_page);
		atomic_dec(&bint->post_writes);
		return;
	}

	log_page_lock(log_page);
	debug_check(log_page->write_id < post->write_id);
	if (log_page->write_id != post->write_id) {
		log_page_unlock(log_page);
		log_page_put(log_page);
		atomic_dec(&bint->post_writes);
		return;
	}

	msg = node_sync_msg_alloc(sizeof(*log_spec), NODE_MSG_LOG_SYNC_POST);
	log_spec = (struct log_spec *)(msg->raw->data);
	log_spec->write_id = post->write_id;
	log_spec->bid = log_page->group->bint->bid;
	log_spec->group_id = log_page->group->group_id;
	log_spec->log_group_idx = log_page->log_group_idx;
	node_sync_send_page(msg, NULL, 0, node_sync_timeout, 0);
	log_page_unlock(log_page);
	log_page_put(log_page);
	atomic_dec(&bint->post_writes);
	node_msg_free(msg);
	GLOB_TEND(log_sync_post_ticks, start_ticks);
	GLOB_INC(log_sync_post_count, 1);
}

static void
handle_amap_table_sync_post(struct node_sync_post *post)
{
	struct amap_table *amap_table = post->priv;
	struct tdisk *tdisk = amap_table->tdisk;
	struct amap_table_spec *amap_table_spec;
	struct node_msg *msg;
	uint64_t lba;
#ifdef ENABLE_STATS
	uint32_t start_ticks;
#endif

	GLOB_TSTART(start_ticks);

	if (!node_sync_enabled() || !node_tdisk_sync_enabled(amap_table->tdisk)) {
		amap_table_put(amap_table);
		tdisk_put(tdisk);
		return;
	}

	amap_table_lock(amap_table);
	debug_check(amap_table->write_id < post->write_id);
	if (amap_table->write_id != post->write_id) {
		amap_table_unlock(amap_table);
		amap_table_put(amap_table);
		tdisk_put(tdisk);
		return;
	}

	lba = amap_table_get_lba_start(amap_table->amap_table_id);
	msg = node_sync_msg_alloc(sizeof(*amap_table_spec), NODE_MSG_AMAP_TABLE_SYNC_POST);
	amap_table_spec = (struct amap_table_spec *)(msg->raw->data);
	amap_table_spec->write_id = post->write_id;
	amap_table_spec->lba = lba;
	amap_table_spec->block = amap_table->amap_table_block;
	amap_table_spec->flags = amap_table->flags;

	msg->raw->target_id = amap_table->tdisk->target_id;
	node_sync_send_page(msg, NULL, 0, node_sync_timeout, 0);
	amap_table_unlock(amap_table);
	amap_table_put(amap_table);
	tdisk_put(tdisk);
	node_msg_free(msg);
	GLOB_TEND(amap_table_sync_post_ticks, start_ticks);
	GLOB_INC(amap_table_sync_post_count, 1);
}

static void
handle_amap_sync_post(struct node_sync_post *post)
{
	struct amap *amap = post->priv;
	struct tdisk *tdisk = amap->amap_table->tdisk;
	struct amap_spec *amap_spec;
	struct node_msg *msg;
	uint64_t lba;
#ifdef ENABLE_STATS
	uint32_t start_ticks;
#endif

	GLOB_TSTART(start_ticks);

	if (!node_sync_enabled() || !node_tdisk_sync_enabled(amap->amap_table->tdisk)) {
		amap_put(amap);
		tdisk_put(tdisk);
		return;
	}

	amap_lock(amap);
	debug_check(amap->write_id < post->write_id);
	if (amap->write_id != post->write_id) {
		amap_unlock(amap);
		amap_put(amap);
		tdisk_put(tdisk);
		return;
	}

	lba = amap_get_lba_start(amap->amap_id);
	msg = node_sync_msg_alloc(sizeof(*amap_spec), NODE_MSG_AMAP_SYNC_POST);
	amap_spec = (struct amap_spec *)(msg->raw->data);
	amap_spec->write_id = post->write_id;
	amap_spec->lba = lba;
	amap_spec->block = amap->amap_block;
	amap_spec->flags = amap->flags;
	msg->raw->target_id = amap->amap_table->tdisk->target_id;

	node_sync_send_page(msg, NULL, 0, node_sync_timeout, 0);
	amap_unlock(amap);
	amap_put(amap);
	tdisk_put(tdisk);
	node_msg_free(msg);
	GLOB_TEND(amap_sync_post_ticks, start_ticks);
	GLOB_INC(amap_sync_post_count, 1);
}

static void
handle_sync_post(struct node_sync_post *post)
{
	if (post->iowaiter.chan)
		iowaiter_end_wait(&post->iowaiter);

	switch (post->type) {
	case NODE_SYNC_TYPE_AMAP:
		handle_amap_sync_post(post);
		break;
	case NODE_SYNC_TYPE_AMAP_TABLE:
		handle_amap_table_sync_post(post);
		break;
	case NODE_SYNC_TYPE_LOG:
		handle_log_sync_post(post);
		break;
	case NODE_SYNC_TYPE_DDLOOKUP:
		handle_ddlookup_sync_post(post);
		break;
	case NODE_SYNC_TYPE_BINTINDEX:
		handle_bintindex_sync_post(post);
		break;
	}
}

static void
process_post_queue(void)
{
	struct node_sync_post *post;

	while ((post = get_next_sync_post()) != NULL) {
		handle_sync_post(post);
		free_iowaiter(&post->iowaiter);
		uma_zfree(node_sync_post_cache, post);
	}
}

#ifdef FREEBSD 
static void sync_post_thread(void *data)
#else
static int sync_post_thread(void *data)
#endif
{
	struct qs_sync_thr *sthr;

	sthr = (struct qs_sync_thr *)data;
	__sched_prio(curthread, QS_PRIO_INOD);

	for (;;) {
		wait_on_chan_interruptible(sync_post_wait, !STAILQ_EMPTY(&pending_post_queue) || kernel_thread_check(&sthr->exit_flags, GDEVQ_EXIT));
		process_post_queue();
		if (unlikely(kernel_thread_check(&sthr->exit_flags, GDEVQ_EXIT)))
			break;
	}
#ifdef FREEBSD 
	kproc_exit(0);
#else
	return 0;
#endif
}

static struct qs_sync_thr *
init_sthr(int id)
{
	struct qs_sync_thr *sthr;
	int retval;

	sthr = zalloc(sizeof(*sthr), M_SYNC_THR, Q_WAITOK);
	sthr->id = id;

	retval = kernel_thread_create(sync_post_thread, sthr, sthr->task, "sthr%d", id);
	if (unlikely(retval != 0)) {
		debug_warn("Failed to run sthr\n");
		free(sthr, M_SYNC_THR);
		return NULL;
	}
	return sthr;
}

void
node_sync_exit_threads(void)
{
	struct qs_sync_thr *sthr;
	int err;

	while ((sthr = SLIST_FIRST(&sync_thr_list)) != NULL) {
		SLIST_REMOVE_HEAD(&sync_thr_list, d_list);
		err = kernel_thread_stop(sthr->task, &sthr->exit_flags, sync_post_wait, GDEVQ_EXIT);
		if (err) {
			debug_warn("Shutting down sync thr %d\n", sthr->id);
			continue;
		}
		free(sthr, M_SYNC_THR);
	}
	wait_chan_free(sync_post_wait);
}

int
node_sync_init_threads(void)
{
	int i;
	struct qs_sync_thr *sthr;

	sync_post_wait = wait_chan_alloc("node sync wait");
	for (i = 0; i < MAX_GDEVQ_THREADS; i++) {
		sthr = init_sthr(i);
		if (unlikely(!sthr)) {
			debug_warn("Failed to init sthr at %d\n", i);
			return -1;
		}
		SLIST_INSERT_HEAD(&sync_thr_list, sthr, d_list);
	}
	return 0;
}
