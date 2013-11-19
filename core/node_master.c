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
#include "vdevdefs.h"
#include "tdisk.h"
#include "log_group.h"
#include "sense.h"
#include "node_sock.h"
#include "rcache.h"
#include "node_sync.h"
#include "node_ha.h"
#include "ddthread.h"
#include "../common/cluster_common.h" 
#include "bdevgroup.h"
#include "node_mirror.h"

struct node_comm *root;
struct node_comm *sync_root;

wait_chan_t *master_wait;
wait_chan_t *master_cleanup_wait;
wait_chan_t *master_sync_wait;
static kproc_t *master_task;
static kproc_t *master_cleanup_task;
static kproc_t *master_sync_task;
extern kproc_t *recv_task;
extern wait_chan_t *recv_wait;
extern int recv_flags;
int master_flags;
static int master_cleanup_flags;
static int master_sync_flags;
static struct queue_list master_queue_list = TAILQ_HEAD_INITIALIZER(master_queue_list);
static mtx_t *master_queue_lock;
struct node_config master_config;
atomic_t node_role;
atomic_t master_pending_writes;
static int node_master_write_unaligned(struct tdisk *tdisk, struct qsio_scsiio *ctio, struct write_list *wlist, struct node_msg *msg);

int
node_get_role(void)
{
	return (atomic_read(&node_role));
}

void
node_set_role(int role)
{
	atomic_set(&node_role, role);
}

void
node_master_pending_writes_incr(void)
{
	atomic_inc(&master_pending_writes);
}

void
node_master_pending_writes_decr(void)
{
	debug_check(!atomic_read(&master_pending_writes));
	if (atomic_dec_and_test(&master_pending_writes)) {
		if (master_wait)
			chan_wakeup_nointr(master_wait);
	}
}

void
node_master_pending_writes_wait(void)
{
	wait_on_chan(master_wait, !atomic_read(&master_pending_writes));
}

static inline void
scsi_cmd_spec_read(struct scsi_cmd_spec *spec, struct qsio_scsiio *ctio)
{
	ctio->task_tag = spec->task_tag;
	port_fill(ctio->i_prt, spec->i_prt);
	port_fill(ctio->t_prt, spec->t_prt);
	ctio->r_prt = spec->r_prt;
	ctio->init_int = spec->init_int;
	ctio->task_attr = spec->task_attr;
}

static inline void
scsi_cmd_spec_generic_read(struct scsi_cmd_spec_generic *spec, struct qsio_scsiio *ctio)
{
	memcpy(ctio->cdb, spec->cdb, sizeof(spec->cdb));
	ctio->task_tag = spec->task_tag;
	port_fill(ctio->i_prt, spec->i_prt);
	port_fill(ctio->t_prt, spec->t_prt);
	ctio->r_prt = spec->r_prt;
	ctio->init_int = spec->init_int;
	ctio->task_attr = spec->task_attr;
}

void
node_msg_cleanup(struct node_msg *msg)
{
	if (msg->wlist)
		write_list_free(msg->wlist);
	node_msg_free(msg);
}

void
node_master_end_ctio(struct qsio_scsiio *ctio)
{
	struct ccb_list ctio_list;
	struct node_msg *msg = ctio_get_node_msg(ctio);

	debug_check(!msg);
	node_comm_put(msg->sock->comm);
	STAILQ_INIT(&ctio_list);
	device_remove_ctio(ctio, &ctio_list);
	ctio_check_free_data(ctio);
	ctio_free_all(ctio);
	device_queue_ctio_list(&ctio_list);
}

static void
node_master_send_ccb(void *ccb_void)
{
	struct qsio_scsiio *ctio = ccb_void;
	struct node_msg *msg = ctio_get_node_msg(ctio);
	struct raw_node_msg *raw = msg->raw;
	struct scsi_sense_spec *sense_spec;
	struct ccb_list ctio_list;

	STAILQ_INIT(&ctio_list);
	device_remove_ctio(ctio, &ctio_list);
	if (ctio->scsi_status == SCSI_STATUS_CHECK_COND) {
		int sense_offset = (ctio->init_int != TARGET_INT_ISCSI) ? 0 : 2;
		struct qs_sense_data *sense = (struct qs_sense_data *)(ctio->sense_data+sense_offset);

		msg->raw = malloc(sizeof(*sense_spec) + sizeof(*raw), M_NODE_RMSG, Q_WAITOK);
		memcpy(msg->raw, raw, sizeof(*raw));
		free(raw, M_NODE_RMSG);
		raw = msg->raw;

		sense_spec = (struct scsi_sense_spec *)(raw->data);
		sense_spec->sense_key = sense->flags;
		sense_spec->error_code = sense->error_code;
		sense_spec->info = *((uint32_t *)sense->info); 
		sense_spec->asc = sense->add_sense_code;
		sense_spec->ascq = sense->add_sense_code_qual;
		debug_info("cmd %x sense key %x error code %x info %u asc %x ascq %x\n", ctio->cdb[0], sense_spec->sense_key, sense_spec->error_code, sense_spec->info, sense_spec->asc, sense_spec->ascq);
		raw->msg_status = NODE_STATUS_SCSI_SENSE; 
		raw->dxfer_len = sizeof(*sense_spec);
		raw->pg_count = 0;
		node_send_msg(msg->sock, msg, 0, 0);
	}
	else {
		raw->msg_status = ctio->scsi_status;
		raw->dxfer_len = ctio->dxfer_len;

		raw->data_csum = net_calc_csum16((uint8_t *)ctio->data_ptr, ctio->dxfer_len);
		raw->csum = net_calc_csum16((((uint8_t *)raw) + sizeof(uint16_t)), sizeof(*raw) - sizeof(uint16_t));
		if (ctio->dxfer_len)
			node_sock_start(msg->sock);
		node_sock_write_data(msg->sock, (uint8_t *)raw, sizeof(*raw));
		debug_check(ctio->pglist_cnt);
		if (ctio->dxfer_len) {
			node_sock_write_data(msg->sock, (uint8_t *)ctio->data_ptr, ctio->dxfer_len);
			node_sock_end(msg->sock);
		}
	}
	node_comm_put(msg->sock->comm);
	node_msg_cleanup(msg);
	ctio_free_all(ctio);
	device_queue_ctio_list(&ctio_list);
}

void
node_master_cmd_generic(struct node_sock *sock, struct raw_node_msg *raw, int in_sync)
{
	struct tdisk *tdisk;
	struct qsio_scsiio *ctio;
	struct node_msg *msg;
	struct scsi_cmd_spec_generic *cmd_spec;
	int retval, ctio_dxfer_len, i;
	struct pgdata **pglist, *pgdata;
	uint16_t csum;
	int exec;

	tdisk = tdisk_locate(raw->target_id);
	if (unlikely(!tdisk)) {
		debug_warn("node cmd request for unknown tdisk %d\n", raw->target_id);
		node_msg_discard(sock, raw);
		node_resp_msg(sock, raw, NODE_STATUS_TARGET_NOT_FOUND);
		return;
	}

	msg = node_msg_alloc(raw->dxfer_len);
	msg->tdisk = tdisk;
	msg->sock = sock;
	memcpy(msg->raw, raw, sizeof(*raw));
	raw = msg->raw;

	raw->xchg_id = node_transaction_id();
	retval = node_sock_read_nofail(sock, raw->data, raw->dxfer_len);
	if (unlikely(retval != 0)) {
		debug_warn("Failed to read %d bytes retval %d\n", raw->dxfer_len, retval);
		node_msg_free(msg);
		return;
	}

	csum = net_calc_csum16(raw->data, raw->dxfer_len);
	if (unlikely(csum != raw->data_csum)) {
		debug_warn("data csum mismatch %x %x\n", csum, raw->data_csum);
		node_sock_read_error(sock);
		node_msg_free(msg);
		return;
	}

	ctio = ctio_new(Q_NOWAIT);
	if (unlikely(!ctio)) {
		debug_warn("Unable to allocate a new ctio\n");
		node_msg_discard_pages(sock, raw->pg_count);
		node_resp_msg(sock, raw, NODE_STATUS_MEM_ALLOC_FAILURE);
		node_msg_free(msg);
		return;
	}

	cmd_spec = scsi_cmd_spec_generic_ptr(raw);
	scsi_cmd_spec_generic_read(cmd_spec, ctio);
	ctio->ccb_h.flags = QSIO_DIR_OUT;
	ctio->ccb_h.tdisk = tdisk;
	ctio->ccb_h.queue_fn = node_master_send_ccb;

	ctio_dxfer_len = cmd_spec->transfer_length;
	if (raw->pg_count) {
		retval = device_allocate_buffers(ctio, raw->pg_count, Q_WAITOK);
		if (unlikely(retval != 0)) {
			debug_warn("Unable to allocate a ctio buffers\n");
			node_msg_discard_pages(sock, raw->pg_count);
			node_resp_msg(sock, raw, NODE_STATUS_MEM_ALLOC_FAILURE);
			node_msg_free(msg);
			ctio_free(ctio);
			return;
		}

		csum = 0;
		pglist = (struct pgdata **)(ctio->data_ptr);
		for (i = 0; i < raw->pg_count; i++) {
			pgdata = pglist[i];

			retval = node_sock_read_nofail(sock, pgdata_page_address(pgdata), LBA_SIZE);
			if (unlikely(retval != 0)) {
				debug_warn("Failed to read %d bytes retval %d\n", LBA_SIZE, retval);
				node_msg_free(msg);
				ctio_free_all(ctio);
				return;
			}
			csum += pgdata_csum(pgdata, LBA_SIZE);
			atomic_set_bit(DDBLOCK_DEDUPE_DISABLED, &pgdata->flags);
			mark_complete(pgdata);
		}

		if (unlikely(csum != cmd_spec->csum)) {
			debug_warn("csum %x mismatch with cmd spec csum %x\n", csum, cmd_spec->csum);
			node_msg_free(msg);
			ctio_free_all(ctio);
			node_sock_read_error(sock);
			return;
		}
		ctio->dxfer_len = ctio_dxfer_len;
	}
	else if (ctio_dxfer_len) {
		ctio_allocate_buffer(ctio, ctio_dxfer_len, Q_WAITOK);
		memcpy(ctio->data_ptr, scsi_data_ptr_generic(raw), ctio_dxfer_len);
	}

	raw->pg_count = 0;
	ctio_set_node_msg(ctio, msg);
	if (in_sync) {
		ctio_set_in_sync(ctio);
		ctio_set_in_mirror(ctio);
	}

	exec = __device_istate_queue_ctio(tdisk, ctio, 1);
	if (exec)
		node_master_proc_cmd(tdisk, ctio);
}

void
node_master_cmd_persistent_reserve_out(struct node_sock *sock, struct raw_node_msg *raw, int in_sync)
{
	struct tdisk *tdisk;
	struct qsio_scsiio *ctio;
	struct node_msg *msg;
	struct scsi_cmd_spec_generic *cmd_spec;
	int retval, ctio_dxfer_len;
	uint16_t csum;
	int exec;

	tdisk = tdisk_locate(raw->target_id);
	if (unlikely(!tdisk)) {
		debug_warn("node cmd request for unknown tdisk %d\n", raw->target_id);
		node_msg_discard(sock, raw);
		node_resp_msg(sock, raw, NODE_STATUS_TARGET_NOT_FOUND);
		return;
	}

	msg = node_msg_alloc(raw->dxfer_len);
	msg->tdisk = tdisk;
	msg->sock = sock;
	memcpy(msg->raw, raw, sizeof(*raw));
	raw = msg->raw;

	raw->xchg_id = node_transaction_id();
	retval = node_sock_read_nofail(sock, raw->data, raw->dxfer_len);
	if (unlikely(retval != 0)) {
		debug_warn("Failed to read %d bytes retval %d\n", raw->dxfer_len, retval);
		node_msg_free(msg);
		return;
	}

	csum = net_calc_csum16(raw->data, raw->dxfer_len);
	if (unlikely(csum != raw->data_csum)) {
		debug_warn("data csum mismatch %x %x\n", csum, raw->data_csum);
		node_sock_read_error(sock);
		node_msg_free(msg);
		return;
	}

	ctio = ctio_new(Q_NOWAIT);
	if (unlikely(!ctio)) {
		debug_warn("Unable to allocate a new ctio\n");
		node_resp_msg(sock, raw, NODE_STATUS_MEM_ALLOC_FAILURE);
		node_msg_free(msg);
		return;
	}

	cmd_spec = scsi_cmd_spec_generic_ptr(raw);
	scsi_cmd_spec_generic_read(cmd_spec, ctio);
	ctio->ccb_h.flags = QSIO_DIR_OUT;
	ctio->ccb_h.tdisk = tdisk;
	ctio->ccb_h.queue_fn = node_master_send_ccb;
	if (in_sync)
		ctio_set_in_sync(ctio);

	ctio_dxfer_len = cmd_spec->transfer_length;
	if (ctio->init_int == TARGET_INT_ISCSI) {
		struct iscsi_priv *priv = &ctio->ccb_h.priv.ipriv;
		priv->init_name = scsi_data_ptr_generic(raw); 
	}

	if (ctio_dxfer_len) {
		ctio_allocate_buffer(ctio, ctio_dxfer_len, Q_WAITOK);
		memcpy(ctio->data_ptr, ((uint8_t *)scsi_data_ptr_generic(raw)) + INITIATOR_NAME_MAX, ctio_dxfer_len);
	}

	raw->pg_count = 0;
	ctio_set_node_msg(ctio, msg);
	exec = __device_istate_queue_ctio(tdisk, ctio, 1);
	if (exec)
		node_master_proc_cmd(tdisk, ctio);
}

static int
xcopy_read_validate(struct tdisk *src_tdisk, struct tdisk *dest_tdisk, struct node_sock *sock)
{
	if (!tdisk_mirroring_configured(dest_tdisk))
		return -1;

	if (!tdisk_mirroring_configured(src_tdisk))
		return -1;

	if (src_tdisk->mirror_state.mirror_ipaddr != dest_tdisk->mirror_state.mirror_ipaddr)
		return -1;

	if (src_tdisk->mirror_state.mirror_ipaddr != sock->comm->node_ipaddr)
		return -1;

	if (tdisk_mirroring_disabled(src_tdisk) || tdisk_mirroring_disabled(dest_tdisk))
		return -1;

	if (tdisk_mirroring_need_resync(src_tdisk) || tdisk_mirroring_need_resync(dest_tdisk))
		return -1;

	return 0;
}

void
node_master_xcopy_read(struct node_sock *sock, struct raw_node_msg *raw, struct queue_list *queue_list, mtx_t *queue_lock)
{
	struct tdisk *tdisk, *dest_tdisk;
	struct qsio_scsiio *ctio;
	struct node_msg *msg;
	struct xcopy_read_spec *xcopy_spec;
	uint8_t *cdb;
	int retval;
	uint16_t csum;
	struct pgdata **pglist;
	int pglist_cnt;
	struct write_list *wlist;
	struct lba_write *lba_write;

	tdisk = tdisk_locate(raw->target_id);
	if (unlikely(!tdisk)) {
		debug_warn("node cmd request for unknown tdisk %d\n", raw->target_id);
		node_error_resp_msg(sock, raw, NODE_STATUS_TARGET_NOT_FOUND);
		return;
	}

	msg = node_msg_alloc(raw->dxfer_len);
	msg->tdisk = tdisk;
	msg->sock = sock;
	msg->queue_list = queue_list;
	msg->queue_lock = queue_lock;
	memcpy(msg->raw, raw, sizeof(*raw));
	raw = msg->raw;

	raw->xchg_id = node_transaction_id();
	debug_check(raw->dxfer_len != sizeof(*xcopy_spec));
	retval = node_sock_read_nofail(sock, raw->data, raw->dxfer_len);
	if (unlikely(retval != 0)) {
		debug_warn("Failed to read %d bytes retval %d\n", raw->dxfer_len, retval);
		node_msg_free(msg);
		return;
	}

	csum = net_calc_csum16(raw->data, raw->dxfer_len);
	if (unlikely(csum != raw->data_csum)) {
		debug_warn("data csum mismatch %x %x\n", csum, raw->data_csum);
		node_sock_read_error(sock);
		node_msg_free(msg);
		return;
	}

	xcopy_spec = (struct xcopy_read_spec *)(raw->data);
	dest_tdisk = tdisk_locate(xcopy_spec->dest_target_id);
	if (unlikely(!dest_tdisk)) {
		debug_warn("Cannot locate dest tdisk at %u\n", xcopy_spec->dest_target_id);
		node_resp_msg(sock, raw, NODE_STATUS_MEM_ALLOC_FAILURE);
		node_msg_free(msg);
		return;
	}

	debug_info("lba %llu dest lba %llu num blocks %u xchg_id %x\n", (unsigned long long)xcopy_spec->lba, (unsigned long long)xcopy_spec->dest_lba, xcopy_spec->num_blocks, raw->xchg_id);
	lba_write = tdisk_add_lba_write(tdisk, xcopy_spec->lba, xcopy_spec->num_blocks, 0, QS_IO_READ, 0);
	retval = xcopy_read_validate(tdisk, dest_tdisk, sock);
	if (unlikely(retval != 0)) {
		tdisk_remove_lba_write(tdisk, &lba_write);
		tdisk_put(dest_tdisk);
		node_resp_msg(sock, raw, NODE_STATUS_ERROR);
		node_msg_free(msg);
		return;
	}

	ctio = ctio_new(Q_NOWAIT);
	if (unlikely(!ctio)) {
		tdisk_remove_lba_write(tdisk, &lba_write);
		debug_warn("Unable to allocate a new ctio\n");
		tdisk_put(dest_tdisk);
		node_resp_msg(sock, raw, NODE_STATUS_MEM_ALLOC_FAILURE);
		node_msg_free(msg);
		return;
	}

	cdb = ctio->cdb;
	cdb[0] = EXTENDED_COPY;
	*(uint64_t *)(&cdb[2]) = htobe64(xcopy_spec->dest_lba);
	*(uint32_t *)(&cdb[10]) = htobe32(xcopy_spec->num_blocks);

	ctio->ccb_h.flags = QSIO_DIR_OUT;
	ctio->ccb_h.tdisk = tdisk;
	ctio->ccb_h.queue_fn = node_master_send_ccb;
	ctio->task_tag = xcopy_spec->task_tag;
	ctio->task_attr = xcopy_spec->task_attr;
	port_fill(ctio->i_prt, xcopy_spec->i_prt);
	port_fill(ctio->t_prt, xcopy_spec->t_prt);
	ctio->r_prt = xcopy_spec->r_prt;

	ctio_set_node_msg(ctio, msg);
	ctio_set_in_sync(ctio);

	wlist = write_list_alloc(tdisk);
	msg->wlist = wlist;

	retval = __tdisk_cmd_ref_int(tdisk, dest_tdisk, ctio, &pglist, &pglist_cnt, xcopy_spec->lba, xcopy_spec->num_blocks, &wlist->index_info_list, 1, 1);
	tdisk_remove_lba_write(tdisk, &lba_write);
	if (unlikely(retval != 0)) {
		tdisk_put(dest_tdisk);
		ctio_free(ctio);
		node_resp_msg(sock, raw, NODE_STATUS_MEM_ALLOC_FAILURE);
		node_msg_cleanup(msg);
		return;
	}
	ctio->pglist_cnt = pglist_cnt;
	ctio->data_ptr = (void *)pglist;
	ctio->dxfer_len = xcopy_spec->num_blocks << tdisk->lba_shift;
	pglist_calc_hash(dest_tdisk, pglist, pglist_cnt, 0, 1);
	tdisk_put(dest_tdisk);

	raw->cmd_status = NODE_CMD_DONE;
	raw->dxfer_len = 0;
	retval = node_send_msg(msg->sock, msg, raw->xchg_id, 1);
	if (unlikely(retval != 0)) {
		ctio_free_all(ctio);
		node_msg_cleanup(msg);
	}
	debug_info("end with retval %d\n", retval);
}

void
node_master_read_cmd(struct node_sock *sock, struct raw_node_msg *raw, struct queue_list *queue_list, mtx_t *queue_lock, int in_sync)
{
	struct tdisk *tdisk;
	struct qsio_scsiio *ctio;
	struct node_msg *msg;
	uint8_t *cdb;
	struct scsi_cmd_spec *cmd_spec;
	int retval;
	uint16_t csum;
	int exec;

	tdisk = tdisk_locate(raw->target_id);
	if (unlikely(!tdisk)) {
		debug_warn("node cmd request for unknown tdisk %d\n", raw->target_id);
		node_error_resp_msg(sock, raw, NODE_STATUS_TARGET_NOT_FOUND);
		return;
	}

	msg = node_msg_alloc(raw->dxfer_len);
	msg->tdisk = tdisk;
	msg->sock = sock;
	msg->queue_list = queue_list;
	msg->queue_lock = queue_lock;
	memcpy(msg->raw, raw, sizeof(*raw));
	raw = msg->raw;

	raw->xchg_id = node_transaction_id();
	debug_check(raw->dxfer_len != sizeof(*cmd_spec));
	retval = node_sock_read_nofail(sock, raw->data, raw->dxfer_len);
	if (unlikely(retval != 0)) {
		debug_warn("Failed to read %d bytes retval %d\n", raw->dxfer_len, retval);
		node_msg_free(msg);
		return;
	}

	csum = net_calc_csum16(raw->data, raw->dxfer_len);
	if (unlikely(csum != raw->data_csum)) {
		debug_warn("data csum mismatch %x %x\n", csum, raw->data_csum);
		node_sock_read_error(sock);
		node_msg_free(msg);
		return;
	}

	ctio = ctio_new(Q_NOWAIT);
	if (unlikely(!ctio)) {
		debug_warn("Unable to allocate a new ctio\n");
		node_resp_msg(sock, raw, NODE_STATUS_MEM_ALLOC_FAILURE);
		node_msg_free(msg);
		return;
	}

	cmd_spec = scsi_cmd_spec_ptr(raw); 

	cdb = ctio->cdb;
	cdb[0] = READ_16;

	*(uint64_t *)(&cdb[2]) = htobe64(cmd_spec->lba);
	*(uint32_t *)(&cdb[10]) = htobe32(cmd_spec->transfer_length);
	scsi_cmd_spec_read(cmd_spec, ctio);
	ctio->ccb_h.flags = QSIO_DIR_OUT;
	ctio->ccb_h.tdisk = tdisk;
	ctio->ccb_h.queue_fn = node_master_send_ccb;

	ctio_set_node_msg(ctio, msg);
	if (in_sync)
		ctio_set_in_sync(ctio);

	exec = __device_istate_queue_ctio(tdisk, ctio, 1);
	if (exec)
		node_master_proc_cmd(tdisk, ctio);
}

static void
mark_pgdata_zero_block(struct pgdata **pglist, int i, int pglist_cnt)
{
	struct pgdata *pgdata;

	debug_info("mark from %d to %d\n", i, pglist_cnt);
	while (i < pglist_cnt) {
		pgdata = pglist[i];
		atomic_set_bit(DDBLOCK_ZERO_BLOCK, &pgdata->flags);
		mark_complete(pgdata);
		i++;
	}
}

static int 
fill_pglist(struct node_msg *msg, struct node_sock *sock, struct pgdata **pglist, int pglist_cnt, int unaligned)
{
	struct pgdata_spec *source_spec, *source_spec_list;
	struct pgdata *pgdata;
	int i, retval, todo, src_idx;

	source_spec_list = pgdata_spec_ptr(msg->raw);
	todo = msg->raw->dxfer_len - sizeof(struct scsi_cmd_spec);
	src_idx = 0;

	debug_info("todo %d pglist_cnt %d unaligned %d\n", todo, pglist_cnt, unaligned);
	for (i = 0; (i < pglist_cnt) && todo; i++) {
		pgdata = pglist[i];
		mark_complete(pgdata);
		source_spec = &source_spec_list[src_idx];
		if (!unaligned && source_spec->csum != i) {
			if (unlikely(source_spec->csum > pglist_cnt)) {
				debug_warn("Mismatch in expected page count source spec count %d pglist cnt %d\n", source_spec->csum, pglist_cnt);
				node_resp_msg(sock, msg->raw, NODE_STATUS_INVALID_MSG);
				return -1;
			}

			mark_pgdata_zero_block(pglist, i, source_spec->csum);
			i = source_spec->csum;
			pgdata = pglist[i];
			mark_complete(pgdata);
		}
		pgdata->flags = source_spec->flags;
		memcpy(pgdata->hash, source_spec->hash, sizeof(pgdata->hash));
		if (unaligned) {
			retval = pgdata_alloc_page(pgdata, 0);
			if (unlikely(retval != 0)) {
				debug_warn("allocating for pgdata page failed\n");
				node_resp_msg(sock, msg->raw, NODE_STATUS_MEM_ALLOC_FAILURE);
				return retval;
			}

			retval = node_sock_read_nofail(sock, pgdata_page_address(pgdata), LBA_SIZE);
			if (unlikely(retval != 0)) {
				debug_warn("Failed to read %d bytes retval %d\n", LBA_SIZE, retval);
				return retval;
			}

			if (unlikely(pgdata_csum(pgdata, LBA_SIZE) != source_spec->csum)) {
				debug_warn("Invalid pgdata csum %x %x\n", pgdata_csum(pgdata, LBA_SIZE), source_spec->csum);
				debug_check(1);
				node_sock_read_error(sock);
				return -1;
			}
		}
		todo -= sizeof(*source_spec);
		src_idx++;
	}

	if (unlikely(todo)) {
		debug_warn("Mismatch in expect page count remaining %d done %d pglist_cnt %d\n", todo, i, pglist_cnt);
		node_resp_msg(sock, msg->raw, NODE_STATUS_INVALID_MSG);
		return -1;
	}

	if (i != pglist_cnt)
		mark_pgdata_zero_block(pglist, i, pglist_cnt);

	return 0;
}

static void
node_master_read_pre(struct tdisk *tdisk, struct qsio_scsiio *ctio)
{
	uint8_t *cdb = ctio->cdb;
	uint64_t lba;
	uint32_t transfer_length;
	struct pgdata *pgtmp, **pglist = NULL;
	struct bdevint *bint = NULL;
	struct amap *amap = NULL;
	struct amap_table *amap_table = NULL;
	struct write_list *wlist = NULL;
	struct amap_table_list table_list;
	struct index_info_list index_info_list;
	struct pgdata_wlist read_list;
	uint32_t entry_id;
	uint64_t amap_entry_block;
	int retval, i;
	int pglist_cnt;
	int need_io = 0;
	int have_rcache = 0;
	struct node_msg *msg = ctio_get_node_msg(ctio);
	struct raw_node_msg *raw;
	struct pgdata_read_spec *source_spec;
	struct node_sock *sock;

	lba = be64toh(*(uint64_t *)(&cdb[2]));
	transfer_length = be32toh(*(uint32_t *)(&cdb[10]));

	if (reached_eom(tdisk, lba, transfer_length)) {
		ctio_construct_sense(ctio, SSD_CURRENT_ERROR, SSD_KEY_ILLEGAL_REQUEST, 0, LOGICAL_BLOCK_ADDRESS_OUT_OF_RANGE_ASC, LOGICAL_BLOCK_ADDRESS_OUT_OF_RANGE_ASCQ);
		device_send_ccb(ctio);
		return;
	}

	TDISK_INC(tdisk, lba_read_count, transfer_length);
	TDISK_INC(tdisk, read_count, 1);
	TDISK_STATS_ADD(tdisk, read_size, (transfer_length << tdisk->lba_shift));

	wlist = zalloc(sizeof(*wlist), M_WLIST, Q_WAITOK);
	wlist->lba_write = tdisk_add_lba_write(tdisk, lba, transfer_length, 0, QS_IO_READ, 0);
	node_master_pending_writes_incr();

	if (tdisk->lba_shift != LBA_SHIFT) {
		uint64_t lba_diff;

		lba_diff = tdisk_get_lba_diff(tdisk, lba);
		transfer_length += lba_diff;
		lba -= lba_diff;
		lba >>= 3;
	}

	pglist_cnt = transfer_length_to_pglist_cnt(tdisk->lba_shift, transfer_length);

	pglist = pgdata_allocate_nopage(pglist_cnt, Q_NOWAIT); 
	if (unlikely(!pglist)) {
		ctio_construct_sense(ctio, SSD_CURRENT_ERROR, SSD_KEY_HARDWARE_ERROR, 0, INTERNAL_TARGET_FAILURE_ASC, INTERNAL_TARGET_FAILURE_ASCQ);
		tdisk_remove_lba_write(tdisk, &wlist->lba_write);
		node_master_pending_writes_decr();
		write_list_free(wlist);
		device_send_ccb(ctio);
		return;
	}

	STAILQ_INIT(&table_list);
	TAILQ_INIT(&index_info_list);
	STAILQ_INIT(&read_list);

	wlist->start_lba = lba;
	for (i = 0; i < pglist_cnt; i++, lba++) {
		pgtmp =  pglist[i];
		pgtmp->lba = lba;
		retval = lba_unmapped(tdisk, lba, pgtmp, &table_list, amap_table, amap);
		if (retval < 0)
			goto err;

		amap_table = pgtmp->amap_table;
		amap = pgtmp->amap;
	}

	retval = pgdata_check_table_list(&table_list, &index_info_list, NULL, QS_IO_READ, 0);
	if (unlikely(retval != 0))
		goto err;

	raw = zalloc(pgdata_read_spec_dxfer_len(pglist_cnt) + sizeof(*raw), M_NODE_RMSG, Q_WAITOK);
	memcpy(raw, msg->raw, sizeof(*raw));
	free(msg->raw, M_NODE_RMSG);
	msg->raw = raw;
	raw->dxfer_len = pgdata_read_spec_dxfer_len(pglist_cnt);

	source_spec = pgdata_read_spec_ptr(raw);
	for (i = 0; i < pglist_cnt; i++, source_spec++) {
		pgtmp =  pglist[i];

		amap = pgtmp->amap;
		if (!amap) {
			atomic_set_bit(DDBLOCK_ZERO_BLOCK, &pgtmp->flags);
			source_spec->flags = pgtmp->flags;
			continue;
		}

		wait_on_chan_check(amap->amap_wait, !atomic_test_bit_short(AMAP_META_DATA_READ_DIRTY, &amap->flags));

		entry_id = amap_entry_id(amap, pgtmp->lba);
		debug_check(entry_id >= ENTRIES_PER_AMAP);
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

		if (!amap_entry_block) {
			atomic_set_bit(DDBLOCK_ZERO_BLOCK, &pgtmp->flags);
			source_spec->flags = pgtmp->flags;
			continue;
		}
		source_spec->amap_block = pgtmp->amap_block = amap_entry_block;

		if (!bint || (bint->bid != BLOCK_BID(amap_entry_block))) {
			bint = bdev_find(BLOCK_BID(amap_entry_block));
			if (unlikely(!bint)) {
				debug_warn("Cannot locate bint at bid %u\n", BLOCK_BID(amap_entry_block));
				goto err;
			}
		}

		if (pgdata_in_read_list(tdisk, pgtmp, &read_list, 0)) {
			source_spec->flags = pgtmp->flags;
			continue;
		}

		if (rcache_locate(pgtmp, 0)) {
			atomic_set_bit(PGDATA_FROM_RCACHE, &pgtmp->flags);
			debug_check(pgtmp->pg_len != LBA_SIZE);
			source_spec->flags = pgtmp->flags;
			have_rcache++;
			source_spec->csum = pgdata_csum(pgtmp, LBA_SIZE);
			continue;
		}

		retval = pgdata_alloc_page(pgtmp, 0);
		if (unlikely(retval != 0)) {
			debug_warn("allocating for pgdata page failed\n");
			goto err;
		}
		need_io = 1;
	}

	ctio->data_ptr = (void *)pglist;
	ctio->pglist_cnt = pglist_cnt;
	ctio->dxfer_len = (pglist_cnt << LBA_SHIFT);

	if (need_io) {
		raw->cmd_status = NODE_CMD_NEED_IO;
		msg->wlist = wlist;
	}
	else {
		tdisk_remove_lba_write(tdisk, &wlist->lba_write);
		write_list_free(wlist);
		wlist = NULL;
		raw->cmd_status = NODE_CMD_DONE;
	}
	raw->pg_count = have_rcache;

	sock = msg->sock;

	node_msg_compute_csum(raw);
	if (need_io)
		node_cmd_hash_insert(sock->comm->node_hash, msg, raw->xchg_id);

	node_sock_start(sock);
	retval = node_sock_write(sock, raw);
	if (unlikely(retval != 0)) {
		node_sock_end(sock);
		goto err2;
	}

	for (i = 0; i < pglist_cnt; i++) {
		pgtmp =  pglist[i];
		if (!atomic_test_bit(PGDATA_FROM_RCACHE, &pgtmp->flags))
			continue;
		retval = node_sock_write_page(sock, pgtmp->page, pgtmp->pg_len);
		if (unlikely(retval != 0)) {
			node_sock_end(sock);
			goto err2;
		}
	}
	node_sock_end(sock);

	if (!need_io) {
		pgdata_free_amaps(pglist, pglist_cnt);
		node_master_pending_writes_decr();
		node_master_end_ctio(ctio);
		node_msg_free(msg);
	}
	return;
err:
	if (wlist) {
		tdisk_remove_lba_write(tdisk, &wlist->lba_write);
		write_list_free(wlist);
	}
	msg->wlist = NULL;

	pgdata_free_amaps(pglist, pglist_cnt);
	node_master_pending_writes_decr();
	pglist_free(pglist, pglist_cnt);
	ctio_construct_sense(ctio, SSD_CURRENT_ERROR, SSD_KEY_HARDWARE_ERROR, 0, INTERNAL_TARGET_FAILURE_ASC, INTERNAL_TARGET_FAILURE_ASCQ);
	device_send_ccb(ctio);
	return;
err2:
	if (wlist) {
		tdisk_remove_lba_write(tdisk, &wlist->lba_write);
		write_list_free(wlist);
	}
	msg->wlist = NULL;

	pgdata_free_amaps(pglist, pglist_cnt);
	if (need_io)
		node_cmd_hash_remove(msg->sock->comm->node_hash, msg, raw->xchg_id);
	node_master_pending_writes_decr();
	node_master_end_ctio(ctio);
	node_msg_free(msg);
}

void
node_master_read_error(struct tdisk *tdisk, struct write_list *wlist, struct qsio_scsiio *ctio)
{
	tdisk_remove_lba_write(tdisk, &wlist->lba_write);
	pgdata_free_amaps((struct pgdata **)ctio->data_ptr, ctio->pglist_cnt);
	node_master_pending_writes_decr();
}

void
node_master_write_error(struct tdisk *tdisk, struct write_list *wlist, struct qsio_scsiio *ctio)
{
	tdisk_write_error(tdisk, ctio, wlist, ctio_in_sync(ctio));
	node_master_pending_writes_decr();
}

static int
__node_master_write_post_pre(struct tdisk *tdisk, struct write_list *wlist, struct pgdata **pglist, int pglist_cnt)
{
	int retval;

	retval = pgdata_amap_io(tdisk, wlist);
	if (unlikely(retval != 0))
		return -1;

	node_newmeta_sync_start(tdisk, wlist);
	node_pgdata_sync_start(tdisk, wlist, pglist, pglist_cnt);
	log_list_end_writes(&wlist->log_list);
	atomic_set_bit(WLIST_DONE_LOG_END, &wlist->flags);

	log_list_end_wait(&wlist->log_list);

	amap_sync_list_free_error(&wlist->nowrites_amap_sync_list);
	sync_amap_list_pre(tdisk, wlist);

	atomic_set_bit(WLIST_DONE_POST_PRE, &wlist->flags);
	return 0;
}

static int
node_master_write_post(struct tdisk *tdisk, struct write_list *wlist, struct qsio_scsiio *ctio)
{
	struct pgdata **pglist;
	int pglist_cnt;
	struct node_msg *msg = ctio_get_node_msg(ctio);
	int retval;

	if (!atomic_test_bit(WLIST_DONE_POST_PRE, &wlist->flags)) {
		retval = __node_master_write_post_pre(tdisk, wlist, (struct pgdata **)ctio->data_ptr, ctio->pglist_cnt);
		if (unlikely(retval != 0))
			return -1;
	}

	pglist = (struct pgdata **)(ctio->data_ptr);
	pglist_cnt = ctio->pglist_cnt;

	ctio->data_ptr = NULL;
	ctio->pglist_cnt = 0;
	ctio->dxfer_len = 0;

	msg->wlist = NULL;
	node_pgdata_sync_client_done(tdisk, wlist->transaction_id);
	pgdata_post_write(tdisk, pglist, pglist_cnt, wlist);

	device_send_ccb(ctio);

	write_list_free(wlist);
	node_master_pending_writes_decr();
	return 0;
}

static void
__node_master_write_pre(struct tdisk *tdisk, struct qsio_scsiio *ctio, int cw)
{
	uint8_t *cdb = ctio->cdb;
	uint64_t lba;
	struct write_list *wlist;
	uint32_t transfer_length;
	struct pgdata **pglist, *pgdata;
	int retval, i;
	struct node_msg *msg;
	struct raw_node_msg *raw;
	struct scsi_cmd_spec *cmd_spec;
	struct pgdata_read_spec *source_spec;
	int need_io = 0, need_comp = 0, need_verify = 0, remote;
	int cw_status, dxfer_len;
	uint32_t cw_offset;
	uint8_t error_code = SSD_KEY_HARDWARE_ERROR;
	uint8_t asc = INTERNAL_TARGET_FAILURE_ASC;
	uint8_t ascq = INTERNAL_TARGET_FAILURE_ASCQ;
#ifdef ENABLE_STATS
	uint32_t start_ticks;
#endif

	msg = ctio_get_node_msg(ctio);
	raw = msg->raw;
	wlist = msg->wlist;
	debug_check(!wlist);

	if (node_in_standby()) {
		ctio_free_data(ctio);
		ctio->scsi_status = SCSI_STATUS_BUSY;
		free_block_refs(tdisk, &wlist->index_info_list);
		device_send_ccb(ctio);
		return;
	}

	lba = be64toh(*(uint64_t *)(&cdb[2]));
	transfer_length = be32toh(*(uint32_t *)(&cdb[10]));

	if (reached_eom(tdisk, lba, transfer_length)) {
		ctio_free_data(ctio);
		ctio_construct_sense(ctio, SSD_CURRENT_ERROR, SSD_KEY_ILLEGAL_REQUEST, 0, LOGICAL_BLOCK_ADDRESS_OUT_OF_RANGE_ASC, LOGICAL_BLOCK_ADDRESS_OUT_OF_RANGE_ASCQ);
		free_block_refs(tdisk, &wlist->index_info_list);
		device_send_ccb(ctio);
		return;
	}

	TDISK_INC(tdisk, lba_write_count, transfer_length);
	TDISK_INC(tdisk, write_count, 1);
	TDISK_STATS_ADD(tdisk, write_size, (transfer_length << tdisk->lba_shift));

	GLOB_TSTART(start_ticks);
	retval = tdisk_lba_write_setup(tdisk, ctio, wlist, lba, transfer_length, cw, 0, 0);
	GLOB_TEND(node_master_lba_write_setup_ticks, start_ticks);
	if (unlikely(retval != 0)) {
		ctio_free_data(ctio);
		free_block_refs(tdisk, &wlist->index_info_list);
		device_send_ccb(ctio);
		return;
	}

	if (tdisk->lba_shift != LBA_SHIFT || cw) {
		cw_status = 0;
		cw_offset = 0;
		retval = check_unaligned_data(tdisk, ctio, &lba, transfer_length, cw, &cw_status, &cw_offset, wlist);
		if (unlikely(retval != 0)) {
			tdisk_remove_lba_write(tdisk, &wlist->lba_write);
			ctio_free_data(ctio);
			ctio_construct_sense(ctio, SSD_CURRENT_ERROR, SSD_KEY_HARDWARE_ERROR, 0, INTERNAL_TARGET_FAILURE_ASC, INTERNAL_TARGET_FAILURE_ASCQ);
			device_send_ccb(ctio);
			return;
		}

		if (cw && cw_status) {
			tdisk_remove_lba_write(tdisk, &wlist->lba_write);
			ctio_free_data(ctio);
			ctio_construct_sense(ctio, SSD_CURRENT_ERROR, SSD_KEY_MISCOMPARE, cw_offset, MISCOMPARE_DURING_VERIFY_OPERATION_ASC, MISCOMPARE_DURING_VERIFY_OPERATION_ASCQ);
			ctio_set_sense_info_valid(ctio);
			TDISK_STATS_ADD(tdisk, cw_misses, 1);
			device_send_ccb(ctio);
			return;
		}
		else if (cw) {
			TDISK_STATS_ADD(tdisk, cw_hits, 1);
		}
	}

	pglist_cnt_incr(ctio->pglist_cnt);
	node_master_pending_writes_incr();

	cmd_spec = scsi_cmd_spec_ptr(raw);
	remote = !atomic_test_bit(WLIST_UNALIGNED_WRITE, &wlist->flags) && !ctio_in_xcopy(ctio);
	GLOB_TSTART(start_ticks);
	wlist->start_lba = lba;
	retval = scan_write_data(tdisk, ctio, lba, (struct pgdata **)(ctio->data_ptr), ctio->pglist_cnt, wlist, &wlist->lba_alloc, remote, &need_comp, cmd_spec->amap_write_id, ctio_in_xcopy(ctio));
	GLOB_TEND(node_master_scan_write_ticks, start_ticks);
	tdisk_remove_alloc_lba_write(&wlist->lba_alloc, tdisk->lba_write_wait, &tdisk->lba_write_list);

	if (unlikely(retval != 0)) {
		debug_warn("scan write data failed for lba %llu transfer length %u\n", (unsigned long long)lba, transfer_length);
		if (retval != ERR_CODE_NOSPACE)
			goto err;
		error_code = SSD_KEY_DATA_PROTECT;
		asc = SPACE_ALLOCATION_FAILED_WRITE_PROTECT_ASC;
		ascq = SPACE_ALLOCATION_FAILED_WRITE_PROTECT_ASCQ;
		goto err;
	}

	if (!STAILQ_EMPTY(&wlist->dedupe_list))
		need_verify = 1;

	dxfer_len = pgdata_read_spec_dxfer_len(ctio->pglist_cnt);
	if (dxfer_len > raw->dxfer_len) {
		msg->raw = malloc(dxfer_len + sizeof(*raw), M_NODE_RMSG, Q_WAITOK);
		memcpy(msg->raw, raw, sizeof(*raw));
		free(raw, M_NODE_RMSG);
		raw = msg->raw;
	}
	raw->dxfer_len = dxfer_len;
	bzero(raw->data, raw->dxfer_len);
	source_spec = pgdata_read_spec_ptr(raw);

	debug_check(ctio_in_xcopy(ctio) && (need_io));
	GLOB_TSTART(start_ticks);
	pglist = (struct pgdata **)(ctio->data_ptr);
	for (i = 0; i < ctio->pglist_cnt; i++, source_spec++) {
		pgdata = pglist[i];
		source_spec->flags = pgdata->flags;
		source_spec->amap_block = pgdata->amap_block;
		if (!atomic_test_bit(DDBLOCK_ENTRY_FOUND_DUPLICATE, &pgdata->flags) && !atomic_test_bit(DDBLOCK_ZERO_BLOCK, &pgdata->flags)) {
			if (!ctio_in_xcopy(ctio)) {
				need_io = 1;
				if (!need_comp && !need_verify && !atomic_test_bit(WLIST_UNALIGNED_WRITE, &wlist->flags))
					TDISK_STATS_ADD(tdisk, uncompressed_size, LBA_SIZE);
			}
			else {
				atomic_set_bit(WLIST_UNALIGNED_WRITE, &wlist->flags);
			}
		}
	}
	GLOB_TEND(node_master_write_spec_setup_ticks, start_ticks);

	debug_check(need_comp && !need_io);
	if (atomic_test_bit(WLIST_UNALIGNED_WRITE, &wlist->flags)) {
		if (ctio_in_sync(ctio) && !ctio_in_xcopy(ctio)) {
			raw->cmd_status = NODE_CMD_NEED_IO_UNALIGNED;
			raw->dxfer_len = 0;
		}
		else {
			retval = node_master_write_unaligned(tdisk, ctio, wlist, msg);
			if (unlikely(retval != 0))
				goto err;
		}
	}
	else if (need_verify) {
		raw->cmd_status = NODE_CMD_NEED_VERIFY;
	}
	else if (need_io) {
		if (need_comp) 
			raw->cmd_status = NODE_CMD_NEED_COMP;
		else {
			raw->cmd_status = NODE_CMD_NEED_IO;
		}
	}
	else {
		raw->cmd_status = NODE_CMD_DONE;
		raw->dxfer_len = 0;
	}

	if (ctio_in_sync(ctio) && tdisk_mirror_master(tdisk) && !tdisk_lba_needs_mirror_sync(tdisk, lba))
		msg->raw->mirror_status = NODE_STATUS_SKIP_LOCAL_WRITE;

	GLOB_TSTART(start_ticks);
	retval = node_send_msg(msg->sock, msg, raw->xchg_id, 1);
	GLOB_TEND(node_master_write_setup_send_ticks, start_ticks);

	if (unlikely(retval != 0)) {
		if (msg->tcache) {
			wait_for_done(msg->tcache->completion);
			tcache_put(msg->tcache);
		}
		goto err2;
	}
	return;

err:
	node_master_write_error(tdisk, wlist, ctio);
	ctio_check_free_data(ctio);
	ctio_construct_sense(ctio, SSD_CURRENT_ERROR, error_code, 0, asc, ascq);
	device_send_ccb(ctio);
	return;
err2:
	node_master_write_error(tdisk, wlist, ctio);
	node_master_end_ctio(ctio);
	node_msg_cleanup(msg);
	return;
}

static void
node_master_write_pre(struct tdisk *tdisk, struct qsio_scsiio *ctio)
{
#ifdef ENABLE_STATS
	uint32_t start_ticks;
#endif
	GLOB_TSTART(start_ticks);
	__node_master_write_pre(tdisk, ctio, 0);
	GLOB_TEND(node_master_write_pre_ticks, start_ticks); 
}

void
node_master_xcopy_write(struct node_sock *sock, struct raw_node_msg *raw, struct queue_list *queue_list, mtx_t *queue_lock)
{
	struct tdisk *tdisk;
	struct qsio_scsiio *ctio;
	struct node_msg *msg;
	uint8_t *cdb;
	struct write_list *wlist;
	int exec;

	debug_info("xchg id %x\n", raw->xchg_id);
	msg = node_cmd_lookup(sock->comm->node_hash, raw->xchg_id, queue_list, queue_lock);
	if (unlikely(!msg)) {
		debug_warn("Missing exchange cmd %llx\n", (unsigned long long)raw->xchg_id);
		node_error_resp_msg(sock, raw, NODE_STATUS_INVALID_MSG);
		return;
	}

	ctio = msg->ctio;
	wlist = msg->wlist;
	tdisk = msg->tdisk;
	msg->sock = sock;

	debug_check(!ctio);
	debug_check(!wlist);
	debug_check(!tdisk);
	
	memcpy(msg->raw, raw, sizeof(*raw));

	cdb = ctio->cdb;
	cdb[0] = WRITE_16;
	ctio_set_in_xcopy(ctio);

	exec = __device_istate_queue_ctio(tdisk, ctio, 1);
	if (exec)
		node_master_proc_cmd(tdisk, ctio);
}

void
node_master_write_cmd(struct node_sock *sock, struct raw_node_msg *raw, struct queue_list *queue_list, mtx_t *queue_lock, int in_sync, int remote_locked)
{
	struct tdisk *tdisk;
	struct qsio_scsiio *ctio;
	struct node_msg *msg;
	uint8_t *cdb;
	struct scsi_cmd_spec *cmd_spec;
	struct write_list *wlist;
	struct pgdata **pglist;
	int retval, unaligned;
	uint16_t csum;
	int exec;

	tdisk = tdisk_locate(raw->target_id);
	if (unlikely(!tdisk)) {
		debug_warn("node cmd request for unknown tdisk %d\n", raw->target_id);
		node_error_resp_msg(sock, raw, NODE_STATUS_TARGET_NOT_FOUND);
		return;
	}

	msg = node_msg_alloc(raw->dxfer_len);
	msg->tdisk = tdisk;
	msg->sock = sock;
	msg->queue_list = queue_list;
	msg->queue_lock = queue_lock;
	memcpy(msg->raw, raw, sizeof(*raw));
	raw = msg->raw;

	raw->xchg_id = node_transaction_id();
	retval = node_sock_read_nofail(sock, raw->data, raw->dxfer_len);
	if (unlikely(retval != 0)) {
		debug_warn("Failed to read %d bytes retval %d\n", raw->dxfer_len, retval);
		node_msg_free(msg);
		return;
	}

	csum = net_calc_csum16(raw->data, raw->dxfer_len);
	if (unlikely(csum != raw->data_csum)) {
		debug_warn("data csum mismatch %x %x\n", csum, raw->data_csum);
		node_sock_read_error(sock);
		node_msg_free(msg);
		return;
	}

	ctio = ctio_new(Q_NOWAIT);
	if (unlikely(!ctio)) {
		debug_warn("Unable to allocate a new ctio\n");
		node_resp_msg(sock, raw, NODE_STATUS_MEM_ALLOC_FAILURE);
		node_msg_free(msg);
		return;
	}

	cmd_spec = scsi_cmd_spec_ptr(raw); 
	pglist = pgdata_allocate_nopage(cmd_spec->pglist_cnt, Q_NOWAIT);
	if (unlikely(!pglist)) {
		debug_warn("Unable to allocate a ctio buffers\n");
		node_resp_msg(sock, raw, NODE_STATUS_MEM_ALLOC_FAILURE);
		node_msg_free(msg);
		ctio_free(ctio);
		return;
	}

	cdb = ctio->cdb;
	cdb[0] = WRITE_16;

	*(uint64_t *)(&cdb[2]) = htobe64(cmd_spec->lba);
	*(uint32_t *)(&cdb[10]) = htobe32(cmd_spec->transfer_length);
	scsi_cmd_spec_read(cmd_spec, ctio);
	ctio->ccb_h.flags = QSIO_DIR_OUT;
	ctio->ccb_h.tdisk = tdisk;
	ctio->ccb_h.queue_fn = node_master_send_ccb;

	unaligned = is_unaligned_write(tdisk, cmd_spec->lba, cmd_spec->transfer_length);

	retval = fill_pglist(msg, sock, pglist, cmd_spec->pglist_cnt, unaligned);
	if (unlikely(retval != 0)) {
		pglist_free(pglist, cmd_spec->pglist_cnt);
		node_msg_free(msg);
		ctio_free_all(ctio);
		return;
	}
	ctio->data_ptr = (void *)pglist;
	ctio->pglist_cnt = cmd_spec->pglist_cnt;
	ctio->dxfer_len = cmd_spec->pglist_cnt << LBA_SHIFT;

	wlist = write_list_alloc(tdisk);
	msg->wlist = wlist;

	ctio_set_node_msg(ctio, msg);
	if (in_sync)
		ctio_set_in_sync(ctio);
	if (remote_locked || (in_sync && !tdisk_mirror_master(tdisk)))
		ctio_set_remote_locked(ctio);

	exec = __device_istate_queue_ctio(tdisk, ctio, 1);
	if (exec)
		node_master_proc_cmd(tdisk, ctio);
}

static void
node_master_read_io_done(struct node_sock *sock, struct raw_node_msg *raw, struct queue_list *queue_list, mtx_t *queue_lock)
{
	struct node_msg *msg;
	struct qsio_scsiio *ctio;
	struct tdisk *tdisk;
	struct write_list *wlist;
	int retval;

	msg = node_cmd_lookup(sock->comm->node_hash, raw->xchg_id, queue_list, queue_lock);
	if (unlikely(!msg)) {
		debug_warn("Missing exchange cmd %llx\n", (unsigned long long)raw->xchg_id);
		node_error_resp_msg(sock, raw, NODE_STATUS_INVALID_MSG);
		return;
	}

	debug_check(msg->sock != sock);
	ctio = msg->ctio;
	wlist = msg->wlist;
	tdisk = msg->tdisk;
	msg->raw->msg_cmd = raw->msg_cmd;

	debug_check(!ctio);
	debug_check(!wlist);
	debug_check(!tdisk);

	msg->raw->cmd_status = NODE_CMD_DONE;
	msg->raw->pg_count = 0;
	msg->raw->dxfer_len = 0;
	retval = node_send_msg(sock, msg, msg->raw->xchg_id, 1);
	if (unlikely(retval != 0))
		goto err;
	return;
err:
	node_master_read_error(tdisk, wlist, ctio);
	node_master_end_ctio(ctio);
	node_msg_cleanup(msg);
	return;
}

void
node_master_read_done(struct node_sock *sock, struct raw_node_msg *raw, struct queue_list *queue_list, mtx_t *queue_lock)
{
	struct node_msg *msg;
	struct qsio_scsiio *ctio;
	struct tdisk *tdisk;
	struct write_list *wlist;

	msg = node_cmd_lookup(sock->comm->node_hash, raw->xchg_id, queue_list, queue_lock);
	if (unlikely(!msg)) {
		debug_warn("Missing exchange cmd %llx\n", (unsigned long long)raw->xchg_id);
		node_error_resp_msg(sock, raw, NODE_STATUS_INVALID_MSG);
		return;
	}

	debug_check(msg->sock != sock);
	ctio = msg->ctio;
	wlist = msg->wlist;
	tdisk = msg->tdisk;

	debug_check(!ctio);
	debug_check(!wlist);
	debug_check(!tdisk);

	tdisk_remove_lba_write(tdisk, &wlist->lba_write);
	pgdata_free_amaps((struct pgdata **)ctio->data_ptr, ctio->pglist_cnt);
	node_master_pending_writes_decr();
	ctio_free_data(ctio);
	node_master_end_ctio(ctio);
	node_msg_cleanup(msg);
}

void
node_master_read_data(struct node_sock *sock, struct raw_node_msg *raw, struct queue_list *queue_list, mtx_t *queue_lock)
{
	struct node_msg *msg;
	struct qsio_scsiio *ctio;
	struct tdisk *tdisk;
	struct tcache *tcache;
	struct bdevint *bint, *prev_bint = NULL;
	struct pgdata *pgtmp, **pglist;
	struct write_list *wlist;
	struct pgdata_read_spec *source_spec;
	pagestruct_t *uncomp_page;
	struct rcache_entry_list rcache_list;
	int retval, i, pg_count = 0;
	uint16_t csum;

	msg = node_cmd_lookup(sock->comm->node_hash, raw->xchg_id, queue_list, queue_lock);
	if (unlikely(!msg)) {
		debug_warn("Missing exchange cmd %llx\n", (unsigned long long)raw->xchg_id);
		node_error_resp_msg(sock, raw, NODE_STATUS_INVALID_MSG);
		return;
	}

	debug_check(msg->sock != sock);
	ctio = msg->ctio;
	wlist = msg->wlist;
	tdisk = msg->tdisk;

	debug_check(!ctio);
	debug_check(!wlist);
	debug_check(!tdisk);

	wlist->lba_alloc = tdisk_add_alloc_lba_write(wlist->start_lba, tdisk->lba_read_wait, &tdisk->lba_read_list, 0);

	free(msg->raw, M_NODE_RMSG);
	msg->raw = malloc(raw->dxfer_len + sizeof(struct raw_node_msg), M_NODE_RMSG, Q_WAITOK);
	memcpy(msg->raw, raw, sizeof(*raw));
	raw = msg->raw;

	TAILQ_INIT(&rcache_list);
	tcache = tcache_alloc(ctio->pglist_cnt);
	retval = node_sock_read_nofail(sock, raw->data, raw->dxfer_len);
	if (unlikely(retval != 0)) {
		debug_warn("Failed to read %d bytes retval %d\n", raw->dxfer_len, retval);
		goto err2;
	}

	csum = net_calc_csum16(raw->data, raw->dxfer_len);
	if (unlikely(csum != raw->data_csum)) {
		debug_warn("data csum mismatch %x %x\n", csum, raw->data_csum);
		node_sock_read_error(sock);
		goto err2;
	}

	source_spec = pgdata_read_spec_ptr(raw);
	pglist = (struct pgdata **)(ctio->data_ptr);

	for (i = 0; i < ctio->pglist_cnt; i++, source_spec++) {
		if (!atomic_test_bit_short(PGDATA_NEED_REMOTE_IO, &source_spec->flags))
			continue;

		pgtmp = pglist[i];
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

		retval = pgdata_alloc_page(pgtmp, 0);
		if (unlikely(retval != 0)) {
			debug_warn("allocating for pgdata page failed\n");
			goto err;
		}

		debug_info("lba %llu block %llu size %u\n", (unsigned long long)pgtmp->lba, (unsigned long long)(BLOCK_BLOCKNR(pgtmp->amap_block)), pgtmp->pg_len);
		retval = tcache_add_page(tcache, pgtmp->page, BLOCK_BLOCKNR(pgtmp->amap_block), bint, lba_block_size(pgtmp->amap_block), QS_IO_READ);
		if (unlikely(retval != 0)) {
			goto err;
		}
		pg_count++;
	}

	debug_check(!atomic_read(&tcache->bio_remain));
	tdisk_check_alloc_lba_write(wlist->lba_alloc, tdisk->lba_read_wait, &tdisk->lba_read_list, LBA_WRITE_DONE_IO);
	tcache_entry_rw(tcache, QS_IO_READ);
	tdisk_remove_alloc_lba_write(&wlist->lba_alloc, tdisk->lba_read_wait, &tdisk->lba_read_list);

	wait_for_done(tcache->completion);
	if (atomic_test_bit_short(TCACHE_IO_ERROR, &tcache->flags))
		goto err;

	tcache_read_comp(tcache);

	tcache_put(tcache);
	tcache = NULL;

	source_spec = pgdata_read_spec_ptr(raw);
	for (i = 0; i < ctio->pglist_cnt; i++, source_spec++) {

		if (!atomic_test_bit_short(PGDATA_NEED_REMOTE_IO, &source_spec->flags))
			continue;

		pgtmp =  pglist[i];
		if (lba_block_size(pgtmp->amap_block) != LBA_SIZE) {
			uncomp_page = vm_pg_alloc(0);
			if (unlikely(!uncomp_page))
				goto err;

			retval = qs_inflate_block(pgtmp->page, lba_block_size(pgtmp->amap_block), uncomp_page);
			if (unlikely(retval != 0)) {
				vm_pg_free(uncomp_page);
				debug_warn("Failed to decompress page lba %llu size %d amap block %llu\n", (unsigned long long)pgtmp->lba, lba_block_size(pgtmp->amap_block), (unsigned long long)pgtmp->amap_block);
				goto err;
			}
			pgdata_free_page(pgtmp);
			pgtmp->page = uncomp_page;
			pgtmp->pg_len = LBA_SIZE;
		}
		rcache_add_to_list(&rcache_list, pgtmp);
		source_spec->csum = pgdata_csum(pgtmp, LBA_SIZE);
	}

	rcache_list_insert(&rcache_list);
	raw->pg_count = pg_count;
	node_msg_compute_csum(raw);
	node_cmd_hash_insert(sock->comm->node_hash, msg, raw->xchg_id);
	node_sock_start(sock);
	retval = node_sock_write(sock, raw);
	if (unlikely(retval != 0)) {
		node_sock_end(sock);
		node_cmd_hash_remove(sock->comm->node_hash, msg, raw->xchg_id);
		goto err2;
	}

	source_spec = pgdata_read_spec_ptr(raw);
	for (i = 0; i < ctio->pglist_cnt; i++, source_spec++) {

		if (!atomic_test_bit_short(PGDATA_NEED_REMOTE_IO, &source_spec->flags))
			continue;

		pgtmp =  pglist[i];

		retval = node_sock_write_page(sock, pgtmp->page, pgtmp->pg_len);
		if (unlikely(retval != 0)) {
			node_sock_end(sock);
			node_cmd_hash_remove(sock->comm->node_hash, msg, raw->xchg_id);
			goto err2;
		}
	}
	node_sock_end(sock);

	return;
err:
	rcache_list_free(&rcache_list);
	if (tcache)
		tcache_put(tcache);
	tdisk_remove_alloc_lba_write(&wlist->lba_alloc, tdisk->lba_read_wait, &tdisk->lba_read_list);
	tdisk_remove_lba_write(tdisk, &wlist->lba_write);
	pgdata_free_amaps((struct pgdata **)ctio->data_ptr, ctio->pglist_cnt);
	node_master_pending_writes_decr();
	ctio_free_data(ctio);
	ctio_construct_sense(ctio, SSD_CURRENT_ERROR, SSD_KEY_HARDWARE_ERROR, 0, INTERNAL_TARGET_FAILURE_ASC, INTERNAL_TARGET_FAILURE_ASCQ);
	device_send_ccb(ctio);
	return;
err2:
	rcache_list_free(&rcache_list);
	if (tcache)
		tcache_put(tcache);
	tdisk_remove_alloc_lba_write(&wlist->lba_alloc, tdisk->lba_read_wait, &tdisk->lba_read_list);
	tdisk_remove_lba_write(tdisk, &wlist->lba_write);
	pgdata_free_amaps((struct pgdata **)ctio->data_ptr, ctio->pglist_cnt);
	node_master_pending_writes_decr();
	node_master_end_ctio(ctio);
	node_msg_cleanup(msg);
}

static int
node_master_write_unaligned(struct tdisk *tdisk, struct qsio_scsiio *ctio, struct write_list *wlist, struct node_msg *msg)
{
	struct tcache *tcache;
	struct pgdata **pglist, *pgtmp, *pgwrite;
	struct bdevint *bint, *prev_bint = NULL;
	int i, retval;

	tcache = tcache_alloc(ctio->pglist_cnt);

	pglist = (struct pgdata **)(ctio->data_ptr);

	for (i = 0; i < ctio->pglist_cnt; i++) {
		pgtmp =  pglist[i];

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
				tcache_put(tcache);
				return -1;
			}
			prev_bint = bint;
		}
		else {
			bint = prev_bint;
		}

		retval = tcache_add_page(tcache, pgwrite->page, BLOCK_BLOCKNR(pgtmp->amap_block), bint, pgwrite->pg_len, QS_IO_WRITE);
		if (unlikely(retval != 0)) {
			tcache_put(tcache);
			return -1;
		}
	}

	debug_check(!atomic_read(&tcache->bio_remain));
	tcache_entry_rw(tcache, QS_IO_WRITE);

	msg->tcache = tcache;
	msg->raw->cmd_status = NODE_CMD_DONE;
	msg->raw->dxfer_len = 0;
	return 0;
}

void
node_master_write_data_unaligned(struct node_sock *sock, struct raw_node_msg *raw, struct queue_list *queue_list, mtx_t *queue_lock)
{
	struct node_msg *msg;
	struct qsio_scsiio *ctio;
	struct tdisk *tdisk;
	struct write_list *wlist;
	int retval;

	msg = node_cmd_lookup(sock->comm->node_hash, raw->xchg_id, queue_list, queue_lock);
	if (unlikely(!msg)) {
		debug_warn("Missing exchange cmd %llx\n", (unsigned long long)raw->xchg_id);
		node_error_resp_msg(sock, raw, NODE_STATUS_INVALID_MSG);
		return;
	}

	debug_check(msg->sock != sock);
	ctio = msg->ctio;
	wlist = msg->wlist;
	tdisk = msg->tdisk;
	msg->raw->msg_cmd = raw->msg_cmd;

	debug_check(!ctio);
	debug_check(!wlist);
	debug_check(!tdisk);

	retval = node_master_write_unaligned(tdisk, ctio, wlist, msg);
	if (unlikely(retval != 0))
		goto err2;

	msg->raw->cmd_status = NODE_CMD_DONE;
	msg->raw->dxfer_len = 0;

	retval = node_send_msg(msg->sock, msg, raw->xchg_id, 1);
	if (unlikely(retval != 0)) {
		debug_warn("Sending response failed\n");
		goto err;
	}
	return;
err:
	node_master_write_error(tdisk, wlist, ctio);
	node_master_end_ctio(ctio);
	node_msg_cleanup(msg);
	return;
err2:
	node_master_write_error(tdisk, wlist, ctio);
	ctio_check_free_data(ctio);
	ctio_construct_sense(ctio, SSD_CURRENT_ERROR, SSD_KEY_HARDWARE_ERROR, 0, INTERNAL_TARGET_FAILURE_ASC, INTERNAL_TARGET_FAILURE_ASCQ);
	device_send_ccb(ctio);
	return;
}

void
node_master_write_data(struct node_sock *sock, struct raw_node_msg *raw, struct queue_list *queue_list, mtx_t *queue_lock)
{
	struct node_msg *msg;
	struct qsio_scsiio *ctio;
	struct tdisk *tdisk;
	struct tcache *tcache = NULL;
	struct bdevint *bint, *prev_bint = NULL;
	struct pgdata *pgtmp, **pglist;
	struct write_list *wlist;
	struct pgdata_read_spec *source_spec;
	int retval, i;
	int flags = 0;
	uint16_t csum;

	msg = node_cmd_lookup(sock->comm->node_hash, raw->xchg_id, queue_list, queue_lock);
	if (unlikely(!msg)) {
		debug_warn("Missing exchange cmd %llx\n", (unsigned long long)raw->xchg_id);
		node_error_resp_msg(sock, raw, NODE_STATUS_INVALID_MSG);
		return;
	}

	debug_check(msg->sock != sock);
	ctio = msg->ctio;
	wlist = msg->wlist;
	tdisk = msg->tdisk;

	debug_check(!ctio);
	debug_check(!wlist);
	debug_check(!tdisk);

	atomic_set_bit(LBA_WRITE_DONE_ALLOC, &flags);
	wlist->lba_alloc = tdisk_add_alloc_lba_write(wlist->start_lba, tdisk->lba_write_wait, &tdisk->lba_write_list, flags);

	debug_check(raw->dxfer_len != pgdata_read_spec_dxfer_len(ctio->pglist_cnt));

	if (raw->dxfer_len != pgdata_read_spec_dxfer_len(ctio->pglist_cnt)) {
		debug_warn("Invalid msg len %d expected %d\n", raw->dxfer_len, (int)pgdata_read_spec_dxfer_len(ctio->pglist_cnt));
		goto err2;
	}

	free(msg->raw, M_NODE_RMSG);
	msg->raw = malloc(raw->dxfer_len + sizeof(struct raw_node_msg), M_NODE_RMSG, Q_WAITOK);
	memcpy(msg->raw, raw, sizeof(*raw));
	raw = msg->raw;

	tcache = tcache_alloc(ctio->pglist_cnt);

	retval = node_sock_read_nofail(sock, raw->data, raw->dxfer_len);
	if (unlikely(retval != 0)) {
		debug_warn("Failed to read %d bytes retval %d\n", raw->dxfer_len, retval);
		goto err;
	}

	csum = net_calc_csum16(raw->data, raw->dxfer_len);
	if (unlikely(csum != raw->data_csum)) {
		debug_warn("data csum mismatch %x %x\n", csum, raw->data_csum);
		node_sock_read_error(sock);
		goto err;
	}

	pglist = (struct pgdata **)(ctio->data_ptr);
	source_spec = pgdata_read_spec_ptr(raw);
	for (i = 0; i < ctio->pglist_cnt; i++, source_spec++) {
		if (!atomic_test_bit_short(PGDATA_NEED_REMOTE_IO, &source_spec->flags))
			continue;

		pgtmp =  pglist[i];

		TDISK_STATS_ADD(tdisk, uncompressed_size, LBA_SIZE);

		debug_check(!pgtmp->write_size);
		debug_check(pgtmp->write_size > LBA_SIZE);
		if (!pgtmp->write_size || pgtmp->write_size > LBA_SIZE) {
			debug_warn("Invalid write size %u pgtmp flags %d source spec flags %d pgtmp amap block %llu source spec amap block %llu\n", pgtmp->write_size, pgtmp->flags, source_spec->flags, (unsigned long long)pgtmp->amap_block, (unsigned long long)source_spec->amap_block);
			goto err2;
		}

		retval = pgdata_alloc_page(pgtmp, 0);
		if (unlikely(retval != 0))
			goto err2;

		retval = node_sock_read_nofail(sock, pgdata_page_address(pgtmp), pgtmp->write_size);
                if (unlikely(retval != 0)) {
			debug_warn("Failed to read %d bytes retval %d\n", pgtmp->write_size, retval);
                        goto err;
		}

		if (unlikely(pgdata_csum(pgtmp, pgtmp->write_size) != source_spec->csum)) {
			debug_warn("Invalid pgdata csum %x %x\n", pgdata_csum(pgtmp, pgtmp->write_size), source_spec->csum);
			debug_check(1);
			node_sock_read_error(sock);
			goto err;
		}

		debug_check(!pgtmp->amap_block);
		if (!prev_bint || (prev_bint->bid != BLOCK_BID(pgtmp->amap_block))) {
			bint = bdev_find(BLOCK_BID(pgtmp->amap_block));
			if (unlikely(!bint)) {
				debug_warn("Cannot locate bint at bid %u amap block %llu\n", BLOCK_BID(pgtmp->amap_block), (unsigned long long)pgtmp->amap_block);
				goto err2;
			}
			prev_bint = bint;
		}
		else {
			bint = prev_bint;
		}

		debug_info("lba %llu block %llu size %u\n", (unsigned long long)pgtmp->lba, (unsigned long long)(BLOCK_BLOCKNR(pgtmp->amap_block)), pgtmp->write_size);
		retval = tcache_add_page(tcache, pgtmp->page, BLOCK_BLOCKNR(pgtmp->amap_block), bint, pgtmp->write_size, QS_IO_WRITE);
		if (unlikely(retval != 0)) {
			debug_warn("i %d pglist cnt %d\n", i, ctio->pglist_cnt);
			goto err2;
		}
	}

	debug_check(!atomic_read(&tcache->bio_remain));
	tdisk_check_alloc_lba_write(wlist->lba_alloc, tdisk->lba_write_wait, &tdisk->lba_write_list, LBA_WRITE_DONE_IO);
	tcache_entry_rw(tcache, QS_IO_WRITE);
	tdisk_remove_alloc_lba_write(&wlist->lba_alloc, tdisk->lba_write_wait, &tdisk->lba_write_list);

	msg->tcache = tcache;
	raw->cmd_status = NODE_CMD_DONE;
	raw->dxfer_len = 0;
	retval = node_send_msg(sock, msg, raw->xchg_id, 1);
	if (unlikely(retval != 0))
		goto err;
	return;
err:
	tdisk_remove_alloc_lba_write(&wlist->lba_alloc, tdisk->lba_write_wait, &tdisk->lba_write_list);
	tcache_put(tcache);
	node_master_write_error(tdisk, wlist, ctio);
	node_master_end_ctio(ctio);
	node_msg_cleanup(msg);
	return;
err2:
	tdisk_remove_alloc_lba_write(&wlist->lba_alloc, tdisk->lba_write_wait, &tdisk->lba_write_list);
	if (tcache)
		tcache_put(tcache);
	node_master_write_error(tdisk, wlist, ctio);
	ctio_check_free_data(ctio);
	ctio_construct_sense(ctio, SSD_CURRENT_ERROR, SSD_KEY_HARDWARE_ERROR, 0, INTERNAL_TARGET_FAILURE_ASC, INTERNAL_TARGET_FAILURE_ASCQ);
	device_send_ccb(ctio);
}

void
node_master_write_post_pre(struct node_sock *sock, struct raw_node_msg *raw, struct queue_list *queue_list, mtx_t *queue_lock)
{
	struct qsio_scsiio *ctio;
	struct write_list *wlist;
	struct tdisk *tdisk;
	struct tcache *tcache;
	int retval;

	struct node_msg *msg;

	msg = node_cmd_lookup(sock->comm->node_hash, raw->xchg_id, queue_list, queue_lock);
	if (unlikely(!msg)) {
		debug_warn("Missing exchange cmd %llx\n", (unsigned long long)raw->xchg_id);
		node_error_resp_msg(sock, raw, NODE_STATUS_INVALID_MSG);
		return;
	}

	ctio = msg->ctio;
	wlist = msg->wlist;
	tdisk = msg->tdisk;
	tcache = msg->tcache;
	msg->tcache = NULL;
	msg->raw->msg_cmd = raw->msg_cmd;
	debug_check(!ctio);
	debug_check(!wlist);
	debug_check(!tdisk);

	if (tcache) {
		wait_for_done(tcache->completion);
		if (atomic_test_bit_short(TCACHE_IO_ERROR, &tcache->flags)) {
			tcache_put(tcache);
			debug_warn("tcache write error\n");
			goto err2;
		}
		tcache_put(tcache);
	}

	retval = __node_master_write_post_pre(tdisk, wlist, (struct pgdata **)ctio->data_ptr, ctio->pglist_cnt);
	if (unlikely(retval != 0)) {
		debug_warn("node master post write failed\n");
		goto err2;
	}

	msg->raw->cmd_status = NODE_CMD_DONE;
	msg->raw->dxfer_len = 0;

	retval = node_send_msg(msg->sock, msg, raw->xchg_id, 1);
	if (unlikely(retval != 0)) {
		debug_warn("Sending response failed\n");
		goto err;
	}
	return;
err:
	node_master_write_error(tdisk, wlist, ctio);
	node_master_end_ctio(ctio);
	node_msg_cleanup(msg);
	return;
err2:
	node_master_write_error(tdisk, wlist, ctio);
	ctio_check_free_data(ctio);
	ctio_construct_sense(ctio, SSD_CURRENT_ERROR, SSD_KEY_HARDWARE_ERROR, 0, INTERNAL_TARGET_FAILURE_ASC, INTERNAL_TARGET_FAILURE_ASCQ);
	device_send_ccb(ctio);
	return;
}

void
node_master_write_done(struct node_sock *sock, struct raw_node_msg *raw, struct queue_list *queue_list, mtx_t *queue_lock)
{
	struct qsio_scsiio *ctio;
	struct write_list *wlist;
	struct tdisk *tdisk;
	struct tcache *tcache;
	int retval;
	struct node_msg *msg;

	msg = node_cmd_lookup(sock->comm->node_hash, raw->xchg_id, queue_list, queue_lock);
	if (unlikely(!msg)) {
		debug_warn("Missing exchange cmd %llx\n", (unsigned long long)raw->xchg_id);
		node_error_resp_msg(sock, raw, NODE_STATUS_INVALID_MSG);
		return;
	}

	ctio = msg->ctio;
	wlist = msg->wlist;
	tdisk = msg->tdisk;
	tcache = msg->tcache;
	msg->tcache = NULL;
	debug_check(!ctio);
	debug_check(!wlist);
	debug_check(!tdisk);

	if (tcache) {
		wait_for_done(tcache->completion);
		if (atomic_test_bit_short(TCACHE_IO_ERROR, &tcache->flags)) {
			tcache_put(tcache);
			debug_warn("tcache write error\n");
			goto err;
		}
		tcache_put(tcache);
	}

	retval = node_master_write_post(tdisk, wlist, ctio);
	if (unlikely(retval != 0)) {
		debug_warn("node master post write failed\n");
		goto err;
	}

	return;
err:
	node_master_write_error(tdisk, wlist, ctio);
	ctio_check_free_data(ctio);
	ctio_construct_sense(ctio, SSD_CURRENT_ERROR, SSD_KEY_HARDWARE_ERROR, 0, INTERNAL_TARGET_FAILURE_ASC, INTERNAL_TARGET_FAILURE_ASCQ);
	device_send_ccb(ctio);
	return;
}

void
node_master_verify_data(struct node_sock *sock, struct raw_node_msg *raw, struct queue_list *queue_list, mtx_t *queue_lock)
{
	struct node_msg *msg;
	struct qsio_scsiio *ctio;
	struct write_list *wlist;
	struct pgdata_read_spec *source_spec;
	struct pgdata **pglist, *pgdata;
	struct tdisk *tdisk;
	uint32_t size = 0;
	int enable_compression;
	struct pgdata_wlist alloc_list;
	int need_io = 0, need_comp = 0;
	int i, retval;
	uint16_t csum;
	uint8_t error_code = SSD_KEY_HARDWARE_ERROR;
	uint8_t asc = INTERNAL_TARGET_FAILURE_ASC;
	uint8_t ascq = INTERNAL_TARGET_FAILURE_ASCQ;

	msg = node_cmd_lookup(sock->comm->node_hash, raw->xchg_id, queue_list, queue_lock);
	if (unlikely(!msg)) {
		debug_warn("Missing exchange cmd %llx\n", (unsigned long long)raw->xchg_id);
		node_error_resp_msg(sock, raw, NODE_STATUS_INVALID_MSG);
		return;
	}

	debug_check(msg->sock != sock);
	ctio = msg->ctio;
	wlist = msg->wlist;
	tdisk = msg->tdisk;
	debug_check(!ctio);
	debug_check(!wlist);
	debug_check(!tdisk);

	wlist->lba_alloc = tdisk_add_alloc_lba_write(wlist->start_lba, tdisk->lba_write_wait, &tdisk->lba_write_list, 0);

	free(msg->raw, M_NODE_RMSG);
	msg->raw = malloc(raw->dxfer_len + sizeof(struct raw_node_msg), M_NODE_RMSG, Q_WAITOK);
	memcpy(msg->raw, raw, sizeof(*raw));
	raw = msg->raw;

	retval = node_sock_read_nofail(sock, raw->data, raw->dxfer_len);
	if (unlikely(retval != 0)) {
		debug_warn("Failed to read %d bytes retval %d\n", raw->dxfer_len, retval);
		goto err;
	}

	csum = net_calc_csum16(raw->data, raw->dxfer_len);
	if (unlikely(csum != raw->data_csum)) {
		debug_warn("data csum mismatch %x %x\n", csum, raw->data_csum);
		node_sock_read_error(sock);
		goto err;
	}

	enable_compression = tdisk->enable_compression && atomic_read(&tdisk->group->comp_bdevs);
	STAILQ_INIT(&alloc_list);
	source_spec = pgdata_read_spec_ptr(raw);
	pglist = (struct pgdata **)(ctio->data_ptr);
	for (i = 0; i < ctio->pglist_cnt; i++, source_spec++) {
		pgdata = pglist[i];

		if (atomic_test_bit(DDBLOCK_ZERO_BLOCK, &pgdata->flags))
			continue;

		if (!atomic_test_bit(DDBLOCK_ENTRY_FOUND_DUPLICATE, &pgdata->flags))
			continue;

		retval = pgdata_alloc_page(pgdata, 0);
		if (unlikely(retval != 0))
			goto err2;

		retval = node_sock_read_nofail(sock, pgdata_page_address(pgdata), LBA_SIZE);
		if (unlikely(retval != 0)) {
			debug_warn("Failed to read %d bytes retval %d\n", LBA_SIZE, retval);
			goto err;
		}

		if (unlikely(pgdata_csum(pgdata, LBA_SIZE) != source_spec->csum)) {
			debug_warn("Invalid pgdata csum %x %x\n", pgdata_csum(pgdata, LBA_SIZE), source_spec->csum);
			debug_check(1);
			node_sock_read_error(sock);
			goto err;
		}
	}

	verify_ddblocks(tdisk, &wlist->dedupe_list, wlist, ctio->pglist_cnt, 1);

	for (i = 0; i < ctio->pglist_cnt; i++) {
		pgdata = pglist[i];

		if (atomic_test_bit(DDBLOCK_ZERO_BLOCK, &pgdata->flags))
			continue;

		if (atomic_test_bit(DDBLOCK_ENTRY_FOUND_DUPLICATE, &pgdata->flags)) {
			TDISK_STATS_ADD(tdisk, blocks_deduped, 1);
			TDISK_STATS_ADD(tdisk, inline_deduped, 1);
			continue;
		}

		need_io = 1;
		if (enable_compression) {
			need_comp = 1;
			continue;
		}

		pgdata->write_size = LBA_SIZE;
		size += LBA_SIZE;
		STAILQ_INSERT_TAIL(&alloc_list, pgdata, w_list);
		TDISK_STATS_ADD(tdisk, uncompressed_size, LBA_SIZE);
	}

	if (!need_io) {
		raw->cmd_status = NODE_CMD_DONE;
		raw->dxfer_len = 0;
	}
	else if (!need_comp) {
		retval = pgdata_alloc_blocks(tdisk, ctio, &alloc_list, size, &wlist->index_info_list, wlist->lba_alloc);
		if (unlikely(retval != 0)) {
			debug_warn("Cannot allocate blocks for size %u\n", size);
			if (retval != ERR_CODE_NOSPACE)
				goto err2;
			error_code = SSD_KEY_DATA_PROTECT;
			asc = SPACE_ALLOCATION_FAILED_WRITE_PROTECT_ASC;
			ascq = SPACE_ALLOCATION_FAILED_WRITE_PROTECT_ASCQ;
			goto err2;
		}

		source_spec = pgdata_read_spec_ptr(raw);
		for (i = 0; i < ctio->pglist_cnt; i++, source_spec++) {
			pgdata = pglist[i];
			source_spec->flags = pgdata->flags;
			source_spec->amap_block = pgdata->amap_block;
		}

		raw->cmd_status = NODE_CMD_NEED_IO;
	}
	else { 
		source_spec = pgdata_read_spec_ptr(raw);
		for (i = 0; i < ctio->pglist_cnt; i++, source_spec++) {
			pgdata = pglist[i];
			source_spec->flags = pgdata->flags;
			source_spec->amap_block = pgdata->amap_block;
		}

		raw->cmd_status = NODE_CMD_NEED_COMP;
	}

	tdisk_remove_alloc_lba_write(&wlist->lba_alloc, tdisk->lba_write_wait, &tdisk->lba_write_list);
	retval = node_send_msg(msg->sock, msg, raw->xchg_id, 1);
	if (unlikely(retval != 0)) {
		debug_warn("Sending response failed\n");
		goto err;
	}
	return;
err:
	tdisk_remove_alloc_lba_write(&wlist->lba_alloc, tdisk->lba_write_wait, &tdisk->lba_write_list);
	node_master_write_error(tdisk, wlist, ctio);
	node_master_end_ctio(ctio);
	node_msg_cleanup(msg);
	return;
err2:
	tdisk_remove_alloc_lba_write(&wlist->lba_alloc, tdisk->lba_write_wait, &tdisk->lba_write_list);
	node_master_write_error(tdisk, wlist, ctio);
	ctio_check_free_data(ctio);
	ctio_construct_sense(ctio, SSD_CURRENT_ERROR, error_code, 0, asc, ascq);
	device_send_ccb(ctio);
}

void
node_master_write_comp_done(struct node_sock *sock, struct raw_node_msg *raw, struct queue_list *queue_list, mtx_t *queue_lock)
{
	struct node_msg *msg;
	struct qsio_scsiio *ctio;
	struct write_list *wlist;
	int i, retval;
	struct pgdata_read_spec *source_spec;
	struct pgdata **pglist, *pgdata;
	struct tdisk *tdisk;
	uint32_t size = 0;
	struct pgdata_wlist alloc_list;
	uint16_t csum;
	uint8_t error_code = SSD_KEY_HARDWARE_ERROR;
	uint8_t asc = INTERNAL_TARGET_FAILURE_ASC;
	uint8_t ascq = INTERNAL_TARGET_FAILURE_ASCQ;

	msg = node_cmd_lookup(sock->comm->node_hash, raw->xchg_id, queue_list, queue_lock);
	if (unlikely(!msg)) {
		debug_warn("Missing exchange cmd %llx\n", (unsigned long long)raw->xchg_id);
		node_error_resp_msg(sock, raw, NODE_STATUS_INVALID_MSG);
		return;
	}

	debug_check(msg->sock != sock);
	ctio = msg->ctio;
	wlist = msg->wlist;
	tdisk = msg->tdisk;
	debug_check(!ctio);
	debug_check(!wlist);
	debug_check(!tdisk);

	wlist->lba_alloc = tdisk_add_alloc_lba_write(wlist->start_lba, tdisk->lba_write_wait, &tdisk->lba_write_list, 0);

	free(msg->raw, M_NODE_RMSG);
	msg->raw = malloc(raw->dxfer_len + sizeof(struct raw_node_msg), M_NODE_RMSG, Q_WAITOK);
	memcpy(msg->raw, raw, sizeof(*raw));
	raw = msg->raw;

	retval = node_sock_read_nofail(sock, raw->data, raw->dxfer_len);
	if (unlikely(retval != 0)) {
		debug_warn("Failed to read %d bytes retval %d\n", raw->dxfer_len, retval);
		goto err;
	}

	csum = net_calc_csum16(raw->data, raw->dxfer_len);
	if (unlikely(csum != raw->data_csum)) {
		debug_warn("data csum mismatch %x %x\n", csum, raw->data_csum);
		node_sock_read_error(sock);
		goto err;
	}

	STAILQ_INIT(&alloc_list);
	source_spec = pgdata_read_spec_ptr(raw);
	pglist = (struct pgdata **)(ctio->data_ptr);
	for (i = 0; i < ctio->pglist_cnt; i++, source_spec++) {
		pgdata = pglist[i];

		if (atomic_test_bit(DDBLOCK_ZERO_BLOCK, &pgdata->flags))
			continue;

		if (atomic_test_bit(DDBLOCK_ENTRY_FOUND_DUPLICATE, &pgdata->flags))
			continue;

		STAILQ_INSERT_TAIL(&alloc_list, pgdata, w_list);
		if (lba_block_size(source_spec->amap_block) == LBA_SIZE) {
			pgdata->write_size = LBA_SIZE;
			size += LBA_SIZE; 
			TDISK_STATS_ADD(tdisk, compression_misses, 1);
			TDISK_STATS_ADD(tdisk, uncompressed_size, LBA_SIZE);
			continue;
		}

		pgdata->write_size = lba_block_size(source_spec->amap_block);
		size += pgdata->write_size;
		TDISK_STATS_ADD(tdisk, compression_hits, 1);
		TDISK_STATS_ADD(tdisk, compressed_size, pgdata->write_size);
	}

	debug_check(!size);
	retval = pgdata_alloc_blocks(tdisk, ctio, &alloc_list, size, &wlist->index_info_list, wlist->lba_alloc);
	if (unlikely(retval != 0)) {
		if (retval != ERR_CODE_NOSPACE)
			goto err2;
		error_code = SSD_KEY_DATA_PROTECT;
		asc = SPACE_ALLOCATION_FAILED_WRITE_PROTECT_ASC;
		ascq = SPACE_ALLOCATION_FAILED_WRITE_PROTECT_ASCQ;
		goto err2;
	}

	source_spec = pgdata_read_spec_ptr(raw);
	pglist = (struct pgdata **)(ctio->data_ptr);
	for (i = 0; i < ctio->pglist_cnt; i++, source_spec++) {
		pgdata = pglist[i];
		source_spec->flags = pgdata->flags;
		source_spec->amap_block = pgdata->amap_block;
	}

	msg->ctio = ctio;
	raw->cmd_status = NODE_CMD_NEED_IO;
	tdisk_remove_alloc_lba_write(&wlist->lba_alloc, tdisk->lba_write_wait, &tdisk->lba_write_list);
	retval = node_send_msg(sock, msg, raw->xchg_id, 1);
	if (unlikely(retval != 0))
		goto err;

	return;
err:
	tdisk_remove_alloc_lba_write(&wlist->lba_alloc, tdisk->lba_write_wait, &tdisk->lba_write_list);
	node_master_write_error(tdisk, wlist, ctio);
	node_master_end_ctio(ctio);
	node_msg_cleanup(msg);
	return;
err2:
	tdisk_remove_alloc_lba_write(&wlist->lba_alloc, tdisk->lba_write_wait, &tdisk->lba_write_list);
	node_master_write_error(tdisk, wlist, ctio);
	ctio_check_free_data(ctio);
	ctio_construct_sense(ctio, SSD_CURRENT_ERROR, error_code, 0, asc, ascq);
	device_send_ccb(ctio);
}

static void
node_master_sync_status(struct node_sock *sock, struct raw_node_msg *raw)
{
	if (node_sync_get_status() == NODE_SYNC_INPROGRESS)
		raw->msg_status = NODE_STATUS_INITIALIZING;
	else if (node_sync_get_status() == NODE_SYNC_DONE)
		raw->msg_status = NODE_STATUS_OK;
	else
		raw->msg_status = NODE_STATUS_ERROR;

	node_msg_compute_csum(raw);
	node_sock_write(sock, raw);
}

void
node_master_sync_wait(void)
{
	while (node_sync_get_status() == NODE_SYNC_INPROGRESS) {
		debug_info("wait for sync progress\n");
		pause("psg", 1000);
	}
}

static void
node_master_sync_start(struct node_sock *sock, struct raw_node_msg *raw)
{
	int retval;

	debug_info("log error %d node_role %d\n", node_get_role());
	if (!atomic_read(&kern_inited)) {
		raw->msg_status = NODE_STATUS_ERROR;
		node_msg_compute_csum(raw);
		node_sock_write(sock, raw);
		return;
	}

	if (node_get_role() != NODE_ROLE_MASTER || (node_sync_get_status() == NODE_SYNC_INPROGRESS)) {
		raw->msg_status = NODE_STATUS_BUSY;
		node_msg_compute_csum(raw);
		node_sock_write(sock, raw);
		return;
	}

	if (node_type_controller()) {
		if (sock->comm->node_ipaddr != master_config.ha_ipaddr) {
			debug_warn("Received sync from unknown node %u master config ha ipaddr %u\n", sock->comm->node_ipaddr, master_config.ha_ipaddr);
			raw->msg_status = NODE_STATUS_ERROR;
			node_msg_compute_csum(raw);
			node_sock_write(sock, raw);
			return;
		}
	}

	retval = node_sync_comm_init(master_config.ha_ipaddr, master_config.ha_bind_ipaddr);
	if (unlikely(retval != 0)) {
		debug_warn("sync comm init failed\n");
		raw->msg_status = NODE_STATUS_ERROR;
		node_msg_compute_csum(raw);
		node_sock_write(sock, raw);
		return;
	}

	node_sync_set_status(NODE_SYNC_UNKNOWN);
	node_sync_pre();
	node_sync_set_status(NODE_SYNC_INPROGRESS);
	raw->msg_status = NODE_STATUS_OK;
	node_msg_compute_csum(raw);
	node_sock_write(sock, raw);
	retval = node_sync_setup_bdevs();
	if (retval == 0)
		node_sync_set_status(NODE_SYNC_DONE);
}

static void
node_master_role(struct node_sock *sock, struct raw_node_msg *raw)
{
	raw->cmd_status = node_get_role();
	node_msg_compute_csum(raw);
	node_sock_write(sock, raw);
}

static void
node_master_ha_ping(struct node_sock *sock, struct raw_node_msg *raw)
{
	ha_set_ping_recv();
	if (node_sync_get_status() == NODE_SYNC_ERROR)
		raw->msg_status = NODE_STATUS_NEED_RESYNC;
	else
		raw->msg_status = NODE_STATUS_OK;

	node_msg_compute_csum(raw);
	node_sock_write(sock, raw);
}

void
node_master_register(struct node_sock *sock, struct raw_node_msg *raw, int node_register, int *flags, wait_chan_t *wait, struct queue_list *queue_list, mtx_t *queue_lock, int notify)
{
	struct node_comm *comm;
	struct node_sock *iter, *next;
	int cleanup = 0;

	comm = sock->comm;
	node_comm_lock(comm);
	TAILQ_FOREACH_SAFE(iter, &comm->sock_list, s_list, next) {
		if (iter == sock && node_register)
			continue;

		node_sock_read_error(iter);
		cleanup = 1;
	}
	node_comm_unlock(comm);

	if (node_register) {
		atomic_set_bit(NODE_COMM_REGISTERED, &comm->flags);
		if (cleanup ) {
			atomic_set_bit(NODE_COMM_CLEANUP, &comm->flags);
			atomic_set_bit(MASTER_CLEANUP, flags);
			chan_wakeup_nointr(wait);
		}
		raw->dxfer_len = 0;
		raw->msg_status = NODE_STATUS_OK;
		node_sock_write(sock, raw);
	}
	else {
		atomic_set_bit(NODE_COMM_UNREGISTERED, &comm->flags);
		atomic_set_bit(MASTER_CLEANUP, flags);
		chan_wakeup_nointr(wait);
	}

	if (notify) {
		node_sync_register_send(comm, node_register);
		if (node_sync_get_status() == NODE_SYNC_DONE)
			__node_client_notify_ha_status(comm->node_ipaddr, 1);
	}
}

static int
node_in_standby_check(struct node_sock *sock, struct raw_node_msg *raw)
{
	if (!node_in_standby() && atomic_read(&kern_inited))
		return 0;

	switch (raw->msg_cmd) {
	case NODE_MSG_GENERIC_CMD:
	case NODE_MSG_PERSISTENT_RESERVE_OUT_CMD:
	case NODE_MSG_WRITE_CMD:
	case NODE_MSG_READ_CMD:
	case NODE_MSG_AMAP_CHECK:
		break;
	default:
		return 0;
	}

	debug_info("Skipping cmd %d msg id %llx\n", raw->msg_cmd, (unsigned long long)raw->msg_id);
	raw->dxfer_len = 0;
	raw->pg_count = 0;
	node_resp_msg(sock, raw, NODE_STATUS_BUSY);
	node_sock_read_error(sock);
	return 1;
}

uint32_t master_register_ticks;
uint32_t master_unregister_ticks;
uint32_t master_read_cmd_ticks;
uint32_t master_read_io_done_ticks;
uint32_t master_read_done_ticks;
uint32_t master_read_data_ticks;
uint32_t master_write_cmd_ticks;
uint32_t master_write_io_done_ticks;
uint32_t master_write_done_ticks;
uint32_t master_write_data_ticks;
uint32_t master_verify_data_ticks;
uint32_t master_comp_done_ticks;
uint32_t master_cmd_generic_ticks;

static void
node_recv_cmd(struct node_sock *sock, struct raw_node_msg *raw)
{
#ifdef ENABLE_STATS
	uint32_t start_ticks;
#endif

	if (node_in_standby_check(sock, raw)) {
		return;
	}

	switch (raw->msg_cmd) {
	case NODE_MSG_REGISTER:
		GLOB_TSTART(start_ticks);
		node_master_register(sock, raw, 1, &master_flags, master_wait, &master_queue_list, master_queue_lock, 1);
		GLOB_TEND(master_register_ticks, start_ticks);
		break;
	case NODE_MSG_UNREGISTER:
		GLOB_TSTART(start_ticks);
		node_master_register(sock, raw, 0, &master_flags, master_wait, &master_queue_list, master_queue_lock, 1);
		GLOB_TEND(master_unregister_ticks, start_ticks);
		break;
	case NODE_MSG_READ_CMD:
		GLOB_TSTART(start_ticks);
		node_master_read_cmd(sock, raw, &master_queue_list, master_queue_lock, 0);
		GLOB_TEND(master_read_cmd_ticks, start_ticks);
		break;
	case NODE_MSG_WRITE_CMD:
		GLOB_TSTART(start_ticks);
		node_master_write_cmd(sock, raw, &master_queue_list, master_queue_lock, 0, 0);
		GLOB_TEND(master_write_cmd_ticks, start_ticks);
		break;
	case NODE_MSG_VERIFY_DATA:
		GLOB_TSTART(start_ticks);
		node_master_verify_data(sock, raw, &master_queue_list, master_queue_lock);
		GLOB_TEND(master_verify_data_ticks, start_ticks);
		break;
	case NODE_MSG_WRITE_COMP_DONE:
		GLOB_TSTART(start_ticks);
		node_master_write_comp_done(sock, raw, &master_queue_list, master_queue_lock);
		GLOB_TEND(master_comp_done_ticks, start_ticks);
		break;
#if 0
	case NODE_MSG_WRITE_IO_DONE:
		GLOB_TSTART(start_ticks);
		node_master_write_io_done(sock, raw);
		GLOB_TEND(master_write_io_done_ticks, start_ticks);
		break;
#endif
	case NODE_MSG_WRITE_DONE:
		GLOB_TSTART(start_ticks);
		node_master_write_done(sock, raw, &master_queue_list, master_queue_lock);
		GLOB_TEND(master_write_done_ticks, start_ticks);
		break;
	case NODE_MSG_WRITE_DATA:
		GLOB_TSTART(start_ticks);
		node_master_write_data(sock, raw, &master_queue_list, master_queue_lock);
		GLOB_TEND(master_write_data_ticks, start_ticks);
		break;
	case NODE_MSG_READ_IO_DONE:
		GLOB_TSTART(start_ticks);
		node_master_read_io_done(sock, raw, &master_queue_list, master_queue_lock);
		GLOB_TEND(master_read_io_done_ticks, start_ticks);
		break;
	case NODE_MSG_READ_DATA:
		GLOB_TSTART(start_ticks);
		node_master_read_data(sock, raw, &master_queue_list, master_queue_lock);
		GLOB_TEND(master_read_data_ticks, start_ticks);
		break;
	case NODE_MSG_READ_DONE:
		GLOB_TSTART(start_ticks);
		node_master_read_done(sock, raw, &master_queue_list, master_queue_lock);
		GLOB_TEND(master_read_done_ticks, start_ticks);
		break;
	case NODE_MSG_GENERIC_CMD:
		GLOB_TSTART(start_ticks);
		node_master_cmd_generic(sock, raw, 0);
		GLOB_TEND(master_cmd_generic_ticks, start_ticks);
		break;
	case NODE_MSG_PERSISTENT_RESERVE_OUT_CMD:
		node_master_cmd_persistent_reserve_out(sock, raw, 0);
		break;
	default:
		debug_warn("Unknown node msg %d received\n", raw->msg_cmd);
		node_error_resp_msg(sock, raw, NODE_STATUS_INVALID_MSG);
		break;
	}
}

static int
node_sync_in_standby_check(struct node_sock *sock, struct raw_node_msg *raw)
{
	if (node_in_standby())
		return 0;

	switch (raw->msg_cmd) {
	case NODE_MSG_ROLE:
	case NODE_MSG_SYNC_START:
	case NODE_MSG_SYNC_STATUS:
	case NODE_MSG_REGISTER:
	case NODE_MSG_UNREGISTER:
	case NODE_MSG_HA_PING:
	case NODE_MSG_COMM_SYNC:
	case NODE_MSG_SYNC_DISABLE:
	case NODE_MSG_HA_RELINQUISH:
	case NODE_MSG_HA_RELINQUISH_STATUS:
	case NODE_MSG_HA_TAKEOVER:
	case NODE_MSG_HA_TAKEOVER_POST:
		return 0;
	default:
		break;
	}

	debug_info("Skipping cmd %d\n", raw->msg_cmd);
	raw->dxfer_len = 0;
	raw->pg_count = 0;
	node_resp_msg(sock, raw, NODE_STATUS_IS_MASTER);
	node_sock_read_error(sock);
	return 1;

}

static void
node_recv_sync_cmd(struct node_sock *sock, struct raw_node_msg *raw)
{
	if (node_sync_in_standby_check(sock, raw)) {
		return;
	}

	switch (raw->msg_cmd) {
	case NODE_MSG_ROLE:
		node_master_role(sock, raw);
		break;
	case NODE_MSG_SYNC_START:
		node_master_sync_start(sock, raw);
		break;
	case NODE_MSG_SYNC_STATUS:
		node_master_sync_status(sock, raw);
		break;
	case NODE_MSG_REGISTER:
		node_master_register(sock, raw, 1, &master_sync_flags, master_sync_wait, NULL, NULL, 0);
		break;
	case NODE_MSG_HA_PING:
		node_master_ha_ping(sock, raw);
		break;
	case NODE_MSG_UNREGISTER:
		node_master_register(sock, raw, 0, &master_sync_flags, master_sync_wait, NULL, NULL, 0);
		break;
	case NODE_MSG_COMM_SYNC:
		node_sync_register_recv(sock, raw);
		break;
	case NODE_MSG_SYNC_DISABLE:
		node_sync_disable_recv(sock, raw);
		break;
	case NODE_MSG_HA_RELINQUISH:
		node_sync_relinquish_recv(sock, raw);
		break;
	case NODE_MSG_HA_RELINQUISH_STATUS:
		node_sync_relinquish_status(sock, raw);
		break;
	case NODE_MSG_HA_TAKEOVER:
		node_sync_takeover_recv(sock, raw);
		break;
	case NODE_MSG_HA_TAKEOVER_POST:
		node_sync_takeover_post_recv(sock, raw);
		break;
	case NODE_MSG_AMAP_SYNC:
		node_amap_sync_recv(sock, raw);
		break;
	case NODE_MSG_AMAP_META_SYNC:
		node_amap_meta_sync_recv(sock, raw);
		break;
	case NODE_MSG_AMAP_SYNC_POST:
		node_amap_sync_post_recv(sock, raw);
		break;
	case NODE_MSG_AMAP_TABLE_SYNC:
		node_amap_table_sync_recv(sock, raw);
		break;
	case NODE_MSG_TABLE_INDEX_SYNC:
		node_table_index_sync_recv(sock, raw);
		break;
	case NODE_MSG_AMAP_TABLE_META_SYNC:
		node_amap_table_meta_sync_recv(sock, raw);
		break;
	case NODE_MSG_AMAP_TABLE_SYNC_POST:
		node_amap_table_sync_post_recv(sock, raw);
		break;
	case NODE_MSG_TDISK_SYNC:
		node_tdisk_sync_recv(sock, raw);
		break;
	case NODE_MSG_TDISK_UPDATE:
		node_tdisk_update_recv(sock, raw);
		break;
	case NODE_MSG_TDISK_DELETE:
		node_tdisk_delete_recv(sock, raw);
		break;
	case NODE_MSG_LOG_SYNC:
		node_log_sync_recv(sock, raw);
		break;
	case NODE_MSG_LOG_SYNC_POST:
		node_log_sync_post_recv(sock, raw);
		break;
	case NODE_MSG_DDLOOKUP_SYNC:
		node_ddlookup_sync_recv(sock, raw);
		break;
	case NODE_MSG_DDLOOKUP_SYNC_POST:
		node_ddlookup_sync_post_recv(sock, raw);
		break;
	case NODE_MSG_INDEX_LOOKUP_SYNC:
		node_index_lookup_sync_recv(sock, raw);
		break;
	case NODE_MSG_BINT_SYNC:
		node_bint_sync_recv(sock, raw);
		break;
	case NODE_MSG_BINT_DELETE:
		node_bint_delete_recv(sock, raw);
		break;
	case NODE_MSG_BINT_INDEX_SYNC:
		node_bintindex_sync_recv(sock, raw);
		break;
	case NODE_MSG_BINT_INDEX_SYNC_POST:
		node_bintindex_sync_post_recv(sock, raw);
		break;
	case NODE_MSG_NEWMETA_SYNC_START:
		node_newmeta_sync_start_recv(sock, raw);
		break;
	case NODE_MSG_PGDATA_SYNC_START:
		node_pgdata_sync_start_recv(sock, raw);
		break;
	case NODE_MSG_PGDATA_SYNC_CLIENT_DONE:
		node_pgdata_sync_client_done_recv(sock, raw);
		break;
	case NODE_MSG_NEWMETA_SYNC_COMPLETE:
		node_newmeta_sync_complete_recv(sock, raw);
		break;
	case NODE_MSG_PGDATA_SYNC_COMPLETE:
		node_pgdata_sync_complete_recv(sock, raw);
		break;
	case NODE_MSG_REGISTRATION_SYNC:
		node_registration_sync_recv(sock, raw);
		break;
	case NODE_MSG_ISTATE_CLEAR:
		node_istate_clear_recv(sock, raw);
		break;
	case NODE_MSG_SENSE_STATE:
		node_sense_state_recv(sock, raw);
		break;
	case NODE_MSG_REGISTRATION_CLEAR_SYNC:
		node_registration_clear_sync_recv(sock, raw);
		break;
	case NODE_MSG_RESERVATION_SYNC:
		node_reservation_sync_recv(sock, raw);
		break;
	default:
		debug_warn("Unknown node msg %d received\n", raw->msg_cmd);
		node_error_resp_msg(sock, raw, NODE_STATUS_INVALID_MSG);
		break;
	}
}

static int
node_master_sync_recv(struct node_sock *sock)
{
	int retval;
	struct raw_node_msg raw;

	while (1) {
		retval = node_sock_read(sock, &raw, sizeof(raw));
		if (retval != 0) {
			atomic_set_bit(NODE_COMM_CLEANUP, &sock->comm->flags);
			atomic_set_bit(MASTER_CLEANUP, &master_sync_flags);
			chan_wakeup_nointr(master_sync_wait);
			return -1;
		}

		if (unlikely(!node_msg_csum_valid(&raw))) {
			debug_warn("Received msg with invalid csum\n");
			node_sock_read_error(sock);
			atomic_set_bit(NODE_COMM_CLEANUP, &sock->comm->flags);
			atomic_set_bit(MASTER_CLEANUP, &master_sync_flags);
			chan_wakeup_nointr(master_sync_wait);
			return -1;
		}

		node_recv_sync_cmd(sock, &raw);
		if (sock_state_error(sock)) {
			atomic_set_bit(NODE_COMM_CLEANUP, &sock->comm->flags);
			atomic_set_bit(MASTER_CLEANUP, &master_sync_flags);
			chan_wakeup_nointr(master_sync_wait);
			return -1;
		}
	}
	return 0;
}

static int
node_master_recv(struct node_sock *sock)
{
	int retval;
	struct raw_node_msg raw;

	while (1) {
		retval = node_sock_read(sock, &raw, sizeof(raw));
		if (retval != 0) {
			atomic_set_bit(NODE_COMM_CLEANUP, &sock->comm->flags);
			atomic_set_bit(MASTER_CLEANUP, &master_flags);
			chan_wakeup_nointr(master_wait);
			return -1;
		}

		if (unlikely(!node_msg_csum_valid(&raw))) {
			debug_warn("Received msg with invalid csum\n");
			atomic_set_bit(NODE_COMM_CLEANUP, &sock->comm->flags);
			atomic_set_bit(MASTER_CLEANUP, &master_flags);
			chan_wakeup_nointr(master_wait);
			node_sock_read_error(sock);
			return -1;
		}

		atomic_inc(&write_requests);
		node_recv_cmd(sock, &raw);
		atomic_dec(&write_requests);
		if (sock_state_error(sock)) {
			atomic_set_bit(NODE_COMM_CLEANUP, &sock->comm->flags);
			atomic_set_bit(MASTER_CLEANUP, &master_flags);
			chan_wakeup_nointr(master_wait);
			return -1;
		}
	}
	return 0;
}

static int
node_master_sync_accept(struct node_sock *recv_sock)
{
	struct node_sock *sock;
	struct node_comm *comm;
	uint32_t ipaddr;
	int error = 0, retval;

	while (1) {
		sock = __node_sock_alloc(NULL, node_master_sync_recv); 
		sock->lsock = sock_accept(recv_sock->lsock, sock, &error, &ipaddr);
		if (!sock->lsock || !atomic_read(&kern_inited)) {
			node_sock_free(sock, 1);
			if (error) {
				return -1;
			}
			return 0;
		}

		comm = node_comm_locate(node_sync_accept_hash, ipaddr, sync_root);
		sock->comm = comm;
		node_comm_lock(comm);
		retval = kernel_thread_create(node_sock_recv_thr, sock, sock->task, "ndsockmsna");
		if (unlikely(retval != 0)) {
			node_sock_free(sock, 1);
			node_comm_unlock(comm);
			return -1;
		}
		TAILQ_INSERT_TAIL(&comm->sock_list, sock, s_list);
		node_comm_unlock(comm);
		if (sock->state == SOCK_STATE_CONNECTED) {
			atomic_set_bit(NODE_SOCK_DATA, &sock->flags);
			chan_wakeup(sock->sock_wait);
		}
	}
	return 0;
}

static int
node_master_accept(struct node_sock *recv_sock)
{
	struct node_sock *sock;
	struct node_comm *comm;
	uint32_t ipaddr;
	int error = 0, retval;

	while (1) {
		sock = __node_sock_alloc(NULL, node_master_recv); 
		sock->lsock = sock_accept(recv_sock->lsock, sock, &error, &ipaddr);
		if (!sock->lsock || !atomic_read(&kern_inited)) {
			node_sock_free(sock, 1);
			if (error) {
				return -1;
			}
			return 0;
		}

		comm = node_comm_locate(node_master_hash, ipaddr, root);
		sock->comm = comm;
		node_comm_lock(comm);
		retval = kernel_thread_create(node_sock_recv_thr, sock, sock->task, "ndsockma");
		if (unlikely(retval != 0)) {
			node_sock_free(sock, 1);
			node_comm_unlock(comm);
			return -1;
		}
		TAILQ_INSERT_TAIL(&comm->sock_list, sock, s_list);
		node_comm_unlock(comm);
		if (sock->state == SOCK_STATE_CONNECTED) {
			atomic_set_bit(NODE_SOCK_DATA, &sock->flags);
			chan_wakeup(sock->sock_wait);
		}
	}
	return 0;
}

void
node_master_proc_cmd(void *disk, void *iop)
{
	struct tdisk *tdisk = disk;
	struct qsio_scsiio *ctio = iop;
	uint8_t *cdb = ctio->cdb;
	int retval = 0;
	struct initiator_state *istate;
	struct sense_info *sinfo;

#ifdef ENABLE_DEBUG
	if (cdb[0])
	{
		print_cdb(cdb);
	}
#endif

	istate = ctio->istate;
	if (!istate) {
		if (is_write_cmd(ctio))
			wait_for_pgdata((struct pgdata **)ctio->data_ptr, ctio->pglist_cnt);
		ctio_free_data(ctio);
		ctio_construct_sense(ctio, SSD_CURRENT_ERROR, SSD_KEY_ILLEGAL_REQUEST, 0, LOGICAL_UNIT_NOT_SUPPORTED_ASC, LOGICAL_UNIT_NOT_SUPPORTED_ASCQ);
		goto out;
	}

	switch(cdb[0]) {
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
			ctio_free_data(ctio);
			ctio->scsi_status = SCSI_STATUS_RESERV_CONFLICT;
			goto out;
		}
	}

	if (node_in_standby()) {
		ctio_free_data(ctio);
		ctio->scsi_status = SCSI_STATUS_BUSY;
		goto out;
	}

	switch(cdb[0]) {
		case TEST_UNIT_READY:
			retval = tdisk_cmd_test_unit_ready(tdisk, ctio);	
			break;
		case INQUIRY:
			debug_check(1);
			retval = -1;
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
		case READ_10:
		case READ_12:
			debug_check(1);
			retval = -1;
			break;
		case READ_16:
			atomic_inc(&write_requests);
			node_master_read_pre(tdisk, ctio);
			atomic_dec(&write_requests);
			goto skip_send;
			break;
		case WRITE_SAME:
			atomic_inc(&write_requests);
			tdisk_cmd_write_same(tdisk, ctio);
			atomic_dec(&write_requests);
			goto skip_send;
			break;
		case WRITE_SAME_16:
			atomic_inc(&write_requests);
			tdisk_cmd_write_same16(tdisk, ctio);
			atomic_dec(&write_requests);
			goto skip_send;
			break;
		case UNMAP:
			atomic_inc(&write_requests);
			tdisk_cmd_unmap(tdisk, ctio);
			atomic_dec(&write_requests);
			goto skip_send;
			break;
		case EXTENDED_COPY:
			atomic_inc(&write_requests);
			tdisk_cmd_extended_copy_read(tdisk, ctio);
			atomic_dec(&write_requests);
			goto skip_send;
			break;
		case RECEIVE_COPY_RESULTS:
			retval = tdisk_cmd_receive_copy_results(tdisk, ctio);
			break;
		case COMPARE_AND_WRITE:
			atomic_inc(&write_requests);
			tdisk_cmd_compare_and_write(tdisk, ctio);
			atomic_dec(&write_requests);
			goto skip_send;
			break;
		case WRITE_6:
		case WRITE_10:
		case WRITE_12:
			debug_check(1);
			retval = -1;
			break;
		case WRITE_16:
			atomic_inc(&write_requests);
			node_master_write_pre(tdisk, ctio);
			atomic_dec(&write_requests);
			goto skip_send;
			break;
		case REPORT_LUNS:
			debug_check(1);
			retval = -1;
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
			retval = tdisk_cmd_sync_cache(tdisk, ctio);
			break;
		case SYNCHRONIZE_CACHE_16:
			retval = tdisk_cmd_sync_cache16(tdisk, ctio);
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
node_root_comm_free(struct node_comm *root_comm, struct queue_list *queue_list, mtx_t *queue_lock)
{
	struct node_comm *comm;

	node_comm_lock(root_comm);
	while ((comm = SLIST_FIRST(&root_comm->comm_list)) != NULL) {
		SLIST_REMOVE_HEAD(&root_comm->comm_list, c_list);
		if (queue_list)
			node_clear_comm_msgs(comm->node_hash, queue_list, queue_lock, comm, NULL);
		debug_check(atomic_read(&comm->refs) > 1);
		node_comm_put(comm);
	}
	node_comm_unlock(root_comm);

}

void
node_cleanups_wait(void)
{
#if 0
	if (master_task)
		wait_on_chan(master_wait, !atomic_test_bit(MASTER_IN_CLEANUP, &master_flags));

	if (master_sync_task)
		wait_on_chan(master_sync_wait, !atomic_test_bit(MASTER_IN_CLEANUP, &master_sync_flags));

	if (recv_task)
		wait_on_chan(recv_wait, !atomic_test_bit(MASTER_IN_CLEANUP, &recv_flags));
#endif
}

void
node_master_exit(void)
{
	if (sync_root) {
		node_root_comm_free(sync_root, NULL, NULL);
		node_comm_put(sync_root);
		sync_root = NULL;
	}

	if (root) {
		node_root_comm_free(root, &master_queue_list, master_queue_lock);
		node_comm_put(root);
		root = NULL;
	}

	if (master_cleanup_task) {
		kernel_thread_stop(master_cleanup_task, &master_cleanup_flags, master_cleanup_wait, MASTER_EXIT);
		master_cleanup_task = NULL;
	}

	if (master_task) {
		wait_on_chan(master_wait, !atomic_test_bit(MASTER_IN_CLEANUP, &master_flags));
		kernel_thread_stop(master_task, &master_flags, master_wait, MASTER_EXIT);
		master_task = NULL;
	}

	if (master_sync_task) {
		wait_on_chan(master_sync_wait, !atomic_test_bit(MASTER_IN_CLEANUP, &master_sync_flags));
		kernel_thread_stop(master_sync_task, &master_sync_flags, master_sync_wait, MASTER_EXIT);
		master_sync_task = NULL;
	}

	if (master_wait) {
		wait_chan_free(master_wait);
		master_wait = NULL;
	}
	if (master_sync_wait) {
		wait_chan_free(master_sync_wait);
		master_sync_wait = NULL;
	}
	if (master_cleanup_wait) {
		wait_chan_free(master_cleanup_wait);
		master_cleanup_wait = NULL;
	}
	node_sync_exit();

	if (master_queue_lock) {
		mtx_free(master_queue_lock);
		master_queue_lock = NULL;
	}
}

void
node_master_cleanup(struct node_comm *root_comm, struct queue_list *queue_list, mtx_t *queue_lock)
{
	struct node_comm *comm, *next, *prev = NULL;
	struct sock_list sock_list, sock_tmp_list;
	struct node_sock *iter;
	SLIST_HEAD(, node_comm) tmp_list;
	int linger;

	if (!atomic_read(&kern_inited))
		return;

	TAILQ_INIT(&sock_list);
	SLIST_INIT(&tmp_list);
	node_comm_lock(root_comm);
	SLIST_FOREACH_SAFE(comm, &root_comm->comm_list, c_list, next) {
		if (!atomic_test_bit(NODE_COMM_UNREGISTERED, &comm->flags) && !atomic_test_bit(NODE_COMM_CLEANUP, &comm->flags)) {
			prev = comm;
			continue;
		}

		if (atomic_test_bit(NODE_COMM_CLEANUP, &comm->flags)) {
			TAILQ_INIT(&sock_tmp_list);
			node_comm_cleanup(comm, &sock_tmp_list);
			if (queue_list && !TAILQ_EMPTY(&sock_tmp_list)) {
				node_clear_comm_msgs(comm->node_hash, queue_list, queue_lock, comm, &sock_tmp_list);
			}
			TAILQ_CONCAT(&sock_list, &sock_tmp_list, s_list);

			if (!TAILQ_EMPTY(&comm->sock_list)) {
				prev = comm;
				continue;
			}
		}

		if (prev)
			SLIST_REMOVE_AFTER(prev, c_list);
		else
			SLIST_REMOVE_HEAD(&root_comm->comm_list, c_list);
		SLIST_INSERT_HEAD(&tmp_list, comm, c_list);
	}
	node_comm_unlock(root_comm);

	while ((iter = TAILQ_FIRST(&sock_list)) != NULL) {
		TAILQ_REMOVE(&sock_list, iter, s_list);
		linger = atomic_test_bit(NODE_COMM_LINGER, &iter->comm->flags);
		node_sock_free(iter, linger);
		if (!linger)
			pause("psg", 10);
	}

	while ((comm = SLIST_FIRST(&tmp_list)) != NULL) {
		SLIST_REMOVE_HEAD(&tmp_list, c_list);
		if (queue_list)
			node_clear_comm_msgs(comm->node_hash, queue_list, queue_lock, comm, NULL);
		if (!atomic_test_bit(NODE_COMM_UNREGISTERED, &comm->flags))
			atomic_clear_bit(NODE_COMM_LINGER, &comm->flags);
		node_comm_put(comm);
	}
}

void
master_queue_wait_for_empty(void)
{
	while (!TAILQ_EMPTY(&master_queue_list)) {
		node_check_timedout_msgs(node_master_hash, &master_queue_list, master_queue_lock, controller_recv_timeout);
		pause("psg", 200);
	}
}

#ifdef FREEBSD 
static void node_master_sync_thr(void *data)
#else
static int node_master_sync_thr(void *data)
#endif
{
	struct node_config *node_config = data;
	int retval;

	sync_root = node_comm_alloc(NULL, node_config->ha_ipaddr, node_config->ha_bind_ipaddr);
	retval = node_sock_bind(sync_root, node_master_sync_accept, CONTROLLER_SYNC_PORT, "ndsockmsnr");
	if (unlikely(retval != 0)) {
		debug_warn("node master/controller sync init failed\n");
		node_comm_put(sync_root);
		sync_root = NULL;
	}

	atomic_set_bit(MASTER_INITED, &master_sync_flags);
	chan_wakeup(master_sync_wait);

	while(!kernel_thread_check(&master_sync_flags, MASTER_EXIT)) {
		wait_on_chan_timeout(master_sync_wait, kernel_thread_check(&master_sync_flags, MASTER_EXIT), 10000);
		if (unlikely(kernel_thread_check(&master_sync_flags, MASTER_EXIT)))
			break;
		if (atomic_test_bit(MASTER_CLEANUP, &master_sync_flags)) {
			atomic_set_bit(MASTER_IN_CLEANUP, &master_sync_flags);
			atomic_clear_bit(MASTER_CLEANUP, &master_sync_flags);
			if (unlikely(kernel_thread_check(&master_sync_flags, MASTER_EXIT))) {
				atomic_clear_bit(MASTER_IN_CLEANUP, &master_sync_flags);
				chan_wakeup(master_sync_wait);
				break;
			}
			if (sync_root)
				node_master_cleanup(sync_root, NULL, NULL);
			atomic_clear_bit(MASTER_IN_CLEANUP, &master_sync_flags);
			chan_wakeup(master_sync_wait);
		}
	}
#ifdef FREEBSD 
	kproc_exit(0);
#else
	return 0;
#endif
}

#ifdef FREEBSD 
static void node_cleanup_thr(void *data)
#else
static int node_cleanup_thr(void *data)
#endif
{
	for(;;) {

		wait_on_chan_timeout(master_cleanup_wait, kernel_thread_check(&master_cleanup_flags, MASTER_EXIT), 5000);
		node_check_timedout_msgs(node_master_hash, &master_queue_list, master_queue_lock, controller_recv_timeout);
		if (kernel_thread_check(&master_cleanup_flags, MASTER_EXIT))
			break;
	}
#ifdef FREEBSD 
	kproc_exit(0);
#else
	return 0;
#endif
}

#ifdef FREEBSD 
static void node_master_thr(void *data)
#else
static int node_master_thr(void *data)
#endif
{
	struct node_config *node_config = data;
	int retval;

	root = node_comm_alloc(NULL, node_config->controller_ipaddr, node_config->node_ipaddr);
	retval = node_sock_bind(root, node_master_accept, CONTROLLER_DATA_PORT, "ndsockmr");
	if (unlikely(retval != 0)) {
		debug_warn("node master/controller init failed\n");
		node_comm_put(root);
		root = NULL;
		atomic_set_bit(MASTER_BIND_ERROR, &master_flags);
	}

	atomic_set_bit(MASTER_INITED, &master_flags);
	chan_wakeup(master_wait);

	while(!kernel_thread_check(&master_flags, MASTER_EXIT)) {
		wait_on_chan_timeout(master_wait, kernel_thread_check(&master_flags, MASTER_EXIT), 5000);
		if (unlikely(kernel_thread_check(&master_flags, MASTER_EXIT)))
			break;
		if (atomic_test_bit(MASTER_CLEANUP, &master_flags)) {
			atomic_set_bit(MASTER_IN_CLEANUP, &master_flags);
			atomic_clear_bit(MASTER_CLEANUP, &master_flags);
			if (unlikely(kernel_thread_check(&master_flags, MASTER_EXIT))) {
				atomic_clear_bit(MASTER_IN_CLEANUP, &master_flags);
				chan_wakeup(master_wait);
				break;
			}
			node_master_cleanup(root, &master_queue_list, master_queue_lock);
			atomic_clear_bit(MASTER_IN_CLEANUP, &master_flags);
			chan_wakeup(master_wait);
		}
#if 0
		node_check_timedout_msgs(node_master_hash, &master_queue_list, master_queue_lock, controller_recv_timeout);
#endif
	}
#ifdef FREEBSD 
	kproc_exit(0);
#else
	return 0;
#endif
}

int
node_master_init(struct node_config *node_config)
{
	int retval;

	SET_NODE_TIMEOUT(node_config, controller_recv_timeout, CONTROLLER_RECV_TIMEOUT_MIN, CONTROLLER_RECV_TIMEOUT_MAX);
	SET_NODE_TIMEOUT(node_config, node_sync_timeout, NODE_SYNC_TIMEOUT_MIN, NODE_SYNC_TIMEOUT_MAX);
	SET_NODE_TIMEOUT(node_config, ha_check_timeout, HA_CHECK_TIMEOUT_MIN, HA_CHECK_TIMEOUT_MAX);
	SET_NODE_TIMEOUT(node_config, ha_ping_timeout, HA_PING_TIMEOUT_MIN, HA_PING_TIMEOUT_MAX);

	if (master_wait)
		return 0;

	memcpy(&master_config, node_config, sizeof(master_config));

	master_wait = wait_chan_alloc("node master wait");
	master_cleanup_wait = wait_chan_alloc("node master cleanup wait");
	master_sync_wait = wait_chan_alloc("node master sync wait");
	master_queue_lock = mtx_alloc("master queue lock");
	TAILQ_INIT(&master_queue_list);

	retval = kernel_thread_create(node_cleanup_thr, NULL, master_cleanup_task, "mstclnthr");
	if (unlikely(retval != 0)) {
		node_master_exit();
		return -1;
	}

	retval = kernel_thread_create(node_master_thr, node_config, master_task, "mstthr");
	if (unlikely(retval != 0)) {
		node_master_exit();
		return -1;
	}

	retval = kernel_thread_create(node_master_sync_thr, node_config, master_sync_task, "mstsynthr");
	if (unlikely(retval != 0)) {
		node_master_exit();
		return -1;
	}

	wait_on_chan_interruptible(master_wait, atomic_test_bit(MASTER_INITED, &master_flags));
	wait_on_chan_interruptible(master_sync_wait, atomic_test_bit(MASTER_INITED, &master_sync_flags));
	return 0;
}
