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
#include "gdevq.h"
#include "sense.h"
#include "tcache.h"
#include "vdevdefs.h"
#include "node_sock.h"
#include "node_ha.h"
#include "../common/cluster_common.h" 

static struct node_comm *master;
static struct node_comm *recv_comm;
struct node_config client_config;
static sx_t *comm_lock;
wait_chan_t *ha_chan;
atomic_t ha_enabled;
int client_flags;
static int node_client_sock_init(struct node_comm *comm, int do_register);

#define node_msg_retry(mgx)	((mgx)->retry)

void
node_msg_wait(struct node_msg *msg, struct node_sock *sock, int timo)
{
	int retval;

	msg->timestamp = ticks;
	retval = wait_for_done_timeout(msg->completion, timo);
	if (retval)
		return;
	debug_warn("msg timedout ticks %llu msg timestamp %llu cmd %d msg_id %llx xchg id %llx timo %d\n", (unsigned long long)ticks, (unsigned long long)msg->timestamp, msg->raw->msg_cmd, (unsigned long long)msg->raw->msg_id, (unsigned long long)msg->raw->xchg_id, timo);
	retval = node_cmd_hash_remove(sock->comm->node_hash, msg, msg->raw->msg_id);
	if (!retval) {
		wait_for_done(msg->completion);
	}
	else {
		node_sock_read_error(sock);
		debug_check(msg->resp);
	}
}

void
scsi_cmd_spec_fill(struct scsi_cmd_spec *spec, struct qsio_scsiio *ctio)
{
	spec->task_tag = ctio->task_tag;
	port_fill(spec->i_prt, ctio->i_prt);
	port_fill(spec->t_prt, ctio->t_prt);
	spec->r_prt = ctio->r_prt;
	spec->init_int = ctio->init_int;
	spec->task_attr = ctio->task_attr;
}

void
scsi_cmd_spec_generic_fill(struct scsi_cmd_spec_generic *spec, struct qsio_scsiio *ctio)
{
	memcpy(spec->cdb, ctio->cdb, sizeof(spec->cdb));
	spec->task_tag = ctio->task_tag;
	port_fill(spec->i_prt, ctio->i_prt);
	port_fill(spec->t_prt, ctio->t_prt);
	spec->r_prt = ctio->r_prt;
	spec->init_int = ctio->init_int;
	spec->task_attr = ctio->task_attr;
}

static void
node_master_setup(uint32_t controller_ipaddr, uint32_t node_ipaddr, int do_register)
{
	int retval;

	master = node_comm_alloc(node_client_hash, controller_ipaddr, node_ipaddr);
	atomic_clear_bit(CLIENT_CONNECT_ERROR, &client_flags);
	retval = node_client_sock_init(master, do_register);
	if (unlikely(retval != 0))
		atomic_set_bit(CLIENT_CONNECT_ERROR, &client_flags);
	chan_wakeup_nointr(ha_chan);
}

static struct node_comm *
node_locate_master(void)
{
	struct node_comm *comm;
	int retval;

	sx_xlock(comm_lock);
	debug_check(!master);
	node_comm_lock(master);
	if (TAILQ_EMPTY(&master->sock_list)) {
		debug_info("out of free socks, trying to reconnect\n");
		retval = node_client_sock_init(master, 0);
		if (unlikely(retval != 0)) {
			debug_warn("Cannot init socks on reconnect\n");
			node_comm_unlock(master);
			sx_xunlock(comm_lock);
			return NULL;
		}
	}
	node_comm_get(master);
	node_comm_unlock(master);
	comm = master;
	sx_xunlock(comm_lock);
	return comm;
}

static void
node_comm_complete(struct node_comm *comm)
{
	if (atomic_read(&comm->waits)) {
		atomic_set(&comm->waits, 0);
		chan_wakeup_nointr(ha_chan);
	}
}

static void
node_busy_check(struct qsio_scsiio *ctio, struct node_msg *msg, struct node_comm *comm, int waits)
{
	if (msg->retry || !ctio || ctio->scsi_status || msg->mirror)
		return;

	if (comm != master) {
		msg->retry = 1;
		return;
	}

	ctio->scsi_status = SCSI_STATUS_BUSY;
	if (!atomic_read(&ha_enabled)) {
		debug_info("skipping ha switch msg id %llx msg cmd %d\n", (unsigned long long)msg->raw->msg_id, msg->raw->msg_cmd);
		pause("psg", 2000);
		return;
	}

	debug_info("waitin for switch msg id %llx msg cmd %d comm %p refs %d\n", (unsigned long long)msg->raw->msg_id, msg->raw->msg_cmd, comm, atomic_read(&comm->refs));
	msg->retry = 1;
	if (waits) {
		atomic_set(&comm->waits, 1);
		wait_on_chan_timeout(ha_chan, ((comm != master) || !atomic_read(&ha_enabled) || !atomic_read(&comm->waits)), HA_SWITCH_WAIT_TIMEOUT);
	}
	else {
		wait_on_chan_timeout(ha_chan, ((comm != master) || !atomic_read(&ha_enabled)), HA_SWITCH_WAIT_TIMEOUT);
	}
	debug_info("done waiting for switch msg id %llx msg cmd %d comm %p refs %d\n", (unsigned long long)msg->raw->msg_id, msg->raw->msg_cmd, comm, atomic_read(&comm->refs));
}

static int
__node_resp_status(struct node_msg *msg)
{
	struct node_msg *resp;
	struct raw_node_msg *raw;

	resp = msg->resp;

	if (unlikely(!resp))
		return -1;

	raw = resp->raw;
	if (raw->msg_status == NODE_STATUS_OK)
		return 0;
	else
		return -1;
}

static int
node_resp_status(struct qsio_scsiio *ctio, struct node_msg *msg, struct node_comm *comm, struct node_sock *sock)
{
	struct node_msg *resp;
	struct raw_node_msg *raw;
	struct scsi_sense_spec *sense_spec;
	int need_sense, error_code;
	int sense_key = 0, asc = 0, ascq = 0;
	uint32_t info = 0;

	resp = msg->resp;

	if (unlikely(!resp)) {
		if (msg->mirror)
			return -1;
		node_busy_check(ctio, msg, comm, 1);
		return -1;
	}

	raw = resp->raw;
	if (raw->msg_status == NODE_STATUS_OK)
		return 0;

	if (!ctio)
		return raw->msg_status;
	need_sense = 0;
	error_code = SSD_CURRENT_ERROR;
	switch (raw->msg_status) {
	case NODE_STATUS_BUSY:
		if (msg->mirror) {
			ctio->scsi_status = SCSI_STATUS_BUSY;
			break;
		} 
		node_busy_check(ctio, msg, comm, 0);
		break;		
	case NODE_STATUS_RESERV_CONFLICT:
		ctio->scsi_status = SCSI_STATUS_RESERV_CONFLICT;
		break;
	case NODE_STATUS_TARGET_NOT_FOUND:
		need_sense = 1;
		sense_key = SSD_KEY_ILLEGAL_REQUEST;
		asc = LOGICAL_UNIT_NOT_SUPPORTED_ASC;
		ascq = LOGICAL_UNIT_NOT_SUPPORTED_ASCQ;
		info = 0;
		break;
	case NODE_STATUS_INVALID_MSG:
	case NODE_STATUS_UNREGISTERED_NODE:
		need_sense = 1;
		sense_key = SSD_KEY_HARDWARE_ERROR;
		asc = INTERNAL_TARGET_FAILURE_ASC;
		ascq = INTERNAL_TARGET_FAILURE_ASCQ;
		info = 0;
		break;
	case NODE_STATUS_MEM_ALLOC_FAILURE:
		node_sock_read_error(sock);
		ctio->scsi_status = SCSI_STATUS_BUSY;
		break;
	case NODE_STATUS_SCSI_SENSE:
		need_sense = 1;
		sense_spec = (struct scsi_sense_spec *)(raw->data);
		debug_check(raw->dxfer_len != sizeof(*sense_spec));
		sense_key = sense_spec->sense_key;
		asc = sense_spec->asc;
		ascq = sense_spec->ascq; 
		info = sense_spec->info;
		error_code = sense_spec->error_code;
		if (msg->mirror)
			debug_warn("cmd sense sense key %x asc %x ascq %x error_code %x info %u\n", sense_key, asc, ascq, error_code, info);
		else
			debug_info("cmd sense sense key %x asc %x ascq %x error_code %x info %u\n", sense_key, asc, ascq, error_code, info);
		break;
	}

	if (need_sense) {
		if (sense_key == SSD_KEY_HARDWARE_ERROR)
			node_sock_read_error(sock);
		ctio_construct_sense(ctio, error_code, sense_key, info, asc, ascq);
	}
	return raw->msg_status;
}

int
node_cmd_remote_write_io(struct node_comm *comm, struct node_sock *sock, struct qsio_scsiio *ctio, struct node_msg *msg,  struct pgdata **pglist, int pglist_cnt, int timeout, int async)
{
	struct raw_node_msg *raw;
	struct pgdata_read_spec *source_spec;
	struct pgdata *pgtmp, *pgwrite;
	int i, retval;

	raw = msg->raw;
	raw->msg_cmd = NODE_MSG_WRITE_DATA;
	node_msg_init(msg);

	source_spec = pgdata_read_spec_ptr(raw);
	for (i = 0; i < pglist_cnt; i++, source_spec++) {
		pgtmp = pglist[i];
		if (!atomic_test_bit(PGDATA_NEED_REMOTE_IO, &pgtmp->flags))
			continue;
		debug_check(!source_spec->amap_block);
		atomic_set_bit_short(PGDATA_NEED_REMOTE_IO, &source_spec->flags);
		if (pgtmp->comp_pgdata && lba_block_size(source_spec->amap_block) != LBA_SIZE) {
			pgwrite = pgtmp->comp_pgdata;
			debug_check(lba_block_size(source_spec->amap_block) !=  pgwrite->pg_len);
		}
		else {
			if (pgtmp->comp_pgdata) {
				pgdata_free(pgtmp->comp_pgdata);
				pgtmp->comp_pgdata = NULL;
			}
			pgwrite = pgtmp;
		}

		source_spec->csum = pgdata_csum(pgwrite, pgwrite->pg_len);
	}

	node_msg_compute_csum(raw);
	node_cmd_hash_insert(comm->node_hash, msg, raw->msg_id);
	node_sock_start(sock);
	retval = node_sock_write(sock, raw);
	if (unlikely(retval != 0)) {
		node_sock_end(sock);
		node_cmd_hash_remove(comm->node_hash, msg, raw->msg_id);
		node_busy_check(ctio, msg, comm, 1);
		return retval;
	}

	for (i = 0; i < pglist_cnt; i++) {
		pgtmp = pglist[i];

		if (!atomic_test_bit(PGDATA_NEED_REMOTE_IO, &pgtmp->flags))
			continue;

		if (pgtmp->comp_pgdata) {
			pgwrite = pgtmp->comp_pgdata;
		}
		else {
			pgwrite = pgtmp;
		}

		retval = node_sock_write_page(sock, pgwrite->page, pgwrite->pg_len);
		if (unlikely(retval != 0)) {
			node_sock_end(sock);
			node_cmd_hash_remove(comm->node_hash, msg, raw->msg_id);
			node_busy_check(ctio, msg, comm, 1);
			return retval;
		}
	}
	node_sock_end(sock);

	if (async) {
		msg->async_wait = 1;
		return 0;
	}

	node_msg_wait(msg, sock, timeout);
	retval = node_resp_status(ctio, msg, comm, sock);
	if (unlikely(retval != 0))
		return retval;

	node_resp_free(msg);
	return 0;
}

void
node_msg_copy_resp(struct node_msg *msg)
{
	struct node_msg *resp = msg->resp;

	free(msg->raw, M_NODE_RMSG);
	msg->raw = resp->raw;
	resp->raw = NULL;

	if (resp->pages) {
		msg->pages = resp->pages;
		msg->pg_count = resp->pg_count;
		resp->pages = NULL;
		resp->pg_count = 0;
	}

	node_resp_free(msg);
}

static int
node_cmd_remote_read_io(struct qsio_scsiio *ctio, struct node_comm *comm, struct node_sock *sock, struct node_msg *msg,  struct pgdata **pglist, int pglist_cnt, int timeout)
{
	struct raw_node_msg *raw;
	struct pgdata_read_spec *source_spec;
	struct pgdata *pgtmp;
	pagestruct_t **pages;
	struct pgdata_wlist read_list;
	int i, retval, pg_idx;

	raw = msg->raw;
	source_spec = pgdata_read_spec_ptr(raw);
	for (i = 0; i < pglist_cnt; i++, source_spec++) {
		pgtmp = pglist[i];

		if (!atomic_test_bit(PGDATA_NEED_REMOTE_IO, &pgtmp->flags))
			continue;

		atomic_set_bit_short(PGDATA_NEED_REMOTE_IO, &source_spec->flags);
	}

	raw->msg_cmd = NODE_MSG_READ_DATA;
	node_msg_init(msg);
	retval = node_send_msg(sock, msg, raw->msg_id, 1);
	if (unlikely(retval != 0)) {
		node_busy_check(ctio, msg, comm, 1);
		return retval;
	}

	node_msg_wait(msg, sock, timeout);
	retval = node_resp_status(ctio, msg, comm, sock);
	if (unlikely(retval != 0))
		return retval;

	node_msg_copy_resp(msg);
	raw = msg->raw;

	source_spec = pgdata_read_spec_ptr(raw);
	pages = msg->pages;
	pg_idx = 0;

	STAILQ_INIT(&read_list);
	retval = 0;

	for (i = 0; i < pglist_cnt; i++, source_spec++) {
		pgtmp = pglist[i];

		if (!atomic_test_bit(PGDATA_NEED_REMOTE_IO, &pgtmp->flags))
			continue;

		debug_check(pg_idx >= msg->pg_count);
		memcpy(pgdata_page_address(pgtmp), vm_pg_address(pages[pg_idx]), LBA_SIZE);
		if (unlikely(pgdata_csum(pgtmp, LBA_SIZE) != source_spec->csum)) {
			debug_warn("Invalid pgdata csum %x %x\n", pgdata_csum(pgtmp, LBA_SIZE), source_spec->csum);
			node_sock_read_error(sock);
			ctio_construct_sense(ctio, SSD_CURRENT_ERROR, SSD_KEY_HARDWARE_ERROR, 0, INTERNAL_TARGET_FAILURE_ASC, INTERNAL_TARGET_FAILURE_ASCQ);
			retval = -1;
			break;
		}
		pg_idx++;
	}

	if (msg->pages) {
		page_list_free(msg->pages, msg->pg_count);
		msg->pages = NULL;
		msg->pg_count = 0;
	}

	return retval;
}

static struct bdevint *
node_bdev_find(uint32_t bid)
{
	return bdev_find(bid);
}

int
node_cmd_read_io(struct tdisk *tdisk, struct qsio_scsiio *ctio, struct node_comm *comm, struct node_sock *sock, struct node_msg *msg, struct pgdata **pglist, int pglist_cnt, int remote, int timeout)
{
	struct raw_node_msg *raw;
	struct tcache *tcache;
	struct pgdata_read_spec *source_spec;
	struct pgdata *pgtmp;
	struct bdevint *bint, *prev_bint = NULL;
	struct pgdata_wlist read_list;
	int i, retval, need_remote_io = 0, need_uncomp = 0;
#ifdef ENABLE_STATS
	uint32_t start_ticks;
#endif

	source_spec = pgdata_read_spec_ptr(msg->raw);
	tcache = tcache_alloc(pglist_cnt);
	STAILQ_INIT(&read_list);

	for (i = 0; i < pglist_cnt; i++, source_spec++) {
		pgtmp = pglist[i];

		pgtmp->amap_block = source_spec->amap_block;
		pgtmp->flags = source_spec->flags;

		TDISK_INC(tdisk, read_total, 1);
		if (!source_spec->amap_block) {
			debug_check(!pgtmp->page);
			continue;
		}

		if (atomic_test_bit_short(PGDATA_FROM_RCACHE, &source_spec->flags)) {
			debug_check(!pgtmp->page);
			TDISK_INC(tdisk, from_rcache, 1);
			STAILQ_INSERT_TAIL(&read_list, pgtmp, t_list);
			continue;
		}

		if (pgdata_in_read_list(tdisk, pgtmp, &read_list, 0)) {
			TDISK_INC(tdisk, from_read_list, 1);
			continue;
		}

		debug_check(pgtmp->page);
		retval = pgdata_alloc_page(pgtmp, 0);
		if (unlikely(retval != 0)) {
			debug_warn("allocating for pgdata page failed\n");
			ctio_construct_sense(ctio, SSD_CURRENT_ERROR, SSD_KEY_HARDWARE_ERROR, 0, INTERNAL_TARGET_FAILURE_ASC, INTERNAL_TARGET_FAILURE_ASCQ);
			tcache_put(tcache);
			return -1;
		}

		if (remote) {
			need_remote_io++;
			TDISK_INC(tdisk, remote_reads, 1);
			atomic_set_bit(PGDATA_NEED_REMOTE_IO, &pgtmp->flags);
			atomic_set_bit(PGDATA_SKIP_UNCOMP, &pgtmp->flags);
			continue;
		}

		if (!prev_bint || (prev_bint->bid != BLOCK_BID(pgtmp->amap_block))) {
			bint = node_bdev_find(BLOCK_BID(source_spec->amap_block));
			if (unlikely(!bint)) {
				need_remote_io++;
				TDISK_INC(tdisk, remote_reads, 1);
				atomic_set_bit(PGDATA_NEED_REMOTE_IO, &pgtmp->flags);
				atomic_set_bit(PGDATA_SKIP_UNCOMP, &pgtmp->flags);
				continue;
			}
			prev_bint = bint;
		}
		else {
			bint = prev_bint;
		}

		TDISK_INC(tdisk, local_reads, 1);
		if (lba_block_size(source_spec->amap_block) != LBA_SIZE)
			need_uncomp++;
		retval = tcache_add_page(tcache, pgtmp->page, BLOCK_BLOCKNR(source_spec->amap_block), bint, lba_block_size(source_spec->amap_block), QS_IO_READ);
		if (unlikely(retval != 0)) {
			debug_warn("tcache add page failed\n");
			ctio_construct_sense(ctio, SSD_CURRENT_ERROR, SSD_KEY_HARDWARE_ERROR, 0, INTERNAL_TARGET_FAILURE_ASC, INTERNAL_TARGET_FAILURE_ASCQ);
			tcache_put(tcache);
			return -1;
		}
	}

	if (atomic_read(&tcache->bio_remain))
		tcache_entry_rw(tcache, QS_IO_READ);
	else 
		wait_complete(tcache->completion);


	if (need_remote_io) {
		TDISK_TSTART(start_ticks);
		retval = node_cmd_remote_read_io(ctio, comm, sock, msg,  pglist, pglist_cnt, timeout);
		TDISK_TEND(tdisk, remote_read_io_ticks, start_ticks);
		if (unlikely(retval != 0)) {
			wait_for_done(tcache->completion);
			tcache_put(tcache);
			return retval;
		}
	}

	wait_for_done(tcache->completion);

	if (atomic_test_bit_short(TCACHE_IO_ERROR, &tcache->flags)) {
		tcache_put(tcache);
		debug_warn("tcache data error\n");
		ctio_construct_sense(ctio, SSD_CURRENT_ERROR, SSD_KEY_HARDWARE_ERROR, 0, INTERNAL_TARGET_FAILURE_ASC, INTERNAL_TARGET_FAILURE_ASCQ);
		return -1;
	}

	tcache_read_comp(tcache);

	tcache_put(tcache);

	raw = msg->raw;
	raw->msg_cmd = NODE_MSG_READ_DONE;
	node_msg_init(msg);
	raw->dxfer_len = 0;
	node_send_msg(sock, msg, 0, 0);

	if (!need_uncomp)
		return 0;

	retval = pgdata_post_read_io(pglist, pglist_cnt, NULL, 0, 0, 0);
	if (unlikely(retval != 0)) {
		debug_warn("pgdata post read io failed\n");
		ctio_construct_sense(ctio, SSD_CURRENT_ERROR, SSD_KEY_HARDWARE_ERROR, 0, INTERNAL_TARGET_FAILURE_ASC, INTERNAL_TARGET_FAILURE_ASCQ);
		return retval;
	}

	return 0;
}

int
node_cmd_write_done(struct qsio_scsiio *ctio, struct node_comm *comm, struct node_sock *sock, struct node_msg *msg, int timeout)
{
	int retval;

	msg->raw->msg_cmd = NODE_MSG_WRITE_DONE;
	node_msg_init(msg);
	msg->raw->dxfer_len = 0;

	retval = node_send_msg(sock, msg, msg->raw->msg_id, 1);
	if (unlikely(retval != 0)) {
		node_busy_check(ctio, msg, comm, 1);
		return retval;
	}

	node_msg_wait(msg, sock, timeout);
	retval = node_resp_status(ctio, msg, comm, sock);
	if (unlikely(retval != 0))
		return retval;

	node_msg_copy_resp(msg);
	return 0;

}

static int
node_cmd_write_io(struct qsio_scsiio *ctio, struct node_comm *comm, struct node_sock *sock, struct node_msg *msg, struct pgdata **pglist, int pglist_cnt)
{
	struct tcache *tcache;
	struct pgdata_read_spec *source_spec;
	struct pgdata *pgtmp, *pgwrite;
	struct bdevint *bint, *prev_bint = NULL;
	int i, retval, need_remote_io = 0;

	source_spec = pgdata_read_spec_ptr(msg->raw);
	tcache = tcache_alloc(pglist_cnt);
	for (i = 0; i < pglist_cnt; i++, source_spec++) {
		pgtmp = pglist[i];

		if (!source_spec->amap_block) {
			debug_check(!atomic_test_bit_short(DDBLOCK_ZERO_BLOCK, &source_spec->flags));
			continue;
		}

		if (atomic_test_bit_short(DDBLOCK_ENTRY_FOUND_DUPLICATE, &source_spec->flags))
			continue;

		if (pgtmp->comp_pgdata && lba_block_size(source_spec->amap_block) != LBA_SIZE) {
			pgwrite = pgtmp->comp_pgdata;
			debug_check(lba_block_size(source_spec->amap_block) !=  pgwrite->pg_len);
		}
		else {
			if (pgtmp->comp_pgdata) {
				pgdata_free(pgtmp->comp_pgdata);
				pgtmp->comp_pgdata = NULL;
			}
			pgwrite = pgtmp;
		}

		if (!prev_bint || (prev_bint->bid != BLOCK_BID(pgtmp->amap_block))) {
			bint = node_bdev_find(BLOCK_BID(source_spec->amap_block));
			if (unlikely(!bint)) {
				need_remote_io++;
				atomic_set_bit(PGDATA_NEED_REMOTE_IO, &pgtmp->flags);
				continue;
			}
			prev_bint = bint;
		}
		else {
			bint = prev_bint;
		}

		retval = tcache_add_page(tcache, pgwrite->page, BLOCK_BLOCKNR(source_spec->amap_block), bint, pgwrite->pg_len, QS_IO_WRITE);
		if (unlikely(retval != 0)) {
			tcache_put(tcache);
			debug_warn("tcache add page\n");
			ctio_construct_sense(ctio, SSD_CURRENT_ERROR, SSD_KEY_HARDWARE_ERROR, 0, INTERNAL_TARGET_FAILURE_ASC, INTERNAL_TARGET_FAILURE_ASCQ);
			return -1;
		}
	}

	if (atomic_read(&tcache->bio_remain))
		tcache_entry_rw(tcache, QS_IO_WRITE);
	else
		wait_complete(tcache->completion);

	if (need_remote_io) {
		retval = node_cmd_remote_write_io(comm, sock, ctio, msg,  pglist, pglist_cnt, client_send_timeout, 0);
		if (unlikely(retval != 0)) {
			wait_for_done(tcache->completion);
			tcache_put(tcache);
			return retval;
		}
	}

	wait_for_done(tcache->completion);
	if (atomic_test_bit_short(TCACHE_IO_ERROR, &tcache->flags)) {
		tcache_put(tcache);
		debug_warn("tcache data error\n");
		ctio_construct_sense(ctio, SSD_CURRENT_ERROR, SSD_KEY_HARDWARE_ERROR, 0, INTERNAL_TARGET_FAILURE_ASC, INTERNAL_TARGET_FAILURE_ASCQ);
		return -1;
	}

	tcache_put(tcache);
	return 0;
}

int
node_verify_setup(struct node_comm *comm, struct node_sock *sock, struct node_msg *msg, struct qsio_scsiio *ctio, int timeout, int async)
{
	struct raw_node_msg *raw;
	struct pgdata_read_spec *source_spec;
	struct pgdata *pgdata;
	struct pgdata **pglist;
	int i, retval;

	raw = msg->raw;
	pglist = (struct pgdata **)(ctio->data_ptr);
	source_spec = pgdata_read_spec_ptr(raw);

	for (i = 0; i < ctio->pglist_cnt; i++, source_spec++) {
		if (!atomic_test_bit_short(DDBLOCK_ENTRY_FOUND_DUPLICATE, &source_spec->flags))
			continue;

		pgdata = pglist[i];
		source_spec->csum = pgdata_csum(pgdata, LBA_SIZE);
	}

	raw->msg_cmd = NODE_MSG_VERIFY_DATA;
	node_msg_init(msg);
	node_msg_compute_csum(raw);
	node_cmd_hash_insert(comm->node_hash, msg, raw->msg_id);
	node_sock_start(sock);
	retval = node_sock_write(sock, raw);
	if (unlikely(retval != 0)) {
		node_sock_end(sock);
		node_cmd_hash_remove(comm->node_hash, msg, raw->msg_id);
		node_busy_check(ctio, msg, comm, 1);
		return retval;
	}

	source_spec = pgdata_read_spec_ptr(raw);
	for (i = 0; i < ctio->pglist_cnt; i++, source_spec++) {
		if (!atomic_test_bit_short(DDBLOCK_ENTRY_FOUND_DUPLICATE, &source_spec->flags))
			continue;

		pgdata = pglist[i];
		retval = node_sock_write_page(sock, pgdata->page, pgdata->pg_len);
		if (unlikely(retval != 0)) {
			node_sock_end(sock);
			node_cmd_hash_remove(comm->node_hash, msg, raw->msg_id);
			node_busy_check(ctio, msg, comm, 1);
			return retval;
		}
	}
	node_sock_end(sock);

	if (async) {
		msg->async_wait = 1;
		return 0;
	}

	node_msg_wait(msg, sock, timeout);
	retval = node_resp_status(ctio, msg, comm, sock);
	if (unlikely(retval != 0))
		return retval;

	node_msg_copy_resp(msg);
	return 0;
}

int
node_comp_setup(struct node_comm *comm, struct node_sock *sock, struct node_msg *msg, struct qsio_scsiio *ctio, int timeout, int async)
{
	struct raw_node_msg *raw;
	struct pgdata_read_spec *source_spec, *tmp;
	struct pgdata *pgdata;
	struct pgdata **pglist;
	int i, retval;
	struct pgdata_wlist pending_list;
	uint64_t id;

	raw = msg->raw;
	source_spec = pgdata_read_spec_ptr(raw);
	pglist = (struct pgdata **)(ctio->data_ptr);

	STAILQ_INIT(&pending_list);
	for (i = 0; i < ctio->pglist_cnt; i++, source_spec++) {
		pgdata = pglist[i];
		pgdata->lba = i; /* id to use */

		if (atomic_test_bit_short(DDBLOCK_ZERO_BLOCK, &source_spec->flags))
			continue;

		if (atomic_test_bit_short(DDBLOCK_ENTRY_FOUND_DUPLICATE, &source_spec->flags))
			continue;

		if (pgdata->comp_pgdata)
			continue;

		gdevq_comp_insert(pgdata);
		STAILQ_INSERT_TAIL(&pending_list, pgdata, t_list);
	}

	source_spec = pgdata_read_spec_ptr(raw);
	while ((pgdata = STAILQ_FIRST(&pending_list)) != NULL) {
		STAILQ_REMOVE_HEAD(&pending_list, t_list);
		wait_for_done(pgdata->completion);
		if (pgdata->comp_pgdata) {
			id = pgdata->lba;
			tmp = &source_spec[id];
			debug_check(tmp->amap_block);
			SET_BLOCK_SIZE(tmp->amap_block, pgdata->comp_pgdata->pg_len);
		}
	}

	raw->msg_cmd = NODE_MSG_WRITE_COMP_DONE;
	node_msg_init(msg);
	retval = node_send_msg(sock, msg, raw->msg_id, 1);
	if (unlikely(retval != 0)) {
		node_busy_check(ctio, msg, comm, 1);
		return retval;
	}

	if (async) {
		msg->async_wait = 1;
		return 0;
	}

	node_msg_wait(msg, sock, timeout);
	retval = node_resp_status(ctio, msg, comm, sock);
	if (unlikely(retval != 0))
		return retval;

	node_msg_copy_resp(msg);
	return 0;
}

int 
node_write_setup(struct node_comm *comm, struct node_sock *sock, struct node_msg *msg, struct qsio_scsiio *ctio, uint64_t lba, uint32_t transfer_length, uint64_t amap_write_id, int unaligned, int timeout, int cmd)
{
	struct raw_node_msg *raw;
	struct pgdata_spec *source_spec;
	struct scsi_cmd_spec *cmd_spec;
	struct pgdata *pgdata;
	struct pgdata **pglist;
	int i, retval, done;

	raw = msg->raw;
	cmd_spec = scsi_cmd_spec_ptr(raw);
	scsi_cmd_spec_fill(cmd_spec, ctio);
	cmd_spec->transfer_length = transfer_length;
	cmd_spec->lba = lba;
	cmd_spec->pglist_cnt = ctio->pglist_cnt;
	cmd_spec->amap_write_id = amap_write_id;

	source_spec = pgdata_spec_ptr(raw);
	done = 0;
	pglist = (struct pgdata **)(ctio->data_ptr);
	for (i = 0; i < ctio->pglist_cnt; i++) {
		pgdata = pglist[i];
		wait_for_done(pgdata->completion);
		if (!unaligned && atomic_test_bit(DDBLOCK_ZERO_BLOCK, &pgdata->flags))
			continue;
		memcpy(source_spec->hash, pgdata->hash, sizeof(pgdata->hash));
		source_spec->flags = pgdata->flags;
		if (unaligned)
			source_spec->csum = pgdata_csum(pgdata, LBA_SIZE);
		else
			source_spec->csum = i;
		source_spec++;
		done++;
	}

	raw->msg_cmd = cmd;
	raw->dxfer_len = sizeof(struct scsi_cmd_spec) + (sizeof(struct pgdata_spec) * done);
	node_msg_compute_csum(raw);
	node_cmd_hash_insert(comm->node_hash, msg, raw->msg_id);
	node_sock_start(sock);
	retval = node_sock_write(sock, raw);
	if (unlikely(retval != 0)) {
		node_sock_end(sock);
		node_cmd_hash_remove(comm->node_hash, msg, raw->msg_id);
		node_busy_check(ctio, msg, comm, 1);
		return retval;
	}

	if (unaligned) {
		for (i = 0; i < ctio->pglist_cnt; i++) {
			pgdata = pglist[i];
			retval = node_sock_write_page(sock, pgdata->page, pgdata->pg_len);
			if (unlikely(retval != 0)) {
				node_sock_end(sock);
				node_cmd_hash_remove(comm->node_hash, msg, raw->msg_id);
				node_busy_check(ctio, msg, comm, 1);
				return retval;
			}
		}
	}
	node_sock_end(sock);

	node_msg_wait(msg, sock, timeout);
	retval = node_resp_status(ctio, msg, comm, sock);
	if (unlikely(retval != 0))
		return retval;

	node_msg_copy_resp(msg);
	return 0;
}

void
ctio_pglist_cleanup(struct qsio_scsiio *ctio)
{
	int i;
	struct pgdata **pglist, *pgdata;
	int norefs = ctio_norefs(ctio);

	pglist = (struct pgdata **)(ctio->data_ptr);
	for (i = 0; i < ctio->pglist_cnt; i++) {
		pgdata = pglist[i];
		if (pgdata->comp_pgdata) 
			pgdata_free(pgdata->comp_pgdata);

		if (!norefs)
			pgdata_free(pgdata);
		else
			pgdata_free_norefs(pgdata);
	}
	free(pglist, M_PGLIST);
	ctio->data_ptr = NULL;
	ctio->dxfer_len = 0;
	ctio->pglist_cnt = 0;
}

static void
pglist_reset(struct pgdata **pglist, int pglist_cnt, int read)
{
	int i;
	struct pgdata *pgdata;
	int zero_block, dedupe_disabled;

	for (i = 0; i < pglist_cnt; i++) {
		pgdata = pglist[i];
		if (pgdata->comp_pgdata) {
			pgdata_free(pgdata->comp_pgdata);
			pgdata->comp_pgdata = NULL;
		}
		pgdata->lba = 0;
		pgdata->amap_block = 0;
		if (read) {
			pgdata->flags = 0;
			pgdata_free_page(pgdata);
		}
		else {
			zero_block = atomic_test_bit(DDBLOCK_ZERO_BLOCK, &pgdata->flags);
			dedupe_disabled = atomic_test_bit(DDBLOCK_DEDUPE_DISABLED, &pgdata->flags);
			pgdata->flags = 0;
			if (zero_block)
				atomic_set_bit(DDBLOCK_ZERO_BLOCK, &pgdata->flags);
			if (dedupe_disabled)
				atomic_set_bit(DDBLOCK_DEDUPE_DISABLED, &pgdata->flags);
		}
	}

}

static void 
node_cmd_write(struct tdisk *tdisk, struct qsio_scsiio *ctio, uint64_t lba, uint32_t transfer_length)
{
	struct node_msg *msg;
	struct raw_node_msg *raw;
	int retval, dxfer_len;
	struct node_comm *comm;
	struct node_sock *sock;
	int unaligned;
#ifdef ENABLE_STATS
	uint32_t start_ticks, tmp_ticks;
#endif

	TDISK_TSTART(tmp_ticks);
	dxfer_len = sizeof(struct scsi_cmd_spec) + (sizeof(struct pgdata_spec) * ctio->pglist_cnt);
retry:
	msg = node_msg_alloc(dxfer_len);
	sock = NULL;
	ctio->scsi_status = 0;
	comm = node_locate_master();
	if (unlikely(!comm)) {
		wait_for_pgdata((struct pgdata **)ctio->data_ptr, ctio->pglist_cnt);
		node_busy_check(ctio, msg, comm, 1);
		goto out;
	}

	raw = msg->raw;
	bzero(raw, dxfer_len + sizeof(*raw));
	raw->target_id = tdisk->target_id;
	raw->dxfer_len = dxfer_len;
	raw->msg_id = node_transaction_id();

	sock = node_comm_get_sock(comm, client_config.client_connect_timeout); /* waits till a sock is free */
	if (unlikely(!sock)) {
		wait_for_pgdata((struct pgdata **)ctio->data_ptr, ctio->pglist_cnt);
		node_busy_check(ctio, msg, comm, 1);
		goto out;
	}

	unaligned = is_unaligned_write(tdisk, lba, transfer_length);

	TDISK_TSTART(start_ticks);
	retval = node_write_setup(comm, sock, msg, ctio, lba, transfer_length, 0ULL, unaligned, client_send_timeout, NODE_MSG_WRITE_CMD);
	TDISK_TEND(tdisk, write_setup_ticks, start_ticks);
	if (unlikely(retval != 0))
		goto out;

	if (node_cmd_status(msg) == NODE_CMD_NEED_VERIFY) {
		retval = node_verify_setup(comm, sock, msg, ctio, client_send_timeout, 0);
		if (unlikely(retval != 0))
			goto out;
	}

	if (node_cmd_status(msg) == NODE_CMD_NEED_COMP) {
		retval = node_comp_setup(comm, sock, msg, ctio, client_send_timeout, 0);
		if (unlikely(retval != 0))
			goto out;
	}

	if (node_cmd_status(msg) == NODE_CMD_NEED_IO) {
		retval = node_cmd_write_io(ctio, comm, sock, msg, (struct pgdata **)ctio->data_ptr, ctio->pglist_cnt);
		if (unlikely(retval != 0))
			goto out;
	}

	TDISK_TSTART(start_ticks);
	node_cmd_write_done(ctio, comm, sock, msg, client_send_timeout);
	TDISK_TEND(tdisk, write_done_ticks, start_ticks);

out:
	if (sock)
		node_sock_finish(sock);
	if (comm) {
		if (!node_msg_retry(msg))
			node_comm_complete(comm);
		node_comm_put(comm);
	}
	if (node_msg_retry(msg)) {
		pglist_reset((struct pgdata **)ctio->data_ptr, ctio->pglist_cnt, 0);
		node_msg_free(msg);
		goto retry;
	}
	node_msg_free(msg);
	ctio_pglist_cleanup(ctio);
	device_send_ccb(ctio);
	TDISK_TEND(tdisk, node_cmd_write_ticks, tmp_ticks);
}

int 
node_read_setup(struct tdisk *tdisk, struct node_comm *comm, struct node_sock *sock, struct qsio_scsiio *ctio, struct node_msg *msg, uint64_t lba, struct pgdata **pglist, int pglist_cnt, uint32_t transfer_length, int timeout)
{
	struct raw_node_msg *raw;
	struct scsi_cmd_spec *cmd_spec;
	int retval;
	struct pgdata_read_spec *source_spec;
	struct pgdata_wlist read_list;
	int i, pg_idx;
	pagestruct_t **pages;
	struct pgdata *pgdata;
	int need_io, found;

	raw = msg->raw;
	raw->msg_cmd = NODE_MSG_READ_CMD;

	cmd_spec = scsi_cmd_spec_ptr(raw);
	scsi_cmd_spec_fill(cmd_spec, ctio);
	cmd_spec->lba = lba;
	cmd_spec->transfer_length = transfer_length;
	cmd_spec->pglist_cnt = pglist_cnt;

	retval = node_send_msg(sock, msg, raw->msg_id, 1);
	if (unlikely(retval != 0)) {
		node_busy_check(ctio, msg, comm, 1);
		return retval;
	}

	node_msg_wait(msg, sock, timeout);
	retval = node_resp_status(ctio, msg, comm, sock);
	if (unlikely(retval != 0))
		return retval;

	node_msg_copy_resp(msg);
	raw = msg->raw;
	if (raw->mirror_status == NODE_STATUS_DO_LOCAL_READ)
		return 0;

	need_io = (node_cmd_status(msg) == NODE_CMD_NEED_IO);

	STAILQ_INIT(&read_list);
	debug_check(raw->dxfer_len != pgdata_read_spec_dxfer_len(pglist_cnt));
	source_spec = pgdata_read_spec_ptr(raw);
	pages = msg->pages;
	pg_idx = 0;
	retval = 0;
	for (i = 0; i < pglist_cnt; i++, source_spec++) {
		pgdata = pglist[i];
		pgdata->amap_block = source_spec->amap_block;
		pgdata->flags = source_spec->flags;

		if (!source_spec->amap_block) {
			pgdata_free_page(pgdata);
			pgdata_add_ref(pgdata, &pgzero);
			continue;
		}
		if (!atomic_test_bit_short(PGDATA_FROM_RCACHE, &source_spec->flags)) {
			if (need_io)
				continue;
			found = pgdata_in_read_list(tdisk, pgdata, &read_list, 0);
			debug_check(!found);
			continue;
		}
		debug_check(pg_idx >= msg->pg_count);
		vm_pg_ref(pages[pg_idx]);
		pgdata_free_page(pgdata);
		pgdata->page = pages[pg_idx];
		pg_idx++;
		if (pgdata_csum(pgdata, LBA_SIZE) != source_spec->csum) {
			debug_warn("Invalid pgdata csum\n");
			node_sock_read_error(sock);
			retval = -1;
			ctio_construct_sense(ctio, SSD_CURRENT_ERROR, SSD_KEY_HARDWARE_ERROR, 0, INTERNAL_TARGET_FAILURE_ASC, INTERNAL_TARGET_FAILURE_ASCQ);
			break;
		}
		STAILQ_INSERT_TAIL(&read_list, pgdata, t_list);
	}

	if (msg->pages) {
		page_list_free(msg->pages, msg->pg_count);
		msg->pages = NULL;
		msg->pg_count = 0;
	}

	raw->pg_count = 0;
	return retval;
}

static int
node_client_cmd_generic2(struct tdisk *tdisk, struct qsio_scsiio *ctio)
{
	struct node_msg *msg, *resp;
	struct raw_node_msg *raw;
	struct node_comm *comm;
	struct scsi_cmd_spec_generic *cmd_spec;
	struct pgdata **pglist, *pgdata;
	struct node_sock *sock;
	int retval, dxfer_len, i;
	uint16_t csum;

	dxfer_len = sizeof(*cmd_spec);
retry:
	msg = node_msg_alloc(dxfer_len);
	sock = NULL;
	ctio->scsi_status = 0;
	comm = node_locate_master();
	if (unlikely(!comm)) {
		node_busy_check(ctio, msg, comm, 1);
		goto err;
	}

	raw = msg->raw;
	bzero(raw, dxfer_len + sizeof(*raw));
	raw->msg_cmd = NODE_MSG_GENERIC_CMD;
	raw->target_id = tdisk->target_id;
	raw->dxfer_len = dxfer_len;
	raw->msg_id = node_transaction_id();
	raw->pg_count = ctio->pglist_cnt;

	cmd_spec = scsi_cmd_spec_generic_ptr(raw);
	scsi_cmd_spec_generic_fill(cmd_spec, ctio);
	cmd_spec->transfer_length = ctio->dxfer_len;

	sock = node_comm_get_sock(comm, client_config.client_connect_timeout);
	if (unlikely(!sock)) {
		node_busy_check(ctio, msg, comm, 1);
		goto err;
	}

	pglist = (struct pgdata **)(ctio->data_ptr);
	csum = 0;
	for (i = 0; i < ctio->pglist_cnt; i++) {
		pgdata = pglist[i];
		if (is_write_cmd(ctio))
			wait_for_done(pgdata->completion);
		csum += pgdata_csum(pgdata, pgdata->pg_len);
	}
	cmd_spec->csum = csum;

	node_msg_compute_csum(raw);
	node_cmd_hash_insert(comm->node_hash, msg, raw->msg_id);
	node_sock_start(sock);
	retval = node_sock_write(sock, raw);
	if (unlikely(retval != 0)) {
		node_sock_end(sock);
		node_cmd_hash_remove(comm->node_hash, msg, raw->msg_id);
		node_busy_check(ctio, msg, comm, 1);
		goto err;
	}

	for (i = 0; i < ctio->pglist_cnt; i++) {
		pgdata = pglist[i];
		retval = node_sock_write_page(sock, pgdata->page, pgdata->pg_len);
		if (unlikely(retval != 0)) {
			node_sock_end(sock);
			node_cmd_hash_remove(comm->node_hash, msg, raw->msg_id);
			node_busy_check(ctio, msg, comm, 1);
			goto err;
		}
	}
	node_sock_end(sock);

	node_msg_wait(msg, sock, client_send_timeout);
	retval = node_resp_status(ctio, msg, comm, sock);
	if (retval != 0)
		goto err;

	node_sock_finish(sock);
	node_comm_put(comm);
	ctio_free_data(ctio);
	resp = msg->resp;
	debug_check(!resp);
	raw = resp->raw;

	if (raw->dxfer_len) {
		ctio_allocate_buffer(ctio, raw->dxfer_len, Q_WAITOK);
		memcpy(ctio->data_ptr, raw->data, raw->dxfer_len);
	}
	node_msg_free(msg);
	return 0;
err:
	if (is_write_cmd(ctio))
		wait_for_pgdata((struct pgdata **)ctio->data_ptr, ctio->pglist_cnt);

	if (sock)
		node_sock_finish(sock);
	if (comm) {
		if (!node_msg_retry(msg))
			node_comm_complete(comm);
		node_comm_put(comm);
	}

	if (node_msg_retry(msg)) {
		node_msg_free(msg);
		goto retry;
	}
	ctio_free_data(ctio);
	node_msg_free(msg);
	return 0;
}

static int
node_client_cmd_generic(struct tdisk *tdisk, struct qsio_scsiio *ctio, int pcmd)
{
	struct node_msg *msg, *resp;
	struct raw_node_msg *raw;
	int retval, dxfer_len;
	struct node_comm *comm;
	struct scsi_cmd_spec_generic *cmd_spec;
	struct node_sock *sock;
	int offset = pcmd ? INITIATOR_NAME_MAX : 0;

	dxfer_len = sizeof(*cmd_spec) + offset + ctio->dxfer_len;
retry:
	msg = node_msg_alloc(dxfer_len);
	sock = NULL;
	ctio->scsi_status = 0;
	comm = node_locate_master();
	if (unlikely(!comm)) {
		node_busy_check(ctio, msg, comm, 1);
		goto err;
	}

	raw = msg->raw;
	bzero(raw, sizeof(*raw) + sizeof(*cmd_spec) + offset);
	if (!pcmd)
		raw->msg_cmd = NODE_MSG_GENERIC_CMD;
	else
		raw->msg_cmd = NODE_MSG_PERSISTENT_RESERVE_OUT_CMD;
	raw->target_id = tdisk->target_id;
	raw->dxfer_len = dxfer_len;
	raw->msg_id = node_transaction_id();

	cmd_spec = scsi_cmd_spec_generic_ptr(raw);
	scsi_cmd_spec_generic_fill(cmd_spec, ctio);
	cmd_spec->transfer_length = ctio->dxfer_len;

	if (pcmd && ctio->init_int == TARGET_INT_ISCSI) {
		struct iscsi_priv *priv = &ctio->ccb_h.priv.ipriv;
		strcpy(scsi_data_ptr_generic(raw), priv->init_name);
	}

	if (ctio->dxfer_len)
		memcpy(((uint8_t *)scsi_data_ptr_generic(raw)) + offset, ctio->data_ptr, ctio->dxfer_len);

	sock = node_comm_get_sock(comm, client_config.client_connect_timeout);
	if (unlikely(!sock)) {
		node_busy_check(ctio, msg, comm, 1);
		goto err;
	}

	retval = node_send_msg(sock, msg, raw->msg_id, 1);
	if (unlikely(retval != 0)) {
		node_busy_check(ctio, msg, comm, 1);
		goto err;
	}

	node_msg_wait(msg, sock, client_send_timeout);
	retval = node_resp_status(ctio, msg, comm, sock);
	if (retval != 0)
		goto err;

	node_sock_finish(sock);
	node_comm_put(comm);
	ctio_free_data(ctio);
	resp = msg->resp;
	debug_check(!resp);
	raw = resp->raw;

	if (raw->dxfer_len) {
		ctio_allocate_buffer(ctio, raw->dxfer_len, Q_WAITOK);
		memcpy(ctio->data_ptr, raw->data, raw->dxfer_len);
	}
	node_msg_free(msg);
	return 0;
err:
	if (sock)
		node_sock_finish(sock);
	if (comm) {
		if (!node_msg_retry(msg))
			node_comm_complete(comm);
		node_comm_put(comm);
	}
	if (node_msg_retry(msg)) {
		node_msg_free(msg);
		goto retry;
	}
	ctio_free_data(ctio);
	node_msg_free(msg);
	return 0;
}

static int 
__node_cmd_read(struct tdisk *tdisk, struct qsio_scsiio *ctio, struct pgdata ***ret_pglist, int *ret_pglist_cnt, uint64_t lba, uint32_t transfer_length)
{
	struct node_msg *msg;
	struct raw_node_msg *raw;
	int retval, dxfer_len;
	struct node_comm *comm;
	struct pgdata **pglist;
	int pglist_cnt;
	struct node_sock *sock;
	uint32_t orig_transfer_length = transfer_length;
#ifdef ENABLE_STATS
	uint32_t start_ticks, tmp_ticks;
#endif

	TDISK_TSTART(tmp_ticks);
	transfer_length += tdisk_get_lba_diff(tdisk, lba);

	pglist_cnt = transfer_length_to_pglist_cnt(tdisk->lba_shift, transfer_length);
	pglist = pgdata_allocate_nopage(pglist_cnt, Q_NOWAIT); 
	if (unlikely(!pglist)) {
		debug_warn("pgdata allocate failed for %d\n", pglist_cnt);
		ctio_construct_sense(ctio, SSD_CURRENT_ERROR, SSD_KEY_HARDWARE_ERROR, 0, INTERNAL_TARGET_FAILURE_ASC, INTERNAL_TARGET_FAILURE_ASCQ);
		return -1;
	}

	dxfer_len = sizeof(struct scsi_cmd_spec);
retry:
	msg = node_msg_alloc(dxfer_len);
	sock = NULL;
	ctio->scsi_status = 0;
	comm = node_locate_master();
	if (unlikely(!comm)) {
		node_busy_check(ctio, msg, comm, 1);
		goto err;
	}

	raw = msg->raw;
	bzero(raw, dxfer_len + sizeof(*raw));
	raw->target_id = tdisk->target_id;
	raw->dxfer_len = dxfer_len;
	raw->msg_id = node_transaction_id();

	sock = node_comm_get_sock(comm, client_config.client_connect_timeout); /* waits till a sock is free */
	if (unlikely(!sock)) {
		node_busy_check(ctio, msg, comm, 1);
		goto err;
	}

	TDISK_TSTART(start_ticks);
	retval = node_read_setup(tdisk, comm, sock, ctio, msg, lba, pglist, pglist_cnt, orig_transfer_length, client_send_timeout);
	TDISK_TEND(tdisk, read_setup_ticks, start_ticks);

	if (unlikely(retval != 0))
		goto err;

	if (node_cmd_status(msg) == NODE_CMD_NEED_IO) {
		TDISK_TSTART(start_ticks);
		retval = node_cmd_read_io(tdisk, ctio, comm, sock, msg, pglist, pglist_cnt, 0, client_send_timeout);
		TDISK_TEND(tdisk, read_io_ticks, start_ticks);
		if (unlikely(retval != 0))
			goto err;
	}

	TDISK_TEND(tdisk, node_cmd_read_ticks, tmp_ticks);
	node_sock_finish(sock);
	node_comm_put(comm);
	node_msg_free(msg);
	*ret_pglist = pglist;
	*ret_pglist_cnt = pglist_cnt;
	return 0;
err:
	if (sock)
		node_sock_finish(sock);
	if (comm) {
		if (!node_msg_retry(msg))
			node_comm_complete(comm);
		node_comm_put(comm);
	}
	if (node_msg_retry(msg)) {
		pglist_reset(pglist, pglist_cnt, 1);
		node_msg_free(msg);
		goto retry;
	}
	pglist_free(pglist, pglist_cnt);
	node_msg_free(msg);
	return -1;
}

static void
node_cmd_read(struct tdisk *tdisk, struct qsio_scsiio *ctio, uint64_t lba, uint32_t transfer_length)
{
	struct pgdata **pglist = NULL;
	int retval;
	int pglist_cnt = 0;

	retval = __node_cmd_read(tdisk, ctio, &pglist, &pglist_cnt, lba, transfer_length);
	if (unlikely(retval != 0)) {
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

		lba_diff = tdisk_get_lba_diff(tdisk, lba);
		pg_offset = (lba_diff << tdisk->lba_shift);
		pgdata = pglist[0];
		pgdata->pg_offset = pg_offset;
		pgdata->pg_len -= pg_offset;

		if (lba_diff || (ctio->dxfer_len & LBA_MASK))
			ctio_fix_pglist_len(ctio);
	}

	device_send_ccb(ctio);
}

static void 
node_client_cmd_read16(struct tdisk *tdisk, struct qsio_scsiio *ctio)
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

	node_cmd_read(tdisk, ctio, lba, transfer_length);
}

static void 
node_client_cmd_read12(struct tdisk *tdisk, struct qsio_scsiio *ctio)
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
	node_cmd_read(tdisk, ctio, lba, transfer_length);
}

static void 
node_client_cmd_read10(struct tdisk *tdisk, struct qsio_scsiio *ctio)
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
	node_cmd_read(tdisk, ctio, lba, transfer_length);
}

static void 
node_client_cmd_read6(struct tdisk *tdisk, struct qsio_scsiio *ctio)
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
	node_cmd_read(tdisk, ctio, lba, transfer_length);
}

static void 
node_client_cmd_write12(struct tdisk *tdisk, struct qsio_scsiio *ctio)
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
	node_cmd_write(tdisk, ctio, lba, transfer_length);
}

static void 
node_client_cmd_write16(struct tdisk *tdisk, struct qsio_scsiio *ctio)
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
	node_cmd_write(tdisk, ctio, lba, transfer_length);
}

static void 
node_client_cmd_write10(struct tdisk *tdisk, struct qsio_scsiio *ctio)
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
	node_cmd_write(tdisk, ctio, lba, transfer_length);
}

static void 
node_client_cmd_write6(struct tdisk *tdisk, struct qsio_scsiio *ctio)
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
	node_cmd_write(tdisk, ctio, lba, transfer_length);
}

void
node_client_proc_cmd(void *disk, void *iop)
{
	struct tdisk *tdisk = disk;
	struct qsio_scsiio *ctio = iop;
	uint8_t *cdb = ctio->cdb;
	int retval = 0;

	if (!atomic_test_bit(VDISK_ATTACHED, &tdisk->flags) || atomic_test_bit(VDISK_DISABLED, &tdisk->flags)) {
		if (is_write_cmd(ctio))
			wait_for_pgdata((struct pgdata **)ctio->data_ptr, ctio->pglist_cnt);
		ctio_free_data(ctio);
		if (atomic_test_bit(VDISK_DISABLED, &tdisk->flags))
			ctio_construct_sense(ctio, SSD_CURRENT_ERROR, SSD_KEY_ILLEGAL_REQUEST, 0, LOGICAL_UNIT_NOT_SUPPORTED_ASC, LOGICAL_UNIT_NOT_SUPPORTED_ASCQ);
		else 
			ctio->scsi_status = SCSI_STATUS_BUSY;
		device_send_ccb(ctio);
		return;
	}

	switch(cdb[0]) {
		case INQUIRY:
			retval = tdisk_cmd_inquiry(tdisk, ctio);
			break;
		case PERSISTENT_RESERVE_OUT:
			retval = node_client_cmd_generic(tdisk, ctio, 1);
			break;
		case TEST_UNIT_READY:
		case RESERVE:
		case RELEASE:
		case PERSISTENT_RESERVE_IN:
		case REQUEST_SENSE:
		case READ_CAPACITY:
		case SERVICE_ACTION_IN:
		case MODE_SENSE_6:
		case MODE_SENSE_10:
		case UNMAP:
		case RECEIVE_COPY_RESULTS:
		case SYNCHRONIZE_CACHE:
		case SYNCHRONIZE_CACHE_16:
		case VERIFY:
		case VERIFY_12:
		case VERIFY_16:
			retval = node_client_cmd_generic(tdisk, ctio, 0);
			break;
		case WRITE_SAME:
		case WRITE_SAME_16:
		case COMPARE_AND_WRITE:
		case EXTENDED_COPY:
			retval = node_client_cmd_generic2(tdisk, ctio);
			break;
		case READ_6:
			node_client_cmd_read6(tdisk, ctio);
			goto skip_send;
			break;
		case READ_10:
			node_client_cmd_read10(tdisk, ctio);
			goto skip_send;
			break;
		case READ_12:
			node_client_cmd_read12(tdisk, ctio);
			goto skip_send;
			break;
		case READ_16:
			node_client_cmd_read16(tdisk, ctio);
			goto skip_send;
			break;
		case WRITE_6:
			node_client_cmd_write6(tdisk, ctio);
			goto skip_send;
			break;
		case WRITE_10:
			node_client_cmd_write10(tdisk, ctio);
			goto skip_send;
			break;
		case WRITE_12:
			node_client_cmd_write12(tdisk, ctio);
			goto skip_send;
			break;
		case WRITE_16:
			node_client_cmd_write16(tdisk, ctio);
			goto skip_send;
			break;
		case REPORT_LUNS:
			retval = tdisk_cmd_report_luns(tdisk, ctio);
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
		debug_warn("Command failed for %x\n", ctio->cdb[0]);
		ctio_construct_sense(ctio, SSD_CURRENT_ERROR, SSD_KEY_HARDWARE_ERROR, 0, INTERNAL_TARGET_FAILURE_ASC, INTERNAL_TARGET_FAILURE_ASCQ);
	}

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

int
node_comm_register(struct node_comm *comm, int timeout)
{
	struct node_msg *msg;
	struct raw_node_msg *raw;
	struct node_sock *sock;
	int retval;

	sock = node_comm_get_sock(comm, timeout);
	if (unlikely(!sock)) {
		debug_warn("Cannot get a free sock\n");
		return -1;
	}

	msg = node_msg_alloc(0);
	raw = msg->raw;
	bzero(raw, sizeof(*raw));
	raw->msg_id = node_transaction_id();
	raw->msg_cmd = NODE_MSG_REGISTER; 
	raw->dxfer_len = 0;
	retval = node_send_msg(sock, msg, raw->msg_id, 1);
	if (unlikely(retval != 0)) {
		debug_warn("Cannot send register message\n");
		node_msg_free(msg);
		node_sock_finish(sock);
		return retval;
	}

	node_msg_wait(msg, sock, timeout);
	retval = __node_resp_status(msg);
	node_msg_free(msg);
	node_sock_finish(sock);
	return retval;
}

static int
node_client_sock_init(struct node_comm *comm, int do_register)
{
	int i = 0, retval;

	if (!do_register)
		goto skip;

	retval = node_sock_connect(comm, node_client_recv, CONTROLLER_DATA_PORT, "ndsockcl");
	if (unlikely(retval != 0)) {
		debug_warn("Connect to controller failed\n");
		return -1;
	}
	pause("psg", 800);

	retval = node_comm_register(comm, client_send_timeout);
	if (unlikely(retval != 0)) {
		debug_warn("Register with controller failed\n");
		return -1;
	}
	i++;
skip:
	for (; i < MAX_GDEVQ_THREADS; i++) {
		retval = node_sock_connect(comm, node_client_recv, CONTROLLER_DATA_PORT, "ndsockcl");
		if (unlikely(retval != 0))
			return -1;
		if ((i % 8) == 0)
			pause("psg", 50);
	}
	return 0;
}

wait_chan_t *client_wait;
kproc_t *client_task;
kproc_t *client_recv_task;

static void
node_client_ha_enabled(struct node_sock *sock, struct raw_node_msg *raw)
{
	raw->dxfer_len = 0;
	node_resp_msg(sock, raw, NODE_STATUS_OK);
	sx_xlock(comm_lock);
	atomic_set(&ha_enabled, 1);
	sx_xunlock(comm_lock);
	chan_wakeup_nointr(ha_chan);
}

static void
node_client_ha_disabled(struct node_sock *sock, struct raw_node_msg *raw)
{
	raw->dxfer_len = 0;
	node_resp_msg(sock, raw, NODE_STATUS_OK);
	sx_xlock(comm_lock);
	atomic_set(&ha_enabled, 0);
	sx_xunlock(comm_lock);
	chan_wakeup_nointr(ha_chan);
}

static void
node_client_ha_switch(struct node_sock *sock, struct raw_node_msg *raw)
{
	struct ha_config ha_config;
	struct node_comm *old_master;
	int retval;

	debug_check(raw->dxfer_len != sizeof(ha_config));
	retval = node_sock_read_nofail(sock, &ha_config, sizeof(ha_config));
	if (unlikely(retval != 0))
		return;

	debug_info("start switch\n");
	sx_xlock(comm_lock);
	old_master = master;
	debug_info("node master setup\n");
	node_master_setup(ha_config.ipaddr, client_config.node_ipaddr, 1);
	atomic_set_bit(NODE_COMM_FROM_HA, &master->flags);
	master->timestamp = ticks;
	debug_info("graceful %d\n", ha_config.graceful);

	raw->dxfer_len = 0;
	node_resp_msg(sock, raw, NODE_STATUS_OK);

	if (!ha_config.graceful)
		node_msg_hash_cancel(node_client_hash);
	debug_info("wait for refs master %p old_master %p\n", master, old_master);
	while (old_master && atomic_read(&old_master->refs) > 1) {
		debug_info("old master refs %d\n", atomic_read(&old_master->refs));
		pause("psg", 2000);
	}

	atomic_set(&ha_enabled, 0);
	sx_xunlock(comm_lock);
	debug_info("end switch\n");
	chan_wakeup_nointr(ha_chan);

	if (!ha_config.graceful) {
		pause("psg", 7000);
		atomic_clear_bit(NODE_COMM_LINGER, &old_master->flags);
	}
	node_comm_put(old_master);
}

static void
node_recv_cmd(struct node_sock *sock, struct raw_node_msg *raw)
{
	switch (raw->msg_cmd) {
	case NODE_MSG_HA_SWITCH:
		node_client_ha_switch(sock, raw);
		break;
	case NODE_MSG_HA_ENABLED:
		node_client_ha_enabled(sock, raw);
		break;
	case NODE_MSG_HA_DISABLED:
		node_client_ha_disabled(sock, raw);
		break;
	}
}

static int
node_client_bind_recv(struct node_sock *sock)
{
	int retval;
	struct raw_node_msg raw;

	while (1) {
		retval = node_sock_read(sock, &raw, sizeof(raw));
		if (retval != 0)
			return -1;

		if (unlikely(!node_msg_csum_valid(&raw))) {
			debug_warn("Received msg with invalid csum\n");
			node_sock_read_error(sock);
			return -1;
		}

		node_recv_cmd(sock, &raw);
	}
	return 0;
}

static int
node_client_recv_accept(struct node_sock *recv_sock)
{
	struct node_sock *sock;
	struct node_comm *comm;
	uint32_t ipaddr;
	int error = 0, retval;

	while (1) {
		sock = __node_sock_alloc(NULL, node_client_bind_recv); 
		sock->lsock = sock_accept(recv_sock->lsock, sock, &error, &ipaddr);
		if (!sock->lsock || !atomic_read(&kern_inited)) {
			node_sock_free(sock, 1);
			if (error) {
				return -1;
			}
			return 0;
		}

		comm = node_comm_locate(node_client_accept_hash, ipaddr, recv_comm);
		sock->comm = comm;
		node_comm_lock(comm);
		retval = kernel_thread_create(node_sock_recv_thr, sock, sock->task, "ndsockclra");
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

#ifdef FREEBSD 
static void node_client_recv_thr(void *data)
#else
static int node_client_recv_thr(void *data)
#endif
{
	struct node_config *node_config = data;
	int retval;

	recv_comm = node_comm_alloc(NULL, node_config->node_ipaddr, node_config->node_ipaddr);
	retval = node_sock_bind(recv_comm, node_client_recv_accept, NODE_CLIENT_NOTIFY_PORT, "ndsockclr");
	if (unlikely(retval != 0)) {
		debug_warn("node client recv init failed\n");
		node_comm_put(recv_comm);
		recv_comm = NULL;
	}

	atomic_set_bit(CLIENT_RECV_INITED, &client_flags);
	chan_wakeup(client_wait);
	wait_on_chan_interruptible(client_wait, kernel_thread_check(&client_flags, CLIENT_RECV_EXIT));
#ifdef FREEBSD 
	kproc_exit(0);
#else
	return 0;
#endif
}

#ifdef FREEBSD 
static void node_client_thr(void *data)
#else
static int node_client_thr(void *data)
#endif
{
	struct node_config *node_config = data;

	node_master_setup(node_config->controller_ipaddr, node_config->node_ipaddr, 1);
	atomic_set_bit(CLIENT_INITED, &client_flags);
	chan_wakeup(client_wait);
	wait_on_chan_interruptible(client_wait, kernel_thread_check(&client_flags, CLIENT_EXIT));
#ifdef FREEBSD 
	kproc_exit(0);
#else
	return 0;
#endif
}

static void
node_client_unregister(struct node_comm *comm)
{
	struct node_sock *sock;
	struct node_msg *msg;
	struct raw_node_msg *raw;

	sock = node_comm_get_sock(comm, client_config.client_connect_timeout);
	if (!sock)
		return;

	msg = node_msg_alloc(0);
	raw = msg->raw;
	bzero(raw, sizeof(*raw));
	raw->msg_id = node_transaction_id();
	raw->msg_cmd = NODE_MSG_UNREGISTER; 
	raw->dxfer_len = 0;

	node_send_msg(sock, msg, 0, 0);
	node_msg_free(msg);
}

void
node_client_exit(void)
{
	if (master)
		node_client_unregister(master);

	if (client_task) {
		kernel_thread_stop(client_task, &client_flags, client_wait, CLIENT_EXIT);
		client_task = NULL;
	}

	if (client_recv_task) {
		kernel_thread_stop(client_recv_task, &client_flags, client_wait, CLIENT_RECV_EXIT);
		client_recv_task = NULL;
	}

	if (client_wait) {
		wait_chan_free(client_wait);
		client_wait = NULL;
	}

	if (comm_lock) {
		sx_free(comm_lock);
		comm_lock = NULL;
	}

	if (ha_chan) {
		wait_chan_free(ha_chan);
		ha_chan = NULL;
	}

	if (master) {
		node_comm_put(master);
		master = NULL;
	}

	if (recv_comm) {
		node_root_comm_free(recv_comm, NULL, NULL);
		node_comm_put(recv_comm);
		recv_comm = NULL;
	}
}

static int
node_client_reinit(struct node_config *node_config)
{
	struct node_comm *old_master;

	debug_info("start reinit\n");
	sx_xlock(comm_lock);

	if (atomic_read(&ha_enabled) || master->controller_ipaddr != node_config->controller_ipaddr) {
		debug_info("skipping reinit master refs %d\n", atomic_read(&master->refs));
		sx_xunlock(comm_lock);
		return 0;
	}

	if (atomic_test_bit(NODE_COMM_FROM_HA, &master->flags)) {
		unsigned long elapsed;
		elapsed = (ticks - master->timestamp);
		if (ticks_to_msecs(elapsed) < NODE_COMM_REINIT_TIMEOUT) {
			debug_info("skipping reinit\n");
			sx_xunlock(comm_lock);
			return 0;
		}
	}

	old_master = master;
	node_master_setup(node_config->controller_ipaddr, node_config->node_ipaddr, 1);
	debug_info("wait for refs\n");
	while (old_master && atomic_read(&old_master->refs) > 1)
		pause("psg", 20);
	debug_info("done wait for refs\n");
	node_comm_put(old_master);
	sx_xunlock(comm_lock);
	debug_info("end reinit\n");
	return 0;
}

int
node_client_init(struct node_config *node_config)
{
	int retval;

	SET_NODE_TIMEOUT(node_config, client_send_timeout, CLIENT_SEND_TIMEOUT_MIN, CLIENT_SEND_TIMEOUT_MAX);
	SET_NODE_TIMEOUT(node_config, ha_check_timeout, HA_CHECK_TIMEOUT_MIN, HA_CHECK_TIMEOUT_MAX);
	SET_NODE_TIMEOUT(node_config, ha_ping_timeout, HA_PING_TIMEOUT_MIN, HA_PING_TIMEOUT_MAX);
	SET_NODE_TIMEOUT(node_config, controller_recv_timeout, CONTROLLER_RECV_TIMEOUT_MIN, CONTROLLER_RECV_TIMEOUT_MAX);
	SET_NODE_TIMEOUT(node_config, node_sync_timeout, NODE_SYNC_TIMEOUT_MIN, NODE_SYNC_TIMEOUT_MAX);

	if (client_wait)
		return node_client_reinit(node_config);

	client_wait = wait_chan_alloc("node client wait");

	comm_lock = sx_alloc("node client comm lock");

	ha_chan = wait_chan_alloc("ha chan");

	memcpy(&client_config, node_config, sizeof(client_config));
	if (client_config.client_connect_timeout)
		client_config.client_connect_timeout *= 1000; /* ms */
	else
		client_config.client_connect_timeout = NODE_GET_SOCK_TIMEOUT;

	retval = kernel_thread_create(node_client_recv_thr, node_config, client_recv_task, "clnrcvthr");  
	if (unlikely(retval != 0)) {
		node_client_exit();
		return -1;
	}

	retval = kernel_thread_create(node_client_thr, node_config, client_task, "clnthr");  
	if (unlikely(retval != 0)) {
		node_client_exit();
		return -1;
	}

	wait_on_chan_interruptible(client_wait, atomic_test_bit(CLIENT_INITED, &client_flags) && atomic_test_bit(CLIENT_RECV_INITED, &client_flags));
	if (unlikely(!master)) {
		node_client_exit();
		return -1;
	}

	return 0;
}

static int
node_client_recv_pages(struct node_sock *sock, struct node_msg *resp, struct raw_node_msg *raw)
{
	pagestruct_t *page, **pages;
	int i, retval;

	pages = malloc((raw->pg_count * sizeof(pagestruct_t *)), M_PAGE_LIST, Q_WAITOK);
	for (i = 0; i < raw->pg_count; i++) {
		page = vm_pg_alloc(0);
		if (unlikely(!page)) {
			page_list_free(pages, i);
			node_sock_read_error(sock);
			return -1;
		}
		pages[i] = page;
		retval = node_sock_read_nofail(sock, vm_pg_address(page), LBA_SIZE);
		if (unlikely(retval != 0)) {
			page_list_free(pages, i+1);
			return -1;
		}
	}
	resp->pages = pages;
	resp->pg_count = raw->pg_count;
	return 0;
}

uint32_t recv_pages_ticks;

static int 
node_client_handle_resp(struct node_sock *sock, struct raw_node_msg *raw)
{
	struct node_msg *resp = NULL;
	int retval;
	struct node_msg *msg;
	uint16_t csum;
#ifdef ENABLE_STATS
	uint32_t start_ticks;
#endif

	resp = node_msg_alloc(raw->dxfer_len);
	memcpy(resp->raw, raw, sizeof(*raw));

	if (raw->dxfer_len) {
		retval = node_sock_read_nofail(sock, resp->raw->data, raw->dxfer_len);
		if (unlikely(retval != 0))
			goto err;

		csum = net_calc_csum16(resp->raw->data, resp->raw->dxfer_len);
		if (unlikely(csum != raw->data_csum)) {
			debug_warn("data csum mismatch\n");
			node_sock_read_error(sock);
			goto err;
		}
	}

	if (raw->pg_count) {
		GLOB_TSTART(start_ticks);
		retval = node_client_recv_pages(sock, resp, raw);
		GLOB_TEND(recv_pages_ticks, start_ticks);
		if (unlikely(retval != 0))
			goto err;
	}

	msg = node_cmd_lookup(sock->comm->node_hash, raw->msg_id, NULL, NULL);
	if (unlikely(!msg)) {
		debug_warn("Received response for unknown id %llx cmd %d \n", (unsigned long long)(raw->msg_id), raw->msg_cmd);
		node_msg_free(resp);
		return 0;
	}

	msg->resp = resp;
	wait_complete_all(msg->completion);
	return 0;
err:
	node_msg_free(resp);
	return -1;
}

int
node_client_recv(struct node_sock *sock)
{
	struct raw_node_msg raw;
	int retval;

	while (!sock_state_error(sock)) {
		retval = node_sock_read(sock, &raw, sizeof(raw));
		if (retval != 0)
			return -1;

		if (unlikely(!node_msg_csum_valid(&raw))) {
			debug_warn("Received msg with invalid csum\n");
			node_sock_read_error(sock);
			return -1;
		}

		retval = node_client_handle_resp(sock, &raw);
		if (unlikely(retval != 0))
			return retval;
	}
	return 0;
}
