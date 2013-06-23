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
#include "../common/commondefs.h"
#include "node_sock.h"
#include "vdevdefs.h"
#include "ddthread.h"
#include "node_sync.h"
#include "node_ha.h"
#include "bdevgroup.h"
#include "node_mirror.h"
#include "sense.h"

static int tdisk_mirror_startup(struct tdisk *tdisk, int recovery);

static void
tdisk_mirror_incr(struct tdisk *tdisk)
{
retry:
	chan_lock(tdisk->mirror_wait);
	if (atomic_test_bit(MIRROR_FLAGS_BLOCK, &tdisk->mirror_state.mirror_flags)) {
		chan_unlock(tdisk->mirror_wait);
		debug_info("Wait for tdisk to unblock\n");
		wait_on_chan(tdisk->mirror_wait, !atomic_test_bit(MIRROR_FLAGS_BLOCK, &tdisk->mirror_state.mirror_flags));
		debug_info("Done Wait for tdisk to unblock\n");
		goto retry;
	}
	atomic_inc(&tdisk->mirror_cmds);
	chan_unlock(tdisk->mirror_wait);
}

static void
tdisk_mirror_decr(struct tdisk *tdisk)
{
	chan_lock(tdisk->mirror_wait);
	debug_check(!atomic_read(&tdisk->mirror_cmds));
	if (atomic_dec_and_test(&tdisk->mirror_cmds)) {
		if (atomic_test_bit(MIRROR_FLAGS_BLOCK, &tdisk->mirror_state.mirror_flags))
			chan_wakeup_unlocked(tdisk->mirror_wait);
	}
	chan_unlock(tdisk->mirror_wait);
}

int
tdisk_mirror_ready(struct tdisk *tdisk)
{
	if (!tdisk_mirroring_configured(tdisk))
		return 1;

	if (tdisk_mirror_master(tdisk))
		return 1;

	if (tdisk_mirroring_disabled(tdisk))
		return 0;
	if (!atomic_test_bit(MIRROR_FLAGS_PEER_LOAD_DONE, &tdisk->mirror_state.mirror_flags))
		return 0;
	else
		return 1;
}

static int
tdisk_flag_write_after(struct tdisk *tdisk)
{
	int retval;

	if (tdisk_mirroring_need_resync(tdisk))
		return 0;

	debug_info("flagging write after\n");
	mirror_set_write_id_skip();
	tdisk_mirroring_resync_set(tdisk);
	atomic_set_bit(VDISK_SYNC_START, &tdisk->flags);
	retval = tdisk_sync(tdisk, 0);
	return retval;
}

static void
__tdisk_mirror_comm_free(struct tdisk *tdisk)
{
	if (tdisk->mirror_comm) {
		rep_comm_put(tdisk->mirror_comm, 0);
		tdisk->mirror_comm = NULL;
	}
}

static void
tdisk_mirror_comm_free(struct tdisk *tdisk)
{
	tdisk_mirror_lock(tdisk);
	__tdisk_mirror_comm_free(tdisk);
	tdisk_mirror_unlock(tdisk);
}

int
tdisk_mirror_peer_failure(struct tdisk *tdisk, int manual)
{
	int retval, is_master;

	debug_info("start\n");
	tdisk_mirror_lock(tdisk);
	is_master = tdisk_mirror_master(tdisk);

	debug_info("is master %d need resync %d in resync %d\n", is_master, tdisk_mirroring_need_resync(tdisk), tdisk_mirroring_in_resync(tdisk));
	if (!is_master && (tdisk_mirroring_need_resync(tdisk) || tdisk_mirroring_in_resync(tdisk))) {
		atomic_set_bit(MIRROR_FLAGS_DISABLED, &tdisk->mirror_state.mirror_flags);
		__tdisk_mirror_comm_free(tdisk);
		tdisk_mirror_unlock(tdisk);
		return -1;
	}
 
	debug_info("is_master %d\n", is_master);
	if (atomic_test_bit(MIRROR_FLAGS_DISABLED, &tdisk->mirror_state.mirror_flags)) {
		debug_info("mirror flags already disabled\n");
		if (is_master)
			tdisk_flag_write_after(tdisk);
		__tdisk_mirror_comm_free(tdisk);
		tdisk_mirror_unlock(tdisk);
		retval = is_master ? 0 : -1;
		debug_info("retval %d\n", retval);
		return retval;
	}

	if (tdisk->mirror_comm && atomic_test_bit(NODE_COMM_FENCED, &tdisk->mirror_comm->flags)) {
		debug_info("skipping checks as mirror already fenced\n");
		is_master = 1;
		goto skip_check;
	}
	
	retval = node_usr_send_mirror_check(tdisk->mirror_state.mirror_ipaddr);
	debug_info("mirror check retval %d\n", retval);
	if (retval == USR_RSP_OK || (retval == USR_RSP_FENCE_SUCCESSFUL) || (retval == USR_RSP_FENCE_MANUAL && (manual || is_master))) {
		debug_info("switching over from peer to master\n");
		if (!is_master)
			debug_warn_notify("VDisk %s switching over to master role\n", tdisk_name(tdisk));
		else if (is_master && !manual && retval == USR_RSP_FENCE_MANUAL)
			debug_warn_notify("Manual fencing and VDisk %s in master role. Continuing writes\n", tdisk_name(tdisk));
		else
			debug_warn_notify("VDisk %s peer has failed\n", tdisk_name(tdisk));
		tdisk_set_mirror_role(tdisk, MIRROR_ROLE_MASTER);
		is_master = 1;
		if (tdisk->mirror_comm && (retval == USR_RSP_FENCE_SUCCESSFUL)) {
			debug_info("Marking comm as fenced\n");
			atomic_set_bit(NODE_COMM_FENCED, &tdisk->mirror_comm->flags);
		}
	}
	else {
		debug_warn("Fencing node failed\n");
		debug_warn_notify("Fencing VDisk %s peer failed. Cannot take over as master\n", tdisk_name(tdisk));
		is_master = 0;
		tdisk_set_mirror_role(tdisk, MIRROR_ROLE_PEER);
	}

skip_check:
	debug_info("disabling mirroring\n");
	atomic_set_bit(MIRROR_FLAGS_DISABLED, &tdisk->mirror_state.mirror_flags);
	atomic_clear_bit(MIRROR_FLAGS_PEER_LOAD_DONE, &tdisk->mirror_state.mirror_flags);
	if (is_master) {
		tdisk_set_next_role(tdisk, MIRROR_ROLE_MASTER);
		tdisk_flag_write_after(tdisk);
	}
	__tdisk_mirror_comm_free(tdisk);
	tdisk_mirror_unlock(tdisk);
	retval = is_master ? 0 : -1;
	debug_info("retval %d\n", retval);
	return retval;
}

static void
tdisk_mirroring_disable(struct tdisk *tdisk)
{
	tdisk_mirror_lock(tdisk);
	if (atomic_test_bit(MIRROR_FLAGS_DISABLED, &tdisk->mirror_state.mirror_flags)) {
		tdisk_mirror_unlock(tdisk);
		return;
	}

	__tdisk_mirror_comm_free(tdisk);
	atomic_set_bit(MIRROR_FLAGS_DISABLED, &tdisk->mirror_state.mirror_flags);
	tdisk_mirror_unlock(tdisk);
}

static struct node_comm *
tdisk_mirror_comm_get(struct tdisk *tdisk, int write_cmd, struct node_sock **ret_sock)
{
	struct node_comm *comm;
	struct node_sock *sock;
	int is_master;
	int tries = 0;

	tdisk_mirror_lock(tdisk);
	comm = tdisk->mirror_comm;
	if (!comm) {
		tdisk_mirror_unlock(tdisk);
		return NULL;
	}

	if (!atomic_test_bit(NODE_COMM_FENCED, &comm->flags)) {
		node_comm_get(comm);
		tdisk_mirror_unlock(tdisk);
retry:
		sock = node_comm_get_sock(comm, recv_config.mirror_connect_timeout);
		if (sock) {
			*ret_sock = sock;
			return comm;
		}
		if (tries) {
			debug_warn("Cannot get a new sock\n");
			rep_comm_put(comm, 0);
			return NULL;
		}
		tries = 1;
		sx_xlock(rep_comm_lock);
		node_comm_lock(comm);
		debug_info("Out of free socks, reconnecting\n");
		rep_client_sock_init(comm, 32);
		node_comm_unlock(comm);
		sx_xunlock(rep_comm_lock);
		goto retry;
	}

	is_master = tdisk_mirror_master(tdisk);
	debug_info("Comm fenced need resync %d is master %d\n", is_master, tdisk_mirroring_need_resync(tdisk));
	if (!is_master && tdisk_mirroring_need_resync(tdisk)) {
		atomic_set_bit(MIRROR_FLAGS_DISABLED, &tdisk->mirror_state.mirror_flags);
		__tdisk_mirror_comm_free(tdisk);
		tdisk_mirror_unlock(tdisk);
		return NULL;
	}

	__tdisk_mirror_comm_free(tdisk);
	debug_info("switching %s to master, write cmd %d\n", tdisk_name(tdisk), write_cmd);
	tdisk_set_mirror_role(tdisk, MIRROR_ROLE_MASTER);
	tdisk_set_next_role(tdisk, MIRROR_ROLE_MASTER);
	atomic_set_bit(MIRROR_FLAGS_DISABLED, &tdisk->mirror_state.mirror_flags);
	atomic_clear_bit(MIRROR_FLAGS_PEER_LOAD_DONE, &tdisk->mirror_state.mirror_flags);
	if (write_cmd)
		tdisk_flag_write_after(tdisk);
	tdisk_mirror_unlock(tdisk);
	return NULL;
}

static void
tdisk_mirror_connect(struct tdisk *tdisk)
{
	tdisk_mirror_lock(tdisk);
	if (tdisk->mirror_comm) {
		tdisk_mirror_unlock(tdisk);
		return;
	}

	tdisk->mirror_comm = rep_comm_get(tdisk->mirror_state.mirror_ipaddr, tdisk->mirror_state.mirror_src_ipaddr, 0);
	if (tdisk->mirror_comm)
		tdisk_mirroring_enable(tdisk);
	else
		tdisk_mirroring_disable(tdisk);
	tdisk_mirror_unlock(tdisk);
}

static void
tdisk_mirror_reconnect(struct tdisk *tdisk)
{
	__tdisk_mirror_comm_free(tdisk);
	tdisk->mirror_comm = rep_comm_get(tdisk->mirror_state.mirror_ipaddr, tdisk->mirror_state.mirror_src_ipaddr, 0);
	if (tdisk->mirror_comm)
		tdisk_mirroring_enable(tdisk);
	else
		tdisk_mirroring_disable(tdisk);
}

static int
node_resp_status(struct node_msg *msg, struct node_sock *sock, struct qsio_scsiio *ctio, void *ret, int ret_len)
{
	struct node_msg *resp;
	struct raw_node_msg *raw;
	struct scsi_sense_spec *sense_spec;
	int need_sense, error_code;
	int sense_key = 0, asc = 0, ascq = 0;
	uint32_t info = 0;


	resp = msg->resp;

	if (unlikely(!resp)) {
		return -1;
	}

	raw = resp->raw;
	if (raw->msg_status == NODE_STATUS_OK) {
		if (ret_len && raw->dxfer_len != ret_len) {
			debug_warn("For cmd %d expected %d got %d\n", msg->raw->msg_cmd, ret_len, raw->dxfer_len);
			return -1;
		}

		if (ret_len)
			memcpy(ret, raw->data, ret_len);

		return 0;
	}

	if (!ctio)
		return raw->msg_status;

	need_sense = 0;
	error_code = SSD_CURRENT_ERROR;
	switch (raw->msg_status) {
	case NODE_STATUS_BUSY:
		ctio->scsi_status = SCSI_STATUS_BUSY;
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
		debug_info("cmd sense sense key %x asc %x ascq %x error_code %x info %u\n", sense_key, asc, ascq, error_code, info);
		break;
	}

	if (need_sense) {
		if (sense_key == SSD_KEY_HARDWARE_ERROR)
			node_sock_read_error(sock);
		ctio_construct_sense(ctio, error_code, sense_key, info, asc, ascq);
	}
	debug_info("msg status %x\n", raw->msg_status);
	return raw->msg_status;
}

static inline int
node_mirror_send_page(struct tdisk *tdisk, struct node_msg *msg, pagestruct_t *page, int len, int timeout, int noresp, void *ret, int ret_len)
{
	struct raw_node_msg *raw = msg->raw;
	struct node_comm *comm;
	struct node_sock *sock;
	int retval;

	msg->raw->target_id = tdisk->mirror_state.mirror_target_id;

	comm = tdisk_mirror_comm_get(tdisk, 0, &sock);
	if (unlikely(!comm))
		return -1;

	node_msg_compute_csum(msg->raw);

	if (!noresp)
		node_cmd_hash_insert(comm->node_hash, msg, raw->msg_id);

	retval = node_sock_write(sock, raw);
	if (unlikely(retval != 0)) {
		if (!noresp)
			node_cmd_hash_remove(comm->node_hash, msg, raw->msg_id);

		node_sock_finish(sock);
		debug_warn("Communicating with remote failed cmd %d\n", raw->msg_cmd);
		rep_comm_put(comm, 0);
		return -1;
	}

	if (len) {
		retval = node_sock_write_page(sock, page, len);
		if (unlikely(retval != 0)) {
			if (!noresp)
				node_cmd_hash_remove(comm->node_hash, msg, raw->msg_id);
			node_sock_finish(sock);
			debug_warn("Communicating with remote failed cmd %d\n", raw->msg_cmd);
			rep_comm_put(comm, 0);
			return -1;
		}
	}

	if (noresp) {
		node_sock_finish(sock);
		rep_comm_put(comm, 0);
		return 0;
	}

	node_msg_wait(msg, sock, timeout);

	retval = node_resp_status(msg, sock, NULL, ret, ret_len);
	node_sock_finish(sock);
	rep_comm_put(comm, 0);
	if (unlikely(retval != 0)) {
		debug_warn("Failed to get a response from remote cmd %d retval %d msg timestamp %llu current %llu sock flags %d state %d\n", raw->msg_cmd, retval, (unsigned long long)msg->timestamp, (unsigned long long)ticks, sock->flags, sock->state);
	}

	return retval;
}

int
tdisk_lba_needs_mirror_sync(struct tdisk *tdisk, uint64_t lba)
{
	uint32_t amap_id;

	if (!tdisk_mirroring_need_resync(tdisk))
		return 1;

	if (!tdisk_in_mirroring(tdisk))
		return 0;

	lba = tdisk_get_lba_real(tdisk, lba);

	amap_id = amap_get_id(lba);
	if (tdisk_get_clone_amap_id(tdisk) < amap_id)
		return 0;
	else
		return 1;
}

static int
node_mirror_wait_for_prev_resp(struct tdisk *tdisk, struct qsio_scsiio *ctio, struct write_list *wlist)
{
	struct node_msg *msg;
	struct node_comm *comm;
	struct node_sock *sock;
	unsigned long elapsed;
	unsigned long timeout;
	int retval;

	msg = wlist->msg;
	if (!msg->async_wait)
		return 0;

	msg->async_wait = 0;

	sock = msg->sock;
	comm = sock->comm;

	elapsed = ticks_to_msecs(get_elapsed(msg->timestamp));
	timeout = (mirror_sync_send_timeout - elapsed);
	debug_info("ticks %llu timestamp %llu elapsed %lu timeout %lu\n", (unsigned long long)ticks, (unsigned long long)msg->timestamp, elapsed, timeout);
	node_msg_wait(msg, sock, timeout);
	retval = node_resp_status(msg, sock, ctio, NULL, 0);

	if (unlikely(retval < 0))
		goto write_error;
	else if (retval > 0) {
		retval = -1;
		goto cleanup;
	}

	node_msg_copy_resp(msg);
	return retval;

write_error:
	debug_warn("Command failed for msg cmd %x msg id %llx excg id %llx\n", msg->raw->msg_cmd, (unsigned long long)msg->raw->msg_id, (unsigned long long)msg->raw->xchg_id);
	retval = tdisk_mirror_peer_failure(tdisk, 0);
cleanup:
	node_sock_finish(sock);
	rep_comm_put(comm, 0);
	node_msg_free(msg);
	tdisk_mirror_decr(tdisk);
	wlist->msg = NULL;
	return retval;
}

static int
tdisk_mirror_send_cmd(struct tdisk *tdisk, struct qsio_scsiio *ctio, struct node_msg *msg, struct write_list *wlist, int cmd, int check_peer)
{
	struct node_sock *sock;
	struct node_comm *comm;
	int retval;

	sock = msg->sock;
	comm = sock->comm;

	msg->raw->msg_cmd = cmd;
	node_msg_init(msg);
	msg->raw->dxfer_len = 0;

	retval = node_send_msg(sock, msg, msg->raw->msg_id, 1);
	if (unlikely(retval < 0))  {
		debug_warn("failed to notify remote peer\n");
		goto write_error;
	}

	node_msg_wait(msg, sock, mirror_sync_send_timeout);
	retval = node_resp_status(msg, sock, ctio, NULL, 0);
	if (retval < 0) {
		debug_info("cannot get response\n");
		goto write_error;
	}
	node_resp_free(msg);

	return 0;

write_error:
	if (!check_peer)
		return -1;

	retval = tdisk_mirror_peer_failure(tdisk, 0);
	if (sock)
		node_sock_finish(sock);
	if (comm)
		rep_comm_put(comm, 0);
	node_msg_free(msg);
	if (wlist) {
		tdisk_mirror_decr(tdisk);
		wlist->msg = NULL;
	}

	if (!retval) {
		debug_warn("peer takeover, retrying command\n");
		return 0;
	}
	ctio_free_data(ctio);
	if (!ctio->scsi_status) {
		debug_warn("Failed to receive ctio response, sending hardware error\n");
		ctio_construct_sense(ctio, SSD_CURRENT_ERROR, SSD_KEY_HARDWARE_ERROR, 0, INTERNAL_TARGET_FAILURE_ASC, INTERNAL_TARGET_FAILURE_ASCQ);
	}
	return 1;

}

static int
tdisk_mirror_skip_local_write(struct tdisk *tdisk, struct qsio_scsiio *ctio, struct write_list *wlist)
{
	int status = 1, retval;
	struct node_msg *msg = wlist->msg;
	struct node_sock *sock = msg->sock;
	struct node_comm *comm = sock->comm;
#ifdef ENABLE_STATS
	uint32_t start_ticks;
#endif

	if (node_cmd_status(msg) == NODE_CMD_NEED_VERIFY) {
		TDISK_TSTART(start_ticks);
		retval = node_verify_setup(comm, sock, msg, ctio, mirror_sync_send_timeout, 0);
		TDISK_TEND(tdisk, mirror_verify_setup_ticks, start_ticks);
		if (unlikely(retval != 0)) {
			status = -1;
			debug_warn("node verify setup failed\n");
			tdisk_mirroring_disable(tdisk);
			goto out;
		}
	}

	if (node_cmd_status(msg) == NODE_CMD_NEED_COMP) {
		TDISK_TSTART(start_ticks);
		retval = node_comp_setup(comm, sock, msg, ctio, mirror_sync_send_timeout, 0);
		TDISK_TEND(tdisk, mirror_comp_setup_ticks, start_ticks);
		if (unlikely(retval != 0)) {
			status = -1;
			debug_warn("node comp setup failed\n");
			tdisk_mirroring_disable(tdisk);
			goto out;
		}
	}

	if (node_cmd_status(msg) == NODE_CMD_NEED_IO_UNALIGNED) {
		retval = tdisk_mirror_send_cmd(tdisk, ctio, msg, NULL, NODE_MSG_WRITE_DATA_UNALIGNED, 0);
		if (unlikely(retval != 0)) {
			status = -1;
			debug_warn("node send write io failed\n");
			tdisk_mirroring_disable(tdisk);
			goto out;
		}
	}
	if (node_cmd_status(msg) == NODE_CMD_NEED_IO) {
		TDISK_TSTART(start_ticks);
		retval = node_send_write_io(ctio, comm, sock, msg, (struct pgdata **)ctio->data_ptr, ctio->pglist_cnt, mirror_sync_send_timeout, 0);
		TDISK_TEND(tdisk, mirror_write_io_ticks, start_ticks);
		if (unlikely(retval != 0)) {
			status = -1;
			debug_warn("node send write io failed\n");
			tdisk_mirroring_disable(tdisk);
			goto out;
		}
	}

	node_cmd_write_done(ctio, comm, sock, msg, mirror_sync_send_timeout);
out:
	node_sock_finish(sock);
	rep_comm_put(comm, 0);
	node_msg_free(msg);
	tdisk_mirror_decr(tdisk);
	wlist->msg = NULL;
	return status;
}

static int
__tdisk_mirror_write_done(struct tdisk *tdisk, struct qsio_scsiio *ctio, struct write_list *wlist)
{
	struct node_msg *msg;
	struct node_sock *sock;
	struct node_comm *comm;

	msg = wlist->msg; 
	if (!msg)
		return 0;

	sock = msg->sock;
	comm = sock->comm;

	TDISK_INC(tdisk, mirror_write_done_bytes, (msg->raw->dxfer_len + sizeof(struct raw_node_msg)));
	node_cmd_write_done(ctio, comm, sock, msg, mirror_sync_send_timeout);

	node_sock_finish(sock);
	rep_comm_put(comm, 0);
	node_msg_free(msg);
	tdisk_mirror_decr(tdisk);
	wlist->msg = NULL;
	return 0;
}

int
tdisk_mirror_write_post_pre(struct tdisk *tdisk, struct qsio_scsiio *ctio, struct write_list *wlist)
{
	int retval;

	if (!wlist->msg)
		return 0;

	if (tdisk_mirror_master(tdisk))
		return 0;

	retval = node_mirror_wait_for_prev_resp(tdisk, ctio, wlist);
	if (unlikely(retval != 0 || !wlist->msg))
		return retval;

	TDISK_INC(tdisk, mirror_write_post_pre_bytes, (wlist->msg->raw->dxfer_len + sizeof(struct raw_node_msg)));
	return tdisk_mirror_send_cmd(tdisk, ctio, wlist->msg, wlist, NODE_MSG_WRITE_POST_PRE, 1);
}

int
tdisk_mirror_write_done_pre(struct tdisk *tdisk, struct qsio_scsiio *ctio, struct write_list *wlist)
{
	int retval;

	if (!wlist->msg)
		return 0;

	if (tdisk_mirror_master(tdisk)) {
#if 0
		return tdisk_mirror_write_post_pre(tdisk, ctio, wlist);
#endif
		return 0;
	}

	retval = node_mirror_wait_for_prev_resp(tdisk, ctio, wlist);
	if (unlikely(retval != 0 || !wlist->msg))
		return retval;

	return __tdisk_mirror_write_done(tdisk, ctio, wlist);
}

int
tdisk_mirror_write_done_post(struct tdisk *tdisk, struct write_list *wlist)
{
	int retval;

	if (!wlist->msg)
		return 0;

	if (!tdisk_mirror_master(tdisk))
		return 0;

	retval = node_mirror_wait_for_prev_resp(tdisk, NULL, wlist);
	if (unlikely(retval != 0 || !wlist->msg))
		return retval;

	return __tdisk_mirror_write_done(tdisk, NULL, wlist);
}


int
tdisk_mirror_write_error(struct tdisk *tdisk, struct qsio_scsiio *ctio, struct write_list *wlist)
{
	struct node_msg *msg;
	struct node_sock *sock;
	struct node_comm *comm;
	int retval;

	msg = wlist->msg; 
	if (!msg)
		return 0;

	retval = node_mirror_wait_for_prev_resp(tdisk, ctio, wlist);
	if (unlikely(retval != 0 || !wlist->msg))
		return retval;
 
	sock = msg->sock;
	comm = sock->comm;

	msg->raw->msg_cmd = NODE_MSG_MIRROR_WRITE_ERROR;
	node_msg_init(msg);
	msg->raw->dxfer_len = 0;

	retval = node_send_msg(sock, msg, msg->raw->msg_id, 1);
	if (unlikely(retval != 0)) {
		debug_warn("failed to notify remote peer\n");
	}
	else {
		node_msg_wait(msg, sock, mirror_send_timeout);
	}

	node_sock_finish(sock);
	rep_comm_put(comm, 0);
	node_msg_free(msg);
	tdisk_mirror_decr(tdisk);
	wlist->msg = NULL;
	return 0;
}

int
tdisk_mirror_check_io(struct tdisk *tdisk, struct qsio_scsiio *ctio, struct write_list *wlist)
{
	struct node_msg *msg;
	struct node_sock *sock;
	struct node_comm *comm;
#ifdef ENABLE_STATS
	uint32_t start_ticks;
#endif
	int retval;

	msg = wlist->msg;
	if (!msg)
		return 0;

	retval = node_mirror_wait_for_prev_resp(tdisk, ctio, wlist);
	if (unlikely(retval != 0 || !wlist->msg))
		return retval;

	if (node_cmd_status(msg) == NODE_CMD_NEED_IO_UNALIGNED)
		return tdisk_mirror_send_cmd(tdisk, ctio, msg, wlist, NODE_MSG_WRITE_DATA_UNALIGNED, 1);

	if (node_cmd_status(msg) != NODE_CMD_NEED_IO)
		return 0;

	sock = msg->sock;
	comm = sock->comm;

	TDISK_INC(tdisk, mirror_check_io_bytes, (msg->raw->dxfer_len + sizeof(struct raw_node_msg)));
	TDISK_TSTART(start_ticks);
	retval = node_send_write_io(ctio, comm, sock, msg, (struct pgdata **)ctio->data_ptr, ctio->pglist_cnt, mirror_sync_send_timeout, 1);
	TDISK_TEND(tdisk, mirror_write_io_ticks, start_ticks);
	if (retval == 0)
		return 0;

	debug_warn("node io setup failed retval %d\n", retval);
	if (!tdisk_mirror_master(tdisk))
		pause("psg", mirror_sync_send_timeout);
	retval = tdisk_mirror_peer_failure(tdisk, 0);
	node_sock_finish(sock);
	rep_comm_put(comm, 0);
	node_msg_free(msg);
	tdisk_mirror_decr(tdisk);
	wlist->msg = NULL;
	return retval;
}

int
tdisk_mirror_check_verify(struct tdisk *tdisk, struct qsio_scsiio *ctio, struct write_list *wlist)
{
	struct node_msg *msg;
	struct node_sock *sock;
	struct node_comm *comm;
#ifdef ENABLE_STATS
	uint32_t start_ticks;
#endif
	int retval;

	msg = wlist->msg;
	if (!msg)
		return 0;

	retval = node_mirror_wait_for_prev_resp(tdisk, ctio, wlist);
	if (unlikely(retval != 0 || !wlist->msg))
		return retval;

	if (msg->raw->mirror_status == NODE_STATUS_SKIP_LOCAL_WRITE) {
		debug_check(tdisk_mirror_master(tdisk));
		tdisk_write_error(tdisk, ctio, wlist, 1);
		return tdisk_mirror_skip_local_write(tdisk, ctio, wlist);
	}

	if (node_cmd_status(msg) != NODE_CMD_NEED_VERIFY)
		return 0;

	sock = msg->sock;
	comm = sock->comm;

	TDISK_TSTART(start_ticks);
	retval = node_verify_setup(comm, sock, msg, ctio, mirror_sync_send_timeout, 1);
	TDISK_TEND(tdisk, mirror_verify_setup_ticks, start_ticks);
	if (retval == 0)
		return 0;

	debug_warn("node verify setup failed\n");
	if (!tdisk_mirror_master(tdisk))
		pause("psg", mirror_sync_send_timeout);
	retval = tdisk_mirror_peer_failure(tdisk, 0);
	node_sock_finish(sock);
	rep_comm_put(comm, 0);
	node_msg_free(msg);
	tdisk_mirror_decr(tdisk);
	wlist->msg = NULL;
	return retval;
}

int
tdisk_mirror_check_comp(struct tdisk *tdisk, struct qsio_scsiio *ctio, struct write_list *wlist)
{
	struct raw_node_msg *raw;
	struct node_msg *msg;
	struct node_sock *sock;
	struct node_comm *comm;
	int retval, i;
	struct pgdata_read_spec *source_spec;
	struct pgdata **pglist, *pgdata;

	msg = wlist->msg; 
	if (!msg)
		return 0;

	retval = node_mirror_wait_for_prev_resp(tdisk, ctio, wlist);
	if (unlikely(retval != 0 || !wlist->msg))
		return retval;

	if (node_cmd_status(msg) != NODE_CMD_NEED_COMP)
		return 0;

	sock = msg->sock;
	comm = sock->comm;

	raw = msg->raw;
	source_spec = pgdata_read_spec_ptr(raw);
	pglist = (struct pgdata **)(ctio->data_ptr);

	for (i = 0; i < ctio->pglist_cnt; i++, source_spec++) {
		pgdata = pglist[i];

		if (atomic_test_bit_short(DDBLOCK_ZERO_BLOCK, &source_spec->flags))
			continue;

		if (atomic_test_bit_short(DDBLOCK_ENTRY_FOUND_DUPLICATE, &source_spec->flags))
			continue;

		if (!pgdata->comp_pgdata)
			continue;
		SET_BLOCK_SIZE(source_spec->amap_block, pgdata->comp_pgdata->pg_len);
	}

	raw->msg_cmd = NODE_MSG_WRITE_COMP_DONE;
	node_msg_init(msg);
	retval = node_send_msg(sock, msg, raw->msg_id, 1);
	if (retval == 0) {
		msg->async_wait = 1;
		return 0;
	}

	debug_warn("node comp setup failed\n");
	if (!tdisk_mirror_master(tdisk))
		pause("psg", mirror_sync_send_timeout);
	retval = tdisk_mirror_peer_failure(tdisk, 0);
	node_sock_finish(sock);
	rep_comm_put(comm, 0);
	node_msg_free(msg);
	tdisk_mirror_decr(tdisk);
	wlist->msg = NULL;
	return retval;
}

int
tdisk_mirror_extended_copy_read(struct tdisk *tdisk, struct qsio_scsiio *ctio, struct tdisk *dest_tdisk, uint64_t lba, uint64_t dest_lba, uint32_t num_blocks, uint32_t *xchg_id)
{
	struct node_msg *msg, *resp;
	struct raw_node_msg *raw;
	int retval;
	struct xcopy_read_spec *xcopy_spec;
	struct node_comm *comm = NULL;
	struct node_sock *sock = NULL;

	debug_info("lba %llu dest lba %llu num blocks %u\n", (unsigned long long)lba, (unsigned long long)dest_lba, num_blocks);
	msg = node_msg_alloc(sizeof(*xcopy_spec));
	msg->mirror = 1;

	comm = tdisk_mirror_comm_get(tdisk, 0, &sock);
	if (unlikely(!comm)) {
		debug_warn("Cannot get a node comm for tdisk %s\n", tdisk_name(tdisk));
		goto write_error;
	}

	raw = msg->raw;
	bzero(raw, sizeof(*raw));
	raw->msg_cmd = NODE_MSG_XCOPY_READ;
	raw->target_id = tdisk->mirror_state.mirror_target_id;
	raw->dxfer_len = sizeof(*xcopy_spec);
	raw->msg_id = node_transaction_id();

	xcopy_spec = (struct xcopy_read_spec *)(raw->data);
	xcopy_spec->lba = lba;
	xcopy_spec->dest_lba = dest_lba;
	xcopy_spec->num_blocks = num_blocks;
	xcopy_spec->dest_target_id = dest_tdisk->mirror_state.mirror_target_id;
	port_fill(xcopy_spec->i_prt, ctio->i_prt);
	port_fill(xcopy_spec->t_prt, ctio->t_prt);
	xcopy_spec->r_prt = ctio->r_prt;
	xcopy_spec->task_tag = ctio->task_tag;
	xcopy_spec->task_attr = ctio->task_attr;

	retval = node_send_msg(sock, msg, raw->msg_id, 1);
	if (unlikely(retval != 0)) {
		debug_info("sock write failure\n");
		goto write_error;
	}

	node_msg_wait(msg, sock, mirror_send_timeout);
	retval = node_resp_status(msg, sock, NULL, NULL, 0);
	if (retval < 0) {
		debug_info("cannot get response\n");
		goto write_error;
	}
	else if (retval == 0) {
		resp = msg->resp;
		debug_check(!resp);
		raw = resp->raw;
		*xchg_id = raw->xchg_id;
		debug_info("Got xchg id %x\n", raw->xchg_id);
	}

	node_sock_finish(sock);
	rep_comm_put(comm, 0);

	node_msg_free(msg);
	return retval;
write_error:
	tdisk_mirroring_disable(tdisk);
	if (sock)
		node_sock_finish(sock);
	if (comm)
		rep_comm_put(comm, 0);
	node_msg_free(msg);
	return -1;
}

static int
__tdisk_mirror_cmd_generic(struct tdisk *tdisk, struct qsio_scsiio *ctio, int pcmd)
{
	struct node_msg *msg, *resp;
	struct raw_node_msg *raw;
	int retval, dxfer_len;
	struct scsi_cmd_spec_generic *cmd_spec;
	struct node_comm *comm = NULL;
	struct node_sock *sock = NULL;
	int offset = pcmd ? INITIATOR_NAME_MAX : 0;

	tdisk_mirror_incr(tdisk);
	dxfer_len = sizeof(*cmd_spec) + offset + ctio->dxfer_len;
	msg = node_msg_alloc(dxfer_len);
	msg->mirror = 1;
	sock = NULL;
	ctio->scsi_status = 0;

	comm = tdisk_mirror_comm_get(tdisk, 1, &sock);
	if (unlikely(!comm)) {
		debug_warn("Cannot get a node comm for tdisk %s\n", tdisk_name(tdisk));
		goto write_error;
	}

	raw = msg->raw;
	bzero(raw, sizeof(*raw) + sizeof(*cmd_spec) + offset);
	if (!pcmd)
		raw->msg_cmd = NODE_MSG_GENERIC_CMD;
	else
		raw->msg_cmd = NODE_MSG_PERSISTENT_RESERVE_OUT_CMD;
	raw->target_id = tdisk->mirror_state.mirror_target_id;
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

	retval = node_send_msg(sock, msg, raw->msg_id, 1);
	if (unlikely(retval != 0)) {
		debug_info("sock write failure\n");
		goto write_error;
	}

	node_msg_wait(msg, sock, mirror_send_timeout);
	retval = node_resp_status(msg, sock, ctio, NULL, 0);
	if (retval < 0) {
		debug_info("cannot get response\n");
		goto write_error;
	}

	node_sock_finish(sock);
	rep_comm_put(comm, 0);

	ctio_free_data(ctio);
	resp = msg->resp;
	debug_check(!resp);
	raw = resp->raw;

	if (raw->dxfer_len && ctio->scsi_status == SCSI_STATUS_OK) {
		ctio_allocate_buffer(ctio, raw->dxfer_len, Q_WAITOK);
		memcpy(ctio->data_ptr, raw->data, raw->dxfer_len);
	}
	node_msg_free(msg);
	tdisk_mirror_decr(tdisk);
	if (!pcmd)
		device_send_ccb(ctio);
	return 1;
write_error:
	retval = tdisk_mirror_peer_failure(tdisk, 0);
	tdisk_mirror_decr(tdisk);
	if (sock)
		node_sock_finish(sock);
	if (comm)
		rep_comm_put(comm, 0);
	node_msg_free(msg);
	if (!retval) {
		debug_warn("peer takeover, retrying command\n");
		return 0;
	}
	ctio_free_data(ctio);
	if (!ctio->scsi_status) {
		debug_warn("Failed to receive ctio response, sending hardware error\n");
		ctio_construct_sense(ctio, SSD_CURRENT_ERROR, SSD_KEY_HARDWARE_ERROR, 0, INTERNAL_TARGET_FAILURE_ASC, INTERNAL_TARGET_FAILURE_ASCQ);
	}
	if (!pcmd)
		device_send_ccb(ctio);
	return -1;
}

int
tdisk_mirror_cmd_generic(struct tdisk *tdisk, struct qsio_scsiio *ctio, int pcmd)
{
	if (!tdisk_mirroring_configured(tdisk) || tdisk_mirror_master(tdisk) || ctio_in_sync(ctio))
		return 0;

	if (tdisk_mirroring_disabled(tdisk)) {
		ctio_free_data(ctio);
		if (!pcmd)
			ctio_construct_sense(ctio, SSD_CURRENT_ERROR, SSD_KEY_DATA_PROTECT, 0, NO_ASC, NO_ASCQ);
		else
			ctio->scsi_status = SCSI_STATUS_RESERV_CONFLICT;
		device_send_ccb(ctio);
		debug_warn("mirroring disabled, sending data protect\n");
		return -1;
	}
	return __tdisk_mirror_cmd_generic(tdisk, ctio, pcmd);
}

int
tdisk_mirror_cmd_generic_nocheck(struct tdisk *tdisk, struct qsio_scsiio *ctio, int pcmd)
{
	if (!tdisk_mirroring_configured(tdisk) || !tdisk_mirror_master(tdisk))
		return 0;

	if (tdisk_mirroring_disabled(tdisk) && !tdisk_mirror_master(tdisk)) {
		ctio_free_data(ctio);
		if (!pcmd)
			ctio_construct_sense(ctio, SSD_CURRENT_ERROR, SSD_KEY_DATA_PROTECT, 0, NO_ASC, NO_ASCQ);
		else
			ctio->scsi_status = SCSI_STATUS_RESERV_CONFLICT;
		device_send_ccb(ctio);
		debug_warn("mirroring disabled, sending data protect\n");
		return -1;
	}

	return __tdisk_mirror_cmd_generic(tdisk, ctio, pcmd);
}

int
tdisk_mirror_cmd_generic2(struct tdisk *tdisk, struct qsio_scsiio *ctio)
{
	struct node_msg *msg, *resp;
	struct raw_node_msg *raw;
	struct scsi_cmd_spec_generic *cmd_spec;
	struct pgdata **pglist, *pgdata;
	struct node_comm *comm = NULL;
	struct node_sock *sock = NULL;
	int retval, dxfer_len, i;
	uint16_t csum;

	if (!tdisk_mirroring_configured(tdisk) || tdisk_mirror_master(tdisk) || ctio_in_sync(ctio))
		return 0;

	if (tdisk_mirroring_disabled(tdisk)) {
		ctio_free_data(ctio);
		ctio_construct_sense(ctio, SSD_CURRENT_ERROR, SSD_KEY_DATA_PROTECT, 0, NO_ASC, NO_ASCQ);
		device_send_ccb(ctio);
		debug_warn("mirroring disabled, sending data protect\n");
		return -1;
	}

	tdisk_mirror_incr(tdisk);
	dxfer_len = sizeof(*cmd_spec);

	msg = node_msg_alloc(dxfer_len);
	msg->mirror = 1;
	sock = NULL;
	ctio->scsi_status = 0;

	comm = tdisk_mirror_comm_get(tdisk, 1, &sock);
	if (unlikely(!comm)) {
		debug_warn("Cannot get a node comm for tdisk %s\n", tdisk_name(tdisk));
		goto write_error;
	}

	raw = msg->raw;
	bzero(raw, dxfer_len + sizeof(*raw));
	raw->msg_cmd = NODE_MSG_GENERIC_CMD;
	raw->target_id = tdisk->mirror_state.mirror_target_id;
	raw->dxfer_len = dxfer_len;
	raw->msg_id = node_transaction_id();
	raw->pg_count = ctio->pglist_cnt;

	cmd_spec = scsi_cmd_spec_generic_ptr(raw);
	scsi_cmd_spec_generic_fill(cmd_spec, ctio);
	cmd_spec->transfer_length = ctio->dxfer_len;

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
	retval = node_sock_write(sock, raw);
	if (unlikely(retval != 0)) {
		node_cmd_hash_remove(comm->node_hash, msg, raw->msg_id);
		goto write_error;
	}

	for (i = 0; i < ctio->pglist_cnt; i++) {
		pgdata = pglist[i];
		retval = node_sock_write_page(sock, pgdata->page, pgdata->pg_len);
		if (unlikely(retval != 0)) {
			node_cmd_hash_remove(comm->node_hash, msg, raw->msg_id);
			goto write_error;
		}
	}

	node_msg_wait(msg, sock, mirror_send_timeout);
	retval = node_resp_status(msg, sock, ctio, NULL, 0);
	if (unlikely(retval < 0))
		goto write_error;

	node_sock_finish(sock);
	rep_comm_put(comm, 0);
	ctio_free_data(ctio);
	resp = msg->resp;
	debug_check(!resp);
	raw = resp->raw;

	if (raw->dxfer_len && ctio->scsi_status == SCSI_STATUS_OK) {
		ctio_allocate_buffer(ctio, raw->dxfer_len, Q_WAITOK);
		memcpy(ctio->data_ptr, raw->data, raw->dxfer_len);
	}
	tdisk_mirror_decr(tdisk);
	node_msg_free(msg);
	device_send_ccb(ctio);
	return 1;
write_error:
	retval = tdisk_mirror_peer_failure(tdisk, 0);
	tdisk_mirror_decr(tdisk);
	if (sock)
		node_sock_finish(sock);
	if (comm)
		rep_comm_put(comm, 0);
	node_msg_free(msg);
	if (!retval) {
		debug_warn("peer takeover, retrying command\n");
		return 0;
	}
	ctio_free_data(ctio);
	if (!ctio->scsi_status) {
		debug_warn("Failed to receive ctio response, sending hardware error\n");
		ctio_construct_sense(ctio, SSD_CURRENT_ERROR, SSD_KEY_HARDWARE_ERROR, 0, INTERNAL_TARGET_FAILURE_ASC, INTERNAL_TARGET_FAILURE_ASCQ);
	}
	device_send_ccb(ctio);
	return 1;
}
 
int
__tdisk_mirror_read(struct tdisk *tdisk, struct qsio_scsiio *ctio, struct pgdata ***ret_pglist, int *ret_pglist_cnt, uint64_t lba, uint32_t transfer_length)
{
	struct node_msg *msg;
	struct raw_node_msg *raw;
	int retval, dxfer_len;
	struct pgdata **pglist;
	int pglist_cnt;
	struct node_comm *comm = NULL;
	struct node_sock *sock = NULL;
	uint32_t orig_transfer_length = transfer_length;
#ifdef ENABLE_STATS
	uint32_t start_ticks, tmp_ticks;
#endif

	if (!tdisk_mirroring_configured(tdisk) || tdisk_mirror_master(tdisk) || ctio_in_sync(ctio))
		return 0;

	if (!tdisk_mirroring_need_resync(tdisk))
		return 0;

	if (*ret_pglist) {
		pglist_free_norefs(*ret_pglist, *ret_pglist_cnt);
		ctio->dxfer_len = 0;
		ctio->pglist_cnt = 0;
		ctio->data_ptr = NULL;
		ctio_clear_norefs(ctio);
		*ret_pglist = NULL;
		*ret_pglist_cnt = 0;
	}

	TDISK_TSTART(tmp_ticks);
	transfer_length += tdisk_get_lba_diff(tdisk, lba);
	dxfer_len = sizeof(struct scsi_cmd_spec);
	msg = node_msg_alloc(dxfer_len);
	msg->mirror = 1;

	pglist_cnt = transfer_length_to_pglist_cnt(tdisk->lba_shift, transfer_length);
	pglist = pgdata_allocate_nopage(pglist_cnt, Q_NOWAIT); 
	if (unlikely(!pglist)) {
		debug_warn("pgdata allocate failed for %d\n", pglist_cnt);
		goto err;
	}

	sock = NULL;
	ctio->scsi_status = 0;
	comm = tdisk_mirror_comm_get(tdisk, 0, &sock);
	if (unlikely(!comm)) {
		debug_warn("failed to get comm\n");
		goto err;
	}

	raw = msg->raw;
	bzero(raw, dxfer_len + sizeof(*raw));
	raw->target_id = tdisk->mirror_state.mirror_target_id;
	raw->dxfer_len = dxfer_len;
	raw->msg_id = node_transaction_id();

	TDISK_TSTART(start_ticks);
	retval = node_read_setup(tdisk, comm, sock, ctio, msg, lba, pglist, pglist_cnt, orig_transfer_length, mirror_sync_send_timeout);
	TDISK_TEND(tdisk, read_setup_ticks, start_ticks);

	if (unlikely(retval != 0)) {
		debug_warn("node read setup failed\n");
		goto err;
	}

	if (node_cmd_status(msg) == NODE_CMD_NEED_IO) {
		TDISK_TSTART(start_ticks);
		retval = node_cmd_read_io(tdisk, ctio, comm, sock, msg, pglist, pglist_cnt, 1, mirror_sync_send_timeout);
		TDISK_TEND(tdisk, read_io_ticks, start_ticks);
		if (unlikely(retval != 0)) {
			debug_warn("node read io failed\n");
			goto err;
		}
	}

	TDISK_TEND(tdisk, node_cmd_read_ticks, tmp_ticks);
	node_sock_finish(sock);
	rep_comm_put(comm, 0);
	node_msg_free(msg);
	*ret_pglist = pglist;
	*ret_pglist_cnt = pglist_cnt;
	return 1;
err:
	debug_warn("mirror master failed and data yet to be resynced, sending hardware error\n");
	ctio_construct_sense(ctio, SSD_CURRENT_ERROR, SSD_KEY_HARDWARE_ERROR, 0, INTERNAL_TARGET_FAILURE_ASC, INTERNAL_TARGET_FAILURE_ASCQ);
	if (sock)
		node_sock_finish(sock);
	if (comm)
		rep_comm_put(comm, 0);
	pglist_free(pglist, pglist_cnt);
	node_msg_free(msg);
	return -1;
}

static inline struct pgdata **
pgdata_allocate_for_cw(struct tdisk *tdisk, struct qsio_scsiio *ctio, uint32_t transfer_length, int *ret_pglist_cnt)
{
	struct pgdata **dest_pglist, *pgdest, *pgsrc, **pglist;
	int dest_pglist_cnt;
	uint32_t size, src_offset, dest_offset;
	int i, dest_idx, min_len, todo;

	size = transfer_length << tdisk->lba_shift; 
	dest_pglist_cnt = transfer_length_to_pglist_cnt(tdisk->lba_shift, transfer_length);
	dest_pglist = pgdata_allocate(dest_pglist_cnt, Q_NOWAIT);
	if (unlikely(!dest_pglist)) {
		debug_warn("Memory allocation failure\n");
		return NULL;
	}

	dest_idx = 0;
	dest_offset = 0;
	ctio_idx_offset(size, &i, &src_offset);
	pglist = (struct pgdata **)ctio->data_ptr;
	todo = size;

	while (i < ctio->pglist_cnt) {
		pgdest = dest_pglist[dest_idx];
		wait_complete_all(pgdest->completion);
		atomic_set_bit(DDBLOCK_DEDUPE_DISABLED, &pgdest->flags);

		pgsrc = pglist[i];
		wait_for_done(pgsrc->completion);
		min_len = min_t(int, pgdest->pg_len - dest_offset, pgsrc->pg_len - src_offset);
		if (min_len > todo)
			min_len = todo;
		memcpy(((uint8_t *)pgdata_page_address(pgdest)) + dest_offset, (((uint8_t *)pgdata_page_address(pgsrc)) + src_offset), min_len);
		todo -= min_len;
		if (!todo)
			break;
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
	}
	*ret_pglist_cnt = dest_pglist_cnt;
	return dest_pglist;
}

static int
tdisk_mirror_xcopy_write(struct tdisk *tdisk, struct write_list *wlist, int32_t xchg_id)
{
	struct node_sock *sock = NULL;
	struct node_comm *comm = NULL;
	struct node_msg *msg;
	struct raw_node_msg *raw;
	int retval;

	debug_info("xchg id %x\n", xchg_id);
	msg = node_msg_alloc(0);
	msg->mirror = 1;

	comm = tdisk_mirror_comm_get(tdisk, 1, &sock);
	if (unlikely(!comm)) {
		debug_warn("Cannot get a node comm for tdisk %s\n", tdisk_name(tdisk));
		goto write_error;
	}

	raw = msg->raw;
	bzero(raw, sizeof(*raw));
	raw->target_id = tdisk->mirror_state.mirror_target_id;
	raw->msg_id = node_transaction_id();
	raw->xchg_id = xchg_id;
	raw->msg_cmd = NODE_MSG_XCOPY_WRITE;
	raw->dxfer_len = 0;

	retval = node_send_msg(sock, msg, raw->msg_id, 1);
	if (unlikely(retval != 0))
		goto write_error;

	msg->sock = sock;
	msg->async_wait = 1;
	wlist->msg = msg;
	return 0;
write_error:
	debug_check(!tdisk_mirror_master(tdisk));
	tdisk_mirroring_disable(tdisk);
	if (sock)
		node_sock_finish(sock);
	if (comm)
		rep_comm_put(comm, 0);
	node_msg_free(msg);
	return 0;
}

int
tdisk_mirror_write_setup(struct tdisk *tdisk, struct qsio_scsiio *ctio, struct write_list *wlist, uint64_t lba, uint32_t transfer_length, int cw, uint32_t xchg_id)
{
	struct node_sock *sock = NULL;
	struct node_comm *comm = NULL;
	struct node_msg *msg;
	struct raw_node_msg *raw;
	struct mirror_state *mirror_state = &tdisk->mirror_state;
	struct pgdata_spec *source_spec;
	struct scsi_cmd_spec *cmd_spec;
	struct pgdata *pgdata, **pglist;
	int i, dxfer_len, retval, unaligned, pglist_cnt, done;

	if (!tdisk_mirroring_configured(tdisk))
		return 0;

	if (tdisk_mirroring_disabled(tdisk)) {
		if (tdisk_mirror_master(tdisk)) {
			tdisk_mirror_lock(tdisk);
			retval = tdisk_flag_write_after(tdisk);
			tdisk_mirror_unlock(tdisk);
			return retval;
		}
		else {
			debug_warn("mirroring disabled, sending data protect\n");
			ctio_construct_sense(ctio, SSD_CURRENT_ERROR, SSD_KEY_DATA_PROTECT, 0, NO_ASC, NO_ASCQ);
			return -1;
		}
	}

	if (tdisk_mirror_master(tdisk) && !tdisk_lba_needs_mirror_sync(tdisk, lba))
		return 0;

	tdisk_mirror_incr(tdisk);
	if (xchg_id)
		return tdisk_mirror_xcopy_write(tdisk, wlist, xchg_id);

	if (cw) {
		pglist = pgdata_allocate_for_cw(tdisk, ctio, transfer_length, &pglist_cnt);
		if (unlikely(!pglist)) {
			ctio_construct_sense(ctio, SSD_CURRENT_ERROR, SSD_KEY_HARDWARE_ERROR, 0, INTERNAL_TARGET_FAILURE_ASC, INTERNAL_TARGET_FAILURE_ASCQ);
			tdisk_mirror_decr(tdisk);
			return -1;
		}
	}
	else {
		pglist = (struct pgdata **)ctio->data_ptr;
		pglist_cnt = ctio->pglist_cnt;
	}

	unaligned = is_unaligned_write(tdisk, lba, transfer_length);

	dxfer_len = sizeof(struct scsi_cmd_spec) + sizeof(struct pgdata_spec) * pglist_cnt;
	msg = node_msg_alloc(dxfer_len);
	msg->mirror = 1;

	comm = tdisk_mirror_comm_get(tdisk, 1, &sock);
	if (unlikely(!comm)) {
		debug_warn("Cannot get a node comm for tdisk %s\n", tdisk_name(tdisk));
		goto write_error;
	}

	raw = msg->raw;
	bzero(raw, dxfer_len + sizeof(*raw));
	raw->target_id = mirror_state->mirror_target_id;
	raw->msg_id = node_transaction_id();

	cmd_spec = scsi_cmd_spec_ptr(raw);
	scsi_cmd_spec_fill(cmd_spec, ctio);
	cmd_spec->transfer_length = transfer_length;
	cmd_spec->lba = lba;
	cmd_spec->pglist_cnt = pglist_cnt;

	source_spec = pgdata_spec_ptr(raw);
	done = 0;
	for (i = 0; i < pglist_cnt; i++) {
		pgdata = pglist[i];
		wait_for_done(pgdata->completion);
		if (!unaligned && atomic_test_bit(DDBLOCK_ZERO_BLOCK, &pgdata->flags))
			continue;
		memcpy(source_spec->hash, pgdata->hash, sizeof(pgdata->hash));
		source_spec->flags = (pgdata->flags & NODE_CLIENT_WRITE_MASK);
		if (unaligned)
			source_spec->csum = pgdata_csum(pgdata, LBA_SIZE);
		else 
			source_spec->csum = i;
		source_spec++;
		done++;
	}

	if (ctio_in_sync(ctio))
		raw->msg_cmd = NODE_MSG_WRITE_MIRROR_CMD;
	else
		raw->msg_cmd = NODE_MSG_WRITE_CMD;
	TDISK_INC(tdisk, mirror_write_setup_orig_bytes, dxfer_len);
	raw->dxfer_len = sizeof(struct scsi_cmd_spec) + (sizeof(struct pgdata_spec) * done);
	TDISK_INC(tdisk, mirror_write_setup_bytes, (raw->dxfer_len + sizeof(*raw)));
	node_msg_compute_csum(raw);
	node_cmd_hash_insert(comm->node_hash, msg, raw->msg_id);
	retval = node_sock_write(sock, raw);
	if (unlikely(retval != 0)) {
		node_cmd_hash_remove(comm->node_hash, msg, raw->msg_id);
		goto write_error;
	}

	if (unaligned) {
		for (i = 0; i < pglist_cnt; i++) {
			pgdata = pglist[i];
			retval = node_sock_write_page(sock, pgdata->page, pgdata->pg_len);
			if (unlikely(retval != 0)) {
				node_cmd_hash_remove(comm->node_hash, msg, raw->msg_id);
				goto write_error;
			}
		}
	}

	if (cw)
		pglist_free(pglist, pglist_cnt);
	msg->sock = sock;
	msg->async_wait = 1;
	wlist->msg = msg;

	if (tdisk_mirror_master(tdisk))
		return 0;

	retval = node_mirror_wait_for_prev_resp(tdisk, ctio, wlist);
	if (unlikely(retval != 0 || !wlist->msg))
		return retval;

	if (msg->raw->mirror_status == NODE_STATUS_SKIP_LOCAL_WRITE)
		return tdisk_mirror_skip_local_write(tdisk, ctio, wlist);

	return 0;
write_error:
	if (!tdisk_mirror_master(tdisk))
		pause("psg", mirror_sync_send_timeout);
	retval = tdisk_mirror_peer_failure(tdisk, 0);
	tdisk_mirror_decr(tdisk);
	if (sock)
		node_sock_finish(sock);
	if (comm)
		rep_comm_put(comm, 0);
	node_msg_free(msg);
	if (cw)
		pglist_free(pglist, pglist_cnt);

	if (!retval) {
		debug_warn("peer takeover, continuing with write command\n");
		return 0;
	}
	if (!ctio->scsi_status) {
		debug_warn("Failed to receive ctio response, sending hardware error\n");
		ctio_construct_sense(ctio, SSD_CURRENT_ERROR, SSD_KEY_HARDWARE_ERROR, 0, INTERNAL_TARGET_FAILURE_ASC, INTERNAL_TARGET_FAILURE_ASCQ);
	}
	return -1;
}

static int
mirror_state_validate(struct tdisk *tdisk, struct mirror_state *mirror_state, struct mirror_state *peer_state, int load)
{
	debug_info("mirror state master %d\n", mirror_state_master(mirror_state));
	debug_info("peer mirror state master %d\n", mirror_state_master(peer_state));
	debug_info("next role %d peer next role %d\n", mirror_state->next_role, peer_state->next_role);
	if (mirror_state_master(peer_state) && mirror_state_master(mirror_state)) {
		if (atomic_test_bit(MIRROR_FLAGS_NEED_RESYNC, &mirror_state->mirror_flags) && atomic_test_bit(MIRROR_FLAGS_NEED_RESYNC, &peer_state->mirror_flags)) {
			debug_warn("Conflict in owner ship of tdisk %s, Both node claim to be masters\n", tdisk_name(tdisk));
			return -1;
		}

		if (atomic_test_bit(MIRROR_FLAGS_NEED_RESYNC, &peer_state->mirror_flags)) {
			tdisk_set_mirror_role(tdisk, MIRROR_ROLE_PEER);
			atomic_set_bit(MIRROR_FLAGS_IN_RESYNC, &mirror_state->mirror_flags);
		}
		else if (!atomic_test_bit(MIRROR_FLAGS_NEED_RESYNC, &mirror_state->mirror_flags) && load) {
			tdisk_set_mirror_role(tdisk, MIRROR_ROLE_PEER);
		}
	}

	if (mirror_state_master(peer_state) && atomic_test_bit(MIRROR_FLAGS_NEED_RESYNC, &peer_state->mirror_flags)) {
		atomic_set_bit(MIRROR_FLAGS_IN_RESYNC, &mirror_state->mirror_flags);
	}

	if (!mirror_state_master(peer_state) && !mirror_state_master(mirror_state)) {
		if (atomic_test_bit(MIRROR_FLAGS_NEED_RESYNC, &mirror_state->mirror_flags) && atomic_test_bit(MIRROR_FLAGS_NEED_RESYNC, &peer_state->mirror_flags)) {
			debug_warn("Conflict in owner ship of tdisk %s, Both node claim to be masters but needing resync\n", tdisk_name(tdisk));
			return -1;
		}

		if (atomic_test_bit(MIRROR_FLAGS_NEED_RESYNC, &mirror_state->mirror_flags)) {
			debug_print("Both nodes not in master state. Switching this node to master as resyncing pending from this node\n");
			tdisk_set_mirror_role(tdisk, MIRROR_ROLE_MASTER);
		}
		else if (!atomic_test_bit(MIRROR_FLAGS_NEED_RESYNC, &peer_state->mirror_flags)) {
			debug_print("Both nodes not in master state. Switching this node to master as no resync pending\n");
			tdisk_set_mirror_role(tdisk, MIRROR_ROLE_MASTER);
		}
	}
#if 0
	if (mirror_state_master(peer_state)) {
		if (atomic_test_bit(MIRROR_FLAGS_NEED_RESYNC, &peer_state->mirror_flags)) {
			debug_info("setting mirror state to resync\n");
			atomic_set_bit(MIRROR_FLAGS_NEED_RESYNC, &mirror_state->mirror_flags);
		}
		debug_info("setting role to peer\n");
		tdisk_set_mirror_role(tdisk, MIRROR_ROLE_PEER);
	}
	else if (!mirror_state_master(peer_state) && (mirror_state_master(mirror_state) || mirror_state->next_role == MIRROR_ROLE_MASTER)) {
		debug_info("setting role to master\n");
		tdisk_set_mirror_role(tdisk, MIRROR_ROLE_MASTER);
	}

	atomic_set_bit(VDISK_SYNC_START, &tdisk->flags);
	tdisk_sync(tdisk, 0);
#endif

	return 0;
}

static inline int
tdisk_master_mirror_resync(struct tdisk *tdisk)
{
	struct clone_config *config;
	struct mirror_state *mirror_state = &tdisk->mirror_state;
	int retval;

	mirror_clear_write_id_skip();

	config = zalloc(sizeof(*config), M_QUADSTOR, Q_WAITOK);
	config->src_target_id = tdisk->target_id;
	config->dest_target_id = mirror_state->mirror_target_id;
	config->src_ipaddr = mirror_state->mirror_src_ipaddr;
	config->dest_ipaddr = mirror_state->mirror_ipaddr;

	sx_xlock(clone_info_lock);
	retval = __vdisk_mirror(config, 1);
	sx_xunlock(clone_info_lock);
	free(config, M_QUADSTOR);

	if (unlikely(retval != 0))
		return retval;

	return 0;
}

static void
tdisk_mirror_checks_master(struct tdisk *tdisk)
{
	if (tdisk_mirroring_disabled(tdisk)) {
		debug_info("mirroring disabled\n");
		return;
	}

	if (!tdisk_mirroring_need_resync(tdisk)) {
		debug_info("mirroring need resync\n");
		return;
	}

	if (!atomic_test_bit(MIRROR_FLAGS_PEER_LOAD_DONE, &tdisk->mirror_state.mirror_flags)) {
		debug_info("!peer load done\n");
		return;
	}

	if (tdisk_in_mirroring(tdisk) || tdisk_in_cloning(tdisk)) {
		debug_info("in mirroring or in cloning\n");
		return;
	}

	tdisk_master_mirror_resync(tdisk);
}

static void
tdisk_mirror_checks_peer(struct tdisk *tdisk)
{
	if (!tdisk_mirroring_disabled(tdisk))
		return;

	tdisk_mirror_lock(tdisk);
	tdisk_mirror_reconnect(tdisk);
	tdisk_mirror_unlock(tdisk);
	if (!tdisk->mirror_comm)
		return;

	tdisk_mirror_startup(tdisk, 1);
}

void
tdisk_mirror_checks(struct tdisk *tdisk)
{
	if (!tdisk_mirroring_configured(tdisk))
		return;

	if (tdisk_mirror_master(tdisk))
		tdisk_mirror_checks_master(tdisk);
	else
		tdisk_mirror_checks_peer(tdisk);
}

int
tdisk_mirror_resize(struct tdisk *tdisk, uint64_t new_size)
{
	struct vdisk_update_spec *update;
	struct node_msg *msg;
	int retval;

	if (!tdisk_mirroring_configured(tdisk))
		return 0;

	if (tdisk_mirroring_disabled(tdisk))
		return -1;

	msg = node_sync_msg_alloc(sizeof(*update), NODE_MSG_VDISK_RESIZE);
	update = (struct vdisk_update_spec *)(msg->raw->data);
	update->end_lba = (new_size >> tdisk->lba_shift);

	retval = node_mirror_send_page(tdisk, msg, NULL, 0, mirror_sync_timeout, 0, NULL, 0);
	if (unlikely(retval != 0)) {
		tdisk_mirroring_disable(tdisk);
		debug_warn("Failed to send updated vdisk properties\n");
	}

	node_msg_free(msg);
	return retval;
}

int
tdisk_mirror_update_properties(struct tdisk *tdisk, struct vdisk_update_spec *spec)
{
	struct vdisk_update_spec *update;
	struct node_msg *msg;
	int retval;

	if (!tdisk_mirroring_configured(tdisk))
		return 0;

	if (tdisk_mirroring_disabled(tdisk))
		return -1;

	msg = node_sync_msg_alloc(sizeof(*update), NODE_MSG_VDISK_UPDATE);
	update = (struct vdisk_update_spec *)(msg->raw->data);
	memcpy(update, spec, sizeof(*spec));

	retval = node_mirror_send_page(tdisk, msg, NULL, 0, mirror_sync_timeout, 0, NULL, 0);
	if (unlikely(retval != 0)) {
		tdisk_mirroring_disable(tdisk);
		debug_warn("Failed to send updated vdisk properties\n");
	}

	node_msg_free(msg);
	return retval;
}

static int
tdisk_mirror_load_done(struct tdisk *tdisk, int msg_id, int recovery)
{
	struct node_msg *msg;
	int retval;

	debug_info("for %s mirroring configured %d mirroring disabled %d\n", tdisk_name(tdisk), tdisk_mirroring_configured(tdisk), tdisk_mirroring_disabled(tdisk));
	if (!tdisk_mirroring_configured(tdisk))
		return 0;

	if (tdisk_mirroring_disabled(tdisk)) {
		debug_warn("mirroring disabled for %s\n", tdisk_name(tdisk));
		return 0;
	}

	msg = node_sync_msg_alloc(0, msg_id);
	retval = node_mirror_send_page(tdisk, msg, NULL, 0, mirror_sync_timeout, 0, NULL, 0);
	if (unlikely(retval != 0)) {
		debug_warn("Failed to send mirror load done message\n");
		tdisk_mirroring_disable(tdisk);
		node_msg_free(msg);
		return -1;
	}

	if (msg_id == NODE_MSG_MIRROR_LOAD_DONE) {
		atomic_set_bit(MIRROR_FLAGS_PEER_LOAD_DONE, &tdisk->mirror_state.mirror_flags);
		if (recovery) {
			cbs_new_device(tdisk, 1);
		}
	}

	node_msg_free(msg);
	return 0;
}

#if 0
static int
tdisk_peer_mirror_resync(struct tdisk *tdisk)
{
	struct mirror_state *mirror_state;
	struct node_msg *msg;
	int retval;

	debug_info("send mirror resync for %s mirroring configured %d mirroring disabled %d\n", tdisk_name(tdisk), tdisk_mirroring_configured(tdisk), tdisk_mirroring_disabled(tdisk));
	if (!tdisk_mirroring_configured(tdisk))
		return 0;

	mirror_state = &tdisk->mirror_state;
	if (tdisk_mirroring_disabled(tdisk)) {
		debug_warn("mirroring disabled for %s\n", tdisk_name(tdisk));
		return -1;
	}

	msg = node_sync_msg_alloc(sizeof(*mirror_state), NODE_MSG_MIRROR_RESYNC_START);
	memcpy(msg->raw->data, mirror_state, sizeof(*mirror_state));
	retval = node_mirror_send_page(tdisk, msg, NULL, 0, mirror_sync_timeout, 0, NULL, 0);
	if (unlikely(retval != 0)) {
		debug_warn("Failed to resync done message\n");
		tdisk_mirroring_disable(tdisk);
	}

	node_msg_free(msg);
	debug_info("end\n");
	return 0;
}

static int
tdisk_mirror_resync(struct tdisk *tdisk)
{
	if (tdisk_mirror_master(tdisk))
		return tdisk_master_mirror_resync(tdisk);
	else
		return tdisk_peer_mirror_resync(tdisk);
}
#endif

static int
tdisk_mirror_registration_clear_send(struct tdisk *tdisk)
{
	struct node_msg *msg;
	int retval;

	msg = node_sync_msg_alloc(0, NODE_MSG_REGISTRATION_CLEAR_SYNC);
	retval = node_mirror_send_page(tdisk, msg, NULL, 0, mirror_sync_timeout, 0, NULL, 0);
	node_msg_free(msg);
	if (unlikely(retval != 0)) {
		tdisk_mirroring_disable(tdisk);
		return retval;
	}
	return retval;
}

static int
tdisk_mirror_reservation_sync_send(struct tdisk *tdisk)
{
	struct reservation_spec *reservation_spec;
	struct reservation *reservation = &tdisk->reservation;
	struct node_msg *msg;
	int retval;

	msg = node_sync_msg_alloc(sizeof(*reservation_spec), NODE_MSG_RESERVATION_SYNC);
	reservation_spec = (struct reservation_spec *)(msg->raw->data);
	if (!reservation->is_reserved || reservation->type == RESERVATION_TYPE_PERSISTENT)
		reservation_spec_fill(&tdisk->reservation, reservation_spec);
	else {
		bzero(reservation_spec, sizeof(*reservation_spec));
		reservation_spec->generation = reservation->generation;
	}

	retval = node_mirror_send_page(tdisk, msg, NULL, 0, mirror_sync_timeout, 0, NULL, 0);
	node_msg_free(msg);
	if (unlikely(retval != 0)) {
		tdisk_mirroring_disable(tdisk);
		return retval;
	}
	return retval;
}

static int
tdisk_mirror_registration_sync_send(struct tdisk *tdisk, struct registration *registration)
{
	struct registration_spec *registration_spec;
	struct node_msg *msg;
	int retval;

	debug_info("key %llx\n", (unsigned long long)registration->key);
	msg = node_sync_msg_alloc(sizeof(*registration_spec), NODE_MSG_REGISTRATION_SYNC);
	registration_spec = (struct registration_spec *)(msg->raw->data);
	registration_spec->key = registration->key;
	port_fill(registration_spec->i_prt, registration->i_prt);
	port_fill(registration_spec->t_prt, registration->t_prt);
	registration_spec->r_prt = registration->r_prt;
	registration_spec->init_int = registration->init_int;
	strcpy(registration_spec->init_name, registration->init_name);
	registration_spec->op = REGISTRATION_OP_ADD;
	retval = node_mirror_send_page(tdisk, msg, NULL, 0, mirror_sync_timeout, 0, NULL, 0);
	node_msg_free(msg);
	if (unlikely(retval != 0)) {
		tdisk_mirroring_disable(tdisk);
		return retval;
	}
	return retval;
}

static int
tdisk_mirror_sync_reservations(struct tdisk *tdisk)
{
	int retval;
	struct registration *registration;

	debug_info("start\n");
	if (!tdisk_mirror_master(tdisk))
		return 0;

	tdisk_reservation_lock(tdisk);
	retval = tdisk_mirror_registration_clear_send(tdisk);
	if (unlikely(retval != 0)) {
		tdisk_reservation_unlock(tdisk);
		return retval;
	}

	SLIST_FOREACH(registration, &tdisk->reservation.registration_list, r_list) {
		retval = tdisk_mirror_registration_sync_send(tdisk, registration);
		if (unlikely(retval != 0))
			break;
	}

	if (unlikely(retval != 0)) {
		tdisk_reservation_unlock(tdisk);
		return retval;
	}

	retval = tdisk_mirror_reservation_sync_send(tdisk);
	tdisk_reservation_unlock(tdisk);
	debug_info("end\n");
	return retval;
}

static int
tdisk_mirror_startup(struct tdisk *tdisk, int recovery)
{
	struct mirror_state *mirror_state;
	struct mirror_state peer_state;
	struct node_msg *msg;
	int retval;

	debug_info("tdisk %s mirror flags %d\n", tdisk_name(tdisk), tdisk->mirror_state.mirror_flags);
	if (!tdisk_mirroring_configured(tdisk))
		return 0;

	tdisk_mirror_connect(tdisk);
	if (unlikely(!tdisk->mirror_comm)) {
		debug_warn("rep comm get failed for mirror ipaddr %u mirror_src_ipaddr %u\n", tdisk->mirror_state.mirror_ipaddr, tdisk->mirror_state.mirror_src_ipaddr);
		tdisk_mirroring_disable(tdisk);
		if (tdisk_mirror_master(tdisk))
			return 1;
		else
			return -1;
	}

	msg = node_sync_msg_alloc(sizeof(*mirror_state), NODE_MSG_MIRROR_STATE);
	mirror_state = (struct mirror_state *)(msg->raw->data);
	memcpy(mirror_state, &tdisk->mirror_state, sizeof(*mirror_state));
	mirror_state->mirror_src_ipaddr = recv_config.recv_ipaddr;

	debug_info("mirror state flags %d\n", mirror_state->mirror_flags);
	retval = node_mirror_send_page(tdisk, msg, NULL, 0, mirror_sync_timeout, 0, &peer_state, sizeof(peer_state));
	if (unlikely(retval != 0)) {
		debug_warn("mirror state send page failed\n");
		tdisk_mirroring_disable(tdisk);
		node_msg_free(msg);
		if (!tdisk_mirror_master(tdisk)) {
			atomic_set_bit(MIRROR_FLAGS_WAIT_FOR_MASTER, &tdisk->mirror_state.mirror_flags);
			debug_warn("peer unreachable when not master\n");
			return -1;
		}
		if (tdisk->mirror_state.next_role != MIRROR_ROLE_MASTER) {
			atomic_set_bit(MIRROR_FLAGS_WAIT_FOR_PEER, &tdisk->mirror_state.mirror_flags);
			debug_warn("peer unreachable when we aren't sure of master state\n");
			return -1;
		}
		return 1;
	}

	debug_info("peer state flags %d\n", peer_state.mirror_flags);

	atomic_clear_bit(MIRROR_FLAGS_WAIT_FOR_MASTER, &tdisk->mirror_state.mirror_flags);
	atomic_clear_bit(MIRROR_FLAGS_WAIT_FOR_PEER, &tdisk->mirror_state.mirror_flags);
	retval = mirror_state_validate(tdisk, &tdisk->mirror_state, &peer_state, 1);
	if (unlikely(retval != 0)) {
		debug_warn("mirror state validate failed\n");
		tdisk_mirror_load_done(tdisk, NODE_MSG_MIRROR_LOAD_ERROR, recovery);
		atomic_set_bit(MIRROR_FLAGS_STATE_INVALID, &tdisk->mirror_state.mirror_flags);
		tdisk_mirroring_disable(tdisk);
		node_msg_free(msg);
		return -1;
	}

	if (tdisk_mirror_master(tdisk)) {
		tdisk_mirror_sync_reservations(tdisk);
		if (unlikely(retval != 0)) {
			tdisk_mirror_load_done(tdisk, NODE_MSG_MIRROR_LOAD_ERROR, recovery);
			tdisk_mirroring_disable(tdisk);
			node_msg_free(msg);
			return -1;
		}
	}

	tdisk_mirror_load_done(tdisk, NODE_MSG_MIRROR_LOAD_DONE, recovery);

	node_msg_free(msg);
	debug_info("end\n");
	return 0;
}

static void
tdisk_mirror_unblock(struct tdisk *tdisk)
{
	struct mirror_state *mirror_state;

	debug_info("mirror cmds %d\n", atomic_read(&tdisk->mirror_cmds));
	mirror_state = &tdisk->mirror_state;
	debug_check(!atomic_test_bit(MIRROR_FLAGS_BLOCK, &mirror_state->mirror_flags));
	chan_lock(tdisk->mirror_wait);
	atomic_clear_bit(MIRROR_FLAGS_BLOCK, &mirror_state->mirror_flags);
	chan_wakeup_unlocked(tdisk->mirror_wait);
	chan_unlock(tdisk->mirror_wait);
}

static void
tdisk_mirror_block(struct tdisk *tdisk)
{
	struct mirror_state *mirror_state;

	mirror_state = &tdisk->mirror_state;
	chan_lock(tdisk->mirror_wait);
	atomic_set_bit(MIRROR_FLAGS_BLOCK, &mirror_state->mirror_flags);
	chan_unlock(tdisk->mirror_wait);
	debug_info("mirror cmds %d\n", atomic_read(&tdisk->mirror_cmds));
	wait_on_chan(tdisk->mirror_wait, !atomic_read(&tdisk->mirror_cmds));
	debug_info("Done wait mirror cmds %d\n", atomic_read(&tdisk->mirror_cmds));
}

int
tdisk_mirror_set_role(struct tdisk *tdisk, int mirror_role)
{
	struct node_msg *msg = NULL;
	struct mirror_state *mirror_state;
	int retval;

	if (!tdisk_mirroring_configured(tdisk))
		return 0;

	debug_info("mirror block\n");
	tdisk_mirror_block(tdisk);
	debug_info("tdisk current role %s new role %s\n", mirror_role_str(tdisk->mirror_state.mirror_role), mirror_role_str(mirror_role));
	if (tdisk->mirror_state.mirror_role == mirror_role) {
		tdisk_mirror_unblock(tdisk);
		return 0;
	}

	debug_info("Mirroring disabled %d\n", tdisk_mirroring_disabled(tdisk));
	if (tdisk_mirroring_disabled(tdisk))
		goto set_role;

	msg = node_sync_msg_alloc(sizeof(*mirror_state), NODE_MSG_MIRROR_SET_ROLE);
	mirror_state = (struct mirror_state *)(msg->raw->data);
	memcpy(mirror_state, &tdisk->mirror_state, sizeof(*mirror_state));
	mirror_state->mirror_role = (mirror_role == MIRROR_ROLE_MASTER) ? MIRROR_ROLE_PEER : MIRROR_ROLE_MASTER;
	debug_info("Send set role message\n");
	retval = node_mirror_send_page(tdisk, msg, NULL, 0, mirror_sync_timeout, 0, NULL, 0);
	debug_info("Set role message retval %d\n", retval);
	node_msg_free(msg);
	if (unlikely(retval < 0)) {
		retval = tdisk_mirror_peer_failure(tdisk, 1);
		if (unlikely(retval != 0)) {
			debug_warn("fencing peer node failed\n");
			tdisk_mirror_unblock(tdisk);
			return -1;
		}
	}
	else if (retval != 0) {
		debug_warn("mirror peer denied switch to role %d with status %d\n", mirror_role, retval);
		tdisk_mirror_unblock(tdisk);
		return -1;
	}

set_role:
	tdisk_set_mirror_role(tdisk, mirror_role);
	atomic_set_bit(VDISK_SYNC_START, &tdisk->flags);
	tdisk_sync(tdisk, 0);
	debug_info("mirror unblock\n");
	tdisk_mirror_unblock(tdisk);
	return 0;
}

int
tdisk_mirror_exit(struct tdisk *tdisk)
{
	struct mirror_state *mirror_state;
	struct node_msg *msg = NULL;
	int retval;

	debug_info("shutdown start for %s mirroring configured %d mirroring disabled %d\n", tdisk_name(tdisk), tdisk_mirroring_configured(tdisk), tdisk_mirroring_disabled(tdisk));
	if (!tdisk_mirroring_configured(tdisk) || !tdisk->mirror_comm)
		goto out;

	mirror_state = &tdisk->mirror_state;
	if (tdisk_mirroring_disabled(tdisk))
		goto out;

	msg = node_sync_msg_alloc(sizeof(*mirror_state), NODE_MSG_PEER_SHUTDOWN);
	memcpy(msg->raw->data, mirror_state, sizeof(*mirror_state));
	retval = node_mirror_send_page(tdisk, msg, NULL, 0, mirror_sync_timeout, 0, NULL, 0);
	if (unlikely(retval != 0)) {
		debug_warn("Cannot send peer shutdown message\n");
		goto out;
	}

	if (tdisk_mirror_master(tdisk)) {
		debug_info("Switching over to peer role\n");
		tdisk_set_next_role(tdisk, MIRROR_ROLE_PEER);
		atomic_set_bit(VDISK_SYNC_START, &tdisk->flags);
	}
out:
	if (msg)
		node_msg_free(msg);
	tdisk_mirror_comm_free(tdisk);
	debug_info("end\n");
	return 0;
}

int
tdisk_mirror_remove(struct tdisk *tdisk, int attach)
{
	struct node_msg *msg;
	int retval;

	if (!tdisk_mirroring_configured(tdisk))
		return 0;

	if (tdisk_mirroring_disabled(tdisk))
		goto out;

	msg = node_sync_msg_alloc(sizeof(tdisk->mirror_state), NODE_MSG_MIRROR_REMOVE);
	memcpy(msg->raw->data, &tdisk->mirror_state, sizeof(tdisk->mirror_state));

	node_mirror_send_page(tdisk, msg, NULL, 0, mirror_sync_timeout, 0, NULL, 0);
	node_msg_free(msg);
out:
	bzero(&tdisk->mirror_state, sizeof(tdisk->mirror_state));
	atomic_set_bit(VDISK_SYNC_START, &tdisk->flags);
	retval = tdisk_sync(tdisk, 0);
	tdisk_mirror_comm_free(tdisk);
	if (!atomic_test_bit(VDISK_ATTACHED, &tdisk->flags) && attach) {
		cbs_new_device(tdisk, 1);
	}
	return retval;
}

int
tdisk_mirror_end(struct tdisk *tdisk)
{
	struct mirror_state *mirror_state;
	struct node_msg *msg = NULL;
	int retval;

	debug_info("mirror end for %s mirroring configured %d mirroring disabled %d\n", tdisk_name(tdisk), tdisk_mirroring_configured(tdisk), tdisk_mirroring_disabled(tdisk));
	if (!tdisk_mirroring_configured(tdisk))
		return 0;

	if (tdisk_mirror_error(tdisk)) {
		debug_warn("Mirror op ended with error\n");
		tdisk_mirroring_disable(tdisk);
		return 0;
	}

	mirror_state = &tdisk->mirror_state;
	if (tdisk_mirroring_disabled(tdisk)) {
		debug_warn("mirroring disabled for %s\n", tdisk_name(tdisk));
		goto out;
	}

	msg = node_sync_msg_alloc(sizeof(*mirror_state), NODE_MSG_MIRROR_RESYNC_DONE);
	memcpy(msg->raw->data, mirror_state, sizeof(*mirror_state));
	retval = node_mirror_send_page(tdisk, msg, NULL, 0, mirror_sync_timeout, 0, NULL, 0);
	if (unlikely(retval != 0)) {
		debug_warn("Failed to resync done message\n");
		tdisk_mirroring_disable(tdisk);
		goto sync;
	}

	debug_info("Clearing need resync for %s\n", tdisk_name(tdisk));
	debug_check(!tdisk_mirroring_need_resync(tdisk));
	tdisk->mirror_state.next_role = 0;
	tdisk_mirroring_resync_clear(tdisk);
	atomic_set_bit(VDISK_MIRROR_LOAD_DONE, &tdisk->flags);
sync:
	debug_info("Syncing %s\n", tdisk_name(tdisk));
	atomic_set_bit(VDISK_SYNC_START, &tdisk->flags);
	tdisk_sync(tdisk, 0);
out:
	if (msg)
		node_msg_free(msg);
	debug_info("end\n");
	return 0;
}

int
tdisk_mirror_setup(struct tdisk *tdisk, struct clone_info *clone_info, char *sys_rid)
{
	struct mirror_setup_spec *setup_spec;
	struct mirror_state *mirror_state;
	struct vdisk_update_spec *update_spec;
	struct node_msg *msg;
	int retval;

	if (tdisk_mirroring_configured(tdisk))
		return -1;

	debug_check(tdisk->mirror_comm);
	msg = node_sync_msg_alloc(sizeof(*setup_spec), NODE_MSG_MIRROR_SETUP);

	setup_spec = (struct mirror_setup_spec *)(msg->raw->data);

	mirror_state = &setup_spec->mirror_state;
	mirror_state->mirror_type = clone_info->mirror_type;
	mirror_state->mirror_role = clone_info->mirror_role;
	mirror_state->mirror_target_id = tdisk->target_id;
	mirror_state->mirror_src_ipaddr = clone_info->src_ipaddr;
	mirror_state->mirror_ipaddr = clone_info->dest_ipaddr;
	strcpy(mirror_state->mirror_vdisk, tdisk_name(tdisk));
	strcpy(mirror_state->mirror_group, tdisk->group->name);
	strcpy(mirror_state->sys_rid, sys_rid);

	update_spec = &setup_spec->properties;
	update_spec->enable_deduplication = tdisk->enable_deduplication;
	update_spec->enable_compression = tdisk->enable_compression;
	update_spec->enable_verify = tdisk->enable_verify;
	update_spec->end_lba = tdisk->end_lba;
	update_spec->lba_shift = tdisk->lba_shift;
	update_spec->max_size = tdisk_max_size(tdisk);

	memcpy(&tdisk->mirror_state, mirror_state, sizeof(*mirror_state));
	tdisk->mirror_state.mirror_target_id = clone_info->dest_target_id;
	strcpy(tdisk->mirror_state.mirror_vdisk, clone_info->mirror_vdisk);
	strcpy(tdisk->mirror_state.mirror_group, clone_info->mirror_group);

	tdisk_mirror_connect(tdisk);
	if (unlikely(!tdisk->mirror_comm)) {
		bzero(&tdisk->mirror_state, sizeof(tdisk->mirror_state));
		tdisk_mirroring_disable(tdisk);
		node_msg_free(msg);
		return 0;
	}

	retval = node_mirror_send_page(tdisk, msg, NULL, 0, mirror_sync_timeout, 0, NULL, 0);
	if (unlikely(retval != 0)) {
		bzero(&tdisk->mirror_state, sizeof(tdisk->mirror_state));
		tdisk_mirror_comm_free(tdisk);
		node_msg_free(msg);
		return -1;
	}

	debug_info("setting initial resync flag\n");
	tdisk_mirroring_resync_set(tdisk);
	atomic_set_bit(MIRROR_FLAGS_CONFIGURED, &tdisk->mirror_state.mirror_flags);
	tdisk_set_mirror_role(tdisk, MIRROR_ROLE_MASTER);

	node_msg_free(msg);
	retval = tdisk_mirror_startup(tdisk, 0);
	if (unlikely(retval != 0)) {
		bzero(&tdisk->mirror_state, sizeof(tdisk->mirror_state));
		tdisk_mirror_comm_free(tdisk);
		return -1;
	}

	atomic_set_bit(VDISK_SYNC_START, &tdisk->flags);
	tdisk_sync(tdisk, 0);
	return 0;
}

int
tdisk_mirror_load(struct tdisk *tdisk)
{
	int retval;

	debug_info("tdisk %s mirror flags %d\n", tdisk_name(tdisk), tdisk->mirror_state.mirror_flags);
	if (!tdisk_mirroring_configured(tdisk))
		return 0;

	debug_info("tdisk %s mirror master %d\n", tdisk_name(tdisk), tdisk_mirror_master(tdisk));
	retval = tdisk_mirror_startup(tdisk, 0);
	if (unlikely(retval != 0)) {
		tdisk_mirror_comm_free(tdisk);
		if (retval > 0)
			return 0;
		else
			return retval;
	}

#if 0
	if (tdisk_mirroring_need_resync(tdisk)) {
		debug_info("tdisk %s needs resync \n", tdisk_name(tdisk));
		retval = tdisk_mirror_resync(tdisk);
		if (unlikely(retval != 0)) {
			debug_warn("mirror resync failed\n");
			return retval;
		}
	}
#endif

	return 0;
}

static int
mirror_peer_valid(struct tdisk *tdisk, struct node_sock *sock)
{
	if (!tdisk_mirroring_configured(tdisk)) {
		debug_warn("Mirroring message when not configured\n");
		return 0;
	}

	if (tdisk_mirroring_invalid(tdisk)) {
		debug_warn("Mirroring message in error state\n");
		return 0;
	}

	if (tdisk->mirror_state.mirror_ipaddr != sock->comm->node_ipaddr) {
		debug_warn("Mirroring message from invalid addr %u\n", sock->comm->node_ipaddr);
		return 0;
	}

	return 1;
}

void
node_mirror_remove(struct node_sock *sock, struct raw_node_msg *raw)
{
	struct tdisk *tdisk;
	struct node_msg *msg;
	struct mirror_state *mirror_state;
	int retval;
	uint16_t csum;

	tdisk = tdisk_locate(raw->target_id);
	if (unlikely(!tdisk)) {
		debug_warn("node cmd request for unknown tdisk %d\n", raw->target_id);
		node_msg_discard(sock, raw);
		node_resp_msg(sock, raw, NODE_STATUS_TARGET_NOT_FOUND);
		return;
	}

	debug_check(raw->dxfer_len != sizeof(*mirror_state));
	msg = node_msg_alloc(raw->dxfer_len);
	memcpy(msg->raw, raw, sizeof(*raw));
	raw = msg->raw;

	retval = node_sock_read_nofail(sock, raw->data, raw->dxfer_len);
	if (unlikely(retval != 0)) {
		tdisk_put(tdisk);
		node_msg_free(msg);
		return;
	}

	csum = net_calc_csum16(raw->data, raw->dxfer_len);
	if (unlikely(csum != raw->data_csum)) {
		debug_warn("data csum mismatch %x %x\n", csum, raw->data_csum);
		tdisk_put(tdisk);
		node_sock_read_error(sock);
		node_msg_free(msg);
		return;
	}

	if (!mirror_peer_valid(tdisk, sock)) {
		tdisk_put(tdisk);
		node_resp_msg(sock, raw, NODE_STATUS_INVALID_MIRROR_CONFIGURATION);
		node_msg_free(msg);
		return;
	}

	mirror_state = (struct mirror_state *)raw->data;
	if (mirror_state->mirror_src_ipaddr != tdisk->mirror_state.mirror_ipaddr) {
		debug_warn("Invalid mirror configuration received for %s\n", tdisk_name(tdisk));
		tdisk_put(tdisk);
		node_resp_msg(sock, raw, NODE_STATUS_INVALID_MIRROR_CONFIGURATION);
		node_msg_free(msg);
		return;
	}

	bzero(&tdisk->mirror_state, sizeof(tdisk->mirror_state));
	atomic_set_bit(VDISK_SYNC_START, &tdisk->flags);
	tdisk_sync(tdisk, 0);
	tdisk_mirror_comm_free(tdisk);
	tdisk_put(tdisk);

	node_send_msg(sock, msg, 0, 0);
	node_msg_free(msg);
}

void
node_mirror_setup(struct node_sock *sock, struct raw_node_msg *raw)
{
	struct tdisk *tdisk;
	struct node_msg *msg;
	struct mirror_setup_spec *setup_spec;
	struct vdisk_update_spec *update_spec;
	struct mirror_state *mirror_state;
	int retval;
	uint16_t csum;

	tdisk = tdisk_locate(raw->target_id);
	if (unlikely(!tdisk)) {
		debug_warn("node cmd request for unknown tdisk %d\n", raw->target_id);
		node_msg_discard(sock, raw);
		node_resp_msg(sock, raw, NODE_STATUS_TARGET_NOT_FOUND);
		return;
	}

	debug_check(raw->dxfer_len != sizeof(*setup_spec));
	msg = node_msg_alloc(raw->dxfer_len);
	memcpy(msg->raw, raw, sizeof(*raw));
	raw = msg->raw;

	retval = node_sock_read_nofail(sock, raw->data, raw->dxfer_len);
	if (unlikely(retval != 0)) {
		debug_warn("Cannot read %d bytes\n", raw->dxfer_len);
		tdisk_put(tdisk);
		node_msg_free(msg);
		return;
	}

	csum = net_calc_csum16(raw->data, raw->dxfer_len);
	if (unlikely(csum != raw->data_csum)) {
		debug_warn("data csum mismatch %x %x\n", csum, raw->data_csum);
		tdisk_put(tdisk);
		node_sock_read_error(sock);
		node_msg_free(msg);
		return;
	}

	if (tdisk_mirroring_configured(tdisk)) {
		debug_warn("received mirror setup for already configured vdisk %s\n", tdisk_name(tdisk));
		tdisk_put(tdisk);
		node_resp_msg(sock, raw, NODE_STATUS_MIRROR_CONFIGURED);
		node_msg_free(msg);
		return;
	}

	setup_spec = (struct mirror_setup_spec *)raw->data;
	mirror_state = &setup_spec->mirror_state;
	update_spec = &setup_spec->properties;

	if (tdisk->end_lba != update_spec->end_lba || tdisk->lba_shift != update_spec->lba_shift) {
		debug_warn("Mismatch in vdisk sizes %llu %llu sector sizes %u %u\n", (unsigned long long)tdisk->end_lba, (unsigned long long)update_spec->end_lba, 1U << tdisk->lba_shift, 1U << update_spec->lba_shift); 
		tdisk_put(tdisk);
		node_resp_msg(sock, raw, NODE_STATUS_INVALID_MIRROR_CONFIGURATION);
		node_msg_free(msg);
		return;
	}

	if (update_spec->max_size > tdisk_max_size(tdisk)) {
		tdisk_stop_delete_thread(tdisk);
		retval = tdisk_reinitialize_index(tdisk, update_spec->max_size, 0);
		if (unlikely(retval != 0)) {
			debug_warn("Cannot reinitalize index for new max size %llu\n", (unsigned long long)update_spec->max_size);
			tdisk_put(tdisk);
			node_resp_msg(sock, raw, NODE_STATUS_ERROR);
			node_msg_free(msg);
			return;
		}
	}

	memcpy(&tdisk->mirror_state, mirror_state, sizeof(*mirror_state));
	tdisk->mirror_state.mirror_src_ipaddr = mirror_state->mirror_ipaddr;
	tdisk->mirror_state.mirror_ipaddr = mirror_state->mirror_src_ipaddr;
	debug_info("setting initial resync flag\n");
	tdisk_mirroring_resync_set(tdisk);
	atomic_set_bit(MIRROR_FLAGS_CONFIGURED, &tdisk->mirror_state.mirror_flags);
	tdisk_set_mirror_role(tdisk, MIRROR_ROLE_PEER);
	atomic_set_bit(VDISK_SYNC_START, &tdisk->flags);
	tdisk_sync(tdisk, 0);
	tdisk_start_resize_thread(tdisk);
	tdisk_put(tdisk);

	raw->dxfer_len = 0;
	node_resp_msg(sock, raw, NODE_STATUS_OK);
	node_msg_free(msg);
}

void
node_mirror_set_role(struct node_sock *sock, struct raw_node_msg *raw)
{
	struct tdisk *tdisk;
	struct mirror_state *mirror_state;
	struct node_msg *msg;
	int retval, status;
	uint16_t csum;

	tdisk = tdisk_locate(raw->target_id);
	if (unlikely(!tdisk)) {
		debug_warn("node cmd request for unknown tdisk %d\n", raw->target_id);
		node_msg_discard(sock, raw);
		node_resp_msg(sock, raw, NODE_STATUS_TARGET_NOT_FOUND);
		return;
	}

	debug_info("tdisk %s\n", tdisk_name(tdisk));
	debug_check(raw->dxfer_len != sizeof(*mirror_state));
	msg = node_msg_alloc(raw->dxfer_len);
	memcpy(msg->raw, raw, sizeof(*raw));
	raw = msg->raw;

	retval = node_sock_read_nofail(sock, raw->data, raw->dxfer_len);
	if (unlikely(retval != 0)) {
		tdisk_put(tdisk);
		node_msg_free(msg);
		return;
	}

	csum = net_calc_csum16(raw->data, raw->dxfer_len);
	if (unlikely(csum != raw->data_csum)) {
		debug_warn("data csum mismatch %x %x\n", csum, raw->data_csum);
		tdisk_put(tdisk);
		node_sock_read_error(sock);
		node_msg_free(msg);
		return;
	}

	if (!mirror_peer_valid(tdisk, sock)) {
		tdisk_put(tdisk);
		node_resp_msg(sock, raw, NODE_STATUS_INVALID_MIRROR_CONFIGURATION);
		node_msg_free(msg);
		return;
	}

	mirror_state = (struct mirror_state *)raw->data;
	tdisk_mirror_block(tdisk);
	tdisk_mirror_lock(tdisk);
	if (tdisk->mirror_state.mirror_role != mirror_state->mirror_role) {
		if (mirror_state->mirror_role == MIRROR_ROLE_PEER && atomic_test_bit(MIRROR_FLAGS_NEED_RESYNC, &tdisk->mirror_state.mirror_flags)) {
			debug_warn("Trying to set role to slave for %s, but resync yet to be completed\n", tdisk_name(tdisk));
			status = NODE_STATUS_ERROR;
		}
		else {
			tdisk_set_mirror_role(tdisk, mirror_state->mirror_role);
			atomic_set_bit(VDISK_SYNC_START, &tdisk->flags);
			tdisk_sync(tdisk, 0);
			status = NODE_STATUS_OK;
		}
	}
	else {
		debug_warn("VDisk %s mismatch in role, peer expects to set %s but we already %s\n", tdisk_name(tdisk), mirror_role_str(mirror_state->mirror_role), mirror_role_str(tdisk->mirror_state.mirror_role));
		status = NODE_STATUS_OK;
	}

	tdisk_mirror_unlock(tdisk);
	tdisk_mirror_unblock(tdisk);
	tdisk_put(tdisk);

	raw->dxfer_len = 0;
	node_resp_msg(sock, raw, status);
	node_msg_free(msg);
}

void
node_mirror_peer_shutdown(struct node_sock *sock, struct raw_node_msg *raw)
{
	struct tdisk *tdisk;
	struct mirror_state *mirror_state;
	struct node_msg *msg;
	int retval, status;
	uint16_t csum;

	tdisk = tdisk_locate(raw->target_id);
	if (unlikely(!tdisk)) {
		debug_warn("node cmd request for unknown tdisk %d\n", raw->target_id);
		node_msg_discard(sock, raw);
		node_resp_msg(sock, raw, NODE_STATUS_TARGET_NOT_FOUND);
		return;
	}

	debug_info("tdisk %s\n", tdisk_name(tdisk));
	debug_check(raw->dxfer_len != sizeof(*mirror_state));
	msg = node_msg_alloc(raw->dxfer_len);
	memcpy(msg->raw, raw, sizeof(*raw));
	raw = msg->raw;

	retval = node_sock_read_nofail(sock, raw->data, raw->dxfer_len);
	if (unlikely(retval != 0)) {
		tdisk_put(tdisk);
		node_msg_free(msg);
		return;
	}

	csum = net_calc_csum16(raw->data, raw->dxfer_len);
	if (unlikely(csum != raw->data_csum)) {
		debug_warn("data csum mismatch %x %x\n", csum, raw->data_csum);
		tdisk_put(tdisk);
		node_sock_read_error(sock);
		node_msg_free(msg);
		return;
	}

	if (!mirror_peer_valid(tdisk, sock)) {
		tdisk_put(tdisk);
		node_resp_msg(sock, raw, NODE_STATUS_INVALID_MIRROR_CONFIGURATION);
		node_msg_free(msg);
		return;
	}

	if (tdisk_mirror_master(tdisk)) {
		tdisk_mirroring_disable(tdisk);
		tdisk_set_next_role(tdisk, MIRROR_ROLE_MASTER);
		atomic_set_bit(VDISK_SYNC_START, &tdisk->flags);
		tdisk_sync(tdisk, 0);
		status = NODE_STATUS_OK;
		goto send;
	}

	debug_info("peer shutdown setting role to master\n");
	if (!tdisk_mirroring_need_resync(tdisk)) {
		tdisk_set_mirror_role(tdisk, MIRROR_ROLE_MASTER);
		tdisk_set_next_role(tdisk, MIRROR_ROLE_MASTER);
		atomic_set_bit(VDISK_SYNC_START, &tdisk->flags);
		tdisk_sync(tdisk, 0);
		status = NODE_STATUS_OK;
	}
	else {
		status = NODE_STATUS_ERROR;
	}

	tdisk_mirroring_disable(tdisk);
send:
	raw->dxfer_len = 0;
	node_resp_msg(sock, raw, status);
	node_msg_free(msg);

	tdisk_mirror_comm_free(tdisk);
	tdisk_put(tdisk);
}

void
node_mirror_vdisk_resize(struct node_sock *sock, struct raw_node_msg *raw)
{
	struct tdisk *tdisk;
	struct vdisk_update_spec update;
	uint64_t size;
	int retval;

	tdisk = tdisk_locate(raw->target_id);
	if (unlikely(!tdisk)) {
		debug_warn("node cmd request for unknown tdisk %d\n", raw->target_id);
		node_msg_discard(sock, raw);
		node_resp_msg(sock, raw, NODE_STATUS_TARGET_NOT_FOUND);
		return;
	}

	retval = node_sock_read_nofail(sock, &update, sizeof(update));
	if (unlikely(retval != 0)) {
		tdisk_put(tdisk);
		return;
	}

	if (!mirror_peer_valid(tdisk, sock)) {
		tdisk_put(tdisk);
		node_resp_msg(sock, raw, NODE_STATUS_INVALID_MIRROR_CONFIGURATION);
		return;
	}

	size = update.end_lba << tdisk->lba_shift;

	tdisk_stop_delete_thread(tdisk);
	retval = tdisk_reinitialize_index(tdisk, size, 1);

	raw->dxfer_len = 0;
	if (retval == 0) {
		node_resp_msg(sock, raw, NODE_STATUS_OK);
		cbs_update_device(tdisk);
	}
	else
		node_resp_msg(sock, raw, NODE_STATUS_ERROR);
	tdisk_start_resize_thread(tdisk);
	tdisk_put(tdisk);
}

void
node_mirror_update_vdisk_properties(struct node_sock *sock, struct raw_node_msg *raw)
{
	struct tdisk *tdisk;
	struct vdisk_update_spec update;
	int retval, need_update = 0;

	tdisk = tdisk_locate(raw->target_id);
	if (unlikely(!tdisk)) {
		debug_warn("node cmd request for unknown tdisk %d\n", raw->target_id);
		node_msg_discard(sock, raw);
		node_resp_msg(sock, raw, NODE_STATUS_TARGET_NOT_FOUND);
		return;
	}

	retval = node_sock_read_nofail(sock, &update, sizeof(update));
	if (unlikely(retval != 0)) {
		tdisk_put(tdisk);
		return;
	}

	if (!mirror_peer_valid(tdisk, sock)) {
		tdisk_put(tdisk);
		node_resp_msg(sock, raw, NODE_STATUS_INVALID_MIRROR_CONFIGURATION);
		return;
	}

	tdisk_lock(tdisk);
	tdisk->enable_deduplication = update.enable_deduplication;
	tdisk->enable_compression = update.enable_compression;
	tdisk->enable_verify = update.enable_verify;
	atomic_set_bit(VDISK_SYNC_START, &tdisk->flags);
	retval = __tdisk_sync(tdisk, 0);
	tdisk_unlock(tdisk);
	if (unlikely(retval != 0)) {
		goto send;
	}

	retval = 0;
	if (tdisk->end_lba != update.end_lba) {
		uint64_t new_size = update.end_lba << tdisk->lba_shift;
		uint64_t cur_size = tdisk->end_lba << tdisk->lba_shift;

		debug_info("End lba was %llu is %llu\n", (unsigned long long)tdisk->end_lba, (unsigned long long)update.end_lba);
		tdisk_stop_delete_thread(tdisk);
		if (new_size > cur_size)
			retval = tdisk_reinitialize_index(tdisk, new_size, 1);
		else
			retval = tdisk_reinitialize_index_reduc(tdisk, new_size);

		if (retval == 0) {
			tdisk->end_lba = update.end_lba;
			need_update = 1;
		}
	}

	if (need_update) {
		node_tdisk_update_send(tdisk);
		cbs_update_device(tdisk);
	}
	tdisk_start_resize_thread(tdisk);
send:
	tdisk_put(tdisk);
	raw->dxfer_len = 0;
	if (retval == 0)
		node_resp_msg(sock, raw, NODE_STATUS_OK);
	else
		node_resp_msg(sock, raw, NODE_STATUS_ERROR);
}

void
node_mirror_load_error(struct node_sock *sock, struct raw_node_msg *raw)
{
	struct tdisk *tdisk;

	tdisk = tdisk_locate(raw->target_id);
	if (unlikely(!tdisk)) {
		debug_warn("node cmd request for unknown tdisk %d\n", raw->target_id);
		node_msg_discard(sock, raw);
		node_resp_msg(sock, raw, NODE_STATUS_TARGET_NOT_FOUND);
		return;
	}

	if (!mirror_peer_valid(tdisk, sock)) {
		tdisk_put(tdisk);
		node_resp_msg(sock, raw, NODE_STATUS_INVALID_MIRROR_CONFIGURATION);
		return;
	}

	tdisk_mirroring_set_invalid(tdisk);
	tdisk_mirroring_disable(tdisk);
	tdisk_put(tdisk);
	raw->dxfer_len = 0;
	node_resp_msg(sock, raw, NODE_STATUS_OK);
}

void
node_mirror_load_done(struct node_sock *sock, struct raw_node_msg *raw)
{
	struct tdisk *tdisk;
	int retval;

	tdisk = tdisk_locate(raw->target_id);
	if (unlikely(!tdisk)) {
		debug_warn("node cmd request for unknown tdisk %d\n", raw->target_id);
		node_msg_discard(sock, raw);
		node_resp_msg(sock, raw, NODE_STATUS_TARGET_NOT_FOUND);
		return;
	}

	if (!mirror_peer_valid(tdisk, sock)) {
		tdisk_put(tdisk);
		node_resp_msg(sock, raw, NODE_STATUS_INVALID_MIRROR_CONFIGURATION);
		return;
	}

	if (!atomic_test_bit(VDISK_ATTACHED, &tdisk->flags)) {
		cbs_new_device(tdisk, 1);
	}

	if (tdisk_mirror_master(tdisk)) {
		retval = tdisk_mirror_sync_reservations(tdisk);
		if (unlikely(retval != 0)) {
			tdisk_put(tdisk);
			return;
		}
	}
	atomic_set_bit(MIRROR_FLAGS_PEER_LOAD_DONE, &tdisk->mirror_state.mirror_flags);

	tdisk_put(tdisk);
	raw->dxfer_len = 0;
	node_resp_msg(sock, raw, NODE_STATUS_OK);
}

#if 0
void
node_mirror_resync_start(struct node_sock *sock, struct raw_node_msg *raw)
{
	struct tdisk *tdisk;
	struct node_msg *msg;
	struct mirror_state *mirror_state;
	int retval;
	uint16_t csum;

	tdisk = tdisk_locate(raw->target_id);
	if (unlikely(!tdisk)) {
		debug_warn("node cmd request for unknown tdisk %d\n", raw->target_id);
		node_msg_discard(sock, raw);
		node_resp_msg(sock, raw, NODE_STATUS_TARGET_NOT_FOUND);
		return;
	}

	debug_check(raw->dxfer_len != sizeof(*mirror_state));
	msg = node_msg_alloc(raw->dxfer_len);
	memcpy(msg->raw, raw, sizeof(*raw));
	raw = msg->raw;

	retval = node_sock_read_nofail(sock, raw->data, raw->dxfer_len);
	if (unlikely(retval != 0)) {
		tdisk_put(tdisk);
		node_msg_free(msg);
		return;
	}

	csum = net_calc_csum16(raw->data, raw->dxfer_len);
	if (unlikely(csum != raw->data_csum)) {
		debug_warn("data csum mismatch %x %x\n", csum, raw->data_csum);
		tdisk_put(tdisk);
		node_sock_read_error(sock);
		node_msg_free(msg);
		return;
	}

	if (!mirror_peer_valid(tdisk, sock) || !tdisk_mirror_master(tdisk)) {
		tdisk_put(tdisk);
		node_resp_msg(sock, raw, NODE_STATUS_INVALID_MIRROR_CONFIGURATION);
		node_msg_free(msg);
		return;
	}

	retval = tdisk_master_mirror_resync(tdisk);
	if (unlikely(retval != 0)) {
		tdisk_put(tdisk);
		node_resp_msg(sock, raw, NODE_STATUS_ERROR);
		node_msg_free(msg);
		return;
	}

	tdisk_put(tdisk);
	raw->dxfer_len = 0;
	node_resp_msg(sock, raw, NODE_STATUS_OK);
	node_msg_free(msg);
}
#endif

void
node_mirror_resync_done(struct node_sock *sock, struct raw_node_msg *raw)
{
	struct tdisk *tdisk;
	struct node_msg *msg;
	struct mirror_state *mirror_state;
	int retval;
	uint16_t csum;

	tdisk = tdisk_locate(raw->target_id);
	if (unlikely(!tdisk)) {
		debug_warn("node cmd request for unknown tdisk %d\n", raw->target_id);
		node_msg_discard(sock, raw);
		node_resp_msg(sock, raw, NODE_STATUS_TARGET_NOT_FOUND);
		return;
	}

	debug_check(raw->dxfer_len != sizeof(*mirror_state));
	msg = node_msg_alloc(raw->dxfer_len);
	memcpy(msg->raw, raw, sizeof(*raw));
	raw = msg->raw;

	retval = node_sock_read_nofail(sock, raw->data, raw->dxfer_len);
	if (unlikely(retval != 0)) {
		tdisk_put(tdisk);
		node_msg_free(msg);
		return;
	}

	csum = net_calc_csum16(raw->data, raw->dxfer_len);
	if (unlikely(csum != raw->data_csum)) {
		debug_warn("data csum mismatch %x %x\n", csum, raw->data_csum);
		tdisk_put(tdisk);
		node_sock_read_error(sock);
		node_msg_free(msg);
		return;
	}

	if (!mirror_peer_valid(tdisk, sock)) {
		tdisk_put(tdisk);
		node_resp_msg(sock, raw, NODE_STATUS_INVALID_MIRROR_CONFIGURATION);
		node_msg_free(msg);
		return;
	}

	debug_info("clearing need resync\n");
	debug_check(!tdisk_mirroring_need_resync(tdisk));
	tdisk_mirroring_resync_clear(tdisk);
	atomic_set_bit(VDISK_SYNC_START, &tdisk->flags);
	atomic_set_bit(VDISK_MIRROR_LOAD_DONE, &tdisk->flags);
	tdisk_sync(tdisk, 0);
	tdisk_put(tdisk);

	raw->dxfer_len = 0;
	node_resp_msg(sock, raw, NODE_STATUS_OK);
	node_msg_free(msg);
}

void
node_mirror_write_error(struct node_sock *sock, struct raw_node_msg *raw)
{
	struct node_msg *msg;
	struct qsio_scsiio *ctio;
	struct write_list *wlist;
	struct tdisk *tdisk;
	struct tcache *tcache;

	msg = node_cmd_lookup(sock->comm->node_hash, raw->xchg_id);
	if (unlikely(!msg)) {
		debug_warn("Missing exchange cmd %x\n", raw->xchg_id);
		node_error_resp_msg(sock, raw, NODE_STATUS_INVALID_MSG);
		return;
	}

	debug_check(msg->sock != sock);
	ctio = msg->ctio;
	wlist = msg->wlist;
	tdisk = msg->tdisk;
	tcache = msg->tcache;

	if (tcache) {
		wait_for_done(tcache->completion);
		tcache_put(tcache);
	}

	node_master_write_error(tdisk, wlist, ctio);
	ctio_free_data(ctio);
	device_send_ccb(ctio);
}

void
node_mirror_registration_clear_recv(struct node_sock *sock, struct raw_node_msg *raw)
{
	struct tdisk *tdisk;

	tdisk = tdisk_locate(raw->target_id);
	if (unlikely(!tdisk)) {
		debug_warn("node cmd request for unknown tdisk %d\n", raw->target_id);
		node_error_resp_msg(sock, raw, NODE_STATUS_TARGET_NOT_FOUND);
		return;
	}

	if (!mirror_peer_valid(tdisk, sock)) {
		tdisk_put(tdisk);
		node_resp_msg(sock, raw, NODE_STATUS_INVALID_MIRROR_CONFIGURATION);
		return;
	}

	tdisk_reservation_lock(tdisk);
	persistent_reservation_clear(&tdisk->reservation.registration_list);
	tdisk_reservation_unlock(tdisk);
	raw->dxfer_len = 0;
	node_resp_msg(sock, raw, NODE_STATUS_OK);
	tdisk_put(tdisk);
}

void
node_mirror_reservation_sync_recv(struct node_sock *sock, struct raw_node_msg *raw)
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

	if (!mirror_peer_valid(tdisk, sock)) {
		tdisk_put(tdisk);
		node_resp_msg(sock, raw, NODE_STATUS_INVALID_MIRROR_CONFIGURATION);
		return;
	}

	reservation = &tdisk->reservation;
	tdisk_reservation_lock(tdisk);
	reservation_spec_copy(reservation, &reservation_spec);
	tdisk_reservation_unlock(tdisk);
	raw->dxfer_len = 0;
	node_resp_msg(sock, raw, NODE_STATUS_OK);
	tdisk_put(tdisk);
}

void
node_mirror_registration_sync_recv(struct node_sock *sock, struct raw_node_msg *raw)
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

	if (!mirror_peer_valid(tdisk, sock)) {
		tdisk_put(tdisk);
		node_resp_msg(sock, raw, NODE_STATUS_INVALID_MIRROR_CONFIGURATION);
		return;
	}

	debug_info("op %d key %llx\n", registration_spec.op, (unsigned long long)registration_spec.key);
	if (registration_spec.op == REGISTRATION_OP_ADD)
		registration_spec_add(tdisk, &tdisk->reservation, &registration_spec);
	else
		registration_spec_remove(tdisk, &tdisk->reservation, &registration_spec);
	raw->dxfer_len = 0;
	node_resp_msg(sock, raw, NODE_STATUS_OK);
	tdisk_put(tdisk);
}

void
node_mirror_state(struct node_sock *sock, struct raw_node_msg *raw)
{
	struct tdisk *tdisk;
	struct node_msg *msg;
	struct mirror_state *mirror_state;
	int retval;
	uint16_t csum;

	tdisk = tdisk_locate(raw->target_id);
	if (unlikely(!tdisk)) {
		debug_warn("node cmd request for unknown tdisk %d\n", raw->target_id);
		node_msg_discard(sock, raw);
		node_resp_msg(sock, raw, NODE_STATUS_TARGET_NOT_FOUND);
		return;
	}

	debug_info("received for tdisk %s\n", tdisk_name(tdisk));
	debug_check(raw->dxfer_len != sizeof(*mirror_state));
	msg = node_msg_alloc(raw->dxfer_len);
	memcpy(msg->raw, raw, sizeof(*raw));
	raw = msg->raw;

	retval = node_sock_read_nofail(sock, raw->data, raw->dxfer_len);
	if (unlikely(retval != 0)) {
		tdisk_put(tdisk);
		node_msg_free(msg);
		return;
	}

	csum = net_calc_csum16(raw->data, raw->dxfer_len);
	if (unlikely(csum != raw->data_csum)) {
		debug_warn("data csum mismatch %x %x\n", csum, raw->data_csum);
		tdisk_put(tdisk);
		node_sock_read_error(sock);
		node_msg_free(msg);
		return;
	}

#if 0
	if (!mirror_peer_valid(tdisk, sock)) {
		tdisk_put(tdisk);
		node_resp_msg(sock, raw, NODE_STATUS_INVALID_MIRROR_CONFIGURATION);
		node_msg_free(msg);
		return;
	}
#endif

	mirror_state = (struct mirror_state *)raw->data;
	debug_info("sys rid %s src ipaddr %u\n", mirror_state->sys_rid, mirror_state->mirror_src_ipaddr);
	if (memcmp(mirror_state->sys_rid, tdisk->mirror_state.sys_rid, sizeof(mirror_state->sys_rid))) {
		debug_warn("Mismatch in sys rid %s %s\n", mirror_state->sys_rid, tdisk->mirror_state.sys_rid);
		tdisk_put(tdisk);
		node_resp_msg(sock, raw, NODE_STATUS_INVALID_MIRROR_CONFIGURATION);
		node_msg_free(msg);
		return;
	}

	debug_info("mirror state flags %d\n", mirror_state->mirror_flags);
	debug_info("tdisk %s mirror state flags %d\n", tdisk_name(tdisk), tdisk->mirror_state.mirror_flags);

	atomic_clear_bit(MIRROR_FLAGS_WAIT_FOR_MASTER, &tdisk->mirror_state.mirror_flags);
	atomic_clear_bit(MIRROR_FLAGS_WAIT_FOR_PEER, &tdisk->mirror_state.mirror_flags);
	retval = mirror_state_validate(tdisk, &tdisk->mirror_state, mirror_state, 0);
	if (unlikely(retval != 0)) {
		tdisk_put(tdisk);
		node_resp_msg(sock, raw, NODE_STATUS_INVALID_MIRROR_CONFIGURATION);
		node_msg_free(msg);
		return;
	}

	tdisk_mirror_lock(tdisk);
	if (tdisk->mirror_state.mirror_ipaddr != mirror_state->mirror_src_ipaddr) {
		tdisk->mirror_state.mirror_ipaddr = mirror_state->mirror_src_ipaddr;
		atomic_set_bit(VDISK_SYNC_START, &tdisk->flags);
		tdisk_sync(tdisk, 0);
	}
	memcpy(mirror_state, &tdisk->mirror_state, sizeof(*mirror_state));
	tdisk_mirror_reconnect(tdisk);
	tdisk_mirror_unlock(tdisk);
	tdisk_put(tdisk);

	node_send_msg(sock, msg, 0, 0);
	node_msg_free(msg);

}
