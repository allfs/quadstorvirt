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
#include "../common/cluster_common.h" 
#include "node_sock.h"
#include "node_mirror.h"

static struct node_comm *recv_root;
wait_chan_t *recv_wait;
wait_chan_t *recv_cleanup_wait;
kproc_t *recv_task;
kproc_t *recv_cleanup_task;
int recv_flags;
int recv_cleanup_flags;
static struct queue_list recv_queue_list = TAILQ_HEAD_INITIALIZER(recv_queue_list);
static mtx_t *recv_queue_lock;
struct node_config recv_config;

static int
amap_needs_sync(struct amap *amap, uint64_t write_id)
{
	return (amap->write_id != write_id);
}

static void
node_recv_amap_check(struct node_sock *sock, struct raw_node_msg *raw)
{
	struct amap_spec amap_spec;
	struct tdisk *tdisk;
	uint64_t lba, end_lba;
	struct amap_table *amap_table = NULL;
	struct amap *amap = NULL;
	int error = 0, status = 0, retval;

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

	lba = amap_spec.lba;
	end_lba = tdisk_get_lba_real(tdisk, tdisk->end_lba);

	if (unlikely(lba >= end_lba)) {
		debug_warn("Invalid lba %llu tdisk end lba %llu\n", (unsigned long long)lba, (unsigned long long)end_lba);
		status = NODE_STATUS_INVALID_MSG;
		goto send;
	}

	amap_table = amap_table_locate(tdisk, lba, &error);
	if (!amap_table) {
		if (!error)
			status = NODE_STATUS_AMAP_NOT_FOUND;
		else
			status = NODE_STATUS_ERROR;
		goto send; 
	}

	amap_table_lock(amap_table);
	amap_table_check_csum(amap_table);
	if (atomic_test_bit_short(ATABLE_META_DATA_ERROR, &amap_table->flags)) {
		amap_table_unlock(amap_table);
		status = NODE_STATUS_ERROR;
		goto send;
	}

	amap = amap_locate(amap_table, lba, &error);
	amap_table_unlock(amap_table);

	if (!amap) {
		if (!error)
			status = NODE_STATUS_AMAP_NOT_FOUND;
		else
			status = NODE_STATUS_ERROR;
		goto send;
	}

	amap_lock(amap);
	amap_check_csum(amap);
	if (atomic_test_bit_short(AMAP_META_DATA_ERROR, &amap->flags)) {
		amap_unlock(amap);
		status = NODE_STATUS_ERROR;
		goto send;
	}

	if (amap_needs_sync(amap, amap_spec.write_id))
		status = NODE_STATUS_AMAP_NEEDS_SYNC;
	else
		status = NODE_STATUS_OK;
	amap_unlock(amap);

send:
	raw->dxfer_len = 0;
	node_resp_msg(sock, raw, status);
	if (amap)
		amap_put(amap);
	if (amap_table)
		amap_table_put(amap_table);
	tdisk_put(tdisk);
}

static void
node_recv_cmd(struct node_sock *sock, struct raw_node_msg *raw)
{
#ifdef ENABLE_STATS
	uint32_t start_ticks;
#endif

	switch (raw->msg_cmd) {
	case NODE_MSG_UNREGISTER:
		node_master_register(sock, raw, 0, &recv_flags, recv_wait, &recv_queue_list, recv_queue_lock, 0);
		break;
	case NODE_MSG_AMAP_CHECK:
		node_recv_amap_check(sock, raw);
		break;
	case NODE_MSG_GENERIC_CMD:
		GLOB_TSTART(start_ticks);
		node_master_cmd_generic(sock, raw, 1);
		GLOB_TEND(node_master_cmd_generic_ticks, start_ticks);
		break;
	case NODE_MSG_PERSISTENT_RESERVE_OUT_CMD:
		node_master_cmd_persistent_reserve_out(sock, raw, 1);
		break;
	case NODE_MSG_READ_CMD:
		GLOB_TSTART(start_ticks);
		node_master_read_cmd(sock, raw, &recv_queue_list, recv_queue_lock, 1);
		GLOB_TEND(node_master_read_cmd_ticks, start_ticks);
		break;
	case NODE_MSG_READ_DATA:
		GLOB_TSTART(start_ticks);
		node_master_read_data(sock, raw, &recv_queue_list, recv_queue_lock);
		GLOB_TEND(node_master_read_data_ticks, start_ticks);
		break;
	case NODE_MSG_READ_DONE:
		GLOB_TSTART(start_ticks);
		node_master_read_done(sock, raw, &recv_queue_list, recv_queue_lock);
		GLOB_TEND(node_master_read_done_ticks, start_ticks);
		break;
	case NODE_MSG_WRITE_CMD:
		GLOB_TSTART(start_ticks);
		node_master_write_cmd(sock, raw, &recv_queue_list, recv_queue_lock, 1, 0);
		GLOB_TEND(node_master_write_cmd_ticks, start_ticks);
		break;
	case NODE_MSG_WRITE_MIRROR_CMD:
		GLOB_TSTART(start_ticks);
		node_master_write_cmd(sock, raw, &recv_queue_list, recv_queue_lock, 1, 1);
		GLOB_TEND(node_master_write_cmd_ticks, start_ticks);
		break;
	case NODE_MSG_XCOPY_READ:
		GLOB_TSTART(start_ticks);
		node_master_xcopy_read(sock, raw, &recv_queue_list, recv_queue_lock);
		GLOB_TEND(node_master_xcopy_read_ticks, start_ticks);
		break;
	case NODE_MSG_XCOPY_WRITE:
		GLOB_TSTART(start_ticks);
		node_master_xcopy_write(sock, raw, &recv_queue_list, recv_queue_lock);
		GLOB_TEND(node_master_xcopy_write_ticks, start_ticks);
		break;
	case NODE_MSG_MIRROR_WRITE_ERROR:
		node_mirror_write_error(sock, raw, &recv_queue_list, recv_queue_lock);
		break;
	case NODE_MSG_VERIFY_DATA:
		GLOB_TSTART(start_ticks);
		node_master_verify_data(sock, raw, &recv_queue_list, recv_queue_lock);
		GLOB_TEND(node_master_verify_data_ticks, start_ticks);
		break;
	case NODE_MSG_WRITE_COMP_DONE:
		GLOB_TSTART(start_ticks);
		node_master_write_comp_done(sock, raw, &recv_queue_list, recv_queue_lock);
		GLOB_TEND(node_master_write_comp_done_ticks, start_ticks);
		break;
	case NODE_MSG_WRITE_DONE:
		GLOB_TSTART(start_ticks);
		node_master_write_done(sock, raw, &recv_queue_list, recv_queue_lock);
		GLOB_TEND(node_master_write_done_ticks, start_ticks);
		break;
	case NODE_MSG_WRITE_POST_PRE:
		GLOB_TSTART(start_ticks);
		node_master_write_post_pre(sock, raw, &recv_queue_list, recv_queue_lock);
		GLOB_TEND(node_master_write_post_pre_ticks, start_ticks);
		break;
	case NODE_MSG_WRITE_DATA_UNALIGNED:
		GLOB_TSTART(start_ticks);
		node_master_write_data_unaligned(sock, raw, &recv_queue_list, recv_queue_lock);
		GLOB_TEND(node_master_write_data_unaligned_ticks, start_ticks);
		break;
	case NODE_MSG_WRITE_DATA:
		GLOB_TSTART(start_ticks);
		node_master_write_data(sock, raw, &recv_queue_list, recv_queue_lock);
		GLOB_TEND(node_master_write_data_ticks, start_ticks);
		break;
	case NODE_MSG_MIRROR_SETUP:
		node_mirror_setup(sock, raw);
		break;
	case NODE_MSG_MIRROR_REMOVE:
		node_mirror_remove(sock, raw);
		break;
	case NODE_MSG_PEER_SHUTDOWN:
		node_mirror_peer_shutdown(sock, raw);
		break;
	case NODE_MSG_MIRROR_SET_ROLE:
		node_mirror_set_role(sock, raw);
		break;
	case NODE_MSG_VDISK_UPDATE:
		node_mirror_update_vdisk_properties(sock, raw);
		break;
	case NODE_MSG_VDISK_RESIZE:
		node_mirror_vdisk_resize(sock, raw);
		break;
#if 0
	case NODE_MSG_MIRROR_RESYNC_START:
		node_mirror_resync_start(sock, raw);
		break;
#endif
	case NODE_MSG_MIRROR_RESYNC_DONE:
		node_mirror_resync_done(sock, raw);
		break;
	case NODE_MSG_MIRROR_STATE:
		node_mirror_state(sock, raw);
		break;
	case NODE_MSG_MIRROR_LOAD_DONE:
		node_mirror_load_done(sock, raw);
		break;
	case NODE_MSG_MIRROR_LOAD_ERROR:
		node_mirror_load_error(sock, raw);
		break;
	case NODE_MSG_REGISTRATION_CLEAR_SYNC:
		node_mirror_registration_clear_recv(sock, raw);
		break;
	case NODE_MSG_REGISTRATION_SYNC:
		node_mirror_registration_sync_recv(sock, raw);
		break;
	case NODE_MSG_RESERVATION_SYNC:
		node_mirror_reservation_sync_recv(sock, raw);
		break;
	default:
		debug_warn("Unknown node msg %d received\n", raw->msg_cmd);
		node_error_resp_msg(sock, raw, NODE_STATUS_INVALID_MSG);
		break;
	}
}

static int
node_recv_recv(struct node_sock *sock)
{
	int retval;
	struct raw_node_msg raw;

	while (1) {
		retval = node_sock_read(sock, &raw, sizeof(raw));
		if (retval != 0) {
			atomic_set_bit(NODE_COMM_CLEANUP, &sock->comm->flags);
			atomic_set_bit(MASTER_CLEANUP, &recv_flags);
			chan_wakeup_nointr(recv_wait);
			return -1;
		}

		if (unlikely(!node_msg_csum_valid(&raw))) {
			debug_warn("Received msg with invalid csum\n");
			node_sock_read_error(sock);
			atomic_set_bit(NODE_COMM_CLEANUP, &sock->comm->flags);
			atomic_set_bit(MASTER_CLEANUP, &recv_flags);
			chan_wakeup_nointr(recv_wait);
			return -1;
		}

		atomic_inc(&write_requests);
		node_recv_cmd(sock, &raw);
		atomic_dec(&write_requests);
		if (sock_state_error(sock)) {
			atomic_set_bit(NODE_COMM_CLEANUP, &sock->comm->flags);
			atomic_set_bit(MASTER_CLEANUP, &recv_flags);
			chan_wakeup_nointr(recv_wait);
			return -1;
		}
	}
	return 0;
}

static int
node_recv_accept(struct node_sock *recv_sock)
{
	struct node_sock *sock;
	struct node_comm *comm;
	uint32_t ipaddr;
	int error = 0, retval;
	int i = 0;

	while (1) {
		sock = __node_sock_alloc(NULL, node_recv_recv); 
		sock->lsock = sock_accept(recv_sock->lsock, sock, &error, &ipaddr);
		if (!sock->lsock || !atomic_read(&kern_inited)) {
			node_sock_free(sock, 1);
			if (error) {
				return -1;
			}
			return 0;
		}

		comm = node_comm_locate(node_rep_recv_hash, ipaddr, recv_root);
		sock->comm = comm;
		node_comm_lock(comm);
		retval = kernel_thread_create(node_sock_recv_thr, sock, sock->task, "ndrsock_%d", i);
		i++;
		if (unlikely(retval != 0)) {
			node_sock_free(sock, 1);
			node_comm_unlock(comm);
			return -1;
		}
		TAILQ_INSERT_TAIL(&comm->sock_list, sock, s_list);
		node_comm_unlock(comm);
	}
	return 0;
}

void
node_recv_exit(void)
{
	if (recv_cleanup_task) {
		kernel_thread_stop(recv_cleanup_task, &recv_cleanup_flags, recv_cleanup_wait, MASTER_EXIT);
		recv_cleanup_task = NULL;
	}

	if (recv_task) {
		wait_on_chan(recv_wait, !atomic_test_bit(MASTER_IN_CLEANUP, &recv_flags));
		kernel_thread_stop(recv_task, &recv_flags, recv_wait, MASTER_EXIT);
		recv_task = NULL;
	}

	if (recv_root) {
		node_root_comm_free(recv_root, &recv_queue_list, recv_queue_lock);
		node_comm_put(recv_root);
		recv_root = NULL;
	}

	if (recv_queue_lock) {
		mtx_free(recv_queue_lock);
		recv_queue_lock = NULL;
	}

	if (recv_cleanup_wait) { 
		wait_chan_free(recv_cleanup_wait);
		recv_cleanup_wait = NULL;
	}

	if (recv_wait) { 
		wait_chan_free(recv_wait);
		recv_wait = NULL;
	}
}

#ifdef FREEBSD 
static void node_cleanup_thr(void *data)
#else
static int node_cleanup_thr(void *data)
#endif
{
	for(;;) {

		wait_on_chan_timeout(recv_cleanup_wait, kernel_thread_check(&recv_cleanup_flags, MASTER_EXIT), 5000);
		node_check_timedout_msgs(node_rep_recv_hash, &recv_queue_list, recv_queue_lock, mirror_recv_timeout);
		if (kernel_thread_check(&recv_cleanup_flags, MASTER_EXIT))
			break;
	}
#ifdef FREEBSD 
	kproc_exit(0);
#else
	return 0;
#endif
}

#ifdef FREEBSD 
static void node_recv_thr(void *data)
#else
static int node_recv_thr(void *data)
#endif
{
	struct node_config *node_config = data;
	int retval;

	recv_root = node_comm_alloc(NULL, node_config->recv_ipaddr, node_config->node_ipaddr);
	retval = node_sock_bind(recv_root, node_recv_accept, RECEIVER_DATA_PORT, "ndsockrr");
	if (unlikely(retval != 0)) {
		debug_warn("node recv init failed\n");
		node_comm_put(recv_root);
		recv_root = NULL;
		atomic_set_bit(MASTER_BIND_ERROR, &recv_flags);
	}

	atomic_set_bit(MASTER_INITED, &recv_flags);
	chan_wakeup(recv_wait);
	while (!kernel_thread_check(&recv_flags, MASTER_EXIT)) {
		wait_on_chan_timeout(recv_wait, kernel_thread_check(&recv_flags, MASTER_EXIT) || atomic_test_bit(MASTER_CLEANUP, &recv_flags), 10000);
		if (unlikely(kernel_thread_check(&recv_flags, MASTER_EXIT)))
			break;
		if (atomic_test_bit(MASTER_CLEANUP, &recv_flags)) {
			atomic_set_bit(MASTER_IN_CLEANUP, &recv_flags);
			atomic_clear_bit(MASTER_CLEANUP, &recv_flags);
			if (unlikely(kernel_thread_check(&recv_flags, MASTER_EXIT))) {
				atomic_clear_bit(MASTER_IN_CLEANUP, &recv_flags);
				chan_wakeup(recv_wait);
				break;
			}
			if (recv_root)
				node_master_cleanup(recv_root, &recv_queue_list, recv_queue_lock);
			atomic_clear_bit(MASTER_IN_CLEANUP, &recv_flags);
			chan_wakeup(recv_wait);
		}
#if 0
		node_check_timedout_msgs(node_rep_recv_hash, &recv_queue_list, recv_queue_lock, mirror_recv_timeout);
#endif
	}
#ifdef FREEBSD 
	kproc_exit(0);
#else
	return 0;
#endif
}

int
node_recv_init(struct node_config *node_config)
{
	int retval;

	SET_NODE_TIMEOUT(node_config, mirror_recv_timeout, MIRROR_RECV_TIMEOUT_MIN, MIRROR_RECV_TIMEOUT_MAX);
	SET_NODE_TIMEOUT(node_config, mirror_send_timeout, MIRROR_SEND_TIMEOUT_MIN, MIRROR_SEND_TIMEOUT_MAX);
	SET_NODE_TIMEOUT(node_config, mirror_sync_timeout, MIRROR_SYNC_TIMEOUT_MIN, MIRROR_SYNC_TIMEOUT_MAX);
	SET_NODE_TIMEOUT(node_config, mirror_sync_recv_timeout, MIRROR_SYNC_RECV_TIMEOUT_MIN, MIRROR_SYNC_RECV_TIMEOUT_MAX);
	SET_NODE_TIMEOUT(node_config, mirror_sync_send_timeout, MIRROR_SYNC_SEND_TIMEOUT_MIN, MIRROR_SYNC_SEND_TIMEOUT_MAX);
	debug_info("mirror_recv_timeout %u\n", mirror_recv_timeout);
	debug_info("mirror_send_timeout %u\n", mirror_send_timeout);
	debug_info("mirror_sync_timeout %u\n", mirror_sync_timeout);
	debug_info("mirror_sync_recv_timeout %u\n", mirror_sync_recv_timeout);
	debug_info("mirror_sync_send_timeout %u\n", mirror_sync_send_timeout);
	debug_info("node recv ipaddr %u\n", node_config->recv_ipaddr);

	if (!node_config->recv_ipaddr)
		return 1;

	memcpy(&recv_config, node_config, sizeof(recv_config));
	if (recv_config.mirror_connect_timeout)
		recv_config.mirror_connect_timeout *= 1000; /* ms */
	else
		recv_config.mirror_connect_timeout = NODE_GET_SOCK_TIMEOUT; /* ms */

	recv_wait = wait_chan_alloc("node recv wait");
	recv_cleanup_wait = wait_chan_alloc("node recv cleanup wait");

	retval = kernel_thread_create(node_cleanup_thr, NULL, recv_cleanup_task, "rcvclnthr");
	if (unlikely(retval != 0)) {
		node_recv_exit();
		return -1;
	}

	retval = kernel_thread_create(node_recv_thr, node_config, recv_task, "rcvthr");
	if (unlikely(retval != 0)) {
		node_recv_exit();
		return -1;
	}

	wait_on_chan_interruptible(recv_wait, atomic_test_bit(MASTER_INITED, &recv_flags));
	recv_queue_lock = mtx_alloc("recv queue lock");
	TAILQ_INIT(&recv_queue_list);
	return 0;
}
