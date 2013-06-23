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
#include "node_sock.h"
#include "../common/cluster_common.h" 
#include "../common/commondefs.h"
#include "gdevq.h"
#include "tdisk.h"

static wait_chan_t *usr_wait;
static sx_t *usr_lock;
struct node_comm *usr_comm;
static kproc_t *usr_task;

int usr_flags;
enum {
	USR_INITED,
	USR_ERROR,
	USR_EXIT,
};

#ifdef FREEBSD 
static void node_usr_thr(void *data)
#else
static int node_usr_thr(void *data)
#endif
{
	int i, retval;

	usr_comm = node_comm_alloc(node_usr_hash, 16777343, 0); /* 127.0.0.1 */

	for (i = 0; i < MAX_GDEVQ_THREADS; i++) {
		retval = node_sock_connect(usr_comm, NULL, USR_MSG_PORT, "ndsockus");
		if (unlikely(retval != 0)) {
			atomic_set_bit(USR_ERROR, &usr_flags);
			break;
		}
		if ((i % 8) == 0)
			pause("psg", 50);
	}

	atomic_set_bit(USR_INITED, &usr_flags);
	chan_wakeup(usr_wait);
	wait_on_chan_interruptible(usr_wait, kernel_thread_check(&usr_flags, USR_EXIT));
#ifdef FREEBSD 
	kproc_exit(0);
#else
	return 0;
#endif
}

void
node_usr_exit(void)
{
	if (usr_task) {
		kernel_thread_stop(usr_task, &usr_flags, usr_wait, USR_EXIT);
		usr_task = NULL;
	}

	if (usr_wait) {
		wait_chan_free(usr_wait);
		usr_wait = NULL;
	}

	if (usr_lock) {
		sx_free(usr_lock);
		usr_lock = NULL;
	}

	if (usr_comm) {
		node_comm_put(usr_comm);
		usr_comm = NULL;
	}
}

int
node_usr_init(void)
{
	int retval;

	usr_wait = wait_chan_alloc("node usr wait");

	usr_lock = sx_alloc("node usr comm lock");

	retval = kernel_thread_create(node_usr_thr, NULL, usr_task, "usrthr");  
	if (unlikely(retval != 0)) {
		node_usr_exit();
		return -1;
	}

	wait_on_chan_interruptible(usr_wait, atomic_test_bit(USR_INITED, &usr_flags));
	if (atomic_test_bit(USR_ERROR, &usr_flags)) {
		node_usr_exit();
		return -1;
	}

	return 0;
}

int
node_usr_send_vdisk_deleted(uint32_t target_id, int status)
{
	struct usr_msg msg;
	struct node_sock *sock;
	int retval;

	if (node_type_client() || node_type_master())
		return 0;

	debug_check(!usr_comm);
	sock = node_comm_get_sock(usr_comm, NODE_GET_SOCK_TIMEOUT);
	if (!sock) {
		debug_warn("Cannot get a free sock\n");
		return USR_RSP_ERR;
	}

	bzero(&msg, sizeof(msg));
	msg.msg_rsp = status;
	msg.target_id = target_id;
	msg.msg_id = USR_MSG_VDISK_DELETED;

	retval = node_sock_write_data(sock, (void *)&msg, sizeof(msg));
	node_sock_finish(sock);
	if (unlikely(retval != 0)) {
		debug_warn("Cannot write %d bytes of data retval %d\n", (int)sizeof(msg), retval);
		return USR_RSP_ERR;
	}
	return USR_RSP_OK;

}

int
node_usr_send_job_completed(uint64_t job_id, int status)
{
	struct usr_msg msg;
	struct node_sock *sock;
	int retval;

	if (node_type_client() || node_type_master())
		return 0;

	debug_check(!usr_comm);
	sock = node_comm_get_sock(usr_comm, NODE_GET_SOCK_TIMEOUT);
	if (!sock) {
		debug_warn("Cannot get a free sock\n");
		return USR_RSP_ERR;
	}

	bzero(&msg, sizeof(msg));
	msg.msg_rsp = status;
	msg.job_id = job_id;
	msg.msg_id = USR_MSG_JOB_COMPLETED;

	retval = node_sock_write_data(sock, (void *)&msg, sizeof(msg));
	node_sock_finish(sock);
	if (unlikely(retval != 0)) {
		debug_warn("Cannot write %d bytes of data retval %d\n", (int)sizeof(msg), retval);
		return USR_RSP_ERR;
	}
	return USR_RSP_OK;
}

int
node_usr_send_bid_valid(int bid)
{
	struct usr_msg msg;
	struct node_sock *sock;
	int retval;

	debug_check(!usr_comm);
	sock = node_comm_get_sock(usr_comm, NODE_GET_SOCK_TIMEOUT);
	if (!sock) {
		debug_warn("Cannot get a free sock\n");
		return USR_RSP_ERR;
	}

	bzero(&msg, sizeof(msg));
	msg.target_id = bid;
	msg.msg_id = USR_MSG_BID_VALID;

	retval = node_sock_write_data(sock, (void *)&msg, sizeof(msg));
	if (unlikely(retval != 0)) {
		node_sock_finish(sock);
		debug_warn("Cannot write %d bytes of data retval %d\n", (int)sizeof(msg), retval);
		return USR_RSP_ERR;
	}

	retval = node_sock_read(sock, &msg, sizeof(msg));
	node_sock_finish(sock);

	if (unlikely(retval != 0)) {
		debug_warn("Cannot read from sock, retval %d\n", retval);
		return USR_RSP_ERR;
	}
	debug_info("msg rsp %d\n", msg.msg_rsp);
	return msg.msg_rsp;
}

void
node_usr_notify_msg(int notify_type, uint32_t target_id, struct usr_notify *notify_msg)
{
	struct usr_msg *msg;
	struct node_sock *sock;

	debug_check(!usr_comm);
	sock = node_comm_get_sock(usr_comm, NODE_GET_SOCK_TIMEOUT);
	if (!sock) {
		debug_warn("Cannot get a free sock\n");
		return;
	}

	msg = &notify_msg->msg; 
	msg->msg_id = USR_MSG_NOTIFY;
	msg->target_id = target_id;
	notify_msg->notify_type = notify_type;
	node_sock_write_data(sock, (void *)notify_msg, sizeof(*notify_msg));
	node_sock_finish(sock);
}

int
node_usr_send_vdisk_attached(struct tdisk *tdisk)
{
	struct usr_msg msg;
	struct node_sock *sock;
	int retval;

	debug_check(!usr_comm);
	sock = node_comm_get_sock(usr_comm, NODE_GET_SOCK_TIMEOUT);
	if (!sock) {
		debug_warn("Cannot get a free sock\n");
		return USR_RSP_ERR;
	}

	bzero(&msg, sizeof(msg));
	msg.iscsi_tid = tdisk->iscsi_tid;
	msg.vhba_id = tdisk->vhba_id;
	msg.target_id = tdisk->target_id;
	msg.msg_id = USR_MSG_ATTACH_INTERFACE;

	retval = node_sock_write_data(sock, (void *)&msg, sizeof(msg));
	node_sock_finish(sock);
	if (unlikely(retval != 0)) {
		debug_warn("Cannot write %d bytes of data retval %d\n", (int)sizeof(msg), retval);
		return USR_RSP_ERR;
	}
	return USR_RSP_OK;
}

int
node_usr_fence_node(void)
{
	struct usr_msg msg;
	struct node_sock *sock;
	int retval;

	debug_info("fencing peer node\n");
	debug_check(!usr_comm);
	sock = node_comm_get_sock(usr_comm, NODE_GET_SOCK_TIMEOUT);
	if (!sock) {
		debug_warn("Cannot get a free sock\n");
		return USR_RSP_ERR;
	}

	bzero(&msg, sizeof(msg));
	msg.msg_id = USR_MSG_FENCE_NODE;

	retval = node_sock_write_data(sock, (void *)&msg, sizeof(msg));
	if (unlikely(retval != 0)) {
		debug_warn("Cannot write %d bytes of data retval %d\n", (int)sizeof(msg), retval);
		node_sock_finish(sock);
		return USR_RSP_ERR;
	}

	retval = node_sock_read(sock, &msg, sizeof(msg));
	node_sock_finish(sock);

	if (unlikely(retval != 0)) {
		debug_warn("Cannot read from sock, retval %d\n", retval);
		return USR_RSP_ERR;
	}
	debug_info("msg rsp %d\n", msg.msg_rsp);
	return msg.msg_rsp;
}
 
int
node_usr_send_mirror_check(uint32_t mirror_ipaddr)
{
	struct usr_msg msg;
	struct node_sock *sock;
	int retval;

	if (node_type_client() || node_type_master())
		return USR_RSP_ERR;

	debug_info("send check for %u\n", mirror_ipaddr);
	debug_check(!usr_comm);
	sock = node_comm_get_sock(usr_comm, NODE_GET_SOCK_TIMEOUT);
	if (!sock) {
		debug_warn("Cannot get a free sock\n");
		return USR_RSP_ERR;
	}

	bzero(&msg, sizeof(msg));
	msg.mirror_ipaddr = mirror_ipaddr;
	msg.msg_id = USR_MSG_MIRROR_CHECK;

	retval = node_sock_write_data(sock, (void *)&msg, sizeof(msg));
	if (unlikely(retval != 0)) {
		debug_warn("Cannot write %d bytes of data retval %d\n", (int)sizeof(msg), retval);
		node_sock_finish(sock);
		return USR_RSP_ERR;
	}

	retval = node_sock_read(sock, &msg, sizeof(msg));
	node_sock_finish(sock);

	if (unlikely(retval != 0)) {
		debug_warn("Cannot read from sock, retval %d\n", retval);
		return USR_RSP_ERR;
	}
	debug_info("msg rsp %d\n", msg.msg_rsp);
	return msg.msg_rsp;
}
