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

#include "node_sock.h"
#include "../common/cluster_common.h"
#include "ddblock.h"

void
node_sock_start(struct node_sock *sock)
{
	sock_nopush(sock->lsock, 1);
}

void
node_sock_end(struct node_sock *sock)
{
	sock_nopush(sock->lsock, 0);
}

#define NODE_SOCK_TIMEOUT	20000

static void
node_sock_wait_for_read_timeout(struct node_sock *sock)
{
#ifdef ENABLE_STATS
	uint32_t start_ticks;
#endif
	GLOB_TSTART(start_ticks);
	if (sock_has_read_data(sock->lsock)) {
		atomic_set_bit(NODE_SOCK_DATA, &sock->flags);
		GLOB_TEND(wait_for_read_timeout_ticks, start_ticks);
		return;
	}

	wait_on_chan_timeout(sock->sock_wait, atomic_test_bit(NODE_SOCK_DATA, &sock->flags) || atomic_test_bit(NODE_SOCK_EXIT, &sock->flags) || sock_state_error(sock), NODE_SOCK_TIMEOUT);
	GLOB_TEND(wait_for_read_timeout_ticks, start_ticks);
}

static inline void
node_sock_wait_for_read(struct node_sock *sock)
{
	if (sock_has_read_data(sock->lsock)) {
		atomic_set_bit(NODE_SOCK_DATA, &sock->flags);
		return;
	}

	wait_on_chan_check(sock->sock_wait, atomic_test_bit(NODE_SOCK_DATA, &sock->flags) || atomic_test_bit(NODE_SOCK_EXIT, &sock->flags) || sock_state_error(sock));
}

uint64_t sock_reads;
int
node_sock_read(struct node_sock *sock, void *buf, int dxfer_len)
{
	uint8_t *buffer = buf;
	int retval;

	while (1) {
		if (atomic_test_bit(NODE_SOCK_EXIT, &sock->flags) || sock_state_error(sock))
			return -1;
		atomic_clear_bit(NODE_SOCK_DATA, &sock->flags);
		retval = sock_read(sock->lsock, buffer, dxfer_len);
		if (unlikely(retval < 0)) {
			node_sock_read_error(sock);
			return retval;
		}

		GLOB_INC(sock_reads, retval);
		dxfer_len -= retval;
		if (!dxfer_len)
			return 0;
		buffer += retval;
		node_sock_wait_for_read_timeout(sock);
	}
}

int
node_sock_read_nofail(struct node_sock *sock, void *buf, int dxfer_len)
{
	uint8_t *buffer = buf;
	int retval;

	while (1) {
		if (atomic_test_bit(NODE_SOCK_EXIT, &sock->flags) || sock_state_error(sock))
			return -1;
		atomic_clear_bit(NODE_SOCK_DATA, &sock->flags);
		retval = sock_read(sock->lsock, buffer, dxfer_len);
		if (unlikely(retval < 0)) {
			node_sock_read_error(sock);
			return retval;
		}

		GLOB_INC(sock_reads, retval);
		dxfer_len -= retval;
		if (!dxfer_len)
			return 0;
		buffer += retval;
		node_sock_wait_for_read_timeout(sock);
		if (!atomic_test_bit(NODE_SOCK_DATA, &sock->flags)) {
			node_sock_read_error(sock);
			return -1;
		}
	}
}

void
node_sock_state_change(void *priv, int newstate)
{
	struct node_sock *sock = priv;
	unsigned long flags;

	chan_lock_intr(sock->sock_wait, &flags);
	if (sock->state != newstate) {
		sock->state = newstate;
		atomic_set_bit(NODE_SOCK_DATA, &sock->flags);
		chan_wakeup_unlocked(sock->sock_wait);
	}
	chan_unlock_intr(sock->sock_wait, &flags);
}

void
node_sock_read_avail(void *priv)
{
	struct node_sock *sock = priv;
	unsigned long flags;

	chan_lock_intr(sock->sock_wait, &flags);
	atomic_set_bit(NODE_SOCK_DATA, &sock->flags);
	chan_wakeup_unlocked(sock->sock_wait);
	chan_unlock_intr(sock->sock_wait, &flags);
}

void
node_sock_wait_for_write(struct node_sock *sock)
{
	unsigned long flags;
#ifdef ENABLE_STATS
	uint32_t start_ticks;
#endif
	GLOB_TSTART(start_ticks);

	chan_lock_intr(sock->sock_wait, &flags);
	if (sock_has_write_space(sock->lsock)) {
		chan_unlock_intr(sock->sock_wait, &flags);
		GLOB_TEND(wait_for_write_ticks, start_ticks);
		return;
	}
	atomic_set_bit(NODE_SOCK_WRITE_WAIT, &sock->flags);
	chan_unlock_intr(sock->sock_wait, &flags);

	wait_on_chan_timeout(sock->sock_wait, !atomic_test_bit(NODE_SOCK_WRITE_WAIT, &sock->flags) || atomic_test_bit(NODE_SOCK_EXIT, &sock->flags) || sock_state_error(sock), NODE_SOCK_TIMEOUT);
	GLOB_INC(wait_for_write_count, 1);
	GLOB_TEND(wait_for_write_ticks, start_ticks);
}

void
node_sock_write_avail(void *priv)
{
	struct node_sock *sock = priv;
	unsigned long flags;

	chan_lock_intr(sock->sock_wait, &flags);
	if (atomic_test_bit(NODE_SOCK_WRITE_WAIT, &sock->flags)) {
		atomic_clear_bit(NODE_SOCK_WRITE_WAIT, &sock->flags);
		chan_wakeup_unlocked(sock->sock_wait);
	}
	chan_unlock_intr(sock->sock_wait, &flags);
}

int
node_sock_connect(struct node_comm *comm, int (*sock_callback) (struct node_sock *), uint16_t port, char *name)
{
	struct node_sock *sock;
	int retval;

	sock = node_sock_alloc(comm, sock_callback, NULL, name);
	if (unlikely(!sock)) {
		debug_warn("Cannot create sock for type %s\n", name);
		return -1;
	}

	retval = sock_connect(sock->lsock, comm->controller_ipaddr, comm->node_ipaddr, port);
	if (unlikely(retval != 0)) {
		debug_warn("sock connect failed with error %d\n", retval);
		TAILQ_REMOVE(&comm->sock_list, sock, s_list);
		node_sock_free(sock, 1);
		return -1;
	}

	return 0;
}

int
node_sock_bind(struct node_comm *comm, int (*sock_callback) (struct node_sock *), uint16_t port, char *name)
{
	struct node_sock *sock;
	int retval;

	sock = node_sock_alloc(comm, sock_callback, NULL, name);
	if (unlikely(!sock)) {
		debug_warn("Cannot create sock for type %s\n", name);
		return -1;
	}

	retval = sock_bind(sock->lsock, comm->node_ipaddr, port);
	if (unlikely(retval != 0)) {
		debug_warn("sock bind failed with error %d\n", retval);
		TAILQ_REMOVE(&comm->sock_list, sock, s_list);
		node_sock_free(sock, 1);
		return -1;
	}

	return 0;
}

#ifdef FREEBSD 
void node_sock_recv_thr(void *data)
#else
int node_sock_recv_thr(void *data)
#endif
{
	struct node_sock *sock = data;

	__sched_prio(curthread, QS_PRIO_INOD);

	thread_start();

	for (;;) {
		wait_on_chan_intr(sock->sock_wait, atomic_test_bit(NODE_SOCK_DATA, &sock->flags) || kernel_thread_check(&sock->flags, NODE_SOCK_EXIT));

		if (kernel_thread_check(&sock->flags, NODE_SOCK_EXIT))
			break;

		atomic_clear_bit(NODE_SOCK_DATA, &sock->flags);
		if (sock_state_error(sock) || atomic_test_bit(NODE_SOCK_EXIT, &sock->flags))
			continue;
		(*sock->sock_callback) (sock);
	}

	thread_end();
#ifdef FREEBSD 
	kproc_exit(0);
#else
	return 0;
#endif
}
