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

#ifndef QS_NODE_SOCK_H_
#define QS_NODE_SOCK_H_
#include "cluster.h"

#ifdef FREEBSD 
void node_sock_recv_thr(void *data);
#else
int node_sock_recv_thr(void *data);
#endif
int node_sock_read(struct node_sock *node_sock, void *buf, int len);
int node_sock_read_nofail(struct node_sock *node_sock, void *buf, int len);
void node_sock_state_change(void *priv, int newstate);
void node_sock_read_avail(void *priv);
void node_sock_write_avail(void *priv);
int node_sock_connect(struct node_comm *comm, int (*sock_callback) (struct node_sock *), uint16_t port, char *name);
int node_sock_bind(struct node_comm *comm, int (*sock_callback) (struct node_sock *), uint16_t, char *name);
void node_sock_wait_for_write(struct node_sock *sock);
void node_sock_start(struct node_sock *sock);
void node_sock_end(struct node_sock *sock);

static inline int
sock_state_error(struct node_sock *sock)
{
	return (atomic_test_bit(NODE_SOCK_READ_ERROR, &sock->flags) || sock->state == SOCK_STATE_CLOSED);
}

#if 0
#define node_sock_start(skt) do {} while (0)
#define node_sock_end(skt) do {} while (0)
#endif
#endif
