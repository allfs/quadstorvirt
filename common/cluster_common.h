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

#ifndef QS_CLUSTER_COMMON_H_
#define QS_CLUSTER_COMMON_H_

struct node_spec {
	char sys_rid[40];
	char host[16]; /* dotted */
	uint32_t ipaddr; /* V4 address only */
	uint8_t node_type;
};

#define MAX_CLUSTER_NODES		8 /* Including ourselves */
#define NODE_CONTROLLER_RECV_PORT	9950
#define NODE_CLIENT_RECV_PORT		9951
#define CONTROLLER_DATA_PORT		9952
#define NODE_MIRROR_RECV_PORT		9953
#define NODE_CLIENT_NOTIFY_PORT		9954
#define RECEIVER_DATA_PORT		9955
#define CONTROLLER_SYNC_PORT		9956
#define USR_MSG_PORT			9957


struct cluster_spec {
	struct node_spec our_spec;
	struct node_spec controller_spec;
	struct node_spec nodes[MAX_CLUSTER_NODES];
	int max_nodes;
};

enum {
	NODE_TYPE_CLIENT 	= 0x1,
	NODE_TYPE_CONTROLLER	= 0x2,
	NODE_TYPE_MASTER	= 0x4,
	NODE_TYPE_FOREIGN	= 0x8,
	NODE_TYPE_RECEIVER	= 0x10,
};

enum {
	NODE_SYNC_UNKNOWN,
	NODE_SYNC_INPROGRESS,
	NODE_SYNC_ERROR,
	NODE_SYNC_NEED_RESYNC,
	NODE_SYNC_DONE,
};

enum {
	NODE_ROLE_UNKNOWN,
	NODE_ROLE_MASTER,
	NODE_ROLE_STANDBY,
};

enum {
	MASTER_INITED,
	MASTER_IN_CLEANUP,
	MASTER_CLEANUP,
	MASTER_BIND_ERROR,
	MASTER_EXIT,
};

enum {
	CLIENT_INITED,
	CLIENT_CONNECT_ERROR,
	CLIENT_RECV_INITED,
	CLIENT_RECV_BIND_ERROR,
	CLIENT_EXIT,
	CLIENT_RECV_EXIT,
};

#endif
