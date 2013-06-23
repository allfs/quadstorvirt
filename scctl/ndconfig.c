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

#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <tlclntapi.h>
#include "../common/cluster_common.h"

#define atomic_test_bit(b, p)                                           \
({                                                                      \
        int __ret;                                                      \
        __ret = ((volatile int *)p)[b >> 5] & (1 << (b & 0x1f));        \
        __ret;                                                          \
})

void
print_usage(void)
{
	fprintf(stdout, "ndconfig usage: \n");
	fprintf(stdout, "With no arguments prints a clustering node's configuration\n");
	fprintf(stdout, "ndconfig -h -s -b <Disk ID> to mark a disk as the HA disk\n");
	fprintf(stdout, "ndconfig -h -x -b <Disk ID> to unmark a disk as the HA disk\n");
	fprintf(stdout, "ndconfig -u -s -b <Disk ID> to enable unmap\n");
	fprintf(stdout, "ndconfig -u -x -b <Disk ID> to disable unmap\n");
	exit(0);
}

void
print_node_role(struct node_config *node_config)
{
	switch (node_config->node_role) {
	case NODE_ROLE_UNKNOWN:
		fprintf(stdout, "%18s: Unknown\n", "Node Role");
		break;
	case NODE_ROLE_MASTER:
		fprintf(stdout, "%18s: Master\n", "Node Role");
		break;
	case NODE_ROLE_STANDBY:
		fprintf(stdout, "%18s: Standby\n", "Node Role");
		break;
	}
}

void
print_sync_status(struct node_config *node_config)
{
	switch (node_config->sync_status) {
	case NODE_SYNC_UNKNOWN:
		fprintf(stdout, "%18s: Unknown\n", "Sync Status");
		break;
	case NODE_SYNC_INPROGRESS:
		fprintf(stdout, "%18s: Sync Inprogress\n", "Sync Status");
		break;
	case NODE_SYNC_ERROR:
		fprintf(stdout, "%18s: Sync Error\n", "Sync Status");
		break;
	case NODE_SYNC_NEED_RESYNC:
		fprintf(stdout, "%18s: Need Resync\n", "Sync Status");
		break;
	case NODE_SYNC_DONE:
		fprintf(stdout, "%18s: Sync Done\n", "Sync Status");
		break;
	default:
		break;
	}
}

void
print_nodes(struct node_config *node_config)
{
	int i, max;
	struct sockaddr_in  in_addr;

	max = sizeof(node_config->nodes) / sizeof(node_config->nodes[0]);
	memset(&in_addr, 0, sizeof(in_addr));
	for (i = 0; i < max; i++) {
		if (!node_config->nodes[i])
			break;
		if (!i) {
			fprintf(stdout, "%18s:", "Nodes");
		}
		in_addr.sin_addr.s_addr = node_config->nodes[i];
		if (i && (i % 5) == 0)
			fprintf(stdout, "\n%18s:", " ");

		fprintf(stdout, " %s", inet_ntoa(in_addr.sin_addr));
	}

	if (!i)
		return;
	fprintf(stdout, "\n");
}

void
print_node_master(struct node_config *node_config)
{
	fprintf(stdout, "%18s: Client\n", "Node Type");
	fprintf(stdout, "%18s: %s\n", "Controller", node_config->controller_host);
	fprintf(stdout, "%18s: %s\n", "Node", node_config->node_host);
	fprintf(stdout, "%18s: %s\n", "HA Peer", node_config->ha_host);
	fprintf(stdout, "%18s: %s\n", "HA Bind", node_config->ha_bind_host);
	if (node_config->node_flags == MASTER_INITED)
		fprintf(stdout, "%18s: Master Inited\n", "Node Status");
	else if (node_config->node_flags == MASTER_BIND_ERROR)
		fprintf(stdout, "%18s: Master Bind Error\n", "Node Status");
	print_node_role(node_config);
	if (node_config->ha_host[0])
		print_sync_status(node_config);
	if (node_config->node_role == NODE_ROLE_MASTER)
		print_nodes(node_config);
}
void
print_node_client(struct node_config *node_config)
{
	fprintf(stdout, "%18s: Client\n", "Node Type");
	fprintf(stdout, "%18s: %s\n", "Controller", node_config->controller_host);
	fprintf(stdout, "%18s: %s\n", "Node", node_config->node_host);
	if (node_config->node_flags == CLIENT_INITED)
		fprintf(stdout, "%18s: Client Inited\n", "Node Status");
	else if (node_config->node_flags == CLIENT_CONNECT_ERROR)
		fprintf(stdout, "%18s: Client connect Error\n", "Node Status");

}

void
print_node_receiver(struct node_config *node_config)
{
	fprintf(stdout, "%18s: Mirror Recv\n", "Node Type");
	fprintf(stdout, "%18s: %s\n", "Recv Address", node_config->recv_host);
	if (node_config->recv_flags == MASTER_INITED)
		fprintf(stdout, "%18s: Recv Inited\n", "Node Status");
	else if (node_config->recv_flags == MASTER_BIND_ERROR)
		fprintf(stdout, "%18s: Recv Bind Error\n", "Node Status");
}

void
print_node_controller(struct node_config *node_config)
{

	fprintf(stdout, "%18s: Controller\n", "Node Type");
	fprintf(stdout, "%18s: %s\n", "Controller", node_config->controller_host);
	fprintf(stdout, "%18s: %s\n", "HA Peer", node_config->ha_host);
	fprintf(stdout, "%18s: %s\n", "HA Bind", node_config->ha_bind_host);
	if (node_config->node_flags == MASTER_INITED)
		fprintf(stdout, "%18s: Controller Inited\n", "Node Status");
	else if (node_config->node_flags == MASTER_BIND_ERROR)
		fprintf(stdout, "%18s: Controller Bind Error\n", "Node Status");
	print_node_role(node_config);

	if (node_config->ha_host[0])
		print_sync_status(node_config);

	if (node_config->node_role == NODE_ROLE_MASTER)
		print_nodes(node_config);
}

void
print_node_config(void)
{
	struct node_config node_config;
	int retval;

	retval = tl_ioctl(TLTARGIOCNODESTATUS, &node_config);
	if (retval != 0) {
		fprintf(stderr, "Cannot get node status %d:%s\n", errno, strerror(errno));
		exit(1);
	}

	if (atomic_test_bit(NODE_TYPE_CONTROLLER, &node_config.node_type))
		print_node_controller(&node_config);
	else if (atomic_test_bit(NODE_TYPE_MASTER, &node_config.node_type))
		print_node_master(&node_config);
	else if (atomic_test_bit(NODE_TYPE_CLIENT, &node_config.node_type))
		print_node_client(&node_config);

	if (atomic_test_bit(NODE_TYPE_RECEIVER, &node_config.node_type))
		print_node_receiver(&node_config);
}

int main(int argc, char *argv[])
{
	char reply[512];
	int c, retval;
	int ha = 0, mark = 0, discard = 0;
	uint32_t bid = 0;

	if (geteuid() != 0) {
		fprintf(stderr, "This program can only be run as root\n");
		exit(1);
	}

	while ((c = getopt(argc, argv, "b:hsux")) != -1) {
		switch (c) {
		case 'u':
			discard = 1;
			break;
		case 'h':
			ha = 1;
			break;
		case 's':
			mark = 1;
			break;
		case 'x':
			mark = 0;
			break;
		case 'b':
			bid = atoi(optarg);
			break;
		default:
			print_usage();
			break;
		}
	}

	if (ha) {
		if (!bid)
			print_usage();

		retval = tl_client_bdev_config(bid, MSG_ID_HA_CONFIG, mark, reply);
		if (retval != 0) {
			fprintf(stderr, "Setting disk with id %u as HA disk failed\n", bid);
			fprintf(stderr, "Message from server is - %s\n", reply);
			exit(1);
		}
	} else if (discard) {
		if (!bid)
			print_usage();

		retval = tl_client_bdev_config(bid, MSG_ID_UNMAP_CONFIG, mark, reply);
		if (retval != 0) {
			fprintf(stderr, "Setting unmap property for disk with id%u failed\n", bid);
			fprintf(stderr, "Message from server is - %s\n", reply);
			exit(1);
		}
	} else {
		print_node_config();
	}
	return 0;
}

