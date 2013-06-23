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
#include <tlsrvapi.h>
#include <pthread.h> 

extern struct blist bdev_list;
static pthread_t nc_thread_id;
uint32_t mirror_recv_timeout;
uint32_t mirror_connect_timeout = MIRROR_CONNECT_TIMEOUT_MIN;
uint32_t mirror_send_timeout;
uint32_t mirror_sync_timeout;
uint32_t mirror_sync_recv_timeout;
uint32_t mirror_sync_send_timeout;
char recv_host[16];
int node_recv_inited;


extern struct tdisk_info * find_tdisk(uint32_t target_id);

extern struct clone_info_list clone_info_list;

static void
node_msg_handle_clone_status(struct tl_comm *comm, struct tl_msg *msg)
{
	struct mirror_spec *mirror_spec;
	char errmsg[256];
	struct clone_info *clone_info, *ret = NULL;

	if (msg->msg_len < sizeof(*mirror_spec)) {
		node_resp_error(comm, msg);
		return;
	}

	mirror_spec = (struct mirror_spec *)(msg->msg_data);

	TAILQ_FOREACH(clone_info, &clone_info_list, c_list) {
		if (strcmp(clone_info->dest, mirror_spec->clone_tdisk))
			continue;
		ret = clone_info;
		break;
	}

	if (!ret) {
		sprintf(errmsg, "Destination VDisk %s not found\n", mirror_spec->dest_tdisk);
		node_resp_error_msg(comm, msg, errmsg);
		return;
	}

	if (clone_info->status == CLONE_STATUS_ERROR) {
		sprintf(errmsg, "Cloning failed for destination VDisk %s\n", mirror_spec->dest_tdisk);
		node_resp_error(comm, msg);
		return;
	}

	if (clone_info->status == CLONE_STATUS_SUCCESSFUL) {
		node_resp_data(comm, msg);
	}
	else {
		node_resp_status(comm, msg, MSG_RESP_INPROGRESS); 
	}
}

static void
node_msg_handle_clone(struct tl_comm *comm, struct tl_msg *msg)
{
	struct mirror_spec *mirror_spec;
	char errmsg[256];
	int retval;

	if (msg->msg_len < sizeof(*mirror_spec)) {
		node_resp_error(comm, msg);
		return;
	}

	mirror_spec = (struct mirror_spec *)(msg->msg_data);

	retval = __tl_server_start_clone(mirror_spec->dest_tdisk, mirror_spec->clone_tdisk, mirror_spec->dest_group, errmsg);
	if (retval != 0) {
		node_resp_error_msg(comm, msg, errmsg);
		return;
	}
	node_resp_data(comm, msg);
}

static void
node_msg_handle_new_vdisk(struct tl_comm *comm, struct tl_msg *msg)
{
	struct mirror_spec *mirror_spec;
	struct tdisk_info *dest_tdisk;
	struct group_info *dest_group;
	char errmsg[256];

	if (msg->msg_len < sizeof(*mirror_spec)) {
		node_resp_error(comm, msg);
		return;
	}

	mirror_spec = (struct mirror_spec *)(msg->msg_data);
	errmsg[0] = 0;

	dest_tdisk = find_tdisk_by_name(mirror_spec->dest_tdisk);
	dest_group = find_group_by_name(mirror_spec->dest_group);
	if (!dest_group) {
		sprintf(errmsg, "Error cannot find Dest group %s\n", mirror_spec->dest_group);
		node_resp_error_msg(comm, msg, errmsg);
		return;
	}

	if (!dest_tdisk) {
		dest_tdisk = add_target(dest_group, mirror_spec->dest_tdisk, mirror_spec->size, mirror_spec->lba_shift, mirror_spec->enable_deduplication, mirror_spec->enable_compression, mirror_spec->enable_verify, mirror_spec->force_inline, mirror_spec->src_serialnumber, errmsg, !mirror_spec->attach, &mirror_spec->iscsiconf);
		if (!dest_tdisk) {
			node_resp_error_msg(comm, msg, errmsg);
			return;
		}
	}
	else {
		if (memcmp(dest_tdisk->serialnumber, mirror_spec->src_serialnumber, sizeof(dest_tdisk->serialnumber))) {
			sprintf(errmsg, "Dest exists, but mismatch in serialnumber src %.32s dest %.32s", mirror_spec->src_serialnumber, dest_tdisk->serialnumber);
			node_resp_error_msg(comm, msg, errmsg);
			return;
		}

		if (dest_tdisk->disabled) {
			sprintf(errmsg, "VDisk %s is being deleted\n", dest_tdisk->name);
			node_resp_error_msg(comm, msg, errmsg);
			return;
		}

		if (dest_group != dest_tdisk->group) {
			sprintf(errmsg, "Mismatch in pool, VDisk's pool is %s\n", dest_group->name);
			node_resp_error_msg(comm, msg, errmsg);
			return;
		}

		if (dest_tdisk->size != mirror_spec->size) {
			sprintf(errmsg, "Dest exists, but mismatch in size src %llu dest %llu", (unsigned long long)mirror_spec->size, (unsigned long long)dest_tdisk->size);
			node_resp_error_msg(comm, msg, errmsg);
			return;
		}
	}


	mirror_spec->dest_target_id = dest_tdisk->target_id;
	memcpy(mirror_spec->dest_serialnumber, dest_tdisk->serialnumber, sizeof(dest_tdisk->serialnumber)); 
	node_resp_data(comm, msg);
}

static void
node_recv_process_request(int clientfd, struct sockaddr_in *client_addr)
{
	struct tl_comm comm;
	struct tl_msg *msg;

	comm.sockfd = clientfd;

	msg = tl_msg_recv_message(&comm);

	if (!msg) {
		close(clientfd);
		return;
	}

	switch (msg->msg_id) {
	case NODE_MSG_CLONE:
		pthread_mutex_lock(&daemon_lock);
		node_msg_handle_clone(&comm, msg);
		pthread_mutex_unlock(&daemon_lock);
		break;
	case NODE_MSG_CLONE_STATUS:
		pthread_mutex_lock(&daemon_lock);
		node_msg_handle_clone_status(&comm, msg);
		pthread_mutex_unlock(&daemon_lock);
		break;
	case NODE_MSG_NEW_VDISK:
		pthread_mutex_lock(&daemon_lock);
		node_msg_handle_new_vdisk(&comm, msg);
		pthread_mutex_unlock(&daemon_lock);
		break;
	}
}

static void *
node_recv_thread(void *arg)
{
	int sockfd, clientfd;
	struct sockaddr_in in_addr, client_addr;
	int reuse = 1, opt, err;
	socklen_t addr_len;
	in_addr_t ipaddr;

	if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		DEBUG_ERR_SERVER("Cannot create recv thread socket\n");
		pthread_exit(0);
	}

	if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(int)) == -1) {
		DEBUG_ERR_SERVER("Cannot set recv thread sockopt SO_REUSEADDR\n");
		close(sockfd);
		pthread_exit(0);
	}

	ipaddr = inet_addr(recv_host);
	if (ipaddr == INADDR_NONE) {
		DEBUG_ERR_SERVER("Invalid recv address specified %s\n", recv_host);
		close(sockfd);
		pthread_exit(0);
	}
	memset(&in_addr, 0, sizeof(struct sockaddr_in));
	in_addr.sin_family = AF_INET;
	in_addr.sin_port = htons(NODE_MIRROR_RECV_PORT);
	in_addr.sin_addr.s_addr = ipaddr;
 
	if (bind(sockfd, (struct sockaddr *)&in_addr, sizeof(in_addr)) == -1) {
		DEBUG_ERR_SERVER("Cannot bind to addr %s\n", recv_host);
		close(sockfd);
		pthread_exit(0);
	}

	if (listen(sockfd, 10) == -1) {
		DEBUG_ERR_SERVER("Cannot listen on recv port\n");
		close(sockfd);
		pthread_exit(0);
	}

	while (1) {
		addr_len = sizeof(struct sockaddr_in);
		if ((clientfd = accept(sockfd, (struct sockaddr *)&client_addr, &addr_len)) == -1) {
			switch (errno) {
			case EINTR:
			case ECONNABORTED:
				break;
			default:
				goto out;
			}
			continue;
		}

		opt = 1;
		err = setsockopt(clientfd, IPPROTO_TCP, TCP_NODELAY, &opt, sizeof(opt));
		if (err) {
			DEBUG_WARN_SERVER("Failed to set sock opt for %d errno %d %s\n", clientfd, errno, strerror(errno));
			close(clientfd);
			continue;
		}

		node_recv_process_request(clientfd, &client_addr);
	}
out:
	pthread_exit(0);
}

#define NODE_RECV_CONFIG_FILE "/quadstor/etc/ndrecv.conf"

static int
node_recv_read_config(void)
{
	FILE *fp;
	char buf[256];
	char *tmp, *key, *val;

	fp = fopen(NODE_RECV_CONFIG_FILE, "r");
	if (!fp)
		return -1;

	while (fgets(buf, sizeof(buf), fp) != NULL) {
		tmp = strchr(buf, '#');
		if (tmp)
			*tmp = 0;
		tmp = strchr(buf, '\n');
		if (tmp)
			*tmp = 0;
		tmp = strchr(buf, '=');
		if (!tmp)
			continue;

		*tmp = 0;
		tmp++;

		key = strip_space(buf);
		val = strip_space(tmp);

		PARSE_IPADDR(key, val, "RecvAddr", recv_host);

		PARSE_TIMEOUT(key, val, "MirrorRecvTimeout", mirror_recv_timeout, MIRROR_RECV_TIMEOUT_MIN, MIRROR_RECV_TIMEOUT_MAX);
		PARSE_TIMEOUT(key, val, "MirrorConnectTimeout", mirror_connect_timeout, MIRROR_CONNECT_TIMEOUT_MIN, MIRROR_CONNECT_TIMEOUT_MAX);
		PARSE_TIMEOUT(key, val, "MirrorSendTimeout", mirror_send_timeout, MIRROR_SEND_TIMEOUT_MIN, MIRROR_SEND_TIMEOUT_MAX);
		PARSE_TIMEOUT(key, val, "MirrorSyncTimeout", mirror_sync_timeout, MIRROR_SYNC_TIMEOUT_MIN, MIRROR_SYNC_TIMEOUT_MAX);
		PARSE_TIMEOUT(key, val, "MirrorSyncRecvTimeout", mirror_sync_recv_timeout, MIRROR_SYNC_RECV_TIMEOUT_MIN, MIRROR_SYNC_RECV_TIMEOUT_MAX);
		PARSE_TIMEOUT(key, val, "MirrorSyncSendTimeout", mirror_sync_send_timeout, MIRROR_SYNC_SEND_TIMEOUT_MIN, MIRROR_SYNC_SEND_TIMEOUT_MAX);
	}

	fclose(fp);

	if (!recv_host[0])
		return -1;

	return 0;
}

int
node_recv_config(void)
{
	struct node_config config;
	int retval;

	memset(&config, 0, sizeof(config));
	config.node_type = NODE_TYPE_RECEIVER;
	strcpy(config.recv_host, recv_host);
	if (recv_host[0]) {
		config.recv_ipaddr = inet_addr(recv_host);
		config.node_ipaddr = config.recv_ipaddr;
	}
	config.mirror_recv_timeout = mirror_recv_timeout;
	config.mirror_connect_timeout = mirror_connect_timeout;
	config.mirror_send_timeout = mirror_send_timeout;
	config.mirror_sync_timeout = mirror_sync_timeout;
	config.mirror_sync_recv_timeout = mirror_sync_recv_timeout;
	config.mirror_sync_send_timeout = mirror_sync_send_timeout;
	retval = tl_ioctl(TLTARGIOCNODECONFIG, &config);
	return retval;
}

int 
node_recv_init(void)
{
	int retval;

	retval = node_recv_read_config();
	if (retval != 0) {
		node_recv_config();
		return 0;
	}

	retval = pthread_create(&nc_thread_id, NULL, node_recv_thread, NULL);
	if (retval != 0) {
		DEBUG_ERR_SERVER("Cannot create node recv thread");
		return -1;
	}

	retval = node_recv_config();
	if (retval != 0) {
		DEBUG_ERR_SERVER("node recv config failed");
		return -1;
	}
	node_recv_inited = 1;
	return 0;
}
