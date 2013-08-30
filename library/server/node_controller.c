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

struct node {
	int sockfd;
	char sys_rid[40];
	char host[16];
	int ipaddr;
	SLIST_ENTRY(node) n_list;
};

static SLIST_HEAD(, node) node_list;
static pthread_mutex_t node_lock = PTHREAD_MUTEX_INITIALIZER;
extern struct tl_blkdevinfo *bdev_list[];
static pthread_t nc_thread_id;
static char controller_host[16];
static char ha_host[16];
static char ha_bind_host[16];
extern char fence_cmd[];

static int clustering_enabled = 0;
static uint16_t controller_recv_timeout;
static uint16_t controller_connect_timeout = CONTROLLER_CONNECT_TIMEOUT_MIN;
static uint16_t node_sync_timeout;
static uint16_t ha_check_timeout;
static uint16_t ha_ping_timeout;

static int is_node_allowed(char *host);

static void
node_free(struct node *node)
{
	free(node);
}

static int
node_exists(uint32_t ipaddr)
{
	struct node *iter;

	SLIST_FOREACH(iter, &node_list, n_list) {
		if (iter->ipaddr == ipaddr)
			return 1;
	}
	return 0;
}

static void
remove_node(uint32_t ipaddr)
{ 
	struct node *iter, *prev = NULL;

	SLIST_FOREACH(iter, &node_list, n_list) {
		if (iter->ipaddr != ipaddr) {
			prev = iter;
			continue;
		}

		if (prev)
			SLIST_REMOVE_AFTER(prev, n_list);
		else
			SLIST_REMOVE_HEAD(&node_list, n_list);
		node_free(iter);
		break;
	}
}

void
node_resp_data(struct tl_comm *comm, struct tl_msg *msg)
{
	msg->msg_resp = MSG_RESP_OK;
	tl_msg_send_message_timeout(comm, msg);
	tl_msg_free_message(msg);
	tl_msg_close_connection(comm);
}

void
node_resp_success(struct tl_comm *comm, struct tl_msg *msg)
{
	tl_msg_free_data(msg);
	msg->msg_resp = MSG_RESP_OK;
	tl_msg_send_message_timeout(comm, msg);
	tl_msg_free_message(msg);
	tl_msg_close_connection(comm);
}

void
node_resp_status(struct tl_comm *comm, struct tl_msg *msg, int status)
{
	tl_msg_free_data(msg);
	msg->msg_resp = status;
	tl_msg_send_message_timeout(comm, msg);
	tl_msg_free_message(msg);
	tl_msg_close_connection(comm);
}

void
node_resp_error(struct tl_comm *comm, struct tl_msg *msg)
{
	tl_msg_free_data(msg);
	msg->msg_resp = MSG_RESP_ERROR;
	tl_msg_send_message_timeout(comm, msg);
	tl_msg_free_message(msg);
	tl_msg_close_connection(comm);
}

static int
node_add(struct node *node)
{
	pthread_mutex_lock(&node_lock);
	remove_node(node->ipaddr);
	SLIST_INSERT_HEAD(&node_list, node, n_list);
	pthread_mutex_unlock(&node_lock);
	return 0;

}

static void
node_msg_ping(struct tl_comm *comm, struct tl_msg *msg, struct sockaddr_in *client_addr)
{
	if (node_exists(client_addr->sin_addr.s_addr))
		node_resp_success(comm, msg);
	else
		node_resp_error(comm, msg);
}

static void
node_msg_handle_unregister(struct tl_comm *comm, struct tl_msg *msg)
{
	struct node_spec *node_spec;

	if (msg->msg_len < sizeof(*node_spec)) {
		node_resp_error(comm, msg);
		return;
	}

	node_spec = (struct node_spec *)msg->msg_data;
	pthread_mutex_lock(&node_lock);
	remove_node(inet_addr(node_spec->host));
	pthread_mutex_unlock(&node_lock);
	tl_msg_free_message(msg);
	tl_msg_close_connection(comm);
}

static void
node_msg_handle_register(struct tl_comm *comm, struct tl_msg *msg)
{
	struct node_spec *node_spec;
	struct node *node;

	if (msg->msg_len < sizeof(*node_spec)) {
		node_resp_error(comm, msg);
		return;
	}

	node_spec = (struct node_spec *)(msg->msg_data);
	if (!is_node_allowed(node_spec->host)) {
		node_resp_error(comm, msg);
		return;
	}

	node = malloc(sizeof(*node));
	if (!node) {
		DEBUG_WARN_SERVER("Memory allocation failure\n");
		node_resp_error(comm, msg);
		return;
	}

	node->ipaddr = inet_addr(node_spec->host);
	memcpy(node->host, node_spec->host, sizeof(node_spec->host));
	memcpy(node->sys_rid, node_spec->sys_rid, sizeof(node_spec->sys_rid));
	node_add(node);
	node_resp_success(comm, msg);
}

extern struct tdisk_info *tdisk_list[];
extern struct group_list group_list;

static void
group_spec_fill(struct group_spec *group_spec, struct group_info *info)
{
	group_spec->group_id = info->group_id;
	strcpy(group_spec->name, info->name);
	group_spec->dedupemeta = info->dedupemeta;
	group_spec->logdata = info->logdata;
}

static void
vdisk_spec_fill(struct vdisk_spec *vdisk_spec, struct tdisk_info *info)
{
	vdisk_spec->block = info->block;
	vdisk_spec->size = info->size;
	vdisk_spec->group_id = info->group->group_id;
	strcpy(vdisk_spec->name, info->name);
	memcpy(vdisk_spec->serialnumber, info->serialnumber, sizeof(info->serialnumber));
	vdisk_spec->target_id = info->target_id;
	vdisk_spec->enable_deduplication = info->enable_deduplication;
	vdisk_spec->enable_compression = info->enable_compression;
	vdisk_spec->enable_verify = info->enable_verify;
	vdisk_spec->force_inline = info->force_inline;
	vdisk_spec->lba_shift = info->lba_shift;
	vdisk_spec->online = info->online;
}

static void
node_msg_list_group(struct tl_comm *comm, struct tl_msg *msg)
{
	struct group_info *info;
	int count = 0;
	struct group_spec *group_spec;

	TAILQ_FOREACH(info, &group_list, q_entry) {
		count++;
	}
	
	if (!count) {
		node_resp_success(comm, msg);
		return;
	}

	msg->msg_data = malloc(count * sizeof(*group_spec));
	if (!msg->msg_data) {
		node_resp_error(comm, msg);
		return;
	}

	memset(msg->msg_data, 0, (count * sizeof(*group_spec)));
	group_spec = (struct group_spec *)(msg->msg_data);
	TAILQ_FOREACH(info, &group_list, q_entry) {
		group_spec_fill(group_spec, info);
		group_spec++;
	}
	msg->msg_len = (count * sizeof(*group_spec));
	node_resp_data(comm, msg);
}

static void
node_msg_list_vdisk(struct tl_comm *comm, struct tl_msg *msg)
{
	struct tdisk_info *info;
	int count = 0, i;
	struct vdisk_spec *vdisk_spec;

	for (i = 1; i < TL_MAX_TDISKS; i++) {
		info = tdisk_list[i];
		if (!info)
			continue;
		if (!info->online || info->disabled)
			continue;
		count++;
	}
	
	if (!count) {
		node_resp_success(comm, msg);
		return;
	}

	msg->msg_data = malloc(count * sizeof(*vdisk_spec));
	if (!msg->msg_data) {
		node_resp_error(comm, msg);
		return;
	}

	memset(msg->msg_data, 0, (count * sizeof(*vdisk_spec)));
	vdisk_spec = (struct vdisk_spec *)(msg->msg_data);
	for (i = 1; i < TL_MAX_TDISKS; i++) {
		info = tdisk_list[i];
		if (!info)
			continue;
		if (!info->online || info->disabled)
			continue;

		vdisk_spec_fill(vdisk_spec, info);
		vdisk_spec++;
	}
	msg->msg_len = (count * sizeof(*vdisk_spec));
	node_resp_data(comm, msg);
}

extern struct tdisk_info * find_tdisk(uint32_t target_id);

static void
node_msg_iscsi_conf(struct tl_comm *comm, struct tl_msg *msg)
{
	struct tdisk_info *info;
	uint32_t target_id;
	int retval;

	retval = sscanf(msg->msg_data, "target_id: %u", &target_id);
	if (retval != 1) {
		node_resp_error(comm, msg);
		return;
	}

	info = find_tdisk(target_id); 
	if (!info) {
		node_resp_error(comm, msg);
		return;
	}

	free(msg->msg_data);
	msg->msg_data = NULL;
	msg->msg_len = 0;

	msg->msg_data = malloc(sizeof(info->iscsiconf));
	if (!msg->msg_data) {
		node_resp_error(comm, msg);
		return;
	}

	memcpy(msg->msg_data, &info->iscsiconf, sizeof(info->iscsiconf));
	msg->msg_len = sizeof(info->iscsiconf);
	node_resp_data(comm, msg);
}

static int 
bdev_spec_fill(struct bdev_spec *bdev_spec, struct tl_blkdevinfo *blkdev)
{
	struct physdisk *disk;
	struct physdevice *device;

	disk = &blkdev->disk;
	device = &disk->info;
	memcpy(bdev_spec->vendor, device->vendor, 8);
	memcpy(bdev_spec->product, device->product, 16);
	memcpy(bdev_spec->serialnumber, device->serialnumber, 32);
	bdev_spec->serial_len = device->serial_len;
	bdev_spec->bid = blkdev->bid;
	bdev_spec->partid = blkdev->disk.partid; 
	bdev_spec->group_id = blkdev->group_id;
	if (device->idflags & ID_FLAGS_NAA) {
		memcpy(bdev_spec->identifier, &device->naa_id, sizeof(device->naa_id));
		bdev_spec->idflags = ID_FLAGS_NAA;
	}
	else if (device->idflags & ID_FLAGS_EUI) {
		memcpy(bdev_spec->identifier, &device->eui_id, sizeof(device->eui_id));
		bdev_spec->idflags = ID_FLAGS_EUI;
	}
	else if (device->idflags & ID_FLAGS_T10) {
		memcpy(bdev_spec->identifier, &device->t10_id, sizeof(device->t10_id));
		bdev_spec->idflags = ID_FLAGS_T10;
	}
	else if (device->idflags & ID_FLAGS_VSPECIFIC) {
		memcpy(bdev_spec->identifier, &device->vspecific_id, sizeof(device->vspecific_id));
		bdev_spec->idflags = ID_FLAGS_VSPECIFIC;
	}
	else if (device->idflags & ID_FLAGS_UNKNOWN) {
		memcpy(bdev_spec->identifier, &device->unknown_id, sizeof(device->unknown_id));
		bdev_spec->idflags = ID_FLAGS_UNKNOWN;
	}
	else {
		memset(bdev_spec, 0, sizeof(*bdev_spec));
		return -1;
	}
	return 0;
}

static void
node_msg_list_bdev(struct tl_comm *comm, struct tl_msg *msg)
{
	struct tl_blkdevinfo *blkdev;
	struct bdev_spec *bdev_spec;
	int count = 0, done, i;

	for (i = 1; i < TL_MAX_DISKS; i++) {
		blkdev = bdev_list[i];
		if (!blkdev)
			continue;
		if (blkdev->offline)
			continue;
		if (blkdev->disk.initialized == -1)
			continue;
		count++;
	}

	if (!count) {
		node_resp_success(comm, msg);
		return;
	}

	msg->msg_data = malloc(count * sizeof(*bdev_spec));
	if (!msg->msg_data) {
		node_resp_error(comm, msg);
		return;
	}

	memset(msg->msg_data, 0, (count * sizeof(*bdev_spec)));
	bdev_spec = (struct bdev_spec *)(msg->msg_data);
	done = 0;

	for (i = 1; i < TL_MAX_DISKS; i++) {
		blkdev = bdev_list[i];
		if (!blkdev)
			continue;
		if (blkdev->offline)
			continue;
		if (blkdev->disk.initialized == -1)
			continue;
		if (bdev_spec_fill(bdev_spec, blkdev) != 0)
			continue;

		done++;
		bdev_spec++;
	}

	if (!done) {
		free(msg->msg_data);
		msg->msg_len = 0;
		node_resp_success(comm, msg);
		return;
	}

	msg->msg_len = (done * sizeof(*bdev_spec));
	node_resp_data(comm, msg);
}

static void
node_controller_process_request(int clientfd, struct sockaddr_in *client_addr)
{
	struct tl_comm comm;
	struct tl_msg *msg;

	comm.sockfd = clientfd;

	msg = tl_msg_recv_message_timeout(&comm);

	if (!msg) {
		close(clientfd);
		return;
	}

	switch (msg->msg_id) {
	case NODE_MSG_REGISTER:
		node_msg_handle_register(&comm, msg);
		break;
	case NODE_MSG_UNREGISTER:
		node_msg_handle_unregister(&comm, msg);
		break;
	case NODE_MSG_LIST_BDEV:
		pthread_mutex_lock(&daemon_lock);
		node_msg_list_bdev(&comm, msg);
		pthread_mutex_unlock(&daemon_lock);
		break;
	case NODE_MSG_ISCSI_CONF:
		/* would be under lock anyway */
		node_msg_iscsi_conf(&comm, msg);
		break;
	case NODE_MSG_LIST_VDISK:
		pthread_mutex_lock(&daemon_lock);
		node_msg_list_vdisk(&comm, msg);
		pthread_mutex_unlock(&daemon_lock);
		break;
	case NODE_MSG_LIST_GROUP:
		pthread_mutex_lock(&daemon_lock);
		node_msg_list_group(&comm, msg);
		pthread_mutex_unlock(&daemon_lock);
		break;
	case NODE_MSG_PING:
		node_msg_ping(&comm, msg, client_addr);
		break;
	default:
		tl_msg_free_message(msg);
	}
}

static void *
node_controller_thread(void *arg)
{
	int sockfd, clientfd;
	struct sockaddr_in in_addr, client_addr;
	int reuse = 1, opt, err;
	socklen_t addr_len;
	in_addr_t ipaddr;

	if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		DEBUG_ERR_SERVER("Cannot create controller thread socket\n");
		pthread_exit(0);
	}

	if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(int)) == -1) {
		DEBUG_ERR_SERVER("Cannot set controller thread sockopt SO_REUSEADDR\n");
		close(sockfd);
		pthread_exit(0);
	}

	ipaddr = inet_addr(controller_host);
	if (ipaddr == INADDR_NONE) {
		DEBUG_ERR_SERVER("Invalid controller address specified %s\n", controller_host);
		close(sockfd);
		pthread_exit(0);
	}
	memset(&in_addr, 0, sizeof(struct sockaddr_in));
	in_addr.sin_family = AF_INET;
	in_addr.sin_port = htons(NODE_CONTROLLER_RECV_PORT);
	in_addr.sin_addr.s_addr = ipaddr;
 
	if (bind(sockfd, (struct sockaddr *)&in_addr, sizeof(in_addr)) == -1) {
		DEBUG_ERR_SERVER("Cannot bind to addr %s\n", controller_host);
		close(sockfd);
		pthread_exit(0);
	}

	if (listen(sockfd, 10) == -1) {
		DEBUG_ERR_SERVER("Cannot listen on controller port\n");
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

		node_controller_process_request(clientfd, &client_addr);
	}
out:
	pthread_exit(0);
}

#define NODE_CONTROLLER_CONFIG_FILE "/quadstor/etc/ndcontroller.conf"

static int
is_node_allowed(char *host)
{
	FILE *fp;
	char buf[256];
	char *tmp, *key, *val;

	fp = fopen(NODE_CONTROLLER_CONFIG_FILE, "r");
	if (!fp)
		return 0;

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

		if (strcasecmp(key, "Node") == 0) {
			if (!ipaddr_valid(val)) {
				DEBUG_WARN_SERVER("Invalid IP address %s specified for node\n", val);
				continue;
			}

			if (strcmp(val, host) == 0) {
				fclose(fp);
				return 1;
			}

		}
	}

	fclose(fp);
	return 0;
}

static int
node_controller_read_config(void)
{
	FILE *fp;
	char buf[256];
	char *tmp, *key, *val;

	fp = fopen(NODE_CONTROLLER_CONFIG_FILE, "r");
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
		if (strcasecmp(buf, "fence") == 0) {
			strcpy(fence_cmd, tmp);
			continue;
		}

		val = strip_space(tmp);
		PARSE_IPADDR(key, val, "Controller", controller_host);
		PARSE_IPADDR(key, val, "HAPeer", ha_host);
		PARSE_IPADDR(key, val, "HABind", ha_bind_host);

		PARSE_TIMEOUT(key, val, "ControllerRecvTimeout", controller_recv_timeout, CONTROLLER_RECV_TIMEOUT_MIN, CONTROLLER_RECV_TIMEOUT_MAX);
		PARSE_TIMEOUT(key, val, "ControllerConnectTimeout", controller_connect_timeout, CONTROLLER_CONNECT_TIMEOUT_MIN, CONTROLLER_CONNECT_TIMEOUT_MAX);
		PARSE_TIMEOUT(key, val, "HASyncTimeout", node_sync_timeout, NODE_SYNC_TIMEOUT_MIN, NODE_SYNC_TIMEOUT_MAX);
		PARSE_TIMEOUT(key, val, "HACheckTimeout", ha_check_timeout, HA_CHECK_TIMEOUT_MIN, HA_CHECK_TIMEOUT_MAX);
		PARSE_TIMEOUT(key, val, "HAPingTimeout", ha_ping_timeout, HA_PING_TIMEOUT_MIN, HA_PING_TIMEOUT_MAX);
		if (strcasecmp(key, "Node") == 0)
			continue;
		DEBUG_WARN_SERVER("Invalid line in configuration file %s\n", buf);
	}

	fclose(fp);

	if (!controller_host[0])
		return -1;

	return 0;
}

int
node_controller_config(void)
{
	struct node_config config;
	int retval;

	memset(&config, 0, sizeof(config));
	config.node_type = NODE_TYPE_CONTROLLER;
	strcpy(config.controller_host, controller_host);
	strcpy(config.ha_host, ha_host);
	if (!ha_bind_host[0])
		strcpy(ha_bind_host, controller_host);
	strcpy(config.ha_bind_host, ha_bind_host);
	config.controller_ipaddr = inet_addr(controller_host);
	config.ha_ipaddr = inet_addr(ha_host);
	config.ha_bind_ipaddr = inet_addr(ha_bind_host);
	config.node_ipaddr = config.controller_ipaddr;
	config.controller_recv_timeout = controller_recv_timeout;
	config.node_sync_timeout = node_sync_timeout;
	config.ha_check_timeout = ha_check_timeout;
	config.ha_ping_timeout = ha_ping_timeout;
	config.fence_enabled = (fence_cmd[0] ? 1 : 0);
	retval = tl_ioctl(TLTARGIOCNODECONFIG, &config);
	return retval;
}

int
node_controller_init_pre(void)
{
	int retval;

	retval = node_controller_read_config();
	if (retval != 0) {
		return 0;
	}

	retval = node_controller_config();
	if (retval != 0) {
		DEBUG_ERR_SERVER("node controller config failed");
		return -1;
	}
	return 0;
}

int 
node_controller_init(void)
{
	int retval;

	if (!controller_host[0])
		return 0;

	retval = pthread_create(&nc_thread_id, NULL, node_controller_thread, NULL);
	if (retval != 0) {
		DEBUG_ERR_SERVER("Cannot create node controller thread");
		return -1;
	}

	clustering_enabled = 1;
	return 0;
}

static void 
node_send_msg(struct node *node, struct tl_msg *msg)
{
	struct tl_comm *comm;
	struct tl_msg *resp;
	int retval;

	comm = tl_msg_remote_connection(node->host, controller_host, NODE_CLIENT_RECV_PORT, controller_connect_timeout);
	if (!comm) {
		remove_node(node->ipaddr);
		return;
	}

	retval = tl_msg_send_message_timeout(comm, msg);
	if (retval != 0) {
		remove_node(node->ipaddr);
		tl_msg_free_connection(comm);
		return;
	}

	resp = tl_msg_recv_message_timeout(comm);
	if (!resp) {
		remove_node(node->ipaddr);
		tl_msg_free_connection(comm);
		return;
	}

	tl_msg_free_message(resp);
	tl_msg_free_connection(comm);
}

static void
node_controller_send_msg(struct tl_msg *msg)
{
	struct node *node;

	pthread_mutex_lock(&node_lock);
	SLIST_FOREACH(node, &node_list, n_list) {
		node_send_msg(node, msg);
	}
	pthread_mutex_unlock(&node_lock);
}

void
__node_controller_group_msg(struct group_info *info, int msg_id)
{
	struct group_spec spec;
	struct tl_msg msg;

	if (!clustering_enabled)
		return;

	memset(&spec, 0, sizeof(spec));
	group_spec_fill(&spec, info);
	msg.msg_id = msg_id;
	msg.msg_len = sizeof(spec);
	msg.msg_data = (void *)(&spec);
	node_controller_send_msg(&msg);
}

void
__node_controller_vdisk_msg(struct tdisk_info *info, int msg_id)
{
	struct vdisk_spec spec;
	struct tl_msg msg;

	if (!clustering_enabled)
		return;

	memset(&spec, 0, sizeof(spec));
	vdisk_spec_fill(&spec, info);
	msg.msg_id = msg_id;
	msg.msg_len = sizeof(spec);
	msg.msg_data = (void *)(&spec);
	node_controller_send_msg(&msg);
}

void
node_controller_group_added(struct group_info *info)
{
	__node_controller_group_msg(info, NODE_MSG_GROUP_ADDED);
}

void
node_controller_group_removed(struct group_info *info)
{
	__node_controller_group_msg(info, NODE_MSG_GROUP_REMOVED);
}

void
node_controller_vdisk_added(struct tdisk_info *info)
{
	__node_controller_vdisk_msg(info, NODE_MSG_VDISK_ADDED);
}

void
node_controller_vdisk_modified(struct tdisk_info *info)
{
	__node_controller_vdisk_msg(info, NODE_MSG_VDISK_MODIFIED);
}

void
node_controller_vdisk_attached(struct tdisk_info *info)
{
	__node_controller_vdisk_msg(info, NODE_MSG_VDISK_ATTACHED);
}

void
node_controller_vdisk_removed(struct tdisk_info *info)
{
	__node_controller_vdisk_msg(info, NODE_MSG_VDISK_REMOVED);
}

void
node_controller_vdisk_disable(struct tdisk_info *info)
{
	__node_controller_vdisk_msg(info, NODE_MSG_VDISK_DISABLE);
}

void
node_controller_bdev_removed(struct tl_blkdevinfo *blkdev)
{
	struct bdev_spec spec;
	struct tl_msg msg;

	if (!clustering_enabled)
		return;

	memset(&spec, 0, sizeof(spec));
	if (bdev_spec_fill(&spec, blkdev) != 0)
		return;

	msg.msg_id = NODE_MSG_BDEV_REMOVED;
	msg.msg_len = sizeof(spec);
	msg.msg_data = (void *)(&spec);
	node_controller_send_msg(&msg);
}

void
node_controller_bdev_added(struct tl_blkdevinfo *blkdev)
{
	struct bdev_spec spec;
	struct tl_msg msg;

	if (!clustering_enabled)
		return;

	memset(&spec, 0, sizeof(spec));
	if (bdev_spec_fill(&spec, blkdev) != 0)
		return;

	msg.msg_id = NODE_MSG_BDEV_ADDED;
	msg.msg_len = sizeof(spec);
	msg.msg_data = (void *)(&spec);
	node_controller_send_msg(&msg);
}
