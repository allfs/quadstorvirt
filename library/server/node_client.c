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
#include <signal.h>
#include "ietadm.h"

extern struct blist bdev_list;
extern struct group_list group_list;
int client_accept_fd;
static char controller_host[16];
static char ha_host[16];
static char ha_bind_host[16];
static char node_host[16];
int node_type;
int delay_secs = 5;
static pthread_t nc_thread_id;
static pthread_t local_thread_id;
int controller_shutdown;
int client_shutdown;
int client_inited;
extern char fence_cmd[];

static uint16_t client_send_timeout;
static uint16_t client_connect_timeout = CLIENT_CONNECT_TIMEOUT_MIN;
static uint16_t controller_recv_timeout;
static uint16_t node_sync_timeout;
static uint16_t ha_check_timeout;
static uint16_t ha_ping_timeout;
static uint16_t client_connect_timeout;

extern char sys_rid[TL_RID_MAX];
static void *prev_term_handler;

struct tl_blkdevinfo *
blkdev_find(uint32_t bid)
{
	struct tl_blkdevinfo *blkdev;

	TAILQ_FOREACH(blkdev, &bdev_list, q_entry) { 
		if (blkdev->bid == bid)
		{
			return blkdev;
		}
	}
	return NULL;	
}

static void
node_client_remove_bdev(struct tl_blkdevinfo *blkdev)
{
	int retval;
	struct bdev_info binfo;

	binfo.bid = blkdev->bid;
	retval = tl_ioctl(TLTARGIOCDELETEBDEVSTUB, &binfo);
	if (retval == 0) {
		bdev_remove(blkdev);
		free(blkdev);
	}
}

#define TL_MAX_DEVICES		4096
struct tdisk_info *vdisks[TL_MAX_DEVICES];

static int
node_client_add_group(struct group_spec *group_spec)
{
	struct group_info *group_info;
	struct group_conf group_conf;
	int retval;

	if (group_name_exists(group_spec->name)) {
		return -1;
	}

	group_info = alloc_buffer(sizeof(*group_info));
	if (!group_info) {
		return -1;
	}

	strcpy(group_info->name, group_spec->name);
	group_info->group_id = group_spec->group_id;
	group_info->dedupemeta = group_spec->dedupemeta;
	group_info->logdata = group_spec->logdata;
	TAILQ_INIT(&group_info->bdev_list);
	TAILQ_INIT(&group_info->tdisk_list);

	group_conf_fill(&group_conf, group_info);
	retval = tl_ioctl(TLTARGIOCADDGROUP, &group_conf);
	if (retval != 0) {
		free(group_info);
		return -1;
	}

	TAILQ_INSERT_TAIL(&group_list, group_info, q_entry);
	return 0;
}

static int
node_client_remove_group(struct group_info *group_info)
{
	int retval;
	struct group_conf group_conf;

	group_conf_fill(&group_conf, group_info);
	retval = tl_ioctl(TLTARGIOCDELETEGROUP, &group_conf);
	if (retval != 0)
		return -1;

	TAILQ_REMOVE(&group_list, group_info, q_entry); 
	free(group_info);
	return 0;
}

static int 
node_client_remove_vdisk(struct tdisk_info *tdisk_info)
{
	int retval;

	vhba_remove_device(tdisk_info);

	ietadm_delete_target(tdisk_info->iscsi_tid);

	retval = tl_ioctl(TLTARGIOCDELETETDISKSTUB, tdisk_info);
	return retval;
}

static int 
node_client_disable_vdisk(struct tdisk_info *tdisk_info)
{
	int retval;

	vhba_remove_device(tdisk_info);

	ietadm_delete_target(tdisk_info->iscsi_tid);
	tdisk_info->iscsi_tid = -1;

	retval = tl_ioctl(TLTARGIOCDISABLETDISKSTUB, tdisk_info);
	return retval;
}

static int
node_client_query_iscsiconf(struct vdisk_spec *vdisk_spec, struct iscsiconf *conf)
{
	struct tl_msg msg, *resp;
	struct tl_comm *comm;
	char buf[32];
	int retval;

	snprintf(buf, sizeof(buf), "target_id: %u", vdisk_spec->target_id);
	msg.msg_id = NODE_MSG_ISCSI_CONF;
	msg.msg_data = buf;
	msg.msg_len = strlen(buf) + 1;

	comm = tl_msg_remote_connection(controller_host, node_host, NODE_CONTROLLER_RECV_PORT, client_connect_timeout);
	if (!comm) {
		return -1;
	}

	retval = tl_msg_send_message(comm, &msg);
	if (retval != 0) {
		tl_msg_free_connection(comm);
		return -1;
	}

	resp = tl_msg_recv_message(comm);
	if (!resp) {
		tl_msg_free_connection(comm);
		return -1;
	}

	if (resp->msg_resp != MSG_RESP_OK) {
		tl_msg_free_message(resp);
		tl_msg_free_connection(comm);
		return -1;
	}
	
	if (resp->msg_len != sizeof(*conf)) {
		DEBUG_WARN_SERVER("Invalid resp msg len %d expected %d\n", resp->msg_len, (int)sizeof(*conf));
		tl_msg_free_message(resp);
		tl_msg_free_connection(comm);
		return -1;
	}
	memcpy(conf, resp->msg_data, resp->msg_len);
	tl_msg_free_message(resp);
	tl_msg_free_connection(comm);
	return 0;
}

static void
node_client_add_vdisk(struct vdisk_spec *vdisk_spec, int force, int attach)
{
	struct tdisk_info *info;
	struct group_info *group_info;
	int retval;

	if (vdisk_spec->target_id >= TL_MAX_DEVICES)
		return;

	info = vdisks[vdisk_spec->target_id];
	if (info) {
		if (strcmp(info->name, vdisk_spec->name) == 0 && !force)
			return;
		node_client_remove_vdisk(info);
		vdisks[vdisk_spec->target_id] = NULL;
		tdisk_remove(info);
		free(info);
	}

	group_info = find_group(vdisk_spec->group_id);
	if (!group_info) {
		DEBUG_ERR("Cannot find pool at id %u\n", vdisk_spec->group_id);
		return;
	}

	info = alloc_buffer(sizeof(*info));
	if (!info) {
		DEBUG_WARN_SERVER("Memory allocation failure\n");
		return;
	}

	retval = node_client_query_iscsiconf(vdisk_spec, &info->iscsiconf);
	if (retval != 0) {
		free(info);
		return;
	}

	info->block = vdisk_spec->block;
	info->size = vdisk_spec->size;
	strcpy(info->name, vdisk_spec->name);
	memcpy(info->serialnumber, vdisk_spec->serialnumber, sizeof(vdisk_spec->serialnumber));
	info->target_id = vdisk_spec->target_id;
	info->group_id = vdisk_spec->group_id;
	info->enable_deduplication = vdisk_spec->enable_deduplication;
	info->enable_compression = vdisk_spec->enable_compression;
	info->enable_verify = vdisk_spec->enable_verify;
	info->force_inline = vdisk_spec->force_inline;
	info->lba_shift = vdisk_spec->lba_shift;
	info->attach = attach;
	retval = tl_ioctl(TLTARGIOCNEWTDISKSTUB, info);
	if (retval != 0) {
		DEBUG_WARN_SERVER("Add new remote VDisk failed for %s\n", info->name);
		free(info);
		return;
	}

	vdisks[info->target_id] = info;
	tdisk_add(group_info, info);

	if (!attach)
		return;

	vhba_add_device(info->vhba_id);
	retval = ietadm_add_target(info->iscsi_tid, &info->iscsiconf);
	if (retval != 0) {
		DEBUG_ERR("Cannot create iscsi target for disk target\n");
	}
	info->online = 1;
}

static void
node_client_process_vdisk_attached(struct tl_comm *comm, struct tl_msg *msg)
{
	struct vdisk_spec *vdisk_spec;
	struct tdisk_info *info;

	if (msg->msg_len != sizeof(*vdisk_spec))
		goto out;

	vdisk_spec = (struct vdisk_spec *)(msg->msg_data);
	if (vdisk_spec->target_id >= TL_MAX_DEVICES)
		goto out;

	info = vdisks[vdisk_spec->target_id];
	if (!info)
		goto out;

	attach_tdisk(info);
out:
	tl_server_msg_success(comm, msg);
}

static void
node_client_process_vdisk_modified(struct tl_comm *comm, struct tl_msg *msg)
{
	struct vdisk_spec *vdisk_spec;
	struct tdisk_info *info;

	if (msg->msg_len != sizeof(*vdisk_spec))
		goto out;

	vdisk_spec = (struct vdisk_spec *)(msg->msg_data);
	if (vdisk_spec->target_id >= TL_MAX_DEVICES)
		goto out;

	info = vdisks[vdisk_spec->target_id];
	if (!info)
		goto out;

	info->enable_deduplication = vdisk_spec->enable_deduplication;
	info->enable_compression = vdisk_spec->enable_compression;
	info->enable_verify = vdisk_spec->enable_verify;
	info->force_inline = vdisk_spec->force_inline;
	tl_ioctl(TLTARGIOCMODIFYTDISK, info);
out:
	tl_server_msg_success(comm, msg);
}

static void
node_client_process_group_added(struct tl_comm *comm, struct tl_msg *msg)
{
	struct group_spec *group_spec;

	if (msg->msg_len != sizeof(*group_spec))
		goto out;

	group_spec = (struct group_spec *)(msg->msg_data);
	
	node_client_add_group(group_spec);
out:
	tl_server_msg_success(comm, msg);
}

static void
node_client_process_group_removed(struct tl_comm *comm, struct tl_msg *msg)
{
	struct group_spec *group_spec;
	struct group_info *group_info;

	if (msg->msg_len != sizeof(*group_spec))
		goto out;

	group_spec = (struct group_spec *)(msg->msg_data);

	group_info = find_group(group_spec->group_id);
	if (!group_info)
		goto out;

	node_client_remove_group(group_info);
out:
	tl_server_msg_success(comm, msg);
}

static void
node_client_process_vdisk_added(struct tl_comm *comm, struct tl_msg *msg)
{
	struct vdisk_spec *vdisk_spec;

	if (msg->msg_len != sizeof(*vdisk_spec))
		goto out;

	vdisk_spec = (struct vdisk_spec *)(msg->msg_data);
	
	node_client_add_vdisk(vdisk_spec, 1, 0);
out:
	tl_server_msg_success(comm, msg);
}

static void
node_client_process_vdisk_removed(struct tl_comm *comm, struct tl_msg *msg)
{
	struct vdisk_spec *vdisk_spec;
	struct tdisk_info *info;
	int retval;

	if (msg->msg_len != sizeof(*vdisk_spec))
		goto out;

	vdisk_spec = (struct vdisk_spec *)(msg->msg_data);

	if (vdisk_spec->target_id >= TL_MAX_DEVICES)
		goto out;

	info = vdisks[vdisk_spec->target_id];
	if (!info)
		goto out;

	retval = node_client_remove_vdisk(info);
	if (retval == 0) {
		vdisks[vdisk_spec->target_id] = NULL;
		tdisk_remove(info);
		free(info);
	}

out:
	tl_server_msg_success(comm, msg);
}

static void
node_client_process_vdisk_disable(struct tl_comm *comm, struct tl_msg *msg)
{
	struct vdisk_spec *vdisk_spec;
	struct tdisk_info *info;

	if (msg->msg_len != sizeof(*vdisk_spec))
		goto out;

	vdisk_spec = (struct vdisk_spec *)(msg->msg_data);

	if (vdisk_spec->target_id >= TL_MAX_DEVICES)
		goto out;

	info = vdisks[vdisk_spec->target_id];
	if (!info)
		goto out;

	node_client_disable_vdisk(info);
out:
	tl_server_msg_success(comm, msg);
}

static struct physdisk *
node_client_find_disk(struct bdev_spec *spec)
{
	struct physdisk disk;
	struct physdevice *device;

	memset(&disk, 0, sizeof(disk));
	device = &disk.info;
	memcpy(device->vendor, spec->vendor, sizeof(spec->vendor));
	memcpy(device->product, spec->product, sizeof(spec->product));
	memcpy(device->serialnumber, spec->serialnumber, sizeof(spec->serialnumber));
	device->serial_len = spec->serial_len;
	device->idflags = spec->idflags;
	disk.partid = spec->partid;

	switch (spec->idflags) {
	case ID_FLAGS_NAA:
		memcpy(&device->naa_id, spec->identifier, sizeof(device->naa_id));
		break;
	case ID_FLAGS_EUI:
		memcpy(&device->eui_id, spec->identifier, sizeof(device->eui_id));
		break;
	case ID_FLAGS_T10:
		memcpy(&device->t10_id, spec->identifier, sizeof(device->t10_id));
		break;
	case ID_FLAGS_VSPECIFIC:
		memcpy(&device->vspecific_id, spec->identifier, sizeof(device->vspecific_id));
		break;
	case ID_FLAGS_UNKNOWN:
		memcpy(&device->unknown_id, spec->identifier, sizeof(device->unknown_id));
		break;
	}

	return tl_common_find_physdisk2(&disk);
}

static void
node_client_add_bdev(struct bdev_spec *spec)
{
	struct tl_blkdevinfo *blkdev;
	struct group_info *group_info;
	struct physdisk *disk;
	struct bdev_info binfo;
	int retval;

	disk = node_client_find_disk(spec);
	if (!disk)
		return;

	group_info = find_group(spec->group_id);
	if (!group_info) {
		DEBUG_ERR("Cannot find pool at id %u\n", spec->group_id);
		return;
	}

	blkdev = blkdev_new(disk->info.devname); 
	if (!blkdev)
		return;

	memcpy(&blkdev->disk, disk, offsetof(struct physdisk, q_entry));
	blkdev->bid = spec->bid;
	blkdev->group_id = spec->group_id;
	strcpy(blkdev->devname, disk->info.devname);
	memset(&binfo, 0, sizeof(struct bdev_info));
	binfo.bid = blkdev->bid;
	binfo.group_id = blkdev->group_id;
	memcpy(binfo.vendor, disk->info.vendor, sizeof(binfo.vendor));
	memcpy(binfo.product, disk->info.product, sizeof(binfo.product));
	memcpy(binfo.serialnumber, disk->info.serialnumber, sizeof(binfo.serialnumber));
	binfo.ddmaster = spec->ddmaster;
	strcpy(binfo.devpath, blkdev->devname);
	retval = tl_ioctl(TLTARGIOCNEWBDEVSTUB, &binfo);
	if (retval == 0)
		bdev_add(group_info, blkdev);
	else
		free(blkdev);
}

static void
node_client_process_bdev_added(struct tl_comm *comm, struct tl_msg *msg)
{
	struct bdev_spec *bdev_spec;
	struct tl_blkdevinfo *blkdev;

	if (msg->msg_len != sizeof(*bdev_spec))
		goto out;

	bdev_spec = (struct bdev_spec *)msg->msg_data;
	blkdev = blkdev_find(bdev_spec->bid);
	if (blkdev)
		node_client_remove_bdev(blkdev);

	node_client_add_bdev(bdev_spec);
out:
	tl_server_msg_success(comm, msg);
}

static void
node_client_process_bdev_removed(struct tl_comm *comm, struct tl_msg *msg)
{
	struct bdev_spec *bdev_spec;
	struct tl_blkdevinfo *blkdev;

	if (msg->msg_len != sizeof(*bdev_spec))
		goto out;

	bdev_spec = (struct bdev_spec *)msg->msg_data;

	blkdev = blkdev_find(bdev_spec->bid);
	if (blkdev)
		node_client_remove_bdev(blkdev);
out:
	tl_server_msg_success(comm, msg);
}

static void
node_client_process_request(int clientfd, struct sockaddr_in *client_addr)
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
	case NODE_MSG_CONTROLLER_SHUTDOWN:
		controller_shutdown = 1;
		tl_msg_free_message(msg);
		tl_msg_close_connection(&comm);
		break;
	case NODE_MSG_VDISK_REMOVED:
		pthread_mutex_lock(&daemon_lock);
		node_client_process_vdisk_removed(&comm, msg);
		pthread_mutex_unlock(&daemon_lock);
		break;
	case NODE_MSG_VDISK_DISABLE:
		pthread_mutex_lock(&daemon_lock);
		node_client_process_vdisk_disable(&comm, msg);
		pthread_mutex_unlock(&daemon_lock);
		break;
	case NODE_MSG_BDEV_REMOVED:
		pthread_mutex_lock(&daemon_lock);
		node_client_process_bdev_removed(&comm, msg);
		pthread_mutex_unlock(&daemon_lock);
		break;
	case NODE_MSG_BDEV_ADDED:
		pthread_mutex_lock(&daemon_lock);
		node_client_process_bdev_added(&comm, msg);
		pthread_mutex_unlock(&daemon_lock);
		break;
	case NODE_MSG_VDISK_ADDED:
		pthread_mutex_lock(&daemon_lock);
		node_client_process_vdisk_added(&comm, msg);
		pthread_mutex_unlock(&daemon_lock);
		break;
	case NODE_MSG_VDISK_ATTACHED:
		pthread_mutex_lock(&daemon_lock);
		node_client_process_vdisk_attached(&comm, msg);
		pthread_mutex_unlock(&daemon_lock);
		break;
	case NODE_MSG_VDISK_MODIFIED:
		pthread_mutex_lock(&daemon_lock);
		node_client_process_vdisk_modified(&comm, msg);
		pthread_mutex_unlock(&daemon_lock);
		break;
	case NODE_MSG_GROUP_ADDED:
		pthread_mutex_lock(&daemon_lock);
		node_client_process_group_added(&comm, msg);
		pthread_mutex_unlock(&daemon_lock);
		break;
	case NODE_MSG_GROUP_REMOVED:
		pthread_mutex_lock(&daemon_lock);
		node_client_process_group_removed(&comm, msg);
		pthread_mutex_unlock(&daemon_lock);
		break;
	default:
		tl_server_msg_invalid(&comm, msg);
	}
}

static void *
node_client_thread(void *arg)
{
	int clientfd;
	struct sockaddr_in in_addr, client_addr;
	int reuse = 1, opt;
	socklen_t addr_len;
	in_addr_t ipaddr, controller_ipaddr;

	if ((client_accept_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		DEBUG_ERR_SERVER("Cannot create client thread socket\n");
		pthread_exit(0);
	}

	if (setsockopt(client_accept_fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(int)) == -1) {
		DEBUG_ERR_SERVER("Cannot set client thread sockopt SO_REUSEADDR\n");
		close(client_accept_fd);
		client_accept_fd = -1;
		pthread_exit(0);
	}

	ipaddr = inet_addr(node_host);
	controller_ipaddr = inet_addr(controller_host);

	memset(&in_addr, 0, sizeof(struct sockaddr_in));
	in_addr.sin_family = AF_INET;
	in_addr.sin_port = htons(NODE_CLIENT_RECV_PORT);
	in_addr.sin_addr.s_addr = ipaddr;
 
	if (bind(client_accept_fd, (struct sockaddr *)&in_addr, sizeof(in_addr)) == -1) {
		DEBUG_ERR_SERVER("Cannot bind to addr %s\n", node_host);
		close(client_accept_fd);
		client_accept_fd = -1;
		pthread_exit(0);
	}

	if (listen(client_accept_fd, 10) == -1) {
		DEBUG_ERR_SERVER("Cannot listen on client port\n");
		close(client_accept_fd);
		client_accept_fd = -1;
		pthread_exit(0);
	}

	while (!client_shutdown) {
		addr_len = sizeof(struct sockaddr_in);
		if ((clientfd = accept(client_accept_fd, (struct sockaddr *)&client_addr, &addr_len)) == -1) {
			switch (errno) {
			case EINTR:
			case ECONNABORTED:
				break;
			default:
				goto out;
			}
			continue;
		}

		if (client_addr.sin_addr.s_addr != controller_ipaddr) {
			DEBUG_WARN_SERVER("Received message from invalid controller node %s\n", inet_ntoa(client_addr.sin_addr));
			close(clientfd);
			continue;
		}

		opt = 1;
		setsockopt(clientfd, IPPROTO_TCP, TCP_NODELAY, &opt, sizeof(opt));
		node_client_process_request(clientfd, &client_addr);
	}
out:
	pthread_exit(0);
}

static void
node_client_unregister(void)
{
	struct node_spec node_spec;
	struct tl_msg msg;
	struct tl_comm *comm;

	memset(&node_spec, 0, sizeof(node_spec));
	memcpy(node_spec.sys_rid, sys_rid, sizeof(sys_rid));
	strcpy(node_spec.host, node_host);
	node_spec.node_type = node_type;

	msg.msg_id = NODE_MSG_UNREGISTER;
	msg.msg_len = sizeof(node_spec);
	msg.msg_data = (void *)&node_spec;

	comm = tl_msg_remote_connection(controller_host, node_host, NODE_CONTROLLER_RECV_PORT, client_connect_timeout);
	if (!comm)
		return;

	tl_msg_send_message(comm, &msg);
	tl_msg_free_connection(comm);
}

static int 
node_client_register(void)
{
	struct node_spec node_spec;
	struct tl_msg msg, *resp;
	struct tl_comm *comm;
	int retval;

	memset(&node_spec, 0, sizeof(node_spec));
	memcpy(node_spec.sys_rid, sys_rid, sizeof(sys_rid));
	strcpy(node_spec.host, node_host);
	node_spec.node_type = node_type;

	msg.msg_id = NODE_MSG_REGISTER;
	msg.msg_len = sizeof(node_spec);
	msg.msg_data = (void *)&node_spec;

again:
	comm = tl_msg_remote_connection(controller_host, node_host, NODE_CONTROLLER_RECV_PORT, client_connect_timeout);
	if (!comm) {
		sleep(delay_secs);
		goto again;
	}

	retval = tl_msg_send_message(comm, &msg);
	if (retval != 0) {
		tl_msg_free_connection(comm);
		sleep(delay_secs);
		goto again;
	}

	resp = tl_msg_recv_message(comm);
	if (!resp) {
		tl_msg_free_connection(comm);
		sleep(delay_secs);
		goto again;
	}

	if (resp->msg_resp != MSG_RESP_OK) {
		tl_msg_free_message(resp);
		tl_msg_free_connection(comm);
		sleep(delay_secs);
		goto again;
	}

	tl_msg_free_message(resp);
	tl_msg_free_connection(comm);
	return 0;
	
}

#define NODE_CLIENT_CONFIG_FILE "/quadstor/etc/ndclient.conf"

int
node_client_read_config(void)
{
	FILE *fp;
	char buf[256];
	char *tmp, *key, *val;

	fp = fopen(NODE_CLIENT_CONFIG_FILE, "r");
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

		/* Dont strip spaces for Fence command */
		if (strcasecmp(key, "Fence") == 0) {
			strcpy(fence_cmd, tmp);
			continue;
		}

		val = strip_space(tmp);

		PARSE_IPADDR(key, val, "Node", node_host);
		PARSE_IPADDR(key, val, "Controller", controller_host);
		PARSE_IPADDR(key, val, "HAPeer", ha_host);
		PARSE_IPADDR(key, val, "HABind", ha_bind_host);

		if (strcasecmp(key, "type") == 0) {
			if (strcasecmp(val, "Master") != 0)
				DEBUG_WARN_SERVER("Invalid node type specified %s\n", val);
			else
				node_type = NODE_TYPE_MASTER;
			continue;
		}

		PARSE_TIMEOUT(key, val, "ClientSendTimeout", client_send_timeout, CLIENT_SEND_TIMEOUT_MIN, CLIENT_SEND_TIMEOUT_MAX);
		PARSE_TIMEOUT(key, val, "ClientConnectTimeout", client_connect_timeout, CLIENT_CONNECT_TIMEOUT_MIN, CLIENT_CONNECT_TIMEOUT_MAX);
		PARSE_TIMEOUT(key, val, "ControllerRecvTimeout", controller_recv_timeout, CONTROLLER_RECV_TIMEOUT_MIN, CONTROLLER_RECV_TIMEOUT_MAX);
		PARSE_TIMEOUT(key, val, "HASyncTimeout", node_sync_timeout, NODE_SYNC_TIMEOUT_MIN, NODE_SYNC_TIMEOUT_MAX);
		PARSE_TIMEOUT(key, val, "HACheckTimeout", ha_check_timeout, HA_CHECK_TIMEOUT_MIN, HA_CHECK_TIMEOUT_MAX);
		PARSE_TIMEOUT(key, val, "HAPingTimeout", ha_ping_timeout, HA_PING_TIMEOUT_MIN, HA_PING_TIMEOUT_MAX);
		DEBUG_WARN_SERVER("Invalid line in configuration file %s = %s\n", key, val);
	}

	fclose(fp);

	if (node_type && node_type != NODE_TYPE_CLIENT && node_type != NODE_TYPE_MASTER) {
		return -1;
	}
	else if (!node_type)
		node_type = NODE_TYPE_CLIENT;

	if (!node_host[0])
		return -1;

	if (!controller_host[0])
		return -1;

	if (!ha_host[0])
		strcpy(ha_host, controller_host);

	if (!ha_bind_host[0])
		strcpy(ha_bind_host, node_host);

	return 0;
}

static void
nc_term_handler(int signo)
{
#if 0
	int i;
	struct tdisk_info *info;
#endif

	if (!client_inited) {
		exit(0);
		return;
	}

	client_shutdown = 1;
	client_inited = 0;

#if 0
	for (i = 0; i < TL_MAX_DEVICES; i++) {
		info = vdisks[i];
		if (!info)
			continue;
		node_client_remove_vdisk(info);
	}
#endif

	tl_ioctl_void(TLTARGIOCUNLOAD);

	node_client_unregister();
#if 0
	if (client_accept_fd >= 0) {
		close(client_accept_fd);
		(void) pthread_join(nc_thread_id, NULL);
	}
#endif

	exit(0);
}

static int 
node_client_test_conn(void)
{
	struct tl_comm *comm;
	struct tl_msg msg, *resp;
	int retval;

	msg.msg_id = NODE_MSG_PING;
	msg.msg_len = 0;
	msg.msg_data = NULL;

	comm = tl_msg_remote_connection(controller_host, node_host, NODE_CONTROLLER_RECV_PORT, client_connect_timeout);
	if (!comm) {
		DEBUG_INFO("Failed to connect to controller %s node addr %s\n", controller_host, node_host);
		return 1;
	}

	retval = tl_msg_send_message(comm, &msg);
	if (retval != 0) {
		DEBUG_INFO("Sending ping msg to controller %s node addr %s failed\n", controller_host, node_host);
		tl_msg_free_connection(comm);
		return 1;
	}

	resp = tl_msg_recv_message(comm);
	if (!resp) {
		DEBUG_INFO("Receiving ping resp from controller %s node addr %s failed\n", controller_host, node_host);
		tl_msg_free_connection(comm);
		return 1;
	}

	if (resp->msg_resp != MSG_RESP_OK) {
		DEBUG_WARN_SERVER("Got error response %d from controller %s\n", resp->msg_resp, controller_host);
		tl_msg_free_message(resp);
		tl_msg_free_connection(comm);
		return 1;
	}
	tl_msg_free_message(resp);
	tl_msg_free_connection(comm);
	return 0;
}

static int
node_client_setup_groups()
{
	struct tl_comm *comm;
	struct tl_msg msg, *resp;
	int i, count, retval;
	struct group_spec *group_spec;

	msg.msg_id = NODE_MSG_LIST_GROUP,
	msg.msg_len = 0;
	msg.msg_data = NULL;

	comm = tl_msg_remote_connection(controller_host, node_host, NODE_CONTROLLER_RECV_PORT, client_connect_timeout);
	if (!comm)
		return 1;

	retval = tl_msg_send_message(comm, &msg);
	if (retval != 0) {
		tl_msg_free_connection(comm);
		return 1;
	}

	resp = tl_msg_recv_message(comm);
	if (!resp) {
		tl_msg_free_connection(comm);
		return 1;
	}

	if (resp->msg_resp != MSG_RESP_OK) {
		tl_msg_free_message(resp);
		tl_msg_free_connection(comm);
		return 1;
	}

	count = resp->msg_len / sizeof(*group_spec);
	group_spec = (struct group_spec *)resp->msg_data;
	pthread_mutex_lock(&daemon_lock);
	for (i = 0; i < count; i++, group_spec++) {
		node_client_add_group(group_spec);
	}
	pthread_mutex_unlock(&daemon_lock);

	tl_msg_free_message(resp);
	tl_msg_free_connection(comm);
	return 0;
}

static int
node_client_setup_vdisks()
{
	struct tl_comm *comm;
	struct tl_msg msg, *resp;
	int i, count, retval;
	struct vdisk_spec *vdisk_spec;

	msg.msg_id = NODE_MSG_LIST_VDISK,
	msg.msg_len = 0;
	msg.msg_data = NULL;

	comm = tl_msg_remote_connection(controller_host, node_host, NODE_CONTROLLER_RECV_PORT, client_connect_timeout);
	if (!comm)
		return 1;

	retval = tl_msg_send_message(comm, &msg);
	if (retval != 0) {
		tl_msg_free_connection(comm);
		return 1;
	}

	resp = tl_msg_recv_message(comm);
	if (!resp) {
		tl_msg_free_connection(comm);
		return 1;
	}

	if (resp->msg_resp != MSG_RESP_OK) {
		tl_msg_free_message(resp);
		tl_msg_free_connection(comm);
		return 1;
	}

	count = resp->msg_len / sizeof(*vdisk_spec);
	vdisk_spec = (struct vdisk_spec *)resp->msg_data;
	pthread_mutex_lock(&daemon_lock);
	for (i = 0; i < count; i++, vdisk_spec++) {
		node_client_add_vdisk(vdisk_spec, 0, vdisk_spec->online);
	}
	pthread_mutex_unlock(&daemon_lock);

	tl_msg_free_message(resp);
	tl_msg_free_connection(comm);
	return 0;
}

static int
blkdev_equal(struct tl_blkdevinfo *blkdev, struct bdev_spec *spec)
{
	struct physdisk *disk1, *disk2;

	disk1 = node_client_find_disk(spec);
	if (!disk1)
		return 0;

	disk2 = tl_common_find_physdisk2(&blkdev->disk);
	if (!disk2)
		return 0;

	return (disk1 == disk2);
}

static void
node_client_insert_bdev(struct bdev_spec *spec)
{
	struct tl_blkdevinfo *blkdev;

	TAILQ_FOREACH(blkdev, &bdev_list, q_entry) {
		if (blkdev_equal(blkdev, spec)) {
			blkdev->offline = 0;
			return;
		}
	}
	node_client_add_bdev(spec);
}

static void
node_client_mark_bdevs_offline(void)
{
	struct tl_blkdevinfo *blkdev;

	TAILQ_FOREACH(blkdev, &bdev_list, q_entry) {
		blkdev->offline = 1;
	}
}

static void
node_client_remove_offline_bdevs(void)
{
	struct tl_blkdevinfo *blkdev, *next;

	TAILQ_FOREACH_SAFE(blkdev, &bdev_list, q_entry, next) {
		if (!blkdev->offline)
			continue;
		node_client_remove_bdev(blkdev);
	}
}

static void
node_client_prune_bdev(struct bdev_spec *spec)
{
	struct tl_blkdevinfo *blkdev;

	TAILQ_FOREACH(blkdev, &bdev_list, q_entry) {
		if (blkdev_equal(blkdev, spec)) {
			if (blkdev->bid != spec->bid)
				node_client_remove_bdev(blkdev);
			return;
		}
	}
}

static int
node_client_setup_bdev()
{
	struct tl_comm *comm;
	struct tl_msg msg, *resp;
	int i, count, retval;
	struct bdev_spec *bdev_spec;

	tl_common_scan_physdisk();

	msg.msg_id = NODE_MSG_LIST_BDEV,
	msg.msg_len = 0;
	msg.msg_data = NULL;

	comm = tl_msg_remote_connection(controller_host, node_host, NODE_CONTROLLER_RECV_PORT, client_connect_timeout);
	if (!comm)
		return 1;

	retval = tl_msg_send_message(comm, &msg);
	if (retval != 0) {
		tl_msg_free_connection(comm);
		return 1;
	}

	resp = tl_msg_recv_message(comm);
	if (!resp) {
		tl_msg_free_connection(comm);
		return 1;
	}

	if (resp->msg_resp != MSG_RESP_OK) {
		tl_msg_free_message(resp);
		tl_msg_free_connection(comm);
		return 1;
	}

	count = resp->msg_len / sizeof(*bdev_spec);
	bdev_spec = (struct bdev_spec *)resp->msg_data;
	pthread_mutex_lock(&daemon_lock);
	for (i = 0; i < count; i++, bdev_spec++) {
		node_client_prune_bdev(bdev_spec);
	}
	node_client_mark_bdevs_offline();

	bdev_spec = (struct bdev_spec *)resp->msg_data;
	for (i = 0; i < count; i++, bdev_spec++) {
		node_client_insert_bdev(bdev_spec);
	}

	node_client_remove_offline_bdevs();
	pthread_mutex_unlock(&daemon_lock);

	tl_msg_free_message(resp);
	tl_msg_free_connection(comm);
	return 0;
}

int
node_client_config(void)
{
	struct node_config config;
	int retval;

	config.node_type = node_type;
	strcpy(config.node_host, node_host);
	strcpy(config.controller_host, controller_host);
	strcpy(config.ha_host, ha_host);
	strcpy(config.ha_bind_host, ha_bind_host);
	config.controller_ipaddr = inet_addr(controller_host);
	config.node_ipaddr = inet_addr(node_host);
	config.ha_ipaddr = inet_addr(ha_host);
	config.ha_bind_ipaddr = inet_addr(ha_bind_host);
	config.client_send_timeout = client_send_timeout;
	config.client_connect_timeout = client_connect_timeout;
	config.controller_recv_timeout = controller_recv_timeout;
	config.node_sync_timeout = node_sync_timeout;
	config.ha_check_timeout = ha_check_timeout;
	config.ha_ping_timeout = ha_ping_timeout;
	config.fence_enabled = (fence_cmd[0] ? 1 : 0);
	retval = tl_ioctl(TLTARGIOCNODECONFIG, &config);
	return retval;
}

static void 
server_process_request(int fd, struct sockaddr_un *client_addr)
{
	struct tl_comm comm;
	struct tl_msg *msg;

	comm.sockfd = fd;

	msg = tl_msg_recv_message(&comm);

	if (!msg) {
		DEBUG_ERR("Message reception failed");
		tl_msg_close_connection(&comm);
		return;
	}

	switch (msg->msg_id) {
	case MSG_ID_DEV_MAPPING:
		pthread_mutex_lock(&daemon_lock);
		tl_server_dev_mapping(&comm, msg);
		pthread_mutex_unlock(&daemon_lock);
		break;
	case MSG_ID_RUN_DIAGNOSTICS:
		pthread_mutex_lock(&daemon_lock);
		tl_server_run_diagnostics(&comm, msg, 0);
		pthread_mutex_unlock(&daemon_lock);
		break;
	default:
		/* Invalid msg id */
		DEBUG_ERR("Invalid msg id %d in message", msg->msg_id);
		tl_server_msg_invalid(&comm, msg);
		break;
	}
}

static void *
local_server_init(void * arg)
{
	struct sockaddr_un un_addr;
	struct sockaddr_un client_addr;
	socklen_t addr_len;
	int sockfd, newfd;
	int reuse = 1;

	if ((sockfd = socket(AF_LOCAL, SOCK_STREAM, 0)) < 0) {
		DEBUG_ERR_SERVER("Unable to create listen socket\n");
		exit(EXIT_FAILURE);
	}

	if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(int)) == -1) {
		DEBUG_ERR_SERVER("Unable to setsockopt SO_REUSEADDR\n");
		close(sockfd);
		exit(EXIT_FAILURE);
	}

	unlink(MDAEMON_PATH);
	memset(&un_addr, 0, sizeof(struct sockaddr_un));
	un_addr.sun_family = AF_LOCAL;
#ifdef FREEBSD
	memcpy((char *) &un_addr.sun_path, MDAEMON_PATH, strlen(MDAEMON_PATH));
#else
	memcpy((char *) &un_addr.sun_path+1, MDAEMON_PATH, strlen(MDAEMON_PATH));
#endif
	addr_len = SUN_LEN(&un_addr); 

	if (bind(sockfd, (struct sockaddr *)&un_addr, sizeof(un_addr)) == -1)
	{
		DEBUG_ERR_SERVER("Unable to bind to mdaemon port errno %d %s\n", errno, strerror(errno));
		close(sockfd);
		exit(EXIT_FAILURE);
	}

	if (listen(sockfd, MDAEMON_BACKLOG) == -1)
	{
		DEBUG_ERR_SERVER("Listen call for mdaemon socket failed\n");
		close(sockfd);
		exit(EXIT_FAILURE);
	}

	while (1) {
		addr_len = sizeof(struct sockaddr_un);

		if ((newfd = accept(sockfd, (struct sockaddr *)&client_addr, &addr_len)) == -1) {
			DEBUG_WARN_SERVER("Client connection accept failed");
			continue;
		}

		server_process_request(newfd, &client_addr);
	}

	close(sockfd);
	pthread_exit(0);
}

static int
local_server_start(pthread_t *thread_id)
{
	int retval;

	retval = pthread_create(thread_id, NULL, local_server_init, NULL);

	if (retval != 0) {
		DEBUG_ERR("Unable to start a new thread for server\n");
		return -1;
	}
	return 0;
}


int
node_client_init(void)
{
	int retval;
	int init = 1;

	server_openlog();

	retval = node_client_read_config();
	if (retval != 0) {
		DEBUG_ERR_SERVER("Invalid node client configuration\n");
		exit(EXIT_FAILURE);
	}

	if (node_type == NODE_TYPE_MASTER && !fence_cmd[0]) {
		DEBUG_ERR_SERVER("Invalid node client configuration. Master node no longer supported without fence command\n");
		exit(EXIT_FAILURE);
	}

	retval = sys_rid_init(1);
	if (retval != 0) {
		DEBUG_ERR_SERVER("sys rid init failed\n");
		exit(EXIT_FAILURE);
	}

	node_usr_init();

	retval = local_server_start(&local_thread_id);
	if (retval != 0) {
		DEBUG_ERR_SERVER("Cannot start local server\n");
		exit(EXIT_FAILURE);
	}

	retval = pthread_create(&nc_thread_id, NULL, node_client_thread, NULL);
	if (retval != 0) {
		DEBUG_ERR("Cannot create node client thread");
		exit(EXIT_FAILURE);
	}

	client_inited = 1;
	prev_term_handler = signal(SIGTERM, nc_term_handler);

again:
	retval = node_client_register();
	if (retval != 0) {
		DEBUG_ERR_SERVER("Cannot register with controller %s\n", controller_host);
		exit(EXIT_FAILURE);
	}

	retval = node_client_config();
	if (retval != 0) {
		DEBUG_ERR_SERVER("node client config failed\n");
		exit(EXIT_FAILURE);
	}

	retval = node_client_setup_groups();
	if (retval < 0) {
		DEBUG_ERR_SERVER("Cannot setup storage groups\n");
		exit(EXIT_FAILURE);
	}

	retval = node_client_setup_bdev();
	if (retval < 0) {
		DEBUG_ERR_SERVER("Cannot set up physical disks\n");
		exit(EXIT_FAILURE);
	}

	if (retval > 0)
		goto again; 

	retval = node_client_setup_vdisks();
	if (retval < 0) {
		DEBUG_ERR_SERVER("Cannot setup VDisks\n");
		exit(EXIT_FAILURE);
	}

	if (init) {
		retval = tl_ioctl_void(TLTARGIOCLOADDONE);
		if (retval < 0) {
			DEBUG_ERR_SERVER("Finishing initialization failed\n");
			exit(EXIT_FAILURE);
		}
		init = 0;
		ietadm_qload_done();
	}

	while ((retval = node_client_test_conn()) <= 0) {
		if (retval < 0)
			exit(EXIT_FAILURE);
		sleep(delay_secs);
	}
	goto again;
}
