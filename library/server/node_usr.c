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
#include <ietadm.h>
#include <sqlint.h>
#include <physlib.h>

static int usr_accept_fd;
static int usr_shutdown;
static pthread_t nc_thread_id;
char fence_cmd[512];

extern struct mirror_check_list mirror_check_list;
static int __node_usr_mirror_check_scsi(struct mirror_check *mirror_check);

struct mirror_check *
mirror_check_locate(struct mirror_check_spec *mirror_check_spec)
{
	uint32_t mirror_ipaddr = inet_addr(mirror_check_spec->mirror_host);
	struct mirror_check *mirror_check;

	TAILQ_FOREACH(mirror_check, &mirror_check_list, q_entry) {
		if (mirror_check->mirror_ipaddr != mirror_ipaddr)
			continue;
		if (mirror_check->type != mirror_check_spec->type)
			continue;
		if (strcmp(mirror_check->value, mirror_check_spec->value))
			continue;
		return mirror_check;
	}
	return NULL;
}

static int
mirror_check_matches(struct mirror_check *mirror_check, struct mirror_check_spec *mirror_check_spec)
{
	uint32_t mirror_ipaddr = inet_addr(mirror_check_spec->mirror_host);

	if (mirror_check_spec->mirror_host[0] && mirror_ipaddr != mirror_check->mirror_ipaddr)
		return 0;

	if (mirror_check_spec->value[0] && strcmp(mirror_check_spec->value, mirror_check->value))
		return 0;

	if (mirror_check_spec->type && mirror_check_spec->type != mirror_check->type)
		return 0;
	return 1;
}

int
tl_server_remove_mirror_check(struct tl_comm *comm, struct tl_msg *msg)
{
	struct mirror_check_spec *mirror_check_spec;
	struct mirror_check *mirror_check, *next;
	int retval;

	if (msg->msg_len < sizeof(*mirror_check_spec)) {
		tl_server_msg_failure2(comm, msg, "Invalid message");
		return -1;
	}

	mirror_check_spec = (struct mirror_check_spec *)(msg->msg_data);

	TAILQ_FOREACH_SAFE(mirror_check, &mirror_check_list, q_entry, next) {
		if (!mirror_check_matches(mirror_check, mirror_check_spec))
			continue;
		retval = sql_delete_mirror_check(mirror_check);
		if (retval != 0) {
			tl_server_msg_failure2(comm, msg, "Cannot remove mirror check specification from db");
			return -1;
		}
		TAILQ_REMOVE(&mirror_check_list, mirror_check, q_entry);
		free(mirror_check);
	}
	tl_server_msg_success(comm, msg);
	return 0;
}

int
tl_server_add_mirror_check(struct tl_comm *comm, struct tl_msg *msg)
{
	struct mirror_check_spec *mirror_check_spec;
	struct mirror_check *mirror_check;
	int retval;

	if (msg->msg_len < sizeof(*mirror_check_spec)) {
		tl_server_msg_failure2(comm, msg, "Invalid message");
		return -1;
	}

	mirror_check_spec = (struct mirror_check_spec *)(msg->msg_data);

	mirror_check = mirror_check_locate(mirror_check_spec);
	if (mirror_check) {
		tl_server_msg_success(comm, msg);
		return 0;
	}

	if (!ipaddr_valid(mirror_check_spec->mirror_host)) {
		tl_server_msg_failure2(comm, msg, "Invalid mirror ipaddr\n");
		return -1;
	}

	if (mirror_check_spec->type == MIRROR_CHECK_TYPE_MDAEMON && !ipaddr_valid(mirror_check_spec->value)) {
		tl_server_msg_failure2(comm, msg, "Invalid alt ipaddr\n");
		return -1;
	}

	mirror_check = malloc(sizeof(*mirror_check));
	if (!mirror_check) {
		tl_server_msg_failure2(comm, msg, "Memory allocation failure");
		return -1;
	}

	retval = sql_add_mirror_check(mirror_check_spec);
	if (retval != 0) {
		free(mirror_check);
		tl_server_msg_failure2(comm, msg, "Cannot insert mirror check specification into db");
		return -1;
	}

	mirror_check->mirror_ipaddr = inet_addr(mirror_check_spec->mirror_host);
	mirror_check->type = mirror_check_spec->type;
	strcpy(mirror_check->value, mirror_check_spec->value);
	TAILQ_INSERT_TAIL(&mirror_check_list, mirror_check, q_entry);
	tl_server_msg_success(comm, msg);

	return 0;
}

int
tl_server_list_mirror_checks(struct tl_comm *comm, struct tl_msg *msg)
{
	char filepath[256];
	FILE *fp;
	struct mirror_check *mirror_check;
	struct sockaddr_in in_addr;

	if (sscanf(msg->msg_data, "tempfile: %s\n", filepath) != 1) {
		DEBUG_ERR_SERVER("Invalid msg data");
		tl_server_msg_failure(comm, msg);
		return -1;
	}

	fp = fopen(filepath, "w");
	if (!fp) {
		DEBUG_ERR_SERVER("Cannot open file %s\n", filepath);
		tl_server_msg_failure(comm, msg);
		return -1;
	}

        memset(&in_addr, 0, sizeof(in_addr));
	TAILQ_FOREACH(mirror_check, &mirror_check_list, q_entry) {
		fprintf(fp, "maddr: %u type: %d value: %s\n", mirror_check->mirror_ipaddr, mirror_check->type, mirror_check->value);
	}
	fclose(fp);
	tl_server_msg_success(comm, msg);
	return 0;
}

#define MIRROR_CHECK_PING_TIMEOUT 3

static int
__node_usr_mirror_check_fence(struct mirror_check *mirror_check)
{
	int retval;
	char cmd[600];

	snprintf(cmd, sizeof(cmd), "%s > /dev/null 2>&1", mirror_check->value); 
	retval = system(cmd);
	if (retval == 0)
		return USR_RSP_OK;
	else {
		DEBUG_ERR_SERVER("Executing fence command %s failed with retval %d errno %d %s\n", cmd, retval, errno, strerror(errno));
		return USR_RSP_FENCE_FAILED;
	}
}

static int
__node_usr_mirror_check_scsi(struct mirror_check *mirror_check)
{
	FILE *fp;
	char buf[512];
	char devname[256];
	int retval, serial_len;
	char serialnumber[64];
	struct sense_info sense_info;

	fp = popen(SG_SCAN_PROG_ALL, "r");

	if (!fp) {
		DEBUG_ERR_SERVER("Unable to execute program %s\n", SG_SCAN_PROG_ALL);
		return 1;
	}

	while (fgets(buf, sizeof(buf), fp) != NULL) {
		retval = sscanf(buf, "%s", devname);
		if (retval != 1)
			continue;

		serial_len = sizeof(serialnumber);
		memset(serialnumber, 0, sizeof(serialnumber));
		retval = do_unit_serial_number(devname, serialnumber, &serial_len);
		if (retval != 0)
			continue;
		if (serial_len != strlen(mirror_check->value))
			continue;
		if (memcmp(mirror_check->value, serialnumber, serial_len))
			continue;
		retval = do_test_unit_ready(devname, &sense_info);
		pclose(fp);
		if (retval == 0) {
			DEBUG_WARN_SERVER("Test Unit Ready successful, peer still active for serial number %s\n", mirror_check->value);
			return 1;
		}
		else
			return 0;
	}
	pclose(fp);
	return 0;
}

static int
__node_usr_mirror_check_daemon(struct mirror_check *mirror_check)
{
	struct sockaddr_in in_addr;
	int sockfd, status;
	int opt = 1;
	char cmd[64];

	memset(&in_addr, 0, sizeof(struct sockaddr_in));
	in_addr.sin_family = AF_INET;
	in_addr.sin_addr.s_addr = inet_addr(mirror_check->value);

	snprintf(cmd, sizeof(cmd), "ping -W %d -c 1 %s > /dev/null 2>&1", MIRROR_CHECK_PING_TIMEOUT, inet_ntoa(in_addr.sin_addr));

	status = system(cmd);
	if (status == 0)
		return 1;

	sockfd = socket(AF_INET, SOCK_STREAM, 0);
	if (sockfd < 0)
		return -1;

	if ((status = fcntl(sockfd, F_GETFL, 0)) == -1) {
		close(sockfd);
		return -1;
	}

	status |= O_NONBLOCK;
	if ((status = fcntl(sockfd, F_SETFL, status)) == -1) {
		close(sockfd);
		return -1;
	}

	status = setsockopt(sockfd, IPPROTO_TCP, TCP_NODELAY, &opt, sizeof(opt));
	if (status != 0) {
		close(sockfd);
		return -1;
	}

	memset(&in_addr, 0, sizeof(struct sockaddr_in));
	in_addr.sin_family = AF_INET;
	in_addr.sin_port = htons(USR_MSG_PORT);
	in_addr.sin_addr.s_addr = inet_addr(mirror_check->value);

	if (do_connect2(sockfd, (struct sockaddr *)&in_addr, sizeof(in_addr), 12) < 0) { /* timeout 12 */
		return 0;
	}

	close(sockfd);
	DEBUG_WARN_SERVER("connect successful, assuming mirror at %s is still alive\n", inet_ntoa(in_addr.sin_addr));
	return 1;
}

static int
__node_usr_mirror_check(struct mirror_check *mirror_check)
{
	if (mirror_check->type == MIRROR_CHECK_TYPE_MDAEMON) {
		return __node_usr_mirror_check_daemon(mirror_check);
	}
	else if (mirror_check->type == MIRROR_CHECK_TYPE_SCSI) {
		return __node_usr_mirror_check_scsi(mirror_check);
	}
	else {
		DEBUG_ERR_SERVER("Invalid mirror check type %d found\n", mirror_check->type);
		return 1;
	}
}

static void
node_usr_fence_node(struct usr_msg *msg)
{
	char cmd[600];
	int retval;

	if (!fence_cmd[0]) {
		msg->msg_rsp = USR_RSP_ERR;
		return;
	}

	snprintf(cmd, sizeof(cmd), "%s > /dev/null 2>&1", fence_cmd);
	retval = system(cmd);
	if (retval == 0)
		msg->msg_rsp = USR_RSP_OK;
	else {
		DEBUG_ERR_SERVER("Executing fence command %s failed with retval %d errno %d %s\n", cmd, retval, errno, strerror(errno));
		msg->msg_rsp = USR_RSP_FENCE_FAILED;
	}
}

static void
node_usr_mirror_check(struct usr_msg *msg)
{
	struct mirror_check *iter;
	int has_checks = 0, has_fence = 0, mirror_active = 0, retval;

	TAILQ_FOREACH(iter, &mirror_check_list, q_entry) {
		if (iter->mirror_ipaddr != msg->mirror_ipaddr)
			continue;

		has_checks = 1;

		if (iter->type == MIRROR_CHECK_TYPE_MANUAL) {
			msg->msg_rsp = USR_RSP_FENCE_MANUAL;
			return;
		}
		else if (iter->type == MIRROR_CHECK_TYPE_IGNORE) {
			msg->msg_rsp = USR_RSP_OK;
			return;
		}
		else if (iter->type == MIRROR_CHECK_TYPE_FENCE) {
			has_fence = 1;
			retval = __node_usr_mirror_check_fence(iter);
			if (retval == 0) {
				msg->msg_rsp = USR_RSP_FENCE_SUCCESSFUL;
				return;
			}
			continue;
		}

		retval = __node_usr_mirror_check(iter);
		if (retval > 0) {
			mirror_active = 1;
		}
	}

	if (has_fence)
		msg->msg_rsp = USR_RSP_FENCE_FAILED;
	else if (mirror_active)
		msg->msg_rsp = USR_RSP_MIRROR_ACTIVE;
	else if (has_checks)
		msg->msg_rsp = USR_RSP_OK;
	else {
		struct sockaddr_in in_addr;
		memset(&in_addr, 0, sizeof(in_addr));
		in_addr.sin_addr.s_addr = msg->mirror_ipaddr;
		DEBUG_WARN_SERVER("Cannot find mirrorcheck configuration for mirror ipaddr %s. Marking mirror peer as active\n", inet_ntoa(in_addr.sin_addr));
		msg->msg_rsp = USR_RSP_MIRROR_ACTIVE;
	}
	return;
}

extern struct clone_info_list clone_info_list;

static void
node_usr_complete_job(struct usr_msg *msg)
{
	struct clone_info *clone_info;

	TAILQ_FOREACH(clone_info, &clone_info_list, c_list) {
		if (clone_info->job_id == msg->job_id) {
			if (msg->msg_rsp)
				clone_info->status = CLONE_STATUS_ERROR;
			else
				clone_info->status = CLONE_STATUS_SUCCESSFUL;
			return;
		}
	}
}

#define QUADSTOR_FSTAB	"/quadstor/etc/fstab.custom"

static void
node_usr_mount_vdisk(char *name)
{
	int i, found = 0, error;
	char cmd[256];
	char dev[100];
	char tabdev[100];
	char buf[100];
	FILE *fp;

#ifdef FREEBSD
	fp = fopen(QUADSTOR_FSTAB, "r");
#else
	fp = fopen("/etc/fstab", "r");
#endif
	if (!fp) 
		return;

	snprintf(dev, sizeof(dev), "/dev/quadstor/%s", name); 
	while (fgets(buf, sizeof(buf) -1, fp) != NULL) {
		tabdev[0] = 0;
		sscanf(buf, "%s", tabdev);
		if (!tabdev[0])
			continue;
		if (strcmp(tabdev, dev))
			continue;
		found = 1;
		break;
	}
	fclose(fp);
	if (!found)
		return;

#ifdef FREEBSD
	snprintf(cmd, sizeof(cmd), "mount -F %s %s > /dev/null 2>&1", QUADSTOR_FSTAB, dev);
#else
	snprintf(cmd, sizeof(cmd), "mount %s > /dev/null 2>&1", dev);
#endif

	for (i = 0; i < 5; i++) {
		sleep(1);
		error = system(cmd);
		if (error == 0)
			break;
	}
}

static void
node_usr_attach_interface(struct usr_msg *msg, char *name)
{
	struct tdisk_info *info;
	int error;

	info = find_tdisk(msg->target_id);
	if (!info) {
		DEBUG_WARN_SERVER("Cannot find vdisk at %u\n", msg->target_id);
		return;
	}

	if (info->online)
		return;

	info->vhba_id = msg->vhba_id;
	info->iscsi_tid = msg->iscsi_tid;
	vhba_add_device(info->vhba_id);
	error = ietadm_add_target(info->iscsi_tid, &info->iscsiconf);
	if (error != 0)
		DEBUG_ERR_SERVER("Unable to create iscsi target for disk target %s host id %u", info->name, info->iscsi_tid);
	info->online = 1;
	strcpy(name, info->name);
	node_controller_vdisk_attached(info);
}

static void
node_usr_bid_valid(struct usr_msg *msg)
{
	struct tl_blkdevinfo *blkdev;

	blkdev = blkdev_find(msg->target_id);
	if (blkdev) {
		msg->msg_rsp = USR_RSP_OK;
	}
	else {
		msg->msg_rsp = USR_RSP_BID_INVALID;
	}

}

static void
node_usr_vdisk_deleted(struct usr_msg *msg)
{
	int status = msg->msg_rsp;
	uint32_t target_id = msg->target_id;
	struct tdisk_info *info;

	info = find_tdisk(target_id);
	if (!info) {
		DEBUG_ERR_SERVER("Cannot find vdisk at id %u\n", target_id);
		return;
	}

	if (status != 0) {
		info->delete_error = status;
		return;
	}
	info->name[0] = 0;
	sql_disable_tdisk(target_id);
	info->disabled = VDISK_DELETED;
	tl_ioctl(TLTARGIOCDELETETDISKPOST, info);
}

#define QUADSTOR_NOTIFICATION_TRAP "1.3.6.1.4.1.35815.2.1.0.2"
#define QUADSTOR_NOTIFICATION_TYPE "1.3.6.1.4.1.35815.2.1.1.1"
#define QUADSTOR_NOTIFICATION_MESSAGE "1.3.6.1.4.1.35815.2.1.1.2"

enum {
	NOTIFICATION_TYPE_INFORMATION = 1,
	NOTIFICATION_TYPE_WARNING = 2,
	NOTIFICATION_TYPE_ERROR = 3,
};

static void
node_usr_send_notification(int type, char *msg)
{
	char notifycmd[512];
	char host[256];
	int len;

	host[0] = 0;
	get_config_value(QUADSTOR_CONFIG_FILE, "TrapAddr", host);
	DEBUG_INFO("Trap addr %s\n", host);
	if (!host[0])
		return;

	len = strlen(msg);
	if (msg[len - 1] == '\n')
		msg[len - 1] = 0;

	snprintf(notifycmd, sizeof(notifycmd), "snmptrap -v 2c -c public %s \"\" %s %s i %d %s s \"%s\"", host, QUADSTOR_NOTIFICATION_TRAP, QUADSTOR_NOTIFICATION_TYPE, type, QUADSTOR_NOTIFICATION_MESSAGE, msg);
	DEBUG_INFO("Executing %s\n", notifycmd);
	system(notifycmd);
	return;
}

static void
node_usr_vdisk_threshold(struct usr_msg *msg, struct usr_notify *notify)
{
	struct tdisk_info *info;
	unsigned long long avail;
	int threshold;
	uint32_t target_id = msg->target_id;
	char notifymsg[256];

	info = find_tdisk(target_id);
	if (!info) {
		DEBUG_ERR_SERVER("Cannot find vdisk at id %u\n", target_id);
		return;
	}

	if (sscanf(notify->notify_msg, "%llu %d", &avail, &threshold) != 2) {
		DEBUG_ERR_SERVER("Invalid msg format %s\n", notify->notify_msg);
		return;
	}

	snprintf(notifymsg, sizeof(notifymsg), "Available space %llu in Pool %s below VDisk %s threshold of %d%%", avail, info->group->name, info->name, threshold);
	node_usr_send_notification(NOTIFICATION_TYPE_WARNING, notifymsg);
	return;
}

static void
node_usr_notify(struct usr_msg *msg, struct usr_notify *notify)
{
	switch (notify->notify_type) {
	case USR_NOTIFY_INFO:
		__DEBUG_INFO_SERVER("%s", notify->notify_msg);
		break;
	case USR_NOTIFY_WARN:
		__DEBUG_WARN_SERVER("%s", notify->notify_msg);
		node_usr_send_notification(NOTIFICATION_TYPE_WARNING, notify->notify_msg);
		break;
	case USR_NOTIFY_ERR:
		__DEBUG_ERR_SERVER("%s", notify->notify_msg);
		node_usr_send_notification(NOTIFICATION_TYPE_ERROR, notify->notify_msg);
		break;
	case USR_NOTIFY_VDISK_THRESHOLD:
		node_usr_vdisk_threshold(msg, notify);
		break;
	}
}

static void *
node_usr_process_request(void *arg)
{
	int clientfd = (int)((unsigned long)arg);
	struct usr_msg msg;
	struct usr_notify notify;
	int retval, notify_len, offset;
	char name[64];

	notify_len = sizeof(notify) - sizeof(msg);
	offset = sizeof(msg);

	while (1) {
		retval = read(clientfd, &msg, sizeof(msg));
		if (retval != sizeof(msg)) {
			close(clientfd);
			pthread_exit(0);
		}

		switch (msg.msg_id) {
		case USR_MSG_MIRROR_CHECK:
			pthread_mutex_lock(&mirror_lock);
			node_usr_mirror_check(&msg);
			pthread_mutex_unlock(&mirror_lock);
			write(clientfd, &msg, sizeof(msg));
			break;
		case USR_MSG_ATTACH_INTERFACE:
			pthread_mutex_lock(&daemon_lock);
			name[0] = 0;
			node_usr_attach_interface(&msg, name);
			pthread_mutex_unlock(&daemon_lock);
			if (name[0])
				node_usr_mount_vdisk(name);
			break;
		case USR_MSG_JOB_COMPLETED:
			pthread_mutex_lock(&daemon_lock);
			node_usr_complete_job(&msg);
			pthread_mutex_unlock(&daemon_lock);
			break;
		case USR_MSG_VDISK_DELETED:
			pthread_mutex_lock(&daemon_lock);
			node_usr_vdisk_deleted(&msg);
			pthread_mutex_unlock(&daemon_lock);
			break;
		case USR_MSG_BID_VALID:
			pthread_mutex_lock(&daemon_lock);
			node_usr_bid_valid(&msg);
			pthread_mutex_unlock(&daemon_lock);
			write(clientfd, &msg, sizeof(msg));
			break;
		case USR_MSG_FENCE_NODE:
			pthread_mutex_lock(&daemon_lock);
			node_usr_fence_node(&msg);
			pthread_mutex_unlock(&daemon_lock);
			write(clientfd, &msg, sizeof(msg));
			break;
		case USR_MSG_NOTIFY:
			retval = read(clientfd, ((uint8_t *)&notify) + offset, notify_len);
			if (retval != notify_len) {
				close(clientfd);
				pthread_exit(0);
			}
			node_usr_notify(&msg, &notify);
			break;
		}
	}
	pthread_exit(0);
}


static void *
node_usr_thread(void *arg)
{
	int clientfd;
	struct sockaddr_in client_addr;
	int opt, retval;
	pthread_t thread_id;
	socklen_t addr_len;

	while (!usr_shutdown) {
		addr_len = sizeof(struct sockaddr_in);
		if ((clientfd = accept(usr_accept_fd, (struct sockaddr *)&client_addr, &addr_len)) == -1) {
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
		setsockopt(clientfd, IPPROTO_TCP, TCP_NODELAY, &opt, sizeof(opt));
		retval = pthread_create(&thread_id, NULL, node_usr_process_request, (void *)((unsigned long)clientfd));
		if (retval != 0) {
			DEBUG_ERR_SERVER("Cannot create node usr process request thread");
			exit(EXIT_FAILURE);
		}
	}
out:
	pthread_exit(0);
}

int
node_usr_init(void)
{
	in_addr_t ipaddr;
	struct sockaddr_in in_addr;
	int reuse = 1, retval;

	if ((usr_accept_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		DEBUG_ERR_SERVER("Cannot create usr bind socket\n");
		return -1;
	}

	if (setsockopt(usr_accept_fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(int)) == -1) {
		DEBUG_ERR_SERVER("Cannot set sockopt SO_REUSEADDR\n");
		close(usr_accept_fd);
		return -1;
	}

	ipaddr = inet_addr("0.0.0.0");

	memset(&in_addr, 0, sizeof(struct sockaddr_in));
	in_addr.sin_family = AF_INET;
	in_addr.sin_port = htons(USR_MSG_PORT);
	in_addr.sin_addr.s_addr = ipaddr;
 
	if (bind(usr_accept_fd, (struct sockaddr *)&in_addr, sizeof(in_addr)) == -1) {
		DEBUG_ERR_SERVER("usr bind failed !\n");
		close(usr_accept_fd);
		return -1;
	}

	if (listen(usr_accept_fd, 64) == -1) {
		DEBUG_ERR_SERVER("Cannot listen on usr bind port\n");
		close(usr_accept_fd);
		return -1;
	}

	retval = pthread_create(&nc_thread_id, NULL, node_usr_thread, NULL);
	if (retval != 0) {
		DEBUG_ERR_SERVER("Cannot create node usr thread");
		exit(EXIT_FAILURE);
	}

	return 0;
}
