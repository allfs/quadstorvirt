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

extern struct clone_info_list clone_info_list;
extern char recv_host[];
extern int node_recv_inited;
extern int mirror_connect_timeout;

static int
node_send_msg(struct mirror_spec *mirror_spec, struct clone_info *clone_info, int msg_id)
{
	struct tl_msg msg, *resp;
	struct tl_comm *comm;
	int retval;

	comm = tl_msg_remote_connection(mirror_spec->dest_host, mirror_spec->src_host, NODE_MIRROR_RECV_PORT, mirror_connect_timeout);
	if (!comm) {
		sprintf(clone_info->errmsg, "Cannot connect to %s\n", mirror_spec->dest_host);
		DEBUG_WARN_SERVER("Cannot connect to %s\n", mirror_spec->dest_host);
		clone_info->status = MIRROR_STATUS_ERROR;
		return -1;
	}

	msg.msg_id = msg_id;
	msg.msg_data = (void *)mirror_spec; 
	msg.msg_len = sizeof(*mirror_spec);

	retval = tl_msg_send_message(comm, &msg);
	if (retval != 0) {
		sprintf(clone_info->errmsg, "Failure communicating with %s\n", mirror_spec->dest_host);
		DEBUG_WARN_SERVER("Failure communicating with %s\n", mirror_spec->dest_host);
		clone_info->status = MIRROR_STATUS_ERROR;
		tl_msg_free_connection(comm);
		return -1;
	}

	resp = tl_msg_recv_message(comm);
	if (!resp) {
		sprintf(clone_info->errmsg, "Failure to receive a response from %s\n", mirror_spec->dest_host);
		DEBUG_WARN_SERVER("Failure to receive a response from %s\n", mirror_spec->dest_host);
		clone_info->status = MIRROR_STATUS_ERROR;
		tl_msg_free_connection(comm);
		return -1;
	}

	if (resp->msg_resp != MSG_RESP_OK) {
		if (resp->msg_len > 0) {
			memcpy(clone_info->errmsg, resp->msg_data, resp->msg_len);
			clone_info->errmsg[resp->msg_len] = 0;
			DEBUG_WARN_SERVER("Server returned non zero status %x %s\n", resp->msg_resp, clone_info->errmsg);
		}
		else {
			sprintf(clone_info->errmsg, "Server returned non zero status %x\n", resp->msg_resp);
			DEBUG_WARN_SERVER("Server returned non zero status %x\n", resp->msg_resp);
		}
		clone_info->status = MIRROR_STATUS_ERROR;
		tl_msg_free_message(resp);
		tl_msg_free_connection(comm);
		return -1;
	}

	if (resp->msg_len < sizeof(*mirror_spec)) {
		sprintf(clone_info->errmsg, "Server returned invalid resp len %d\n", resp->msg_len);
		DEBUG_WARN_SERVER("Server returned invalid resp len %d\n", resp->msg_len);
		clone_info->status = MIRROR_STATUS_ERROR;
		tl_msg_free_message(resp);
		tl_msg_free_connection(comm);
		return -1;
	}

	memcpy(mirror_spec, resp->msg_data, sizeof(*mirror_spec));
	tl_msg_free_message(resp);
	tl_msg_free_connection(comm);
	return 0;
}

int
__list_mirrors(char *filepath, int prune)
{
	FILE *fp;
	struct clone_info *clone_info, *next;
	int retval;
	struct clone_config clone_config;

	fp = fopen(filepath, "w");
	if (!fp) {
		DEBUG_ERR_SERVER("Cannot open file %s\n", filepath);
		return -1;
	}

	TAILQ_FOREACH_SAFE(clone_info, &clone_info_list, c_list, next) {
		if (clone_info->op != OP_MIRROR)
			continue;

		if (clone_info->status == MIRROR_STATUS_SUCCESSFUL || clone_info->status == MIRROR_STATUS_ERROR) {
			fprintf(fp, "dest: %s src: %s progress: %d status: %d\n", clone_info->dest, clone_info->src, clone_info->progress, clone_info->status);
			if (prune) {
				TAILQ_REMOVE(&clone_info_list, clone_info, c_list);
				free(clone_info);
			}
			continue;
		}
		memset(&clone_config, 0, sizeof(clone_config));
		clone_config.dest_target_id = clone_info->dest_target_id;
		clone_config.src_target_id = clone_info->src_target_id;
		retval = tl_ioctl(TLTARGIOCMIRRORSTATUS, &clone_config);
		if (retval != 0)
			continue;
		clone_info->status = clone_config.status;
		clone_info->progress = clone_config.progress;
		fprintf(fp, "dest: %s src: %s progress: %d status: %d\n", clone_info->dest, clone_info->src, clone_info->progress, clone_info->status);
		if (prune && ((clone_info->status == MIRROR_STATUS_SUCCESSFUL || clone_info->status == MIRROR_STATUS_ERROR)))  {
			TAILQ_REMOVE(&clone_info_list, clone_info, c_list);
			free(clone_info);
		}
	}

	fclose(fp);
	return 0;
}

int
tl_server_list_mirrors(struct tl_comm *comm, struct tl_msg *msg, int prune)
{
	char filepath[256];
	int retval;

	if (sscanf(msg->msg_data, "tempfile: %s\n", filepath) != 1) {
		DEBUG_ERR_SERVER("Invalid msg data");
		tl_server_msg_failure(comm, msg);
		return -1;
	}

	retval = __list_mirrors(filepath, prune);
	if (retval != 0) {
		tl_server_msg_failure(comm, msg);
		return -1;
	}

	tl_server_msg_success(comm, msg);
	return 0;
}

#if 0
static void *
node_send_thread(void *arg)
{
	struct mirror_spec *mirror_spec = arg;
	int retval;
	struct tdisk_info *src_info;
	struct clone_info *clone_info;
	struct clone_config clone_config;

	clone_info = alloc_buffer(sizeof(*clone_info));
	if (!clone_info) {
		DEBUG_WARN("Memory allocation failure\n");
		goto out;
	}

	src_info = find_tdisk_by_name(mirror_spec->src_tdisk);
	if (!src_info) {
		DEBUG_ERR("Cannot find source VDisk %s target id %u", mirror_spec->src_tdisk, mirror_spec->src_target_id);
		free(clone_info);
		goto out;
	}

	clone_info->op = OP_MIRROR;
	clone_info->job_id = get_job_id();
	clone_info->status = MIRROR_STATUS_INPROGRESS;
	clone_info->src_target_id = src_info->target_id;

	strcpy(clone_info->dest, mirror_spec->dest_tdisk);
	strcpy(clone_info->src, mirror_spec->src_tdisk);
	pthread_mutex_lock(&daemon_lock);
	TAILQ_INSERT_TAIL(&clone_info_list, clone_info, c_list);
	pthread_mutex_unlock(&daemon_lock);

	retval = node_send_msg(mirror_spec, clone_info, NODE_MSG_NEW_VDISK);
	if (retval != 0)
		goto out;

	if (mirror_spec->clone) {
		retval = node_send_msg(mirror_spec, clone_info, NODE_MSG_CLONE); 
		if (retval != 0)
			goto out;

		while (mirror_spec->clone_status != MIRROR_STATUS_SUCCESSFUL &&
			mirror_spec->clone_status != MIRROR_STATUS_ERROR) {
			sleep(2);
			retval = node_send_msg(mirror_spec, clone_info, NODE_MSG_MIRROR_STATUS);
			if (retval != 0)
				goto out;
		}
	}

	memset(&clone_config, 0, sizeof(clone_config));
	clone_config.dest_target_id = mirror_spec->dest_target_id;
	clone_config.src_target_id = mirror_spec->src_target_id;
	clone_config.dest_ipaddr = inet_addr(mirror_spec->dest_host);
	if (mirror_spec->src_host[0])
		clone_config.src_ipaddr = inet_addr(mirror_spec->src_host);
	clone_config.attach = mirror_spec->attach;
	clone_config.mirror_type = mirror_spec->mirror_type;
	clone_config.mirror_role = mirror_spec->mirror_role;
	strcpy(clone_config.mirror_vdisk, mirror_spec->dest_tdisk);
	strcpy(clone_config.mirror_group, mirror_spec->dest_group);
	clone_config.job_id = clone_info->job_id;
	gen_rid(clone_config.sys_rid);

	retval = tl_ioctl(TLTARGIOCMIRRORVDISK, &clone_config);
	if (retval != 0) {
		sprintf(clone_info->errmsg, "Mirror failed to start for %s", mirror_spec->src_tdisk);
		DEBUG_WARN("Mirror failed to start for %s", mirror_spec->src_tdisk);
		clone_info->status = MIRROR_STATUS_ERROR;
		goto out;
	}

out:
	free(mirror_spec);
	pthread_exit(0);
}
#endif

static int
source_mirror_cancel(char *src)
{
	struct clone_info *clone_info;
	struct clone_config clone_config;
	int retval = 0;

	TAILQ_FOREACH(clone_info, &clone_info_list, c_list) {
		if (clone_info->op != OP_MIRROR)
			continue;
		if (strcmp(clone_info->src, src))
			continue;
		if (clone_info->status == MIRROR_STATUS_SUCCESSFUL || clone_info->status == MIRROR_STATUS_ERROR)
			continue;

		memset(&clone_config, 0, sizeof(clone_config));
		clone_config.src_target_id = clone_info->src_target_id;
		retval = tl_ioctl(TLTARGIOCMIRRORCANCEL, &clone_config);
		break;

	}
	return retval;
}

int
tl_server_cancel_mirror(struct tl_comm *comm, struct tl_msg *msg)
{
	int retval;
	struct mirror_spec mirror_spec;

	if (msg->msg_len < sizeof(mirror_spec)) {
		tl_server_msg_failure(comm, msg);
		return -1;
	}

	memcpy(&mirror_spec, msg->msg_data, sizeof(mirror_spec));

	retval = source_mirror_cancel(mirror_spec.src_tdisk);
	if (retval != 0) {
		tl_server_msg_failure(comm, msg);
		return -1;
	}

	tl_server_msg_success(comm, msg);
	return 0;
}

int
tl_server_remove_mirror(struct tl_comm *comm, struct tl_msg *msg)
{
	int retval;
	struct mirror_spec mirror_spec;
	struct clone_config clone_config;
	struct tdisk_info *src_info;
	char errmsg[512];

	if (msg->msg_len < sizeof(mirror_spec)) {
		tl_server_msg_failure(comm, msg);
		return -1;
	}

	memcpy(&mirror_spec, msg->msg_data, sizeof(mirror_spec));

	if (mirror_spec.src_tdisk[0])
		src_info = find_tdisk_by_name(mirror_spec.src_tdisk);
	else
		src_info = find_tdisk(mirror_spec.src_target_id);
	
	if (!src_info) {
		sprintf(errmsg, "Cannot find source VDisk %s target id %u", mirror_spec.src_tdisk, mirror_spec.src_target_id);
		tl_server_msg_failure2(comm, msg, errmsg);
		return -1;
	}

	strcpy(mirror_spec.src_tdisk, src_info->name);
	mirror_spec.src_target_id = src_info->target_id;

	retval = source_mirror_cancel(src_info->name);
	if (retval != 0) {
		sprintf(errmsg, "Cannot cancel pending mirror operations for %s", mirror_spec.src_tdisk);
		tl_server_msg_failure(comm, msg);
		return -1;
	}

	memset(&clone_config, 0, sizeof(clone_config));
	clone_config.src_target_id = src_info->target_id;
	retval = tl_ioctl(TLTARGIOCMIRRORREMOVE, &clone_config);
	if (retval != 0) {
		sprintf(errmsg, "Cannot remove mirror configuration for %s", mirror_spec.src_tdisk);
		tl_server_msg_failure2(comm, msg, errmsg);
		return -1;
	}

	tl_server_msg_success(comm, msg);
	return 0;
}

static int
source_mirror_valid(char *src)
{
	struct clone_info *clone_info;
	struct clone_config clone_config;
	int valid = 1, retval;

	TAILQ_FOREACH(clone_info, &clone_info_list, c_list) {
		if (clone_info->op != OP_MIRROR)
			continue;
		if (strcmp(clone_info->src, src))
			continue;
		if (clone_info->status == MIRROR_STATUS_SUCCESSFUL || clone_info->status == MIRROR_STATUS_ERROR)
			continue;

		memset(&clone_config, 0, sizeof(clone_config));
		clone_config.dest_target_id = clone_info->dest_target_id;
		clone_config.src_target_id = clone_info->src_target_id;
		retval = tl_ioctl(TLTARGIOCMIRRORSTATUS, &clone_config);
		if (retval != 0) {
			DEBUG_WARN_SERVER("Cannot get mirror status for src target id %u\n", clone_config.src_target_id);
			valid = -1;
			break;
		}
		clone_info->status = clone_config.status;
		clone_info->progress = clone_config.progress;

		if (clone_info->status == MIRROR_STATUS_SUCCESSFUL || clone_info->status == MIRROR_STATUS_ERROR)
			continue;
		valid = 0;
		break;
	}
	return valid;
}

int
tl_server_start_mirror(struct tl_comm *client_comm, struct tl_msg *client_msg)
{
	int retval;
	struct mirror_spec mirror_spec;
	struct tdisk_info *src_info;
	char errmsg[256];
	struct clone_info *clone_info;
	struct clone_config clone_config;
	int valid;

	if (client_msg->msg_len < sizeof(mirror_spec)) {
		tl_server_msg_failure2(client_comm, client_msg, "Invalid mirror start message");
		return -1;
	}

	memcpy(&mirror_spec, client_msg->msg_data, sizeof(mirror_spec));
	if (mirror_spec.src_tdisk[0])
		src_info = find_tdisk_by_name(mirror_spec.src_tdisk);
	else
		src_info = find_tdisk(mirror_spec.src_target_id);
	if (!src_info) {
		sprintf(errmsg, "Cannot find source VDisk %s target id %u", mirror_spec.src_tdisk, mirror_spec.src_target_id);
		goto err;
	}

	strcpy(mirror_spec.src_tdisk, src_info->name);
	mirror_spec.src_target_id = src_info->target_id;

	if (!src_info->v2_format) {
		sprintf(errmsg, "Cannot mirror older format VDisk %s", mirror_spec.src_tdisk);
		goto err;
	}

	valid = source_mirror_valid(mirror_spec.src_tdisk);
	if (valid < 0) {
		sprintf(errmsg, "Failure getting existing mirroring information");
		goto err;
	}
	else if (!valid) {
		sprintf(errmsg, "A mirroring operation exists for source VDisk %s", mirror_spec.src_tdisk);
		goto err;
	}

	if (mirror_spec.attach && (!node_recv_inited || !recv_host[0] || !ipaddr_valid(recv_host))) {
		sprintf(errmsg, "This node is unable to receive mirror messages. Check if ndrecv.conf is setup properly\n");
		goto err;
	}

	if (mirror_spec.attach) {
		strcpy(mirror_spec.src_host, recv_host);
	}

	if (strcmp(mirror_spec.src_host, mirror_spec.dest_host) == 0) {
		sprintf(errmsg, "Source and Destination host cannot be the same. Host specified %s\n", mirror_spec.src_host);
		goto err;
	}

	memcpy(mirror_spec.src_serialnumber, src_info->serialnumber, sizeof(src_info->serialnumber));
	mirror_spec.lba_shift = src_info->lba_shift;
	mirror_spec.enable_deduplication = src_info->enable_deduplication;
	mirror_spec.enable_compression = src_info->enable_compression;
	mirror_spec.enable_verify = src_info->enable_verify;
	mirror_spec.force_inline = src_info->force_inline;
	mirror_spec.src_target_id = src_info->target_id;
	mirror_spec.size = src_info->size;
	memcpy(&mirror_spec.iscsiconf, &src_info->iscsiconf, sizeof(src_info->iscsiconf));
	if (!mirror_spec.dest_group[0])
		strcpy(mirror_spec.dest_group, src_info->group->name);

	clone_info = alloc_buffer(sizeof(*clone_info));
	if (!clone_info) {
		DEBUG_WARN_SERVER("Memory allocation failure\n");
		sprintf(errmsg, "Memory allocation failure\n");
		goto err;
	}

	clone_info->op = OP_MIRROR;
	clone_info->job_id = get_job_id();
	clone_info->status = MIRROR_STATUS_INPROGRESS;
	clone_info->src_target_id = src_info->target_id;

	strcpy(clone_info->dest, mirror_spec.dest_tdisk);
	strcpy(clone_info->src, mirror_spec.src_tdisk);

	retval = node_send_msg(&mirror_spec, clone_info, NODE_MSG_NEW_VDISK);
	if (retval != 0) {
		strcpy(errmsg, clone_info->errmsg);
		free(clone_info);
		goto err;
	}

	memset(&clone_config, 0, sizeof(clone_config));
	clone_config.dest_target_id = mirror_spec.dest_target_id;
	clone_config.src_target_id = mirror_spec.src_target_id;
	clone_config.dest_ipaddr = inet_addr(mirror_spec.dest_host);
	if (mirror_spec.src_host[0])
		clone_config.src_ipaddr = inet_addr(mirror_spec.src_host);
	clone_config.attach = mirror_spec.attach;
	clone_config.mirror_type = mirror_spec.mirror_type;
	clone_config.mirror_role = mirror_spec.mirror_role;
	strcpy(clone_config.mirror_vdisk, mirror_spec.dest_tdisk);
	strcpy(clone_config.mirror_group, mirror_spec.dest_group);
	clone_config.job_id = clone_info->job_id;
	gen_rid(clone_config.sys_rid);
	TAILQ_INSERT_TAIL(&clone_info_list, clone_info, c_list);

	retval = tl_ioctl(TLTARGIOCMIRRORVDISK, &clone_config);
	if (retval != 0) {
		TAILQ_REMOVE(&clone_info_list, clone_info, c_list);
		free(clone_info);
		if (clone_config.errmsg[0])
			strcpy(errmsg, clone_config.errmsg);
		else
			sprintf(errmsg, "Mirror failed to start for %s", mirror_spec.src_tdisk);
		DEBUG_WARN_SERVER("Mirror failed to start for %s", mirror_spec.src_tdisk);
		goto err;
	}

	tl_server_msg_success(client_comm, client_msg);
	return 0;
err:
	tl_server_msg_failure2(client_comm, client_msg, errmsg);
	return -1;
}
