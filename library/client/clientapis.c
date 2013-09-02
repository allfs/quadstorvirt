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

#include <tlclntapi.h>

static int
tl_client_send_msg(struct tl_msg *msg, char *reply)
{
	struct tl_comm *tl_comm;
	struct tl_msg *resp;
	int retval;

	tl_comm = tl_msg_make_connection();
	if (!tl_comm) {
		if (msg->msg_len)
			free(msg->msg_data);
		return -1;
	}

	retval = tl_msg_send_message(tl_comm, msg);

	if (msg->msg_len)
		free(msg->msg_data);

	if (retval != 0) {
		tl_msg_free_connection(tl_comm);
		return retval;
	}

	resp = tl_msg_recv_message(tl_comm);
	if (!resp) {
		tl_msg_free_connection(tl_comm);
		return -1;
	}

	if (!reply)
		goto skip;

	if (resp->msg_len > 0)
		memcpy(reply, resp->msg_data, resp->msg_len);
	reply[resp->msg_len] = 0; /* trailing 0 ??? ensure correctness */

skip:
	retval = resp->msg_resp;
	tl_msg_free_message(resp);
	tl_msg_free_connection(tl_comm);
	return retval;
}

int
tl_client_load_conf(void)
{
	struct tl_msg msg;

	msg.msg_id = MSG_ID_LOAD_CONF;
	msg.msg_len = 0;

	return tl_client_send_msg(&msg, NULL);
}

int
tl_client_reset_logs(void)
{
	struct tl_msg msg;

	msg.msg_id = MSG_ID_RESET_LOGS;
	msg.msg_len = 0;

	return tl_client_send_msg(&msg, NULL);
}

int
tl_client_unload_conf(void)
{
	struct tl_msg msg;

	msg.msg_id = MSG_ID_UNLOAD_CONF;
	msg.msg_len = 0;

	return tl_client_send_msg(&msg, NULL);
}

int
tl_client_list_generic(char *tempfile, int msg_id)
{
	struct tl_msg msg;

	msg.msg_id = msg_id;

	msg.msg_data = malloc(512);
	if (!msg.msg_data)
		return -1;

	sprintf(msg.msg_data, "tempfile: %s\n", tempfile);
	msg.msg_len = strlen(msg.msg_data)+1;

	return tl_client_send_msg(&msg, NULL);
}

int
tl_client_clone_op(struct clone_spec *clone_spec, char *reply, int msg_id)
{
	struct tl_msg msg;

	msg.msg_id = msg_id;
	msg.msg_len = sizeof(*clone_spec);
	msg.msg_data = malloc(sizeof(*clone_spec));
	if (!msg.msg_data) {
		return -1;
	}
	memcpy(msg.msg_data, clone_spec, sizeof(*clone_spec));

	return tl_client_send_msg(&msg, reply);
}

int
tl_client_mirror_op(struct mirror_spec *mirror_spec, char *reply, int msg_id)
{
	struct tl_msg msg;

	msg.msg_id = msg_id;
	msg.msg_len = sizeof(*mirror_spec);
	msg.msg_data = malloc(sizeof(*mirror_spec));
	if (!msg.msg_data) {
		return -1;
	}
	memcpy(msg.msg_data, mirror_spec, sizeof(*mirror_spec));

	return tl_client_send_msg(&msg, reply);
}

int
tl_client_fc_rule_op(struct fc_rule_spec *fc_rule_spec, char *reply, int msg_id)
{
	struct tl_msg msg;

	msg.msg_id = msg_id;
	msg.msg_len = sizeof(*fc_rule_spec);
	msg.msg_data = malloc(sizeof(*fc_rule_spec));
	if (!msg.msg_data)
		return -1;

	memcpy(msg.msg_data, fc_rule_spec, sizeof(*fc_rule_spec));

	return tl_client_send_msg(&msg, reply);
}

int
tl_client_mirror_check_op(struct mirror_check_spec *mirror_check_spec, char *reply, int msg_id)
{
	struct tl_msg msg;

	msg.msg_id = msg_id;
	msg.msg_len = sizeof(*mirror_check_spec);
	msg.msg_data = malloc(sizeof(*mirror_check_spec));
	if (!msg.msg_data)
		return -1;

	memcpy(msg.msg_data, mirror_check_spec, sizeof(*mirror_check_spec));
	return tl_client_send_msg(&msg, reply);
}

int
tl_client_bdev_config(uint32_t bid, int msg_id, int mark, char *reply)
{
	struct tl_msg msg;

	msg.msg_id = msg_id;

	msg.msg_data = malloc(512);
	if (!msg.msg_data)
		return -1;

	sprintf(msg.msg_data, "bid: %u\nmark: %d\n", bid, mark);

	msg.msg_len = strlen(msg.msg_data)+1;

	return tl_client_send_msg(&msg, reply);
}

int
tl_client_set_vdisk_role(char *src, int mirror_role, int force, char *reply)
{
	struct tl_msg msg;

	msg.msg_id = MSG_ID_SET_VDISK_ROLE;

	msg.msg_data = malloc(512);
	if (!msg.msg_data)
		return -1;

	sprintf(msg.msg_data, "role: %d\nforce: %d\nsrc: %s\n", mirror_role, force, src);
	msg.msg_len = strlen(msg.msg_data)+1;

	return tl_client_send_msg(&msg, reply);

}

int
tl_client_vdisk_resize(char *src, unsigned long long size, int force, char *reply)
{
	struct tl_msg msg;

	msg.msg_id = MSG_ID_VDISK_RESIZE;

	msg.msg_data = malloc(512);
	if (!msg.msg_data)
		return -1;

	sprintf(msg.msg_data, "src: %s\nsize: %llu\nforce: %d\n", src, size, force);

	msg.msg_len = strlen(msg.msg_data)+1;

	return tl_client_send_msg(&msg, reply);
}

int
tl_client_tdisk_stats_reset(uint32_t target_id)
{
	struct tl_msg msg;

	msg.msg_id = MSG_ID_TDISK_STATS_RESET;

	msg.msg_data = malloc(512);
	if (!msg.msg_data)
		return -1;

	sprintf(msg.msg_data, "target_id: %d\n", target_id);
	msg.msg_len = strlen(msg.msg_data)+1;

	return tl_client_send_msg(&msg, NULL);

}

int
tl_client_delete_tdisk(uint32_t target_id)
{
	struct tl_msg msg;

	msg.msg_id = MSG_ID_DELETE_TDISK;

	msg.msg_data = malloc(512);
	if (!msg.msg_data)
		return -1;

	sprintf(msg.msg_data, "target_id: %d\n", target_id);
	msg.msg_len = strlen(msg.msg_data)+1;

	return tl_client_send_msg(&msg, NULL);
}

int
tl_client_delete_group(uint32_t group_id, char *reply)
{
	struct tl_msg msg;

	msg.msg_id = MSG_ID_DELETE_GROUP;

	msg.msg_data = malloc(512);
	if (!msg.msg_data)
		return -1;

	sprintf(msg.msg_data, "group_id: %d\n", group_id);
	msg.msg_len = strlen(msg.msg_data)+1;

	return tl_client_send_msg(&msg, reply);
}

int
tl_client_rename_pool(uint32_t group_id, char *name, char *reply)
{
	struct tl_msg msg;

	msg.msg_id = MSG_ID_RENAME_POOL;

	msg.msg_data = malloc(512);
	if (!msg.msg_data)
		return -1;

	sprintf(msg.msg_data, "group_id: %u\ngroupname: %s\n", group_id, name);
	msg.msg_len = strlen(msg.msg_data)+1;

	return tl_client_send_msg(&msg, reply);
}

int
tl_client_modify_tdisk(uint32_t target_id, int dedupe, int comp, int verify, int force_inline)
{
	struct tl_msg msg;

	msg.msg_id = MSG_ID_MODIFY_TDISK;

	msg.msg_data = malloc(512);
	if (!msg.msg_data)
		return -1;

	sprintf(msg.msg_data, "target_id: %u\ndedupe: %d\ncomp: %d\nverify: %d\ninline: %d\n", target_id, dedupe, comp, verify, force_inline);
	msg.msg_len = strlen(msg.msg_data)+1;

	return tl_client_send_msg(&msg, NULL);
}

int
tl_client_add_tdisk(char *targetname, uint64_t targetsize, int lba_shift, uint32_t group_id, char *reply)
{
	struct tl_msg msg;

	msg.msg_id = MSG_ID_ADD_TDISK;

	msg.msg_data = malloc(512);
	if (!msg.msg_data)
		return -1;

	sprintf(msg.msg_data, "targetname: %s\ntargetsize: %llu\nlba_shift: %d\ngroup_id: %u\n", targetname, (unsigned long long)targetsize, lba_shift, group_id);
	msg.msg_len = strlen(msg.msg_data)+1;

	return tl_client_send_msg(&msg, reply);
}

int
tl_client_list_clone(struct job_list *job_list, int msg_id)
{
	struct job_info *job_info;
	struct job_stats *stats;
	char tempfile[100];
	char buf[512];
	char *progress_str;
	FILE *fp;
	int fd, retval, progress, status;

	TAILQ_INIT(job_list);

	strcpy(tempfile, MKSTEMP_PREFIX);
	fd = mkstemp(tempfile);
	if (fd == -1)
		return -1;
	close(fd);

	retval = tl_client_list_generic(tempfile, msg_id);
	if (retval != 0) {
		remove(tempfile);
		return -1;
	}

	fp = fopen(tempfile, "r");
	if (!fp) {
		remove(tempfile);
		return -1;
	}

	while ((fgets(buf, sizeof(buf), fp) != NULL)) {
		job_info = alloc_buffer(sizeof(*job_info));
		if (!job_info) {
			DEBUG_WARN_NEW("Memory allocation failure\n");
			break;
		}

		stats = &job_info->stats;
		retval = sscanf(buf, "dest: %s src: %s progress: %d status: %d %u %u %u %u %u %u %u %"PRIu64" %"PRIu64" %"PRIu64" %"PRIu64" %"PRIu64" %"PRIu64" %"PRIu64"\n", job_info->dest_tdisk, job_info->src_tdisk, &progress, &status, &stats->elapsed_msecs, &stats->read_msecs, &stats->write_msecs, &stats->hash_compute_msecs, &stats->hash_lookup_msecs, &stats->dest_ipaddr, &stats->src_ipaddr, &stats->mapped_blocks, &stats->deduped_blocks, &stats->refed_blocks, &stats->bytes_read, &stats->blocks_read, &stats->blocks_written, &stats->bytes_written);
		if (retval != 18) {
			DEBUG_WARN_NEW("Invalid buf %s\n", buf);
			free(job_info);
			continue;
		}

		progress_str = job_info->progress_str;
		if (status == CLONE_STATUS_INPROGRESS) {
			sprintf(progress_str, "%d%%", progress);
		}
		else if (status == CLONE_STATUS_SUCCESSFUL) {
			strcpy(progress_str, "Done");
		}
		else {
			strcpy(progress_str, "Error");
		}
		TAILQ_INSERT_TAIL(job_list, job_info, c_entry); 
	}
	fclose(fp);
	close(fd);
	remove(tempfile);
	return 0;
}

int
tl_client_list_disks(struct d_list *dlist, int msg_id)
{
	char tempfile[100];
	FILE *fp;
	int fd;
	int retval;

	TAILQ_INIT(dlist);
	strcpy(tempfile, MKSTEMP_PREFIX);
	fd = mkstemp(tempfile);
	if (fd == -1)
		return -1;
	close(fd);

	retval = tl_client_list_generic(tempfile, msg_id);
	if (retval != 0) {
		remove(tempfile);
		return -1;
	}

	fp = fopen(tempfile, "r");
	if (!fp) {
		remove(tempfile);
		return -1;
	}

	retval = tl_common_parse_physdisk(fp, dlist);
	fclose(fp);
	remove(tempfile);
	return retval;
}

int
tl_client_list_vdisks(struct tdisk_list *tdisk_list, int msg_id)
{
	char tempfile[100];
	FILE *fp;
	int fd, retval;

	TAILQ_INIT(tdisk_list);

	strcpy(tempfile, MKSTEMP_PREFIX);
	fd = mkstemp(tempfile);
	if (fd == -1)
		return -1;
	close(fd);

	retval = tl_client_list_generic(tempfile, msg_id);
	if (retval != 0) {
		remove(tempfile);
		return -1;
	}

	fp = fopen(tempfile, "r");
	if (!fp) {
		remove(tempfile);
		return -1;
	}

	retval = tl_common_parse_tdisk(fp, tdisk_list);
	fclose(fp);
	remove(tempfile);
	return retval;
}

int
tl_client_list_groups(struct group_list *group_list, int msg_id)
{
	char tempfile[100];
	FILE *fp;
	int fd, retval;

	TAILQ_INIT(group_list);

	strcpy(tempfile, MKSTEMP_PREFIX);
	fd = mkstemp(tempfile);
	if (fd == -1)
		return -1;
	close(fd);

	retval = tl_client_list_generic(tempfile, msg_id);
	if (retval != 0) {
		remove(tempfile);
		return -1;
	}

	fp = fopen(tempfile, "r");
	if (!fp) {
		remove(tempfile);
		return -1;
	}

	retval = tl_common_parse_group(fp, group_list);
	fclose(fp);
	remove(tempfile);
	return retval;
}

int
tl_client_add_group(char *groupname, int dedupemeta, int logdata, char *reply)
{
	struct tl_msg msg;

	msg.msg_id = MSG_ID_ADD_GROUP;

	msg.msg_data = malloc(512);
	if (!msg.msg_data)
		return -1;

	sprintf(msg.msg_data, "groupname: %s\ndedupemeta: %d\nlogdata: %d\n", groupname, dedupemeta, logdata);
	msg.msg_len = strlen(msg.msg_data)+1;

	return tl_client_send_msg(&msg, reply);
}

int
tl_client_add_disk(char *dev, int comp, int log_disk, int ha_disk, uint32_t group_id, char *reply)
{
	struct tl_msg msg;

	msg.msg_id = MSG_ID_ADD_DISK;

	msg.msg_data = malloc(512);
	if (!msg.msg_data)
		return -1;

	sprintf(msg.msg_data, "group_id: %u\ncomp: %d\nlog_disk: %d\nha_disk: %d\ndev: %s\n", group_id, comp, log_disk, ha_disk, dev);
	msg.msg_len = strlen(msg.msg_data)+1;

	return tl_client_send_msg(&msg, reply);
}

int
tl_client_delete_disk(char *dev, char *reply)
{
	struct tl_msg msg;

	msg.msg_id = MSG_ID_DELETE_DISK;

	msg.msg_data = malloc(512);
	if (!msg.msg_data)
		return -1;

	sprintf(msg.msg_data, "dev: %s\n", dev);
	msg.msg_len = strlen(msg.msg_data)+1;

	return tl_client_send_msg(&msg, reply);
}

int
tl_client_rescan_disks(char *reply)
{
	struct tl_msg msg;

	msg.msg_id = MSG_ID_RESCAN_DISKS;
	msg.msg_len = 0;

	return tl_client_send_msg(&msg, reply);
}

int
tl_client_reboot_system(int msg_id)
{
	struct tl_msg msg;

	msg.msg_id = msg_id;
	msg.msg_len = 0;

	return tl_client_send_msg(&msg, NULL);
}

static int
tl_client_get_target_data(struct tl_msg *msg, void *ptr, int len)
{
	struct tl_comm *tl_comm;
	struct tl_msg *resp;
	int retval;

	tl_comm = tl_msg_make_connection();
	if (!tl_comm) {
		fprintf(stderr, "connect failed\n");
		if (msg->msg_len)
			free(msg->msg_data);
		return -1;
	}

	retval = tl_msg_send_message(tl_comm, msg);
	free(msg->msg_data);
	if (retval != 0) {
		tl_msg_free_connection(tl_comm);
		fprintf(stderr, "message transfer failed\n");
		return -1;
	}

	resp = tl_msg_recv_message(tl_comm);
	if (!resp) {
		tl_msg_free_connection(tl_comm);
		return -1;
	}

	if (resp->msg_resp != MSG_RESP_OK) {
		fprintf(stderr, "Failed msg response %d\n", resp->msg_resp);
		tl_msg_free_message(resp);
		tl_msg_free_connection(tl_comm);
		return -1;
	}

	if (resp->msg_len != len) {
		fprintf(stderr, "Invalid msg len %d required %d\n", resp->msg_len, len);
		tl_msg_free_message(resp);
		tl_msg_free_connection(tl_comm);
		return -1;
	}

	memcpy(ptr, resp->msg_data, len);
	tl_msg_free_message(resp);
	tl_msg_free_connection(tl_comm);
	return 0;
}

int
tl_client_get_mirrorconf(uint32_t target_id, struct mirror_state *mirror_state)
{
	struct tl_msg msg;

	msg.msg_id = MSG_ID_GET_MIRRORCONF;

	msg.msg_data = malloc(512);
	if (!msg.msg_data) {
		return -1;
	}

	sprintf(msg.msg_data, "target_id: %u\n", target_id);
	msg.msg_len = strlen(msg.msg_data)+1;

	return tl_client_get_target_data(&msg, mirror_state, sizeof(*mirror_state));
}

int
tl_client_get_vdiskconf(uint32_t target_id, struct vdiskconf *vdiskconf)
{
	struct tl_msg msg;

	msg.msg_id = MSG_ID_GET_VDISKCONF;

	msg.msg_data = malloc(512);
	if (!msg.msg_data) {
		return -1;
	}

	sprintf(msg.msg_data, "target_id: %u\n", target_id);
	msg.msg_len = strlen(msg.msg_data)+1;

	return tl_client_get_target_data(&msg, vdiskconf, sizeof(*vdiskconf));
}

int
tl_client_get_iscsiconf(uint32_t target_id, struct iscsiconf *iscsiconf)
{
	struct tl_msg msg;

	msg.msg_id = MSG_ID_GET_ISCSICONF;

	msg.msg_data = malloc(512);
	if (!msg.msg_data) {
		return -1;
	}

	sprintf(msg.msg_data, "target_id: %u\n", target_id);
	msg.msg_len = strlen(msg.msg_data)+1;

	return tl_client_get_target_data(&msg, iscsiconf, sizeof(*iscsiconf));
}

int
tl_client_get_diskconf(uint32_t bid, struct physdisk *disk)
{
	struct tl_msg msg;

	msg.msg_id = MSG_ID_GET_DISKCONF;

	msg.msg_data = malloc(512);
	if (!msg.msg_data) {
		return -1;
	}

	sprintf(msg.msg_data, "bid: %u\n", bid);
	msg.msg_len = strlen(msg.msg_data)+1;

	return tl_client_get_target_data(&msg, disk, sizeof(*disk));

}

int
tl_client_set_vdiskconf(struct vdiskconf *vdiskconf, int msg_id, char *reply)
{
	struct tl_msg msg;

	msg.msg_id = msg_id;

	msg.msg_data = malloc(512);
	if (!msg.msg_data)
		return -1;

	memcpy(msg.msg_data, vdiskconf, sizeof(*vdiskconf));
	msg.msg_len = sizeof(*vdiskconf);

	return tl_client_send_msg(&msg, reply);
}

int
tl_client_set_diskconf(struct physdisk *physdisk, char *reply)
{
	struct tl_msg msg;

	msg.msg_id = MSG_ID_SET_DISKCONF;

	msg.msg_data = malloc(sizeof(*physdisk) + 128);
	if (!msg.msg_data)
		return -1;

	memcpy(msg.msg_data, physdisk, sizeof(*physdisk));
	msg.msg_len = sizeof(*physdisk);

	return tl_client_send_msg(&msg, reply);

}

int
tl_client_set_iscsiconf(struct iscsiconf *iscsiconf, char *reply)
{
	struct tl_msg msg;

	msg.msg_id = MSG_ID_SET_ISCSICONF;

	msg.msg_data = malloc(512);
	if (!msg.msg_data)
		return -1;

	memcpy(msg.msg_data, iscsiconf, sizeof(*iscsiconf));
	msg.msg_len = sizeof(*iscsiconf);

	return tl_client_send_msg(&msg, reply);
}

int
tl_client_list_target_generic(uint32_t target_id, char *tempfile, int msg_id)
{
	struct tl_msg msg;

	msg.msg_id = msg_id;

	msg.msg_data = malloc(512);
	if (!msg.msg_data)
		return -1;

	sprintf(msg.msg_data, "target_id: %u\ntempfile: %s\n", target_id, tempfile);
	msg.msg_len = strlen(msg.msg_data)+1;

	return tl_client_send_msg(&msg, NULL);
}

int
tl_client_get_string(char *reply, int msg_id)
{
	struct tl_msg msg;

	msg.msg_id = msg_id;
	msg.msg_len = 0;

	return tl_client_send_msg(&msg, reply);
}

int
tl_client_dev_mapping(char *path, char *reply)
{
	struct tl_msg msg;

	msg.msg_id = MSG_ID_DEV_MAPPING; 
	msg.msg_data = malloc(512);
	if (!msg.msg_data)
		return -1;

	sprintf(msg.msg_data, "path: %s\n", path);
	msg.msg_len = strlen(msg.msg_data)+1;
	return tl_client_send_msg(&msg, reply);
}

int
tl_client_get_data(int msg_id, void *reply, int msg_len)
{
	struct tl_comm *tl_comm;
	struct tl_msg msg;
	struct tl_msg *resp;
	int retval;

	msg.msg_id = msg_id;
	msg.msg_len = 0;

	tl_comm = tl_msg_make_connection();
	if (!tl_comm) {
		fprintf(stderr, "connect failed\n");
		return -1;
	}

	retval = tl_msg_send_message(tl_comm, &msg);
	if (retval != 0) {
		tl_msg_free_connection(tl_comm);
		fprintf(stderr, "message transfer failed\n");
		return -1;
	}

	resp = tl_msg_recv_message(tl_comm);
	if (!resp) {
		tl_msg_free_connection(tl_comm);
		return -1;
	}

	if (resp->msg_len != msg_len) {
		tl_msg_free_message(resp);
		tl_msg_free_connection(tl_comm);
		return -1;
	}

	retval = resp->msg_resp;
	if (resp->msg_len > 0) {
		memcpy(reply, resp->msg_data, resp->msg_len);
	}

	tl_msg_free_message(resp);
	tl_msg_free_connection(tl_comm);
	return retval;

}

int
tl_client_send_data(int msg_id, void *msg_data, int msg_len)
{
	struct tl_comm *tl_comm;
	struct tl_msg msg;
	struct tl_msg *resp;
	int retval;

	msg.msg_id = msg_id;
	msg.msg_len = msg_len;
	msg.msg_data = msg_data;

	tl_comm = tl_msg_make_connection();
	if (!tl_comm) {
		fprintf(stderr, "connect failed\n");
		return -1;
	}

	retval = tl_msg_send_message(tl_comm, &msg);
	if (retval != 0) {
		tl_msg_free_connection(tl_comm);
		fprintf(stderr, "message transfer failed\n");
		return -1;
	}

	resp = tl_msg_recv_message(tl_comm);
	if (!resp) {
		tl_msg_free_connection(tl_comm);
		return -1;
	}

	retval = resp->msg_resp;
	tl_msg_free_message(resp);
	tl_msg_free_connection(tl_comm);
	return retval;

}

int
tl_client_get_target_id(char *name)
{
	struct tdisk_list tdisk_list;
	struct tdisk_info *tdisk_info;
	int retval;
	int target_id = -1;

	retval = tl_client_list_vdisks(&tdisk_list, MSG_ID_LIST_TDISK);
	if (retval != 0) {
		fprintf(stderr, "Getting VDisk list failed\n");
		return -1;
	}

	TAILQ_FOREACH(tdisk_info, &tdisk_list, q_entry) {
		if (tdisk_info->disabled == VDISK_DELETED)
			continue;
		if (strcmp(tdisk_info->name, name))
			continue;
		target_id = tdisk_info->target_id;
		break;
	}
	tdisk_list_free(&tdisk_list);
	return target_id;
}

int
tl_client_get_group_id(char *name)
{
	struct group_list group_list;
	struct group_info *group_info;
	int retval;
	int group_id = -1;

	retval = tl_client_list_groups(&group_list, MSG_ID_LIST_GROUP);
	if (retval != 0) {
		fprintf(stderr, "Getting pool list failed\n");
		return -1;
	}

	TAILQ_FOREACH(group_info, &group_list, q_entry) {
		if (strcmp(group_info->name, name))
			continue;
		group_id = group_info->group_id;
		break;
	} 
	return group_id;
}

int
tl_client_prompt_user(char *msg)
{
	int resp;

	fprintf(stdout, "%s", msg);
	fflush(stdout);
again:
	resp = getchar();
#ifdef FREEBSD
	fpurge(stdin);
#endif
	if ((char)(resp) == 'y')
		return 1;
	else if ((char)(resp) == 'n')
		return 0;
	else if ((char)(resp) == '\n')
		goto again;
	else if ((char)(resp) == ' ')
		goto again;
	else {
		fprintf(stdout, "Enter y/n ");
		fflush(stdout);
		goto again;
	}
}

