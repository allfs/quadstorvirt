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

#include <apicommon.h>
#include <stdarg.h>
#include <tlsrvapi.h>
#include <netdb.h>
#include <pthread.h>
#include <time.h>
#include <assert.h>
#include "diskinfo.h"
#include <sqlint.h> 
#include <ietadm.h>
#include <rawdefs.h>
#include "cluster.h"
#include "md5.h"

struct group_list group_list = TAILQ_HEAD_INITIALIZER(group_list);
struct tdisk_list tdisk_list = TAILQ_HEAD_INITIALIZER(tdisk_list);  
struct mirror_check_list mirror_check_list = TAILQ_HEAD_INITIALIZER(mirror_check_list);  
struct fc_rule_list fc_rule_list = TAILQ_HEAD_INITIALIZER(fc_rule_list);  

char default_group[TDISK_MAX_NAME_LEN];
struct tl_blkdevinfo *bdev_list[TL_MAX_DISKS];
char sys_rid[TL_RID_MAX];
pthread_mutex_t daemon_lock = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t mirror_lock = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t daemon_cond = PTHREAD_COND_INITIALIZER;
pthread_cond_t socket_cond = PTHREAD_COND_INITIALIZER;
int done_server_init;
int done_socket_init;
int log_error;
int done_load;
int done_init;

static int check_blkdev_exists(char *devname);
static int update_blkdev_info(struct tl_blkdevinfo *blkdev);
static int __list_clones(char *filepath, int prune);
static int __list_disks(char *filepath);
static int __list_configured_disks(char *filepath);
static int __list_groups(char *filepath, int configured);
static int __list_tdisks(char *filepath);
static int __list_sync_mirrors(char *filepath);

extern struct d_list disk_list;
struct mdaemon_info mdaemon_info;

uint64_t job_id;

uint64_t
get_job_id()
{
	return (++job_id);
}

void
group_conf_fill(struct group_conf *group_conf, struct group_info *group_info)
{
	strcpy(group_conf->name, group_info->name);
	group_conf->group_id = group_info->group_id;
	group_conf->dedupemeta = group_info->dedupemeta;
	group_conf->logdata = group_info->logdata;
}
 
int
group_get_disk_count(struct group_info *group_info)
{
	struct tl_blkdevinfo *blkdev;
	int count = 0;

	TAILQ_FOREACH(blkdev, &group_info->bdev_list, g_entry) {
		count++;
	}
	return count;
}

int
group_get_tdisk_count(struct group_info *group_info)
{
	struct tdisk_info *tdisk_info; 
	int count = 0;

	TAILQ_FOREACH(tdisk_info, &group_info->tdisk_list, g_entry) {
		if (tdisk_info->disabled == VDISK_DELETED)
			continue;
		count++;
	}
	return count;
}

void
bdev_group_insert(struct group_info *group_info, struct tl_blkdevinfo *blkdev)
{
	blkdev->group = group_info;
	blkdev->group_id = group_info->group_id;
	TAILQ_INSERT_TAIL(&group_info->bdev_list, blkdev, g_entry);
}

void
bdev_add(struct group_info *group_info, struct tl_blkdevinfo *blkdev)
{
	blkdev->group = group_info;
	blkdev->group_id = group_info->group_id;
	bdev_list[blkdev->bid] = blkdev;
	TAILQ_INSERT_TAIL(&group_info->bdev_list, blkdev, g_entry);
	blkdev->offline = 0;
}

void
bdev_remove(struct tl_blkdevinfo *blkdev)
{
	struct group_info *group_info = blkdev->group;

	if (group_info) {
		TAILQ_REMOVE(&group_info->bdev_list, blkdev, g_entry); 
		blkdev->group = NULL;
	}
	bdev_list[blkdev->bid] = NULL;
}

void
tdisk_group_insert(struct group_info *group_info, struct tdisk_info *tdisk_info)
{
	tdisk_info->group = group_info;
	TAILQ_INSERT_TAIL(&group_info->tdisk_list, tdisk_info, g_entry);
}

void
tdisk_add(struct group_info *group_info, struct tdisk_info *tdisk_info)
{
	tdisk_info->group = group_info;
	TAILQ_INSERT_TAIL(&group_info->tdisk_list, tdisk_info, g_entry);
	TAILQ_INSERT_TAIL(&tdisk_list, tdisk_info, q_entry);
}

void
tdisk_remove(struct tdisk_info *tdisk_info)
{
	struct group_info *group_info = tdisk_info->group;

	if (group_info) {
		TAILQ_REMOVE(&group_info->tdisk_list, tdisk_info, g_entry); 
		tdisk_info->group = NULL;
	}
	TAILQ_REMOVE(&tdisk_list, tdisk_info, q_entry); 
}

struct group_info * 
find_group(uint32_t group_id)
{

	struct group_info *group_info;

	TAILQ_FOREACH(group_info, &group_list, q_entry) {
		if (group_info->group_id == group_id)
			return group_info;
	}
	return NULL;
}

#ifdef FREEBSD
int
gen_rid(char *rid)
{
	char *tmp;
	uint32_t status;
	uuid_t uuid;

	uuid_create(&uuid, &status);
	if (status != uuid_s_ok)
		return -1;
 
	uuid_to_string(&uuid, &tmp, &status);
	if (status != uuid_s_ok)
		return -1;
	strcpy(rid, tmp);
	return 0;
}
#else
int
gen_rid(char *rid)
{
	char buf[256];
	FILE *fp;

	fp = popen("/usr/bin/uuidgen", "r");
	if (!fp) {
		DEBUG_WARN_NEW("Failed to run /usr/bin/uuidgen program\n");
		return -1;
	}

	fgets(buf, sizeof(buf), fp);
	pclose(fp);
	if (!strlen(buf)) {
		DEBUG_WARN_NEW("Failed to generate uuid string\n");
		return -1;
	}

	if (buf[strlen(buf) - 1] == '\n')
		buf[strlen(buf) - 1] = 0;

	if (strlen(buf) != 36) {
		DEBUG_WARN_NEW("Invalid uuid string %s. Invalid length %d\n", buf, (int)strlen(buf));
		return -1;
	}
	strcpy(rid, buf);
	return 0;
}
#endif

int
sync_blkdev(struct tl_blkdevinfo *blkdev)
{
	struct physdisk disk;
	int retval;

	if (blkdev->disk.initialized == -1)
		return 0;

	memset(&disk, 0, sizeof(struct physdisk));
	memcpy(&disk, &blkdev->disk, offsetof(struct physdisk, q_entry));

	retval = tl_common_sync_physdisk(&disk);
	if (retval != 0) {
		DEBUG_ERR_SERVER("Unable to locate disk. Disk offline ???\n");
		blkdev->offline = 1;
		return -1;
	}

	memcpy(&blkdev->disk, &disk, offsetof(struct physdisk, q_entry));
	retval = is_ignore_dev(blkdev->disk.info.devname);
	if (retval)
		goto err;

	strcpy(blkdev->devname, blkdev->disk.info.devname);
	retval = update_blkdev_info(blkdev);
	if (retval != 0)
	{
		DEBUG_ERR_SERVER("Updating blkdevinfo failed");
		goto err;
	}

	return 0;
err:
	return -1;
}

void
tl_server_msg_invalid(struct tl_comm *comm, struct tl_msg *msg)
{
	int msg_len = strlen(MSG_STR_INVALID_MSG);

	tl_msg_free_data(msg);
	msg->msg_len = msg_len;
	msg->msg_resp = MSG_RESP_ERROR;

	msg->msg_data = malloc(msg_len+1);
	if (!msg->msg_data)
	{
		msg->msg_len = 0;
		tl_msg_send_message(comm, msg);
		tl_msg_free_message(msg);
		tl_msg_close_connection(comm);
		return;
	}
	strcpy(msg->msg_data, MSG_STR_INVALID_MSG);
	tl_msg_send_message(comm, msg);
	tl_msg_free_message(msg);
	tl_msg_close_connection(comm);
}

static void
tl_server_send_message(struct tl_comm *comm, struct tl_msg *msg, char *new_msg)
{
	int msg_len = 0;

	if (strlen(new_msg) > 0)
	{
		msg_len = strlen(new_msg);
	}

	tl_msg_free_data(msg);

	if (msg_len)
	{
		msg->msg_data = malloc(msg_len + 1);
		if (!msg->msg_data)
		{
			msg->msg_len = 0;
			tl_msg_send_message(comm, msg);
			tl_msg_free_message(msg);
			tl_msg_close_connection(comm);
			return;
		}
	}

	if (msg_len > 0)
	{
		strcpy(msg->msg_data, new_msg);
		msg->msg_len = msg_len;
	}
	tl_msg_send_message(comm, msg);
	tl_msg_free_message(msg);
	tl_msg_close_connection(comm);
}

void
tl_server_msg_failure(struct tl_comm *comm, struct tl_msg *msg)
{
	int msg_len = strlen(MSG_STR_COMMAND_FAILED);

	tl_msg_free_data(msg);
	msg->msg_len = msg_len;
	msg->msg_resp = MSG_RESP_ERROR;

	msg->msg_data = malloc(msg_len + 1);
	if (!msg->msg_data)
		msg->msg_len = 0;
	else
		strcpy(msg->msg_data, MSG_STR_COMMAND_FAILED); 
	tl_msg_send_message(comm, msg);
	tl_msg_free_message(msg);
	tl_msg_close_connection(comm);
}

void
tl_server_msg_failure2(struct tl_comm *comm, struct tl_msg *msg, char *newmsg)
{
	int msg_len = strlen(newmsg);

	tl_msg_free_data(msg);
	msg->msg_len = msg_len;
	msg->msg_resp = MSG_RESP_ERROR;

	if (msg_len) {
		msg->msg_data = malloc(msg_len + 1);
		if (!msg->msg_data)
			msg->msg_len = 0;
		else
			strcpy(msg->msg_data, newmsg); 
	}

	tl_msg_send_message(comm, msg);
	tl_msg_free_message(msg);
	tl_msg_close_connection(comm);
}

void
tl_server_msg_success(struct tl_comm *comm, struct tl_msg *msg)
{
	tl_msg_free_data(msg);
	msg->msg_resp = MSG_RESP_OK;
	tl_msg_send_message(comm, msg);
	tl_msg_free_message(msg);
	tl_msg_close_connection(comm);
}

static int
check_blkdev_exists(char *devname)
{
	struct tl_blkdevinfo *blkdev;
	int i;

	for (i = 1; i < TL_MAX_DISKS; i++) {
		blkdev = bdev_list[i];
		if (!blkdev)
			continue;
		if (strcmp(blkdev->devname, devname) == 0)
		{
			return 1;
		}
	}
	return 0;
}

static int
update_blkdev_info(struct tl_blkdevinfo *blkdev)
{
	dev_t b_dev;
	char *devname = blkdev->devname;
	int error = 0;

	b_dev = get_device_id(devname, &error);
	if (error < 0) {
		DEBUG_ERR_SERVER("Unable to get device id for %s\n", devname);
		return -1;
	}
	blkdev->b_dev = b_dev;
	return 0;
}

static int
get_next_bid()
{
	int i;

	for (i = 1; i < TL_MAX_DISKS; i++) {
		if (bdev_list[i])
			continue;
		return i;
	}
	return 0;
}

struct tl_blkdevinfo *
blkdev_new(char *devname)
{
	struct tl_blkdevinfo *blkdev;
	dev_t b_dev;
	int error = 0;
	int bid;

	bid = get_next_bid();
	if (!bid) {
		DEBUG_ERR("Unable to get bid\n");
		return NULL;
	}
 
	b_dev = get_device_id(devname, &error);
	if (error < 0) {
		DEBUG_ERR_SERVER("Unable to get device id for %s\n", devname);
		return NULL;
	}

	blkdev = alloc_buffer(sizeof(struct tl_blkdevinfo));
	if (!blkdev) {
		DEBUG_ERR_SERVER("Memory allocation failure\n");
		return NULL;
	}
	blkdev->b_dev = b_dev;
	blkdev->bid = bid;
	return blkdev;
}

void
vhba_add_device(int vhba_id)
{
#ifdef LINUX
	char cmd[128];
	struct stat stbuf;

	if (vhba_id < 0)
		return;

	if (stat("/proc/scsi/scsi", &stbuf) == 0)
		snprintf(cmd, sizeof(cmd), "echo \"scsi add-single-device %d 0 0 0\" > /proc/scsi/scsi", vhba_id);
	else
		snprintf(cmd, sizeof(cmd), "echo \"0 0 0\" > /sys/class/scsi_host/host%d/scan", vhba_id);
	system(cmd);
#endif
}

void
vhba_remove_device(struct tdisk_info *info)
{
	char cmd[128];
#ifdef LINUX
	struct stat stbuf;
#endif

	if (info->vhba_id < 0)
		return;

	if (info->name[0]) {
		snprintf(cmd, sizeof(cmd), "umount /dev/quadstor/%s", info->name);
		system(cmd);
	}

#ifdef LINUX
	if (stat("/proc/scsi/scsi", &stbuf) == 0)
		snprintf(cmd, sizeof(cmd), "echo \"scsi remove-single-device %d 0 0 0\" > /proc/scsi/scsi", info->vhba_id);
	else
		snprintf(cmd, sizeof(cmd), "echo 1 > /sys/class/scsi_device/%d:0:0:0/device/delete", info->vhba_id);
	system(cmd);
#endif
	info->vhba_id = -1;
}

int
attach_tdisk(struct tdisk_info *info)
{
	int error;

	if (info->online)
		return 0;

	error = tl_ioctl(TLTARGIOCATTACHTDISK, info);
	if (error != 0) {
		DEBUG_ERR_SERVER("Attach vdisk ioctl failed for name %s id %d\n", info->name, info->target_id);
		return -1;
	}

	return 0;
}

static void 
detach_tdisk(struct tdisk_info *tdisk_info)
{
	vhba_remove_device(tdisk_info);
#if 0
	ietadm_delete_target(tdisk_info->iscsi_tid);
#endif
}

static int
attach_tdisks(void)
{
	struct tdisk_info *info;
	int retval;

	info = TAILQ_FIRST(&tdisk_list);
	while (info) {
		struct tdisk_info *next;
		next = TAILQ_NEXT(info, q_entry);
		if (info->disabled != VDISK_DELETED) {
			info = next;
			continue;
		}
		sql_delete_tdisk(info->target_id);
		tdisk_remove(info);
		free(info);
		info = next;
	}

	TAILQ_FOREACH(info, &tdisk_list, q_entry) {
		if (info->disabled)
			continue;

		attach_tdisk(info);
	}

	pthread_mutex_lock(&daemon_lock);
	TAILQ_FOREACH(info, &tdisk_list, q_entry) {
		if (info->disabled != VDISK_DELETING)
			continue;

		info->free_alloc = 1;
		retval = tl_ioctl(TLTARGIOCDELETETDISK, info);
		if (retval != 0)
			DEBUG_ERR_SERVER("Cannot restart delete for %s\n", info->name);
	}
	pthread_mutex_unlock(&daemon_lock);
	return 0;
}

static int
load_tdisks(struct tl_blkdevinfo *blkdev)
{
	int error;
	struct tdisk_info *info;
	struct group_info *group_info;

	TAILQ_FOREACH(info, &tdisk_list, q_entry) {
		if (info->disabled == VDISK_DELETED)
			continue;

		if (blkdev && blkdev->group->group_id != info->group_id)
			continue;

		DEBUG_BUG_ON(info->group);
		group_info = find_group(info->group_id);
		if (!group_info) {
			DEBUG_ERR_SERVER("Cannot find pool at id %u\n", info->group_id);
			return -1;
		}

		tdisk_group_insert(group_info, info);
		error = tl_ioctl(TLTARGIOCLOADTDISK, info);
		if (error != 0) {
			DEBUG_ERR_SERVER("Load vdisk ioctl failed for name %s id %d\n", info->name, info->target_id);
			if ((errno == ENOENT) && info->disabled == VDISK_DELETING)
				info->disabled = VDISK_DELETED;
			continue;
		}
	}
	return 0;
}

static int
iqn_name_valid(char *name)
{
	int i;
	int len = strlen(name);

	for (i = 0; i < len; i++) {
		if (!isalnum(name[i]) && name[i] != '_' && name[i] != '-' && name[i] != '.')
			return 0;
	}
	return 1;
}

int
get_config_value(char *path, char *name, char *value)
{
	FILE *fp;
	char buf[256];
	char *tmp, *key, *val;

	fp = fopen(path, "r");
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

		if (strcasecmp(key, name) == 0) {
			strcpy(value, val);
			break;
		}
	}
	fclose(fp);

	return 0;
}

int
load_quadstor_conf(void)
{
	char buf[256];

	strcpy(default_group, DEFAULT_GROUP_NAME);

	buf[0] = 0;
	get_config_value(QUADSTOR_CONFIG_FILE, "DefaultPool", buf);
	if (buf[0]) {
		if (group_name_exists(buf)) {
			DEBUG_WARN_SERVER("Default pool name %s already in use\n", buf);
			return 0;
		}
		if (strlen(buf) >= TDISK_MAX_NAME_LEN) {
			DEBUG_WARN_SERVER("Default pool name %s length exceeds maximum %d\n", buf, TDISK_MAX_NAME_LEN - 1);
			return 0;
		}
		strcpy(default_group, buf);
	}
	return 0;
}

int
load_configured_groups(void)
{
	struct group_info *group_info, *group_none;
	struct group_conf group_conf;
	int error = 0, retval;

	TAILQ_INIT(&group_list);

	error = sql_query_groups(&group_list);
	if (error != 0) {
		DEBUG_ERR_SERVER("sql_query_groups failed\n");
		return -1;
	}

	load_quadstor_conf();

	group_none = alloc_buffer(sizeof(*group_none));
	if (!group_none) {
		DEBUG_ERR_SERVER("Memory allocation failure\n");
		return -1;
	}

	group_none->group_id = 0;
	strcpy(group_none->name, default_group);
	group_none->dedupemeta = 1;
	group_none->logdata = 1;
	TAILQ_INIT(&group_none->bdev_list);
	TAILQ_INIT(&group_none->tdisk_list);
	group_conf_fill(&group_conf, group_none);
	retval = tl_ioctl(TLTARGIOCADDGROUP, &group_conf);
	if (retval != 0)
		error = -1;

	TAILQ_FOREACH(group_info, &group_list, q_entry) {
		DEBUG_BUG_ON(!group_info->group_id);
		group_conf_fill(&group_conf, group_info);
		retval = tl_ioctl(TLTARGIOCADDGROUP, &group_conf);
		if (retval != 0)
			error = -1;
	}

	TAILQ_INSERT_HEAD(&group_list, group_none, q_entry); 
	return error;
}

int
load_configured_tdisks(void)
{
	int error;

	TAILQ_INIT(&tdisk_list);
	error = sql_query_tdisks(&tdisk_list);
	if (error != 0)
	{
		DEBUG_ERR_SERVER("VDisk query failed\n");
		return -1;
	}

	load_tdisks(NULL);
	return 0;
}

static inline int
char_to_int(char tmp)
{
        if (tmp >= '0' && tmp <= '9')
                return (tmp - '0');
        else
                return ((tmp - 'a') + 10);
}

static uint64_t 
char_to_wwpn(char *arr) 
{
	int val1, val2;
	int i, j;
	uint8_t wwpn[8];

	if (!strlen(arr))
		return 0ULL;

	for (i = 0, j = 0; i < 24; i+=3, j++) {
		val1 = char_to_int(arr[i]);
		val2 = char_to_int(arr[i+1]);
		wwpn[j] = (val1 << 4) | val2;
	}

	return (uint64_t)wwpn[0] << 56 | (uint64_t)wwpn[1] << 48 | (uint64_t)wwpn[2] << 40 | (uint64_t)wwpn[3] << 32 | (uint64_t)wwpn[4] << 24 | (uint64_t)wwpn[5] << 16 | (uint64_t)wwpn[6] <<  8 | (uint64_t)wwpn[7];
}

void
fc_rule_config_fill(struct fc_rule *fc_rule, struct fc_rule_config *fc_rule_config)
{
	memset(fc_rule_config, 0, sizeof(*fc_rule_config));
	if (fc_rule->vdisk)
		fc_rule_config->target_id = fc_rule->vdisk->target_id;
	fc_rule_config->wwpn[0] = char_to_wwpn(fc_rule->wwpn);
	fc_rule_config->wwpn[1] = char_to_wwpn(fc_rule->wwpn1);
	fc_rule_config->rule = fc_rule->rule;
}

int
load_fc_rules(void)
{
	int error;
	struct fc_rule *fc_rule;
	struct fc_rule_config fc_rule_config;

	error = sql_query_fc_rules(&fc_rule_list);
	if (error != 0)
		return -1;

	TAILQ_FOREACH(fc_rule, &fc_rule_list, q_entry) {
		fc_rule_config_fill(fc_rule, &fc_rule_config);
		error = tl_ioctl(TLTARGIOCADDFCRULE, &fc_rule_config);
		if (error != 0)
			return error;
	}
	return 0;
}

static int
load_blkdev(struct tl_blkdevinfo *blkdev)
{
	struct bdev_info binfo;
	struct group_info *group_info;
	int error;

	memset(&binfo, 0, sizeof(struct bdev_info));
	binfo.bid = blkdev->bid;
	strcpy(binfo.devpath, blkdev->devname);
	memcpy(binfo.vendor, blkdev->disk.info.vendor, sizeof(binfo.vendor));
	memcpy(binfo.product, blkdev->disk.info.product, sizeof(binfo.product));
	memcpy(binfo.serialnumber, blkdev->disk.info.serialnumber, sizeof(binfo.serialnumber));
	binfo.isnew = 0;
	error = gen_rid(binfo.rid);
	if (error != 0) {
		blkdev->disk.initialized = -1;
		return -1;
	}

	error = tl_ioctl(TLTARGIOCNEWBLKDEV, &binfo);
	if (error != 0) {
		DEBUG_ERR_SERVER("Load vdisk ioctl failed\n");
		blkdev->disk.initialized = -1;
		return -1;
	}

	group_info = find_group(binfo.group_id);
	if (!group_info)
		return -1;

	bdev_group_insert(group_info, blkdev);
	blkdev->offline = 0;
	blkdev->ddmaster = binfo.ddmaster;
	blkdev->disk.write_cache = binfo.write_cache;
	return 0;
}
int
load_configured_disks(void)
{
	struct tl_blkdevinfo *blkdev;
	int error, i;

	error = sql_query_blkdevs(bdev_list);
	if (error != 0) {
		DEBUG_ERR_SERVER("Disks query failed\n");
		goto err;
	}

	for (i = 1; i < TL_MAX_DISKS; i++) {
		blkdev = bdev_list[i];
		if (!blkdev)
			continue;
		error = sync_blkdev(blkdev);
		if (error != 0) {
			blkdev->offline = 1;
			DEBUG_ERR_SERVER("Marking disk as offline\n");
			continue;
		}
		load_blkdev(blkdev);
	}

	return 0;
err:
	for (i = 1; i < TL_MAX_DISKS; i++) {
		blkdev = bdev_list[i];
		if (!blkdev)
			continue;
		bdev_remove(blkdev);
		free(blkdev);
	}
	return -1;
}

int
sys_rid_init(int nosql)
{
	char sqlcmd[256];
	int error = 0, retval;

	retval = gen_rid(sys_rid);
	if (retval != 0)
		return retval;

	if (nosql)
		return 0;

	snprintf(sqlcmd, sizeof(sqlcmd), "UPDATE SYSINFO SET SYS_RID='%s'", sys_rid);
	pgsql_exec_query2(sqlcmd, 0, &error, NULL, NULL);
	if (error != 0)
	{
		DEBUG_ERR_SERVER("Failed to initialize system rid cmd is %s\n", sqlcmd);
		return -1;
	}
	return 0;
}

static int
sys_rid_load()
{
	char sqlcmd[64];
	int nrows;
	PGconn *conn;
	PGresult *res;

	strcpy(sqlcmd, "SELECT SYS_RID FROM SYSINFO");
	res = pgsql_exec_query(sqlcmd, &conn);
	if (res == NULL)
	{
		DEBUG_ERR_SERVER("Error occurred in executing sqlcmd %s\n", sqlcmd); 
		return -1;
	}

	nrows = PQntuples(res);
	if (nrows != 1)
	{
		DEBUG_ERR_SERVER("Got invalid number of table rows %d\n", nrows);
		PQclear(res);
		PQfinish(conn);
		return -1;
	}

	strcpy(sys_rid, PQgetvalue(res, 0, 0));
	PQclear(res);
	PQfinish(conn);
	if (!sys_rid[0])
	{
		return sys_rid_init(0);
	}
	return 0;
}

static int
__tl_server_load(void)
{
	int retval;

	retval = sys_rid_load();
	if (retval != 0) {
		DEBUG_ERR_SERVER("Failed to load uuid information\n");
		exit(EXIT_FAILURE);

	}

	retval = tl_server_register_pid();
	if (retval != 0) {
		DEBUG_ERR_SERVER("Cannot register mdaemon pid\n");
		exit(EXIT_FAILURE);
	}

	retval = sql_query_mirror_checks(&mirror_check_list);
	if (retval != 0) {
		DEBUG_ERR_SERVER("Getting mirror check list failed\n");
		exit(EXIT_FAILURE);
	}

	retval = load_configured_groups();
	if (retval != 0) {
		DEBUG_ERR_SERVER("Getting configured pool list failed\n");
		exit(EXIT_FAILURE);
	}

	retval = load_configured_disks();
	if (retval != 0) {
		DEBUG_ERR_SERVER("Getting configured disk list failed\n");
		exit(EXIT_FAILURE);
	}

	retval = load_configured_tdisks();
	if (retval != 0) {
		DEBUG_ERR_SERVER("Load configured vdisks failed\n");
		exit(EXIT_FAILURE);
	}

	retval = load_fc_rules();
	if (retval != 0) {
		DEBUG_ERR_SERVER("Load configured fc rules failed\n");
		exit(EXIT_FAILURE);
	}

	return 0;
}

struct clone_info_list clone_info_list = TAILQ_HEAD_INITIALIZER(clone_info_list);

int
group_name_exists(char *groupname)
{
	struct group_info *group_info;

	TAILQ_FOREACH(group_info, &group_list, q_entry) {
		if (strcasecmp(group_info->name, groupname) == 0) 
			return 1;
	}
	return 0;
}

int
iqn_exists(char *iqn)
{
	struct tdisk_info *tdisk_info;

	TAILQ_FOREACH(tdisk_info, &tdisk_list, q_entry) {
		if (tdisk_info->disabled)
			continue;
		if (strcasecmp(tdisk_info->iscsiconf.iqn, iqn) == 0)
			return 1;
	}
	return 0;
}

int
target_name_exists(char *targetname)
{
	struct tdisk_info *tdisk_info;

	TAILQ_FOREACH(tdisk_info, &tdisk_list, q_entry) {
		if (strcasecmp(tdisk_info->name, targetname) == 0) 
			return 1;
	}
	return 0;
}

struct tdisk_info * 
find_tdisk(uint32_t target_id)
{

	struct tdisk_info *tdisk_info;

	TAILQ_FOREACH(tdisk_info, &tdisk_list, q_entry) {
		if (tdisk_info->target_id == target_id)
			return tdisk_info;
	}
	return NULL;
}

static int
serial_number_unique(char *serialnumber)
{
	struct tdisk_info *tdisk_info;

	DEBUG_INFO("new serial number %.32s\n", serialnumber);
	TAILQ_FOREACH(tdisk_info, &tdisk_list, q_entry) {
		DEBUG_INFO("tdisk %s serial number %.32s\n", tdisk_info->name, tdisk_info->serialnumber);
		if (memcmp(tdisk_info->serialnumber, serialnumber, 32) == 0)
			return 0;
	}
	return 1;
}

static int
construct_serialnumber(uint32_t target_id, char *serialnumber)
{
	char uniqueid[48];
	unsigned char hash[16];
	MD5_CTX ctx;
	int retval, i;

again:
	snprintf(uniqueid, sizeof(uniqueid), "%s%04X", sys_rid, target_id);
	MD5Init(&ctx);
	MD5Update(&ctx, uniqueid, strlen(uniqueid));
	MD5Final(hash, &ctx);

	hash[0] = 0x6e;
	for (i = 0; i < 16; i++) {
		snprintf(serialnumber + (i * 2), 3, "%02x", hash[i]);
	}

	if (serial_number_unique(serialnumber))
		return 0;

	retval = sys_rid_init(0);
	if (retval != 0)
		return -1;

	goto again;
}

struct tdisk_info * 
add_target(struct group_info *group_info, char *targetname, uint64_t targetsize, int lba_shift, int enable_deduplication, int enable_compression, int enable_verify, int force_inline, char *serialnumber, char *err, int attach, struct iscsiconf *srcconf)
{
	PGconn *conn;
	struct tdisk_info *tdisk_info;
	struct tdisk_info *old_info;
	int retval;

	if (srcconf && iqn_exists(srcconf->iqn)) {
		sprintf(err, "IQN %s exists for another VDisk\n", srcconf->iqn);
		return NULL;
	}
	else if (!srcconf) {
		char iqn[256];

		snprintf(iqn, sizeof(iqn), "iqn.2006-06.com.quadstor.vdisk.%s", targetname);
		if (iqn_exists(iqn)) {
			sprintf(err, "IQN %s exists for another VDisk\n", iqn);
			return NULL;
		}
	}

	tdisk_info = alloc_buffer(sizeof(struct tdisk_info));
	if (!tdisk_info) {
		sprintf(err, "Mem alloc failure\n");
		return NULL;
	}

	tdisk_info->tl_id = 0xFFFF;
	tdisk_info->vhba_id = -1;
	tdisk_info->iscsi_tid = -1;

	conn = pgsql_begin();
	if (!conn)
	{
		sprintf(err, "Unable to connect to db\n");
		free(tdisk_info);
		return NULL;
	}

	strcpy(tdisk_info->name, targetname);
	tdisk_info->size = targetsize;
	tdisk_info->enable_deduplication = enable_deduplication;
	tdisk_info->enable_compression = enable_compression;
	tdisk_info->enable_verify = enable_verify;
	tdisk_info->force_inline = force_inline;
	tdisk_info->lba_shift = lba_shift;
	tdisk_info->group_id = group_info->group_id;

	retval = sql_add_tdisk(conn, tdisk_info);
	if (retval != 0)
	{
		sprintf(err, "Unable to add new target information into DB\n");
		goto errrsp;
	}

	old_info = find_tdisk(tdisk_info->target_id);
	if (old_info) {
		sprintf(err, "Cannot find an unique target id. If VDisks have been deleted before and the system or QUADStor service restart hasn't occured since, restarting QUADStor service will fix this issue");
		goto errrsp;
	}

	if (!serialnumber) {
		retval = construct_serialnumber(tdisk_info->target_id, tdisk_info->serialnumber);
		if (retval != 0) {
			sprintf(err, "Cannot generate unique serial number\n");
			goto errrsp;
		}
	} else {
		memcpy(tdisk_info->serialnumber, serialnumber, sizeof(tdisk_info->serialnumber));
	}

	retval = tl_ioctl(TLTARGIOCNEWTDISK, tdisk_info);
	if (retval != 0)
	{
		sprintf(err, "Unable to insert new target information in kernel\n");
		goto errrsp;
	}

	retval = sql_update_tdisk_block(conn, tdisk_info);
	if (retval != 0)
	{
		sprintf(err, "Unable to update new target start block\n");
		goto errrsp;
	}

	retval = ietadm_default_settings(conn, tdisk_info, srcconf);
	if (retval != 0) {
		sprintf(err, "Unable to set default iscsi settings\n");
		goto errrsp;
	}

	retval = pgsql_commit(conn);
	if (retval != 0)
	{
		sprintf(err, "Unable to commit transaction\n");
		goto senderr;
	}

	tdisk_add(group_info, tdisk_info);
	node_controller_vdisk_added(tdisk_info);
	if (attach) {
		tdisk_info->attach = attach;
		attach_tdisk(tdisk_info);
	}
	return tdisk_info;
errrsp:
	pgsql_rollback(conn);
senderr:
	free(tdisk_info);
	return NULL;
}

struct group_info *
find_group_by_name(char *name)
{
	struct group_info *group_info;

	TAILQ_FOREACH(group_info, &group_list, q_entry) {
		if (strcasecmp(group_info->name, name) == 0) 
			return group_info;
	}
	return NULL;
}
struct tdisk_info *
find_tdisk_by_name(char *name)
{
	struct tdisk_info *tdisk_info;

	TAILQ_FOREACH(tdisk_info, &tdisk_list, q_entry) {
		if (strcasecmp(tdisk_info->name, name) == 0) 
			return tdisk_info;
	}
	return NULL;
}

static int
source_clone_valid(char *src)
{
	struct clone_info *clone_info;
	struct clone_config clone_config;
	int valid = 1, retval;

	TAILQ_FOREACH(clone_info, &clone_info_list, c_list) {
		if (clone_info->op != OP_CLONE)
			continue;
		if (strcmp(clone_info->src, src))
			continue;
		if (clone_info->status == CLONE_STATUS_SUCCESSFUL || clone_info->status == CLONE_STATUS_ERROR)
			continue;

		memset(&clone_config, 0, sizeof(clone_config));
		clone_config.dest_target_id = clone_info->dest_target_id;
		clone_config.src_target_id = clone_info->src_target_id;
		retval = tl_ioctl(TLTARGIOCCLONESTATUS, &clone_config);
		if (retval != 0) {
			DEBUG_WARN_SERVER("Cannot get clone status for src target id %u\n", clone_config.src_target_id);
			valid = -1;
			break;
		}
		clone_info->status = clone_config.status;
		clone_info->progress = clone_config.progress;

		if (clone_info->status == CLONE_STATUS_SUCCESSFUL || clone_info->status == CLONE_STATUS_ERROR)
			continue;
		valid = 0;
		break;
	}
	return valid;
}

int
__tl_server_start_clone(char *src, char *dest, char *dest_pool, char *errmsg)
{
	struct tdisk_info *src_info, *dest_info;
	int retval;
	struct clone_config clone_config;
	struct clone_info *clone_info;
	struct group_info *group_info;
	int valid;

	valid = source_clone_valid(src);
	if (valid < 0) {
		sprintf(errmsg, "Failure getting existing clones information");
		return -1;
	}
	else if (!valid) {
		sprintf(errmsg, "A cloning operation exists for source VDisk %s", src);
		return -1;
	}

	src_info = find_tdisk_by_name(src);
	if (!src_info) {
		sprintf(errmsg, "Cannot find source VDisk with name %s", src);
		return -1;
	}

	retval = target_name_exists(dest);
	if (retval) {
		sprintf(errmsg, "A VDisk with name %s already exists", dest);
		return -1;
	}

	retval = target_name_valid(dest);
	if (!retval) {
		sprintf(errmsg, "Invalid clone VDisk with name %s", dest);
		return -1;
	}

	clone_info = alloc_buffer(sizeof(*clone_info));
	if (!clone_info) {
		sprintf(errmsg, "Memory allocation failure\n");
		return -1;
	}
	clone_info->job_id = get_job_id();

	if (dest_pool[0]) {
		group_info = find_group_by_name(dest_pool);
		if (!group_info) {
			sprintf(errmsg, "Cannot find pool %s\n", dest_pool);
			free(clone_info);
			return -1;
		}
	}
	else {
		group_info = src_info->group;
		if (!group_info) {
			sprintf(errmsg, "Cannot find pool at id %u\n", src_info->group_id);
			free(clone_info);
			return -1;
		}
	}

	dest_info = add_target(group_info, dest, src_info->size, src_info->lba_shift, src_info->enable_deduplication, src_info->enable_compression, src_info->enable_verify, src_info->force_inline, NULL, errmsg, 0, NULL);
	if (!dest_info) {
		free(clone_info);
		return -1;
	}
	memset(&clone_config, 0, sizeof(clone_config));
	clone_config.src_target_id = src_info->target_id;
	clone_config.dest_target_id = dest_info->target_id;
	clone_config.job_id = clone_info->job_id;
	DEBUG_INFO("start clone for %s to %s\n", src, dest);
	retval = tl_ioctl(TLTARGIOCCLONEVDISK, &clone_config);
	if (retval != 0) { 
		free(clone_info);
		sprintf(errmsg, "Clone operation failed %s", dest);
		return -1;
	}
	strcpy(clone_info->dest, dest);
	strcpy(clone_info->src, src);
	clone_info->dest_target_id = clone_config.dest_target_id;
	clone_info->src_target_id = clone_config.src_target_id;
	clone_info->op = OP_CLONE;
	TAILQ_INSERT_TAIL(&clone_info_list, clone_info, c_list);
	return 0;
}

static int
__tl_server_disk_config(struct tl_blkdevinfo *blkdev, int mark, int prop)
{
	struct bdev_info binfo;
	int retval;
	unsigned long int ioctl_cmd = 0;

	memset(&binfo, 0, sizeof(binfo));
	binfo.bid = blkdev->bid;
	switch (prop) {
	case DISK_PROP_HA:
		binfo.ha_disk = mark;
		ioctl_cmd = TLTARGIOCHACONFIG;
		break;
	case DISK_PROP_UNMAP:
		binfo.unmap = mark;
		ioctl_cmd = TLTARGIOCUNMAPCONFIG;
		break;
	case DISK_PROP_WC:
		binfo.write_cache = mark;
		ioctl_cmd = TLTARGIOCWCCONFIG;
		break;
	default:
		return -1;
	}
	retval = tl_ioctl(ioctl_cmd, &binfo);
	return retval;
}

static int
tl_server_unmap_config(struct tl_comm *comm, struct tl_msg *msg)
{
	char errmsg[128];
	uint32_t bid;
	int mark, retval;
	struct tl_blkdevinfo *blkdev;

	if (sscanf(msg->msg_data, "bid: %u\nmark: %d\n", &bid, &mark) != 2) {
		snprintf(errmsg, sizeof(errmsg), "Invalid unmap config message");
		goto senderr;
	}

	if (!bid || mark < 0 || mark > 1) {
		snprintf(errmsg, sizeof(errmsg), "Invalid unmap config message");
		goto senderr;
	}

	blkdev = blkdev_find(bid);
	if (!blkdev) {
		snprintf(errmsg, sizeof(errmsg), "Invalid unmap config message. Cannot find disk at ID %d", bid);
		goto senderr;
	}

	retval = __tl_server_disk_config(blkdev, mark, DISK_PROP_UNMAP);
	if (retval != 0) {
		snprintf(errmsg, sizeof(errmsg), "Error changing unmap properties for disk\n");
		goto senderr;
	}

	tl_server_msg_success(comm, msg);
	return 0;
senderr:
	tl_server_msg_failure2(comm, msg, errmsg);
	return -1;
}

static int
tl_server_ha_config(struct tl_comm *comm, struct tl_msg *msg)
{
	char errmsg[128];
	uint32_t bid;
	int mark, retval;
	struct tl_blkdevinfo *blkdev;

	if (sscanf(msg->msg_data, "bid: %u\nmark: %d\n", &bid, &mark) != 2) {
		snprintf(errmsg, sizeof(errmsg), "Invalid ha config message");
		goto senderr;
	}

	if (!bid || mark < 0 || mark > 1) {
		snprintf(errmsg, sizeof(errmsg), "Invalid ha config message");
		goto senderr;
	}

	blkdev = blkdev_find(bid);
	if (!blkdev) {
		snprintf(errmsg, sizeof(errmsg), "Invalid ha config message. Cannot find disk at ID %d", bid);
		goto senderr;
	}

	retval = __tl_server_disk_config(blkdev, mark, DISK_PROP_HA);
	if (retval != 0) {
		snprintf(errmsg, sizeof(errmsg), "Error changing ha properties for disk\n");
		goto senderr;
	}

	tl_server_msg_success(comm, msg);
	return 0;
senderr:
	tl_server_msg_failure2(comm, msg, errmsg);
	return -1;
}

static int
__tl_server_vdisk_rename(struct tdisk_info *tdisk_info, char *targetname, char *err)
{
	PGconn *conn;
	struct tdisk_info tmp;
	int retval;

	if (target_name_exists(targetname)) {
		sprintf(err, "VDisk name %s exists\n", targetname);
		return -1;
	}

	if (strlen(targetname) >  TDISK_NAME_LEN) {
		sprintf(err, "VDisk name can be upto a maximum of %d characters", TDISK_NAME_LEN);
		return -1;
	}

	if (!target_name_valid(targetname)) {
		sprintf(err, "VDisk name can only contain alphabets, numbers, underscores and hyphens");
		return -1;
	}

	conn = pgsql_begin();
	if (!conn) {
		sprintf(err, "Unable to connect to db\n");
		goto senderr;
	}

	retval = sql_rename_vdisk(tdisk_info->target_id, targetname);
	if (retval != 0) {
		sprintf(err, "Update db with new vdisk name failed\n");
		goto rollback;
	}

	memcpy(&tmp, tdisk_info, sizeof(tmp));
	strcpy(tmp.name, targetname);
	retval = tl_ioctl(TLTARGIOCRENAMETDISK, &tmp);
	if (retval != 0) {
		sprintf(err, "Changing vdisk name failed\n");
		goto rollback;
	}

	retval = pgsql_commit(conn);
	if (retval != 0) {
		sprintf(err, "Unable to commit transaction\n");
		goto senderr;
	}
	strcpy(tdisk_info->name, targetname);
	return 0;

rollback:
	pgsql_rollback(conn);
senderr:
	return -1;
}

static int
__tl_server_vdisk_resize(struct tdisk_info *tdisk_info, uint64_t size, int force, char *errmsg)
{
	int retval;
	uint64_t old_size;

	if (size == tdisk_info->size)
		return 0;

	if (!size || (!force && size < tdisk_info->size) || size > MAX_TARGET_SIZE) {
		sprintf(errmsg, "Invalid VDisk size %llu (bytes) specified for resize\n", (unsigned long long)size);
		return -1;
	}

	old_size = tdisk_info->size;
	tdisk_info->size = size;
	retval = tl_ioctl(TLTARGIOCRESIZETDISK, tdisk_info);
	if (retval != 0) {
		tdisk_info->size = old_size;
		sprintf(errmsg, "Unable to insert VDisk with new size information\n");
		return -1;
	}
	return 0;
}

static int
__tl_server_set_vdisk_role(struct tdisk_info *tdisk_info, int mirror_role, char *errmsg)
{
	int retval;

	tdisk_info->mirror_state.mirror_role = mirror_role;
	retval = tl_ioctl(TLTARGIOCSETMIRRORROLE, tdisk_info);
	if (retval != 0) {
		sprintf(errmsg, "Setting mirror role for %s failed. Ioctl failure\n", tdisk_info->name);
	}

	return retval;
}

static int
__list_sync_mirrors(char *filepath)
{
	FILE *fp;
	struct tdisk_info *tdisk_info;
	struct mirror_state *mirror_state;
	struct sockaddr_in in_addr;
	char status[64];
	int retval;

	fp = fopen(filepath, "w");
	if (!fp) {
		DEBUG_ERR_SERVER("Cannot open file %s\n", filepath);
		return -1;
	}

	TAILQ_FOREACH(tdisk_info, &tdisk_list, q_entry) {
		if (tdisk_info->disabled)
			continue;
		retval = tl_ioctl(TLTARGIOCTDISKSTATS, tdisk_info);
		if (retval != 0) {
			DEBUG_WARN_SERVER("Getting VDisk information failed for %s\n", tdisk_info->name);
			continue;
		}

		mirror_state = &tdisk_info->mirror_state;
		if (!mirror_state->mirror_ipaddr)
			continue;

		memset(&in_addr, 0, sizeof(in_addr));
		in_addr.sin_addr.s_addr = mirror_state->mirror_ipaddr;

		get_mirror_status_str(mirror_state, status);

		fprintf(fp, "dest: %s src: %s pool: %s daddr: %s role: %s status: %s\n", mirror_state->mirror_vdisk, tdisk_info->name, mirror_state->mirror_group, inet_ntoa(in_addr.sin_addr), mirror_role_str(mirror_state->mirror_role), status);
	}
	fclose(fp);
	return 0;
}

static int
tl_server_list_sync_mirrors(struct tl_comm *comm, struct tl_msg *msg)
{
	char filepath[256];
	int retval;

	if (sscanf(msg->msg_data, "tempfile: %s\n", filepath) != 1) {
		DEBUG_ERR_SERVER("Invalid msg data");
		tl_server_msg_failure(comm, msg);
		return -1;
	}

	retval = __list_sync_mirrors(filepath);
	if (retval != 0) {
		tl_server_msg_failure(comm, msg);
		return -1;
	}
	tl_server_msg_success(comm, msg);
	return 0;
}

static int
tl_server_set_vdisk_role(struct tl_comm *comm, struct tl_msg *msg)
{
	char src[40];
	char errmsg[256];
	int mirror_role, retval, force;
	struct tdisk_info *tdisk_info;

	src[0] = 0;
	force = 0;

	if (sscanf(msg->msg_data, "role: %d\nforce: %d\nsrc: %[^\n]", &mirror_role, &force, src) < 2) {
		snprintf(errmsg, sizeof(errmsg), "Invalid VDisk role message");
		goto senderr;
	}

	if (src[0]) {
		tdisk_info = find_tdisk_by_name(src);
		if (!tdisk_info) {
			snprintf(errmsg, sizeof(errmsg), "Cannot locate VDisk %s", src);
			goto senderr;
		}
		if (tdisk_info->disabled) {
			snprintf(errmsg, sizeof(errmsg), "VDisk %s is disabled or queued for deletion", src);
			goto senderr;
		}

		retval = __tl_server_set_vdisk_role(tdisk_info, mirror_role, errmsg);
		if (retval != 0)
			goto senderr;
	}
	else if (force) {
		TAILQ_FOREACH(tdisk_info, &tdisk_list, q_entry) {
			if (tdisk_info->disabled)
				continue;
			retval = __tl_server_set_vdisk_role(tdisk_info, mirror_role, errmsg);
			if (retval != 0)
				goto senderr;
		}
	}
	else {
		snprintf(errmsg, sizeof(errmsg), "Invalid VDisk role message");
		goto senderr;
	}

	tl_server_msg_success(comm, msg);
	return 0;
senderr:
	tl_server_msg_failure2(comm, msg, errmsg);
	return -1;
}

static int
tl_server_vdisk_resize(struct tl_comm *comm, struct tl_msg *msg)
{
	char src[40];
	char errmsg[256];
	unsigned long long size;
	struct tdisk_info *tdisk_info;
	int retval, force;

	if (sscanf(msg->msg_data, "src: %s\nsize: %llu\nforce: %d\n", src, &size, &force) != 3) {
		snprintf(errmsg, sizeof(errmsg), "Invalid vdisk resize message");
		tl_server_msg_failure2(comm, msg, errmsg);
		return -1;
	}

	tdisk_info = find_tdisk_by_name(src);
	if (!tdisk_info) {
		snprintf(errmsg, sizeof(errmsg), "Cannot find source VDisk with name %s", src);
		tl_server_msg_failure2(comm, msg, errmsg);
		return -1;
	}

	retval = __tl_server_vdisk_resize(tdisk_info, size, force, errmsg);
	if (retval == 0)
		tl_server_msg_success(comm, msg);
	else
		tl_server_msg_failure2(comm, msg, errmsg);
	return retval;
}

static int
tl_server_start_clone(struct tl_comm *comm, struct tl_msg *msg)
{
	char errmsg[256];
	int retval;
	struct clone_spec clone_spec;

	if (msg->msg_len < sizeof(clone_spec)) {
		snprintf(errmsg, sizeof(errmsg), "Invalid clone start message");
		tl_server_msg_failure2(comm, msg, errmsg);
		return -1;
	}

	memcpy(&clone_spec, msg->msg_data, sizeof(clone_spec));

	retval = __tl_server_start_clone(clone_spec.src_tdisk, clone_spec.dest_tdisk, clone_spec.dest_group, errmsg);
	if (retval != 0) {
		tl_server_msg_failure2(comm, msg, errmsg);
		return -1;
	}

	tl_server_msg_success(comm, msg);
	return 0;
}

static void 
cancel_all_clone_ops(void)
{
	struct clone_info *clone_info, *next;
	struct clone_config clone_config;

	TAILQ_FOREACH_SAFE(clone_info, &clone_info_list, c_list, next) {
		if (clone_info->status == CLONE_STATUS_SUCCESSFUL || clone_info->status == CLONE_STATUS_ERROR)
			continue;

		memset(&clone_config, 0, sizeof(clone_config));
		clone_config.dest_target_id = clone_info->dest_target_id;
		clone_config.src_target_id = clone_info->src_target_id;
		if (clone_info->op == OP_CLONE)
			tl_ioctl(TLTARGIOCCLONECANCEL, &clone_config);
		else
			tl_ioctl(TLTARGIOCMIRRORCANCEL, &clone_config);
		TAILQ_REMOVE(&clone_info_list, clone_info, c_list);
		free(clone_info);
		break;

	}
}

static int
source_clone_cancel(char *src)
{
	struct clone_info *clone_info;
	struct clone_config clone_config;
	int retval = 0;

	TAILQ_FOREACH(clone_info, &clone_info_list, c_list) {
		if (clone_info->op != OP_CLONE)
			continue;
		if (strcmp(clone_info->src, src))
			continue;
		if (clone_info->status == CLONE_STATUS_SUCCESSFUL || clone_info->status == CLONE_STATUS_ERROR)
			continue;

		memset(&clone_config, 0, sizeof(clone_config));
		clone_config.dest_target_id = clone_info->dest_target_id;
		clone_config.src_target_id = clone_info->src_target_id;
		retval = tl_ioctl(TLTARGIOCCLONECANCEL, &clone_config);
		break;

	}
	return retval;
}

static int
tl_server_cancel_clone(struct tl_comm *comm, struct tl_msg *msg)
{
	struct clone_spec clone_spec;
	int retval;

	if (msg->msg_len < sizeof(clone_spec)) {
		tl_server_msg_failure(comm, msg);
		return -1;
	}

	memcpy(&clone_spec, msg->msg_data, sizeof(clone_spec));
	retval = source_clone_cancel(clone_spec.src_tdisk);
	if (retval != 0) {
		tl_server_msg_failure(comm, msg);
		return -1;
	}

	tl_server_msg_success(comm, msg);
	return 0;
}

#if 0
static void
check_clone_attached(struct clone_info *clone_info)
{
	struct tdisk_info *info;

	if (clone_info->attached)
		return;

	info = find_tdisk_by_name(clone_info->dest);
	if (!info) {
		DEBUG_WARN_SERVER("Cannot find VDisk %s\n", clone_info->dest);
		return;
	}
	attach_tdisk(info);
	clone_info->attached = 1;
}
#endif

static int
__list_clones(char *filepath, int prune)
{
	struct clone_info *clone_info, *next;
	struct clone_config clone_config;
	FILE *fp;
	int retval;

	fp = fopen(filepath, "w");
	if (!fp) {
		DEBUG_ERR_SERVER("Cannot open file %s\n", filepath);
		return -1;
	}

	TAILQ_FOREACH_SAFE(clone_info, &clone_info_list, c_list, next) {
		if (clone_info->op != OP_CLONE)
			continue;

		if (clone_info->status == CLONE_STATUS_SUCCESSFUL || clone_info->status == CLONE_STATUS_ERROR) {
			fprintf(fp, "dest: %s src: %s progress: %d status: %d\n", clone_info->dest, clone_info->src, clone_info->progress, clone_info->status);
#if 0 
			if (clone_info->status == CLONE_STATUS_SUCCESSFUL)
				check_clone_attached(clone_info);
#endif

			if (prune) {
				TAILQ_REMOVE(&clone_info_list, clone_info, c_list);
				free(clone_info);
			}
			continue;
		}
		memset(&clone_config, 0, sizeof(clone_config));
		clone_config.dest_target_id = clone_info->dest_target_id;
		clone_config.src_target_id = clone_info->src_target_id;
		retval = tl_ioctl(TLTARGIOCCLONESTATUS, &clone_config);
		if (retval != 0)
			continue;
		clone_info->status = clone_config.status;
		clone_info->progress = clone_config.progress;
		fprintf(fp, "dest: %s src: %s progress: %d status: %d\n", clone_info->dest, clone_info->src, clone_info->progress, clone_info->status);
#if 0
		if (clone_info->status == CLONE_STATUS_SUCCESSFUL)
			check_clone_attached(clone_info);
#endif

		if (prune && ((clone_info->status == CLONE_STATUS_SUCCESSFUL || clone_info->status == CLONE_STATUS_ERROR)))  {
			TAILQ_REMOVE(&clone_info_list, clone_info, c_list);
			free(clone_info);
		}
	}
	fclose(fp);
	return 0;
}

static int
tl_server_list_clones(struct tl_comm *comm, struct tl_msg *msg, int prune)
{
	char filepath[256];
	int retval;

	if (sscanf(msg->msg_data, "tempfile: %s\n", filepath) != 1)
	{
		DEBUG_ERR_SERVER("Invalid msg data");
		tl_server_msg_failure(comm, msg);
		return -1;
	}

	retval = __list_clones(filepath, prune);
	if (retval != 0) {
		tl_server_msg_failure(comm, msg);
		return -1;
	}

	tl_server_msg_success(comm, msg);
	return 0;
}

int
tl_server_dev_mapping(struct tl_comm *comm, struct tl_msg *msg)
{
	char path[256];
	char name[64];
	int retval, serial_len;
	struct tdisk_info *tdisk_info, *ret = NULL;
	char serialnumber[64];

	if (sscanf(msg->msg_data, "path: %s\n", path) != 1) {
		DEBUG_ERR_SERVER("Invalid msg data");
		tl_server_msg_failure(comm, msg);
		return -1;
	}

	serial_len = sizeof(serialnumber);
	memset(serialnumber, 0, sizeof(serialnumber));
	retval = do_unit_serial_number(path, serialnumber, &serial_len);
	if (retval != 0) {
		DEBUG_ERR_SERVER("Reading serial number failed for %s", path);
		tl_server_msg_failure(comm, msg);
		return -1;
	}

	TAILQ_FOREACH(tdisk_info, &tdisk_list, q_entry) {
		if (memcmp(tdisk_info->serialnumber, serialnumber, 32))
			continue;
		ret = tdisk_info;
		break;
	}

	if (!ret) {
		DEBUG_ERR_SERVER("Cannot find VDisk for %s", path);
		tl_server_msg_failure(comm, msg);
		return -1;
	}
	strcpy(name, ret->name);
	msg->msg_resp = MSG_RESP_OK;
	tl_server_send_message(comm, msg, name);
	return 0;
}

static int
__list_disks(char *filepath)
{
	FILE *fp;
	struct physdisk *disk;

	fp = fopen(filepath, "w");
	if (!fp) {
		DEBUG_ERR_SERVER("Cannot open file %s\n", filepath);
		return -1;
	}

	TAILQ_FOREACH(disk, &disk_list, q_entry) {
		fprintf (fp, "<disk>\n");
		dump_disk(fp, disk, 0);
		fprintf (fp, "</disk>\n");
	}
	fclose(fp);
	return 0;
}

static int
tl_server_list_disks(struct tl_comm *comm, struct tl_msg *msg)
{
	char filepath[256];
	int retval;

	if (sscanf(msg->msg_data, "tempfile: %s\n", filepath) != 1)
	{
		DEBUG_ERR_SERVER("Invalid msg data");
		tl_server_msg_failure(comm, msg);
		return -1;
	}

	retval = __list_disks(filepath);
	if (retval != 0) {
		tl_server_msg_failure(comm, msg);
		return -1;
	}

	tl_server_msg_success(comm, msg);
	return 0;
}

static void
tl_server_unload_tdisks()
{
	struct tdisk_info *tdisk_info;

	TAILQ_FOREACH(tdisk_info, &tdisk_list, q_entry) {
		if (!tdisk_info->online || tdisk_info->disabled)
			continue;
		detach_tdisk(tdisk_info);
	}
}

static int
tl_server_tdisk_stats_reset(struct tl_comm *comm, struct tl_msg *msg)
{
	struct tdisk_info *tdisk_info;
	uint32_t target_id;

	if (sscanf(msg->msg_data, "target_id: %u\n", &target_id) != 1) {
		DEBUG_ERR_SERVER("Invalid msg data");
		tl_server_msg_failure(comm, msg);
		return -1;
	}

	tdisk_info = find_tdisk(target_id);
	if (!tdisk_info) {
		DEBUG_ERR_SERVER("Cannot find target disk at %u\n", target_id);
		tl_server_msg_failure(comm, msg);
		return -1;
	}

	if (!tdisk_info->disabled)
		tl_ioctl(TLTARGIOCTDISKRESETSTATS, tdisk_info);
	tl_server_msg_success(comm, msg);
	return 0;
}

static int
tl_server_tdisk_stats(struct tl_comm *comm, struct tl_msg *msg)
{
	struct tdisk_info *tdisk_info;
	char filepath[256];
	FILE *fp;
	uint32_t target_id;

	if (sscanf(msg->msg_data, "target_id: %u\ntempfile: %s\n", &target_id, filepath) != 2)
	{
		DEBUG_ERR_SERVER("Invalid msg data");
		tl_server_msg_failure(comm, msg);
		return -1;
	}

	tdisk_info = find_tdisk(target_id);
	if (!tdisk_info)
	{
		DEBUG_ERR_SERVER("Cannot find target disk at %u\n", target_id);
		tl_server_msg_failure(comm, msg);
		return -1;
	}

	fp = fopen(filepath, "w");
	if (!fp)
	{
		DEBUG_ERR_SERVER("Cannot open file %s\n", filepath);
		tl_server_msg_failure(comm, msg);
		return -1;
	}

	if (!tdisk_info->disabled)
		tl_ioctl(TLTARGIOCTDISKSTATS, tdisk_info);
	dump_tdisk_stats(fp, &tdisk_info->stats);
	tl_server_msg_success(comm, msg);
	return 0;
}

static int
__list_groups(char *filepath, int configured)
{
	struct group_info *group_info;
	FILE *fp;

	fp = fopen(filepath, "w");
	if (!fp) {
		DEBUG_ERR_SERVER("Cannot open file %s\n", filepath);
		return -1;
	}

	TAILQ_FOREACH(group_info, &group_list, q_entry) {
		if (configured && TAILQ_EMPTY(&group_info->bdev_list))
			continue;

		fprintf(fp, "<group>\n");
		fprintf(fp, "group_id: %u\n", group_info->group_id);
		fprintf(fp, "name: %s\n", group_info->name);
		fprintf(fp, "dedupemeta: %d\n", group_info->dedupemeta);
		fprintf(fp, "logdata: %d\n", group_info->logdata);
		fprintf(fp, "disks: %d\n", group_get_disk_count(group_info));
		fprintf(fp, "tdisks: %d\n", group_get_tdisk_count(group_info));
		fprintf(fp, "</group>\n");
	}

	fclose(fp);
	return 0;
}

static int
tl_server_list_groups(struct tl_comm *comm, struct tl_msg *msg, int configured)
{
	char filepath[256];
	int retval;

	if (sscanf(msg->msg_data, "tempfile: %s\n", filepath) != 1)
	{
		DEBUG_ERR_SERVER("Invalid msg data");
		tl_server_msg_failure(comm, msg);
		return -1;
	}

	retval = __list_groups(filepath, configured);
	if (retval != 0) {
		tl_server_msg_failure(comm, msg);
		return -1;
	}

	tl_server_msg_success(comm, msg);
	return 0;
}

static int
__list_tdisks(char *filepath)
{
	struct tdisk_info *tdisk_info;
	FILE *fp;

	fp = fopen(filepath, "w");
	if (!fp) {
		DEBUG_ERR_SERVER("Cannot open file %s\n", filepath);
		return -1;
	}

	TAILQ_FOREACH(tdisk_info, &tdisk_list, q_entry) {
		if (tdisk_info->disabled == VDISK_DELETED)
			continue;

		if (tdisk_info->disabled != VDISK_DELETING)
			tl_ioctl(TLTARGIOCTDISKSTATS, tdisk_info);

		fprintf(fp, "<tdisk>\n");
		fprintf(fp, "target_id: %u\n", tdisk_info->target_id);
		fprintf(fp, "name: %s\n", tdisk_info->name);
		fprintf(fp, "group_name: %s\n", tdisk_info->group->name);
		if (strlen(tdisk_info->serialnumber) > 0)
			fprintf(fp, "serialnumber: %s\n", tdisk_info->serialnumber);
		else
			fprintf(fp, "serialnumber: Unknown\n");
		fprintf(fp, "size: %llu\n", (unsigned long long)tdisk_info->size);
		fprintf(fp, "online: %d\n", tdisk_info->online);
		fprintf(fp, "disabled: %d\n", tdisk_info->disabled);
		fprintf(fp, "delete_error: %d\n", tdisk_info->delete_error);
		fprintf(fp, "enable_deduplication: %d\n", tdisk_info->enable_deduplication);
		fprintf(fp, "enable_compression: %d\n", tdisk_info->enable_compression);
		fprintf(fp, "enable_verify: %d\n", tdisk_info->enable_verify);
		fprintf(fp, "force_inline: %d\n", tdisk_info->force_inline);
		fprintf(fp, "lba_shift: %d\n", tdisk_info->lba_shift);
		fprintf(fp, "</tdisk>\n");
	}

	fclose(fp);
	return 0;
}

static int
tl_server_list_tdisks(struct tl_comm *comm, struct tl_msg *msg)
{
	char filepath[256];
	int retval;

	if (sscanf(msg->msg_data, "tempfile: %s\n", filepath) != 1) {
		DEBUG_ERR_SERVER("Invalid msg data");
		tl_server_msg_failure(comm, msg);
		return -1;
	}

	retval = __list_tdisks(filepath);
	if (retval != 0) {
		tl_server_msg_failure(comm, msg);
		return -1;
	}

	tl_server_msg_success(comm, msg);
	return 0;
}

static int
tl_server_list_pool_tdisks(struct tl_comm *comm, struct tl_msg *msg)
{
	struct tdisk_info *tdisk_info;
	char filepath[256];
	FILE *fp;
	uint32_t group_id;

	if (sscanf(msg->msg_data, "target_id: %u\ntempfile: %s\n", &group_id, filepath) != 2) {
		DEBUG_ERR_SERVER("Invalid msg data");
		tl_server_msg_failure(comm, msg);
		return -1;
	}

	fp = fopen(filepath, "w");
	if (!fp)
	{
		DEBUG_ERR_SERVER("Cannot open file %s\n", filepath);
		tl_server_msg_failure(comm, msg);
		return -1;
	}

	TAILQ_FOREACH(tdisk_info, &tdisk_list, q_entry) {
		if (tdisk_info->disabled == VDISK_DELETED)
			continue;

		if (!tdisk_info->group || tdisk_info->group->group_id != group_id)
			continue;

		tl_ioctl(TLTARGIOCTDISKSTATS, tdisk_info);

		fprintf(fp, "<tdisk>\n");
		fprintf(fp, "target_id: %u\n", tdisk_info->target_id);
		fprintf(fp, "name: %s\n", tdisk_info->name);
		fprintf(fp, "group_name: %s\n", tdisk_info->group->name);
		if (strlen(tdisk_info->serialnumber) > 0)
			fprintf(fp, "serialnumber: %s\n", tdisk_info->serialnumber);
		else
			fprintf(fp, "serialnumber: Unknown\n");
		fprintf(fp, "size: %llu\n", (unsigned long long)tdisk_info->size);
		fprintf(fp, "online: %d\n", tdisk_info->online);
		fprintf(fp, "disabled: %d\n", tdisk_info->disabled);
		fprintf(fp, "enable_deduplication: %d\n", tdisk_info->enable_deduplication);
		fprintf(fp, "enable_compression: %d\n", tdisk_info->enable_compression);
		fprintf(fp, "enable_verify: %d\n", tdisk_info->enable_verify);
		fprintf(fp, "force_inline: %d\n", tdisk_info->force_inline);
		fprintf(fp, "lba_shift: %d\n", tdisk_info->lba_shift);
		fprintf(fp, "</tdisk>\n");
	}

	fclose(fp);
	tl_server_msg_success(comm, msg);
	return 0;
}

static int
tl_server_rename_pool(struct tl_comm *comm, struct tl_msg *msg)
{
	PGconn *conn;
	char errmsg[256];
	struct group_info *group_info;
	struct group_conf group_conf;
	char name[TDISK_MAX_NAME_LEN], newname[TDISK_MAX_NAME_LEN];
	uint32_t group_id;
	int retval;

	if (sscanf(msg->msg_data, "group_id:%u\ngroupname: %s\n", &group_id, newname) != 2) {
		snprintf(errmsg, sizeof(errmsg), "Invalid msg msg_data\n");
		goto senderr;
	}

	group_info = find_group(group_id);
	if (!group_info) {
		snprintf(errmsg, sizeof(errmsg), "Cannot find pool with id %u\n", group_id);
		goto senderr;
	}

	if (!group_info->group_id) {
		tl_server_msg_success(comm, msg);
		return 0;
	}

	if (strlen(newname) > TDISK_NAME_LEN) {
		snprintf(errmsg, sizeof(errmsg), "Pool name can be upto a maximum of %d characters", TDISK_NAME_LEN);
		goto senderr;
	}

	if (!target_name_valid(newname)) {
		snprintf(errmsg, sizeof(errmsg), "Pool name can only contain alphabets, numbers, underscores and hyphens");
		goto senderr;
	}

	if (strcmp(group_info->name, newname) == 0) {
		tl_server_msg_success(comm, msg);
		return 0;
	}

	conn = pgsql_begin();
	if (!conn) {
		snprintf(errmsg, sizeof(errmsg), "Unable to connect to db\n");
		goto senderr;
	}

	strcpy(name, group_conf.name);
	group_conf_fill(&group_conf, group_info);
	strcpy(group_conf.name, newname);

	retval = sql_rename_pool(group_info->group_id, newname);
	if (retval != 0) {
		snprintf(errmsg, sizeof(errmsg), "Update db with new pool name failed\n");
		goto rollback;
	}

	retval = tl_ioctl(TLTARGIOCRENAMEGROUP, &group_conf);
	if (retval != 0) {
		snprintf(errmsg, sizeof(errmsg), "Changing pool name failed\n");
		goto rollback;
	}

	retval = pgsql_commit(conn);
	if (retval != 0) {
		snprintf(errmsg, sizeof(errmsg), "Unable to commit transaction\n");
		goto senderr;
	}
	strcpy(group_info->name, newname);
	tl_server_msg_success(comm, msg);
	return 0;

rollback:
	strcpy(group_conf.name, name);
	pgsql_rollback(conn);
senderr:
	tl_server_msg_failure2(comm, msg, errmsg);
	return -1;
}

static int
tl_server_add_group(struct tl_comm *comm, struct tl_msg *msg)
{
	PGconn *conn;
	char groupname[256];
	char errmsg[256];
	struct group_info *group_info = NULL;
	struct group_conf group_conf;
	int retval, dedupemeta, logdata;

	if (sscanf(msg->msg_data, "groupname: %s\ndedupemeta: %d\nlogdata: %d\n", groupname, &dedupemeta, &logdata) != 3) {
		snprintf(errmsg, sizeof(errmsg), "Invalid msg msg_data\n");
		goto senderr;
	}

	if (group_name_exists(groupname)) {
		snprintf(errmsg, sizeof(errmsg), "Pool name %s exists\n", groupname);
		goto senderr;
	}

	if (strlen(groupname) > TDISK_NAME_LEN) {
		snprintf(errmsg, sizeof(errmsg), "Pool name can be upto a maximum of %d characters", TDISK_NAME_LEN);
		goto senderr;
	}

	if (!target_name_valid(groupname)) {
		snprintf(errmsg, sizeof(errmsg), "Pool name can only contain alphabets, numbers, underscores and hyphens");
		goto senderr;
	}

	group_info = alloc_buffer(sizeof(*group_info));
	if (!group_info) {
		snprintf(errmsg, sizeof(errmsg), "Memory allocation error\n");
		goto senderr;
	}

	conn = pgsql_begin();
	if (!conn) {
		snprintf(errmsg, sizeof(errmsg), "Unable to connect to db\n");
		goto senderr;
	}

	strcpy(group_info->name, groupname);
	group_info->dedupemeta = dedupemeta;
	group_info->logdata = logdata;
	TAILQ_INIT(&group_info->bdev_list);
	TAILQ_INIT(&group_info->tdisk_list);

	retval = sql_add_group(conn, group_info);
	if (retval != 0) {
		snprintf(errmsg, sizeof(errmsg), "Cannot add pool to db\n");
		goto errrsp;
	}

	group_conf_fill(&group_conf, group_info);
	retval = tl_ioctl(TLTARGIOCADDGROUP, &group_conf);
	if (retval != 0) {
		snprintf(errmsg, sizeof(errmsg), "Cannot add pool, ioctl failed\n");
		goto errrsp;
	}

	retval = pgsql_commit(conn);
	if (retval != 0) {
		snprintf(errmsg, sizeof(errmsg), "Unable to commit transaction\n");
		goto senderr;
	}

	node_controller_group_added(group_info);
	TAILQ_INSERT_TAIL(&group_list, group_info, q_entry); 

	tl_server_msg_success(comm, msg);
	return 0;
errrsp:
	pgsql_rollback(conn);
senderr:
	if (group_info)
		free(group_info);
	tl_server_msg_failure2(comm, msg, errmsg);
	return -1;
}

static int
tl_server_add_target(struct tl_comm *comm, struct tl_msg *msg)
{
	char targetname[256];
	char errmsg[256];
	unsigned long long targetsize;
	int lba_shift;
	uint32_t group_id;
	struct tdisk_info *info;
	struct group_info *group_info;

	if (sscanf(msg->msg_data, "targetname: %s\ntargetsize: %llu\nlba_shift: %d\ngroup_id: %u\n", targetname, &targetsize, &lba_shift, &group_id) != 4) {
		snprintf(errmsg, sizeof(errmsg), "Invalid msg msg_data\n");
		goto senderr;
	}

	if (targetsize > MAX_TARGET_SIZE) {
		snprintf(errmsg, sizeof(errmsg), "Vdisk size exceeds maximum configurable size\n");
		goto senderr;
	}

	if (target_name_exists(targetname)) {
		snprintf(errmsg, sizeof(errmsg), "VDisk name %s exists\n", targetname);
		goto senderr;
	}

	if (strlen(targetname) >  TDISK_NAME_LEN) {
		snprintf(errmsg, sizeof(errmsg), "VDisk name can be upto a maximum of %d characters", TDISK_NAME_LEN);
		goto senderr;
	}

	if (!target_name_valid(targetname)) {
		snprintf(errmsg, sizeof(errmsg), "VDisk name can only contain alphabets, numbers, underscores and hyphens");
		goto senderr;
	}

	group_info = find_group(group_id);
	if (!group_info) {
		snprintf(errmsg, sizeof(errmsg), "Cannot find pool with id %u\n", group_id);
		goto senderr;
	}

	info = add_target(group_info, targetname, targetsize, lba_shift, 1, 0, 0, 0, NULL, errmsg, 1, NULL);
	if (!info)
		goto senderr;

	tl_server_msg_success(comm, msg);
	return 0;
senderr:
	tl_server_msg_failure2(comm, msg, errmsg);
	return -1;
}

static int
tl_server_modify_tdisk(struct tl_comm *comm, struct tl_msg *msg)
{
	char errmsg[256];
	struct tdisk_info *tdisk_info;
	int retval;
	uint32_t target_id;
	struct tdisk_info tmp;
	int dedupe, comp, verify, force_inline;

	if (sscanf(msg->msg_data, "target_id: %u\ndedupe: %d\ncomp: %d\nverify: %d\ninline: %d\n", &target_id, &dedupe, &comp, &verify, &force_inline) != 5) {
		snprintf(errmsg, sizeof(errmsg), "Invalid msg msg_data\n");
		goto senderr;
	}

	tdisk_info = find_tdisk(target_id);
	if (!tdisk_info) {
		snprintf(errmsg, sizeof(errmsg), "Cannot find tdisk at target_id %u\n", target_id);
		goto senderr;
	}

	if (tdisk_info->disabled) {
		tl_server_msg_success(comm, msg);
		return 0;
	}

	memcpy(&tmp, tdisk_info, sizeof(tmp));
	tmp.enable_deduplication = dedupe;
	tmp.enable_compression = comp;
	tmp.enable_verify = verify;
	tmp.force_inline = force_inline;

	retval = tl_ioctl(TLTARGIOCMODIFYTDISK, &tmp);
	if (retval != 0) {
		snprintf(errmsg, sizeof(errmsg), "Modify VDisk ioctl failed\n");
		goto senderr;
	}

	tdisk_info->enable_compression = comp;
	tdisk_info->enable_verify = verify;
	tdisk_info->force_inline = force_inline;
	tdisk_info->enable_deduplication = dedupe;
	node_controller_vdisk_modified(tdisk_info);

	sql_update_tdisk(tdisk_info);
	tl_server_msg_success(comm, msg);
	return 0;
senderr:
	tl_server_msg_failure2(comm, msg, errmsg);
	return -1;
}

static int
tl_server_delete_group(struct tl_comm *comm, struct tl_msg *msg)
{
	char errmsg[256];
	struct group_info *group_info;
	struct group_conf group_conf;
	int retval;
	uint32_t group_id;

	if (sscanf(msg->msg_data, "group_id: %u\n", &group_id) != 1) {
		snprintf(errmsg, sizeof(errmsg), "Invalid msg msg_data\n");
		goto senderr;
	}

	if (!group_id) {
		snprintf(errmsg, sizeof(errmsg), "Cannot delete default group\n");
		goto senderr;
	}

	group_info = find_group(group_id);
	if (!group_info) {
		snprintf(errmsg, sizeof(errmsg), "Cannot find pool at group_id %u\n", group_id);
		goto senderr;
	}

	group_conf_fill(&group_conf, group_info);
	retval = tl_ioctl(TLTARGIOCDELETEGROUP, &group_conf);
	if (retval != 0) {
		snprintf(errmsg, sizeof(errmsg), "Cannot add pool, ioctl failed\n");
		goto senderr;
	}

	retval = sql_delete_group(group_id);
	if (retval != 0) {
		snprintf(errmsg, sizeof(errmsg), "Cannot delete pool information from DB\n");
		goto senderr;
	}

	TAILQ_REMOVE(&group_list, group_info, q_entry); 
	node_controller_group_removed(group_info);
	free(group_info);
	tl_server_msg_success(comm, msg);
	return 0;
senderr:
	tl_server_msg_failure2(comm, msg, errmsg);
	return -1;
}

static int
tl_server_delete_tdisk(struct tl_comm *comm, struct tl_msg *msg)
{
	char errmsg[256];
	PGconn *conn;
	struct tdisk_info *tdisk_info;
	int retval;
	uint32_t target_id;

	if (sscanf(msg->msg_data, "target_id: %u\n", &target_id) != 1) {
		snprintf(errmsg, sizeof(errmsg), "Invalid msg msg_data\n");
		goto senderr;
	}

	tdisk_info = find_tdisk(target_id);
	if (!tdisk_info) {
		snprintf(errmsg, sizeof(errmsg), "Cannot find tdisk at target_id %u\n", target_id);
		goto senderr;
	}

	if (tdisk_info->disabled == VDISK_DELETED) {
		tl_server_msg_success(comm, msg);
		return 0;
	}

	retval = tl_server_remove_tdisk_fc_rules(tdisk_info);
	if (retval != 0) {
		snprintf(errmsg, sizeof(errmsg), "Cannot delete fc rules for vdisk %s\n", tdisk_info->name);
		goto senderr;
	}
	node_controller_vdisk_disable(tdisk_info);

	conn = pgsql_begin();
	if (!conn) {
		snprintf(errmsg, sizeof(errmsg), "Unable to connect to db\n");
		goto senderr;
	}

	retval = sql_mark_tdisk_for_deletion(conn, target_id);
	if (retval != 0) {
		snprintf(errmsg, sizeof(errmsg), "Failed to delete volume from db\n");
		goto errrsp;
	}

	if (tdisk_info->disabled != VDISK_DELETING) {
		vhba_remove_device(tdisk_info);

		retval = ietadm_delete_target(tdisk_info->iscsi_tid);
		if (retval != 0) {
			DEBUG_ERR_SERVER("Unable to delete vdisk iscsi target");
			goto errrsp;
		}
	}

	tdisk_info->free_alloc = 1;
	tdisk_info->disabled = VDISK_DELETING;
	retval = tl_ioctl(TLTARGIOCDELETETDISK, tdisk_info);
	if (retval != 0) {
		snprintf(errmsg, sizeof(errmsg), "Cannot delete vdisk information from kernel\n");
		goto errrsp;
	}

	retval = pgsql_commit(conn);
	if (retval != 0) {
		snprintf(errmsg, sizeof(errmsg), "Unable to commit transaction\n");
		goto senderr;
	}

	node_controller_vdisk_removed(tdisk_info);
	tl_server_msg_success(comm, msg);
	return 0;
errrsp:
	pgsql_rollback(conn);
	tdisk_info->disabled = 0;
senderr:
	tl_server_msg_failure2(comm, msg, errmsg);
	return -1;
}

static int
__list_configured_disks(char *filepath)
{
	FILE *fp;
	struct tl_blkdevinfo *blkdev;
	int retval, i;

	fp = fopen(filepath, "w");
	if (!fp) {
		DEBUG_ERR_SERVER("Cannot open file %s\n", filepath);
		return -1;
	}

	for (i = 1; i < TL_MAX_DISKS; i++) {
		struct bdev_info binfo;

		blkdev = bdev_list[i];
		if (!blkdev)
			continue;
		fprintf (fp, "<disk>\n");
		memset(&binfo, 0, sizeof(struct bdev_info));
		binfo.bid = blkdev->bid;

		if (!blkdev->offline && blkdev->disk.initialized != -1) {
			retval = tl_ioctl(TLTARGIOCGETBLKDEV, &binfo);
			if (retval == 0) {
				blkdev->disk.size = binfo.size;
				blkdev->disk.used = (binfo.size - binfo.free);
				blkdev->disk.reserved = binfo.reserved;
				blkdev->disk.initialized = binfo.initialized;
				blkdev->disk.log_disk = binfo.log_disk;
				blkdev->disk.ha_disk = binfo.ha_disk;
				blkdev->disk.unmap = binfo.unmap;
				blkdev->disk.enable_comp = binfo.enable_comp;
				blkdev->disk.dedupe_blocks = binfo.stats.dedupe_blocks;
				blkdev->disk.total_blocks = binfo.stats.total_blocks;
				blkdev->disk.uncompressed_size = binfo.stats.uncompressed_size;
				blkdev->disk.compressed_size = binfo.stats.compressed_size;
				blkdev->disk.compression_hits = binfo.stats.compression_hits;
				blkdev->disk.write_cache = binfo.write_cache;
				blkdev->ddmaster = binfo.ddmaster;
			}
			blkdev->disk.info.online = 1;
			strcpy(blkdev->disk.group_name, blkdev->group->name);
		}

		blkdev->disk.ddmaster = blkdev->ddmaster;
		dump_disk(fp, &blkdev->disk, blkdev->bid);
		fprintf (fp, "</disk>\n");
	}

	fclose(fp);
	return 0;
}

static int
tl_server_get_configured_disks(struct tl_comm *comm, struct tl_msg *msg)
{
	char filepath[256];
	int retval;

	if (sscanf(msg->msg_data, "tempfile: %s\n", filepath) != 1) {
		DEBUG_ERR_SERVER("Invalid msg data");
		tl_server_msg_failure(comm, msg);
		return -1;
	}

	retval = __list_configured_disks(filepath);
	if (retval != 0) {
		tl_server_msg_failure(comm, msg);
		return -1;
	}

	tl_server_msg_success(comm, msg);
	return 0;
}

static int
tl_server_get_pool_configured_disks(struct tl_comm *comm, struct tl_msg *msg)
{
	char filepath[256];
	FILE *fp;
	struct tl_blkdevinfo *blkdev;
	int retval, i;
	uint32_t group_id;

	if (sscanf(msg->msg_data, "target_id: %u\ntempfile: %s\n", &group_id, filepath) != 2) {
		DEBUG_ERR_SERVER("Invalid msg data");
		tl_server_msg_failure(comm, msg);
		return -1;
	}

	fp = fopen(filepath, "w");
	if (!fp)
	{
		DEBUG_ERR_SERVER("Cannot open file %s\n", filepath);
		tl_server_msg_failure(comm, msg);
		return -1;
	}

	for (i = 1; i < TL_MAX_DISKS; i++) {
		struct bdev_info binfo;

		blkdev = bdev_list[i];
		if (!blkdev)
			continue;
		if (!blkdev->group || blkdev->group->group_id != group_id)
			continue;
		fprintf (fp, "<disk>\n");
		memset(&binfo, 0, sizeof(struct bdev_info));
		binfo.bid = blkdev->bid;

		if (!blkdev->offline && blkdev->disk.initialized != -1) {
			retval = tl_ioctl(TLTARGIOCGETBLKDEV, &binfo);
			if (retval == 0) {
				blkdev->disk.size = binfo.size;
				blkdev->disk.used = (binfo.size - binfo.free);
				blkdev->disk.reserved = binfo.reserved;
				blkdev->disk.initialized = binfo.initialized;
				blkdev->disk.log_disk = binfo.log_disk;
				blkdev->disk.ha_disk = binfo.ha_disk;
				blkdev->disk.unmap = binfo.unmap;
				blkdev->disk.enable_comp = binfo.enable_comp;
				blkdev->disk.dedupe_blocks = binfo.stats.dedupe_blocks;
				blkdev->disk.total_blocks = binfo.stats.total_blocks;
				blkdev->disk.uncompressed_size = binfo.stats.uncompressed_size;
				blkdev->disk.compressed_size = binfo.stats.compressed_size;
				blkdev->disk.compression_hits = binfo.stats.compression_hits;
				blkdev->disk.write_cache = binfo.write_cache;
				blkdev->ddmaster = binfo.ddmaster;
			}
			blkdev->disk.info.online = 1;
			strcpy(blkdev->disk.group_name, blkdev->group->name);
		}

		blkdev->disk.ddmaster = blkdev->ddmaster;
		dump_disk(fp, &blkdev->disk, blkdev->bid);
		fprintf (fp, "</disk>\n");
	}

	fclose(fp);

	tl_server_msg_success(comm, msg);
	return 0;
}

static int
tl_server_delete_disk(struct tl_comm *comm, struct tl_msg *msg)
{
	struct tl_blkdevinfo *blkdev = NULL, *tmp;
	struct bdev_info binfo;
	int retval, i;
	char errmsg[256];
	char dev[512];
	int count = 0, tcount;

	if (sscanf(msg->msg_data, "dev: %[^\n]", dev) != 1) {
		DEBUG_ERR_SERVER("Invalid msg data %s\n", msg->msg_data);
		goto senderr;
	}

	for (i = 1; i < TL_MAX_DISKS; i++) {
		tmp = bdev_list[i];
		if (!tmp)
			continue;
		if (strcmp(tmp->disk.info.devname, dev))
			continue;
		blkdev = tmp;
		break;
	}

	if (!blkdev) {
		snprintf(errmsg, sizeof(errmsg), "Unable to find disk at %s for deletion\n", dev);
		DEBUG_ERR_SERVER("Unable to find disk at %s for deletion\n", dev);
		goto senderr;
	}

	TAILQ_FOREACH(tmp, &blkdev->group->bdev_list, g_entry) {
		count++;
	}

	memset(&binfo, 0, sizeof(struct bdev_info));
	binfo.bid = blkdev->bid;
	retval = tl_ioctl(TLTARGIOCGETBLKDEV, &binfo);
	if (retval < 0) {
		snprintf(errmsg, sizeof(errmsg), "Cannot get disk information from kernel\n");
		goto senderr;
	}

	tcount = group_get_tdisk_count(blkdev->group);
	if (count > 1) {
		if (blkdev->ddmaster) {
			snprintf(errmsg, sizeof(errmsg), "Error in removing disk. Disk containing deduplication metadata can only be removed last\n");
			goto senderr;
		}
		if (tcount && (binfo.free != (binfo.usize - binfo.reserved))) {
			snprintf(errmsg, sizeof(errmsg), "Cannot delete disk which has active data usize %llu reserved %llu free %llu\n", (unsigned long long)binfo.usize, (unsigned long long)binfo.reserved, (unsigned long long)binfo.free);
			goto senderr;
		}
	}
	else {
		if (tcount > 0) {
			snprintf(errmsg, sizeof(errmsg), "Cannot delete disk which has active data\n");
			goto senderr;
		}
	}

	memset(&binfo, 0, sizeof(struct bdev_info));
	binfo.bid = blkdev->bid;
	binfo.ddmaster = blkdev->ddmaster;
	binfo.free_alloc = 1;
	retval = tl_ioctl(TLTARGIOCDELBLKDEV, &binfo);
	if (retval != 0) {
		if (binfo.errmsg[0])
			strcpy(errmsg, binfo.errmsg);
		else
			snprintf(errmsg, sizeof(errmsg), "Unable to delete disk from module information\n");
		goto senderr;
	}

	node_controller_bdev_removed(blkdev);

	DEBUG_BUG_ON(!blkdev->bid);
	retval = sql_delete_blkdev(blkdev);
	if (retval != 0) {
		snprintf(errmsg, sizeof(errmsg), "Unable to delete disk from database\n");
		goto senderr;
	}

	bdev_remove(blkdev);
	free(blkdev);
	msg->msg_resp = MSG_RESP_OK;
	tl_server_msg_success(comm, msg);
	return 0;
senderr:
	tl_server_msg_failure2(comm, msg, errmsg);
	return -1;
}

static int
tl_server_add_disk(struct tl_comm *comm, struct tl_msg *msg)
{
	struct group_info *group_info;
	struct physdisk *disk;
	int retval;
	struct tl_blkdevinfo *blkdev;
	char errmsg[256];
	struct bdev_info binfo;
	PGconn *conn;
	char dev[512];
	int comp, log_disk, ha_disk;
	uint32_t group_id;

	if (sscanf(msg->msg_data, "group_id: %u\ncomp: %d\nlog_disk: %d\nha_disk: %d\ndev: %[^\n]", &group_id, &comp, &log_disk, &ha_disk, dev) != 5) {
		DEBUG_ERR_SERVER("Invalid msg data %s\n", msg->msg_data);
		goto senderr;
	}

	group_info = find_group(group_id);
	if (!group_info) {
		snprintf(errmsg, sizeof(errmsg), "Cannot find pool with id %u\n", group_id);
		goto senderr;
	}

	disk = tl_common_find_disk(dev);
	if (!disk) {
		snprintf(errmsg, sizeof(errmsg), "Unable to find disk at %s for addition\n", dev);
		DEBUG_ERR_SERVER("Unable to find disk at %s for addition\n", dev);
		goto senderr;
	}

	retval = is_ignore_dev(disk->info.devname);
	if (retval) {
		snprintf(errmsg, sizeof(errmsg), "Cannot add a disk with mounted partitions dev is %s\n", disk->info.devname);
		goto senderr;
	}

	retval = check_blkdev_exists(disk->info.devname);
	if (retval != 0) {
		snprintf(errmsg, sizeof(errmsg), "Disk at devpath %s already added\n", disk->info.devname);
		goto senderr;
	}

	blkdev = blkdev_new(disk->info.devname);
	if (!blkdev) {
		snprintf(errmsg, sizeof(errmsg), "Memory Allocation failure\n");
		goto senderr;
	}

	memcpy(&blkdev->disk, disk, offsetof(struct physdisk, q_entry));
	strcpy(blkdev->devname, disk->info.devname);
	blkdev->group_id = group_id;

	conn = sql_add_blkdev(&blkdev->disk, blkdev->bid);
	if (!conn) {
		snprintf(errmsg, sizeof(errmsg), "Adding disk to database failed\n");
		free(blkdev);
		goto senderr;
	}

	memset(&binfo, 0, sizeof(struct bdev_info));
	binfo.bid = blkdev->bid;
	binfo.group_id = group_id;
	strcpy(binfo.devpath, blkdev->devname);
	memcpy(binfo.vendor, blkdev->disk.info.vendor, sizeof(binfo.vendor));
	memcpy(binfo.product, blkdev->disk.info.product, sizeof(binfo.product));
	memcpy(binfo.serialnumber, blkdev->disk.info.serialnumber, sizeof(binfo.serialnumber));
	node_controller_bdev_added(blkdev);
	binfo.isnew = 1;
	binfo.enable_comp = comp;
	binfo.log_disk = log_disk;
	binfo.ha_disk = ha_disk;
	binfo.write_cache = WRITE_CACHE_DEFAULT;
	retval = gen_rid(binfo.rid);
	if (retval != 0) {
		snprintf(errmsg, sizeof(errmsg), "Error adding disk, gen rid failed\n");
		goto err;
	}

	retval = tl_ioctl(TLTARGIOCNEWBLKDEV, &binfo);
	if (retval != 0)
	{
		DEBUG_ERR_SERVER("Error adding new disk, ioctl failed\n");
		if (binfo.errmsg[0])
			strcpy(errmsg, binfo.errmsg);
		else
			snprintf(errmsg, sizeof(errmsg), "Error adding disk, ioctl failed\n");
		goto err;
	}

	bdev_add(group_info, blkdev);

	msg->msg_resp = MSG_RESP_OK;
	tl_server_msg_success(comm, msg);

	retval = pgsql_commit(conn);
	if (retval != 0)
	{
		binfo.free_alloc = 1;
		tl_ioctl(TLTARGIOCDELBLKDEV, &binfo);
	}

	return retval;

err:
	pgsql_rollback(conn);
	node_controller_bdev_removed(blkdev);
	free(blkdev);
senderr:
	tl_server_msg_failure2(comm, msg, errmsg);
	return -1;
}

static void
diag_dump_prog(char *dirpath, char *file, char *prog)
{
	char cmd[256];

	snprintf(cmd, sizeof(cmd), "%s > %s/%s 2>&1", prog, dirpath, file);
	system(cmd);
}

static inline void
diag_dump_file(char *dirpath, char *file, char *src)
{
	char cmd[512];

	snprintf(cmd, sizeof(cmd), "cp -f %s %s/%s", src, dirpath, file);
	system(cmd);
}

int
tl_server_run_diagnostics(struct tl_comm *comm, struct tl_msg *msg, int controller)
{
	char diagdir[100];
	char filepath[256];
	char cmd[256];

	if (sscanf(msg->msg_data, "tempfile: %s\n", diagdir) != 1) {
		tl_server_msg_failure(comm, msg);
		return -1;
	}

	snprintf(filepath, sizeof(filepath), "%s/clones.lst", diagdir);
	__list_clones(filepath, 0);
	snprintf(filepath, sizeof(filepath), "%s/mirrors.lst", diagdir);
	__list_mirrors(filepath, 0);
	snprintf(filepath, sizeof(filepath), "%s/disks.lst", diagdir);
	__list_disks(filepath);
	snprintf(filepath, sizeof(filepath), "%s/cdisks.lst", diagdir);
	__list_configured_disks(filepath);
	snprintf(filepath, sizeof(filepath), "%s/groups.lst", diagdir);
	__list_groups(filepath, 0);
	snprintf(filepath, sizeof(filepath), "%s/cgroups.lst", diagdir);
	__list_groups(filepath, 1);

	snprintf(filepath, sizeof(filepath), "%s/vdisks.lst", diagdir);
	__list_tdisks(filepath);
	snprintf(filepath, sizeof(filepath), "%s/qsync.lst", diagdir);
	__list_sync_mirrors(filepath);

	diag_dump_prog(diagdir, "ndconfig.txt", "/quadstor/bin/ndconfig");
	snprintf(cmd, sizeof(cmd), "/quadstor/bin/diaghelper %s", diagdir);
	system(cmd);
	tl_server_msg_success(comm, msg);
	return 0;
}

static int
tl_server_get_status(struct tl_comm *comm, struct tl_msg *msg)
{
	char newmsg[100];

	if (log_error)
		strcpy(newmsg, "Server failed to initialize\n");
	else if (done_init)
		strcpy(newmsg, "Server initialized and running\n");
	else
		strcpy(newmsg, "Server initializing...\n");

	tl_server_send_message(comm, msg, newmsg);
	return 0;
}

static int
tl_server_get_uid(struct tl_comm *comm, struct tl_msg *msg)
{
	char newmsg[100];

	strcpy(newmsg, sys_rid);
	tl_server_send_message(comm, msg, newmsg);
	return 0;
}

static int
tl_server_get_mirrorconf(struct tl_comm *comm, struct tl_msg *msg)
{
	uint32_t target_id;
	struct tdisk_info *tdisk_info;
	struct mirror_state *mirror_state;

	if (sscanf(msg->msg_data, "target_id: %u\n", &target_id) != 1) {
		DEBUG_WARN_SERVER("Invalid msg data");
		tl_server_msg_failure(comm, msg);
		return -1;
	}

	tdisk_info = find_tdisk(target_id);
	if (!tdisk_info) {
		DEBUG_WARN_SERVER("Invalid target_id %u passed\n", target_id);
		tl_server_msg_failure(comm, msg);
		return -1;
	}

	if (!tdisk_info->disabled)
		tl_ioctl(TLTARGIOCTDISKSTATS, tdisk_info);
	mirror_state = &tdisk_info->mirror_state;
	free(msg->msg_data);
	msg->msg_data = malloc(sizeof(*mirror_state));
	if (!msg->msg_data) {
		tl_server_msg_failure(comm, msg);
		return -1;
	}
	memcpy(msg->msg_data, mirror_state, sizeof(*mirror_state));
	msg->msg_len = sizeof(*mirror_state);
	msg->msg_resp = MSG_RESP_OK;
	tl_msg_send_message(comm, msg);
	tl_msg_free_message(msg);
	tl_msg_close_connection(comm);
	return 0;
}

static int
tl_server_set_diskconf(struct tl_comm *comm, struct tl_msg *msg)
{
	struct tl_blkdevinfo *blkdev;
	struct physdisk tmp;
	char errmsg[256];
	int retval;

	if (msg->msg_len != sizeof(tmp)) {
		snprintf(errmsg, sizeof(errmsg), "Invalid msg data");
		goto senderr;
	}

	memcpy(&tmp, msg->msg_data, sizeof(tmp));
	blkdev = blkdev_find(tmp.bid);
	if (!blkdev) {
		snprintf(errmsg, sizeof(errmsg), "Invalid bid %u passed\n", tmp.bid);
		goto senderr;
	}

	if (tmp.ha_disk != blkdev->disk.ha_disk) {
		retval = __tl_server_disk_config(blkdev, tmp.ha_disk, DISK_PROP_HA);
		if (retval != 0) {
			snprintf(errmsg, sizeof(errmsg), "Error changing ha properties for disk\n");
			goto senderr;
		}
	}

	if (tmp.unmap != blkdev->disk.unmap) {
		retval = __tl_server_disk_config(blkdev, tmp.unmap, DISK_PROP_UNMAP);
		if (retval != 0) {
			snprintf(errmsg, sizeof(errmsg), "Error changing unmap properties for disk\n");
			goto senderr;
		}
	}

	if (tmp.write_cache != blkdev->disk.write_cache) {
		retval = __tl_server_disk_config(blkdev, tmp.write_cache, DISK_PROP_WC);
		if (retval != 0) {
			snprintf(errmsg, sizeof(errmsg), "Error changing write cache properties for disk\n");
			goto senderr;
		}
	}

	tl_server_msg_success(comm, msg);
	return 0;
senderr:
	tl_server_msg_failure2(comm, msg, errmsg);
	return -1;
}

static int
tl_server_set_vdiskconf(struct tl_comm *comm, struct tl_msg *msg)
{
	struct tdisk_info *tdisk_info;
	struct vdiskconf newconf;
	struct tdisk_info tmp;
	char errmsg[256];
	int retval;

	if (msg->msg_len != sizeof(newconf)) {
		snprintf(errmsg, sizeof(errmsg), "Invalid msg data");
		goto senderr;
	}

	memcpy(&newconf, msg->msg_data, sizeof(newconf));
	tdisk_info = find_tdisk(newconf.target_id);
	if (!tdisk_info) {
		snprintf(errmsg, sizeof(errmsg), "Invalid target_id %u passed\n", newconf.target_id);
		goto senderr;
	}

	if (tdisk_info->disabled) {
		tl_server_msg_success(comm, msg);
		return 0;
	}

	if (newconf.name[0] && strcmp(newconf.name, tdisk_info->name)) {
		retval = __tl_server_vdisk_rename(tdisk_info, newconf.name, errmsg);
		if (retval != 0)
			goto senderr;
	}

	if (newconf.size && newconf.size != tdisk_info->size) {
		retval = __tl_server_vdisk_resize(tdisk_info, newconf.size, 1, errmsg);
		if (retval != 0)
			goto senderr;
	}

	memcpy(&tmp, tdisk_info, sizeof(tmp));
	tmp.enable_deduplication = newconf.enable_deduplication;
	tmp.enable_compression = newconf.enable_compression;
	tmp.enable_verify = newconf.enable_verify;
	tmp.threshold = newconf.threshold;

	retval = tl_ioctl(TLTARGIOCMODIFYTDISK, &tmp);
	if (retval != 0) {
		snprintf(errmsg, sizeof(errmsg), "VDisk modify ioctl failed\n");
		goto senderr;
	}

	tdisk_info->enable_compression = newconf.enable_compression;
	tdisk_info->enable_verify = newconf.enable_verify;
	tdisk_info->enable_deduplication = newconf.enable_deduplication;
	tdisk_info->threshold = newconf.threshold;
	node_controller_vdisk_modified(tdisk_info);

	sql_update_tdisk(tdisk_info);
	tl_server_msg_success(comm, msg);
	return 0;
senderr:
	tl_server_msg_failure2(comm, msg, errmsg);
	return -1;
}

static int
tl_server_get_diskconf(struct tl_comm *comm, struct tl_msg *msg)
{
	uint32_t bid;
	struct tl_blkdevinfo *blkdev;

	if (sscanf(msg->msg_data, "bid: %u\n", &bid) != 1) {
		DEBUG_WARN_SERVER("Invalid msg data");
		tl_server_msg_failure(comm, msg);
		return -1;
	}

	blkdev = blkdev_find(bid);
	if (!blkdev) {
		DEBUG_WARN_SERVER("Invalid bid %u passed\n", bid);
		tl_server_msg_failure(comm, msg);
		return -1;
	}

	free(msg->msg_data);
	msg->msg_data = malloc(sizeof(blkdev->disk));
	if (!msg->msg_data) {
		tl_server_msg_failure(comm, msg);
		return -1;
	}
	memcpy(msg->msg_data, &blkdev->disk, sizeof(blkdev->disk));
	msg->msg_len = sizeof(blkdev->disk);
	msg->msg_resp = MSG_RESP_OK;
	tl_msg_send_message(comm, msg);
	tl_msg_free_message(msg);
	tl_msg_close_connection(comm);
	return 0;
}

static int
tl_server_get_vdiskconf(struct tl_comm *comm, struct tl_msg *msg)
{
	uint32_t target_id;
	struct tdisk_info *tdisk_info;
	struct vdiskconf vdiskconf;

	if (sscanf(msg->msg_data, "target_id: %u\n", &target_id) != 1) {
		DEBUG_WARN_SERVER("Invalid msg data");
		tl_server_msg_failure(comm, msg);
		return -1;
	}

	tdisk_info = find_tdisk(target_id);
	if (!tdisk_info) {
		DEBUG_WARN_SERVER("Invalid target_id %u passed\n", target_id);
		tl_server_msg_failure(comm, msg);
		return -1;
	}

	memset(&vdiskconf, 0, sizeof(vdiskconf));
	vdiskconf.enable_deduplication = tdisk_info->enable_deduplication;
	vdiskconf.enable_compression = tdisk_info->enable_compression;
	vdiskconf.enable_verify = tdisk_info->enable_verify;
	vdiskconf.size = tdisk_info->size;
	vdiskconf.threshold = tdisk_info->threshold;
	strcpy(vdiskconf.name, tdisk_info->name);
	if (tdisk_info->group)
		strcpy(vdiskconf.group_name, tdisk_info->group->name);

	free(msg->msg_data);
	msg->msg_data = malloc(sizeof(vdiskconf));
	if (!msg->msg_data) {
		tl_server_msg_failure(comm, msg);
		return -1;
	}
	memcpy(msg->msg_data, &vdiskconf, sizeof(vdiskconf));
	msg->msg_len = sizeof(vdiskconf);
	msg->msg_resp = MSG_RESP_OK;
	tl_msg_send_message(comm, msg);
	tl_msg_free_message(msg);
	tl_msg_close_connection(comm);
	return 0;
}

static int
tl_server_get_iscsiconf(struct tl_comm *comm, struct tl_msg *msg)
{
	uint32_t target_id;
	struct tdisk_info *tdisk_info;
	struct iscsiconf *iscsiconf = NULL;

	if (sscanf(msg->msg_data, "target_id: %u\n", &target_id) != 1) {
		DEBUG_WARN_SERVER("Invalid msg data");
		tl_server_msg_failure(comm, msg);
		return -1;
	}

	tdisk_info = find_tdisk(target_id);
	if (!tdisk_info) {
		DEBUG_WARN_SERVER("Invalid target_id %u passed\n", target_id);
		tl_server_msg_failure(comm, msg);
		return -1;
	}

	iscsiconf = &tdisk_info->iscsiconf;
	free(msg->msg_data);
	msg->msg_data = malloc(sizeof(*iscsiconf));
	if (!msg->msg_data) {
		tl_server_msg_failure(comm, msg);
		return -1;
	}
	memcpy(msg->msg_data, iscsiconf, sizeof(*iscsiconf));
	msg->msg_len = sizeof(*iscsiconf);
	msg->msg_resp = MSG_RESP_OK;
	tl_msg_send_message(comm, msg);
	tl_msg_free_message(msg);
	tl_msg_close_connection(comm);
	return 0;
}

static int
tl_server_set_iscsiconf(struct tl_comm *comm, struct tl_msg *msg)
{
	struct tdisk_info *tdisk_info;
	struct iscsiconf *iscsiconf = NULL;
	struct iscsiconf newconf;
	int retval;
	char errmsg[512];

	if (msg->msg_len != sizeof(newconf)) {
		snprintf(errmsg, sizeof(errmsg), "Invalid msg data");
		goto senderr;
	}

	memcpy(&newconf, msg->msg_data, sizeof(newconf));
	tdisk_info = find_tdisk(newconf.target_id);
	if (!tdisk_info) {
		snprintf(errmsg, sizeof(errmsg), "Invalid target_id %u passed\n", newconf.target_id);
		goto senderr;
	}

	if (tdisk_info->disabled) {
		tl_server_msg_success(comm, msg);
		return 0;
	}

	iscsiconf = &tdisk_info->iscsiconf;

	if (newconf.iqn[0]) {
		DEBUG_INFO("For %s new iqn passed %s\n", tdisk_info->name, newconf.iqn);
		if (!iqn_name_valid(newconf.iqn)) {
			snprintf(errmsg, sizeof(errmsg), "iqn %s is not valid\n", newconf.iqn);
			goto senderr;
		}

		if (iqn_exists(newconf.iqn)) {
			snprintf(errmsg, sizeof(errmsg), "IQN %s exists for another VDisk\n", newconf.iqn);
			goto senderr;
		}
	}
	else {
		strcpy(newconf.iqn, iscsiconf->iqn);
	}

	retval = ietadm_mod_target(tdisk_info->iscsi_tid, &newconf, iscsiconf);
	if (retval != 0) {
		DEBUG_ERR_SERVER("ietadm_mod_target failed for tid %d\n", newconf.target_id);
		snprintf(errmsg, sizeof(errmsg), "ietadm update of new iSCSI settings failed\n");
		goto senderr;
	}

	memcpy(iscsiconf, &newconf, sizeof(newconf));

	retval = sql_update_iscsiconf(iscsiconf->target_id, iscsiconf);
	if (retval != 0) {
		DEBUG_ERR_SERVER("sql update failed for target_id %u\n", iscsiconf->target_id);
		snprintf(errmsg, sizeof(errmsg), "Updating DB with new iSCSI settings failed\n");
		goto senderr;
	}

	tl_server_msg_success(comm, msg);
	return 0;
senderr:
	tl_server_msg_failure2(comm, msg, errmsg);
	return -1;
}

static int
tl_server_rescan_disks(struct tl_comm *comm, struct tl_msg *msg)
{
	int retval, i;
	struct tl_blkdevinfo *blkdev;

	retval = tl_common_scan_physdisk();
	if (retval != 0) {
		tl_server_msg_failure(comm, msg);
		return -1;
	}

	for (i = 1; i < TL_MAX_DISKS; i++) {
		blkdev = bdev_list[i];
		if (!blkdev)
			continue;
		retval = sync_blkdev(blkdev);
		if (retval != 0) {
			blkdev->offline = 1;
			continue;
		}

		if (blkdev->offline) {
			load_blkdev(blkdev);
			if (!blkdev->offline && blkdev->ddmaster) {
				load_tdisks(blkdev);
				attach_tdisks();
			}
		}

	}
	tl_server_msg_success(comm, msg);
	return 0;
}

int mdaemon_exit;

int
tl_server_reset_logs(struct tl_comm *comm, struct tl_msg *msg)
{
	int retval;

	if (!log_error) {
		tl_server_msg_success(comm, msg);
		return 0;
	}

	retval = tl_ioctl_void(TLTARGIOCRESETLOGS);
	if (retval != 0) {
		tl_server_msg_failure(comm, msg);
		return -1;
	}

	log_error = 0;
	attach_tdisks();
	done_init = 1;
	tl_server_msg_success(comm, msg);
	return 0;
}

static void
tl_server_reboot_system(void)
{
	DEBUG_INFO_SERVER("Reboot command received. Rebooting system now\n");
	system("shutdown -r now");
}

static void
tl_server_restart_service(void)
{
	static int done_restart = 0;

	if (done_restart)
		return;

	DEBUG_INFO_SERVER("Restart command received. Restarting service now\n");
	system("echo \"service quadstor restart\" | at now + 1 minute");
	done_restart = 1;
}

int
tl_server_unload(void)
{
	pthread_mutex_lock(&daemon_lock);
	if (mdaemon_exit)
	{
		pthread_mutex_unlock(&daemon_lock);
		return 0;
	}
	mdaemon_exit = 1;
	cancel_all_clone_ops();
	tl_server_unload_tdisks();
	pthread_mutex_unlock(&daemon_lock);
	tl_ioctl_void(TLTARGIOCUNLOAD);
	return 0;
}

extern struct m_list mchanger_list;
extern struct t_list tdrive_list;

static void
tl_server_load(void)
{
	int retval;

	tl_common_scan_physdisk();
	__tl_server_load();

	retval = node_controller_init_pre();
	if (retval != 0)
		exit(1); 

	retval = tl_ioctl_void(TLTARGIOCLOADDONE);
	if (retval != 0)
		log_error = 1;
}

void
tl_server_load_conf(struct tl_comm *comm, struct tl_msg *msg)
{
	int retval;

	pthread_mutex_lock(&daemon_lock);
	if (!done_server_init)
		pthread_cond_wait(&daemon_cond, &daemon_lock);
	pthread_mutex_unlock(&daemon_lock);

	if (done_init) {
		tl_server_msg_success(comm, msg);
		return;
	}

	if (log_error) {
		tl_server_msg_failure(comm, msg);
		return;
	}

	retval = node_recv_init();
	if (retval != 0)
		exit(EXIT_FAILURE); 

	attach_tdisks();
	done_init = 1;

	retval = node_controller_init();
	if (retval != 0)
		exit(EXIT_FAILURE); 

	ietadm_qload_done();
	tl_server_msg_success(comm, msg);
}

static int
tl_server_handle_msg(struct tl_comm *comm, struct tl_msg *msg)
{

	switch (msg->msg_id) {
		case MSG_ID_REBOOT_SYSTEM:
			tl_server_reboot_system();
			tl_server_msg_success(comm, msg);
			break;
		case MSG_ID_RESTART_SERVICE:
			tl_server_restart_service();
			tl_server_msg_success(comm, msg);
			break;
		case MSG_ID_LOAD_CONF:
			tl_server_load_conf(comm, msg);
			break;
		case MSG_ID_UNLOAD_CONF:
			tl_server_unload();
			tl_server_msg_success(comm, msg);
			break;
		case MSG_ID_RESET_LOGS:
			tl_server_reset_logs(comm, msg);
			break;
		case MSG_ID_GET_CONFIGURED_DISKS:
			pthread_mutex_lock(&daemon_lock);
			tl_server_get_configured_disks(comm, msg);
			pthread_mutex_unlock(&daemon_lock);
			break;
		case MSG_ID_GET_POOL_CONFIGURED_DISKS:
			pthread_mutex_lock(&daemon_lock);
			tl_server_get_pool_configured_disks(comm, msg);
			pthread_mutex_unlock(&daemon_lock);
			break;
		case MSG_ID_DEV_MAPPING:
			pthread_mutex_lock(&daemon_lock);
			tl_server_dev_mapping(comm, msg);
			pthread_mutex_unlock(&daemon_lock);
			break;
		case MSG_ID_LIST_DISKS:
			pthread_mutex_lock(&daemon_lock);
			tl_server_list_disks(comm, msg);
			pthread_mutex_unlock(&daemon_lock);
			break;
		case MSG_ID_ADD_DISK:
			pthread_mutex_lock(&daemon_lock);
			tl_server_add_disk(comm, msg);
			pthread_mutex_unlock(&daemon_lock);
			break;
		case MSG_ID_DELETE_DISK:
			pthread_mutex_lock(&daemon_lock);
			tl_server_delete_disk(comm, msg);
			pthread_mutex_unlock(&daemon_lock);
			break;
		case MSG_ID_RESCAN_DISKS:
			pthread_mutex_lock(&daemon_lock);
			tl_server_rescan_disks(comm, msg);
			pthread_mutex_unlock(&daemon_lock);
			break;
		case MSG_ID_GET_ISCSICONF:
			pthread_mutex_lock(&daemon_lock);
			tl_server_get_iscsiconf(comm, msg);
			pthread_mutex_unlock(&daemon_lock);
			break;
		case MSG_ID_SET_ISCSICONF:
			pthread_mutex_lock(&daemon_lock);
			tl_server_set_iscsiconf(comm, msg);
			pthread_mutex_unlock(&daemon_lock);
			break;
		case MSG_ID_SERVER_STATUS:
			tl_server_get_status(comm, msg);
			break;
		case MSG_ID_GET_UID:
			tl_server_get_uid(comm, msg);
			break;
		case MSG_ID_RUN_DIAGNOSTICS:
			tl_server_run_diagnostics(comm, msg, 1);
			break;
		case MSG_ID_ADD_GROUP:
			pthread_mutex_lock(&daemon_lock);
			tl_server_add_group(comm, msg);
			pthread_mutex_unlock(&daemon_lock);
			break;
		case MSG_ID_ADD_TDISK:
			pthread_mutex_lock(&daemon_lock);
			tl_server_add_target(comm, msg);
			pthread_mutex_unlock(&daemon_lock);
			break;
		case MSG_ID_LIST_GROUP:
			pthread_mutex_lock(&daemon_lock);
			tl_server_list_groups(comm, msg, 0);
			pthread_mutex_unlock(&daemon_lock);
			break;
		case MSG_ID_LIST_GROUP_CONFIGURED:
			pthread_mutex_lock(&daemon_lock);
			tl_server_list_groups(comm, msg, 1);
			pthread_mutex_unlock(&daemon_lock);
			break;
		case MSG_ID_RENAME_POOL:
			pthread_mutex_lock(&daemon_lock);
			tl_server_rename_pool(comm, msg);
			pthread_mutex_unlock(&daemon_lock);
			break;
		case MSG_ID_LIST_TDISK:
			pthread_mutex_lock(&daemon_lock);
			tl_server_list_tdisks(comm, msg);
			pthread_mutex_unlock(&daemon_lock);
			break;
		case MSG_ID_LIST_POOL_TDISK:
			pthread_mutex_lock(&daemon_lock);
			tl_server_list_pool_tdisks(comm, msg);
			pthread_mutex_unlock(&daemon_lock);
			break;
		case MSG_ID_TDISK_STATS:
			pthread_mutex_lock(&daemon_lock);
			tl_server_tdisk_stats(comm, msg);
			pthread_mutex_unlock(&daemon_lock);
			break;
		case MSG_ID_TDISK_STATS_RESET:
			pthread_mutex_lock(&daemon_lock);
			tl_server_tdisk_stats_reset(comm, msg);
			pthread_mutex_unlock(&daemon_lock);
			break;
		case MSG_ID_DELETE_TDISK:
			pthread_mutex_lock(&daemon_lock);
			tl_server_delete_tdisk(comm, msg);
			pthread_mutex_unlock(&daemon_lock);
			break;
		case MSG_ID_DELETE_GROUP:
			pthread_mutex_lock(&daemon_lock);
			tl_server_delete_group(comm, msg);
			pthread_mutex_unlock(&daemon_lock);
			break;
		case MSG_ID_GET_DISKCONF:
			pthread_mutex_lock(&daemon_lock);
			tl_server_get_diskconf(comm, msg);
			pthread_mutex_unlock(&daemon_lock);
			break;
		case MSG_ID_SET_DISKCONF:
			pthread_mutex_lock(&daemon_lock);
			tl_server_set_diskconf(comm, msg);
			pthread_mutex_unlock(&daemon_lock);
			break;
		case MSG_ID_GET_VDISKCONF:
			pthread_mutex_lock(&daemon_lock);
			tl_server_get_vdiskconf(comm, msg);
			pthread_mutex_unlock(&daemon_lock);
			break;
		case MSG_ID_SET_VDISKCONF:
			pthread_mutex_lock(&daemon_lock);
			tl_server_set_vdiskconf(comm, msg);
			pthread_mutex_unlock(&daemon_lock);
			break;
		case MSG_ID_MODIFY_TDISK:
			pthread_mutex_lock(&daemon_lock);
			tl_server_modify_tdisk(comm, msg);
			pthread_mutex_unlock(&daemon_lock);
			break;
		case MSG_ID_LIST_CLONES:
			pthread_mutex_lock(&daemon_lock);
			tl_server_list_clones(comm, msg, 0);
			pthread_mutex_unlock(&daemon_lock);
			break;
		case MSG_ID_LIST_CLONES_PRUNE:
			pthread_mutex_lock(&daemon_lock);
			tl_server_list_clones(comm, msg, 1);
			pthread_mutex_unlock(&daemon_lock);
			break;
		case MSG_ID_CANCEL_CLONE:
			pthread_mutex_lock(&daemon_lock);
			tl_server_cancel_clone(comm, msg);
			pthread_mutex_unlock(&daemon_lock);
			break;
		case MSG_ID_START_CLONE:
			pthread_mutex_lock(&daemon_lock);
			tl_server_start_clone(comm, msg);
			pthread_mutex_unlock(&daemon_lock);
			break;
		case MSG_ID_SET_VDISK_ROLE:
			pthread_mutex_lock(&daemon_lock);
			tl_server_set_vdisk_role(comm, msg);
			pthread_mutex_unlock(&daemon_lock);
			break;
		case MSG_ID_VDISK_RESIZE:
			pthread_mutex_lock(&daemon_lock);
			tl_server_vdisk_resize(comm, msg);
			pthread_mutex_unlock(&daemon_lock);
			break;
		case MSG_ID_HA_CONFIG:
			pthread_mutex_lock(&daemon_lock);
			tl_server_ha_config(comm, msg);
			pthread_mutex_unlock(&daemon_lock);
			break;
		case MSG_ID_UNMAP_CONFIG:
			pthread_mutex_lock(&daemon_lock);
			tl_server_unmap_config(comm, msg);
			pthread_mutex_unlock(&daemon_lock);
			break;
		case MSG_ID_GET_MIRRORCONF:
			pthread_mutex_lock(&daemon_lock);
			tl_server_get_mirrorconf(comm, msg);
			pthread_mutex_unlock(&daemon_lock);
			break;
		case MSG_ID_CANCEL_MIRROR:
			pthread_mutex_lock(&daemon_lock);
			tl_server_cancel_mirror(comm, msg);
			pthread_mutex_unlock(&daemon_lock);
			break;
		case MSG_ID_START_MIRROR:
			pthread_mutex_lock(&daemon_lock);
			tl_server_start_mirror(comm, msg);
			pthread_mutex_unlock(&daemon_lock);
			break;
		case MSG_ID_REMOVE_MIRROR:
			pthread_mutex_lock(&daemon_lock);
			tl_server_remove_mirror(comm, msg);
			pthread_mutex_unlock(&daemon_lock);
			break;
		case MSG_ID_LIST_SYNC_MIRRORS:
			pthread_mutex_lock(&daemon_lock);
			tl_server_list_sync_mirrors(comm, msg);
			pthread_mutex_unlock(&daemon_lock);
			break;
		case MSG_ID_LIST_MIRRORS:
			pthread_mutex_lock(&daemon_lock);
			tl_server_list_mirrors(comm, msg, 0);
			pthread_mutex_unlock(&daemon_lock);
			break;
		case MSG_ID_LIST_MIRRORS_PRUNE:
			pthread_mutex_lock(&daemon_lock);
			tl_server_list_mirrors(comm, msg, 1);
			pthread_mutex_unlock(&daemon_lock);
			break;
		case MSG_ID_LIST_MIRROR_CHECKS:
			pthread_mutex_lock(&mirror_lock);
			tl_server_list_mirror_checks(comm, msg);
			pthread_mutex_unlock(&mirror_lock);
			break;
		case MSG_ID_ADD_MIRROR_CHECK:
			pthread_mutex_lock(&mirror_lock);
			tl_server_add_mirror_check(comm, msg);
			pthread_mutex_unlock(&mirror_lock);
			break;
		case MSG_ID_REMOVE_MIRROR_CHECK:
			pthread_mutex_lock(&mirror_lock);
			tl_server_remove_mirror_check(comm, msg);
			pthread_mutex_unlock(&mirror_lock);
			break;
		case MSG_ID_LIST_FC_RULES:
			pthread_mutex_lock(&daemon_lock);
			tl_server_list_fc_rules(comm, msg);
			pthread_mutex_unlock(&daemon_lock);
			break;
		case MSG_ID_ADD_FC_RULE:
			pthread_mutex_lock(&daemon_lock);
			tl_server_add_fc_rule(comm, msg);
			pthread_mutex_unlock(&daemon_lock);
			break;
		case MSG_ID_REMOVE_FC_RULE:
			pthread_mutex_lock(&daemon_lock);
			tl_server_remove_fc_rule(comm, msg);
			pthread_mutex_unlock(&daemon_lock);
			break;
		default:
			/* Invalid msg id */
			DEBUG_ERR_SERVER("Invalid msg id %d in message", msg->msg_id);
			tl_server_msg_invalid(comm, msg);
			break;
	}
	return 0;
}



int
tl_server_process_request(int fd, struct sockaddr_un *client_addr)
{
	struct tl_comm comm;
	struct tl_msg *msg;

	comm.sockfd = fd;

	msg = tl_msg_recv_message(&comm);

	if (!msg) {
		DEBUG_ERR_SERVER("Message receive failed\n");
		tl_msg_close_connection(&comm);
		return -1;
	}

	tl_server_handle_msg(&comm, msg);

	return 0;
}

#ifdef FREEBSD
long int get_random()
{
	srandomdev();
	return random();
}
#else
long int get_random()
{
	struct timeval tv;
	struct timezone tz;
	long int res;
	struct drand48_data buffer;

	gettimeofday(&tv, &tz);
	srand48_r(tv.tv_sec + tv.tv_usec, &buffer);
	lrand48_r(&buffer, &res);
	return res;
}
#endif

static void *
server_init(void * arg)
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

	pthread_mutex_lock(&daemon_lock);
	done_socket_init = 1;
	pthread_cond_broadcast(&socket_cond);
	pthread_mutex_unlock(&daemon_lock);

	while (1)
	{
		addr_len = sizeof(struct sockaddr_un);

		if ((newfd = accept(sockfd, (struct sockaddr *)&client_addr, &addr_len)) == -1)
		{
			DEBUG_WARN_SERVER("Client connection accept failed");
			continue;
		}

		tl_server_process_request(newfd, &client_addr);
	}

	close(sockfd);
	pthread_exit(0);
}

int
main_server_start(pthread_t *thread_id)
{
	int retval;

	server_openlog();

	retval = pthread_create(thread_id, NULL, server_init, NULL);

	if (retval != 0)
	{
		DEBUG_ERR_SERVER("Unable to start a new thread for server\n");
		return -1;
	}

	pthread_mutex_lock(&daemon_lock);
	if (!done_socket_init)
		pthread_cond_wait(&socket_cond, &daemon_lock);
	pthread_mutex_unlock(&daemon_lock);

	node_usr_init();

	tl_server_load();

	pthread_mutex_lock(&daemon_lock);
	done_server_init = 1;
	pthread_cond_broadcast(&daemon_cond);
	pthread_mutex_unlock(&daemon_lock);

	return 0;

}

int
tl_server_register_pid(void)
{
	int retval;

	mdaemon_info.daemon_pid = getpid();
	retval = tl_ioctl(TLTARGIOCDAEMONSETINFO, &mdaemon_info);

	if (retval != 0)
	{
		DEBUG_ERR_SERVER("Failed to register our pid\n");
		return -1;
	}
	return 0;
}
