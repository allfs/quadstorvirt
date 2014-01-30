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

static void
print_usage(void)
{
	fprintf(stdout, "vdconfig usage: \n\n");
	fprintf(stdout, "Listing VDisks: \n");
	fprintf(stdout, "vdconfig -l\n\n");
	fprintf(stdout, "Adding a VDisk: \n");
	fprintf(stdout, "vdconfig -a -v <vdisk name> -s <size> -g <pool name> -e (optional)\n\n");
	fprintf(stdout, "Deleting a VDisk: \n");
	fprintf(stdout, "vdconfig -x -v <vdisk name> -f (force)\n\n");
	fprintf(stdout, "Modifying a VDisk: \n");
	fprintf(stdout, "vdconfig -m -v <vdisk name> -d (dedupe) -c (compression) -y (verify) -t <threshold value>\n\n");
	fprintf(stdout, "Resizing a VDisk: \n");
	fprintf(stdout, "vdconfig -v <vdisk name> -s <new size> (Where 1 GB = 1024 x 1024 x 1024 bytes)\n\n");
	fprintf(stdout, "Set VDisk serial number: \n");
	fprintf(stdout, "vdconfig -n <New serial number> -v <vdisk name>\n");
	fprintf(stdout, "New serial number can be left empty. System will generate its own\n");
	fprintf(stdout, "New serial number if specified will be of the form \n");
	fprintf(stdout, "6e... <32 characters containing only 0 - 9, a - f>\n\n");
	exit(0);
}

static void 
tdisk_list_calc_format_length(struct tdisk_list *tdisk_list, int *ret_name_len, int *ret_pool_len)
{
	struct tdisk_info *tdisk_info;
	int name_len = strlen("Name");
	int pool_len = strlen("Pool");
	int len;

	TAILQ_FOREACH(tdisk_info, tdisk_list, q_entry) {
		if (tdisk_info->disabled == VDISK_DELETED)
			continue;
		len = strlen(tdisk_info->name);
		if (len > name_len)
			name_len = len;
		len = strlen(tdisk_info->group_name);
		if (len > pool_len)
			pool_len = len;
	}
	*ret_name_len = name_len;
	*ret_pool_len = pool_len;
}

static int
vdconfig_add_vdisk(char *name, char *pool, uint64_t size, int emulate, int dedupe, int compression, int verify, int threshold, char *iqn)
{
	int group_id;
	int lba_shift;
	int retval;
	char reply[512];

	if (pool[0]) {
		group_id = tl_client_get_group_id(pool);
		if (group_id <= 0) {
			fprintf(stderr, "Cannot get group id for pool %s\n", pool);
			return -1;
		}
	}
	else
		group_id = 0;

	size *= (1024 * 1024 * 1024);
	if (size > MAX_TARGET_SIZE) {
		fprintf(stderr, "VDisk size exceeds maximum\n");
		return -1;
	}

	if (!target_name_valid(name)) {
		fprintf(stderr, "Invalid vdisk name specified\n");
		return -1;
	}

	if (strlen(iqn) > 255) {
		fprintf(stderr, "Invalid iqn specified\n");
		return -1;
	}

	if (emulate)
		lba_shift = 9;
	else
		lba_shift = 12;

	retval = tl_client_add_tdisk(name, size, lba_shift, group_id, dedupe, compression, verify, threshold, iqn, reply);
	if (retval != 0) {
		fprintf(stderr, "Unable to add VDisk. Message from server is: %s\n", reply);
		return -1;
	}
	fprintf(stdout, "Adding VDisk %s successful\n", name);
	return 0;
}

static int
vdconfig_set_serialnumber(char *name, char *serialnumber)
{
	int retval, target_id;
	struct vdiskconf vdiskconf;
	char reply[512];

	target_id = tl_client_get_target_id(name);
	if (target_id <= 0) {
		fprintf(stderr, "Cannot get target id for VDisk %s\n", name);
		return -1;
	}

	memset(&vdiskconf, 0, sizeof(vdiskconf));
	vdiskconf.target_id = target_id;
	memcpy(vdiskconf.serialnumber, serialnumber, 32);
	retval = tl_client_set_vdiskconf(&vdiskconf, MSG_ID_SET_SERIALNUMBER, reply);
	if (retval != 0) {
		fprintf(stderr, "Unable to set serial number for VDisk %s\n", name);
		fprintf(stderr, "Message from server is: %s\n", reply);
		exit(1);
	}
	fprintf(stdout, "Updating serial number for VDisk %s successful\n", name);
	return 0;
}

static int
vdconfig_modify_vdisk(char *name, int dedupe, int compression, int verify, int threshold)
{
	int retval, target_id;
	struct vdiskconf vdiskconf;
	char reply[512];

	target_id = tl_client_get_target_id(name);
	if (target_id <= 0) {
		fprintf(stderr, "Cannot get target id for VDisk %s\n", name);
		return -1;
	}

	if (!dedupe)
		verify = 0;

	memset(&vdiskconf, 0, sizeof(vdiskconf));
	vdiskconf.target_id = target_id;
	vdiskconf.enable_deduplication = dedupe;
	vdiskconf.enable_compression = compression;
	vdiskconf.enable_verify = verify;
	vdiskconf.threshold = threshold;
	retval = tl_client_set_vdiskconf(&vdiskconf, MSG_ID_SET_VDISKCONF, reply);
	if (retval != 0) {
		fprintf(stderr, "Unable to modify VDisk %s\n", name);
		fprintf(stderr, "Message from server is: %s\n", reply);
		exit(1);
	}
	fprintf(stdout, "Modifying VDisk %s successful\n", name);
	return 0;
}

static int
vdconfig_delete_vdisk(char *name, int force)
{
	int retval, target_id;

	target_id = tl_client_get_target_id(name);
	if (target_id <= 0) {
		fprintf(stderr, "Cannot get target id for VDisk %s\n", name);
		return -1;
	}

	if (!force) {
		char msg[128];
		snprintf(msg, sizeof(msg), "Delete VDisk %s ? (y/n)", name);
		retval = tl_client_prompt_user(msg);
		if (retval != 1) {
			fprintf(stdout, "Skipping deletion of VDisk %s\n", name);
			exit(1);
		}
	}

	retval = tl_client_delete_tdisk(target_id);
	if (retval != 0) {
		fprintf(stderr, "Deleting VDisk %s failed\n", name);
		return -1;
	}
	fprintf(stdout, "Deleting VDisk %s successful\n", name);
	return 0;
}

static int
vdconfig_list_vdisks(void)
{
	struct tdisk_list tdisk_list;
	struct tdisk_info *tdisk_info;
	char databuf[64];
	int retval;
	int name_len, pool_len;
	char fmt[256];
	char status[64];
	char lunid[32];

	retval = tl_client_list_vdisks(&tdisk_list, MSG_ID_LIST_TDISK);
	if (retval != 0) {
		fprintf(stderr, "Getting VDisk list failed\n");
		return -1;
	}

	tdisk_list_calc_format_length(&tdisk_list, &name_len, &pool_len);
	sprintf(fmt, "%%-%ds %%-%ds %%-32s %%-8s %%-5s %%-20s\n", name_len, pool_len); 
	fprintf(stdout, fmt, "Name", "Pool", "Serial Number", "Size(GB)", "LUN", "Status");
	TAILQ_FOREACH(tdisk_info, &tdisk_list, q_entry) {
		if (tdisk_info->disabled == VDISK_DELETED)
			continue;

		status[0] = 0;
		if (tdisk_info->enable_deduplication)
			strcat(status, "D");

		if (tdisk_info->enable_compression) {
			if (strlen(status) > 0)
				strcat(status, " ");
			strcat(status, "C");
		}

		if (tdisk_info->enable_verify) {
			if (strlen(status) > 0)
				strcat(status, " ");
			strcat(status, "V");
		}

		if (tdisk_info->lba_shift == 9) {
			if (strlen(status) > 0)
				strcat(status, " ");
			strcat(status, "E");
		}

		if (tdisk_info->disabled == VDISK_DELETED)
			strcpy(status, "Disabled");
		else if (tdisk_info->disabled == VDISK_DELETING && tdisk_info->delete_error == -1)
			strcpy(status, "Delete error");
		else if (tdisk_info->disabled == VDISK_DELETING && tdisk_info->delete_error)
			strcpy(status, "Delete stopped");
		else if (tdisk_info->disabled == VDISK_DELETING)
			strcpy(status, "Deletion in progress");
		else if (!tdisk_info->online)
			strcpy(status, "Offline");
		sprintf(databuf, "%llu", (unsigned long long)(tdisk_info->size / (1024 * 1024 * 1024)));
		sprintf(lunid, "%d", tdisk_info->tl_id + 1);
		fprintf(stdout, fmt, tdisk_info->name, tdisk_info->group_name, tdisk_info->serialnumber, databuf, lunid, status);
	}
	tdisk_list_free(&tdisk_list);
	return 0;
}

int main(int argc, char *argv[])
{
	char src[TDISK_MAX_NAME_LEN];
	char pool[GROUP_MAX_NAME_LEN];
	char serialnumber[50];
	char iqn[256];
	char reply[512];
	int c, retval;
	int force = 0;
	int set_serialnumber = 0;
	int list = 0, delete = 0, add = 0, emulate = 0;
	int dedupe = 0, compression = 0, verify = 0;
	int modify = 0, threshold = 0;
	unsigned long long size = 0, sizebytes;

	if (geteuid() != 0) {
		fprintf(stderr, "This program can only be run as root\n");
		exit(1);
	}

	memset(src, 0, sizeof(src));
	memset(pool, 0, sizeof(pool));
	memset(iqn, 0, sizeof(iqn));
	memset(serialnumber, 0, sizeof(serialnumber));
	force = 0;
	while ((c = getopt(argc, argv, "v:s:g:t:n:i:flxaedcym")) != -1) {
		switch (c) {
		case 'v':
			strncpy(src, optarg, TDISK_MAX_NAME_LEN - 1);
			break;
		case 's':
			size = strtoull(optarg, NULL, 10);
			break;
		case 'g':
			strncpy(pool, optarg, GROUP_NAME_LEN);
			break;
		case 'i':
			strncpy(iqn, optarg, 255);
			break;
		case 't':
			threshold = atoi(optarg);
			break;
		case 'a':
			add = 1;
			break;
		case 'e':
			emulate = 1;
			break;
		case 'd':
			dedupe = 1;
			break;
		case 'c':
			compression = 1;
			break;
		case 'y':
			verify = 1;
			break;
		case 'm':
			modify = 1;
			break;
		case 'x':
			delete = 1;
			break;
		case 'l':
			list = 1;
			break;
		case 'f':
			force = 1;
			break;
		case 'n':
			set_serialnumber = 1;
			if (optarg)
				strncpy(serialnumber, optarg, 32);
			break;
		default:
			print_usage();
			break;
		}
	}

	if (list) {
		return vdconfig_list_vdisks();
	}
	if (set_serialnumber) {
		if (!src[0])
			print_usage();
		if (strcmp(serialnumber, "gen") == 0)
			memset(serialnumber, 0, sizeof(serialnumber));
		if (serialnumber[0] && !serialnumber_valid(serialnumber)) {
			fprintf(stderr, "Invalid serial number %.32s\n", serialnumber);
			print_usage();
		}
		return vdconfig_set_serialnumber(src, serialnumber);
	}
	if (add) {
		if (!size || !src[0])
			print_usage();

		return vdconfig_add_vdisk(src, pool, size, emulate, dedupe, compression, verify, threshold, iqn);
	}
	if (modify) {
		if (!src[0])
			print_usage();

		if (threshold < 0 || threshold >= 100) {
			fprintf(stderr, "Invalid threshold value\n");
			print_usage();
		}

		return vdconfig_modify_vdisk(src, dedupe, compression, verify, threshold);
	}

	if (delete) {
		if (!src[0])
			print_usage();
		return vdconfig_delete_vdisk(src, force);
	}		


	if (!size || !src[0]) {
		print_usage();
	}

	sizebytes = (size * 1024 * 1024 * 1024);
	retval = tl_client_vdisk_resize(src, sizebytes, force, reply);
	if (retval != 0) {
		fprintf(stderr, "VDisk %s resize to %llu GB failed\n", src, (unsigned long long)size);
		fprintf(stderr, "Message from server is: %s\n", reply);
		exit(1);
	}
	else {
		fprintf(stderr, "VDisk %s resized to %llu GB\n", src, (unsigned long long)size);
	}
	return 0;
}

