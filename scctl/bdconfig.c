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

static inline void
print_usage()
{
	fprintf(stdout, "bpconfig usage: \n\n");
	fprintf(stdout, "Listing all disks: \n");
	fprintf(stdout, "bdconfig -l\n\n");
	fprintf(stdout, "Listing all configured disks: \n");
	fprintf(stdout, "bdconfig -l -c\n\n");
	fprintf(stdout, "Listing all disks exclude configured: \n");
	fprintf(stdout, "bdconfig -l -e\n\n");
	fprintf(stdout, "Adding a disk: \n");
	fprintf(stdout, "bdconfig -a -d <devicepath> -p (if enable compression) -o (if log disk) -h (if ha disk)\n\n");
	fprintf(stdout, "Deleting a disk: \n");
	fprintf(stdout, "bdconfig -x -d <devicepath>\n\n");
	exit(1);
}

static int
calc_vendor_len(char *ptr, int max)
{
	int len = max;
	int i;

	for (i = max - 1; i >= 0; i--) {
		if (ptr[i] && ptr[i] != ' ')
			break;
		ptr[i] = 0;
		len = i + 1;
	}
	return len;
}

static void
disk_list_calc_format_length(struct d_list *dlist, struct d_list *configured_dlist, int *ret_name_len, int *ret_pool_len, int *ret_vendor_len, int *ret_product_len, int *ret_serial_len, int configured, int excludeconfigured)
{
	struct physdisk *disk;
	int name_len = strlen("Name");
	int pool_len = strlen("Pool");
	int vendor_len = strlen("Vendor");
	int product_len = strlen("Product");
	int serial_len = strlen("SerialNumber");
	int len;

	TAILQ_FOREACH(disk, dlist, q_entry) {
		struct physdisk *config;

		config = disk_configured(disk, configured_dlist);
		if (config && excludeconfigured)
			continue;
		else if (!config && configured)
			continue;
		if (config) {
			len = strlen(config->group_name);
			if (len > pool_len)
				pool_len = len;
		}
		len = strlen(disk->info.devname);
		if (len > name_len)
			name_len = len;
		len = calc_vendor_len(disk->info.vendor, 8);
		if (len > vendor_len)
			vendor_len = len;
		len = calc_vendor_len(disk->info.product, 16);
		if (len > product_len)
			product_len = len;
		len = calc_vendor_len(disk->info.serialnumber, 32);
		if (len > serial_len)
			serial_len = len;
			
	}
	*ret_name_len = name_len;
	*ret_pool_len = pool_len;
	*ret_vendor_len = vendor_len;
	*ret_product_len = product_len;
	*ret_serial_len = serial_len;
}

static int
bdconfig_delete_disk(char *devpath)
{
	struct physdisk *disk;
	struct d_list configured_dlist;
	char reply[512];
	int configured = 0;
	int retval;

	retval = tl_client_list_disks(&configured_dlist, MSG_ID_GET_CONFIGURED_DISKS);
	if (retval != 0) {
		fprintf(stderr, "Unable to get configured disk list\n");
		return -1;
	}

	TAILQ_FOREACH(disk, &configured_dlist, q_entry) {
		if (strcmp(devpath, disk->info.devname) == 0) {
			configured = 1;
			break;
		}
	}
	disk_free_all(&configured_dlist);

	if (!configured) {
		fprintf(stderr, "Disk %s not configured\n", devpath);
		return -1;
	}

	retval = tl_client_delete_disk(devpath, reply);
	if (retval != 0) {
		fprintf(stderr, "Unable to delete disk. Message from server is %s\n", reply);
		return -1;
	}
	fprintf(stdout, "Deleting disk %s successful\n", devpath);
	return 0;

}

static int
bdconfig_add_disk(char *devpath, char *pool, int compression, int log, int ha)
{
	struct physdisk *disk;
	struct d_list configured_dlist;
	char reply[512];
	int group_id, retval;

	retval = tl_client_list_disks(&configured_dlist, MSG_ID_GET_CONFIGURED_DISKS);
	if (retval != 0) {
		fprintf(stderr, "Unable to get configured disk list\n");
		return -1;
	}

	TAILQ_FOREACH(disk, &configured_dlist, q_entry) {
		if (strcmp(devpath, disk->info.devname) == 0) {
			fprintf(stderr, "Disk %s already configured\n", devpath);
			disk_free_all(&configured_dlist);
			return -1;
		}
	}
	disk_free_all(&configured_dlist);

	if (pool[0]) {
		group_id = tl_client_get_group_id(pool);
		if (group_id <= 0) {
			fprintf(stderr, "Cannot get group id for pool %s\n", pool);
			return -1;
		}
	}
	else
		group_id = 0;

	retval = tl_client_add_disk(devpath, compression, log, ha, group_id, reply);
	if (retval != 0) {
		fprintf(stderr, "Unable to add disk. Message from server is %s\n", reply);
		return -1;
	}
	fprintf(stdout, "Adding disk %s successful\n", devpath);
	return 0;
}

static int
bdconfig_list_disks(int configured, int excludeconfigured)
{
	struct physdisk *disk;
	struct d_list dlist;
	struct d_list configured_dlist;
	char status[32];
	char fmt[128];
	int name_len, pool_len, vendor_len, product_len, serial_len;
	int retval;

	retval = tl_client_list_disks(&configured_dlist, MSG_ID_GET_CONFIGURED_DISKS);
	if (retval != 0) {
		fprintf(stderr, "Unable to get configured disk list\n");
		return -1;
	}

	retval = tl_client_list_disks(&dlist, MSG_ID_LIST_DISKS);
	if (retval != 0) {
		fprintf(stderr, "Unable to get disk list\n");
		disk_free_all(&configured_dlist);
		return -1;
	}

	disk_list_calc_format_length(&dlist, &configured_dlist, &name_len, &pool_len, &vendor_len, &product_len, &serial_len, configured, excludeconfigured);
	sprintf(fmt, "%%-3s %%-%ds %%-%ds %%-%ds %%-%ds %%-%ds %%-8s %%-8s %%-12s\n", vendor_len, product_len, serial_len, name_len, pool_len);
	fprintf(stdout, fmt, "ID", "Vendor", "Model", "SerialNumber", "Name", "Pool", "Size", "Used", "Status");
	sprintf(fmt, "%%-3d %%-%ds %%-%ds %%-%ds %%-%ds %%-%ds %%-8.2f %%-8.2f %%-12s\n", vendor_len, product_len, serial_len, name_len, pool_len);

	TAILQ_FOREACH(disk, &dlist, q_entry) {
		struct physdisk *config;

		config = disk_configured(disk, &configured_dlist);
		if (config && excludeconfigured)
			continue;
		else if (!config && configured)
			continue;
		status[0] = 0;
		if (config && config->initialized > 0) {
			if (config->ddmaster)
				strcat(status, "D");
			if (config->log_disk) {
				if (strlen(status) > 0)
					strcat(status, " ");
				strcat(status, "L");
			}
			if (config->ha_disk) {
				if (strlen(status) > 0)
					strcat(status, " ");
				strcat(status, "H");
			}
			if (config->unmap) {
				if (strlen(status) > 0)
					strcat(status, " ");
				strcat(status, "U");
			}
			if (config->enable_comp) {
				if (strlen(status) > 0)
					strcat(status, " ");
				strcat(status, "C");
			}

			if (!config->log_disk)
				goto skip_wc;
			if (config->write_cache == WRITE_CACHE_DEFAULT) {
				if (strlen(status) > 0)
					strcat(status, " ");
				strcat(status, "WC");
			}
			else if (config->write_cache == WRITE_CACHE_FLUSH) {
				if (strlen(status) > 0)
					strcat(status, " ");
				strcat(status, "WF");
			}
			else if (config->write_cache == WRITE_CACHE_FUA) {
				if (strlen(status) > 0)
					strcat(status, " ");
				strcat(status, "WU");
			}
		}
		else if (config && config->initialized == 0) {
			strcpy(status, "Initializing");
		}
		else if (config) {
			strcpy(status, "Initialization failed");
		}
skip_wc:
		if (config && !disk->info.online)
			strcpy(status, "offline");

		if (config && disk->info.online) {
			fprintf(stdout, fmt, config->bid, disk->info.vendor, disk->info.product, disk->info.serialnumber, disk->info.devname, config->group_name, disk->size / (1024.00 * 1024.00 * 1024.00), config->used/(1024.00 * 1024.00 * 1024.00), status);
		}
		else if (config)
			fprintf(stdout, fmt, config->bid, disk->info.vendor, disk->info.product, disk->info.serialnumber, disk->info.devname, config->group_name, disk->size / (1024.00 * 1024.00 * 1024.00), 0.00, status);
		else
			fprintf(stdout, fmt, 0, disk->info.vendor, disk->info.product, disk->info.serialnumber, disk->info.devname, "N/A", disk->size / (1024.00 * 1024.00 * 1024.00), 0.00, "N/A");
	}
	disk_free_all(&configured_dlist);
	disk_free_all(&dlist);
	return 0;
}

int main(int argc, char *argv[])
{
	char devpath[256];
	char pool[40];
	int c;
	int add = 0, delete = 0, list = 0;
	int listconfigured = 0, excludeconfigured = 0;
	int compression = 0, log = 0, ha = 0;

	if (geteuid() != 0) {
		fprintf(stderr, "This program can only be run as root\n");
		exit(1);
	}

	memset(devpath, 0, sizeof(devpath));
	memset(pool, 0, sizeof(pool));
	while ((c = getopt(argc, argv, "d:g:axlceh")) != -1) {
		switch (c) {
		case 'd':
			snprintf(devpath, sizeof(devpath), "%s", optarg);
			break;
		case 'g':
			strncpy(pool, optarg, 36);
			break;
		case 'a':
			add = 1;
			break;
		case 'x':
			delete = 1;
			break;
		case 'l':
			list = 1;
			break;
		case 'c':
			listconfigured = 1;
			break;
		case 'e':
			excludeconfigured = 1;
			break;
		case 'p':
			compression = 1;
			break;
		case 'o':
			log = 1;
			break;
		case 'h':
			ha = 1;
			break;
		}
	}

	if (list)
		return bdconfig_list_disks(listconfigured, excludeconfigured);

	if (!devpath[0])
		print_usage();

	if (add)
		return bdconfig_add_disk(devpath, pool, compression, log, ha);
	else if (delete)
		return bdconfig_delete_disk(devpath);
	else
		print_usage();
	return 0;
}
