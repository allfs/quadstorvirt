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
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <tlclntapi.h>
#include <tlsrvapi.h>
#include <sqlint.h> 
#ifdef FREEBSD
#include <libgeom.h>
#else
#include <linux/types.h>
#endif
#include <rawdefs.h>
#include <ietadm.h>

extern struct tl_blkdevinfo *bdev_list[];
extern struct d_list disk_list;
extern struct tdisk_info *tdisk_list[];
extern struct group_info *group_list[];
int testmode = 0;

#define atomic_test_bit(b, p)                                           \
({                                                                      \
        int __ret;                                                      \
        __ret = ((volatile int *)p)[b >> 5] & (1 << (b & 0x1f));        \
        __ret;                                                          \
})

struct physdisk *
locate_group_master(uint32_t group_id)
{
	struct physdisk *disk;

	TAILQ_FOREACH(disk, &disk_list, q_entry) {
		if (disk->ignore)
			continue;
		if (disk->group_id != group_id)
			continue;
		if ((!group_id && disk->ddmaster) || (atomic_test_bit(GROUP_FLAGS_MASTER, &disk->group_flags)))
			return disk;
	}
	return NULL;
}

int
read_raw_bint(struct physdisk *disk, struct raw_bdevint *raw_bint)
{
	int retval;
	char buf[4096];

	retval = read_from_device(disk->info.devname, buf, sizeof(buf), BDEV_META_OFFSET);
	if (retval < 0) {
		fprintf(stdout, "IO error while readin %s\n", disk->info.devname);
		return -1;
	}
	memcpy(raw_bint, buf, sizeof(*raw_bint));
	return 0;
}

void
scan_vdisks(void)
{
	int i, j;
	int retval, offset;
	char buf[4096];
	struct raw_index_data *raw_data;
	char msg[256];
	struct tdisk_info info;
	PGconn *conn;
	struct group_info *group_info;
	struct physdisk *disk;

	for (j = 0; j < TL_MAX_POOLS; j++) {
		group_info = group_list[j];
		if (!group_info)
			continue;
		disk = locate_group_master(group_info->group_id);
		if (!disk) {
			fprintf(stdout, "Cannot find master for pool %s. Skipping VDisk addtion\n", group_info->name);
			continue;
		}

		for (i = 0; i < TL_MAX_TDISKS; i++) {
			offset = TDISK_RESERVED_OFFSET + (i * 4096);
			retval = read_from_device(disk->info.devname, buf, sizeof(buf), offset);
			if (retval < 0) {
				fprintf(stdout, "IO error while reading %s\n", disk->info.devname);
				exit(1);
			}

			raw_data = (struct raw_index_data *)(buf);
			if (memcmp(raw_data->magic, DISK_INDEX_MAGIC, strlen(DISK_INDEX_MAGIC)))
				continue;

			if (target_name_exists((char *)(raw_data->name)))
				continue;

			if (!disk->mrid[0]) {
				sprintf(msg, "Add VDisk with name %s ? ", raw_data->name);
				retval = tl_client_prompt_user(msg);
				if (retval != 1)
					continue;
			}

			fprintf(stdout, "Adding VDisk %s\n", raw_data->name);
			if (testmode)
				continue;

			memset(&info, 0, sizeof(info));
			strcpy(info.name, (char *)(raw_data->name));
			info.size = raw_data->size;
			info.lba_shift = raw_data->lba_shift;
			info.target_id = raw_data->target_id;
			info.group_id = raw_data->group_id;
			SET_BLOCK(info.block, 0, disk->bid);
			info.enable_deduplication = 1;
			conn = pgsql_begin();
			if (!conn) {
				fprintf(stdout, "Unable to connect to db\n");
				exit(1);
			}

			retval = sql_add_tdisk(conn, &info);
			if (retval != 0) {
				fprintf(stdout, "Failed to add VDisk to db\n");
				exit(1);
			}

			retval = ietadm_default_settings(conn, &info, NULL);
			if (retval != 0) {
				fprintf(stdout, "Unable to set default iscsi settings\n");
				exit(1);
			}

			retval = pgsql_commit(conn);
			if (retval != 0) {
				fprintf(stdout, "Failed to commit transaction\n");
				exit(1);
			}
		}
	}
}

static struct group_info *
add_group(struct raw_bdevint *raw_bint, int testmode)
{
	struct group_info *group_info;
	PGconn *conn;
	int retval;

	group_info = alloc_buffer(sizeof(*group_info));
	if (!group_info)
		return NULL;

	conn = pgsql_begin();
	if (!conn) {
		free(group_info);
		return NULL;
	}
	group_info->dedupemeta = atomic_test_bit(GROUP_FLAGS_DEDUPEMETA, &raw_bint->group_flags) ? 1 : 0;
	group_info->logdata = atomic_test_bit(GROUP_FLAGS_LOGDATA, &raw_bint->group_flags) ? 1 : 0;
	strcpy(group_info->name, raw_bint->group_name);
	group_info->group_id = raw_bint->group_id;
	TAILQ_INIT(&group_info->bdev_list);

	fprintf(stdout, "Adding pool %s pool id %u dedupemeta %d logdata %d\n", group_info->name, group_info->group_id, group_info->dedupemeta, group_info->logdata);
	if (testmode) {
		group_list[group_info->group_id] = group_info;
		return group_info;
	}

	retval = sql_add_group(conn, group_info);
	if (retval != 0) {
		pgsql_rollback(conn);
		free(group_info);
		return NULL;
	}

	retval = pgsql_commit(conn);
	if (retval != 0) {
		free(group_info);
		return NULL;
	}

	group_list[group_info->group_id] = group_info;
	return group_info;
}

static int
__srv_disk_configured(struct physdisk *disk)
{
	struct physdisk *cur_disk;
	int configured = 0, j;
	struct tl_blkdevinfo *blkdev;

	for (j = 1; j < TL_MAX_DISKS; j++) {
		blkdev = bdev_list[j];
		if (!blkdev)
			continue;
		cur_disk = &blkdev->disk;

		if (device_equal(&cur_disk->info, &disk->info) == 0) {
			configured = 1;
			break;
		}
	}
	return configured;
}

int
main(int argc, char *argv[])
{
	struct physdisk *disk, *master_disk;
	struct raw_bdevint raw_bint;
	PGconn *conn;
	int retval, fd;
	char msg[256];
	struct group_info *group_info;
	struct tl_blkdevinfo *blkdev;
	int c;

	if (geteuid() != 0) {
		fprintf(stdout, "This program can only be run as root\n");
		exit(1);
	}

	while ((c = getopt(argc, argv, "t")) != -1) {
		switch (c) {
		case 't':
			testmode = 1;
			break;
		default:
			fprintf(stdout, "Invalid option passed\n");
			exit(1);
		}
	}

	fd = open("/dev/null", O_WRONLY);
	if (fd >= 0)
		dup2(fd, 2);

	retval = sql_query_groups(group_list);
	if (retval != 0) {
		fprintf(stdout, "Error in getting configured pools\n");
		exit(1);
	}

	group_info = alloc_buffer(sizeof(*group_info));
	if (!group_info) {
		fprintf(stdout, "Memory allocation failure\n");
		exit(1);
	}

	group_info->group_id = 0;
	strcpy(group_info->name, DEFAULT_GROUP_NAME);
	group_info->dedupemeta = 1;
	group_info->logdata = 1;
	TAILQ_INIT(&group_info->bdev_list);
	TAILQ_INIT(&group_info->tdisk_list);
	group_list[0] = group_info;

	tl_common_scan_physdisk();
	retval = sql_query_blkdevs(bdev_list);
	if (retval != 0) {
		fprintf(stdout, "Error in getting configured disks\n");
		exit(1);
	}

	retval = sql_query_tdisks(tdisk_list);
	if (retval != 0) {
		fprintf(stdout, "Error in getting configured VDisks\n");
		exit(1);
	}

	TAILQ_FOREACH(disk, &disk_list, q_entry) {
		if (disk->ignore)
			continue;

		retval = read_raw_bint(disk, &raw_bint);
		if (retval != 0) {
			fprintf(stdout, "Failed to read properties for %s\n", disk->info.devname);
			continue;
		}

		if (memcmp(raw_bint.magic, "QUADSTOR", strlen("QUADSTOR")))
			continue;

		if (!memcmp(((uint8_t *)(&raw_bint))+0x72, "VTL", strlen("VTL")))
			continue;

		if ((!raw_bint.group_id && !raw_bint.ddmaster) || (raw_bint.group_id && !atomic_test_bit(GROUP_FLAGS_MASTER, &raw_bint.group_flags)))
			continue;

		group_info = find_group(raw_bint.group_id);
		if (!group_info) {
			group_info = add_group(&raw_bint, testmode);
			if (!group_info) {
				fprintf(stdout, "Adding back pool %s failed\n", raw_bint.group_name);
				exit(1);
			}
		}

		disk->ddmaster = raw_bint.ddmaster;
		disk->group_flags = raw_bint.group_flags;
		disk->group_id = raw_bint.group_id;
		disk->bid = raw_bint.bid;
		memcpy(disk->mrid, raw_bint.mrid, TL_RID_MAX);

		if (__srv_disk_configured(disk)) {
			continue;
		}

		if (memcmp(raw_bint.vendor, disk->info.vendor, 8)) {
			fprintf(stdout, "Vendor mismatch %.8s %.8s\n", raw_bint.vendor, disk->info.vendor);
			continue;
		}

		if (memcmp(raw_bint.product, disk->info.product, 16)) {
			fprintf(stdout, "Product mismatch %.16s %.16s\n", raw_bint.product, disk->info.product);
			continue;
		}

		if (!raw_bint_serial_match(&raw_bint, disk->info.serialnumber, disk->info.serial_len)) {
			fprintf(stdout, "Serial number mismatch %.32s %.32s\n", raw_bint.serialnumber, disk->info.serialnumber);
			continue;
		}

		if (raw_bint.flags & RID_SET) {
			fprintf(stdout, "Adding Master Physical Disk  %s Vendor: %.8s Model: %.16s Serial Number: %.32s\n", disk->info.devname, disk->info.vendor, disk->info.product, disk->info.serialnumber);
		}
		else {
			fprintf(stdout, "Vendor: %.8s\n", disk->info.vendor);
			fprintf(stdout, "Model: %.16s\n", disk->info.product);
			fprintf(stdout, "Serial Number: %.32s\n", disk->info.serialnumber);
			sprintf(msg, "Add Master Physical Disk with path %s ? ", disk->info.devname);
			retval = tl_client_prompt_user(msg);
			if (retval != 1) {
				disk->ignore = 1;
				continue;
			}
		}

		if (testmode) {
			continue;
		}

		conn = sql_add_blkdev(disk, raw_bint.bid, raw_bint.group_id);
		if (!conn) {
			fprintf(stdout, "Failed to update disk information for %s", disk->info.devname);
			exit(1);
		}

		retval = pgsql_commit(conn);
		if (retval != 0) {
			fprintf(stdout, "Failed to commit transaction %s", disk->info.devname);
			exit(1);
		}

		blkdev = alloc_buffer(sizeof(*blkdev));
		if (!blkdev) {
			fprintf(stdout, "Memory allocation failure\n");
			exit(1);
		}
		memcpy(&blkdev->disk, disk, sizeof(*disk));
		bdev_list[blkdev->bid] = blkdev;

	}

	TAILQ_FOREACH(disk, &disk_list, q_entry) {
		if (__srv_disk_configured(disk)) {
			continue;
		}

		retval = read_raw_bint(disk, &raw_bint);
		if (retval != 0) {
			fprintf(stdout, "Failed to read properties for %s\n", disk->info.devname);
			continue;
		}

		group_info = find_group(raw_bint.group_id);
		if (!group_info) {
			fprintf(stdout, "Cannot find pool %s. Skipping disk %s\n", raw_bint.group_name, disk->info.devname);
			continue;
		}

		if ((!raw_bint.group_id && raw_bint.ddmaster) || atomic_test_bit(GROUP_FLAGS_MASTER, &raw_bint.group_flags))
			continue;

		if (memcmp(raw_bint.magic, "QUADSTOR", strlen("QUADSTOR")))
			continue;

		if (memcmp(raw_bint.vendor, disk->info.vendor, 8)) {
			fprintf(stdout, "Vendor mismatch %.8s %.8s\n", raw_bint.vendor, disk->info.vendor);
			continue;
		}

		if (memcmp(raw_bint.product, disk->info.product, 16)) {
			fprintf(stdout, "Product mismatch %.16s %.16s\n", raw_bint.product, disk->info.product);
			continue;
		}

		if (memcmp(raw_bint.serialnumber, disk->info.serialnumber, disk->info.serial_len)) {
			fprintf(stdout, "Serial number mismatch %.32s %.32s\n", raw_bint.serialnumber, disk->info.serialnumber);
			continue;
		}

		master_disk = locate_group_master(raw_bint.group_id);
		if (!master_disk) {
			fprintf(stdout, "Cannot find master for pool %s. Skipping disk %s\n", raw_bint.group_name, disk->info.devname);
			continue;
		}

		if (!(raw_bint.flags & RID_SET) || !master_disk->mrid[0] || memcmp(master_disk->mrid, raw_bint.mrid, sizeof(disk->mrid))) {
			fprintf(stdout, "Vendor: %.8s\n", disk->info.vendor);
			fprintf(stdout, "Model: %.16s\n", disk->info.product);
			fprintf(stdout, "Serial Number: %.32s\n", disk->info.serialnumber);
			sprintf(msg, "Add Physical Disk with path %s ? ", disk->info.devname);
			retval = tl_client_prompt_user(msg);
			if (retval != 1) {
				disk->ignore = 1;
				continue;
			}
		}
		else {
			fprintf(stdout, "Adding Physical Disk  %s Vendor: %.8s Model: %.16s Serial Number: %.32s\n", disk->info.devname, disk->info.vendor, disk->info.product, disk->info.serialnumber);
		}

		if (testmode)
			continue;
		conn = sql_add_blkdev(disk, raw_bint.bid, raw_bint.group_id);
		if (!conn) {
			fprintf(stdout, "Failed to update disk information for %s", disk->info.devname);
			exit(1);
		}

		retval = pgsql_commit(conn);
		if (retval != 0) {
			fprintf(stdout, "Failed to commit transaction %s", disk->info.devname);
			exit(1);
		}
	}

	scan_vdisks();
	return 0;
}
