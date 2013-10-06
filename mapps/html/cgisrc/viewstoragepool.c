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

#include "cgimain.h"

static int
initializing_disks_present(struct d_list *configured_dlist)
{
	struct physdisk *disk;

	TAILQ_FOREACH(disk, configured_dlist, q_entry) {
		if (disk->initialized == 0)
			return 1;
	}
	return 0;
}

int main()
{
	llist entries;
	char tempfile[40];
	char alias[512];
	int fd;
	int retval;
	FILE *fp;
	struct d_list configured_dlist;
#if 0
	struct tdisk_list tdisk_list;
	struct tdisk_info *tdisk_info;
#endif
	struct physdisk *disk;
	char databuf[64];
	char status[512];
	char *name;
	uint32_t group_id;
	uint64_t dedupe_blocks = 0, total_blocks = 0;
	uint64_t uncompressed_size = 0;
	uint64_t compressed_size = 0;
	uint64_t compression_hits = 0;
	uint64_t used = 0, reserved = 0, total = 0;
	double ratio;
	char *tmp;
	char *cols[] = {"ID", "Vendor", "Model", "{ key: 'Serial', label: 'Serial Number'}", "Name", "Size", "Used", "Status", NULL};
	char *cols1[] = {"name", "value", NULL};
#if 0
	char *cols2[] = {"Name", "{ key: 'Serial', label: 'Serial Number'}", "Size", "Status", "{ key: 'Modify', allowHTML: true }", "{ key: 'Statistics', allowHTML: true }", "{ key: 'Delete', allowHTML: true }", NULL};
#endif

	read_cgi_input(&entries);

	tmp = cgi_val(entries, "group_id");
	if (!tmp) {
		__cgi_print_header("Storage Pools", NULL, 1, NULL, 10);
		cgi_print_error_page("Invalid CGI parameters passed\n");
	}

	name = cgi_val(entries, "name");
	if (!name) {
		__cgi_print_header("Storage Pools", NULL, 1, NULL, 10);
		cgi_print_error_page("Invalid CGI parameters passed\n");
	}

	group_id = atoi(tmp);

	strcpy(tempfile, MKSTEMP_PREFIX);
	fd = mkstemp(tempfile);
	if (fd == -1) {
		__cgi_print_header("Storage Pools", NULL, 1, NULL, 10);
		cgi_print_error_page("Internal processing error\n");
	}

	retval = tl_client_list_target_generic(group_id, tempfile, MSG_ID_GET_POOL_CONFIGURED_DISKS);
	if (retval != 0) {
		struct timeval tv;
		gettimeofday(&tv, NULL);

		__cgi_print_header("Storage Pools", NULL, 1, NULL, 10);
		remove(tempfile);
		cgi_print_error_page("Getting configured storage list failed\n");
	}

	fp = fopen(tempfile, "r");
	if (!fp) {
		remove(tempfile);
		__cgi_print_header("Storage Pools", NULL, 1, NULL, 10);
		cgi_print_error_page("Internal processing error\n");
	}

	TAILQ_INIT(&configured_dlist);
	retval = tl_common_parse_physdisk(fp, &configured_dlist);
	fclose(fp);
	if (retval != 0) {
		remove(tempfile);
		__cgi_print_header("Storage Pools", NULL, 1, NULL, 10);
		cgi_print_error_page("Unable to get configured disk list\n");
	}
#if 0
	retval = tl_client_list_target_generic(group_id, tempfile, MSG_ID_LIST_POOL_TDISK);
	if (retval != 0) {
		remove(tempfile);
		__cgi_print_header("Storage Pools", NULL, 1, NULL, 10);
		cgi_print_error_page("Getting VDisk list failed\n");
	}

	fp = fopen(tempfile, "r");
	if (!fp) {
		remove(tempfile);
		__cgi_print_header("Storage Pools", NULL, 1, NULL, 10);
		cgi_print_error_page("Internal processing error\n");
	}

	TAILQ_INIT(&tdisk_list);
	retval = tl_common_parse_tdisk(fp, &tdisk_list);

	fclose(fp);
#endif
	close(fd);
	remove(tempfile);

	if (retval != 0) {
		__cgi_print_header("Storage Pools", NULL, 1, NULL, 10);
		cgi_print_error_page("Unable to get VDisk list\n");
	}

	if (initializing_disks_present(&configured_dlist))
		__cgi_print_header("Storage Pools", "modifystoragepool.js", 1, NULL, 10);
	else
		__cgi_print_header("Storage Pools", "modifystoragepool.js", 1, NULL, 0);

	if (!group_id)
		goto skip_rename;

	cgi_print_form_start("modifystoragepool", "modifystoragepool.cgi", "post", 1);
	printf ("<input type=\"hidden\" name=\"group_id\" value=\"%u\">\n", group_id);
	cgi_print_thdr("Rename Pool");
	cgi_print_div_start("center");
	printf("<table class=\"ctable\">\n");
	printf ("<tr>\n");
	printf ("<td>Pool Name:</td>\n");
	printf ("<td>");
	cgi_print_text_input("groupname", 15, name, GROUP_NAME_LEN);
	printf ("</td>\n");
	printf ("</tr>\n");
	printf("</table>\n");
	cgi_print_submit_button("submit", "Submit");
	cgi_print_div_end();
	cgi_print_form_end();

skip_rename:
	if (!TAILQ_EMPTY(&configured_dlist))
		printf("<div style=\"float: right;\"><p style=\"font-size: x-small;\"><i>D: Dedupe Disk C: Compression Enabled L: Log Disk H: HA Disk</i></p></div>\n");

	cgi_print_thdr("Configured Disks");
	if (TAILQ_EMPTY(&configured_dlist)) {
		cgi_print_div_start("center");
		cgi_print_paragraph("None");
		cgi_print_div_end();
	}
	else {
		cgi_print_table_div("pool-disks-table");
	}

	cgi_print_thdr("Pool Disk Statistics");
	cgi_print_table_div("pool-stats-table");

#if 0
	if (!TAILQ_EMPTY(&tdisk_list))
		printf("<div style=\"float: right;\"><p style=\"font-size: x-small;\"><i>D: Deduplication Enabled E: 512 byte emulation C: Compression Enabled V: Verify Enabled</i></p></div>\n");
	cgi_print_thdr("Configured VDisks");

	if (TAILQ_EMPTY(&tdisk_list)) {
		cgi_print_div_start("center");
		cgi_print_paragraph("None");
		cgi_print_div_end();
	}
	else {
		cgi_print_table_div("pool-vdisks-table");
	}
#endif

	cgi_print_div_trailer();

	if (TAILQ_EMPTY(&configured_dlist))
		goto skip;

	cgi_print_table_start("pool-disks-table", cols, 1);

	TAILQ_FOREACH(disk, &configured_dlist, q_entry) {
		cgi_print_row_start();
		cgi_print_column_format("ID", "%u", disk->bid); 
		cgi_print_comma();

		cgi_print_column_format("Vendor", "%.8s", disk->info.vendor);
		cgi_print_comma();

		cgi_print_column_format("Model", "%.16s", disk->info.product);
		cgi_print_comma();

		sprintf(databuf, "Serial: '%%.%ds'", disk->info.serial_len);
		printf(databuf, disk->info.serialnumber);
		cgi_print_comma();

		if (disk->info.multipath)
			device_get_alias(disk->info.mdevname, alias);
		else
			device_get_alias(disk->info.devname, alias);

		cgi_print_column_format("Name", "%.32s", alias);
		cgi_print_comma();

		if (disk->info.online) {
			total_blocks  += disk->total_blocks;
			dedupe_blocks  += disk->dedupe_blocks;
			uncompressed_size  += disk->uncompressed_size;
			compressed_size  += disk->compressed_size;
			compression_hits  += disk->compression_hits;
			total += disk->size;
			used += disk->used;
			reserved += disk->reserved;

			get_data_str(disk->size, databuf);
			cgi_print_column("Size", databuf);
			cgi_print_comma();

			get_data_str(disk->used, databuf);
			cgi_print_column("Used", databuf);
			cgi_print_comma();

			status[0] = 0;
			if (disk->ddmaster)
				strcat(status, "D");
			if (disk->log_disk) {
				if (strlen(status) > 0)
					strcat(status, " ");
				strcat(status, "L");
			}
			if (disk->ha_disk) {
				if (strlen(status) > 0)
					strcat(status, " ");
				strcat(status, "H");
			}
			if (disk->enable_comp) {
				if (strlen(status) > 0)
					strcat(status, " ");
				strcat(status, "C");
			}

			cgi_print_column("Status", status);
			cgi_print_comma();
		}
		else {
			cgi_print_column("Used", "N/A");
			cgi_print_comma();

			cgi_print_column("Status", "offline");
			cgi_print_comma();
		}


		cgi_print_row_end();
	}
	cgi_print_table_end("pool-disks-table");

#if 0
	if (TAILQ_EMPTY(&tdisk_list))
		goto skip;

	cgi_print_table_start("pool-vdisks-table", cols2, 1);

	TAILQ_FOREACH(tdisk_info, &tdisk_list, q_entry) {
		if (tdisk_info->disabled)
			continue;

		cgi_print_row_start();

#if 0
		cgi_print_column_format("ID", "%u", tdisk_info->target_id);
		cgi_print_comma();
#endif

		cgi_print_column("Name", tdisk_info->name);
		cgi_print_comma();

		cgi_print_column("Serial", tdisk_info->serialnumber);
		cgi_print_comma();

		get_data_str_int(tdisk_info->size, databuf);
		cgi_print_column("Size", databuf);
		cgi_print_comma();

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

#if 0
		if (tdisk_info->force_inline) {
			if (strlen(status) > 0)
				strcat(status, " ");
			strcat(status, "I");
		}
#endif

		if (tdisk_info->lba_shift == 9) {
			if (strlen(status) > 0)
				strcat(status, " ");
			strcat(status, "E");
		}

		if (tdisk_info->disabled)
			cgi_print_column("Status", "Disabled");
		else if (!tdisk_info->online)
			cgi_print_column("Status", "Offline");
		else
			cgi_print_column("Status", status);
		cgi_print_comma();

		cgi_print_column_format("Modify", "<a href=\"modifytdisk.cgi?target_id=%u&dedupe=%d&comp=%d&verify=%d&inline=%d\">Modify</a>", tdisk_info->target_id, tdisk_info->enable_deduplication, tdisk_info->enable_compression, tdisk_info->enable_verify, tdisk_info->force_inline);
		cgi_print_comma();

		cgi_print_column_format("Statistics", "<a href=\"viewtdisk.cgi?target_id=%u\">View</a>", tdisk_info->target_id);
		cgi_print_comma();

		cgi_print_column_format("Delete", "<a href=\"deletetdisk.cgi?target_id=%u\"  onclick=\\'return confirm(\\\"Delete VDisk %s?\\\");\\'><img src=\"/quadstor/delete.png\" width=16px height=16px border=0></a>", tdisk_info->target_id, tdisk_info->name);
		cgi_print_comma();

		cgi_print_row_end();
	}

	cgi_print_table_end("pool-vdisks-table");
#endif
skip:
	cgi_print_table_start("pool-stats-table", cols1, 0);

	cgi_print_row_start();
	cgi_print_column("name", "Total Size:");
	cgi_print_comma();
	get_data_str(total, databuf);
	cgi_print_column("value", databuf);
	cgi_print_row_end();

	cgi_print_row_start();
	cgi_print_column("name", "Used Size:");
	cgi_print_comma();
	get_data_str(used, databuf);
	cgi_print_column("value", databuf);
	cgi_print_row_end();

	cgi_print_row_start();
	cgi_print_column("name", "VDisk Usage:");
	cgi_print_comma();
	get_data_str((uncompressed_size + compression_hits + (dedupe_blocks << 12)), databuf);
	cgi_print_column("value", databuf);
	cgi_print_row_end();

	cgi_print_row_start();
	cgi_print_column("name", "Deduped Size:");
	cgi_print_comma();
	get_data_str(dedupe_blocks << 12, databuf);
	cgi_print_column("value", databuf);
	cgi_print_row_end();


	cgi_print_row_start();
	cgi_print_column("name", "Uncompressed Size:");
	cgi_print_comma();
	get_data_str(uncompressed_size, databuf);
	cgi_print_column("value", databuf);
	cgi_print_row_end();

	cgi_print_row_start();
	cgi_print_column("name", "Compressed Size:");
	cgi_print_comma();
	get_data_str(compressed_size, databuf);
	cgi_print_column("value", databuf);
	cgi_print_row_end();

	cgi_print_row_start();
	cgi_print_column("name", "Compression Hits:");
	cgi_print_comma();
	get_data_str(compression_hits, databuf);
	cgi_print_column("value", databuf);
	cgi_print_row_end();

	cgi_print_row_start();
	cgi_print_column("name", "Dedupe Ratio:");
	cgi_print_comma();
	if (uncompressed_size + compressed_size)
		ratio = (double)(uncompressed_size + compression_hits + (dedupe_blocks << 12))/(double)((uncompressed_size + compressed_size));
	else
		ratio = 0;
	cgi_print_column_format("value", "%.3f", ratio);
	cgi_print_row_end();

	cgi_print_table_end("pool-stats-table");

	cgi_print_body_trailer();

	disk_free_all(&configured_dlist);
	return 0;
}	

