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
	int retval;
	struct d_list dlist;
	struct d_list configured_dlist;
	struct physdisk *disk;
	char alias[512];
	char databuf[64];
	char status[32];
	uint64_t dedupe_blocks = 0, total_blocks = 0;
	uint64_t uncompressed_size = 0;
	uint64_t compressed_size = 0;
	uint64_t compression_hits = 0;
	uint64_t used = 0, reserved = 0, total = 0;
	double ratio;
	char *cols[] = {"ID", "Vendor", "Model", "{ key: 'Serial', label: 'Serial Number'}", "Name", "{key: 'Pool', label: 'Pool', sortable: true}", "Size", "Used", "Status", "{ key: 'Modify', allowHTML: true }", "{ key: 'Add', label: ' ', allowHTML: true }", NULL};
	char *cols1[] = {"name", "value", NULL};


	TAILQ_INIT(&dlist);
	TAILQ_INIT(&configured_dlist);
	retval = tl_client_list_disks(&configured_dlist, MSG_ID_GET_CONFIGURED_DISKS);
	if (retval != 0) {
		__cgi_print_header("Physical Storage", NULL, 1, NULL, 10);
		cgi_print_error_page("Unable to get configured disk list\n");
	}

	retval = tl_client_list_disks(&dlist, MSG_ID_LIST_DISKS);
	if (retval != 0) {
		__cgi_print_header("Physical Storage", NULL, 1, NULL, 10);
		cgi_print_error_page("Unable to get disk list\n");
	}

	if (initializing_disks_present(&configured_dlist))
		__cgi_print_header("Physical Storage", NULL, 1, NULL, 10);
	else
		__cgi_print_header("Physical Storage", NULL, 1, NULL, 0);

	if (!TAILQ_EMPTY(&configured_dlist))
		printf("<div style=\"float: right;\"><p style=\"font-size: x-small;\"><i>D: Dedupe Disk C: Compression Enabled L: Log Disk H: HA Disk WC: Write Cache WF: Write Flush FUA WU: Write FUA</i></p></div>\n");

	cgi_print_thdr("Physical Storage");
	if (TAILQ_EMPTY(&dlist) && TAILQ_EMPTY(&configured_dlist)) {
		cgi_print_div_start("center");
		cgi_print_paragraph("None");
		cgi_print_div_end();
	}
	else {
		cgi_print_table_div("disks-table");
	}

	cgi_print_div_start("center");
	cgi_print_form_start("rescandisk", "rescandisk.cgi", "post", 0);
	cgi_print_submit_button("submit", "Rescan");
	cgi_print_form_end();
	cgi_print_div_end();

	cgi_print_thdr("Global Disk Statistics");
	cgi_print_table_div("stats-table");

	cgi_print_div_trailer();

	if (TAILQ_EMPTY(&dlist) && TAILQ_EMPTY(&configured_dlist))
		goto skip;

	cgi_print_table_start("disks-table", cols, 1);

	TAILQ_FOREACH(disk, &dlist, q_entry) {
		struct physdisk *config;

		config = disk_configured(disk, &configured_dlist);

		cgi_print_row_start();

		if (!config)
			cgi_print_column_format("ID", "N/A");
		else
			cgi_print_column_format("ID", "%u", config->bid);
		cgi_print_comma();

		cgi_print_column_format("Vendor", "%.8s", disk->info.vendor);
		cgi_print_comma();

		cgi_print_column_format("Model", "%.16s", disk->info.product);
		cgi_print_comma();

		cgi_print_column_format("Serial", "%.32s", disk->info.serialnumber);
		cgi_print_comma();

		if (disk->info.multipath)
			device_get_alias(disk->info.mdevname, alias);
		else
			device_get_alias(disk->info.devname, alias);

		cgi_print_column_format("Name", "%.32s", alias);
		cgi_print_comma();

		if (!config)
			cgi_print_column("Pool", "N/A");
		else
			cgi_print_column("Pool", config->group_name);
		cgi_print_comma();

		get_data_str(disk->size, databuf);
		cgi_print_column("Size", databuf);
		cgi_print_comma();

		if (!config) {
			cgi_print_column("Used", "N/A");
			cgi_print_comma();

			cgi_print_column("Status", "N/A");
			cgi_print_comma();

			cgi_print_column("Modify", "N/A");
			cgi_print_comma();

			cgi_print_column_format("Add", "<a href=\"adddiskcomp.cgi?dev=%s&op=1\">Add</a>", disk->info.devname);
		}
		else
		{
			if (config->initialized > 0) {
				get_data_str(config->used, databuf);
				cgi_print_column("Used", databuf);
				cgi_print_comma();

				status[0] = 0;
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

skip_wc:
				cgi_print_column("Status", status);
				cgi_print_comma();

				cgi_print_column_format("Modify", "<a href=\"modifydisk.cgi?bid=%u\">Modify</a>", config->bid);
				cgi_print_comma();

				cgi_print_column_format("Add", "<a href=\"adddiskpost.cgi?dev=%s&op=2\">Remove</a>", disk->info.devname); 
			}
			else if (config->initialized == 0) {
				cgi_print_column("Used", "Initializing");
				cgi_print_comma();

				cgi_print_column("Status", " ");
				cgi_print_comma();

				cgi_print_column("Modify", " ");
				cgi_print_comma();

				cgi_print_column("Add", " ");
			}
			else {
				cgi_print_column("Used", "Initialization failed");
				cgi_print_comma();

				cgi_print_column("Status", " ");
				cgi_print_comma();

				cgi_print_column("Modify", " ");
				cgi_print_comma();

				cgi_print_column_format("Add", "<a href=\"adddiskpost.cgi?dev=%s&op=2\">Remove</a>", disk->info.devname); 
			}

		}
		cgi_print_row_end();
	}

	TAILQ_FOREACH(disk, &configured_dlist, q_entry) {
		if (disk->info.online) {
			total_blocks  += disk->total_blocks;
			dedupe_blocks  += disk->dedupe_blocks;
			uncompressed_size  += disk->uncompressed_size;
			compressed_size  += disk->compressed_size;
			compression_hits  += disk->compression_hits;
			used += disk->used;
			total += disk->size;
			reserved += disk->reserved;
			continue;
		}

		cgi_print_row_start();
		cgi_print_column_format("ID", "%u", disk->bid); 
		cgi_print_comma();

		cgi_print_column_format("Vendor", "%.8s", disk->info.vendor);
		cgi_print_comma();

		cgi_print_column_format("Model", "%.16s", disk->info.product);
		cgi_print_comma();

		cgi_print_column_format("Serial", "%.32s", disk->info.serialnumber);
		cgi_print_comma();

		cgi_print_column("Name", "N/A");
		cgi_print_comma();

		cgi_print_column("Pool", disk->group_name);
		cgi_print_comma();

		cgi_print_column("Size", "N/A");
		cgi_print_comma();

		cgi_print_column("Used", "N/A");
		cgi_print_comma();

		cgi_print_column("Status", "offline");
		cgi_print_comma();

		cgi_print_column("Add", "&nbsp;");

		cgi_print_row_end();
	}
	cgi_print_table_end("disks-table");

skip:
	cgi_print_table_start("stats-table", cols1, 0);

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

	cgi_print_table_end("stats-table");

	cgi_print_body_trailer();

	disk_free_all(&configured_dlist);
	disk_free_all(&dlist);
	return 0;
}	

