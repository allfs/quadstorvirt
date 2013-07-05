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

#include <html-lib.h>
#include "cgimain.h"

static int
deleting_vdisks_present(struct tdisk_list *tdisk_list)
{
	struct tdisk_info *tdisk_info;

	TAILQ_FOREACH(tdisk_info, tdisk_list, q_entry) {
		/* Include offline also */
		if (!tdisk_info->online || tdisk_info->disabled == VDISK_DELETING)
			return 1;
	}
	return 0;
}

int main()
{
	char databuf[64];
	int retval;
	struct tdisk_list tdisk_list;
	struct tdisk_info *tdisk_info;
	char status[512];
	char *cols[] = {"{ key: 'Name', sortable: true}", "{ key: 'Pool', sortable: true}", "{ key: 'Serial', label: 'Serial Number'}", "Size", "Status", "{ key: 'Modify', allowHTML: true }", "{ key: 'Statistics', allowHTML: true }", "{ key: 'Delete', label: ' ', allowHTML: true }", NULL};


	retval = tl_client_list_vdisks(&tdisk_list, MSG_ID_LIST_TDISK);
	if (retval != 0) {
		cgi_print_header("Virtual Disks", NULL, 1);
		cgi_print_error_page("Getting VDisk list failed\n");
	}

	if (deleting_vdisks_present(&tdisk_list))
		__cgi_print_header("Virtual Disks", NULL, 1, NULL, 10);
	else
		cgi_print_header("Virtual Disks", NULL, 1);

	if (!TAILQ_EMPTY(&tdisk_list))
		printf("<div style=\"float: right;\"><p style=\"font-size: x-small;\"><i>D: Deduplication Enabled E: 512 byte emulation C: Compression Enabled V: Verify Enabled</i></p></div>\n");
	cgi_print_thdr("Configured VDisks");

	if (TAILQ_EMPTY(&tdisk_list)) {
		cgi_print_div_start("center");
		cgi_print_paragraph("None");
		cgi_print_div_end();
	}
	else {
		cgi_print_table_div("vdisks-table");
	}

	cgi_print_div_start("center");
	cgi_print_form_start("addtdisk", "addtdisk.cgi", "post", 0);
	cgi_print_submit_button("submit", "Add VDisk");
	cgi_print_form_end();
	cgi_print_div_end();

	cgi_print_div_trailer();

	if (TAILQ_EMPTY(&tdisk_list))
		goto skip;

	cgi_print_table_start("vdisks-table", cols, 1);

	TAILQ_FOREACH(tdisk_info, &tdisk_list, q_entry) {
		if (tdisk_info->disabled == VDISK_DELETED)
			continue;

		cgi_print_row_start();

#if 0
		cgi_print_column_format("ID", "%u", tdisk_info->target_id);
		cgi_print_comma();
#endif

		cgi_print_column("Name", tdisk_info->name);
		cgi_print_comma();

		cgi_print_column("Pool", tdisk_info->group_name);
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

		if (tdisk_info->disabled == VDISK_DELETED)
			cgi_print_column("Status", "Disabled");
		else if (tdisk_info->disabled == VDISK_DELETING && tdisk_info->delete_error == -1)
			cgi_print_column("Status", "Delete error");
		else if (tdisk_info->disabled == VDISK_DELETING && tdisk_info->delete_error)
			cgi_print_column("Status", "Delete stopped");
		else if (tdisk_info->disabled == VDISK_DELETING)
			cgi_print_column("Status", "Deletion in progress");
		else if (!tdisk_info->online)
			cgi_print_column("Status", "Offline");
		else
			cgi_print_column("Status", status);
		cgi_print_comma();

		cgi_print_column_format("Modify", "<a href=\"modifytdisk.cgi?target_id=%u\">Modify</a>", tdisk_info->target_id);
		cgi_print_comma();

		cgi_print_column_format("Statistics", "<a href=\"viewtdisk.cgi?target_id=%u\">View</a>", tdisk_info->target_id);
		cgi_print_comma();

		if (tdisk_info->online && !tdisk_info->disabled)
			cgi_print_column_format("Delete", "<a href=\"deletetdisk.cgi?target_id=%u\"  onclick=\\'return confirm(\\\"Delete VDisk %s?\\\");\\'><img src=\"/quadstor/delete.png\" width=16px height=16px border=0></a>", tdisk_info->target_id, tdisk_info->name);
		else
			cgi_print_column("Delete", "");
		cgi_print_comma();

		cgi_print_row_end();
	}

	cgi_print_table_end("vdisks-table");

skip:
	cgi_print_body_trailer();

	tdisk_list_free(&tdisk_list);

	return 0;
}
