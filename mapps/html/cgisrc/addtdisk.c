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
#include <tlclntapi.h>

int main()
{
	struct group_list group_list;
	struct group_info *group_info;
	int retval;

	cgi_print_header("Add VDisk", "addtdisk.js", 0);
	retval = tl_client_list_groups(&group_list, MSG_ID_LIST_GROUP_CONFIGURED);

	if (retval != 0)
		cgi_print_error_page("Getting pool list failed\n");

	cgi_print_form_start("addvdisk", "addtdiskpost.cgi", "post", 1);

	cgi_print_thdr("Add VDisk");

	cgi_print_div_start("center");
	printf("<table class=\"ctable\">\n");

	printf ("<tr>\n");
	printf ("<td>VDisk Name:</td>\n");
	cgi_print_text_input_td("targetname", 20, "", TDISK_NAME_LEN);
	printf ("</tr>\n");

	printf ("<tr>\n");
	printf ("<td>VDisk Size (GB):</td>\n");
	cgi_print_text_input_td("targetsize", 10, "", 10);
	printf ("</tr>\n");

	printf ("<tr>\n");
	printf ("<td>512 byte Emulation:</td>\n");
//	cgi_print_checkbox_input_td("512e", 1);
	printf("<td><input type=\"checkbox\" name=\"512e\" class=\"inputt\"><i>For ESXi, XenServer, Hyper-V</i></td>");
	printf ("</tr>\n");

#if 0
	printf ("<tr>\n");
	printf ("<td colspan=2><i>Disable 512 byte emulation if not accessed by ESXi</i></td>\n");
	printf ("</tr>\n");
#endif

	printf ("<tr>\n");
	printf ("<td>Storage Pool:</td>\n");
	printf ("<td><select class=\"inputt\" name=\"group_id\">\n");
	TAILQ_FOREACH(group_info, &group_list, q_entry) {
		printf ("<option value=\"%u\">%s</option>\n", group_info->group_id, group_info->name);
	}
	printf("</select></td>\n");
	printf ("</tr>\n");

	printf("</table>\n");
	group_list_free(&group_list);

	cgi_print_submit_button("submit", "Submit");

	cgi_print_div_end();
	cgi_print_form_end();

	cgi_print_div_trailer();

	cgi_print_body_trailer();
	return 0;
}

