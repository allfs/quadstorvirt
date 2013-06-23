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

int main()
{
	llist entries;
	char *tmp;
	char reply[512];
	int retval;
	uint64_t targetsize;
	char *targetname;
	int lba_shift;
	uint32_t group_id;

	read_cgi_input(&entries);

	targetname = cgi_val(entries, "targetname");
	if (!targetname)
		cgi_print_header_error_page("Invalid CGI parameters passed\n");

	tmp = cgi_val(entries, "targetsize");
	if (!tmp)
		cgi_print_header_error_page("Invalid CGI parameters passed\n");

	targetsize = strtoull(tmp, NULL, 10);
	if (!targetsize)
		cgi_print_header_error_page("Invalid CGI parameters passed\n");

	tmp = cgi_val(entries, "512e");
	if (tmp && (strcasecmp(tmp, "on") == 0))
		lba_shift = 9;
	else
		lba_shift = 12;

	tmp = cgi_val(entries, "group_id");
	if (tmp)
		group_id = strtoull(tmp, NULL, 10);
	else
		group_id = 0;

	reply[0] = 0;
	targetsize *= (1024 * 1024 * 1024);
	if (targetsize > MAX_TARGET_SIZE)
		cgi_print_header_error_page("VDisk size exceeds maximum\n");

	retval = tl_client_add_tdisk(targetname, targetsize, lba_shift, group_id, reply);
	if (retval != 0) {
		char errmsg[1024];

		sprintf (errmsg, "Unable to add VDisk.<br/>Message from server is:<br/>\"%s\"\n", reply);
		cgi_print_header_error_page(errmsg);
	}

	cgi_redirect("listtdisk.cgi");
	return 0;
}
