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
	int retval;
	uint32_t bid;
	char *tmp;
	struct physdisk disk;

	read_cgi_input(&entries);

	tmp = cgi_val(entries, "bid");
	if (!tmp)
		cgi_print_header_error_page("Insufficient CGI parameters\n");

	bid = atoi(tmp);
	if (!bid)
		cgi_print_header_error_page("Insufficient CGI parameters\n");

	retval = tl_client_get_diskconf(bid, &disk);
	if (retval != 0)
		cgi_print_header_error_page("Unable to get disk properties\n");

	cgi_print_header("Modify Disk Properties", NULL, 0);
	cgi_print_form_start("modifydisk", "modifydiskpost.cgi", "post", 0);
	printf ("<input type=\"hidden\" name=\"bid\" value=\"%u\">\n", bid);

	cgi_print_thdr("Modify Disk Properties");

	cgi_print_div_start("center");
	printf("<table class=\"ctable\">\n");

	printf ("<tr>\n");
	printf ("<td>HA Disk: </td>\n");
	cgi_print_checkbox_input_td("ha_disk", disk.ha_disk);
	printf ("</tr>\n");

	printf ("<tr>\n");
	printf ("<td>Unmap: </td>\n");
	cgi_print_checkbox_input_td("unmap", disk.unmap);
	printf ("</tr>\n");

	printf ("<tr>\n");
	printf ("<td>Write Cache: </td>\n");
	printf ("<td><select class=\"inputt\" name=\"write_cache\">\n");
	if (disk.write_cache == WRITE_CACHE_DEFAULT)
		printf ("<option value=\"%d\" selected>Write Cache</option>\n", WRITE_CACHE_DEFAULT);
	else
		printf ("<option value=\"%d\">Write Cache</option>\n", WRITE_CACHE_DEFAULT);
	if (disk.write_cache == WRITE_CACHE_FLUSH)
		printf ("<option value=\"%d\" selected>Write Flush FUA</option>\n", WRITE_CACHE_FLUSH);
	else
		printf ("<option value=\"%d\">Write Flush FUA</option>\n", WRITE_CACHE_FLUSH);
	if (disk.write_cache == WRITE_CACHE_FUA)
		printf ("<option value=\"%d\" selected>Write FUA</option>\n", WRITE_CACHE_FUA);
	else
		printf ("<option value=\"%d\">Write FUA</option>\n", WRITE_CACHE_FUA);
	printf ("</select></td>\n");
	printf ("</tr>\n");

	printf("</table>\n");
	cgi_print_div_end();

	cgi_print_submit_button("submit", "Submit");

	cgi_print_form_end();

	cgi_print_div_trailer();

	cgi_print_body_trailer();
	return 0;
}
