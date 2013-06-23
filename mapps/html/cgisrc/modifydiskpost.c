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
	char reply[256];
	uint32_t bid;
	char *tmp;
	struct physdisk disk;

	read_cgi_input(&entries);

	tmp = cgi_val(entries, "bid");
	if (!tmp)
		cgi_print_header_error_page("Invalid CGI parameters passed\n");

	bid = strtoul(tmp, NULL, 10);
	if (!bid)
		cgi_print_header_error_page("Invalid CGI parameters passed\n");

	memset(&disk, 0, sizeof(disk));

	tmp = cgi_val(entries, "ha_disk");
	if (tmp && (strcasecmp(tmp, "on") == 0))
		disk.ha_disk = 1;

	tmp = cgi_val(entries, "unmap");
	if (tmp && (strcasecmp(tmp, "on") == 0))
		disk.unmap = 1;

	tmp = cgi_val(entries, "write_cache");
	if (!tmp)
		cgi_print_header_error_page("Invalid CGI parameters passed\n");

	disk.write_cache = atoi(tmp);
	switch (disk.write_cache) {
	case WRITE_CACHE_DEFAULT:
	case WRITE_CACHE_FLUSH:
	case WRITE_CACHE_FUA:
		break;
	default:
		cgi_print_header_error_page("Invalid CGI parameters passed\n");
	}

	disk.bid = bid;
	retval = tl_client_set_diskconf(&disk, reply);

	if (retval != 0) {
		char errmsg[512];

		sprintf (errmsg, "Error modifying disk properties. Reply from server is \"%s\"", reply);
		cgi_print_header_error_page(errmsg);
	}

	cgi_redirect("adddisk.cgi");
	return 0;
}
