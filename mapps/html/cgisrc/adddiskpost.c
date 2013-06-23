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
	char *dev;
	int retval;
	char reply[256];
	int op;
	int comp = 0;
	int log_disk = 0;
	int ha_disk = 0;
	uint32_t group_id;
	char *tmp;

	read_cgi_input(&entries);

	tmp = cgi_val(entries, "op");
	if (!tmp || !(op = atoi(tmp))) {
		cgi_print_header_error_page("Add/Delete Storage: Invalid operation");
		return 0;
	}

	tmp = cgi_val(entries, "comp");
	if (tmp && (strcasecmp(tmp, "on") == 0))
		comp = 1;

	tmp = cgi_val(entries, "log_disk");
	if (tmp && (strcasecmp(tmp, "on") == 0))
		log_disk = 1;

	tmp = cgi_val(entries, "ha_disk");
	if (tmp && (strcasecmp(tmp, "on") == 0))
		ha_disk = 1;

	tmp = cgi_val(entries, "group_id");
	if (tmp)
		group_id = strtoull(tmp, NULL, 10);
	else
		group_id = 0;

	dev = cgi_val(entries, "dev");
	if (!dev)
		cgi_print_header_error_page("Insufficient CGI parameters\n");

	if (op == 1)
		retval = tl_client_add_disk(dev, comp, log_disk, ha_disk, group_id, reply);
	else
		retval = tl_client_delete_disk(dev, reply);

	if (retval != 0) {
		char errmsg[512];

		sprintf (errmsg, "Reply from server is \"%s\"", reply);
		cgi_print_header_error_page(errmsg);
	}

	cgi_redirect("adddisk.cgi");
	return 0;
}
