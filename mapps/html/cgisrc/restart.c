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
	int restartsys = 0, retval;

	read_cgi_input(&entries);
	tmp = cgi_val(entries, "restartsys");
	if (tmp)
		restartsys = 1;

	if (restartsys) {
		retval = tl_client_reboot_system(MSG_ID_REBOOT_SYSTEM);
		if (retval != 0)
			cgi_print_header_error_page("Restarting system failed\n");
		cgi_refresh("system.cgi", "Restart system", "Done restarting system.", 240);
	}
	else {
		retval = tl_client_reboot_system(MSG_ID_RESTART_SERVICE);
		if (retval != 0)
			cgi_print_header_error_page("Restarting service failed\n");
		cgi_refresh("system.cgi", "Restart service", "Done restarting service.", 120);
	}

	return 0;
}
