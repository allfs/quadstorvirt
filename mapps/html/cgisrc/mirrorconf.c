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
	uint32_t target_id;
	int retval;
	int op;
	char *tmp;
	char cmd[256];
	char *dest, *dest_host, *pool;
	struct mirror_spec mirror_spec;
	char reply[512];
	char errmsg[512];

	read_cgi_input(&entries);

	tmp = cgi_val(entries, "target_id");
	if (!tmp)
		cgi_print_header_error_page("Invalid CGI Parameters\n");

	target_id = strtoul(tmp, NULL, 10);
	if (!target_id)
		cgi_print_header_error_page("Invalid CGI Parameters\n");

	tmp = cgi_val(entries, "op");
	if (!tmp)
		cgi_print_header_error_page("Invalid CGI Parameters\n");

	op = atoi(tmp);
	if (!op)
		cgi_print_header_error_page("Invalid CGI Parameters\n");

	memset(&mirror_spec, 0, sizeof(mirror_spec));

	mirror_spec.src_target_id = target_id;
	if (op == 2) {
		retval = tl_client_mirror_op(&mirror_spec, reply, MSG_ID_REMOVE_MIRROR);
		if (retval != 0)
			cgi_print_header_error_page("Removing mirroring configuration failed");
		sprintf(cmd, "redirect.cgi?cgiscript=modifytdisk.cgi&target_id=%u&title=%s&refresh=1&msg=%s", target_id, "Update Mirror Configuration", "Done updating mirroring configuration");
		cgi_redirect(cmd);
		return 0;
	}

	dest = cgi_val(entries, "dest");
	if (!dest)
		cgi_print_header_error_page("Invalid CGI parameters passed\n");

	pool = cgi_val(entries, "pool");
	if (!pool)
		pool = "";

	dest_host = cgi_val(entries, "dest_host");
	if (!dest_host)
		cgi_print_header_error_page("Invalid CGI parameters passed\n");

	if (!ipaddr_valid(dest_host))
		cgi_print_header_error_page("Invalid Mirror IP Address passed\n");

#if 0
	src_host = cgi_val(entries, "src_host");
	if (!src_host)
		cgi_print_header_error_page("Invalid CGI parameters passed\n");

	if (!ipaddr_valid(src_host))
		cgi_print_header_error_page("Invalid Source IP Address passed\n");
#endif

	strcpy(mirror_spec.dest_tdisk, dest);
#if 0
	strcpy(mirror_spec.src_host, src_host);
#endif
	strcpy(mirror_spec.dest_host, dest_host);
	strcpy(mirror_spec.dest_group, pool);
	mirror_spec.attach = 1;

	retval = tl_client_mirror_op(&mirror_spec, reply, MSG_ID_START_MIRROR);
	if (retval != 0) {
		sprintf(errmsg, "Setting mirroring configuration failed</br>Message from server is:<br/>\"%s\"\n", reply);
		cgi_print_header_error_page(errmsg);
	}

	sprintf(cmd, "redirect.cgi?cgiscript=modifytdisk.cgi&target_id=%u&title=%s&refresh=1&msg=%s", target_id, "Update Mirror Configuration", "Done updating mirroring configuration");
	cgi_redirect(cmd);
	return 0;
}

