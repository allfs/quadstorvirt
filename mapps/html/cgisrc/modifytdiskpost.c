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
	char *tmp, *name;
	struct vdiskconf vdiskconf;
	uint32_t target_id;
	int dedupe, comp, verify, retval, threshold;
	uint64_t size = 0;
	char reply[512];
	char *endptr = NULL;

	read_cgi_input(&entries);

	tmp = cgi_val(entries, "target_id");
	if (!tmp)
		cgi_print_header_error_page("Invalid CGI parameters passed\n");

	target_id = strtoul(tmp, NULL, 10);
	if (!target_id)
		cgi_print_header_error_page("Invalid CGI parameters passed\n");

	tmp = cgi_val(entries, "resetstats");
	if (tmp) {
		tl_client_tdisk_stats_reset(target_id);
		sprintf(reply, "viewtdisk.cgi?target_id=%u", target_id);
		cgi_redirect(reply);
		return 0;
	}

	tmp = cgi_val(entries, "targetsize");
	if (!tmp)
		cgi_print_header_error_page("Invalid CGI parameters passed\n");

	size = strtoull(tmp, NULL, 10);
	if (endptr)
		cgi_print_header_error_page("Invalid CGI parameters passed\n");

	tmp = cgi_val(entries, "dedupe");
	if (tmp && (strcasecmp(tmp, "on") == 0))
		dedupe = 1;
	else
		dedupe = 0;

	tmp = cgi_val(entries, "comp");
	if (tmp && (strcasecmp(tmp, "on") == 0))
		comp = 1;
	else
		comp = 0;

	tmp = cgi_val(entries, "verify");
	if (tmp && (strcasecmp(tmp, "on") == 0))
		verify = 1;
	else
		verify = 0;

	if (!dedupe) {
		verify = 0;
	}

	name = cgi_val(entries, "targetname");

	tmp = cgi_val(entries, "threshold");
	if (tmp)
		threshold = atoi(tmp);
	else
		threshold = 0;

	if (threshold < 0 || threshold >= 100)
		cgi_print_header_error_page("Invalid CGI parameters passed\n");

	memset(&vdiskconf, 0, sizeof(vdiskconf));
	vdiskconf.target_id = target_id;
	vdiskconf.enable_deduplication = dedupe;
	vdiskconf.enable_compression = comp;
	vdiskconf.enable_verify = verify;
	vdiskconf.threshold = threshold;

	if (name && strlen(name) <= TDISK_NAME_LEN)
		strcpy(vdiskconf.name, name);
	if (size)
		vdiskconf.size = (size << 30);

	retval = tl_client_set_vdiskconf(&vdiskconf, reply);
	if (retval != 0) {
		char errmsg[1024];

		sprintf (errmsg, "Unable to modify VDisk.<br/>Message from server is:<br/>\"%s\"\n", reply);
		cgi_print_header_error_page(errmsg);
	}

	cgi_redirect("listtdisk.cgi");
	return 0;
}
