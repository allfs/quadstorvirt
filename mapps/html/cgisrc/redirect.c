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
	char *title;
	char *tmp;
	char *cgiscript;
	char *msg;
	int refresh = 0;
	uint32_t target_id = 0;
	int dedupe = 0, comp = 0, verify = 0;
	char cmd[512];
	struct timeval tv;

	gettimeofday(&tv, NULL);

	read_cgi_input(&entries);

	title = cgi_val(entries, "title");
	if (!title)
		cgi_print_header_error_page("Invalid cgi parameters\n");

	tmp = cgi_val(entries, "refresh");
	if (!tmp || !(refresh = atoi(tmp)))
		cgi_print_header_error_page("Invalid cgi parameters\n");

	cgiscript = cgi_val(entries, "cgiscript");
	if (!cgiscript)
		cgi_print_header_error_page("Invalid cgi parameters\n");

	msg = cgi_val(entries, "msg");
	if (!msg)
		cgi_print_header_error_page("Invalid cgi parameters\n");

	tmp = cgi_val(entries, "target_id");
	if (tmp)
		target_id = atoi(tmp);

	if (target_id) {
		tmp = cgi_val(entries, "dedupe");
		if (tmp)
			dedupe = atoi(tmp);

		tmp = cgi_val(entries, "comp");
		if (tmp)
			comp = atoi(tmp);

		tmp = cgi_val(entries, "verify");
		if (tmp)
			verify = atoi(tmp);

		sprintf(cmd, "%s?target_id=%u&dedupe=%d&comp=%d&verify=%d&tjid=%ld.%ld", cgiscript, target_id, dedupe, comp, verify, (long)tv.tv_sec, (long)tv.tv_usec);
	}
	else
		sprintf(cmd, "%s?tjid=%ld.%ld", cgiscript, (long)tv.tv_sec, (long)tv.tv_usec);

	cgi_refresh(cmd, title, msg, refresh);
	return 0;
}
