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

char version[128];

char *
get_version(char *path)
{
	FILE *fp;
	char buf[128];
	int len;

	fp = fopen(path, "r");
	if (!fp)
		return "Unknown";

	memset(buf, 0, sizeof(buf));
	fgets(buf, sizeof(buf) - 1, fp);
	fclose(fp);
	len = strlen(buf);
	if (!len) {
		return "Unknown";
	}

	if (buf[len - 1] == '\n')
		buf[len - 1] = 0;

	strcpy(version, buf);
	return version;
}

int main()
{
	char status[256];
	char hostname[256];
	FILE *fp;
	char *cols[] = {"name", "value", NULL};

	memset(hostname, 0, sizeof(hostname));
	fp = popen("hostname", "r");
	if (fp) {
		fgets(hostname, sizeof(hostname), fp);
		hostname[strlen(hostname) - 1] = 0;
		pclose(fp);
	}

	status[0] = 0;
	tl_client_get_string(status, MSG_ID_SERVER_STATUS);

	cgi_print_header("System Information", NULL, 1);

	cgi_print_thdr("System Information");

	cgi_print_table_div("system-table");

	printf("<div style=\"text-align: center;margin-top: 4px;margin-bottom: 4px;\">\n");
	printf("<form id=\"restartservice\" action=\"restart.cgi\" method=\"post\" onSubmit=\"return confirm('Do you want to restart the service?');\">\n");
	printf("<input type=\"submit\" class=\"yui3-button\" name=\"restartsrv\" value=\"Restart Service\"/>\n");
	cgi_print_form_end();
	cgi_print_div_end();

	printf("<div style=\"text-align: center;margin-top: 4px;margin-bottom: 4px;\">\n");
	printf("<form id=\"restartssystem\" action=\"restart.cgi\" method=\"post\" onSubmit=\"return confirm('Do you want to restart the system?');\">\n");
	printf ("<input type=\"hidden\" name=\"restartsys\" value=\"1\">\n");
	printf("<input type=\"submit\" class=\"yui3-button\" name=\"restartsys\" value=\"Restart System\"/>\n");
	cgi_print_form_end();
	cgi_print_div_end();

	cgi_print_thdr("Run Diagnostics");
	cgi_print_div_start("center");
	cgi_print_paragraph("Clicking on submit would generate a tar/gzip file. <br/>Please save the file to your system and send the file to QUADStor support");
	cgi_print_form_start("rundiag", "rundiag.cgi", "post", 0);
	cgi_print_submit_button("submit", "Submit");
	cgi_print_form_end();

	cgi_print_div_end();

	cgi_print_div_trailer();

	cgi_print_table_start("system-table", cols, 0);

	cgi_print_row_start();
	cgi_print_column("name", "System Name");
	cgi_print_comma();
	cgi_print_column("value", hostname);
	cgi_print_row_end();

	cgi_print_row_start();
	cgi_print_column("name", "Core Version");
	cgi_print_comma();
	cgi_print_column("value", get_version("/quadstor/etc/quadstor-core-version"));
	cgi_print_row_end();

	cgi_print_row_start();
	cgi_print_column("name", "Itf Version");
	cgi_print_comma();
	cgi_print_column("value", get_version("/quadstor/etc/quadstor-itf-version"));
	cgi_print_row_end();

	cgi_print_row_start();
	cgi_print_column("name", "Server Status");
	cgi_print_comma();
	cgi_print_column("value", cgi_strip_newline(status));
	cgi_print_row_end();


	cgi_print_table_end("system-table");

	cgi_print_body_trailer();
	return 0;
}
