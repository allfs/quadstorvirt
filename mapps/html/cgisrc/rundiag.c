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

static int
mdaemon_run_diagnostics()
{
	char tempfile[100];
	char diagfile[100];
	char tarfile[100];
	FILE *fp;
	char cmd[256];
	char buf[512];
	int retval;
	char *tmp;
	struct stat stbuf;

	strcpy(tempfile, "/tmp/quadstorrndag.XXXXXX");

	tmp = mkdtemp(tempfile);
	if (!tmp)
		cgi_print_header_error_page("Unable to run diagnostics. Internal error");

	sprintf(diagfile, "%s/%s", tempfile, "scdiag.xml");
	retval  = tl_client_list_generic(tempfile, MSG_ID_RUN_DIAGNOSTICS);
	if (retval != 0) {
		cgi_print_header_error_page("Unable to run diagnostics, error from daemon");
		rmdir(tempfile);
	}

	tmp = tempfile + 5;
	sprintf(cmd, "cd /tmp && tar czf %s.tgz %s", tmp, tmp);
	retval = system(cmd);
	if (retval != 0)
	{
		sprintf(cmd, "rm -f %s/*", tempfile);
		system(cmd);
		rmdir(tempfile);
		cgi_print_header_error_page("Error packing diagnostics file");
	}
	else
	{
		sprintf(tarfile, "%s.tgz", tempfile);
	}


	retval = stat(tarfile, &stbuf);
	if (retval != 0)
	{
		sprintf(cmd, "rm -f %s/*", tempfile);
		system(cmd);
		rmdir(tempfile);
		remove(tarfile);
		cgi_print_header_error_page("Error getting stats for diagnostics file");
	}

	fprintf(stdout, "Content-disposition: attachment; filename=quadstordiag.tgz\r\n");
	fprintf(stdout, "Content-Length: %ld\r\n", (long)stbuf.st_size);
	fprintf(stdout, "Content-type: application/x-gzip\r\n");
	fprintf(stdout, "\n");

	fp = fopen(tarfile, "r");
	if (!fp)
	{
		sprintf(cmd, "rm -f %s/*", tempfile);
		system(cmd);
		rmdir(tempfile);
		remove(tarfile);
		cgi_print_header_error_page("Error loading diagnostics file");
	}

	while ((retval = fread(buf, sizeof(char), sizeof(buf), fp)) != 0)
	{
		fwrite(buf, sizeof(char), retval, stdout);
	}
	fclose(fp);
	fflush(stdout);
	sprintf(cmd, "rm -f %s/*", tempfile);
	system(cmd);
	rmdir(tempfile);
	remove(tarfile);

	return 0;
}

int main()
{
	mdaemon_run_diagnostics();
	return 0;
}
