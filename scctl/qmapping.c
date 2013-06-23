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

#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <tlclntapi.h>

int main(int argc, char *argv[])
{
	char path[256];
	char reply[256];
	int retval;

	if (geteuid() != 0) {
		fprintf(stderr, "This program can only be run as root\n");
		exit(1);
	}

	if (argc != 2) {
		fprintf(stderr, "Usage: qmapping <path>");
		exit(1);
	}

	strcpy(path, argv[1]);

	retval = tl_client_dev_mapping(path, reply);
	if (retval != 0) {
		fprintf(stderr, "Mapping failed for %s\n", path);
		exit(1);
	}
	fprintf(stdout, "%s\n", reply);
	exit(0);
}
