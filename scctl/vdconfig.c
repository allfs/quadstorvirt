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

static void
print_usage(void)
{
	fprintf(stdout, "vdconfig usage: \n");
	fprintf(stdout, "vdconfig -v <vdisk name> -s <new size in GB> (Where 1 GB = 1024 x 1024 x 1024 bytes)\n");
	exit(0);
}

int main(int argc, char *argv[])
{
	char src[50];
	char reply[512];
	int c, retval;
	int force;
	unsigned long long size = 0, sizebytes;

	if (geteuid() != 0) {
		fprintf(stderr, "This program can only be run as root\n");
		exit(1);
	}

	memset(src, 0, sizeof(src));
	force = 0;
	while ((c = getopt(argc, argv, "v:s:f")) != -1) {
		switch (c) {
		case 'v':
			strncpy(src, optarg, 40);
			break;
		case 's':
			size = strtoull(optarg, NULL, 10);
			break;
		case 'f':
			force = 1;
			break;
		default:
			print_usage();
			break;
		}
	}

	if (!size || !src[0]) {
		print_usage();
	}

	sizebytes = (size * 1024 * 1024 * 1024);
	retval = tl_client_vdisk_resize(src, sizebytes, force, reply);
	if (retval != 0) {
		fprintf(stderr, "VDisk %s resize to %llu GB failed\n", src, (unsigned long long)size);
		fprintf(stderr, "Message from server is - %s\n", reply);
		exit(1);
	}
	else {
		fprintf(stderr, "VDisk %s resized to %llu GB\n", src, (unsigned long long)size);
	}
	return 0;
}

