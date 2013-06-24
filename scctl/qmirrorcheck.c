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
	fprintf(stdout, "qmirrorcheck usage: \n");
	fprintf(stdout, "qmirrorcheck -l lists configured mirror checks\n");
#if 0
	fprintf(stdout, "qmirrorcheck -a -t mdaemon -r <mirror ipaddress> -v <check ipaddress>\n");
	fprintf(stdout, "qmirrorcheck -x -t mdaemon -r <mirror ipaddress> -v <check ipaddress>\n");
	fprintf(stdout, "qmirrorcheck -a -t scsi -r <mirror ipaddress> -v <serial number>\n");
	fprintf(stdout, "qmirrorcheck -x -t scsi -r <mirror ipaddress> -v <serialnumber>\n");
#endif
	fprintf(stdout, "qmirrorcheck -a -t ignore -r <mirror ipaddress>\n");
	fprintf(stdout, "qmirrorcheck -x -t ignore -r <mirror ipaddress>\n");
	fprintf(stdout, "qmirrorcheck -a -t manual -r <mirror ipaddress>\n");
	fprintf(stdout, "qmirrorcheck -x -t manual -r <mirror ipaddress>\n");
	fprintf(stdout, "qmirrorcheck -a -t fence -r <mirror ipaddress> -v 'fence command'\n");
	fprintf(stdout, "qmirrorcheck -x -t fence -r <mirror ipaddress> -v 'fence command'\n");
	fprintf(stdout, "-a will add -x will delete\n");
	exit(0);
}

static void
remove_mirror_check(struct mirror_check_spec *mirror_check_spec)
{
	int retval;
	char reply[512];

	retval = tl_client_mirror_check_op(mirror_check_spec, reply, MSG_ID_REMOVE_MIRROR_CHECK);
	if (retval != 0) {
		fprintf(stderr, "Removing mirror check configuration failed\n");
		fprintf(stderr, "Message from server is - %s\n", reply);
		exit(1);
	}
	fprintf(stdout, "Mirror check configuration for successfully removed\n");
	exit(0);
}

static void
add_mirror_check(struct mirror_check_spec *mirror_check_spec)
{
	int retval;
	char reply[512];

	retval = tl_client_mirror_check_op(mirror_check_spec, reply, MSG_ID_ADD_MIRROR_CHECK);
	if (retval != 0) {
		fprintf(stderr, "Adding mirror check configuration failed\n");
		fprintf(stderr, "Message from server is - %s\n", reply);
		exit(1);
	}
	fprintf(stdout, "Mirror check configuration for successfully added\n");
	exit(0);
}

static void
dump_qmirror_check_list(void)
{
	char tempfile[48];
	char buf[512];
	FILE *fp;
	int fd;
	int retval;
	uint32_t maddr;
	int type;
	char value[512];
	struct sockaddr_in in_addr;

        memset(&in_addr, 0, sizeof(in_addr));

	strcpy(tempfile, "/tmp/.quadstorqmirrchklst.XXXXXX");
	fd = mkstemp(tempfile);
	if (fd == -1) {
		fprintf(stderr, "Internal system error\n");
		exit(1);
	}

	retval = tl_client_list_generic(tempfile, MSG_ID_LIST_MIRROR_CHECKS);
	if (retval != 0) {
		remove(tempfile);
		fprintf(stderr, "Cannot get qclone list\n");
		exit(1);
	}

	fp = fopen(tempfile, "r");
	if (!fp) {
		remove(tempfile);
		fprintf(stderr, "Internal system error\n");
		exit(1);
	}

	fprintf(stdout, "%-18s %-12s %-40s\n", "Mirror Ipaddr", "Type", "Value");
	while ((fgets(buf, sizeof(buf), fp) != NULL)) {
		retval = sscanf(buf, "maddr: %u type: %d value: %[^\n]\n", &maddr, &type, value);
		if (retval < 2) {
			fprintf(stderr, "Invalid buf %s\n", buf);
			exit(1);
			break;
		}

		in_addr.sin_addr.s_addr = maddr;
		if (type == MIRROR_CHECK_TYPE_MDAEMON)  {
			fprintf(stdout, "%-18s %-12s %-40s\n", inet_ntoa(in_addr.sin_addr), "mdaemon" , value);
		}
		else if (type == MIRROR_CHECK_TYPE_SCSI) {
			fprintf(stdout, "%-18s %-12s %-40s\n", inet_ntoa(in_addr.sin_addr), "scsi" , value);
		}
		else if (type == MIRROR_CHECK_TYPE_FENCE) {
			fprintf(stdout, "%-18s %-12s %-40s\n", inet_ntoa(in_addr.sin_addr), "fence" , value);
		}
		else if (type == MIRROR_CHECK_TYPE_IGNORE) {
			fprintf(stdout, "%-18s %-12s %-40s\n", inet_ntoa(in_addr.sin_addr), "ignore" , "N/A");
		}
		else if (type == MIRROR_CHECK_TYPE_MANUAL) {
			fprintf(stdout, "%-18s %-12s %-40s\n", inet_ntoa(in_addr.sin_addr), "manual" , "N/A");
		}
		else
			continue;
	}

	fclose(fp);
	close(fd);
	remove(tempfile);
	exit(0);
}

int main(int argc, char *argv[])
{
	char type[20];
	int c;
	int list = 0;
	char value[128];
	char mirror_host[20];
	int attach = 0, detach = 0;
	struct mirror_check_spec mirror_check_spec;

	if (geteuid() != 0) {
		fprintf(stderr, "This program can only be run as root\n");
		exit(1);
	}

	memset(mirror_host, 0, sizeof(mirror_host));
	memset(value, 0, sizeof(value));
	memset(type, 0, sizeof(type));
	memset(&mirror_check_spec, 0, sizeof(mirror_check_spec));

	while ((c = getopt(argc, argv, "t:r:v:lax")) != -1) {
		switch (c) {
		case 't':
			strncpy(type, optarg, sizeof(type) - 1);
			break;
		case 'r':
			strncpy(mirror_host, optarg, sizeof(mirror_host) - 1);
			break;
		case 'v':
			strncpy(value, optarg, sizeof(value) - 1);
			break;
		case 'a':
			attach = 1;
			break;
		case 'x':
			detach = 1;
			break;
		case 'l':
			list = 1;
			break;
		default:
			print_usage();
			break;
		}
	}

	if (list) {
		dump_qmirror_check_list();
	}
	else {
		if (!attach && !detach) {
			fprintf(stderr, "-a or -x needs to be specified\n");
			print_usage();
		}


		if (attach && !ipaddr_valid(mirror_host)) {
			fprintf(stderr, "Invalid mirror ipaddr %s\n", mirror_host);
			print_usage();
		}

		if (attach && strcmp(type, "ignore") && strcmp(type, "manual") && !value[0]) {
			fprintf(stderr, "No IPaddr/Serial Number/Command specified\n");
			print_usage();
		}

		if (attach && !strcmp(type, "mdaemon") && !ipaddr_valid(value)) {
			fprintf(stderr, "Invalid check ipaddr %s\n", value);
			print_usage();
		}

		strcpy(mirror_check_spec.value, value);
		strcpy(mirror_check_spec.mirror_host, mirror_host);
		if (!strcasecmp(type, "mdaemon"))
			mirror_check_spec.type = MIRROR_CHECK_TYPE_MDAEMON;
		else if (!strcasecmp(type, "scsi"))
			mirror_check_spec.type = MIRROR_CHECK_TYPE_SCSI;
		else if (!strcasecmp(type, "fence"))
			mirror_check_spec.type = MIRROR_CHECK_TYPE_FENCE;
		else if (!strcasecmp(type, "ignore"))
			mirror_check_spec.type = MIRROR_CHECK_TYPE_IGNORE;
		else if (!strcasecmp(type, "manual"))
			mirror_check_spec.type = MIRROR_CHECK_TYPE_MANUAL;
		else {
			if (attach || type[0]) {
				fprintf(stderr, "Invalid type %s specified\n", type);
				print_usage();
			}
		}

		if (attach)
			add_mirror_check(&mirror_check_spec);
		else
			remove_mirror_check(&mirror_check_spec);
	}
	return 0;
}

