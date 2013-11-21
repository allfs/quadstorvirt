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
	fprintf(stdout, "qsync usage: \n");
	fprintf(stdout, "qsync -l lists running/completed replication operations\n");
	fprintf(stdout, "qsync -s <source vdisk name> -d <destination vdisk name> -r <dest server ip address> -g <destination storage pool> configures mirroring\n");
	fprintf(stdout, "qsync -x -s <source vdisk name> deletes an existing mirroring configuration\n");
	fprintf(stdout, "qsync -s <source vdisk name> -m <mirror role> sets the mirroring role for the vdisk\n");
	fprintf(stdout, "Destination storage pool can be specified with the -g option, if omitted source VDisk pool name is used\n");
	exit(0);
}

static void
remove_mirror(char *src)
{
	int retval;
	char reply[512];
	struct mirror_spec mirror_spec;

	memset(&mirror_spec, 0, sizeof(mirror_spec));
	strcpy(mirror_spec.src_tdisk, src);

	retval = tl_client_mirror_op(&mirror_spec, reply, MSG_ID_REMOVE_MIRROR);
	if (retval != 0) {
		fprintf(stderr, "Removing mirror configuration failed\n");
		fprintf(stderr, "Message from server is - %s\n", reply);
		exit(1);
	}
	fprintf(stdout, "Mirror configuration for %s successfully removed\n", src);
	exit(0);
}

static void
configure_mirror(char *dest, char *src, char *dest_host, char *pool)
{
	int retval;
	char reply[512];
	struct mirror_spec mirror_spec;

	if (!ipaddr_valid(dest_host)) {
		fprintf(stderr, "Invalid dest ipaddr %s\n", dest_host);
		exit(1);
	}

	memset(&mirror_spec, 0, sizeof(mirror_spec));
	strcpy(mirror_spec.src_tdisk, src);
	strcpy(mirror_spec.dest_tdisk, dest);
	strcpy(mirror_spec.dest_host, dest_host);
	strcpy(mirror_spec.dest_group, pool);
	mirror_spec.attach = 1;

	retval = tl_client_mirror_op(&mirror_spec, reply, MSG_ID_START_MIRROR);
	if (retval != 0) {
		fprintf(stderr, "Starting mirror operation failed\n");
		fprintf(stderr, "Message from server is - %s\n", reply);
		exit(1);
	}
	fprintf(stdout, "Mirror of %s to %s on %s successfully configured\n", src, dest, dest_host);
	exit(0);
}

static void
handle_mirror_role(char *role, char *src, int force, char *reply)
{
	int mirror_role, retval;

	if (strcasecmp(role, "slave") == 0)
		mirror_role = MIRROR_ROLE_PEER;
	else if (strcasecmp(role, "master") == 0)
		mirror_role = MIRROR_ROLE_MASTER;
	else {
		fprintf(stderr, "Invalid role %s specified\n", role);
		exit(1);
	}

	retval = tl_client_set_vdisk_role(src, mirror_role, force, reply);
	if (retval != 0) {
		fprintf(stderr, "Setting VDisk role(s) failed.\nReply from server is : %s\n", reply);
	}
	else {
		fprintf(stdout, "Setting VDisk role(s) successful\n");
	}
}

static void
list_mirror_configuration(void)
{
	char tempfile[32];
	char buf[512];
	FILE *fp;
	int fd;
	int retval;
	char src[TDISK_MAX_NAME_LEN], dest[TDISK_MAX_NAME_LEN], pool[GROUP_MAX_NAME_LEN], daddr[30], status[64], role[20];

	strcpy(tempfile, MKSTEMP_PREFIX);
	fd = mkstemp(tempfile);
	if (fd == -1) {
		fprintf(stderr, "Internal system error\n");
		exit(1);
	}

	retval = tl_client_list_generic(tempfile, MSG_ID_LIST_SYNC_MIRRORS);
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

	fprintf(stdout, "%-18s %-18s %-16s %-14s %-8s %-16s\n", "Local", "Remote", "Pool", "Dest Addr", "Role", "Status");
	while ((fgets(buf, sizeof(buf), fp) != NULL)) {
		retval = sscanf(buf, "dest: %s src: %s pool: %s daddr: %s role: %s status: %[^\n]", dest, src, pool, daddr, role, status);
		if (retval != 6) {
			fprintf(stderr, "Invalid buf %s\n", buf);
			exit(1);
			break;
		}
		fprintf(stdout, "%-18s %-18s %-16s %-14s %-8s %-16s\n", src, dest, pool, daddr, role, status);
	}

	fclose(fp);
	close(fd);
	remove(tempfile);
	exit(0);
}

int main(int argc, char *argv[])
{
	char src[TDISK_MAX_NAME_LEN], dest[TDISK_MAX_NAME_LEN], dest_host[30], pool[GROUP_MAX_NAME_LEN], role[30], reply[256];
	int c;
	int detach = 0, list = 0, force = 0;

	if (geteuid() != 0) {
		fprintf(stderr, "This program can only be run as root\n");
		exit(1);
	}

	role[0] = 0;
	memset(src, 0, sizeof(src));
	memset(dest, 0, sizeof(dest));
	memset(dest_host, 0, sizeof(dest_host));
	memset(pool, 0, sizeof(pool));

	while ((c = getopt(argc, argv, "s:d:r:g:m:xlf")) != -1) {
		switch (c) {
		case 'x':
			detach = 1;
			break;
		case 'g':
			strncpy(pool, optarg, GROUP_NAME_LEN);
			break;
		case 's':
			strncpy(src, optarg, TDISK_MAX_NAME_LEN - 1);
			break;
		case 'd':
			strncpy(dest, optarg, TDISK_MAX_NAME_LEN - 1); 
			break;
		case 'r':
			strncpy(dest_host, optarg, 20); 
			break;
		case 'm':
			strncpy(role, optarg, 20);
			break;
		case 'l':
			list = 1;
			break;
		case 'f':
			force = 1;
			break;
		default:
			print_usage();
			break;
		}
	}

	if (list) {
		list_mirror_configuration();
	}
	else  if (role[0]) {
		if (!force && !src[0]) {
			fprintf(stderr, "In order to set a role for all VDisks -f option needs to specified\n");
			exit(1);
		}
		handle_mirror_role(role, src, force, reply);
	}
	else if (!detach) {
		if (!dest[0] || !src[0] || !dest_host[0])
			print_usage();

		configure_mirror(dest, src, dest_host, pool);
	}
	else
		remove_mirror(src);

	return 0;
}

