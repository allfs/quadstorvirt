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
	fprintf(stdout, "qmirror usage: \n");
	fprintf(stdout, "qmirror -l lists running/completed replication operations\n");
	fprintf(stdout, "qmirror -c -s <source vdisk name> cancels a mirror operation\n");
	fprintf(stdout, "qmirror -s <source vdisk name> -d <destination vdisk name> -r <dest server ip address> -g <destination storage pool> -h <src ip address (optional)> starts a mirror operation\n");
	fprintf(stdout, "For new mirror operations a new VDisk is created, destination VDisk name cannot already exist\n");
	fprintf(stdout, "Destination storage pool can be specified with the -g option, if omitted source VDisk pool name is used\n");
	exit(0);
}

static void
cancel_qmirror(char *src)
{
	int retval;
	char reply[512];
	struct mirror_spec mirror_spec;

	memset(&mirror_spec, 0, sizeof(mirror_spec));
	strcpy(mirror_spec.src_tdisk, src);
	retval = tl_client_mirror_op(&mirror_spec, reply, MSG_ID_CANCEL_MIRROR);
	if (retval != 0) {
		fprintf(stderr, "Cancelling mirror operation failed\n");
		fprintf(stderr, "Message from server is - %s\n", reply);
		exit(1);
	}
	fprintf(stdout, "Cancelled mirror operation on %s\n", src);
	exit(0);
}

static void
remove_qmirror(char *src)
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
start_qmirror(char *dest, char *src, char *dest_host, char *src_host, char *clone, char *pool, int attach)
{
	int retval;
	char reply[512];
	struct mirror_spec mirror_spec;

	if (!ipaddr_valid(dest_host)) {
		fprintf(stderr, "Invalid dest ipaddr %s\n", dest_host);
		exit(1);
	}

	if (src_host[0] && !ipaddr_valid(src_host)) {
		fprintf(stderr, "Invalid src ipaddr %s\n", src_host);
		exit(1);
	}

	if (attach && !ipaddr_valid(src_host)) {
		fprintf(stderr, "For qmirror attach operation source ipaddress needs to be specified\n");
		exit(1);
	}

	memset(&mirror_spec, 0, sizeof(mirror_spec));
	strcpy(mirror_spec.src_tdisk, src);
	strcpy(mirror_spec.dest_tdisk, dest);
	strcpy(mirror_spec.src_host, src_host);
	strcpy(mirror_spec.dest_host, dest_host);
	strcpy(mirror_spec.clone_tdisk, clone);
	strcpy(mirror_spec.dest_group, pool);
	if (clone[0])
		mirror_spec.clone = 1;
	mirror_spec.attach = attach;

	retval = tl_client_mirror_op(&mirror_spec, reply, MSG_ID_START_MIRROR);
	if (retval != 0) {
		fprintf(stderr, "Starting mirror operation failed\n");
		fprintf(stderr, "Message from server is - %s\n", reply);
		exit(1);
	}
	fprintf(stdout, "Mirror of %s to %s successfully started\n", src, dest);
	exit(0);
}

static void
dump_qmirror_list(int prune)
{
	char tempfile[32];
	char buf[512];
	FILE *fp;
	int fd;
	int retval;
	char src[50];
	char dest[50];
	int progress;
	int status;
	char progress_str[50];

	strcpy(tempfile, "/tmp/.quadstorqmirrlst.XXXXXX");
	fd = mkstemp(tempfile);
	if (fd == -1) {
		fprintf(stderr, "Internal system error\n");
		exit(1);
	}

	if (!prune)
		retval = tl_client_list_generic(tempfile, MSG_ID_LIST_MIRRORS);
	else
		retval = tl_client_list_generic(tempfile, MSG_ID_LIST_MIRRORS_PRUNE);
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

	fprintf(stdout, "%30s %30s %12s\n", "Source", "Destination", "Progress");
	while ((fgets(buf, sizeof(buf), fp) != NULL)) {
		retval = sscanf(buf, "dest: %s src: %s progress: %d status: %d\n", dest, src, &progress, &status);
		if (retval != 4) {
			fprintf(stderr, "Invalid buf %s\n", buf);
			exit(1);
			break;
		}

		if (status == CLONE_STATUS_INPROGRESS) {
			sprintf(progress_str, "%d%%", progress);
		}
		else if (status == CLONE_STATUS_SUCCESSFUL) {
			strcpy(progress_str, "Completed");
		}
		else {
			strcpy(progress_str, "Error");
		}

		fprintf(stdout, "%30s %30s %12s\n", src, dest, progress_str);
	}

	fclose(fp);
	close(fd);
	remove(tempfile);
	exit(0);
}

int main(int argc, char *argv[])
{
	char src[50], dest[50], dest_host[30], src_host[30], pool[50];
	char clone[50];
	int c;
	int cancel = 0;
	int list = 0;
	int prune = 0;
	int attach = 0, detach = 0;

	if (geteuid() != 0) {
		fprintf(stderr, "This program can only be run as root\n");
		exit(1);
	}

	memset(src, 0, sizeof(src));
	memset(dest, 0, sizeof(dest));
	memset(clone, 0, sizeof(clone));
	memset(src_host, 0, sizeof(src_host));
	memset(dest_host, 0, sizeof(dest_host));
	memset(pool, 0, sizeof(pool));

	while ((c = getopt(argc, argv, "s:d:h:r:q:g:lcpax")) != -1) {
		switch (c) {
		case 'a':
			attach = 1;
			break;
		case 'x':
			detach = 1;
			break;
		case 'c':
			cancel = 1;
			break;
		case 'p':
			prune = 1;
			break;
		case 'l':
			list = 1;
			break;
		case 'g':
			strncpy(pool, optarg, 40);
			break;
		case 's':
			strncpy(src, optarg, 40);
			break;
		case 'd':
			strncpy(dest, optarg, 40); 
			break;
		case 'q':
			strncpy(clone, optarg, 40); 
			break;
		case 'h':
			strncpy(src_host, optarg, 20); 
			break;
		case 'r':
			strncpy(dest_host, optarg, 20); 
			break;
		default:
			print_usage();
			break;
		}
	}

	if (list) {
		dump_qmirror_list(prune);
	}
	else if (cancel) {
		if (!src[0])
			print_usage();
		cancel_qmirror(src);
	}
	else {
		if (!detach) {
			if (!dest[0] || !src[0] || !dest_host[0])
				print_usage();

			start_qmirror(dest, src, dest_host, src_host, clone, pool, attach);
		}
		else
			remove_qmirror(src);
	}
	return 0;
}

