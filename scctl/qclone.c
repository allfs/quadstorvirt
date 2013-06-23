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
	fprintf(stdout, "qclone usage: \n");
	fprintf(stdout, "qclone -l lists running/completed clone operations\n");
	fprintf(stdout, "qclone -c -s <src vdisk name> cancels a clone operation\n");
	fprintf(stdout, "qclone -s <source vdisk name> -d <destination vdisk name> -g <destination storage pool> starts a clone operation\n");
	fprintf(stdout, "For new clone operations a new VDisk is created, destination VDisk cannot already exist\n");
	fprintf(stdout, "Destination storage pool can be specified with the -g option, if omitted source VDisk pool name is used\n");
	exit(0);
}

static void
cancel_qclone(char *src)
{
	struct clone_spec clone_spec;
	int retval;
	char reply[512];

	memset(&clone_spec, 0, sizeof(clone_spec));
	strcpy(clone_spec.src_tdisk, src);

	retval = tl_client_clone_op(&clone_spec, reply, MSG_ID_CANCEL_CLONE);
	if (retval != 0) {
		fprintf(stderr, "Cancelling clone operation failed\n");
		fprintf(stderr, "Message from server is - %s\n", reply);
		exit(1);
	}
	fprintf(stdout, "Cancelled clone operation for %s\n", src);
	fprintf(stdout, "Cancelled clone would have to be manually deleted\n");
	exit(0);
}

static void
start_qclone(char *dest, char *src, char *pool)
{
	int retval;
	char reply[512];
	struct clone_spec clone_spec;

	memset(&clone_spec, 0, sizeof(clone_spec));
	strcpy(clone_spec.src_tdisk, src);
	strcpy(clone_spec.dest_tdisk, dest);
	strcpy(clone_spec.dest_group, pool);

	retval = tl_client_clone_op(&clone_spec, reply, MSG_ID_START_CLONE);
	if (retval != 0) {
		fprintf(stderr, "Starting clone operation failed\n");
		fprintf(stderr, "Message from server is - %s\n", reply);
		exit(1);
	}
	fprintf(stdout, "Clone of %s to %s successfully started\n", src, dest);
	exit(0);
}

static void
dump_qclone_list(int prune)
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

	strcpy(tempfile, "/tmp/.quadstorqclonlst.XXXXXX");
	fd = mkstemp(tempfile);
	if (fd == -1) {
		fprintf(stderr, "Internal system error\n");
		exit(1);
	}

	if (!prune)
		retval = tl_client_list_generic(tempfile, MSG_ID_LIST_CLONES);
	else
		retval = tl_client_list_generic(tempfile, MSG_ID_LIST_CLONES_PRUNE);
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
	char src[50], dest[50], pool[50];
	int c;
	int cancel = 0;
	int list = 0;
	int prune = 0;

	if (geteuid() != 0) {
		fprintf(stderr, "This program can only be run as root\n");
		exit(1);
	}

	memset(src, 0, sizeof(src));
	memset(dest, 0, sizeof(dest));
	memset(pool, 0, sizeof(pool));

	while ((c = getopt(argc, argv, "s:d:g:lcp")) != -1) {
		switch (c) {
		case 'c':
			cancel = 1;
			break;
		case 'p':
			prune = 1;
			break;
		case 'l':
			list = 1;
			break;
		case 's':
			strncpy(src, optarg, 40);
			break;
		case 'd':
			strncpy(dest, optarg, 40); 
			break;
		case 'g':
			strncpy(pool, optarg, 40);
			break;
		default:
			print_usage();
			break;
		}
	}

	if (list) {
		dump_qclone_list(prune);
	}
	else if (cancel) {
		if (!src[0])
			print_usage();
		cancel_qclone(src);
	}
	else {
		if (!dest[0] || !src[0])
			print_usage();
		if (strlen(dest) > TDISK_NAME_LEN) {
			fprintf(stderr, "VDisk name is limited to %d characters", TDISK_NAME_LEN);
			exit(1);
		}
		start_qclone(dest, src, pool);
	}
	return 0;
}

