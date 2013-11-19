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
	fprintf(stdout, "qclone -l lists clone operations\n");
	fprintf(stdout, "qclone -l -p lists clone operations, clears all completed operations\n");
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
start_qclone(char *dest, char *src, char *pool, int wait)
{
	struct clone_spec clone_spec;
	char reply[512];
	uint64_t job_id;
	int retval;

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
	if (!wait)
		exit(0);
	retval = sscanf(reply, "jobid: %"PRIu64"\n", &job_id);
	if (retval != 1) {
		fprintf(stderr, "Invalid format for job id received. Software upgrade needed\n");
		exit(1);
	}

	while (1) {
		retval = tl_client_clone_status(job_id);
		switch (retval) {
		case MSG_RESP_OK:
			fprintf(stdout, "Clone of %s to %s completed\n", src, dest);
			exit(0);
		case MSG_RESP_BUSY:
			break;
		case MSG_RESP_ERROR:
		default:
			fprintf(stdout, "Clone of %s to %s failed\n", src, dest);
			exit(1);
		}
		sleep(5);
	}
}

static void
job_list_calc_format_length(struct job_list *job_list, int *ret_src_len, int *ret_dest_len, int *ret_progress_len)
{
	struct job_info *job_info;
	int src_len = strlen("Source");
	int dest_len = strlen("Destination");
	int progress_len = strlen("Progress");
	int len;

	TAILQ_FOREACH(job_info, job_list, c_entry) {
		len = strlen(job_info->src_tdisk);
		if (len > src_len)
			src_len = len;
		len = strlen(job_info->dest_tdisk);
		if (len > dest_len)
			dest_len = len;
		len = strlen(job_info->progress_str);
		if (len > progress_len)
			progress_len = len;
	}
	*ret_src_len = src_len;
	*ret_dest_len = dest_len;
	*ret_progress_len = progress_len;
}

static void
dump_qclone_list(int prune, int extended)
{
	struct job_list job_list;
	struct job_info *job_info;
	struct job_stats *stats;
	char fmt[256];
	int retval, msg_id;
	int src_len, dest_len, progress_len;
	char mapped[32], deduped[32], refed[32];
	char bytesr[32], blocksr[32], bytesw[32], blocksw[32];

	msg_id = prune ? MSG_ID_LIST_CLONES_PRUNE : MSG_ID_LIST_CLONES;
	retval = tl_client_list_clone(&job_list, msg_id);
	if (retval != 0) {
		fprintf(stderr, "Cannot get qclone list\n");
		exit(1);
	}

	if (TAILQ_EMPTY(&job_list))
		exit(0);

	job_list_calc_format_length(&job_list, &src_len, &dest_len, &progress_len);
	if (!extended) {
		sprintf(fmt, "%%-%ds %%-%ds %%-%ds %%-5s\n", src_len, dest_len, progress_len);
		fprintf(stdout, fmt, "Source", "Destination", "Progress", "Time");
		sprintf(fmt, "%%-%ds %%-%ds %%-%ds %%-5.1f\n", src_len, dest_len, progress_len);
	} else {
		sprintf(fmt, "%%-%ds %%-%ds %%-%ds %%-5s %%-5s %%-5s %%-5s %%-5s %%-9s %%-9s %%-9s %%-9s %%-9s %%-9s %%-9s\n", src_len, dest_len, progress_len);
		fprintf(stdout, fmt, "Source", "Destination", "Progress", "Time", "Read", "Write", "HComp", "HLook", "Mapped", "Deduped", "Refed", "BytesR", "BlocksR", "BytesW", "BlocksW");
		sprintf(fmt, "%%-%ds %%-%ds %%-%ds %%-5.1f %%-5.1f %%-5.1f %%-5.1f %%-5.1f %%-9s %%-9s %%-9s %%-9s %%-9s %%-9s %%-9s\n", src_len, dest_len, progress_len);
	}

	TAILQ_FOREACH(job_info, &job_list, c_entry) {
		stats = &job_info->stats;
		if (!extended)
			fprintf(stdout, fmt, job_info->src_tdisk, job_info->dest_tdisk, job_info->progress_str, stats->elapsed_msecs/1000.0);
		else {
			get_data_str(stats->mapped_blocks << 12, mapped);
			get_data_str(stats->deduped_blocks << 12, deduped);
			get_data_str(stats->refed_blocks << 12, refed);
			get_data_str(stats->bytes_read, bytesr);
			get_data_str(stats->blocks_read << 12, blocksr); 
			get_data_str(stats->bytes_written, bytesw);
			get_data_str(stats->blocks_written << 12, blocksw);
			fprintf(stdout, fmt, job_info->src_tdisk, job_info->dest_tdisk, job_info->progress_str, stats->elapsed_msecs/1000.0, stats->read_msecs/1000.0, stats->write_msecs/1000.0, stats->hash_compute_msecs/1000.0, stats->hash_lookup_msecs/1000.0, mapped, deduped, refed, bytesr, blocksr, bytesw, blocksw);
		}
	}
	job_list_free(&job_list);
	exit(0);
}

int main(int argc, char *argv[])
{
	char src[TDISK_MAX_NAME_LEN], dest[TDISK_MAX_NAME_LEN], pool[GROUP_MAX_NAME_LEN];
	int c;
	int cancel = 0;
	int list = 0;
	int prune = 0;
	int extended = 0;
	int wait = 0;

	if (geteuid() != 0) {
		fprintf(stderr, "This program can only be run as root\n");
		exit(1);
	}

	memset(src, 0, sizeof(src));
	memset(dest, 0, sizeof(dest));
	memset(pool, 0, sizeof(pool));

	while ((c = getopt(argc, argv, "s:d:g:lcpew")) != -1) {
		switch (c) {
		case 'c':
			cancel = 1;
			break;
		case 'w':
			wait = 1;
			break;
		case 'p':
			prune = 1;
			break;
		case 'e':
			extended = 1;
			break;
		case 'l':
			list = 1;
			break;
		case 's':
			strncpy(src, optarg, TDISK_NAME_LEN);
			break;
		case 'd':
			strncpy(dest, optarg, TDISK_NAME_LEN); 
			break;
		case 'g':
			strncpy(pool, optarg, GROUP_NAME_LEN);
			break;
		default:
			print_usage();
			break;
		}
	}

	if (list) {
		dump_qclone_list(prune, extended);
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
		start_qclone(dest, src, pool, wait);
	}
	return 0;
}

