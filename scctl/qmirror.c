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
job_list_calc_format_length(struct job_list *job_list, int *ret_src_len, int *ret_src_addr_len, int *ret_dest_len, int *ret_dest_addr_len, int *ret_progress_len)
{
	struct job_info *job_info;
	struct job_stats *stats;
	int src_len = strlen("Source");
	int src_addr_len = strlen("SAddr");
	int dest_len = strlen("Destination");
	int dest_addr_len = strlen("DAddr");
	int progress_len = strlen("Progress");
	struct sockaddr_in in_addr;
	int len;

	memset(&in_addr, 0, sizeof(in_addr));
	TAILQ_FOREACH(job_info, job_list, c_entry) {
		stats = &job_info->stats;
		len = strlen(job_info->src_tdisk);
		if (len > src_len)
			src_len = len;
		len = strlen(job_info->dest_tdisk);
		if (len > dest_len)
			dest_len = len;
		len = strlen(job_info->progress_str);
		if (len > progress_len)
			progress_len = len;
		in_addr.sin_addr.s_addr = stats->src_ipaddr;
		len = strlen(inet_ntoa(in_addr.sin_addr));
		if (len > src_addr_len)
			src_addr_len = len;
		in_addr.sin_addr.s_addr = stats->dest_ipaddr;
		len = strlen(inet_ntoa(in_addr.sin_addr));
		if (len > dest_addr_len)
			dest_addr_len = len;
	}
	*ret_src_len = src_len;
	*ret_src_addr_len = src_addr_len;
	*ret_dest_len = dest_len;
	*ret_dest_addr_len = dest_addr_len;
	*ret_progress_len = progress_len;
}

static void
dump_qmirror_list(int prune, int extended)
{
	struct job_list job_list;
	struct job_info *job_info;
	struct job_stats *stats;
	char fmt[512];
	int retval, msg_id;
	int src_len, src_addr_len, dest_len, dest_addr_len, progress_len;
	char mapped[32], deduped[32];
	char bytesr[32], blocksr[32], bytesw[32], blocksw[32];
	char daddr[32], saddr[32];
	struct sockaddr_in in_addr;

	memset(&in_addr, 0, sizeof(in_addr));
	msg_id = prune ? MSG_ID_LIST_MIRRORS_PRUNE : MSG_ID_LIST_MIRRORS;
	retval = tl_client_list_clone(&job_list, msg_id);
	if (retval != 0) {
		fprintf(stderr, "Cannot get qmirror list\n");
		exit(1);
	}

	if (TAILQ_EMPTY(&job_list))
		exit(0);

	job_list_calc_format_length(&job_list, &src_len, &src_addr_len, &dest_len, &dest_addr_len, &progress_len);
	if (!extended) {
		sprintf(fmt, "%%-%ds %%-%ds %%-%ds %%-%ds %%-%ds %%-5s\n", src_len, src_addr_len, dest_len, dest_addr_len, progress_len);
		fprintf(stdout, fmt, "Source", "SAddr", "Destination", "DAddr", "Progress", "Time");
		sprintf(fmt, "%%-%ds %%-%ds %%-%ds %%-%ds %%-%ds %%-5.1f\n", src_len, src_addr_len, dest_len, dest_addr_len, progress_len);
	} else {
		sprintf(fmt, "%%-%ds %%-%ds %%-%ds %%-%ds %%-%ds %%-5s %%-5s %%-5s %%-9s %%-9s %%-9s %%-9s %%-9s %%-9s\n", src_len, src_addr_len, dest_len, dest_addr_len, progress_len);
		fprintf(stdout, fmt, "Source", "SAddr", "Destination", "DAddr", "Progress", "Time", "Read", "Write", "Mapped", "Deduped", "BytesR", "BlocksR", "BytesW", "BlocksW");
		sprintf(fmt, "%%-%ds %%-%ds %%-%ds %%-%ds %%-%ds %%-5.1f %%-5.1f %%-5.1f %%-9s %%-9s %%-9s %%-9s %%-9s %%-9s\n", src_len, src_addr_len, dest_len, dest_addr_len, progress_len);
	}

	TAILQ_FOREACH(job_info, &job_list, c_entry) {
		stats = &job_info->stats;
		in_addr.sin_addr.s_addr = stats->src_ipaddr;
		strcpy(saddr, inet_ntoa(in_addr.sin_addr)); 
		in_addr.sin_addr.s_addr = stats->dest_ipaddr;
		strcpy(daddr, inet_ntoa(in_addr.sin_addr)); 
		if (!extended) {
			fprintf(stdout, fmt, job_info->src_tdisk, saddr, job_info->dest_tdisk, daddr, job_info->progress_str, stats->elapsed_msecs/1000.0);
		}
		else {
			get_data_str(stats->mapped_blocks << 12, mapped);
			get_data_str(stats->deduped_blocks << 12, deduped);
			get_data_str(stats->bytes_read, bytesr);
			get_data_str(stats->blocks_read << 12, blocksr); 
			get_data_str(stats->bytes_written, bytesw);
			get_data_str(stats->blocks_written << 12, blocksw);
			fprintf(stdout, fmt, job_info->src_tdisk, saddr, job_info->dest_tdisk, daddr, job_info->progress_str, stats->elapsed_msecs/1000.0, stats->read_msecs/1000.0, stats->write_msecs/1000.0, mapped, deduped, bytesr, blocksr, bytesw, blocksw);
		}
	}
	job_list_free(&job_list);
	exit(0);
}

int main(int argc, char *argv[])
{
	char src[TDISK_MAX_NAME_LEN], dest[TDISK_MAX_NAME_LEN], dest_host[30], src_host[30], pool[GROUP_MAX_NAME_LEN];
	char clone[TDISK_MAX_NAME_LEN];
	int c;
	int cancel = 0;
	int list = 0;
	int prune = 0;
	int extended = 0;
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

	while ((c = getopt(argc, argv, "s:d:h:r:q:g:lcpaxe")) != -1) {
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
		case 'e':
			extended = 1;
			break;
		case 'l':
			list = 1;
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
		case 'q':
			strncpy(clone, optarg, TDISK_MAX_NAME_LEN - 1);
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
		dump_qmirror_list(prune, extended);
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
