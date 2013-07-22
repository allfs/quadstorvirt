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
	fprintf(stdout, "spconfig usage: \n\n");
	fprintf(stdout, "Listing Pools: \n");
	fprintf(stdout, "spconfig -l\n\n");
	fprintf(stdout, "Adding a Pool: \n");
	fprintf(stdout, "spconfig -a -g <pool name> -d (Enable dedupe metadata) -o (Enable Logs)\n\n");
	fprintf(stdout, "Deleting a Pool: \n");
	fprintf(stdout, "spconfig -x -g <pool name>\n\n");
	exit(1);
}

static int
spconfig_delete_pool(char *name)
{
	int group_id, retval;
	char reply[512];

	group_id = tl_client_get_group_id(name);
	if (group_id <= 0) {
		fprintf(stderr, "Cannot get group id for pool %s\n", name);
		return -1;
	}

	retval = tl_client_delete_group(group_id, reply);
	if (retval != 0) {
		fprintf(stderr, "Deleting pool %s failed\n", name);
		fprintf(stderr, "Message from server is %s\n", reply);
		return -1;
	}
	fprintf(stdout, "Deleting pool %s successful\n", name);
	return 0;
}

static int
spconfig_add_pool(char *name, int dedupemeta, int logdata)
{
	char reply[512];
	int retval;

	if (!target_name_valid(name)) {
		fprintf(stderr, "Invalid pool name specified\n");
		return -1;
	}

	retval = tl_client_add_group(name, dedupemeta, logdata, reply);
	if (retval != 0) {
		fprintf(stderr, "Unable to add pool\n");
		fprintf(stderr, "Message from server is %s\n", reply);
		return -1;
	}
	fprintf(stdout, "Adding pool %s successful\n", name);
	return 0;
}


static void
group_list_calc_format_length(struct group_list *group_list, int *ret_name_len)
{
	struct group_info *group_info;
	int name_len = strlen("Name");
	int len;

	TAILQ_FOREACH(group_info, group_list, q_entry) {
		len = strlen(group_info->name);
		if (len > name_len)
			name_len = len;
	}
	*ret_name_len = name_len;
}

static int
spconfig_list_pools(void)
{
	struct group_list group_list;
	struct group_info *group_info;
	char fmt[64];
	char status[64];
	int retval, name_len;

	retval = tl_client_list_groups(&group_list, MSG_ID_LIST_GROUP);
	if (retval != 0) {
		fprintf(stderr, "Getting pool list failed\n");
		return -1;
	}

	group_list_calc_format_length(&group_list, &name_len);
	sprintf(fmt, "%%-%ds %%-5s %%-6s %%-8s\n", name_len);
	fprintf(stdout, fmt, "Name", "Disks", "VDisks", "Status");
	sprintf(fmt, "%%-%ds %%-5d %%-6d %%-8s\n", name_len);
	TAILQ_FOREACH(group_info, &group_list, q_entry) {

		status[0] = 0;
		if (group_info->dedupemeta)
			strcat(status, "D");

		if (group_info->logdata) {
			if (strlen(status) > 0)
				strcat(status, " ");
			strcat(status, "L");
		}
		fprintf(stdout, fmt, group_info->name, group_info->disks, group_info->tdisks, status);
	}
	group_list_free(&group_list);
	return 0;
}

int main(int argc, char *argv[])
{
	char pool[50];
	int c;
	int add = 0, delete = 0, list = 0;
	int dedupemeta = 0, logdata = 0;

	if (geteuid() != 0) {
		fprintf(stderr, "This program can only be run as root\n");
		exit(1);
	}

	memset(pool, 0, sizeof(pool));
	while ((c = getopt(argc, argv, "g:axldo")) != -1) {
		switch (c) {
		case 'g':
			strncpy(pool, optarg, 36);
			break;
		case 'a':
			add = 1;
			break;
		case 'x':
			delete = 1;
			break;
		case 'l':
			list = 1;
			break;
		case 'd':
			dedupemeta = 1;
			break;
		case 'o':
			logdata = 1;
			break;
		}
	}

	if (list)
		return spconfig_list_pools();

	if (!pool[0])
		print_usage();

	if (add)
		return spconfig_add_pool(pool, dedupemeta, logdata);
	else if (delete)
		return spconfig_delete_pool(pool);
	return 0;
}
