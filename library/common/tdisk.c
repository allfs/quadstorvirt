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

#include <apicommon.h>

void
group_list_free(struct group_list *group_list)
{
	struct group_info *info;

	while ((info = TAILQ_FIRST(group_list)))
	{
		TAILQ_REMOVE(group_list, info, q_entry);
		free(info);
	}
}

void
tdisk_list_free(struct tdisk_list *tdisk_list)
{
	struct tdisk_info *info;

	while ((info = TAILQ_FIRST(tdisk_list)))
	{
		TAILQ_REMOVE(tdisk_list, info, q_entry);
		free(info);
	}
}

void
dump_tdisk_stats(FILE *fp, struct tdisk_stats *stats)
{
	fprintf(fp, "<tdisk>\n");
	fprintf(fp, "write_size: %llu\n", (unsigned long long)stats->write_size);
	fprintf(fp, "read_size: %llu\n", (unsigned long long)stats->read_size);
	fprintf(fp, "unaligned_size: %llu\n", (unsigned long long)stats->unaligned_size);
	fprintf(fp, "blocks_deduped: %llu\n", (unsigned long long)stats->blocks_deduped);
	fprintf(fp, "inline_deduped: %llu\n", (unsigned long long)stats->inline_deduped);
	fprintf(fp, "post_deduped: %llu\n", (unsigned long long)stats->post_deduped);
	fprintf(fp, "zero_blocks: %llu\n", (unsigned long long)stats->zero_blocks);
	fprintf(fp, "unmap_blocks: %llu\n", (unsigned long long)stats->unmap_blocks);
	fprintf(fp, "wsame_blocks: %llu\n", (unsigned long long)stats->wsame_blocks);
	fprintf(fp, "uncompressed_size: %llu\n", (unsigned long long)stats->uncompressed_size);
	fprintf(fp, "compressed_size: %llu\n", (unsigned long long)stats->compressed_size);
	fprintf(fp, "compression_hits: %llu\n", (unsigned long long)stats->compression_hits);
	fprintf(fp, "compression_misses: %llu\n", (unsigned long long)stats->compression_misses);
	fprintf(fp, "verify_hits: %llu\n", (unsigned long long)stats->verify_hits);
	fprintf(fp, "verify_misses: %llu\n", (unsigned long long)stats->verify_misses);
	fprintf(fp, "verify_errors: %llu\n", (unsigned long long)stats->verify_errors);
	fprintf(fp, "inline_waits: %llu\n", (unsigned long long)stats->inline_waits);
	fprintf(fp, "cw_hits: %llu\n", (unsigned long long)stats->cw_hits);
	fprintf(fp, "cw_misses: %llu\n", (unsigned long long)stats->cw_misses);
	fprintf(fp, "xcopy_write: %llu\n", (unsigned long long)stats->xcopy_write);
	fprintf(fp, "xcopy_read: %llu\n", (unsigned long long)stats->xcopy_read);
	fprintf(fp, "</tdisk>\n");
	fclose(fp);
}

void
parse_tdisk_stats(FILE *fp, struct tdisk_stats *stats)
{
	char buf[512];

	memset(stats, 0, sizeof(*stats));

	while (fgets(buf, sizeof(buf), fp) != NULL)
	{
		if (strncmp(buf, "<tdisk>", strlen("<tdisk>")) != 0)
		{
			continue;
		}

		fscanf(fp, "write_size: %"PRIu64"\n", &stats->write_size);
		fscanf(fp, "read_size: %"PRIu64"\n", &stats->read_size);
		fscanf(fp, "unaligned_size: %"PRIu64"\n", &stats->unaligned_size);
		fscanf(fp, "blocks_deduped: %"PRIu64"\n", &stats->blocks_deduped);
		fscanf(fp, "inline_deduped: %"PRIu64"\n", &stats->inline_deduped);
		fscanf(fp, "post_deduped: %"PRIu64"\n", &stats->post_deduped);
		fscanf(fp, "zero_blocks: %"PRIu64"\n", &stats->zero_blocks);
		fscanf(fp, "unmap_blocks: %"PRIu64"\n", &stats->unmap_blocks);
		fscanf(fp, "wsame_blocks: %"PRIu64"\n", &stats->wsame_blocks);
		fscanf(fp, "uncompressed_size: %"PRIu64"\n", &stats->uncompressed_size);
		fscanf(fp, "compressed_size: %"PRIu64"\n", &stats->compressed_size);
		fscanf(fp, "compression_hits: %"PRIu64"\n", &stats->compression_hits);
		fscanf(fp, "compression_misses: %"PRIu64"\n", &stats->compression_misses);
		fscanf(fp, "verify_hits: %"PRIu64"\n", &stats->verify_hits);
		fscanf(fp, "verify_misses: %"PRIu64"\n", &stats->verify_misses);
		fscanf(fp, "verify_errors: %"PRIu64"\n", &stats->verify_errors);
		fscanf(fp, "inline_waits: %"PRIu64"\n", &stats->inline_waits);
		fscanf(fp, "cw_hits: %"PRIu64"\n", &stats->cw_hits);
		fscanf(fp, "cw_misses: %"PRIu64"\n", &stats->cw_misses);
		fscanf(fp, "xcopy_write: %"PRIu64"\n", &stats->xcopy_write);
		fscanf(fp, "xcopy_read: %"PRIu64"\n", &stats->xcopy_read);
		break;
	}
}

int
tl_common_parse_group(FILE *fp, struct group_list *group_list)
{
	struct group_info *info;
	char buf[512];
	int retval;

	while (fgets(buf, sizeof(buf), fp) != NULL)
	{
		if (strncmp(buf, "<group>", strlen("<group>")) != 0)
		{
			continue;
		}

		info = malloc(sizeof(struct group_info));
		if (!info)
		{
			return -1;
		}
		memset(info, 0, sizeof(struct group_info));

		retval = fscanf(fp, "group_id: %u\n", &info->group_id);
		if (retval != 1)
		{
			DEBUG_INFO("Unable to get group id");
			free(info);
			return -1;
		}

		retval = fscanf(fp, "name: %s\n", info->name);
		if (retval != 1)
		{
			DEBUG_INFO("Unable to get name");
			free(info);
			return -1;
		}

		retval = fscanf(fp, "dedupemeta: %d\n", &info->dedupemeta);
		if (retval != 1) {
			DEBUG_INFO("Unable to get dedupemeta property");
			free(info);
			return -1;
		}

		retval = fscanf(fp, "logdata: %d\n", &info->logdata);
		if (retval != 1) {
			DEBUG_INFO("Unable to get logdata property");
			free(info);
			return -1;
		}

		retval = fscanf(fp, "disks: %d\n", &info->disks);
		if (retval != 1) {
			DEBUG_INFO("Unable to get disks property");
			free(info);
			return -1;
		}

		retval = fscanf(fp, "tdisks: %d\n", &info->tdisks);
		if (retval != 1) {
			DEBUG_INFO("Unable to get tdisks property");
			free(info);
			return -1;
		}

		buf[0] = 0;
		fgets(buf, sizeof(buf), fp);
		if (strncmp(buf, "</group>", strlen("</group>")) != 0)
		{
			free(info);
			return -1;
		}

		TAILQ_INSERT_TAIL(group_list, info, q_entry); 
	}

	return 0;
}

int
tl_common_parse_tdisk(FILE *fp, struct tdisk_list *tdisk_list)
{
	struct tdisk_info *info;
	char buf[512];
	int retval;

	while (fgets(buf, sizeof(buf), fp) != NULL)
	{
		if (strncmp(buf, "<tdisk>", strlen("<tdisk>")) != 0)
		{
			continue;
		}

		info = malloc(sizeof(struct tdisk_info));
		if (!info)
		{
			return -1;
		}
		memset(info, 0, sizeof(struct tdisk_info));

		retval = fscanf(fp, "target_id: %u\n", &info->target_id);
		if (retval != 1)
		{
			DEBUG_INFO("Unable to get target id");
			free(info);
			return -1;
		}

		retval = fscanf(fp, "name: %s\n", info->name);
		if (retval != 1)
		{
			DEBUG_INFO("Unable to get name");
			free(info);
			return -1;
		}

		retval = fscanf(fp, "group_name: %s\n", info->group_name);
		if (retval != 1) {
			DEBUG_INFO("Unable to get name");
			free(info);
			return -1;
		}

		retval = fscanf(fp, "serialnumber: %s\n", info->serialnumber);
		if (retval != 1)
		{
			DEBUG_INFO("Unable to get serialnumber");
			free(info);
			return -1;
		}

		retval = fscanf(fp, "size: %"PRIu64"\n", &info->size);
		if (retval != 1)
		{
			DEBUG_INFO("Unable to get size");
			free(info);
			return -1;
		}

		retval = fscanf(fp, "online: %hhu\n", &info->online);
		if (retval != 1)
		{
			DEBUG_INFO("Unable to get online status");
			free(info);
			return -1;
		}

		retval = fscanf(fp, "disabled: %hhu\n", &info->disabled);
		if (retval != 1)
		{
			DEBUG_INFO("Unable to get disabled status");
			free(info);
			return -1;
		}

		retval = fscanf(fp, "delete_error: %hhu\n", &info->delete_error);
		if (retval != 1)
		{
			DEBUG_INFO("Unable to get delete_error status");
			free(info);
			return -1;
		}

		retval = fscanf(fp, "enable_deduplication: %hhu\n", &info->enable_deduplication);
		if (retval != 1)
		{
			DEBUG_INFO("Unable to get deduplication status");
			free(info);
			return -1;
		}

		retval = fscanf(fp, "enable_compression: %hhu\n", &info->enable_compression);
		if (retval != 1)
		{
			DEBUG_INFO("Unable to get compression status");
			free(info);
			return -1;
		}

		retval = fscanf(fp, "enable_verify: %hhu\n", &info->enable_verify);
		if (retval != 1)
		{
			DEBUG_INFO("Unable to get verification status");
			free(info);
			return -1;
		}

		retval = fscanf(fp, "force_inline: %hhu\n", &info->force_inline);
		if (retval != 1)
		{
			DEBUG_INFO("Unable to get inline status");
			free(info);
			return -1;
		}

		retval = fscanf(fp, "lba_shift: %hhu\n", &info->lba_shift);
		if (retval != 1)
		{
			DEBUG_INFO("Unable to get lba_shift status");
			free(info);
			return -1;
		}

		buf[0] = 0;
		fgets(buf, sizeof(buf), fp);
		if (strncmp(buf, "</tdisk>", strlen("</tdisk>")) != 0)
		{
			free(info);
			return -1;
		}

		TAILQ_INSERT_TAIL(tdisk_list, info, q_entry); 
	}
	return 0;
}
