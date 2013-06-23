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

#include "cgimain.h"

int main()
{
	FILE *fp;
	llist entries;
	char tempfile[100];
	int fd;
	int retval;
	uint32_t target_id;
	struct tdisk_stats stats;
	char *tmp;
	char databuf[64];
	double ratio;
	uint64_t used_size;
	char *cols[] = {"name", "value", NULL};

	read_cgi_input(&entries);

	tmp = cgi_val(entries, "target_id");
	if (!tmp)
		cgi_print_header_error_page("Invalid CGI parameters passed\n");

	target_id = strtoul(tmp, NULL, 10);
	if (!target_id)
		cgi_print_header_error_page("Invalid CGI parameters passed\n");

	strcpy(tempfile, "/tmp/.quadstorvwtdk.XXXXXX");
	fd = mkstemp(tempfile);
	if (fd == -1)
		cgi_print_header_error_page("Internal processing error\n");
	close(fd);

	retval = tl_client_list_target_generic(target_id, tempfile, MSG_ID_TDISK_STATS);
	if (retval != 0) {
		remove(tempfile);
		cgi_print_header_error_page("Getting vdisk stats failed\n");
	}

	fp = fopen(tempfile, "r");
	if (!fp) {
		remove(tempfile);
		cgi_print_header_error_page("Internal processing error\n");
	}

	memset(&stats, 0, sizeof(stats));
	parse_tdisk_stats(fp, &stats);
	remove(tempfile);

	cgi_print_header("VDisk Statistics", NULL, 1);

	cgi_print_thdr("VDisk Statisics");

	cgi_print_table_div("vstats-table");

	cgi_print_form_start("resetstats", "modifytdiskpost.cgi", "post", 1);
	printf ("<input type=\"hidden\" name=\"target_id\" value=\"%u\">\n", target_id);
	printf ("<input type=\"hidden\" name=\"resetstats\" value=\"1\">\n");
	cgi_print_submit_button("submit", "Reset");
	cgi_print_form_end();

	cgi_print_div_trailer();

	cgi_print_table_start("vstats-table", cols, 0);

	cgi_print_row_start();
	cgi_print_column("name", "Write Size:");
	cgi_print_comma();
	get_data_str(stats.write_size, databuf);
	cgi_print_column("value", databuf);
	cgi_print_row_end();

	cgi_print_row_start();
	cgi_print_column("name", "Read Size:");
	cgi_print_comma();
	get_data_str(stats.read_size, databuf);
	cgi_print_column("value", databuf);
	cgi_print_row_end();

	cgi_print_row_start();
	cgi_print_column("name", "Unaligned Size:");
	cgi_print_comma();
	get_data_str(stats.unaligned_size, databuf);
	cgi_print_column("value", databuf);
	cgi_print_row_end();

	cgi_print_row_start();
	cgi_print_column("name", "Data Deduped:");
	cgi_print_comma();
	get_data_str(stats.blocks_deduped << 12, databuf);
	cgi_print_column("value", databuf);
	cgi_print_row_end();

#if 0
	cgi_print_row_start();
	cgi_print_column("name", "Zero Blocks:");
	cgi_print_comma();
	get_data_str(stats.zero_blocks << 12, databuf);
	cgi_print_column("value", databuf);
	cgi_print_row_end();

	build_tr(count++);
	printf("<td>Inline Deduped:</td>\n");
	get_data_str(stats.inline_deduped << 12, databuf);
	printf("<td>%s</td>\n", databuf);
	printf("</tr>\n");

	build_tr(count++);
	printf("<td>Post Deduped:</td>\n");
	get_data_str(stats.post_deduped << 12, databuf);
	printf("<td>%s</td>\n", databuf);
	printf("</tr>\n");
#endif

	cgi_print_row_start();
	cgi_print_column("name", "Dedupe Ratio:");
	cgi_print_comma();
	used_size = stats.uncompressed_size + (stats.compression_hits << 12) + (stats.blocks_deduped << 12);
	if (used_size && stats.blocks_deduped)
		ratio = (double)(used_size)/(double)(used_size - (stats.blocks_deduped << 12));
	else
		ratio = 0;
	cgi_print_column_format("value", "%.3f", ratio);
	cgi_print_row_end();

	cgi_print_row_start();
	cgi_print_column("name", "Data Unmapped:");
	cgi_print_comma();
	get_data_str(stats.unmap_blocks << 12, databuf);
	cgi_print_column("value", databuf);
	cgi_print_row_end();

	cgi_print_row_start();
	cgi_print_column("name", "Blocks Zeroed:");
	cgi_print_comma();
	get_data_str(stats.wsame_blocks << 12, databuf);
	cgi_print_column("value", databuf);
	cgi_print_row_end();

	cgi_print_row_start();
	cgi_print_column("name", "Uncompressed Size:");
	cgi_print_comma();
	get_data_str(stats.uncompressed_size, databuf);
	cgi_print_column("value", databuf);
	cgi_print_row_end();

	cgi_print_row_start();
	cgi_print_column("name", "Compressed Size:");
	cgi_print_comma();
	get_data_str(stats.compressed_size, databuf);
	cgi_print_column("value", databuf);
	cgi_print_row_end();

	cgi_print_row_start();
	cgi_print_column("name", "Compression Hits:");
	cgi_print_comma();
	get_data_str(stats.compression_hits << 12, databuf);
	cgi_print_column("value", databuf);
	cgi_print_row_end();

	cgi_print_row_start();
	cgi_print_column("name", "Compression Misses:");
	cgi_print_comma();
	get_data_str(stats.compression_misses << 12, databuf);
	cgi_print_column("value", databuf);
	cgi_print_row_end();

	cgi_print_row_start();
	cgi_print_column("name", "Verify Hits:");
	cgi_print_comma();
	get_data_str(stats.verify_hits << 12, databuf);
	cgi_print_column("value", databuf);
	cgi_print_row_end();

	cgi_print_row_start();
	cgi_print_column("name", "Verify Misses:");
	cgi_print_comma();
	get_data_str(stats.verify_misses << 12, databuf);
	cgi_print_column("value", databuf);
	cgi_print_row_end();

	cgi_print_row_start();
	cgi_print_column("name", "Verify Errors:");
	cgi_print_comma();
	get_data_str(stats.verify_errors << 12, databuf);
	cgi_print_column("value", databuf);
	cgi_print_row_end();

#if 0
	cgi_print_row_start();
	cgi_print_column("name", "Inline Waits:");
	cgi_print_comma();
	get_data_str(stats.inline_waits << 12, databuf);
	cgi_print_column("value", databuf);
	cgi_print_row_end();
#endif

	cgi_print_row_start();
	cgi_print_column("name", "CW Hits:");
	cgi_print_comma();
	cgi_print_column_format("value", "%llu", (unsigned long long)stats.cw_hits);
	cgi_print_row_end();

	cgi_print_row_start();
	cgi_print_column("name", "CW Misses:");
	cgi_print_comma();
	cgi_print_column_format("value", "%llu", (unsigned long long)stats.cw_misses);
	cgi_print_row_end();

	cgi_print_row_start();
	cgi_print_column("name", "XCopy Write:");
	cgi_print_comma();
	get_data_str(stats.xcopy_write, databuf);
	cgi_print_column("value", databuf);
	cgi_print_row_end();

	cgi_print_row_start();
	cgi_print_column("name", "XCopy Read:");
	cgi_print_comma();
	get_data_str(stats.xcopy_read, databuf);
	cgi_print_column("value", databuf);
	cgi_print_row_end();

	cgi_print_table_end("vstats-table");

	cgi_print_body_trailer();
	return 0;
}
