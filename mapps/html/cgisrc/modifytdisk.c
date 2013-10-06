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
	llist entries;
	char *tmp;
	uint32_t target_id;
	int retval;
	struct vdiskconf vdiskconf;
	struct iscsiconf iscsiconf;
	struct mirror_state mirror_state;
	struct sockaddr_in in_addr;
	char status[256];
	char name[TDISK_MAX_NAME_LEN];
	char tmpstr[32];

        memset(&in_addr, 0, sizeof(in_addr));

	read_cgi_input(&entries);

	tmp = cgi_val(entries, "target_id");
	if (!tmp)
		cgi_print_header_error_page("Invalid CGI parameters passed\n");

	target_id = strtoul(tmp, NULL, 10);
	if (!target_id)
		cgi_print_header_error_page("Invalid CGI parameters passed\n");

	retval = tl_client_get_vdiskconf(target_id, &vdiskconf);
	if (retval != 0)
		cgi_print_header_error_page("Unable to get VDisk configuration\n");

	memset(&iscsiconf, 0, sizeof(struct iscsiconf));
	retval = tl_client_get_iscsiconf(target_id, &iscsiconf);
	if (retval != 0)
		cgi_print_header_error_page("Unable to get iscsi configuration\n");

	retval = tl_client_get_mirrorconf(target_id, &mirror_state);
	if (retval != 0)
		cgi_print_header_error_page("Unable to get mirroring configuration\n"); 

	cgi_print_header("Modify VDisk", "iscsiconf.js", 1);

	sprintf(tmpstr, "%llu", (unsigned long long)(vdiskconf.size >> 30));

	cgi_print_div_container(54, "left");
	cgi_print_div_padding(4);

	cgi_print_thdr("Modify VDisk");

	cgi_print_div_start("center");

	cgi_print_form_start_check("modifyvdisk", "modifytdiskpost.cgi", "post", "checkModifyVDisk");
	printf ("<input type=\"hidden\" name=\"target_id\" value=\"%u\">\n", target_id);
	printf ("<input type=\"hidden\" name=\"oldtargetsize\" value=\"%s\">\n", tmpstr);
	
	printf("<table class=\"ctable\">\n");

	printf ("<tr>\n");
	printf ("<td>VDisk Name: </td>\n");
	cgi_print_text_input_td("targetname", 20, vdiskconf.name, TDISK_NAME_LEN);
	printf ("</tr>\n");

	printf ("<tr>\n");
	printf ("<td>VDisk Size (GB):</td>\n");
	cgi_print_text_input_td("targetsize", 10, tmpstr, 10);
	printf ("</tr>\n");

	sprintf(tmpstr, "%d", vdiskconf.threshold);
	printf ("<tr>\n");
	printf ("<td>Threshold %%:</td>\n");
	cgi_print_text_input_td("threshold", 2, tmpstr, 2);
	printf ("</tr>\n");

	printf ("<tr>\n");
	printf ("<td>Enable Deduplication: </td>\n");
	cgi_print_checkbox_input_td("dedupe", vdiskconf.enable_deduplication);
	printf ("</tr>\n");

	printf ("<tr>\n");
	printf ("<td>Enable Compression: </td>\n");
	cgi_print_checkbox_input_td("comp", vdiskconf.enable_compression);
	printf ("</tr>\n");

	printf ("<tr>\n");
	printf ("<td>Enable Verify: </td>\n");
	cgi_print_checkbox_input_td("verify", vdiskconf.enable_verify);
	printf ("</tr>\n");

	printf("</table>\n");

	cgi_print_submit_button("submit", "Submit");

	cgi_print_form_end();

	cgi_print_form_start_check("iscsiconf", "iscsiconfpost.cgi", "post", "checkModifyiSCSI");
	printf ("<input type=\"hidden\" name=\"target_id\" value=\"%u\">\n", target_id);

	cgi_print_thdr("iSCSI Configuration");

	printf("<table class=\"ctable\">\n");

	printf ("<tr>\n");
	printf ("<td>IQN:</td>\n");
	cgi_print_text_input_td("iqn", 40, iscsiconf.iqn, 255);
	printf ("</tr>\n");

	printf ("<tr>\n");
	printf ("<td>Incoming User:</td>\n");
	cgi_print_text_input_td("IncomingUser", 20, iscsiconf.IncomingUser, 35);
	printf ("</tr>\n");

	printf ("<tr>\n");
	printf ("<td>Incoming Passwd:</td>\n");
	cgi_print_text_input_td("IncomingPasswd", 20, iscsiconf.IncomingPasswd, 35);
	printf ("</tr>\n");

	printf ("<tr>\n");
	printf ("<td>Outgoing User:</td>\n");
	cgi_print_text_input_td("OutgoingUser", 20, iscsiconf.OutgoingUser, 35);
	printf ("</tr>\n");

	printf ("<tr>\n");
	printf ("<td>Outgoing Passwd:</td>\n");
	cgi_print_text_input_td("OutgoingPasswd", 20, iscsiconf.OutgoingPasswd, 35);
	printf ("</tr>\n");

	printf("</table>\n");

	cgi_print_submit_button("updateiscsi", "Submit");
	cgi_print_form_end();

	cgi_print_div_end();
	cgi_print_div_end();
	cgi_print_div_end();


	cgi_print_div_container(42, "left");
	cgi_print_div_padding(4);

	cgi_print_thdr("Mirroring Configuration");
	cgi_print_div_start("center");
	cgi_print_form_start("mirrorconf", "mirrorconf.cgi", "post", 0);

	printf ("<input type=\"hidden\" name=\"target_id\" value=\"%u\">\n", target_id);

	if (!mirror_state.mirror_ipaddr) {
		printf ("<input type=\"hidden\" name=\"op\" value=\"1\">\n");
		printf("<table class=\"ctable\">\n");

		printf ("<tr>\n");
		printf ("<td>Destination VDisk:</td>\n");
		cgi_print_text_input_td("dest", 20, vdiskconf.name, TDISK_NAME_LEN);
		printf ("</tr>\n");

		printf ("<tr>\n");
		printf ("<td>Destination VDisk Pool:</td>\n");
		cgi_print_text_input_td("pool", 20, vdiskconf.group_name, TDISK_NAME_LEN);
		printf ("</tr>\n");

		printf ("<tr>\n");
		printf ("<td>Mirror IP Address:</td>\n");
		cgi_print_text_input_td("dest_host", 20, "", 20);
		printf ("</tr>\n");

#if 0
		printf ("<tr>\n");
		printf ("<td>Source IP Address:</td>\n");
		cgi_print_text_input_td("src_host", 20, "", 20);
		printf ("</tr>\n");
#endif

		printf("</table>\n");
		cgi_print_submit_button("submitmirror", "Submit");
	}
	else {
		printf ("<input type=\"hidden\" name=\"op\" value=\"2\">\n");
		printf("<table class=\"ctable\">\n");

		mirror_state_get_vdisk_name(&mirror_state, name);
		printf ("<tr>\n");
		printf ("<td>Destination VDisk:</td>\n");
		printf ("<td>%s</td>\n", name);
		printf ("</tr>\n");

		printf ("<tr>\n");
		printf ("<td>Destination Pool:</td>\n");
		printf ("<td>%s</td>\n", mirror_state.mirror_group);
		printf ("</tr>\n");

		in_addr.sin_addr.s_addr = mirror_state.mirror_ipaddr;
		printf ("<tr>\n");
		printf ("<td>Mirror Address:</td>\n");
		printf ("<td>%s</td>\n", inet_ntoa(in_addr.sin_addr));
		printf ("</tr>\n");

		in_addr.sin_addr.s_addr = mirror_state.mirror_src_ipaddr;
		printf ("<tr>\n");
		printf ("<td>Source Address:</td>\n");
		printf ("<td>%s</td>\n", inet_ntoa(in_addr.sin_addr));
		printf ("</tr>\n");

		printf ("<tr>\n");
		printf ("<td>Current Role:</td>\n");
		if (mirror_state.mirror_role == MIRROR_ROLE_MASTER)
			printf ("<td>Master</td>\n");
		else if (mirror_state.mirror_role == MIRROR_ROLE_PEER)
			printf ("<td>Slave</td>\n");
		else
			printf ("<td>Unknown!</td>\n");
		printf ("</tr>\n");

		printf ("<tr>\n");
		printf ("<td>Status:</td>\n");
		get_mirror_status_str(&mirror_state, status);
		printf ("<td>%s</td>\n", status);
		printf ("</tr>\n");

		printf("</table>\n");
		cgi_print_submit_button("deletemirror", "Delete");
	}


	cgi_print_form_end();

	cgi_print_div_end();
	cgi_print_div_end();
	cgi_print_div_end();

	cgi_print_div_trailer();

	cgi_print_body_trailer();
	return 0;
}
