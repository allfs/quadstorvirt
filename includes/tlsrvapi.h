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

#ifndef TLSRVAPI_H_
#define TLSRVAPI_H_

#include <physlib.h>


#include <apicommon.h>

int tl_server_process_request(int fd, struct sockaddr_un *client_addr);
void tl_notify(int msgtype, char *msg);
void tl_log(char *logfile, char *msg, char *sev);
int main_server_start(pthread_t *thread_id);
int tl_server_register_pid(void);
int tl_server_unload(void);
int load_configured_disks(void);
int load_configured_tdisks(void);
int target_name_exists(char *targetname);
struct group_info * find_group_by_name(char *name);
struct group_info * find_group(uint32_t group_id);

#endif
