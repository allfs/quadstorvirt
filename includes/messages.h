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

#ifndef QS_MESSAGES_H_
#define QS_MESSAGES_H_

/* Msg format would be of the form
 * header message indicator 
 * msglen: <message len>
 * msgid: <msgid>
 * msg body
 */

enum {
	MSG_ID_LOAD_CONF		= 0x01,
	MSG_ID_UNLOAD_CONF,
	MSG_ID_GET_CONFIGURED_DISKS,
	MSG_ID_LIST_DISKS,
	MSG_ID_ADD_DISK,
	MSG_ID_DELETE_DISK,
	MSG_ID_RESCAN_DISKS,
	MSG_ID_REBOOT_SYSTEM,
	MSG_ID_GET_ISCSICONF,
	MSG_ID_SET_ISCSICONF,
	MSG_ID_RUN_DIAGNOSTICS,
	MSG_ID_DISK_CHECK,
	MSG_ID_GET_UID,
	MSG_ID_ADD_TDISK,
	MSG_ID_LIST_TDISK,
	MSG_ID_DELETE_TDISK,
	MSG_ID_MODIFY_TDISK,
	MSG_ID_TDISK_STATS,
	MSG_ID_RESET_LOGS,
	MSG_ID_SERVER_STATUS,
	MSG_ID_LIST_CLONES,
	MSG_ID_LIST_CLONES_PRUNE,
	MSG_ID_START_CLONE,
	MSG_ID_CANCEL_CLONE,
	MSG_ID_LIST_MIRRORS,
	MSG_ID_LIST_MIRRORS_PRUNE,
	MSG_ID_START_MIRROR,
	MSG_ID_CANCEL_MIRROR,
	MSG_ID_VDISK_RESIZE,
	MSG_ID_ADD_GROUP,
	MSG_ID_DELETE_GROUP,
	MSG_ID_LIST_GROUP,
	MSG_ID_HA_CONFIG,
	MSG_ID_LIST_GROUP_CONFIGURED,
	MSG_ID_REMOVE_MIRROR,
	MSG_ID_ADD_MIRROR_CHECK,
	MSG_ID_REMOVE_MIRROR_CHECK,
	MSG_ID_LIST_MIRROR_CHECKS,
	MSG_ID_ADD_FC_RULE,
	MSG_ID_REMOVE_FC_RULE,
	MSG_ID_LIST_FC_RULES,
	MSG_ID_GET_POOL_CONFIGURED_DISKS,
	MSG_ID_LIST_POOL_TDISK,
	MSG_ID_GET_MIRRORCONF,
	MSG_ID_UNMAP_CONFIG,
	MSG_ID_RENAME_POOL,
	MSG_ID_GET_VDISKCONF,
	MSG_ID_SET_VDISKCONF,
	MSG_ID_GET_DISKCONF,
	MSG_ID_SET_DISKCONF,
	MSG_ID_TDISK_STATS_RESET,
	MSG_ID_DEV_MAPPING,
	MSG_ID_RESTART_SERVICE,
	MSG_ID_SET_VDISK_ROLE,
	MSG_ID_LIST_SYNC_MIRRORS,
	MSG_ID_SET_SERIALNUMBER,
};

#define MSG_STR_INVALID_MSG  "Invalid Message data or ID"
#define MSG_STR_COMMAND_FAILED  "Command Failed"
#define MSG_STR_COMMAND_SUCCESS  "Command Success"
#define MSG_STR_SERVER_BUSY  "Server Busy"
#define MSG_STR_AUTH_FAILURE  "Authentication failure"

/* Response Codes */
enum {
	MSG_RESP_OK		= 0x0000,
	MSG_RESP_ERROR		= 0x0001,
	MSG_RESP_BUSY		= 0x0002,
	MSG_RESP_INVALID	= 0x0003,
	MSG_RESP_AUTH_FAILURE	= 0x0004,
	MSG_RESP_INPROGRESS	= 0x0005,
};

#endif /* MESSAGES_H_ */
