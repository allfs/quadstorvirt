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

#include "ietadm.h"
#include <sqlint.h>
#include "cluster.h"

int 
ietadm_default_settings(void *conn, struct tdisk_info *tdisk_info, struct iscsiconf *srcconf)
{
	int retval;
	struct iscsiconf *iscsiconf = &tdisk_info->iscsiconf;

	memset(iscsiconf, 0, sizeof(struct iscsiconf));

	iscsiconf->target_id = tdisk_info->target_id;
	if (!srcconf) {
		strcpy(iscsiconf->IncomingUser, "");
		strcpy(iscsiconf->IncomingPasswd, "");
		strcpy(iscsiconf->OutgoingUser, "");
		strcpy(iscsiconf->OutgoingPasswd, "");
		snprintf(iscsiconf->iqn, sizeof(iscsiconf->iqn), "iqn.2006-06.com.quadstor.vdisk.%s", tdisk_info->name);
	}
	else {
		strcpy(iscsiconf->IncomingUser, srcconf->IncomingUser);
		strcpy(iscsiconf->IncomingPasswd, srcconf->IncomingPasswd);
		strcpy(iscsiconf->OutgoingUser, srcconf->OutgoingUser);
		strcpy(iscsiconf->OutgoingPasswd, srcconf->OutgoingPasswd);
		strcpy(iscsiconf->iqn, srcconf->iqn);
	}

	retval = sql_add_iscsiconf(conn, tdisk_info->target_id, iscsiconf);
	return retval;
}

int
ietadm_mod_target(int tid, struct iscsiconf *iscsiconf, struct iscsiconf *oldconf)
{
	char cmd[512];
	int retval;
	char user[40], passwd[40];

	if (tid <= 0)
		return 0;

	if (oldconf && strcmp(iscsiconf->iqn, oldconf->iqn)) {
		snprintf(cmd, sizeof(cmd), "%s --op rename --tid=%d --params Name=%s", IETADM_PATH, tid, iscsiconf->iqn);
		DEBUG_INFO("iqn change cmd is %s\n", iscsiconf->iqn);
		retval  = system(cmd);
		if (retval != 0) {
			DEBUG_WARN_SERVER("Changing target iqn failed: cmd is %s %d %s\n", cmd, errno, strerror(errno));
			return -1;
		}
	}

	if (strlen(iscsiconf->IncomingUser) > 0) {
		strcpy(user, iscsiconf->IncomingUser);
		strcpy(passwd, iscsiconf->IncomingPasswd);
		snprintf(cmd, sizeof(cmd), "%s --op new --tid=%d --user --params=IncomingUser=%s,Password=%s\n", IETADM_PATH, tid, user, passwd);
		retval  = system(cmd);
		if (retval != 0) {
			DEBUG_WARN_SERVER("Changing target user configuration failed: cmd is %s %d %s\n", cmd, errno, strerror(errno));
			return -1;
		}
	}

	if (oldconf && strlen(oldconf->IncomingUser) > 0) {
		strcpy(user, oldconf->IncomingUser);
		strcpy(passwd, oldconf->IncomingPasswd);
		snprintf(cmd, sizeof(cmd), "%s --op delete --tid=%d --user --params=IncomingUser=%s,Password=%s\n", IETADM_PATH, tid, user, passwd);
		retval  = system(cmd);
		if (retval != 0) {
			DEBUG_WARN_SERVER("Changing target user configuration failed: cmd is %s %d %s\n", cmd, errno, strerror(errno));
			return -1;
		}
	}

	if (oldconf && strlen(oldconf->OutgoingUser) > 0) {
		strcpy(user, oldconf->OutgoingUser);
		strcpy(passwd, oldconf->OutgoingPasswd);
		snprintf(cmd, sizeof(cmd), "%s --op delete --tid=%d --user --params=OutgoingUser=%s,Password=%s\n", IETADM_PATH, tid, user, passwd);
		retval  = system(cmd);
		if (retval != 0) {
			DEBUG_WARN_SERVER("Changing target user configuration failed: cmd is %s %d %s\n", cmd, errno, strerror(errno));
			return -1;
		}
	}

	if (strlen(iscsiconf->OutgoingUser) > 0) {
		strcpy(user, iscsiconf->OutgoingUser);
		strcpy(passwd, iscsiconf->OutgoingPasswd);
		snprintf(cmd, sizeof(cmd), "%s --op new --tid=%d --user --params=OutgoingUser=%s,Password=%s\n", IETADM_PATH, tid, user, passwd);
		retval  = system(cmd);
		if (retval != 0) {
			DEBUG_WARN_SERVER("Changing target user configuration failed: cmd is %s %d %s\n", cmd, errno, strerror(errno));
			return -1;
		}
	}

	return 0;
}

int
ietadm_qload_done(void)
{
	char cmd[128];
	int retval;

	snprintf(cmd, sizeof(cmd), "%s -q\n", IETADM_PATH);
	retval = system(cmd);
	if (retval != 0) {
		DEBUG_ERR_SERVER("ietadm returned not zero status %d cmd is %s %d %s\n", retval, cmd, errno, strerror(errno));
	}
	return retval;
}

int
ietadm_add_target(int tid, struct iscsiconf *iscsiconf)
{
	char cmd[512];
	int retval;

	if (tid <= 0)
		return 0;

	snprintf(cmd, sizeof(cmd), "%s --op new --tid=%d --params Name=%s\n", IETADM_PATH, tid, iscsiconf->iqn);
	retval = system(cmd);

	if (retval != 0)
	{
		DEBUG_ERR_SERVER("ietadm returned not zero status %d cmd is %s %d %s\n", retval, cmd, errno, strerror(errno));
		return retval;	
	}

	if (iscsiconf) {
		retval = ietadm_mod_target(tid, iscsiconf, NULL);
	}
	return retval;	
}

int
ietadm_delete_target(int tid)
{
	char cmd[128];
	int retval;

	if (tid <= 0)
		return 0;

	snprintf(cmd, sizeof(cmd), "%s --op delete --tid=%d > /dev/null 2>&1", IETADM_PATH, tid);
	retval = system(cmd);
	if (retval != 0)
	{
		DEBUG_ERR_SERVER("ietadm returned non zero status %d for tid %d cmd %s %d %s\n", retval, tid, cmd, errno, strerror(errno));
		return -1;
	}

	return 0;
}

int
ietadm_delete(void)
{
	char cmd[128];

	snprintf(cmd, sizeof(cmd), "%s --op delete > /dev/null 2>&1", IETADM_PATH);
	system(cmd);
	return 0;
}
