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
#include <tlsrvapi.h>
#include <pgsql.h>
#include <cluster.h>

PGconn *
sql_add_blkdev(struct physdisk *disk, uint32_t *ret_bid)
{
	char *sqlcmd = NULL;
	int cmdlen;
	struct physdevice *device = (struct physdevice *)disk;
	int retval;
	int error;
	PGconn *conn;
	unsigned char *t10id = NULL;
	unsigned char *naaid = NULL;
	unsigned char *euiid = NULL;
	unsigned char *unknownid = NULL;
	size_t len;
	unsigned char *t10esc = (unsigned char *)"NULL";
	unsigned char *naaesc = (unsigned char *)"NULL";
	unsigned char *euiesc = (unsigned char *)"NULL";
	unsigned char *unesc = (unsigned char *)"NULL";
	uint32_t bid = *ret_bid;

	conn = pgsql_begin();
	if (!conn)
	{
		return NULL;
	}

	retval = -1;
	cmdlen = 512;
	if (device->idflags & ID_FLAGS_T10)
	{
		t10id = PQescapeByteaConn(conn, (const unsigned char *)(&device->t10_id), sizeof(device->t10_id), &len);
		if (!t10id)
		{
			DEBUG_ERR_SERVER("Unable to escape t10 id\n");
			goto err;
		}
		t10esc = t10id;
		cmdlen += len;
	}

	if (device->idflags & ID_FLAGS_NAA)
	{
		naaid = PQescapeByteaConn(conn, (const unsigned char *)(device->naa_id.naa_id), sizeof(device->naa_id.naa_id), &len);
		if (!naaid)
		{
			DEBUG_ERR_SERVER("Unable to escape naa id\n");
			goto err;
		}
		naaesc = naaid;
		cmdlen += len;
	}

	if (device->idflags & ID_FLAGS_EUI)
	{
		euiid = PQescapeByteaConn(conn, (const unsigned char *)(device->eui_id.eui_id), sizeof(device->eui_id.eui_id), &len);
		if (!euiid)
		{
			DEBUG_ERR_SERVER("Unable to escape eui id\n");
			goto err;
		}
		euiesc = euiid;
		cmdlen += len;
	}

	if (device->idflags & ID_FLAGS_UNKNOWN)
	{
		unknownid = PQescapeByteaConn(conn, (const unsigned char *)(device->unknown_id.unknown_id), sizeof(device->unknown_id.unknown_id), &len);
		if (!unknownid)
		{
			DEBUG_ERR_SERVER("Unable to escape unknown id\n");
			goto err;
		}
		unesc = unknownid;
		cmdlen += len;
	}

	sqlcmd = alloc_buffer(cmdlen);
	if (!sqlcmd)
	{
		DEBUG_ERR_SERVER("Memory allocation for %d bytes\n", cmdlen);
		goto err;
	}

	if (!bid) {
		snprintf(sqlcmd, cmdlen, "INSERT INTO PHYSSTOR (VENDOR, PRODUCT, IDFLAGS, T10ID, NAAID, EUI64ID, UNKNOWNID, ISRAID, RAIDDEV, PID) VALUES ('%.8s', '%.16s', '%u', '%s', '%s', '%s', '%s', '%d', '%s', '%d')", device->vendor, device->product, device->idflags, t10esc, naaesc, euiesc, unesc, disk->raiddisk, disk->raiddisk ? device->devname : "", disk->partid);
		bid = pgsql_exec_query3(conn, sqlcmd, 1, &error, "PHYSSTOR", "BID");
	}
	else {
		snprintf(sqlcmd, cmdlen, "INSERT INTO PHYSSTOR (BID, VENDOR, PRODUCT, IDFLAGS, T10ID, NAAID, EUI64ID, UNKNOWNID, ISRAID, RAIDDEV, PID) VALUES ('%u', '%.8s', '%.16s', '%u', '%s', '%s', '%s', '%s', '%d', '%s', '%d')", bid, device->vendor, device->product, device->idflags, t10esc, naaesc, euiesc, unesc, disk->raiddisk, disk->raiddisk ? device->devname : "", disk->partid);
		pgsql_exec_query3(conn, sqlcmd, 0, &error, NULL, NULL);
	}

	free(sqlcmd);

	if (error != 0 || !bid)
	{
		DEBUG_ERR_SERVER("sqlcmd execution failed with error %d bid %u\n", error, bid);
		goto err;
	}
	else
	{
		retval = 0;
		*ret_bid = bid;
	}

err:
	if (t10id)
	{
		PQfreemem(t10id);
	}
	if (naaid)
	{
		PQfreemem(naaid);
	}
	if (euiid)
	{
		PQfreemem(euiid);
	}
	if (unknownid)
	{
		PQfreemem(unknownid);
	}
	if (retval != 0)
	{
		pgsql_rollback(conn);
		return NULL;
	}
	else
	{
		return conn;
	}
}

int
sql_delete_blkdev(struct tl_blkdevinfo *binfo)
{
	char sqlcmd[100];
	int error;

	snprintf(sqlcmd, sizeof(sqlcmd), "DELETE FROM PHYSSTOR WHERE BID='%u'", binfo->bid);
	pgsql_exec_query2(sqlcmd, 0, &error, NULL, NULL);
	if (error != 0)
	{
		DEBUG_ERR_SERVER("Error occurred in executing sqlcmd %s\n", sqlcmd);
		return -1;
	}
	return 0;
}

int
sql_update_iscsiconf(uint32_t target_id, struct iscsiconf *iscsiconf)
{
	char sqlcmd[512];
	int error;

	snprintf(sqlcmd, sizeof(sqlcmd), "UPDATE ISCSICONF SET INCOMINGUSER='%s', INCOMINGPASSWD='%s', OUTGOINGUSER='%s', OUTGOINGPASSWD='%s', IQN='%s' WHERE TDISKID='%u'", iscsiconf->IncomingUser, iscsiconf->IncomingPasswd, iscsiconf->OutgoingUser, iscsiconf->OutgoingPasswd, iscsiconf->iqn, target_id);
	DEBUG_INFO("cmd %s\n", sqlcmd);

	pgsql_exec_query2(sqlcmd, 0, &error, NULL, NULL);
	if (error != 0)
	{
		return -1;
	}
	return 0;
}

int
sql_add_iscsiconf(PGconn *conn, uint32_t target_id, struct iscsiconf *iscsiconf)
{
	char sqlcmd[512];
	int error;

	snprintf(sqlcmd, sizeof(sqlcmd), "INSERT INTO ISCSICONF (TDISKID, INCOMINGUSER, INCOMINGPASSWD, OUTGOINGUSER, OUTGOINGPASSWD, IQN) VALUES ('%u', '%s', '%s', '%s', '%s', '%s')", target_id, iscsiconf->IncomingUser, iscsiconf->IncomingPasswd, iscsiconf->OutgoingUser, iscsiconf->OutgoingPasswd, iscsiconf->iqn);

	pgsql_exec_query3(conn, sqlcmd, 0, &error, NULL, NULL);
	if (error != 0)
	{
		return -1;
	}

	return 0;
}

int
sql_query_iscsiconf(uint32_t target_id, char *name, struct iscsiconf *iscsiconf)
{
	char sqlcmd[512];
	PGconn *conn;
	PGresult *res;
	int nrows;

	snprintf(sqlcmd, sizeof(sqlcmd), "SELECT INCOMINGUSER, INCOMINGPASSWD, OUTGOINGUSER, OUTGOINGPASSWD, IQN FROM ISCSICONF WHERE TDISKID='%u'", target_id);
	res = pgsql_exec_query(sqlcmd, &conn);
	if (res == NULL)
	{
		return -1;
	}
	nrows = PQntuples(res);
	if (nrows != 1)
	{
		DEBUG_ERR_SERVER("Invalid number of table rows %d\n", nrows);
		PQclear(res);
		PQfinish(conn);
		if (!nrows)
		{
			return -2;
		}
		return -1;
	}

	iscsiconf->target_id = target_id;
	memcpy(iscsiconf->IncomingUser, PQgetvalue(res, 0, 0), PQgetlength(res, 0, 1));
	memcpy(iscsiconf->IncomingPasswd, PQgetvalue(res, 0, 1), PQgetlength(res, 0, 1));
	memcpy(iscsiconf->OutgoingUser, PQgetvalue(res, 0, 2), PQgetlength(res, 0, 2));
	memcpy(iscsiconf->OutgoingPasswd, PQgetvalue(res, 0, 3), PQgetlength(res, 0, 3));
	memcpy(iscsiconf->iqn, PQgetvalue(res, 0, 4), PQgetlength(res, 0, 4));
	if (!iscsiconf->iqn[0]) {
		snprintf(iscsiconf->iqn, sizeof(iscsiconf->iqn), "iqn.2006-06.com.quadstor.vdisk.%s", name);
	}
	PQclear(res);
	PQfinish(conn);
	return 0;
}

int
sql_add_fc_rule(struct fc_rule *fc_rule)
{
	char sqlcmd[512];
	int error = -1;

	if (fc_rule->vdisk)
		snprintf(sqlcmd, sizeof(sqlcmd), "INSERT INTO FCCONFIG (WWPN, WWPN1, TDISKID, RULE) VALUES ('%s', '%s', '%u', '%d')", fc_rule->wwpn, fc_rule->wwpn1, fc_rule->vdisk->target_id, fc_rule->rule);
	else
		snprintf(sqlcmd, sizeof(sqlcmd), "INSERT INTO FCCONFIG (WWPN, WWPN1, TDISKID, RULE) VALUES ('%s', '%s', '%u', '%d')", fc_rule->wwpn, fc_rule->wwpn1, 0U, fc_rule->rule);
	pgsql_exec_query2(sqlcmd, 0, &error, NULL, NULL);
	return error;
}

int
sql_delete_fc_rule(struct fc_rule *fc_rule)
{
	char sqlcmd[512];
	int error = -1;

	if (fc_rule->vdisk)
		snprintf(sqlcmd, sizeof(sqlcmd), "DELETE FROM FCCONFIG WHERE WWPN='%s' AND WWPN1='%s' AND TDISKID='%u'", fc_rule->wwpn, fc_rule->wwpn1, fc_rule->vdisk->target_id);
	else
		snprintf(sqlcmd, sizeof(sqlcmd), "DELETE FROM FCCONFIG WHERE WWPN='%s' AND WWPN1='%s' AND TDISKID='%u'", fc_rule->wwpn, fc_rule->wwpn1, 0U);
	pgsql_exec_query2(sqlcmd, 0, &error, NULL, NULL);
	return error;
}

int
sql_delete_tdisk_fc_rules(uint32_t target_id)
{
	char sqlcmd[128];
	int error = -1;

	snprintf(sqlcmd, sizeof(sqlcmd), "DELETE FROM FCCONFIG WHERE TDISKID='%u'", target_id);
	pgsql_exec_query2(sqlcmd, 0, &error, NULL, NULL);
	return error;
}

int
sql_add_mirror_check(struct mirror_check_spec *mirror_check_spec)
{
	char sqlcmd[512];
	int error = -1;

	snprintf(sqlcmd, sizeof(sqlcmd), "INSERT INTO MIRRORCHECK (MIRRORHOST, CHECKTYPE, CHECKVALUE) VALUES ('%s', '%d', '%s')", mirror_check_spec->mirror_host, mirror_check_spec->type, mirror_check_spec->value);
	pgsql_exec_query2(sqlcmd, 0, &error, NULL, NULL);
	return error;
}

int
sql_delete_mirror_check(struct mirror_check *mirror_check)
{
	struct sockaddr_in in_addr;
	char sqlcmd[512];
	int error = -1;

        memset(&in_addr, 0, sizeof(in_addr));
	in_addr.sin_addr.s_addr = mirror_check->mirror_ipaddr;

	snprintf(sqlcmd, sizeof(sqlcmd), "DELETE FROM MIRRORCHECK WHERE MIRRORHOST='%s' AND CHECKTYPE='%d' AND CHECKVALUE='%s'", inet_ntoa(in_addr.sin_addr), mirror_check->type, mirror_check->value);
	pgsql_exec_query2(sqlcmd, 0, &error, NULL, NULL);
	return error;
}

int
sql_query_fc_rules(struct fc_rule_list *fc_rule_list)
{
	char sqlcmd[512];
	PGconn *conn;
	PGresult *res;
	int nrows;
	int i;
	struct fc_rule *fc_rule;
	struct tdisk_info *info;
	uint32_t target_id;

	snprintf(sqlcmd, sizeof(sqlcmd), "SELECT WWPN,WWPN1,TDISKID,RULE FROM FCCONFIG ORDER BY TDISKID");
	res = pgsql_exec_query(sqlcmd, &conn);
	if (res == NULL) {
		DEBUG_ERR_SERVER("Error occurred in executing sqlcmd %s\n", sqlcmd); 
		return -1;
	}

	nrows = PQntuples(res);
	for (i = 0; i < nrows; i++) {
		fc_rule = alloc_buffer(sizeof(*fc_rule));
		if (!fc_rule) {
			PQclear(res);
			PQfinish(conn);
			return -1;
		}

		strcpy(fc_rule->wwpn, PQgetvalue(res, i, 0));
		strcpy(fc_rule->wwpn1, PQgetvalue(res, i, 1));
		target_id = atoi(PQgetvalue(res, i, 2));
		if (target_id) {
			info = find_tdisk(target_id);
			if (!info) {
				free(fc_rule);
				continue;
			}
			fc_rule->vdisk = info;
		}
		fc_rule->rule = atoi(PQgetvalue(res, i, 3));
		TAILQ_INSERT_TAIL(fc_rule_list, fc_rule, q_entry);
	}

	PQclear(res);
	PQfinish(conn);
	return 0;

}

int
sql_query_mirror_checks(struct mirror_check_list *mirror_check_list)
{
	char sqlcmd[512];
	PGconn *conn;
	PGresult *res;
	int nrows;
	int i;
	struct mirror_check *mirror_check;

	snprintf(sqlcmd, sizeof(sqlcmd), "SELECT MIRRORHOST,CHECKTYPE,CHECKVALUE FROM MIRRORCHECK ORDER BY MIRRORHOST");
	res = pgsql_exec_query(sqlcmd, &conn);
	if (res == NULL) {
		DEBUG_ERR_SERVER("Error occurred in executing sqlcmd %s\n", sqlcmd); 
		return -1;
	}

	nrows = PQntuples(res);
	for (i = 0; i < nrows; i++) {
		mirror_check = malloc(sizeof(*mirror_check));
		if (!mirror_check) {
			PQclear(res);
			PQfinish(conn);
			return -1;
		}

		memset(mirror_check, 0, sizeof(*mirror_check));
		if (!ipaddr_valid(PQgetvalue(res, i, 0))) {
			DEBUG_WARN_SERVER("Invalid mirror host %s found\n", PQgetvalue(res, i, 0));
			free(mirror_check);
			continue;
		}
		
		mirror_check->mirror_ipaddr = inet_addr(PQgetvalue(res, i, 0));
		mirror_check->type = atoi(PQgetvalue(res, i, 1));
		strcpy(mirror_check->value, PQgetvalue(res, i, 2));
		TAILQ_INSERT_TAIL(mirror_check_list, mirror_check, q_entry);
	}

	PQclear(res);
	PQfinish(conn);
	return 0;
}

int
sql_query_groups(struct group_list *group_list)
{
	char sqlcmd[512];
	PGconn *conn;
	PGresult *res;
	int nrows;
	int i, error = 0;
	struct group_info *group_info;

	snprintf(sqlcmd, sizeof(sqlcmd), "SELECT GROUPID,NAME,DEDUPEMETA,LOGDATA FROM STORAGEGROUP ORDER BY GROUPID");

	res = pgsql_exec_query(sqlcmd, &conn);
	if (res == NULL) {
		DEBUG_ERR_SERVER("Error occurred in executing sqlcmd %s\n", sqlcmd); 
		return -1;
	}

	nrows = PQntuples(res);
	for (i = 0; i < nrows; i++) {
		group_info = malloc(sizeof(struct group_info));
		if (!group_info) {
			PQclear(res);
			PQfinish(conn);
			return -1;
		}

		memset(group_info, 0, sizeof(struct group_info));
		group_info->group_id = atoi(PQgetvalue(res, i, 0));
		memcpy(group_info->name, PQgetvalue(res, i, 1), PQgetlength(res, i, 1));
		group_info->dedupemeta = atoi(PQgetvalue(res, i, 2));
		group_info->logdata = atoi(PQgetvalue(res, i, 3));
		TAILQ_INIT(&group_info->bdev_list);
		TAILQ_INIT(&group_info->tdisk_list);
		TAILQ_INSERT_TAIL(group_list, group_info, q_entry);
	}

	PQclear(res);
	PQfinish(conn);
	return error;
}

int
sql_query_tdisks(struct tdisk_list *tdisk_list)
{
	char sqlcmd[512];
	PGconn *conn;
	PGresult *res;
	int nrows;
	int i;
	int retval, error = 0;
	struct tdisk_info *tdisk_info;

	snprintf(sqlcmd, sizeof(sqlcmd), "SELECT TDISKID,NAME,DSIZE,BLOCK,DISABLED,DEDUPLICATION,COMPRESSION,VERIFY,INLINE,LBASHIFT,GROUPID FROM TDISK ORDER BY TDISKID");

	res = pgsql_exec_query(sqlcmd, &conn);
	if (res == NULL)
	{
		DEBUG_ERR_SERVER("Error occurred in executing sqlcmd %s\n", sqlcmd); 
		return -1;
	}

	nrows = PQntuples(res);
	for (i = 0; i < nrows; i++)
	{
		tdisk_info = alloc_buffer(sizeof(struct tdisk_info));
		if (!tdisk_info) {
			PQclear(res);
			PQfinish(conn);
			return -1;
		}

		tdisk_info->tl_id = 0xFFFF;
		tdisk_info->vhba_id = -1;
		tdisk_info->iscsi_tid = -1;

		tdisk_info->target_id = atoi(PQgetvalue(res, i, 0));
		memcpy(tdisk_info->name, PQgetvalue(res, i, 1), PQgetlength(res, i, 1));
		tdisk_info->size = strtoull(PQgetvalue(res, i, 2), NULL, 16);
		tdisk_info->block = strtoull(PQgetvalue(res, i, 3), NULL, 16);
		tdisk_info->disabled = atoi(PQgetvalue(res, i, 4));
		tdisk_info->enable_deduplication = atoi(PQgetvalue(res, i, 5));
		tdisk_info->enable_compression = atoi(PQgetvalue(res, i, 6));
		tdisk_info->enable_verify = atoi(PQgetvalue(res, i, 7));
		tdisk_info->force_inline = atoi(PQgetvalue(res, i, 8));
		tdisk_info->lba_shift = atoi(PQgetvalue(res, i, 9));
		tdisk_info->group_id = strtoull(PQgetvalue(res, i, 10), NULL, 10);
		retval = sql_query_iscsiconf(tdisk_info->target_id, tdisk_info->name, &tdisk_info->iscsiconf);
		if (retval != 0) {
			free(tdisk_info);
			error = -1;
			break;
		}

		TAILQ_INSERT_TAIL(tdisk_list, tdisk_info, q_entry);
	}

	PQclear(res);
	PQfinish(conn);
	return error;
}

int
sql_query_blkdevs(struct blist *bdev_list)
{
	char sqlcmd[512];
	PGconn *conn;
	PGresult *res;
	int nrows;
	int i;
	struct tl_blkdevinfo *binfo;

	snprintf(sqlcmd, sizeof(sqlcmd), "SELECT BID,VENDOR,PRODUCT,IDFLAGS,T10ID::bytea,NAAID::bytea,EUI64ID::bytea,UNKNOWNID::bytea,PID,ISRAID,RAIDDEV FROM PHYSSTOR");

	res = pgsql_exec_query(sqlcmd, &conn);
	if (res == NULL)
	{
		DEBUG_ERR_SERVER("Error occurred in executing sqlcmd %s\n", sqlcmd); 
		return -1;
	}

	nrows = PQntuples(res);
	for (i = 0; i < nrows; i++)
	{
		struct physdisk *disk;
		struct physdevice *device;

		binfo = malloc(sizeof(struct tl_blkdevinfo));
		if (!binfo)
		{
			DEBUG_ERR_SERVER("Unable to alloc a new blkdev struct\n");
			goto err;
		}

		memset(binfo, 0, sizeof(struct tl_blkdevinfo));
		disk = &binfo->disk;
		device = (struct physdevice *)(disk);
		strcpy(device->devname, "none");
		binfo->bid = strtoull(PQgetvalue(res, i, 0), NULL, 10);
		disk->partid =  strtoull(PQgetvalue(res, i, 8), NULL, 10); 
		disk->raiddisk = strtoull(PQgetvalue(res, i, 9), NULL, 10);
		if (disk->raiddisk)
		{
			strcpy(device->devname, PQgetvalue(res, i, 10));
		}
		if (PQgetlength(res, i, 1) != 8)
		{
			DEBUG_ERR_SERVER("Got invalid length for vendor %d\n", PQgetlength(res, i, 1));
			goto err;
		}
		memcpy(device->vendor, PQgetvalue(res, i, 1), 8);
		if (PQgetlength(res, i, 2) != 16)
		{
			DEBUG_ERR_SERVER("Got invalid length for product %d\n", PQgetlength(res, i, 2));
			goto err;
		}
		memcpy(device->product, PQgetvalue(res, i, 2), 16);

		device->idflags = strtoul(PQgetvalue(res, i, 3), NULL, 10);

		if (device->idflags & ID_FLAGS_T10)
		{
			uint8_t *ptr;
			size_t len;

			ptr = PQunescapeBytea((const unsigned char *)PQgetvalue(res, i, 4), &len);
			if (!ptr)
			{
				DEBUG_ERR_SERVER("Unescaping binary string failed\n");
				goto err;
			}

			if (len != sizeof(struct device_t10_id))
			{
				DEBUG_ERR_SERVER("Got invalid length for t10id %d\n", (int)len);
				PQfreemem(ptr);
				goto err;
			}
			memcpy(&device->t10_id, ptr, sizeof(struct device_t10_id));
			PQfreemem(ptr);
		}

		if (device->idflags & ID_FLAGS_NAA)
		{
			uint8_t *ptr;
			size_t len;

			ptr = PQunescapeBytea((const unsigned char *)PQgetvalue(res, i, 5), &len);
			if (!ptr)
			{
				DEBUG_ERR_SERVER("Unescaping binary string failed\n");
				goto err;
			}

			if (len != sizeof(device->naa_id.naa_id))
			{
				DEBUG_ERR_SERVER("Got invalid length for naaid %d\n", (int)len);
				PQfreemem(ptr);
				goto err;
			}
			memcpy(device->naa_id.naa_id, ptr, sizeof(device->naa_id.naa_id));
			PQfreemem(ptr);
		}

		if (device->idflags & ID_FLAGS_EUI)
		{
			uint8_t *ptr;
			size_t len;

			ptr = PQunescapeBytea((const unsigned char *)PQgetvalue(res, i, 6), &len);
			if (!ptr)
			{
				DEBUG_ERR_SERVER("Unescaping binary string failed\n");
				goto err;
			}

			if (len != sizeof(device->eui_id.eui_id))
			{
				DEBUG_ERR_SERVER("Got invalid length for euiid %d\n", (int)len);
				PQfreemem(ptr);
				goto err;
			}
			memcpy(device->eui_id.eui_id, ptr, sizeof(device->eui_id.eui_id));
			PQfreemem(ptr);
		}

		if (device->idflags & ID_FLAGS_UNKNOWN)
		{
			uint8_t *ptr;
			size_t len;

			ptr = PQunescapeBytea((const unsigned char *)PQgetvalue(res, i, 7), &len);
			if (!ptr)
			{
				DEBUG_ERR_SERVER("Unescaping binary string failed\n");
				goto err;
			}

			if (len != sizeof(device->unknown_id.unknown_id))
			{
				DEBUG_ERR_SERVER("Got invalid length for unknownid %d\n", (int)len);
				PQfreemem(ptr);
				goto err;
			}
			memcpy(device->unknown_id.unknown_id, ptr, sizeof(device->unknown_id.unknown_id));
			PQfreemem(ptr);
		}

		TAILQ_INSERT_TAIL(bdev_list, binfo, q_entry); 
	}

	PQclear(res);
	PQfinish(conn);
	return 0;
err:
	if (binfo)
	{
		free(binfo);
	}
	PQclear(res);
	PQfinish(conn);
	return -1;
}

int
sql_update_tdisk_size(PGconn *conn, struct tdisk_info *tdisk_info)
{
	char sqlcmd[128];
	int error = -1;

	snprintf(sqlcmd, sizeof(sqlcmd), "UPDATE TDISK SET DSIZE='%"PRIx64"' WHERE TDISKID='%u'", tdisk_info->size, tdisk_info->target_id);
	pgsql_exec_query3(conn, sqlcmd, 0, &error, NULL, NULL);
	if (error < 0)
	{
		DEBUG_ERR_SERVER("Error occurred in executing sqlcmd %s\n", sqlcmd);
		return -1;
	}
	return 0;
}

int
sql_update_tdisk_block(PGconn *conn, struct tdisk_info *tdisk_info)
{
	char sqlcmd[128];
	int error = -1;

	snprintf(sqlcmd, sizeof(sqlcmd), "UPDATE TDISK SET BLOCK='%"PRIx64"' WHERE TDISKID='%u'", tdisk_info->block, tdisk_info->target_id);
	pgsql_exec_query3(conn, sqlcmd, 0, &error, NULL, NULL);
	if (error < 0)
	{
		DEBUG_ERR_SERVER("Error occurred in executing sqlcmd %s\n", sqlcmd);
		return -1;
	}
	return 0;
}

int
sql_update_tdisk(struct tdisk_info *tdisk_info)
{
	char sqlcmd[128];
	int error = -1;

	snprintf(sqlcmd, sizeof(sqlcmd), "UPDATE TDISK SET DEDUPLICATION='%d',COMPRESSION='%d',VERIFY='%d',INLINE='%d' WHERE TDISKID='%u'", tdisk_info->enable_deduplication, tdisk_info->enable_compression, tdisk_info->enable_verify, tdisk_info->force_inline, tdisk_info->target_id);
	pgsql_exec_query2(sqlcmd, 0, &error, NULL, NULL);
	if (error < 0)
	{
		DEBUG_ERR_SERVER("Error occurred in executing sqlcmd %s\n", sqlcmd);
		return -1;
	}
	return 0;

}

int
sql_rename_vdisk(uint32_t target_id, char *name)
{
	char sqlcmd[128];
	int error = -1;

	snprintf(sqlcmd, sizeof(sqlcmd), "UPDATE TDISK SET NAME='%s' WHERE TDISKID='%u'", name, target_id);
	pgsql_exec_query2(sqlcmd, 0, &error, NULL, NULL);
	if (error < 0)
	{
		DEBUG_ERR_SERVER("Error occurred in executing sqlcmd %s\n", sqlcmd);
		return -1;
	}
	return 0;
}

int
sql_rename_pool(uint32_t group_id, char *name)
{
	char sqlcmd[128];
	int error = -1;

	snprintf(sqlcmd, sizeof(sqlcmd), "UPDATE STORAGEGROUP SET NAME='%s' WHERE GROUPID='%u'", name, group_id);
	pgsql_exec_query2(sqlcmd, 0, &error, NULL, NULL);
	if (error < 0)
	{
		DEBUG_ERR_SERVER("Error occurred in executing sqlcmd %s\n", sqlcmd);
		return -1;
	}
	return 0;
}

int
sql_delete_group(uint32_t group_id)
{
	char sqlcmd[128];
	int error = -1;

	snprintf(sqlcmd, sizeof(sqlcmd), "DELETE FROM STORAGEGROUP WHERE GROUPID='%u'", group_id);
	pgsql_exec_query2(sqlcmd, 0, &error, NULL, NULL);
	if (error < 0)
	{
		DEBUG_ERR_SERVER("Error occurred in executing sqlcmd %s\n", sqlcmd);
		return -1;
	}
	return 0;

}

int
sql_delete_tdisk(uint32_t target_id)
{
	char sqlcmd[128];
	int error = -1;

	snprintf(sqlcmd, sizeof(sqlcmd), "DELETE FROM TDISK WHERE TDISKID='%u'", target_id);
	pgsql_exec_query2(sqlcmd, 0, &error, NULL, NULL);
	if (error < 0)
	{
		DEBUG_ERR_SERVER("Error occurred in executing sqlcmd %s\n", sqlcmd);
		return -1;
	}
	return 0;
}

int
sql_mark_tdisk_for_deletion(PGconn *conn, uint32_t target_id)
{
	char sqlcmd[128];
	int error = -1;

	snprintf(sqlcmd, sizeof(sqlcmd), "UPDATE TDISK SET DISABLED='%d' WHERE TDISKID='%u'", VDISK_DELETING, target_id);
	pgsql_exec_query3(conn, sqlcmd, 0, &error, NULL, NULL);
	if (error < 0)
	{
		DEBUG_ERR_SERVER("Error occurred in executing sqlcmd %s\n", sqlcmd);
		return -1;
	}
	return 0;
}

int
sql_disable_tdisk(uint32_t target_id)
{
	char sqlcmd[128];
	int error = -1;

	snprintf(sqlcmd, sizeof(sqlcmd), "UPDATE TDISK SET DISABLED='%d', NAME='' WHERE TDISKID='%u'", VDISK_DELETED, target_id);
	pgsql_exec_query2(sqlcmd, 0, &error, NULL, NULL);
	if (error < 0)
	{
		DEBUG_ERR_SERVER("Error occurred in executing sqlcmd %s\n", sqlcmd);
		return -1;
	}
	return 0;
}

int
sql_add_group(PGconn *conn, struct group_info *group_info)
{
	char sqlcmd[256];
	int error = -1;

	if (!group_info->group_id) {
		snprintf(sqlcmd, sizeof(sqlcmd), "INSERT INTO STORAGEGROUP (NAME, DEDUPEMETA, LOGDATA) VALUES('%s', '%d', '%d')", group_info->name, group_info->dedupemeta, group_info->logdata);
		group_info->group_id = pgsql_exec_query3(conn, sqlcmd, 1, &error, "STORAGEGROUP", "GROUPID");
	}
	else {
		snprintf(sqlcmd, sizeof(sqlcmd), "INSERT INTO STORAGEGROUP (GROUPID, NAME, DEDUPEMETA, LOGDATA) VALUES('%u', '%s', '%d', '%d')", group_info->group_id, group_info->name, group_info->dedupemeta, group_info->logdata);
		pgsql_exec_query3(conn, sqlcmd, 0, &error, NULL, NULL);
	}

	if (!group_info->group_id || error != 0)
		return -1;
	else
		return 0;
}

int
sql_add_tdisk(PGconn *conn, struct tdisk_info *info)
{
	char sqlcmd[512];
	int error = -1;

	if (!info->target_id) {
		snprintf(sqlcmd, sizeof(sqlcmd), "INSERT INTO TDISK (NAME, DSIZE, BLOCK, DEDUPLICATION, COMPRESSION, VERIFY, INLINE, LBASHIFT, GROUPID) VALUES ('%s', '%"PRIx64"', '%"PRIx64"', '%d', '%d', '%d', '%d', '%d', '%u')", info->name, info->size, info->block, info->enable_deduplication, info->enable_compression, info->enable_verify, info->force_inline, info->lba_shift, info->group_id);
		info->target_id = pgsql_exec_query3(conn, sqlcmd, 1, &error, "TDISK", "TDISKID");
	}
	else {
		snprintf(sqlcmd, sizeof(sqlcmd), "INSERT INTO TDISK (TDISKID, NAME, DSIZE, BLOCK, DEDUPLICATION, COMPRESSION, VERIFY, INLINE, LBASHIFT, GROUPID) VALUES ('%u', '%s', '%"PRIx64"', '%"PRIx64"', '%d', '%d', '%d', '%d', '%d', '%u')", info->target_id, info->name, info->size, info->block, info->enable_deduplication, info->enable_compression, info->enable_verify, info->force_inline, info->lba_shift, info->group_id);
		pgsql_exec_query3(conn, sqlcmd, 0, &error, NULL, NULL);
	}
	if (info->target_id == 0 || error != 0)
		return -1;
	return 0;
}
