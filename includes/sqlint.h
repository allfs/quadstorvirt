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

#ifndef QUADSTOR_SQLINT_H_
#define QUADSTOR_SQLINT_H_

#include "pgsql.h"

struct tl_blkdevinfo;
PGconn *sql_add_blkdev(struct physdisk *disk, uint32_t bid);
int sql_delete_blkdev(struct tl_blkdevinfo *binfo);
int sql_update_iscsiconf(uint32_t target_id, struct iscsiconf *iscsiconf);
int sql_add_iscsiconf(PGconn *conn, uint32_t target_id, struct iscsiconf *iscsiconf);
struct blist;
int sql_query_blkdevs(struct tl_blkdevinfo *bdev_list[]);
int sql_query_iscsiconf(uint32_t target_id, struct iscsiconf *iscsiconf);
int sql_add_group(PGconn *conn, struct group_info *group_info);
int sql_add_tdisk(PGconn *conn, struct tdisk_info *info);
int sql_delete_group(uint32_t group_id);
int sql_rename_vdisk(uint32_t target_id, char *name);
int sql_rename_pool(uint32_t group_id, char *name);
int sql_delete_tdisk(uint32_t target_id);
int sql_disable_tdisk(uint32_t target_id);
int sql_mark_tdisk_for_deletion(PGconn *conn, uint32_t target_id);
int sql_query_groups(struct group_info *group_list[]);
int sql_query_tdisks(struct tdisk_list *tdisk_list);
int sql_update_tdisk_size(PGconn *conn, struct tdisk_info *info);
int sql_update_tdisk_block(PGconn *conn, struct tdisk_info *tdisk_info);
int sql_update_tdisk(struct tdisk_info *tdisk_info);
int sql_query_mirror_checks(struct mirror_check_list *mirror_check_list);
int sql_add_mirror_check(struct mirror_check_spec *mirror_check_spec);
int sql_delete_mirror_check(struct mirror_check *mirror_check);
int sql_add_fc_rule(struct fc_rule *fc_rule);
int sql_delete_fc_rule(struct fc_rule *fc_rule);
int sql_delete_tdisk_fc_rules(uint32_t target_id);
int sql_query_fc_rules(struct fc_rule_list *fc_rule_list);
#endif
