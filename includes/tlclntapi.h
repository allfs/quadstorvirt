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

#ifndef TLCLNTAPI_H_
#define TLCLNTAPI_H_

#include <apicommon.h>

int tl_client_load_conf(void);
int tl_client_reset_logs(void);
int tl_client_unload_conf(void);
int tl_client_clear_log(char *logfile);
int tl_client_add_disk(char *dev, int comp, int log_disk, int ha_disk, uint32_t group_id, char *reply);
int tl_client_delete_disk(char *dev, char *reply);
int tl_client_list_generic(char *tempfile, int msg_id);
int tl_client_rescan_disks(void);
int tl_client_reboot_system(int msg_id);
struct iscsiconf;
struct vdiskconf;
int tl_client_set_iscsiconf(struct iscsiconf *iscsiconf, char *reply);
int tl_client_get_iscsiconf(uint32_t target_id, struct iscsiconf *iscsiconf);
int tl_client_get_vdiskconf(uint32_t target_id, struct vdiskconf *vdiskconf);
int tl_client_set_vdiskconf(struct vdiskconf *vdiskconf, char *reply);
int tl_client_get_diskconf(uint32_t bid, struct physdisk *disk);
int tl_client_set_diskconf(struct physdisk *physdisk, char *reply);
int tl_client_get_mirrorconf(uint32_t target_id, struct mirror_state *mirror_state);
int tl_client_list_groups(struct group_list *group_list, int msg_id);
int tl_client_list_disks(struct d_list *d_list, int msg_id);
int tl_client_list_vdisks(struct tdisk_list *tdisk_list, int msg_id);
int tl_client_add_group(char *groupname, int dedupemeta, int logdata, char *reply);
int tl_client_add_tdisk(char *targetname, uint64_t targetsize, int lba_shift, uint32_t group_id, char *reply);
int tl_client_modify_tdisk(uint32_t target_id, int dedupe, int comp, int verify, int force_inline);
int tl_client_rename_pool(uint32_t group_id, char *name, char *reply);
int tl_client_delete_group(uint32_t group_id);
int tl_client_delete_tdisk(uint32_t target_id);
int tl_client_tdisk_stats_reset(uint32_t target_id);
int tl_client_vdisk_resize(char *src, unsigned long long size, int force, char *reply);
int tl_client_set_vdisk_role(char *src, int mirror_role, int force, char *reply);
int tl_client_bdev_config(uint32_t bid, int msg_id, int mark, char *reply);
int tl_client_clone_op(struct clone_spec *clone_spec, char *reply, int msg_id);
int tl_client_mirror_op(struct mirror_spec *mirror_spec, char *reply, int msg_id);
int tl_client_mirror_check_op(struct mirror_check_spec *mirror_check_spec, char *reply, int msg_id);
int tl_client_fc_rule_op(struct fc_rule_spec *fc_rule_spec, char *reply, int msg_id);
int tl_client_get_string(char *reply, int msg_id);
int tl_client_list_target_generic(uint32_t target_id, char *tempfile, int msg_id);
int tl_client_get_data(int msg_id, void *reply, int msg_len);
int tl_client_send_data(int msg_id, void *msg_data, int msg_len);
int tl_client_dev_mapping(char *path, char *reply);
int tl_client_get_target_id(char *name);
int tl_client_get_group_id(char *name);

#endif /* TLCLNTAPI_H_ */
