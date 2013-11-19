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

#ifndef QS_CLUSTER_H_
#define QS_CLUSTER_H_
#include <apicommon.h>
#include <cluster_common.h>

struct group_spec {
	uint32_t group_id;
	char name[GROUP_MAX_NAME_LEN];
	int dedupemeta;
	int logdata;
};

struct vdisk_spec {
	uint64_t block;
	uint64_t size;
	char name[TDISK_MAX_NAME_LEN];
	char serialnumber[36];
	uint32_t target_id;
	uint32_t group_id;
	uint8_t enable_deduplication;
	uint8_t enable_compression;
	uint8_t enable_verify;
	uint8_t force_inline;
	uint8_t lba_shift;
	uint8_t online;
};
  
struct bdev_spec {
	char vendor[8];
	char product[16];
	char serialnumber[256];
	int serial_len;
	uint32_t group_id;
	uint32_t idflags;
	uint16_t bid;
	uint8_t  ddmaster;
	uint8_t  pad1;
	uint32_t partid;
	char identifier[128];
} __attribute__ ((__packed__));

enum {
	/* Messages sent from client to controller */

	NODE_MSG_REGISTER,
	NODE_MSG_UNREGISTER,
	NODE_MSG_LIST_BDEV,
	NODE_MSG_LIST_VDISK,
	NODE_MSG_ISCSI_CONF,
	NODE_MSG_PING,

	/* Message sent from controller to client */
	NODE_MSG_VDISK_ADDED,
	NODE_MSG_VDISK_REMOVED,
	NODE_MSG_VDISK_MODIFIED,
	NODE_MSG_VDISK_DISABLE,
	NODE_MSG_VDISK_ATTACHED,
	NODE_MSG_BDEV_ADDED,
	NODE_MSG_BDEV_REMOVED,
	NODE_MSG_CONTROLLER_SHUTDOWN,

	/* Recv defs */
	NODE_MSG_MIRROR_START,
	NODE_MSG_MIRROR_STATUS,
	NODE_MSG_MIRROR_END,
	NODE_MSG_CLONE,
	NODE_MSG_CLONE_STATUS,
	NODE_MSG_NEW_VDISK,

	NODE_MSG_LIST_GROUP,
	NODE_MSG_GROUP_ADDED,
	NODE_MSG_GROUP_REMOVED,
};

int node_controller_init(void);
int node_controller_init_pre(void);
int node_recv_init(void);
int node_client_init(void);
void tl_server_node_config(struct tl_comm *comm, struct tl_msg *msg);
int tl_server_start_mirror(struct tl_comm *comm, struct tl_msg *msg);
int tl_server_remove_mirror(struct tl_comm *comm, struct tl_msg *msg);
int tl_server_cancel_mirror(struct tl_comm *comm, struct tl_msg *msg);
int tl_server_list_mirrors(struct tl_comm *comm, struct tl_msg *msg, int prune);
int sys_rid_init(int nosql);
void vhba_add_device(int vhba_id);
struct tl_blkdevinfo * blkdev_new(char *devname);
int gen_rid(char *rid);
void vhba_remove_device(struct tdisk_info *info);
void node_controller_bdev_added(struct tl_blkdevinfo *blkdev);
void node_controller_bdev_removed(struct tl_blkdevinfo *blkdev);
void node_controller_group_added(struct group_info *info);
void node_controller_group_removed(struct group_info *info);
void node_controller_vdisk_added(struct tdisk_info *info);
void node_controller_vdisk_attached(struct tdisk_info *info);
void node_controller_vdisk_modified(struct tdisk_info *info);
void node_controller_vdisk_removed(struct tdisk_info *info);
void node_controller_vdisk_disable(struct tdisk_info *info);

void node_resp_data(struct tl_comm *comm, struct tl_msg *msg);
void node_resp_success(struct tl_comm *comm, struct tl_msg *msg);
void node_resp_status(struct tl_comm *comm, struct tl_msg *msg, int msg_status);
void node_resp_error(struct tl_comm *comm, struct tl_msg *msg);
void tl_server_msg_failure2(struct tl_comm *comm, struct tl_msg *msg, char *newmsg);
void tl_server_msg_failure(struct tl_comm *comm, struct tl_msg *msg);
void tl_server_msg_success(struct tl_comm *comm, struct tl_msg *msg);
#define node_resp_error_msg tl_server_msg_failure2

struct tdisk_info * find_tdisk_by_name(char *name);
struct tdisk_info * find_tdisk(uint32_t target_id);
struct tdisk_info *add_target(struct group_info *group_info, char *targetname, uint64_t targetsize, int lba_shift, int enable_deduplication, int enable_compression, int enable_verify, int force_inline, char *serialnumber, char *err, int attach, struct iscsiconf *srcconf);
int __tl_server_start_clone(char *src, char *dest, char *pool, char *errmsg, uint64_t *job_id);
int attach_tdisk(struct tdisk_info *info);
void group_conf_fill(struct group_conf *group_conf, struct group_info *group_info);

struct clone_info {
	char dest[40];
	char src[40];
	char errmsg[256];
	uint32_t dest_target_id;
	uint32_t src_target_id;
	uint32_t progress;
	uint32_t status;
	uint64_t job_id;
	int op;
	int remote;
	int attached;
	struct job_stats stats;
	TAILQ_ENTRY(clone_info) c_list;
};
TAILQ_HEAD(clone_info_list, clone_info);
extern pthread_mutex_t daemon_lock;
extern pthread_mutex_t mirror_lock;
int group_name_exists(char *groupname);
void tdisk_add(struct group_info *group_info, struct tdisk_info *tdisk_info);
void tdisk_remove(struct tdisk_info *tdisk_info);
void tdisk_group_insert(struct group_info *group_info, struct tdisk_info *tdisk_info);
void bdev_remove(struct tl_blkdevinfo *blkdev);
void bdev_add(struct group_info *group_info, struct tl_blkdevinfo *blkdev);
void bdev_group_insert(struct group_info *group_info, struct tl_blkdevinfo *blkdev);
struct tl_blkdevinfo * blkdev_find(uint32_t bid);

int tl_server_remove_mirror_check(struct tl_comm *comm, struct tl_msg *msg);
int tl_server_add_mirror_check(struct tl_comm *comm, struct tl_msg *msg);
int tl_server_list_mirror_checks(struct tl_comm *comm, struct tl_msg *msg);

int tl_server_list_fc_rules(struct tl_comm *comm, struct tl_msg *msg);
int tl_server_add_fc_rule(struct tl_comm *comm, struct tl_msg *msg);
int tl_server_remove_fc_rule(struct tl_comm *comm, struct tl_msg *msg);

void fc_rule_config_fill(struct fc_rule *fc_rule, struct fc_rule_config *fc_rule_config);
int tl_server_remove_tdisk_fc_rules(struct tdisk_info *tdisk_info);
int node_usr_init(void);
uint64_t get_job_id(void);

int is_ignore_dev(char *devname);

static inline char *
strip_space(char *tmp)
{
	char *ret = NULL;

	while (tmp[0]) {
		if (tmp[0] == ' ')
			tmp[0] = 0;
		else if (!ret)
			ret = tmp;
		tmp++;
	}
	if (!ret)
		ret = tmp;
	return ret;
}

#define PARSE_IPADDR(bf,vl,key,var)					\
{									\
	if (strcasecmp(bf, key) == 0) {					\
		if (!ipaddr_valid(vl)) {				\
			DEBUG_WARN("Invalid IP address %s specified for %s\n", vl, key); \
			continue;					\
		}							\
		strcpy(var, vl);					\
		continue;						\
	}								\
}

#define PARSE_TIMEOUT(bf,vl,key,var,tmin,tmax)				\
{									\
	if (strcasecmp(bf, key) == 0) {					\
		if ((atoi(vl) > tmax) || (atoi(vl) < tmin)) {		\
			DEBUG_WARN("Invalid timeout %s specified for %s\n", vl, key);	\
			continue;					\
		}							\
		var = atoi(vl);						\
		continue;						\
	}								\
}

void server_log(char *, char *fmt, ...);
int server_openlog(void);
void tl_server_msg_invalid(struct tl_comm *comm, struct tl_msg *msg);
int tl_server_dev_mapping(struct tl_comm *comm, struct tl_msg *msg);
int tl_server_run_diagnostics(struct tl_comm *comm, struct tl_msg *msg, int controller);
int __list_mirrors(char *filepath, int prune);
void print_clone_info(FILE *fp, struct clone_info *clone_info);

#define DEBUG_INFO_SERVER(fmt,args...)								\
do {												\
	server_log(SEVERITY_MSG_INFORMATION, "%s:%d "fmt, __FUNCTION__, __LINE__, ##args);	\
} while (0)

#define DEBUG_WARN_SERVER(fmt,args...)								\
do {												\
	server_log(SEVERITY_MSG_WARNING, "%s:%d "fmt, __FUNCTION__, __LINE__, ##args);		\
	DEBUG_WARN_NEW(fmt, ##args);								\
} while (0)

#define DEBUG_ERR_SERVER(fmt,args...)								\
do {												\
	server_log(SEVERITY_MSG_ERROR, fmt, ##args);						\
	DEBUG_ERR_NEW(fmt, ##args);								\
} while (0)

#define __DEBUG_INFO_SERVER(fmt,args...)							\
do {												\
	server_log(SEVERITY_MSG_INFORMATION, fmt, ##args);					\
} while (0)

#define __DEBUG_WARN_SERVER(fmt,args...)							\
do {												\
	server_log(SEVERITY_MSG_WARNING, fmt, ##args);						\
	DEBUG_WARN_NEW(fmt, ##args);								\
} while (0)

#define __DEBUG_ERR_SERVER(fmt,args...)								\
do {												\
	server_log(SEVERITY_MSG_ERROR, fmt, ##args);						\
	DEBUG_ERR_NEW(fmt, ##args);								\
} while (0)

#endif
