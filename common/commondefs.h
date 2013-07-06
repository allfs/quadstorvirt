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

#ifndef QS_COMMONDEFS_H_
#define QS_COMMONDEFS_H_ 1

#define TL_DEV_NAME	"iodev"
#define TL_DEV		"/dev/iodev"
#define MIN_PHYSDISK_SIZE	(1ULL << 32)


/* Limits */

#define TL_RID_MAX	40
struct mdaemon_info {
	pid_t daemon_pid;
	char sys_rid[TL_RID_MAX];
};

#define TDISK_NAME_LEN		36
#define TDISK_MAX_NAME_LEN	40

struct iscsiconf {
	uint32_t target_id;
	char iqn[256];
	char IncomingUser[36];
	char IncomingPasswd[36];
	char OutgoingUser[36];
	char OutgoingPasswd[36];
	uint32_t MaxConnections;
	uint32_t MaxSessions;
	uint32_t InitialR2T;
	uint32_t ImmediateData;
	uint32_t MaxRecvDataSegmentLength;
	uint32_t MaxXmitDataSegmentLength;
	uint32_t MaxBurstLength;
	uint32_t FirstBurstLength;
	uint32_t NOPInterval;
	uint32_t NOPTimeout;
};

struct tdisk_stats {
	uint64_t write_size;
	uint64_t read_size;
	uint64_t unaligned_size;
	uint64_t blocks_deduped;
	uint64_t inline_deduped;
	uint64_t post_deduped;
	uint64_t zero_blocks;
	uint64_t unmap_blocks;
	uint64_t uncompressed_size;
	uint64_t compressed_size;
	uint64_t compression_hits;
	uint64_t compression_misses;
	uint64_t verify_hits;
	uint64_t verify_misses;
	uint64_t verify_errors;
	uint64_t inline_waits;
	uint64_t cw_hits;
	uint64_t cw_misses;
	uint64_t xcopy_write;
	uint64_t xcopy_read;
	uint64_t wsame_blocks;
	uint64_t pad[63];
} __attribute__ ((__packed__));

struct mirror_state {
	uint8_t mirror_type;
	uint8_t mirror_role;
	uint8_t next_role;
	uint8_t pad1;
	uint16_t mirror_target_id;
	uint16_t pad2;
	int mirror_flags;
	uint32_t pad3;
	uint32_t mirror_src_ipaddr;
	uint32_t mirror_ipaddr;
	char mirror_vdisk[TDISK_MAX_NAME_LEN];
	char mirror_group[TDISK_MAX_NAME_LEN];
	uint64_t pad4;
	uint64_t pad5;
	char sys_rid[40];
} __attribute__ ((__packed__));

enum {
	VDISK_DELETED = 0x1,
	VDISK_DELETING = 0x2,
};

struct tdisk_info {
	uint64_t block;
	uint64_t size;
	char name[TDISK_MAX_NAME_LEN];
	char group_name[TDISK_MAX_NAME_LEN];
	char serialnumber[36];
	struct mirror_state mirror_state;
	uint32_t target_id;
	int free_alloc;
	uint32_t tl_id;
	int iscsi_tid;
	int vhba_id;
	uint8_t online;
	uint8_t disabled;
	uint8_t enable_deduplication;
	uint8_t enable_compression;
	uint8_t enable_verify;
	uint8_t force_inline;
	uint8_t lba_shift;
	uint8_t clone_error;
	uint8_t mirror_error;
	int8_t delete_error;
	uint8_t attach;
	uint8_t v2_format;
	uint8_t threshold;
	uint32_t group_id;
	struct iscsiconf iscsiconf;
	struct tdisk_stats stats;
	TAILQ_ENTRY(tdisk_info) g_entry;
	TAILQ_ENTRY(tdisk_info) q_entry;
	struct group_info *group;
};

enum {
	TDISK_ENABLE_DEDUPLICATION = 1,
	TDISK_DISABLE_DEDUPLICATION,
	TDISK_ENABLE_COMPRESSION,
	TDISK_DISABLE_COMPRESION,
};

#define MAX_TDISKS		4096
#define MAX_TARGET_SIZE		(1ULL << 46) /* 64 TB */

struct bint_stats {
	uint64_t dedupe_blocks;
	uint64_t compressed_size;
	uint64_t uncompressed_size;
	uint64_t total_blocks;
	uint64_t compression_hits;
	uint64_t pad2;
	uint64_t pad3;
	uint64_t pad4;
	uint64_t pad5;
	uint64_t pad6;
	uint64_t pad7;
	uint64_t pad8;
	uint64_t pad9;
	uint64_t pad10;
};

#define V2_DISK		0x1
#define V2_LOG_FORMAT	0x2
#define RID_SET		0x4
#define V3_LOG_FORMAT	0x8

struct raw_bdevint {
	uint8_t ddmaster;
	uint8_t ddbits;
	uint8_t log_disk;
	uint8_t log_disks;
	int8_t initialized;
	uint8_t enable_comp;
	uint8_t log_write;
	uint8_t flags;
	uint32_t bid;
	uint32_t sector_shift;
	uint64_t usize;
	uint64_t free;
	uint64_t b_start;
	uint64_t b_end;
	uint8_t magic[8];
	uint8_t vendor[8];
	uint8_t product[16];
	uint8_t serialnumber[32];
	uint32_t group_id;
	int32_t group_flags;
	uint8_t write_cache;
	uint8_t pad2[7];
	uint64_t pad3;
	uint64_t pad4;
	uint64_t pad5;
	uint64_t pad6;
	uint64_t pad7;
	uint64_t pad8;
	uint64_t pad9;
	uint64_t pad10;
	struct bint_stats stats;
	char mrid[TL_RID_MAX];
	char group_name[TDISK_MAX_NAME_LEN];
} __attribute__ ((__packed__));

struct group_conf {
	char name[TDISK_MAX_NAME_LEN];
	uint32_t group_id;
	int dedupemeta;
	int logdata;
};

#define DEFAULT_GROUP_NAME	"Default"

struct bdev_info {
	uint32_t bid;
	char devpath[256];
	uint64_t size;
	uint64_t usize;
	uint64_t free;
	uint64_t reserved;
	uint8_t  isnew;
	uint8_t  ddmaster;
	uint8_t  log_disk;
	uint8_t  ha_disk;
	uint8_t  unmap;
	uint8_t  write_cache;
	int8_t initialized;
	uint8_t enable_comp;
	uint8_t free_alloc;
	uint8_t  vendor[8];
	uint8_t  product[16];
	uint8_t  serialnumber[32];
	uint32_t max_index_groups;
	uint32_t group_id;
	struct bint_stats stats;
	char rid[TL_RID_MAX];
	char errmsg[256];
};

#define DISK_INDEX_MAGIC	"QSDINDEX"
#define INDEX_TABLE_PAD_MAX	74

struct raw_index_data {
	uint8_t magic[8];
	uint8_t name[40];
	uint8_t serialnumber[32];
	uint64_t size;
	uint16_t target_id;
	uint16_t lba_shift;
	uint32_t flags;
	uint32_t group_id;
	uint8_t  threshold;
	uint8_t pad3[3];
	uint64_t max_size;
	uint64_t pad5;
	uint64_t pad6;
	uint64_t pad7;
	uint64_t pad8;
	uint64_t pad9;
	uint64_t pad10;
	uint64_t table_pad[INDEX_TABLE_PAD_MAX]; 
	struct tdisk_stats stats;
	struct mirror_state mirror_state;
} __attribute__ ((__packed__));

struct node_config {
	int node_type;
	char node_host[16];
	char controller_host[16];
	char recv_host[16];
	char ha_host[16];
	char ha_bind_host[16];
	uint32_t nodes[64];
	uint32_t node_ipaddr;
	uint32_t controller_ipaddr;
	uint32_t recv_ipaddr;
	uint32_t ha_ipaddr;
	uint32_t ha_bind_ipaddr;
	int sync_status;
	int node_flags;
	int node_role;
	int recv_flags;
	int fence_enabled;
	uint16_t mirror_recv_timeout;
	uint16_t mirror_send_timeout;
	uint16_t mirror_sync_timeout;
	uint16_t mirror_sync_recv_timeout;
	uint16_t mirror_sync_send_timeout;
	uint16_t client_send_timeout;
	uint16_t controller_recv_timeout;
	uint16_t node_sync_timeout;
	uint16_t ha_check_timeout;
	uint16_t ha_ping_timeout;
	uint32_t client_connect_timeout;
	uint32_t mirror_connect_timeout;
};

enum {
	OP_CLONE,
	OP_MIRROR,
};

enum {
	CLONE_STATUS_SUCCESSFUL = 0x1,
	CLONE_STATUS_ERROR,
	CLONE_STATUS_INPROGRESS,
};

enum {
	MIRROR_STATUS_SUCCESSFUL = CLONE_STATUS_SUCCESSFUL,
	MIRROR_STATUS_ERROR = CLONE_STATUS_ERROR,
	MIRROR_STATUS_INPROGRESS = CLONE_STATUS_INPROGRESS,
};

struct clone_config {
	uint32_t src_target_id;
	uint32_t dest_target_id;
	uint32_t dest_ipaddr;
	uint32_t src_ipaddr;
	uint64_t job_id;
	uint8_t  op;
	uint8_t  status;
	uint8_t  progress;
	uint8_t  attach;
	uint8_t  mirror_type;
	uint8_t  mirror_role;
	char mirror_vdisk[TDISK_MAX_NAME_LEN];
	char mirror_group[TDISK_MAX_NAME_LEN];
	char sys_rid[40];
	char errmsg[256];
};

enum {
	GROUP_FLAGS_MASTER,
	GROUP_FLAGS_HA_DISK,
	GROUP_FLAGS_DEDUPEMETA,
	GROUP_FLAGS_LOGDATA,
	GROUP_FLAGS_UNMAP_ENABLED,
	GROUP_FLAGS_UNMAP,
	GROUP_FLAGS_TAIL_META,
};

enum {
	MIRROR_TYPE_NONE,
	MIRROR_TYPE_ACTIVE,
	MIRROR_TYPE_PASSIVE,
};

enum {
	MIRROR_ROLE_UNKNOWN,
	MIRROR_ROLE_MASTER,
	MIRROR_ROLE_PEER,
};

static inline char *
mirror_role_str(int role)
{
	switch (role) {
	case MIRROR_ROLE_MASTER:
		return "Master";
	case MIRROR_ROLE_PEER:
		return "Slave";
	default:
		return "Unknown";
	}
}

struct usr_msg {
	int msg_id;
	int msg_rsp;
	int iscsi_tid;
	int vhba_id;
	uint32_t target_id;
	uint32_t mirror_ipaddr;
	uint64_t job_id;
} __attribute__ ((__packed__));

struct usr_notify {
	struct usr_msg msg;
	int notify_type;
	char notify_msg[96];
} __attribute__ ((__packed__));

enum {
	USR_NOTIFY_INFO,
	USR_NOTIFY_WARN,
	USR_NOTIFY_ERR,
	USR_NOTIFY_VDISK_THRESHOLD,
};

enum {
	USR_RSP_OK,
	USR_RSP_ERR,
	USR_RSP_MIRROR_ACTIVE,
	USR_RSP_FENCE_FAILED,
	USR_RSP_FENCE_SUCCESSFUL,
	USR_RSP_BID_INVALID,
	USR_RSP_FENCE_MANUAL,
};

enum {
	USR_MSG_MIRROR_CHECK,
	USR_MSG_ATTACH_INTERFACE,
	USR_MSG_JOB_COMPLETED,
	USR_MSG_VDISK_DELETED,
	USR_MSG_FENCE_NODE,
	USR_MSG_BID_VALID,
	USR_MSG_NOTIFY,
};

struct fc_rule_config {
	uint64_t wwpn[2];
	uint32_t target_id;
	int rule;
};

enum {
	FC_RULE_ALLOW,
	FC_RULE_DISALLOW,
};

#define MIRROR_RECV_TIMEOUT_MAX			120
#define MIRROR_CONNECT_TIMEOUT_MAX		70
#define MIRROR_SEND_TIMEOUT_MAX			120
#define MIRROR_SYNC_TIMEOUT_MAX			90
#define MIRROR_SYNC_RECV_TIMEOUT_MAX		90
#define MIRROR_SYNC_SEND_TIMEOUT_MAX		90
#define CLIENT_SEND_TIMEOUT_MAX			90
#define CLIENT_CONNECT_TIMEOUT_MAX		90
#define CONTROLLER_RECV_TIMEOUT_MAX		70
#define CONTROLLER_CONNECT_TIMEOUT_MAX		70
#define NODE_SYNC_TIMEOUT_MAX			60
#define HA_CHECK_TIMEOUT_MAX			60
#define HA_PING_TIMEOUT_MAX			60

#define MIRROR_RECV_TIMEOUT_MIN			20
#define MIRROR_CONNECT_TIMEOUT_MIN		5
#define MIRROR_SEND_TIMEOUT_MIN			20
#define MIRROR_SYNC_TIMEOUT_MIN			15	
#define MIRROR_SYNC_RECV_TIMEOUT_MIN		15
#define MIRROR_SYNC_SEND_TIMEOUT_MIN		15
#define CLIENT_SEND_TIMEOUT_MIN			15
#define CLIENT_CONNECT_TIMEOUT_MIN		5
#define CONTROLLER_RECV_TIMEOUT_MIN		15
#define CONTROLLER_CONNECT_TIMEOUT_MIN		5
#define NODE_SYNC_TIMEOUT_MIN			20
#define HA_CHECK_TIMEOUT_MIN			5
#define HA_PING_TIMEOUT_MIN			2

enum {
	WRITE_CACHE_DEFAULT,
	WRITE_CACHE_FLUSH,
	WRITE_CACHE_FUA,
};

enum {
	MIRROR_FLAGS_CONFIGURED,
	MIRROR_FLAGS_DISABLED,
	MIRROR_FLAGS_NEED_RESYNC,
	MIRROR_FLAGS_PEER_LOAD_DONE,
	MIRROR_FLAGS_STATE_INVALID,
	MIRROR_FLAGS_IN_RESYNC,
	MIRROR_FLAGS_BLOCK,
	MIRROR_FLAGS_WAIT_FOR_MASTER,
	MIRROR_FLAGS_WAIT_FOR_PEER,
	MIRROR_FLAGS_WRITE_BITMAP_VALID,
};

#endif /* COMMONDEFS_H_ */
