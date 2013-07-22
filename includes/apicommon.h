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

#ifndef APICOMMON_H_
#define APICOMMON_H_

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <ctype.h>
#include <inttypes.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/un.h> /* for unix domain sockets */
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <syslog.h>
#include <assert.h>
#include "messages.h"
#include <stdarg.h>
#if defined(LINUX)
#include <queue.h>
#include <mntent.h>
#include <scsi/scsi.h>
#include <scsi/sg.h>
#include <linux/netlink.h>
#include <byteswap.h>
#include <endian.h>
#include <linux/mtio.h>
#include "linuxuserdefs.h"
#elif defined(FREEBSD)
#include <sys/queue.h>
#include <sys/disk.h>
#include <sys/endian.h>
#include <sys/mtio.h>
#include <sys/disk.h>
#include <uuid.h>
#include <cam/cam.h>
#include <cam/cam_ccb.h>
#include <camlib.h>
#include <camlib.h>
#include <cam/scsi/scsi_all.h>
#include <cam/scsi/scsi_sa.h>
#include <cam/scsi/scsi_message.h>
#else
#error "Unsupported arch"
#endif
#include <ioctldefs.h> 
#include "physlib.h"

enum {
	LOG_TYPE_INFORMATION	= 0x01,
	LOG_TYPE_WARNING	= 0X02,
	Log_TYPE_ERROR		= 0x03,
};

#define MDAEMON_NAME		"mdaemon"
#define MDAEMON_PORT		9999
#define MDAEMON_PORT2		9997
#define MDAEMON_BACKLOG		64
#ifdef FREEBSD
#define MDAEMON_PATH		"/quadstor/.mdaemon"
#else
#define MDAEMON_PATH		"QUADSTOR_ABSTRACT_NAMESPACE"
#endif
#define IETADM_PATH		"/quadstor/bin/ietadm"

struct tl_msg {
	int msg_id;
	int msg_len;
	int msg_resp;
	char *msg_data;
} __attribute__ ((__packed__));

struct tl_comm {
	int sockfd;
	char hname[256];
	int  ai_family;
};

struct target_desc {
	int type;
	uint32_t bus_id;
	uint32_t target_id;
	uint64_t lun_id;
};

#define ISCSI_UNAME_LEN		30
#define ISCSI_PASSWD_LEN	30

#define HEADER_DIGEST_NONE	0x00
#define HEADER_DIGEST_CRC	0x01

#define DATA_DIGEST_NONE	0x00
#define DATA_DIGEST_CRC		0x01
#define TL_MAX_ISCSI_CONN	16

TAILQ_HEAD(tdisk_list, tdisk_info);

struct group_info;
struct tl_blkdevinfo {
	/* The next four fields are filled up on start up */
	uint32_t bid;
	struct physdisk disk;
	char devname[256];
	dev_t b_dev;
	int offline;
	int ddmaster;
	int ismaster;
	int log_disk;
	int ha_disk;
	uint32_t group_id;
	uint32_t db_group_id;
	TAILQ_ENTRY(tl_blkdevinfo) g_entry;
	struct group_info *group;
};

TAILQ_HEAD(blist, tl_blkdevinfo);

struct group_info {
	char name[TDISK_MAX_NAME_LEN];
	char mrid[TL_RID_MAX];
	uint32_t group_id;
	int dedupemeta;
	int logdata;
	int tdisks;
	int disks;
	TAILQ_ENTRY(group_info) q_entry;
	TAILQ_HEAD(, tdisk_info) tdisk_list;
	TAILQ_HEAD(, tl_blkdevinfo) bdev_list;
};

TAILQ_HEAD(group_list, group_info);


/* error code */
#define TL_ENOMEM          -1 
#define TL_MSG_INVALID	   -2

enum {
	SEVERITY_CRITICAL	= 0x01,
	SEVERITY_ERROR,
	SEVERITY_WARNING,
	SEVERITY_INFORMATION
};

#define SEVERITY_MSG_CRITICAL		"Crit:"
#define SEVERITY_MSG_ERROR		"Err:"
#define SEVERITY_MSG_WARNING		"Warn:"
#define SEVERITY_MSG_INFORMATION	"Info:"

/* API prototypes */
struct tl_comm * tl_msg_make_connection(void);
struct tl_comm * tl_msg_remote_connection(char *host, char *local, uint16_t portnum, int timeout);
void tl_msg_free_message(struct tl_msg *msg);
void tl_msg_free_data(struct tl_msg *msg);
void tl_msg_free_connection(struct tl_comm *tl_comm);
void tl_msg_close_connection(struct tl_comm *tl_comm);
int tl_msg_send_message(struct tl_comm *tl_comm, struct tl_msg *msg);
int tl_msg_send_message_timeout(struct tl_comm *tl_comm, struct tl_msg *msg);
struct tl_msg * tl_msg_recv_message(struct tl_comm *comm); 
struct tl_msg * tl_msg_recv_message_timeout(struct tl_comm *comm);

void group_list_free(struct group_list *group_list);
void tdisk_list_free(struct tdisk_list *tdisk_list);
void parse_tdisk_stats(FILE *fp, struct tdisk_stats *stats);
void dump_tdisk_stats(FILE *fp, struct tdisk_stats *stats);
int tl_common_parse_group(FILE *fp, struct group_list *group_list);
int tl_common_parse_tdisk(FILE *fp, struct tdisk_list *tdisk_list);
int tl_common_parse_roup(FILE *fp, struct group_list *group_list);
int tl_ioctl2(char *dev, unsigned long int request, void *arg);
int tl_ioctl(unsigned long int request, void *arg);
int tl_ioctl_void(unsigned long int request);
int usage_percentage(uint64_t size, uint64_t used);

static inline void *
alloc_buffer(int buffer_len)
{
	void *ret;

	ret = malloc(buffer_len);
	if (!ret)
		return NULL;
	memset(ret, 0, buffer_len);
	return ret;
}

struct clone_spec {
	char dest_tdisk[TDISK_MAX_NAME_LEN];
	char src_tdisk[TDISK_MAX_NAME_LEN];
	char dest_group[TDISK_MAX_NAME_LEN];
};

struct mirror_spec {
	char dest_tdisk[TDISK_MAX_NAME_LEN];
	char clone_tdisk[TDISK_MAX_NAME_LEN];
	char src_tdisk[TDISK_MAX_NAME_LEN];
	char dest_group[TDISK_MAX_NAME_LEN];
	char dest_host[20];
	char src_host[20];
	uint64_t size;
	uint32_t dest_target_id;
	uint32_t src_target_id;
	char src_serialnumber[36];
	char dest_serialnumber[36];
	int enable_deduplication;
	int enable_compression;
	int enable_verify;
	int force_inline;
	int lba_shift;
	int attach;
	int detach;
	int clone;
	int mirror_type;
	int mirror_role;
	int clone_status;
	struct iscsiconf iscsiconf;
};

long int get_random();
void get_data_str(double bytes, char *buf);
void get_data_str_int(uint64_t bytes, char *buf);
void get_transfer_rate(double bytes, long elapsed, char *buf);
int ipaddr_valid(char *addr);

#ifdef ENABLE_DEBUG
#define DEBUG_INFO(fmt,args...)		syslog(LOG_ERR, "info: "fmt, ##args)
#else
#define DEBUG_INFO(fmt,args...)
#endif

#define DEBUG_BUG_ON(cond) do { if (((cond)) != 0) *(char *)(NULL) = 'A'; } while(0)

#define DEBUG_WARN(fmt,args...)		syslog(LOG_ERR, "WARN: %s:%d "fmt, __FUNCTION__, __LINE__, ##args)
#define DEBUG_ERR(fmt,args...)		syslog(LOG_ERR, "ERROR: %s:%d "fmt, __FUNCTION__, __LINE__, ##args)
#define DEBUG_CRIT(fmt,args...)		syslog(LOG_ERR, "CRIT: %s:%d "fmt, __FUNCTION__, __LINE__, ##args)
#define DEBUG_INFO_NEW(fmt,args...)	syslog(LOG_ERR, "%s:%d "fmt, __FUNCTION__, __LINE__, ##args)
#define DEBUG_WARN_NEW(fmt,args...)	syslog(LOG_ERR, "WARN: %s:%d "fmt, __FUNCTION__, __LINE__, ##args)
#define DEBUG_ERR_NEW(fmt,args...)	syslog(LOG_ERR, "ERR: %s:%d "fmt, __FUNCTION__, __LINE__, ##args)

int do_connect2(int sockfd, struct sockaddr *addr, socklen_t len, int timeout);

struct mirror_check_spec {
	char mirror_host[20];
	int type;
	char value[512];
};

enum {
	MIRROR_CHECK_TYPE_MDAEMON = 0x1,
	MIRROR_CHECK_TYPE_SCSI,
	MIRROR_CHECK_TYPE_FENCE,
	MIRROR_CHECK_TYPE_IGNORE,
	MIRROR_CHECK_TYPE_MANUAL,
};

struct mirror_check {
	uint32_t mirror_ipaddr;
	int type;
	char value[512];
	char path[512];
	TAILQ_ENTRY(mirror_check) q_entry;
};
TAILQ_HEAD(mirror_check_list, mirror_check);

struct fc_rule {
	int rule;
	char wwpn[24];
	char wwpn1[24];
	struct tdisk_info *vdisk;
	TAILQ_ENTRY(fc_rule) q_entry;
};

TAILQ_HEAD(fc_rule_list, fc_rule);

struct fc_rule_spec {
	int rule;
	char wwpn[24];
	char wwpn1[24];
	char vdisk[TDISK_MAX_NAME_LEN];
};

struct vdiskconf {
	uint64_t size;
	char name[TDISK_MAX_NAME_LEN];
	char group_name[TDISK_MAX_NAME_LEN];
	uint32_t target_id;
	uint8_t enable_deduplication;
	uint8_t enable_compression;
	uint8_t enable_verify;
	uint8_t threshold;
};

enum {
	DISK_PROP_HA,
	DISK_PROP_UNMAP,
	DISK_PROP_WC,
};

#define QUADSTOR_CONFIG_FILE "/quadstor/etc/quadstor.conf"
int get_config_value(char *path, char *name, char *value);
void get_mirror_status_str(struct mirror_state *mirror_state, char *status);

static inline int
target_name_valid(char *name)
{
	int i;
	int len = strlen(name);

	for (i = 0; i < len; i++) {
		if (!isalnum(name[i]) && name[i] != '_' && name[i] != '-')
			return 0;
	}
	return 1;
}

#endif /* API_COMMON_H_ */
