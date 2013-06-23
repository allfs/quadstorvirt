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

#include "coredefs.h"
#include "rawdefs.h"
#include "../common/cluster_common.h" 
#include "../common/commondefs.h"

enum {
	NODE_MASTER,
	NODE_CLIENT,
};

enum {
	NODE_CMD_DONE,
	NODE_CMD_NEED_COMP,
	NODE_CMD_NEED_IO,
	NODE_CMD_NEED_IO_UNALIGNED,
	NODE_CMD_NEED_VERIFY,
};

enum {
	NODE_MSG_REGISTER = 1,
	NODE_MSG_UNREGISTER,
	NODE_MSG_GENERIC_CMD,
	NODE_MSG_PERSISTENT_RESERVE_OUT_CMD,
	NODE_MSG_WRITE_CMD,
	NODE_MSG_WRITE_COMP_DONE,
	NODE_MSG_WRITE_DATA,
	NODE_MSG_WRITE_IO_DONE,
	NODE_MSG_WRITE_DONE,
	NODE_MSG_READ_CMD,
	NODE_MSG_READ_DATA,
	NODE_MSG_READ_IO_DONE,
	NODE_MSG_READ_DONE,
	NODE_MSG_VERIFY_DATA,
	NODE_MSG_AMAP_CHECK,
	NODE_MSG_AMAP_SYNC,
	NODE_MSG_AMAP_META_SYNC,
	NODE_MSG_AMAP_SYNC_POST,
	NODE_MSG_AMAP_TABLE_SYNC,
	NODE_MSG_AMAP_TABLE_META_SYNC,
	NODE_MSG_AMAP_TABLE_SYNC_POST,
	NODE_MSG_TABLE_INDEX_SYNC,
	NODE_MSG_TDISK_SYNC,
	NODE_MSG_TDISK_UPDATE,
	NODE_MSG_TDISK_DELETE,
	NODE_MSG_LOG_SYNC,
	NODE_MSG_LOG_SYNC_POST,
	NODE_MSG_DDLOOKUP_SYNC,
	NODE_MSG_DDLOOKUP_SYNC_POST,
	NODE_MSG_INDEX_LOOKUP_SYNC,
	NODE_MSG_BINT_SYNC,
	NODE_MSG_BINT_DELETE,
	NODE_MSG_BINT_INDEX_SYNC,
	NODE_MSG_BINT_INDEX_SYNC_POST,
	NODE_MSG_ISTATE_CLEAR,
	NODE_MSG_SENSE_STATE,
	NODE_MSG_REGISTRATION_SYNC,
	NODE_MSG_REGISTRATION_CLEAR_SYNC,
	NODE_MSG_RESERVATION_SYNC,
	NODE_MSG_COMM_SYNC,
	NODE_MSG_PGDATA_SYNC_START,
	NODE_MSG_PGDATA_SYNC_CLIENT_DONE,
	NODE_MSG_PGDATA_SYNC_COMPLETE,
	NODE_MSG_NEWMETA_SYNC_START,
	NODE_MSG_NEWMETA_SYNC_COMPLETE,
	NODE_MSG_ROLE,
	NODE_MSG_HA_PING,
	NODE_MSG_SYNC_START,
	NODE_MSG_SYNC_DISABLE,
	NODE_MSG_SYNC_STATUS,
	NODE_MSG_HA_SWITCH,
	NODE_MSG_HA_RELINQUISH,
	NODE_MSG_HA_TAKEOVER,
	NODE_MSG_HA_TAKEOVER_POST,
	NODE_MSG_HA_ENABLED,
	NODE_MSG_HA_DISABLED,
	NODE_MSG_MIRROR_WRITE_ERROR,
	NODE_MSG_MIRROR_STATE,
	NODE_MSG_MIRROR_RESYNC_START,
	NODE_MSG_MIRROR_RESYNC_DONE,
	NODE_MSG_PEER_SHUTDOWN,
	NODE_MSG_MIRROR_SETUP,
	NODE_MSG_MIRROR_REMOVE,
	NODE_MSG_WRITE_DATA_UNALIGNED,
	NODE_MSG_WRITE_POST_PRE,
	NODE_MSG_VDISK_UPDATE,
	NODE_MSG_MIRROR_LOAD_DONE,
	NODE_MSG_MIRROR_LOAD_ERROR,
	NODE_MSG_VDISK_RESIZE,
	NODE_MSG_XCOPY_READ,
	NODE_MSG_XCOPY_WRITE,
	NODE_MSG_WRITE_MIRROR_CMD,
	NODE_MSG_HA_RELINQUISH_STATUS,
	NODE_MSG_MIRROR_SET_ROLE,
};

enum {
	NODE_STATUS_OK			= SCSI_STATUS_OK,
	NODE_STATUS_SCSI_SENSE		= SCSI_STATUS_CHECK_COND,
	NODE_STATUS_BUSY		= SCSI_STATUS_BUSY,
	NODE_STATUS_RESERV_CONFLICT	= SCSI_STATUS_RESERV_CONFLICT,

	/* Custom codes */
	NODE_STATUS_TARGET_NOT_FOUND	= 0xE0,
	NODE_STATUS_INVALID_MSG		= 0xE1,
	NODE_STATUS_UNREGISTERED_NODE	= 0xE2,
	NODE_STATUS_MEM_ALLOC_FAILURE	= 0xE3,
	NODE_STATUS_ERROR		= 0xE4,
	NODE_STATUS_AMAP_NOT_FOUND	= 0xE5,
	NODE_STATUS_AMAP_NEEDS_SYNC	= 0xE6,
	NODE_STATUS_INITIALIZING	= 0xE7,
	NODE_STATUS_NEED_RESYNC		= 0xE8,
	NODE_STATUS_MIRROR_CONFIGURED	= 0xE9,
	NODE_STATUS_INVALID_MIRROR_CONFIGURATION	= 0xEA,
	NODE_STATUS_SKIP_LOCAL_WRITE	= 0xEB,
	NODE_STATUS_IS_MASTER		= 0xEC,
};

struct node {
	uint64_t node_id;
	char sys_rid[40];
	SLIST_ENTRY(node) n_list;
	atomic_t refs;
	int role;
	struct node_comm *master_send;
	struct node_comm *master_recv;
	struct node_comm *controller_recv;
};
SLIST_HEAD(node_list, node);

struct raw_node_msg {
	uint16_t csum;
	uint16_t data_csum;
	uint8_t  msg_cmd;
	uint8_t  msg_status;
	uint8_t  cmd_status;
	uint8_t  mirror_status;
	uint32_t msg_id;
	uint32_t xchg_id;
	uint32_t dxfer_len;
	uint16_t target_id;
	uint16_t pg_count;
	uint8_t  data[0];
} __attribute__ ((__packed__));

enum {
	NODE_MSG_TYPE_REQ,
	NODE_MSG_TYPE_RESP,
};

enum {
	CMD_EXPECTED_DONE_COMP,
	CMD_EXPECTED_DONE_IO,
};

struct node_msg {
	uint32_t timestamp;
	uint32_t id;
	struct raw_node_msg *raw;
	struct node_msg *resp;
	struct node_sock *sock;
	wait_compl_t *completion;
	struct tdisk *tdisk;
	struct tcache *tcache;
	struct qsio_scsiio *ctio;
	struct write_list *wlist;
	TAILQ_ENTRY(node_msg) q_list;
	struct queue_list *queue_list;
	mtx_t *queue_lock;
	pagestruct_t **pages;
	uint16_t pg_count;
	int16_t retry;
	int16_t mirror;
	int16_t async_wait;
	LIST_ENTRY(node_msg) c_list;
};

TAILQ_HEAD(queue_list, node_msg);

static inline int
node_cmd_status(struct node_msg *msg)
{
	return (msg->raw->cmd_status);
}

struct node_msg_list {
	BSD_LIST_HEAD(, node_msg) msgs;
	mtx_t *list_lock;
};

enum {
	NODE_SOCK_DATA,
	NODE_SOCK_EXIT,
	NODE_SOCK_READ_ERROR,
	NODE_SOCK_WRITE_WAIT,
	NODE_SOCK_BUSY,
};

struct node_comm;
struct node_sock {
	sock_t *lsock; /* low level socket */
	struct node_comm *comm;
	kproc_t *task;
	int flags;
	int state;
	wait_chan_t *sock_wait;
	mtx_t *sock_lock;
	int (*sock_callback) (struct node_sock *);
	SLIST_HEAD(, node_sock) accept_list;
	TAILQ_ENTRY(node_sock) s_list;
	TAILQ_ENTRY(node_sock) f_list;
};

TAILQ_HEAD(sock_list, node_sock);

enum {
	NODE_COMM_REGISTERED,
	NODE_COMM_UNREGISTERED,
	NODE_COMM_CLEANUP,
	NODE_COMM_FENCED,
	NODE_COMM_LINGER,
	NODE_COMM_FROM_HA,
};

struct node_comm {
	TAILQ_HEAD(, node_sock) sock_list;
	TAILQ_HEAD(, node_sock) free_sock_list;
	wait_chan_t *comm_wait;
	struct node_msg_list *node_hash;
	atomic_t refs;
	atomic_t waits;
	atomic_t jobs;
	uint32_t node_ipaddr;
	uint32_t controller_ipaddr;
	int flags;
	sx_t *comm_lock;
	SLIST_ENTRY(node_comm) c_list;
	SLIST_HEAD(, node_comm) comm_list;
	uint32_t timestamp;
};

#define node_comm_lock(cmm)				\
do {							\
	debug_check(sx_xlocked_check((cmm)->comm_lock));	\
	sx_xlock((cmm)->comm_lock);			\
} while (0)

#define node_comm_unlock(cmm)				\
do {							\
	debug_check(!sx_xlocked((cmm)->comm_lock));	\
	sx_xunlock((cmm)->comm_lock);			\
} while (0)

struct node_msg *node_msg_alloc(int msg_len);
void node_msg_free(struct node_msg *msg);
void node_resp_free(struct node_msg *msg);

#define node_msg_init(mg)	(init_wait_completion((mg)->completion))

extern uint64_t ntransaction_id;
extern mtx_t *node_transaction_lock;

#define NODE_TRANSACTION_ID_MAX	((1ULL <<  32) - 1)

static inline uint64_t 
node_transaction_id(void)
{
	uint64_t ret;

	mtx_lock(node_transaction_lock);
	ret = ++ntransaction_id;
	if (ntransaction_id == NODE_TRANSACTION_ID_MAX)
		ntransaction_id = 0;

	mtx_unlock(node_transaction_lock);
	return ret;
}

int node_send_msg(struct node_sock *sock, struct node_msg *msg, uint64_t id, int resp);
int node_msg_discard(struct node_sock *sock, struct raw_node_msg *raw);
int node_msg_discard_pages(struct node_sock *sock, int pg_count);
int node_msg_discard_data(struct node_sock *sock, int dxfer_len);
void node_error_resp_msg(struct node_sock *sock, struct raw_node_msg *msg, int msg_status);
void node_resp_msg(struct node_sock *sock, struct raw_node_msg *msg, int msg_status);
struct node_comm * node_comm_alloc(struct node_msg_list *node_hash, uint32_t controller_ipaddr, uint32_t node_ipaddr);
void node_comm_put(struct node_comm *comm);
void node_comm_free(struct node_comm *comm);
void node_comm_cleanup(struct node_comm *comm, struct sock_list *sock_list);
void node_master_cleanup(struct node_comm *root_comm, struct queue_list *queue_list, mtx_t *queue_lock);
void node_cleanups_wait(void);
void node_master_register(struct node_sock *sock, struct raw_node_msg *raw, int node_register, int *flags, wait_chan_t *wait, struct queue_list *queue_list, mtx_t *queue_lock, int notify);
#define node_comm_get(cmm)	(atomic_inc(&cmm->refs))
struct node_sock * node_sock_alloc(struct node_comm *comm, int (*sock_callback) (struct node_sock *), sock_t *lsock, char *name);
void node_sock_free(struct node_sock *sock, int linger);
struct node_sock * __node_sock_alloc(struct node_comm *comm, int (*sock_callback) (struct node_sock *));
int node_get_role(void);
void node_set_role(int role);

struct vdisk_update_spec {
	uint8_t enable_compression;
	uint8_t enable_deduplication;
	uint8_t enable_verify;
	uint8_t lba_shift;
	uint8_t threshold;
	uint8_t pad;
	uint64_t end_lba;
	uint64_t max_size;
} __attribute__ ((__packed__));

struct mirror_setup_spec {
	struct mirror_state mirror_state;
	struct vdisk_update_spec properties;
};

struct sense_spec {
	uint8_t error_code;
	uint8_t flags;
	uint8_t asc;
	uint8_t ascq;
	uint32_t info;
} __attribute__ ((__packed__));

struct istate_spec {
	uint64_t i_prt[2];
	uint64_t t_prt[2];
	uint16_t r_prt;
	uint8_t init_int;
	uint8_t pad;
	struct sense_spec sense_spec[MAX_UNIT_ATTENTIONS];
} __attribute__ ((__packed__));

struct comm_spec {
	uint32_t ipaddr;
	uint32_t node_register;
} __attribute__ ((__packed__));

struct bintindex_spec {
	uint64_t write_id;
	uint32_t subgroup_id;
	uint32_t group_id;
	uint32_t index_id;
	uint16_t bid;
	uint16_t csum;
} __attribute__ ((__packed__));

struct ilookup_spec {
	uint32_t group_id;
	uint16_t bid;
	uint16_t csum;
} __attribute__ ((__packed__));

struct ddlookup_spec {
	uint64_t block;
	uint64_t write_id;
	uint64_t prev_b_start;
	uint32_t group_id;
	int32_t hash_id;
	uint16_t num_entries;
	uint16_t csum;
} __attribute__ ((__packed__));

struct log_spec {
	uint64_t write_id;
	uint32_t group_id;
	uint16_t bid;
	uint16_t log_group_idx;
	uint16_t csum;
} __attribute__ ((__packed__));

struct table_index_spec {
	uint32_t table_index_id;
	uint32_t pad;
	uint64_t csum;
} __attribute__ ((__packed__));

struct amap_table_spec {
	uint64_t write_id;
	uint64_t lba;
	uint64_t block;
	uint16_t csum;
	int16_t  flags;
	uint32_t pad;
} __attribute__ ((__packed__));

struct tdisk_spec {
	uint16_t csum;
	uint16_t pad;
	uint16_t amap_table_group_max;
	uint16_t table_index_max;
	uint32_t amap_table_max;
	uint64_t end_lba;
} __attribute__ ((__packed__));

struct amap_spec {
	uint64_t write_id;
	uint64_t lba;
	uint64_t block;
	uint64_t amap_table_block;
	uint16_t csum;
	int16_t  flags;
} __attribute__ ((__packed__));

/* command specs */
struct scsi_sense_spec {
	uint8_t  sense_key;
	uint8_t  error_code;
	uint8_t  asc;
	uint8_t  ascq;
	uint32_t info;
};

struct xcopy_read_spec {
	uint64_t lba;
	uint64_t dest_lba;
	uint64_t dest_num_blocks;
	uint64_t i_prt[2];
	uint64_t t_prt[2];
	uint32_t num_blocks;
	uint16_t dest_target_id;
	uint16_t r_prt;
	uint32_t task_tag;
	uint8_t  task_attr;
	uint8_t  pad[3];
} __attribute__ ((__packed__));

struct scsi_cmd_spec_generic {
	uint8_t  cdb[16];
	uint32_t transfer_length;
	uint32_t task_tag;
	uint64_t i_prt[2];
	uint64_t t_prt[2];
	uint16_t r_prt;
	uint16_t pglist_cnt;
	uint8_t  init_int;
	uint8_t  task_attr;
	uint16_t csum;
} __attribute__ ((__packed__));

struct scsi_cmd_spec {
	uint32_t transfer_length;
	uint32_t task_tag;
	uint64_t lba;
	uint64_t i_prt[2];
	uint64_t t_prt[2];
	uint16_t r_prt;
	uint16_t pglist_cnt;
	uint8_t  init_int;
	uint8_t  task_attr;
	uint16_t csum;
	uint64_t amap_write_id;
} __attribute__ ((__packed__));

struct pgdata_spec {
	uint8_t hash[32];
	int16_t flags;
	uint16_t csum;
} __attribute__ ((__packed__));

struct pgdata_write_spec_header {
	uint64_t lba;
} __attribute__ ((__packed__));

struct newmeta_spec {
	uint64_t block;
	uint64_t lba;
	int meta_type;
} __attribute__ ((__packed__));

struct pgdata_write_spec {
	uint64_t amap_block;
	uint64_t old_amap_block;
	uint64_t amap_write_id;
	uint64_t index_write_id;
} __attribute__ ((__packed__));

struct pgdata_read_spec {
	uint64_t amap_block;
	int16_t flags;
	uint16_t csum;
} __attribute__ ((__packed__));

#define pgdata_read_spec_dxfer_len(pgcnt) (sizeof(struct pgdata_read_spec) * pgcnt)
#define pgdata_read_spec_ptr(rw) ((struct pgdata_read_spec *)((rw)->data))

#define pgdata_spec_ptr(rw)	((struct pgdata_spec *)((rw)->data + sizeof(struct scsi_cmd_spec)))

#define amap_spec_ptr(rw)	((struct amap_spec *)((rw)->data))
#define scsi_cmd_spec_ptr(rw)	((struct scsi_cmd_spec *)((rw)->data))
#define scsi_cmd_spec_generic_ptr(rw)	((struct scsi_cmd_spec_generic *)((rw)->data))
#define scsi_data_ptr(rw)	((void *)((rw)->data + sizeof(struct scsi_cmd_spec)))
#define scsi_data_ptr_generic(rw)	((void *)((rw)->data + sizeof(struct scsi_cmd_spec_generic)))
#define ctio_set_node_msg(cto,nmsg)				\
do {								\
	(cto)->ccb_h.priv.npriv.node_msg = nmsg;		\
	(cto)->ccb_h.flags |= QSIO_CLUSTERED;			\
	atomic_inc(&nmsg->sock->comm->refs);			\
	nmsg->ctio = ctio;					\
} while (0)

#define ctio_set_in_xcopy(cto)		((cto)->ccb_h.flags |= QSIO_XCOPY)
#define ctio_set_in_sync(cto)		((cto)->ccb_h.flags |= QSIO_SYNC)
#define ctio_set_in_mirror(cto)		((cto)->ccb_h.flags |= QSIO_MIRROR)
#define ctio_set_remote_locked(cto)	((cto)->ccb_h.flags |= QSIO_LOCKED)
#define ctio_in_xcopy(cto)		((cto)->ccb_h.flags & QSIO_XCOPY)
#define ctio_in_sync(cto)		((cto)->ccb_h.flags & QSIO_SYNC)
#define ctio_in_mirror(cto)		((cto)->ccb_h.flags & QSIO_MIRROR)
#define ctio_remote_locked(cto)		((cto)->ccb_h.flags & QSIO_LOCKED)

#define ctio_get_node_msg(cto)		((cto)->ccb_h.priv.npriv.node_msg)


int node_config(struct node_config *node_config);
int node_status(struct node_config *node_config);
uint64_t node_get_tprt(void);
int node_client_init(struct node_config *node_config);
int node_usr_init(void);
void node_exit(void);
void node_init(void);
void node_client_exit(void);
void node_usr_exit(void);
int node_master_init(struct node_config *node_config);
void node_master_exit(void);
void node_master_proc_cmd(void *disk, void *iop);
void node_client_proc_cmd(void *disk, void *iop);
struct node_sock * node_comm_get_sock(struct node_comm *comm, int wait);
int node_cmd_hash_remove(struct node_msg_list *node_hash, struct node_msg *msg, uint32_t id);
void node_ha_hash_insert(struct node_msg *msg, uint32_t id);
void node_ha_meta_hash_insert(struct node_msg *msg, uint32_t id);
void node_msg_hash_cancel(struct node_msg_list *node_hash);
void node_ha_hash_cancel(void);
void node_ha_meta_hash_cancel(void);
void node_cmd_hash_insert(struct node_msg_list *node_hash, struct node_msg *msg, uint32_t id);
int node_sock_write(struct node_sock *sock, struct raw_node_msg *raw);
int node_sock_write_page(struct node_sock *sock, pagestruct_t *page, int dxfer_len);
uint16_t pgdata_csum(struct pgdata *pgdata, int len);
int node_sock_write_data(struct node_sock *sock, uint8_t *buffer, int dxfer_len);
void node_sock_mark_close(struct node_sock *sock);
struct node_msg * node_cmd_lookup(struct node_msg_list *node_hash, uint64_t id);
struct node_msg * node_ha_lookup(uint64_t id);
struct node_msg * node_ha_meta_lookup(uint64_t id);
void page_list_free(pagestruct_t **pages, int pg_count);
void node_sock_finish(struct node_sock *sock);
void node_sock_add_to_free_list(struct node_sock *sock);
void node_remove(uint64_t node_id, char *sys_rid);
void node_sock_write_error(struct node_sock *sock);
void node_sock_read_error(struct node_sock *sock);
struct node_comm * node_comm_locate(struct node_msg_list *node_hash, uint32_t ipaddr, struct node_comm *root);

void node_master_write_cmd(struct node_sock *sock, struct raw_node_msg *raw, struct queue_list *queue_list, mtx_t *queue_lock, int in_sync, int remote_locked);
void node_master_verify_data(struct node_sock *sock, struct raw_node_msg *raw);
void node_master_write_comp_done(struct node_sock *sock, struct raw_node_msg *raw);
void node_master_write_done(struct node_sock *sock, struct raw_node_msg *raw);
void node_master_write_post_pre(struct node_sock *sock, struct raw_node_msg *raw);
void node_master_write_data(struct node_sock *sock, struct raw_node_msg *raw);
void node_master_write_data_unaligned(struct node_sock *sock, struct raw_node_msg *raw);
void node_master_cmd_generic(struct node_sock *sock, struct raw_node_msg *raw, int in_sync);
void node_master_cmd_persistent_reserve_out(struct node_sock *sock, struct raw_node_msg *raw, int in_sync);
void node_master_read_cmd(struct node_sock *sock, struct raw_node_msg *raw, struct queue_list *queue_list, mtx_t *queue_lock, int in_sync);
void node_master_read_data(struct node_sock *sock, struct raw_node_msg *raw);
void node_master_read_done(struct node_sock *sock, struct raw_node_msg *raw);
void node_master_xcopy_read(struct node_sock *sock, struct raw_node_msg *raw, struct queue_list *queue_list, mtx_t *queue_lock);
void node_master_xcopy_write(struct node_sock *sock, struct raw_node_msg *raw);

int node_write_setup(struct node_comm *comm, struct node_sock *sock, struct node_msg *msg, struct qsio_scsiio *ctio, uint64_t lba, uint32_t transfer_length, uint64_t amap_write_id, int unaligned, int timeout, int cmd);
int node_verify_setup(struct node_comm *comm, struct node_sock *sock, struct node_msg *msg, struct qsio_scsiio *ctio, int timeout, int async);
int node_comp_setup(struct node_comm *comm, struct node_sock *sock, struct node_msg *msg, struct qsio_scsiio *ctio, int timeout, int async);
int node_cmd_remote_write_io(struct node_comm *comm, struct node_sock *sock, struct qsio_scsiio *ctio, struct node_msg *msg,  struct pgdata **pglist, int pglist_cnt, int timeout, int async);

/* replication related */
int node_recv_init(struct node_config *node_config);
int node_client_recv(struct node_sock *sock);
void node_recv_exit(void);

struct clone_info;
void tdisk_clone_setup(struct tdisk *tdisk, struct tdisk *src_tdisk, int in_sync, struct clone_info *clone_info);
void tdisk_clone_cleanup(struct tdisk *tdisk, struct tdisk *src_tdisk);
#define MAX_AMAP_CLONE_THREADS		8
#define MAX_AMAP_MIRROR_THREADS	MAX_AMAP_CLONE_THREADS
enum {
	CLONE_THREAD_START,
	CLONE_THREAD_EXIT,
	CLONE_THREAD_ERROR,
};

void clone_info_list_complete(void);
struct clone_data * clone_list_next(struct tdisk *tdisk);
struct clone_data * clone_data_alloc(int type);
void clone_data_free(struct clone_data *clone_data);
int clone_list_wait(struct tdisk *tdisk);
void amap_group_bmaps_free(struct tdisk *tdisk, uint32_t group_id);
struct amap_group_bitmap * amap_group_table_bmap_locate(struct tdisk *tdisk, uint32_t group_id, int *error);
struct amap_group_bitmap * amap_group_bmap_locate(struct tdisk *tdisk, uint32_t group_id, uint32_t group_offset, int *error);
int bmap_bit_is_set(struct amap_group_bitmap *bmap, uint32_t bmap_offset);
void bmap_set_bit(struct amap_group_bitmap *bmap, uint32_t bmap_offset);
void node_msg_wait(struct node_msg *msg, struct node_sock *sock, int timo);

static inline uint32_t
amap_to_bitmap_offset(uint32_t amap_id)
{
	return (amap_id & 0x7FFF);
}
uint32_t amap_bitmap_group_offset(uint32_t amap_id);

/* timeouts */
#define NODE_GENERIC_TIMEOUT		20000
#define CLIENT_SEND_TIMEOUT		24000
#define CONTROLLER_RECV_TIMEOUT		21000
#define NODE_COMM_REINIT_TIMEOUT	30000
#define MIRROR_SYNC_RECV_TIMEOUT	14000
#define MIRROR_SYNC_SEND_TIMEOUT	20000
#define MIRROR_RECV_TIMEOUT		30000
#define MIRROR_SEND_TIMEOUT		30000
#define HA_SWITCH_WAIT_TIMEOUT		60000

void node_msg_compute_csum(struct raw_node_msg *raw);
int node_msg_csum_valid(struct raw_node_msg *raw);
void node_msg_queue_remove(struct node_msg *msg);
void node_msg_queue_insert(struct node_msg *msg);
void node_check_timedout_msgs(struct node_msg_list *node_hash, struct queue_list *queue_list, mtx_t *queue_lock, uint32_t timeout_secs);
void master_queue_wait_for_empty(void);
void node_clear_comm_msgs(struct node_msg_list *node_hash, struct queue_list *queue_list, mtx_t *queue_lock, struct node_comm *comm, struct sock_list *sock_list);
void node_master_write_error(struct tdisk *tdisk, struct write_list *wlist, struct qsio_scsiio *ctio);
void node_master_read_error(struct tdisk *tdisk, struct write_list *wlist, struct qsio_scsiio *ctio);
void node_master_end_ctio(struct qsio_scsiio *ctio);
void node_msg_cleanup(struct node_msg *msg);
int node_comm_register(struct node_comm *comm, int timeout);
int node_comm_free_sock_count(struct node_comm *comm);
void ctio_pglist_cleanup(struct qsio_scsiio *ctio);
struct index_sync_list;
struct amap_sync_list;
int node_ha_hash_cleanup(struct amap_sync_list *amap_sync_list, struct index_sync_list *index_sync_list);
int node_ha_meta_hash_cleanup(struct amap_sync_list *amap_sync_list, struct index_sync_list *index_sync_list);
void node_master_sync_wait(void);
void node_master_pending_writes_incr(void);
void node_master_pending_writes_decr(void);
void node_master_pending_writes_wait(void);
void node_root_comm_free(struct node_comm *root_comm, struct queue_list *queue_list, mtx_t *queue_lock);
int node_cmd_write_done(struct qsio_scsiio *ctio, struct node_comm *comm, struct node_sock *sock, struct node_msg *msg, int timeout);

int node_type_client(void);
int node_type_master(void);
int node_type_controller(void);
int node_type_receiver(void);
void scsi_cmd_spec_fill(struct scsi_cmd_spec *spec, struct qsio_scsiio *ctio);
void scsi_cmd_spec_generic_fill(struct scsi_cmd_spec_generic *spec, struct qsio_scsiio *ctio);
void node_msg_copy_resp(struct node_msg *msg);
int node_send_write_io(struct qsio_scsiio *ctio, struct node_comm *comm, struct node_sock *sock, struct node_msg *msg, struct pgdata **pglist, int pglist_cnt, int timeout, int async);
int node_read_setup(struct tdisk *tdisk, struct node_comm *comm, struct node_sock *sock, struct qsio_scsiio *ctio, struct node_msg *msg, uint64_t lba, struct pgdata **pglist, int pglist_cnt, uint32_t transfer_length, int timeout);
int node_cmd_read_io(struct tdisk *tdisk, struct qsio_scsiio *ctio, struct node_comm *comm, struct node_sock *sock, struct node_msg *msg, struct pgdata **pglist, int pglist_cnt, int remote, int timeout);
struct node_comm * rep_comm_get(uint32_t dest_ipaddr, uint32_t src_ipaddr, int mirror_job);
void rep_comm_put(struct node_comm *comm, int mirror_job);
int rep_client_sock_init(struct node_comm *comm, int sock_count);
int node_usr_send_mirror_check(uint32_t mirror_ipaddr);
int node_usr_send_vdisk_attached(struct tdisk *tdisk);
int node_usr_send_job_completed(uint64_t job_id, int status);
int node_usr_send_vdisk_deleted(uint32_t target_id, int status);
int node_usr_send_bid_valid(int bid);
int node_usr_fence_node(void);
void node_usr_notify_msg(int notify_type, uint32_t target_id, struct usr_notify *notify_msg);

extern struct node_msg_list node_client_hash[];
extern struct node_msg_list node_client_accept_hash[];
extern struct node_msg_list node_usr_hash[];
extern struct node_msg_list node_master_hash[];
extern struct node_msg_list node_sync_accept_hash[];
extern struct node_msg_list node_sync_hash[];
extern struct node_msg_list node_rep_send_hash[];
extern struct node_msg_list node_rep_recv_hash[];

#define NODE_GET_SOCK_TIMEOUT		8000
#define NODE_GET_SOCK_TIMEOUT_FAST	2000

extern uint32_t wait_for_read_timeout_ticks;
extern uint32_t wait_for_write_ticks;
extern uint32_t wait_for_write_count;
extern uint32_t node_master_write_pre_ticks;
extern uint32_t node_master_lba_write_setup_ticks;
extern uint32_t node_master_scan_write_ticks;
extern uint32_t node_master_write_spec_setup_ticks;
extern uint32_t node_master_write_setup_send_ticks;
extern uint32_t node_master_cmd_generic_ticks;
extern uint32_t node_master_read_cmd_ticks;
extern uint32_t node_master_read_data_ticks;
extern uint32_t node_master_read_done_ticks;
extern uint32_t node_master_write_cmd_ticks;
extern uint32_t node_master_xcopy_read_ticks;
extern uint32_t node_master_xcopy_write_ticks;
extern uint32_t node_master_verify_data_ticks;
extern uint32_t node_master_write_comp_done_ticks;
extern uint32_t node_master_write_done_ticks;
extern uint32_t node_master_write_post_pre_ticks;
extern uint32_t node_master_write_data_unaligned_ticks;
extern uint32_t node_master_write_data_ticks;
#endif
