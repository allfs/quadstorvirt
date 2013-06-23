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

#ifndef QS_NODE_SYNC_H_
#define QS_NODE_SYNC_H_
#include "bdevmgr.h"

#define NODE_SYNC_TIMEOUT		15000
#define NODE_SYNC_RELINQUISH_TIMEOUT	30000
#define NODE_SYNC_TIMEOUT_LONG_LONG	(3 * 60 * 1000)
#define NODE_DDTABLES_SYNC_TIMEOUT	(5 * 60 * 1000)
#define NODE_LOGS_SYNC_TIMEOUT		(3 * 60 * 1000)

struct node_sync_post {
	void *priv;
	uint64_t write_id;
	struct iowaiter iowaiter;
	int type;
	STAILQ_ENTRY(node_sync_post) s_list;
};
STAILQ_HEAD(node_sync_post_list, node_sync_post);

struct node_ddlookup_sync_post {
	struct ddtable_ddlookup_node *ddlookup;
	struct ddtable *ddtable;
	uint64_t write_id;
};

struct ddtable_ddlookup_node;
struct amap_table_index;
int node_amap_sync_send(struct amap *amap);
int node_amap_meta_sync_send(struct amap *amap);
void node_amap_sync_recv(struct node_sock *sock, struct raw_node_msg *raw);
void node_amap_meta_sync_recv(struct node_sock *sock, struct raw_node_msg *raw);
void node_amap_sync_post_recv(struct node_sock *sock, struct raw_node_msg *raw);
int node_log_sync_send(struct log_page *log_page, struct tcache *tcache);
int node_log_sync_post_send(struct log_page *log_page);
void node_log_sync_recv(struct node_sock *sock, struct raw_node_msg *raw);
void node_log_sync_post_recv(struct node_sock *sock, struct raw_node_msg *raw);
int node_ddlookup_sync_send(struct ddtable *ddtable, struct ddtable_ddlookup_node *ddlookup, int32_t hash_id, uint64_t prev_b_start);
void node_ddlookup_sync_recv(struct node_sock *sock, struct raw_node_msg *raw);
void node_ddlookup_sync_post_recv(struct node_sock *sock, struct raw_node_msg *raw);
int node_index_lookup_sync_send(struct index_group *group, pagestruct_t *page);
void node_index_lookup_sync_recv(struct node_sock *sock, struct raw_node_msg *raw);
int node_bintindex_sync_send(struct bintindex *index, struct tcache *tcache, pagestruct_t *metadata, uint64_t write_id);
void node_bintindex_sync_recv(struct node_sock *sock, struct raw_node_msg *raw);
void node_bintindex_sync_post_recv(struct node_sock *sock, struct raw_node_msg *raw);
int node_amap_table_sync_send(struct amap_table *amap_table);
int node_amap_table_meta_sync_send(struct amap_table *amap_table);
int node_table_index_sync_send(struct tdisk *tdisk, struct amap_table_index *table_index, uint32_t table_index_id);
void node_table_index_sync_recv(struct node_sock *sock, struct raw_node_msg *msg);
void node_amap_table_sync_recv(struct node_sock *sock, struct raw_node_msg *raw);
void node_amap_table_meta_sync_recv(struct node_sock *sock, struct raw_node_msg *raw);
void node_amap_table_sync_post_recv(struct node_sock *sock, struct raw_node_msg *raw);
struct registration;
int node_registration_sync_send(struct tdisk *tdisk, struct registration *registration, int op);
void node_istate_clear_recv(struct node_sock *sock, struct raw_node_msg *raw);
int node_istate_sense_state_send(struct tdisk *tdisk);
void node_sense_state_recv(struct node_sock *sock, struct raw_node_msg *raw);
void node_registration_sync_recv(struct node_sock *sock, struct raw_node_msg *raw);
struct reservation;
int node_registration_clear_sync_send(struct tdisk *tdisk);
void node_registration_clear_sync_recv(struct node_sock *sock, struct raw_node_msg *raw);
int node_reservation_sync_send(struct tdisk *tdisk, struct reservation *reservation);
void node_reservation_sync_recv(struct node_sock *sock, struct raw_node_msg *raw);
int node_tdisk_sync_send(struct tdisk *tdisk);
void node_tdisk_sync_recv(struct node_sock *sock, struct raw_node_msg *msg);
int node_tdisk_update_send(struct tdisk *tdisk);
void node_tdisk_update_recv(struct node_sock *sock, struct raw_node_msg *msg);
int node_tdisk_delete_send(struct tdisk *tdisk);
void node_tdisk_delete_recv(struct node_sock *sock, struct raw_node_msg *msg);
int node_bint_sync_send(struct bdevint *bint);
void node_bint_sync_recv(struct node_sock *sock, struct raw_node_msg *raw);
int node_bint_delete_send(struct bdevint *bint);
void node_bint_delete_recv(struct node_sock *sock, struct raw_node_msg *raw);
int node_sync_setup_bdevs(void);
int node_sync_setup_bdevs_for_takeover(void);
void node_sync_pre(void);
void node_sync_mark_sync_enabled(void);
int node_sync_setup_logs(struct bdevint *bint);
int node_sync_setup_index_lookups(struct bdevint *bint);
int node_sync_comm_init(uint32_t remote_ipaddr, uint32_t node_ipaddr);
void node_sync_exit(void);
void node_sync_comm_exit(int graceful);
struct node_comm * node_sync_comm_get(void);
int node_sync_start(uint32_t remote_ipaddr, uint32_t node_ipaddr);
int node_sync_comm_check(uint32_t remote_ipaddr, uint32_t node_ipaddr);
int __node_sync_start(void);
void node_sync_force_restart(void);
void __node_sync_force_restart(void);
void node_sync_exit_threads(void);
int node_sync_register_send(struct node_comm *comm, int node_register);
void node_sync_register_recv(struct node_sock *sock, struct raw_node_msg *raw);
int node_sync_relinquish_send(void);
void node_sync_relinquish_recv(struct node_sock *sock, struct raw_node_msg *raw);
void node_sync_relinquish_status(struct node_sock *sock, struct raw_node_msg *raw);
int node_sync_disable_send(void);
void node_sync_disable(void);
void node_sync_disable_recv(struct node_sock *sock, struct raw_node_msg *raw);
int node_sync_takeover_send(void);
void node_sync_takeover_recv(struct node_sock *sock, struct raw_node_msg *raw);
int node_sync_takeover_post_send(void);
void node_sync_takeover_post_recv(struct node_sock *sock, struct raw_node_msg *raw);
void node_sync_notify_takeover(int graceful);
int node_sync_init_threads(void);
int node_sync_enabled(void);
int node_sync_inprogress(void);
int node_tdisk_sync_enabled(struct tdisk *tdisk);
int node_sync_need_resync(void);
int node_pgdata_sync_client_done(struct tdisk *tdisk, uint64_t transaction_id);
int node_pgdata_sync_complete(struct tdisk *tdisk, uint64_t transaction_id);
int node_pgdata_sync_start(struct tdisk *tdisk, struct write_list *wlist, struct pgdata **pglist, int pglist_cnt);
int node_newmeta_sync_start(struct tdisk *tdisk, struct write_list *wlist);
int node_newmeta_sync_complete(struct tdisk *tdisk, uint64_t transaction_id);
void node_newmeta_sync_start_recv(struct node_sock *sock, struct raw_node_msg *raw);
void node_pgdata_sync_start_recv(struct node_sock *sock, struct raw_node_msg *raw);
void node_pgdata_sync_client_done_recv(struct node_sock *sock, struct raw_node_msg *raw);
void node_newmeta_sync_complete_recv(struct node_sock *sock, struct raw_node_msg *raw);
void node_pgdata_sync_complete_recv(struct node_sock *sock, struct raw_node_msg *raw);
void node_client_notify_ha_status(int enabled);
void __node_client_notify_ha_status(uint32_t ipaddr, int enabled);

enum {
	NODE_SYNC_TYPE_AMAP,
	NODE_SYNC_TYPE_AMAP_TABLE,
	NODE_SYNC_TYPE_LOG,
	NODE_SYNC_TYPE_BINTINDEX,
	NODE_SYNC_TYPE_DDLOOKUP,
};

void ddtable_mark_sync_busy(struct bdevint *bint);
void ddtable_wait_sync_busy(struct ddtable *ddtable);
void ddtable_unmark_sync_busy(struct bdevint *bint);
int __node_bint_sync_send(struct bdevint *bint);
int __node_tdisk_sync_send(struct tdisk *tdisk);
void sync_post_wait_for_empty(void);
int node_sync_get_status(void);
void node_sync_set_status(int status);
struct node_msg * node_sync_msg_alloc(int dxfer_len, int msg_cmd);

#ifdef ENABLE_STATS
extern uint32_t ddlookup_sync_count;
extern uint32_t ddlookup_sync_ticks;
extern uint32_t ddlookup_sync_post_count;
extern uint32_t ddlookup_sync_post_ticks;
extern uint32_t log_sync_count;
extern uint32_t log_sync_ticks;
extern uint32_t log_sync_post_count;
extern uint32_t log_sync_post_ticks;
extern uint32_t index_lookup_sync_count;
extern uint32_t index_lookup_sync_ticks;
extern uint32_t index_sync_count;
extern uint32_t index_sync_ticks;
extern uint32_t index_sync_post_count;
extern uint32_t index_sync_post_ticks;
extern uint32_t amap_sync_count;
extern uint32_t amap_sync_ticks;
extern uint32_t amap_sync_post_count;
extern uint32_t amap_sync_post_ticks;
extern uint32_t amap_table_sync_count;
extern uint32_t amap_table_sync_ticks;
extern uint32_t amap_table_sync_post_count;
extern uint32_t amap_table_sync_post_ticks;
extern uint32_t amap_meta_sync_count;
extern uint32_t amap_meta_sync_ticks;
extern uint32_t amap_table_meta_sync_count;
extern uint32_t amap_table_meta_sync_ticks;
extern uint32_t table_index_sync_count;
extern uint32_t table_index_sync_ticks;
extern uint32_t reservation_sync_ticks;
extern uint32_t reservation_sync_count;
extern uint32_t sense_state_sync_ticks;
extern uint32_t sense_state_sync_count;
extern uint32_t istate_clear_sync_ticks;
extern uint32_t istate_clear_sync_count;
extern uint32_t registration_sync_ticks;
extern uint32_t registration_sync_count;
extern uint32_t registration_clear_sync_ticks;
extern uint32_t registration_clear_sync_count;
extern uint32_t tdisk_sync_ticks;
extern uint32_t tdisk_sync_count;
extern uint32_t pgdata_sync_complete_ticks;
extern uint32_t pgdata_sync_complete_count;
extern uint32_t pgdata_sync_client_done_ticks;
extern uint32_t pgdata_sync_client_done_count;
extern uint32_t pgdata_sync_start_ticks;
extern uint32_t pgdata_sync_start_count;
extern uint32_t bint_sync_ticks;
extern uint32_t bint_sync_count;
extern uint32_t sync_send_bytes;
extern uint32_t sync_page_send_bytes;
#endif
#endif
