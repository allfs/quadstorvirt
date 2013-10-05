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

#include "cluster.h"
#include "bdevmgr.h"
#include "qs_lib.h"
#include "tdisk.h"
#include "tcache.h"
#include "log_group.h"
#include "rcache.h"
#include "gdevq.h"
#include "../common/cluster_common.h" 
#include "node_sock.h"
#include "vdevdefs.h"
#include "node_sync.h"
#include "node_ha.h"
#include "ddthread.h"
#include "bdevgroup.h"

enum {
	HA_BUSY,
	HA_EXIT,
};

extern struct node_config master_config;
atomic_t node_transition;
kproc_t *ha_task;
extern wait_chan_t *ha_wait;
int ha_flags;
uint64_t ping_recv_timestamp;
uint64_t ping_sent_timestamp;

static int ha_read_config(struct ha_config *ha_config);

void
ha_set_ping_recv(void)
{
	chan_lock(ha_wait);
	ping_recv_timestamp = ticks;
	chan_unlock(ha_wait);
}

static inline void
ha_set_ping_sent(void)
{
	chan_lock(ha_wait);
	ping_sent_timestamp = ticks;
	chan_unlock(ha_wait);
}

static inline uint64_t 
ha_get_ping_recv(void)
{
	uint64_t ret;

	chan_lock(ha_wait);
	ret = ping_recv_timestamp;
	chan_unlock(ha_wait);
	return ret;
}

static inline uint64_t 
ha_get_ping_sent(void)
{
	uint64_t ret;

	ret = ping_sent_timestamp;
	return ret;
}

int
node_in_standby(void)
{
	return (node_get_role() == NODE_ROLE_STANDBY);
}
 
int
node_in_transition(void)
{
	return (atomic_read(&node_transition) == 1);
}
 
void 
node_set_in_transition(void)
{
	atomic_set(&node_transition, 1);
}
 
void 
node_clear_in_transition(void)
{
	atomic_set(&node_transition, 0);
}
 
static int
ha_set_config(struct ha_config *ha_config)
{
	pagestruct_t *page;
	uint64_t b_start;
	int retval;
	struct bdevint *ha_bint;

	ha_bint = bdev_group_get_ha_bint();
	if (!ha_bint) 
		return 0;

	page = vm_pg_alloc(VM_ALLOC_ZERO);
	if (unlikely(!page)) {
		debug_warn("Page allocation failure\n");
		return -1;
	}

	debug_info("timestamp %llu ipaddr %u ha_allowed %u ha init allowed %u\n", (unsigned long long)ha_config->timestamp, ha_config->ipaddr, ha_config->ha_allowed, ha_config->ha_allowed_init);
	memcpy(ha_config->magic, HA_MAGIC, strlen(HA_MAGIC));
	memcpy(vm_pg_address(page), ha_config, sizeof(*ha_config));
	b_start = BDEV_HA_OFFSET >> ha_bint->sector_shift;
	retval = qs_lib_bio_lba(ha_bint, b_start, page, QS_IO_WRITE, TYPE_HA_INDEX);
	vm_pg_free(page);

	if (unlikely(retval != 0))
		debug_warn_notify("Cannot read ha configuration from disk\n");
	return retval;
}

static int 
ha_fence_node(void)
{
	int retval;

	retval = node_usr_fence_node();
	if (unlikely(retval != USR_RSP_OK)) {
		debug_error_notify("fencing peer failed with error %d\n", retval);
		return -1;
	}
	return 0;
}

static void
ha_crit(char *msg)
{
	int retval;

	if (master_config.fence_enabled) {
		retval = ha_fence_node();
		if (unlikely(retval != 0))
			kern_panic(msg);
	}
	else
		kern_panic(msg);
}

void
node_ha_disable(void)
{
	struct ha_config ha_config;
	struct bdevint *ha_bint;
	int retval;
	char msg[128];

	if (node_get_role() != NODE_ROLE_MASTER)
		return;

	retval = ha_read_config(&ha_config);
	if (unlikely(retval != 0)) {
		ha_bint = bdev_group_get_ha_bint();
		if (ha_bint)
			ha_crit("Cannot read ownership from quorum disk\n");
		else
			return;
	}

	if (ha_config.ipaddr != master_config.ha_bind_ipaddr) {
		sprintf(msg, "Lost quorum when still master ha config ipaddr %u ha bind ipaddr %u\n", ha_config.ipaddr, master_config.ha_bind_ipaddr);
		kern_panic(msg);
	}

	bzero(&ha_config, sizeof(ha_config));
	ha_config.ipaddr = master_config.ha_bind_ipaddr;
	ha_config.ha_allowed = 0;
	ha_config.timestamp = ticks;
	retval = ha_set_config(&ha_config);
	if (unlikely(retval != 0)) {
		ha_bint = bdev_group_get_ha_bint();
		if (ha_bint)
			ha_crit("Cannot set ownership on quorum disk\n");
	}
}

static int 
node_ha_disable_nocheck(struct ha_config *old_config)
{
	struct ha_config ha_config;
	int retval;

	retval = ha_read_config(&ha_config);
	if (unlikely(retval != 0))
		return -1;

	debug_info("ha config timestamp %llu old config timestamp %llu\n", (unsigned long long)ha_config.timestamp, (unsigned long long)old_config->timestamp);
	if (ha_config.timestamp != old_config->timestamp)
		return -1;

	bzero(&ha_config, sizeof(ha_config));
	ha_config.ipaddr = master_config.ha_bind_ipaddr;
	ha_config.ha_allowed = 0;
	ha_config.timestamp = ticks;
	debug_info("set config timestamp %llu\n", (unsigned long long)ha_config.timestamp);
	retval = ha_set_config(&ha_config);
	memcpy(old_config, &ha_config, sizeof(ha_config));
	return retval;
}

void
node_ha_enable(void)
{
	struct ha_config ha_config;

	debug_check(node_get_role() != NODE_ROLE_MASTER && !node_in_transition());
	bzero(&ha_config, sizeof(ha_config));
	ha_config.ipaddr = master_config.ha_bind_ipaddr;
	ha_config.ha_allowed = 1;
	ha_config.timestamp = ticks;
	ha_set_config(&ha_config);
}

static void
node_ha_enable_init(void)
{
	struct ha_config ha_config;

	debug_check(node_get_role() != NODE_ROLE_MASTER);
	bzero(&ha_config, sizeof(ha_config));
	ha_config.ipaddr = master_config.ha_bind_ipaddr;
	ha_config.ha_allowed_init = 1;
	ha_config.timestamp = ticks;
	ha_set_config(&ha_config);
}

static int
node_resp_status(struct node_msg *msg)
{
	struct node_msg *resp;
	struct raw_node_msg *raw;

	resp = msg->resp;

	if (unlikely(!resp))
		return -1;

	raw = resp->raw;
	if (raw->msg_status == NODE_STATUS_OK)
		return 0;
	else
		return raw->msg_status;
}

static int
ha_read_config(struct ha_config *ha_config)
{
	pagestruct_t *page;
	int retval;
	uint64_t b_start;
	struct bdevint *ha_bint;

	ha_bint = bdev_group_get_ha_bint();
	if (unlikely(!ha_bint))
		return -1;

	page = vm_pg_alloc(0);
	if (unlikely(!page)) {
		debug_warn("Page allocation failure\n");
		return -1;
	}

	b_start = BDEV_HA_OFFSET >> ha_bint->sector_shift;
	retval = qs_lib_bio_lba(ha_bint, b_start, page, QS_IO_READ, TYPE_HA_INDEX);
	if (unlikely(retval != 0)) {
		debug_warn_notify("Cannot read ha configuration from disk\n");
		vm_pg_free(page);
		return -1;
	}
	memcpy(ha_config, vm_pg_address(page), sizeof(*ha_config));
	vm_pg_free(page);
	return 0;
}

static int
check_ha_active(uint64_t timestamp, int check_timestamp)
{
	struct ha_config ha_config;
	int retval;

	pause("psg", ha_check_timeout);
	bzero(&ha_config, sizeof(ha_config));
	retval = ha_read_config(&ha_config);
	if (unlikely(retval != 0)) {
		return -1;
	}

	debug_info("ha allowed %d ha allowed init %d ipaddr %u ha config timestamp %llu check_timestamp %d timestamp %llu\n", ha_config.ha_allowed, ha_config.ha_allowed_init, ha_config.ipaddr, (unsigned long long)ha_config.timestamp, check_timestamp, (unsigned long long)timestamp);

	if (!ha_config.ha_allowed && !ha_config.ha_allowed_init && !check_timestamp)
		return 1;

	if (ha_config.timestamp != timestamp)
		return 1;
	else
		return 0;
}

static inline int
ha_peer_role(void)
{
	struct node_msg *msg;
	struct raw_node_msg *raw;
	struct node_sock *sock;
	int role, retval;
	struct node_comm *comm;

	retval = node_sync_comm_init(master_config.ha_ipaddr, master_config.ha_bind_ipaddr);
	if (unlikely(retval != 0)) {
		debug_warn("sync comm init failed\n");
		return NODE_ROLE_UNKNOWN;
	}
		
	comm = node_sync_comm_get();
	if (!comm) {
		debug_warn("sync comm get failed\n");
		return NODE_ROLE_UNKNOWN;
	}

	sock = node_comm_get_sock(comm, NODE_GET_SOCK_TIMEOUT);
	if (!sock) {
		debug_warn("sync comm get free sock failed\n");
		node_comm_put(comm);
		return NODE_ROLE_UNKNOWN;
	}

	msg = node_msg_alloc(0);
	raw = msg->raw;
	bzero(raw, sizeof(*raw));
	raw->msg_id = node_transaction_id();
	raw->msg_cmd = NODE_MSG_ROLE; 
	raw->dxfer_len = 0;
	retval = node_send_msg(sock, msg, raw->msg_id, 1);
	if (unlikely(retval != 0)) {
		debug_warn("sync comm send peer role msg failed\n");
		node_sock_finish(sock);
		node_comm_put(comm);
		node_msg_free(msg);
		return NODE_ROLE_UNKNOWN;
	}

	node_msg_wait(msg, sock, NODE_GENERIC_TIMEOUT);
	node_sock_finish(sock);
	node_comm_put(comm);
	retval = node_resp_status(msg);

	if (retval != 0) {
		debug_warn("sync comm get peer role resp failed\n");
		node_msg_free(msg);
		return NODE_ROLE_UNKNOWN;
	}

	role = msg->resp->raw->cmd_status;
	debug_info("Got role %d\n", role);
	node_msg_free(msg);
	return role;
}

enum {
	NODE_HA_CHECK_ERROR = -1,
	NODE_HA_CHECK_OK = 0,
	NODE_HA_CHECK_NEED_RESYNC,
	NODE_HA_CHECK_TAKEOVER,
};

static int 
node_standby_checks(void)
{
	int retval;
	struct ha_config ha_config;
	uint64_t ping_recv; 

	ping_recv = ha_get_ping_recv();
	debug_info("ping recv %llu ping sent %llu\n", (unsigned long long)ping_recv, (unsigned long long)ha_get_ping_sent());
	bzero(&ha_config, sizeof(ha_config));

	retval = ha_read_config(&ha_config);
	if (unlikely(retval != 0)) {
		debug_warn_notify("Error reading HA configuration\n");
		node_sync_disable();
		pause("psg", ha_check_timeout);
		return NODE_HA_CHECK_ERROR;
	}

	debug_info("ha allowed %d ha allowed init %d ipaddr %u timestamp %llu\n", ha_config.ha_allowed, ha_config.ha_allowed_init, ha_config.ipaddr, (unsigned long long)ha_config.timestamp);
	retval = check_ha_active(ha_config.timestamp, 0);
	if (unlikely(retval < 0)) {
		debug_warn_notify("Check for peer node failed\n");
		node_sync_disable();
		pause("psg", ha_check_timeout);
		return NODE_HA_CHECK_ERROR;
	}

	if (retval > 0) {
		debug_warn_notify("master %u seems to be active, but unresponsive over sync port\n", ha_config.ipaddr);
		node_sync_disable();
		pause("psg", ha_check_timeout);
		return NODE_HA_CHECK_NEED_RESYNC;
	}

	debug_info("ping recv %llu ping sent %llu\n", (unsigned long long)ha_get_ping_recv(), (unsigned long long)ha_get_ping_sent());
	if (ping_recv != ha_get_ping_recv()) {
		debug_warn_notify("master %u seems to be active, but unresponsive over sync port\n", ha_config.ipaddr);
		node_sync_disable();
		pause("psg", ha_check_timeout);
		return NODE_HA_CHECK_NEED_RESYNC;
	}

	debug_info("peer failed, need to takeover\n");
	return NODE_HA_CHECK_TAKEOVER;
}

static int 
node_master_checks(void)
{
	debug_warn_notify("Peer node has probably failed. Disabling ha\n");
	node_sync_disable();
	return NODE_HA_CHECK_OK;
}

static void 
node_ha_peer_checks(void)
{
	int retval;

	debug_info("node role %d\n", node_get_role());
	if (node_get_role() == NODE_ROLE_STANDBY) {
		if (node_sync_need_resync()) {
			node_sync_comm_exit(1);
			return;
		}

		retval = node_standby_checks();
		debug_info("standby check retval %d\n", retval);
		if (retval == NODE_HA_CHECK_NEED_RESYNC) {
			node_sync_force_restart();
		}
		else if (retval == NODE_HA_CHECK_TAKEOVER) {
			struct ha_config ha_config;

			retval = node_ha_takeover_pre(&ha_config, 0, 1);
			if (retval == 0)
				node_ha_takeover(&ha_config, 0);
		}
	}
	else if (node_get_role() == NODE_ROLE_MASTER) {
		node_master_checks();
	}
	else {
		pause("psg", ha_check_timeout);
		debug_check(1);
	}
	node_sync_comm_exit(0);
}

void
wait_for_ha_busy(void)
{
	wait_on_chan(ha_wait, !atomic_test_bit(HA_BUSY, &ha_flags));
}

static void
mark_ha_busy(void)
{
	chan_lock(ha_wait);
	atomic_set_bit(HA_BUSY, &ha_flags);
	chan_unlock(ha_wait);
}

static void
unmark_ha_busy(void)
{
	chan_lock(ha_wait);
	atomic_clear_bit(HA_BUSY, &ha_flags);
	chan_wakeup_unlocked(ha_wait);
	chan_unlock(ha_wait);
}

static void
ha_pause(int timeout)
{
	if (!kernel_thread_check(&ha_flags, HA_EXIT)) 
		pause("psg", timeout);
}

static int
node_msg_ha_wait(struct node_msg *msg, struct node_sock *sock)
{
	int retval;

	msg->timestamp = ticks;
	retval = wait_for_done_timeout(msg->completion, ha_ping_timeout);
	if (retval) {
		retval = node_resp_status(msg);
		node_resp_free(msg);
		return retval;
	}

	if (get_elapsed(ha_get_ping_recv()) < get_elapsed(msg->timestamp)) {
		debug_info("ping recv %llu timestamp %llu\n", (unsigned long long)ha_get_ping_recv(), (unsigned long long)msg->timestamp);
		if (node_type_controller())
			retval = wait_for_done_timeout(msg->completion, ha_ping_timeout >> 1);
		else 
			retval = wait_for_done_timeout(msg->completion, ha_ping_timeout);
		if (retval) {
			retval = node_resp_status(msg);
			node_resp_free(msg);
			return retval;
		}
	}

	retval = node_cmd_hash_remove(sock->comm->node_hash, msg, msg->raw->msg_id);
	if (!retval) {
		wait_for_done(msg->completion);
	}
	else {
		node_sock_read_error(sock);
		debug_check(msg->resp);
	}

	retval = node_resp_status(msg);
	node_resp_free(msg);
	debug_info("retval %d\n", retval);
	return retval;
}

#ifdef FREEBSD 
static void node_ha_thr(void *data)
#else
static int node_ha_thr(void *data)
#endif
{
	struct node_msg *msg;
	struct raw_node_msg *raw;
	struct node_sock *sock;
	struct node_comm *comm;
	int retval;
	struct bdevint *ha_bint;

	__sched_prio(curthread, QS_PRIO_SWP);

	msg = node_msg_alloc(0);
	raw = msg->raw;
	bzero(raw, sizeof(*raw));
	raw->msg_id = node_transaction_id();
	raw->msg_cmd = NODE_MSG_HA_PING;
	raw->dxfer_len = 0;

	while (!kernel_thread_check(&ha_flags, HA_EXIT)) {
		mark_ha_busy();

		ha_bint = bdev_group_get_ha_bint();
		if (!ha_bint) {
			unmark_ha_busy();
			ha_pause(ha_check_timeout);
			continue;
		}

		if (!node_sync_enabled()) {
			if (node_get_role() == NODE_ROLE_MASTER && node_type_master()) {
				node_ha_disable();
				unmark_ha_busy();
				ha_pause(ha_check_timeout);
				continue;
			}

			if (!node_sync_need_resync()) {
				unmark_ha_busy();
				ha_pause(ha_check_timeout);
				continue;
			}
		}

		if (node_sync_inprogress() || node_in_transition()) {
			unmark_ha_busy();
			ha_pause(ha_check_timeout);
			continue;
		}

		if (kernel_thread_check(&ha_flags, HA_EXIT)) {
			unmark_ha_busy();
			continue;
		}

		retval = node_sync_comm_check(master_config.ha_ipaddr, master_config.ha_bind_ipaddr);
		if (unlikely(retval != 0)) {
			unmark_ha_busy();
			ha_pause(ha_check_timeout);
			continue;
		}

		comm = node_sync_comm_get();
		if (!comm) {
			unmark_ha_busy();
			ha_pause(ha_check_timeout);
			continue;
		}

		sock = node_comm_get_sock(comm, NODE_GET_SOCK_TIMEOUT);
		if (!sock) {
			debug_warn("Failed to get a new sock\n");
			node_comm_put(comm);
			node_ha_peer_checks();
			unmark_ha_busy();
			ha_pause(ha_check_timeout);
			continue;
		}

		node_msg_init(msg);
		retval = node_send_msg(sock, msg, raw->msg_id, 1);
		if (unlikely(retval != 0)) {
			debug_warn_notify("Failed to send ping message to standby/active node\n");
			node_sock_finish(sock);
			node_comm_put(comm);
			node_ha_peer_checks();
			unmark_ha_busy();
			ha_pause(ha_check_timeout);
			continue;
		}

		retval = node_msg_ha_wait(msg, sock);
		node_sock_finish(sock);
		node_comm_put(comm);
		if (unlikely(retval != 0 && retval != NODE_STATUS_NEED_RESYNC)) {
			debug_warn_notify("Failed to get a success response from standby/active node\n");
			node_ha_peer_checks();
			unmark_ha_busy();
			ha_pause(ha_check_timeout);
			continue;
		}

		if (node_in_standby() && retval == NODE_STATUS_NEED_RESYNC)
			node_sync_force_restart();

		ha_set_ping_sent();
		if (node_sync_need_resync()) {
			retval = node_sync_start(master_config.ha_ipaddr, master_config.ha_bind_ipaddr);
			unmark_ha_busy();
			if (retval != 0)
				node_sync_comm_exit(1);
			ha_pause(ha_check_timeout);
			continue;
		}

		unmark_ha_busy();
		ha_pause(ha_check_timeout);
	}

	node_msg_free(msg);

#ifdef FREEBSD 
	kproc_exit(0);
#else
	return 0;
#endif
}

static int 
node_ha_thr_setup(void)
{
	int retval;

	if (ha_task)
		return 0;

	retval = kernel_thread_create(node_ha_thr, NULL, ha_task, "hathr");
	return retval;
}

int
node_master_ha_init(void)
{
	int retval = 0;
	int tries = 5;

	if (node_get_role() != NODE_ROLE_STANDBY)
		return 0;

again:
	__node_sync_force_restart();
	retval = node_sync_start(master_config.ha_ipaddr, master_config.ha_bind_ipaddr);
	if (node_sync_get_status() == NODE_SYNC_NEED_RESYNC) {
		tries--;
		if (!tries) {
			debug_error_notify("Cannot setup as ha standby node. Giving up\n");
			return retval;
		}
		debug_info("retrying master sync\n");
		pause("psg", ha_check_timeout);
		goto again;
	}
 
	if (node_sync_get_status() == NODE_SYNC_DONE) {
		retval = node_ha_thr_setup();
		if (unlikely(retval != 0)) {
			debug_warn_notify("Failed to create a new ha thread\n");
			node_sync_disable();
		}
	}

	return retval;
}

void
ha_init_config(void)
{
	struct ha_config ha_config;
	struct bdevint *ha_bint;

	ha_bint = bdev_group_get_ha_bint();
	debug_check(!ha_bint);
	bzero(&ha_config, sizeof(ha_config));
	ha_set_config(&ha_config);
}

static int
ha_config_magic_valid(struct ha_config *ha_config)
{
	if (memcmp(ha_config->magic, HA_MAGIC, strlen(HA_MAGIC)) == 0)
		return 1;
	else
		return 0;
}

int
node_controller_ha_init(void)
{
	int retval, error;
	struct ha_config ha_config;
	int peer_role = NODE_ROLE_UNKNOWN;
	struct bdevint *ha_bint;
	int retries = 5;

	ha_bint = bdev_group_get_ha_bint();

	debug_info("ha bint %p\n", ha_bint);
	if (!ha_bint) {
		debug_info("setting node role to master\n");
		node_set_role(NODE_ROLE_MASTER);
		return 0;
	}

	bzero(&ha_config, sizeof(ha_config));
	retval = ha_read_config(&ha_config);
	if (unlikely(retval != 0)) {
		return -1;
	}

	debug_info("ha config ipaddr %u master config controller ipaddr %u ha bint %p ha allowed %u\n", ha_config.ipaddr, master_config.ha_bind_ipaddr, ha_bint, ha_config.ha_allowed);
	if (!ha_config.ipaddr || ha_config.ipaddr == master_config.ha_bind_ipaddr || !ha_config_magic_valid(&ha_config) || ha_config.ha_allowed_init) {
		debug_info("node role setting as master\n");
		bzero(&ha_config, sizeof(ha_config));
		ha_config.ipaddr = master_config.ha_bind_ipaddr;
		ha_config.timestamp = ticks;
		retval = ha_set_config(&ha_config);
		if (unlikely(retval != 0))
			return -1;
		node_set_role(NODE_ROLE_MASTER);
	}
	else {
		debug_info_notify("ha config ipaddr %u master config controller ipaddr %u ha bint %p ha allowed %u\n", ha_config.ipaddr, master_config.ha_bind_ipaddr, ha_bint, ha_config.ha_allowed);
		peer_role = ha_peer_role();
		if (peer_role == NODE_ROLE_MASTER) {
			node_set_role(NODE_ROLE_STANDBY);
			goto out;
		}
		else if (peer_role == NODE_ROLE_UNKNOWN) {
retry:
			retval = check_ha_active(ha_config.timestamp, 1);
			if (unlikely(retval < 0)) {
				return -1;
			}

			debug_info("Check ha active %d\n", retval);

			if (retval && ha_config.ipaddr != master_config.ha_ipaddr) {
				debug_warn_notify("ha node specified as %u but it seems that %u is active\n", master_config.ha_ipaddr, ha_config.ipaddr);
				return -1;
			}
			else if (retval) {
				debug_warn_notify("peer node %u responsive over network, but role is unknown\n", ha_config.ipaddr);
				return -1;
			}

			if (master_config.fence_enabled) {
				if (ha_config.ipaddr != master_config.ha_ipaddr) {
					debug_warn("ha peer specified as %u but ha config on disk says %u\n", master_config.ha_ipaddr, ha_config.ipaddr);
					if (--retries)
						goto retry;
				}
				else {
					debug_warn_notify("Trying to fence peer node %u\n", ha_config.ipaddr);
					retval = ha_fence_node();
					if (unlikely(retval != 0)) {
						debug_error_notify("Fencing peer node failed, cannot continue\n");
						return -1;
					}
				}
			}
			else {
				debug_error_notify("Fence command not specified. Cannot continue\n");
				return -1;
			}
		}

		bzero(&ha_config, sizeof(ha_config));
		ha_config.ipaddr = master_config.ha_bind_ipaddr;
		ha_config.timestamp = ticks;
		retval = ha_set_config(&ha_config);
		if (unlikely(retval != 0))
			return -1;
		node_set_role(NODE_ROLE_MASTER);
	}

out:
	retval = 0;
	if (node_get_role() == NODE_ROLE_STANDBY) {
		debug_info("start sync\n");
#if 0
		retval = node_sync_comm_init(master_config.ha_ipaddr, master_config.ha_bind_ipaddr);
		if (unlikely(retval != 0)) {
			debug_warn("sync comm init failed\n");
			return -1;
		}
#endif

		__node_sync_force_restart();
		retval = __node_sync_start();
		if (unlikely(retval != 0)) {
			debug_error_notify("Controller failed to sync states from peer. Cannot continue\n");
			return -1;
		}

		debug_info("take over send\n");
		retval = node_sync_takeover_send();
		if (unlikely(retval) != 0) {
			debug_error_notify("HA takeover from peer failed. Cannot continue\n");
			node_sync_disable();
			return -1;
		}
		debug_info("ha takeover\n");
		retval = node_ha_takeover_pre(&ha_config, 1, 0);
		if (retval == 0)
			retval = node_ha_takeover(&ha_config, 1);
		debug_info("takeover status %d\n", retval);
		if (retval == 0) 
			retval = 1;

		error = node_ha_thr_setup();
		if (error != 0) {
			retval = -1;
			node_sync_disable();
		}
	}
	else if (master_config.ha_ipaddr) {
		retval = node_ha_thr_setup();
		if (unlikely(retval != 0))
			node_sync_disable();
	}
	return retval;
}

void
node_ha_exit(void)
{
	int err, retval;

	if (!ha_task && node_type_controller()) {
		node_master_sync_wait();
		node_set_role(NODE_ROLE_STANDBY);
		node_set_in_transition();
		mdevq_wait_for_empty();
		node_master_pending_writes_wait();
		master_queue_wait_for_empty();
		ddthread_wait_for_empty();
		sync_post_wait_for_empty();
		node_set_role(NODE_ROLE_MASTER);
		node_sync_disable_send();
		node_clear_in_transition();
		return;
	}

	if (!ha_task)
		return;

	wait_for_ha_busy();
	err = kernel_thread_stop(ha_task, &ha_flags, ha_wait, HA_EXIT);
	if (unlikely(err)) {
		debug_warn("Shutting down ha thread failed\n");
		return;
	}

	debug_info("node sync enabled %d node in standby %d\n", node_sync_enabled(), node_in_standby());
	if (node_sync_enabled() && !node_in_standby()) {
		debug_info("wait for sync\n");
		node_master_sync_wait();
		debug_info("disable ha\n");
		node_ha_disable();
		debug_info("set in transition\n");
		node_set_in_transition();
		node_set_role(NODE_ROLE_STANDBY);
		mdevq_wait_for_empty();
		debug_info("wait for pending writes\n");
		node_master_pending_writes_wait();
		master_queue_wait_for_empty();
		debug_info("wait for ddthread queue\n");
		ddthread_wait_for_empty();
		debug_info("wait for sync post\n");
		bdev_groups_ddtable_wait_sync_busy();
		debug_info("wait for mdevq queue\n");
		sync_post_wait_for_empty();
		debug_info("setup bdevs for takeover\n");
		node_sync_setup_bdevs_for_takeover();
		debug_info("enable ha\n");
		node_ha_enable();
		debug_info("clear in transition  sync\n");
		debug_info("send relinquish command\n");
		retval = node_sync_relinquish_send();
		if (unlikely(retval != 0)) {
#if 0
			node_client_notify_ha_status(0);
#endif
			node_set_role(NODE_ROLE_MASTER);
			node_ha_enable_init();
		}
		node_clear_in_transition();
	}
	else if (!node_sync_enabled() && !node_in_standby()) {
		node_ha_enable_init();
	}
	else {
		node_sync_disable_send();
	}

	ha_task = NULL;
}

static void
node_ha_bdevs_takeover(void)
{
	struct bdevint *bint;
	int i;

	for (i = 0; i < TL_MAX_DISKS; i++) {
		bint = bint_list[i];
		if (!bint || bint->initialized <= 0)
			continue;

		bint_ha_takeover(bint);
	}
}

static void
node_ha_bdevs_takeover_post(void)
{
	struct bdevint *bint;
	int i;

	for (i = 0; i < TL_MAX_DISKS; i++) {
		bint = bint_list[i];
		if (!bint || bint->initialized <= 0)
			continue;

		bint_ha_takeover_post(bint);
	}

	for (i = 0; i < TL_MAX_DISKS; i++) {
		bint = bint_list[i];
		if (!bint || bint->initialized <= 0)
			continue;

		bint_ha_takeover_post_load(bint);
	}
}

static int 
log_group_sync_pending(struct log_group *group, struct tcache_list *tcache_list)
{
	int i, pending = 0, retval;
	struct log_page *log_page;
	struct tcache *tcache = NULL;

	for (i = 0; i < LOG_GROUP_MAX_PAGES; i++) {
		log_page = group->logs[i];
		if (!atomic_test_bit_short(LOG_META_DATA_DIRTY, &log_page->flags))
			continue;
		pending++;
		log_group_add_write_page(group, log_page);
	}

	if (!pending)
		return 0;

	retval = log_group_io(group, &tcache);
	if (unlikely(retval != 0))
		return -1;

	if (tcache)
		SLIST_INSERT_HEAD(tcache_list, tcache, t_list);
	return 0;
}

static int 
bint_ha_logs_takeover(struct bdevint *bint)
{
	struct log_group *log_group;
	int error = 0, retval;
	struct tcache_list tcache_list;

	SLIST_INIT(&tcache_list);
	LIST_FOREACH(log_group, &bint->log_group_list, g_list) {
		log_group_lock(log_group);
		retval = log_group_sync_pending(log_group, &tcache_list);
		log_group_unlock(log_group);
		if (unlikely(retval != 0))
			error = -1;
	}

	debug_info("wait for tcache list\n");
	retval = tcache_list_wait(&tcache_list);
	debug_info("done wait for tcache list\n");
	if (unlikely(retval != 0))
		error = -1;
	return error;
}

static int 
node_ha_logs_takeover(void)
{
	struct bdevint *bint;
	int error = 0, retval, i;

	for (i = 0; i < TL_MAX_DISKS; i++) {
		bint = bint_list[i];
		if (!bint || bint->initialized <= 0 || !bint->log_disk)
			continue;

		retval = bint_ha_logs_takeover(bint);
		if (unlikely(retval != 0))
			error = -1;
	}
	return error;
}

static int
bdev_conditional_free(struct bdevint *bint, uint64_t b_start, struct index_sync_list *index_sync_list)
{
	struct bintindex *index;
	struct index_group *group;
	struct index_subgroup *subgroup;
	uint32_t group_id, subgroup_id;
	uint32_t subgroup_offset;
	uint64_t index_id;
	uint32_t entry;
	int freed;
	int retval;

	index_id = index_id_from_block(bint, b_start, &entry);
	group_id = index_group_id(index_id);
	subgroup_id = index_subgroup_id(index_id, &subgroup_offset); 

	debug_check(group_id >= bint->max_index_groups);
	group = bint->index_groups[group_id];

	debug_check(subgroup_id >= group->max_subgroups);
	subgroup = group->subgroups[subgroup_id];

	sx_xlock(subgroup->subgroup_lock);
	index = subgroup_get_index(subgroup, index_id, 0);
	debug_check(!index);
	if (unlikely(!index)) {
		sx_xunlock(subgroup->subgroup_lock);
		return -1;
	}

	if (atomic_test_bit(META_IO_READ_PENDING, &index->flags)) {
		retval = qs_lib_bio_lba(bint, bint_index_bstart(subgroup->group->bint, index->index_id), index->metadata, QS_IO_READ, TYPE_BINT);
		if (unlikely(retval != 0)) {
			sx_xunlock(subgroup->subgroup_lock);
			index_put(index);
			return -1;
		}
		atomic_clear_bit(META_IO_READ_PENDING, &index->flags);
	}
	sx_xunlock(subgroup->subgroup_lock);

	wait_on_chan(index->index_wait, !atomic_test_bit(META_DATA_READ_DIRTY, &index->flags));
	index_lock(index);
	index_check_load(index);
	if (atomic_test_bit(META_DATA_ERROR, &index->flags)) {
		index_unlock(index);
		index_put(index);
		return -1;
	}
	bint_free_block(bint, index, entry, LBA_SIZE, &freed, TYPE_META_BLOCK, 1);
	index_unlock(index);
	index_sync_insert(index_sync_list, index);
	index_put(index);
	return 0;
}

int
bdev_conditional_ref(struct bdevint *bint, uint64_t b_start, struct index_sync_list *index_sync_list)
{
	struct bintindex *index;
	struct index_group *group;
	struct index_subgroup *subgroup;
	uint32_t group_id, subgroup_id;
	uint32_t subgroup_offset;
	uint64_t index_id;
	uint32_t entry;
	int retval;

	index_id = index_id_from_block(bint, b_start, &entry);
	group_id = index_group_id(index_id);
	subgroup_id = index_subgroup_id(index_id, &subgroup_offset); 

	debug_check(group_id >= bint->max_index_groups);
	group = bint->index_groups[group_id];

	debug_check(subgroup_id >= group->max_subgroups);
	subgroup = group->subgroups[subgroup_id];

	sx_xlock(subgroup->subgroup_lock);
	index = subgroup_get_index(subgroup, index_id, 0);
	debug_check(!index);
	if (unlikely(!index)) {
		sx_xunlock(subgroup->subgroup_lock);
		return 0;
	}

	if (atomic_test_bit(META_IO_READ_PENDING, &index->flags)) {
		retval = qs_lib_bio_lba(bint,  bint_index_bstart(subgroup->group->bint, index->index_id), index->metadata, QS_IO_READ, TYPE_BINT);
		if (unlikely(retval != 0)) {
			sx_xunlock(subgroup->subgroup_lock);
			index_put(index);
			return -1;
		}
		atomic_clear_bit(META_IO_READ_PENDING, &index->flags);
	}
	sx_xunlock(subgroup->subgroup_lock);

	wait_on_chan(index->index_wait, !atomic_test_bit(META_DATA_READ_DIRTY, &index->flags));
	index_lock(index);
	index_check_load(index);
	if (atomic_test_bit(META_DATA_ERROR, &index->flags)) {
		index_unlock(index);
		index_put(index);
		return -1;
	}
	bint_log_replay(bint, index, entry, LBA_SIZE, TYPE_META_BLOCK);
	index_unlock(index);
	index_sync_insert(index_sync_list, index);
	index_put(index);
	return 0;
}

static int
metadata_empty(pagestruct_t *metadata)
{
	return (zero_memcmp((uint64_t *)(vm_pg_address(metadata))) == 0);
}

#if 0
static int
node_amap_table_sync(struct amap_table *amap_table, struct index_sync_list *index_sync_list)
{
	struct amap *amap;
	uint64_t block;
	int retval, error = 0;
	int i;

	for (i = 0; i < AMAPS_PER_AMAP_TABLE; i++) {
		amap = amap_table->amap_index[i];
		if (!amap)
			continue;
		debug_check(atomic_test_bit_short(AMAP_META_IO_PENDING, &amap->flags));
		debug_check(atomic_test_bit_short(AMAP_META_DATA_DIRTY, &amap->flags));
		debug_check(atomic_test_bit_short(AMAP_META_DATA_INVALID, &amap->flags));
		atomic_clear_bit_short(AMAP_META_IO_PENDING, &amap->flags);
		if (!atomic_test_bit_short(AMAP_META_DATA_NEW, &amap->flags))
			continue;
		block = get_amap_block(amap_table, amap->amap_idx);
		if (!block) {
			debug_check(!metadata_empty(amap->metadata));
			amap_table->amap_index[i] = NULL;
			retval = bdev_conditional_free(amap_bint(amap), amap_bstart(amap), index_sync_list);
			amap_put(amap);
		}
		else {
			retval = bdev_conditional_ref(amap_bint(amap), amap_bstart(amap), index_sync_list);
			atomic_set_bit_short(ATABLE_META_IO_PENDING, &amap->amap_table->flags);
		}
		if (unlikely(retval != 0))
			error = -1;
		atomic_clear_bit_short(AMAP_META_DATA_NEW, &amap->flags);
	}
	return error;
}
#endif

static int
node_amap_table_group_sync(struct tdisk *tdisk, struct amap_table_group *group, struct index_sync_list *index_sync_list)
{
	struct amap_table *amap_table;
	struct amap_table_index *table_index;
	uint64_t block;
	int i, retval, error = 0;
	uint32_t index_id, index_offset;
	struct tpriv priv = { 0 };
	struct iowaiter iowaiter;
	struct bio_meta bio_meta;

	for (i = 0; i < group->amap_table_max; i++) {
		amap_table = group->amap_table[i];
		if (!amap_table)
			continue;

		index_id = amap_table->amap_table_id >> INDEX_TABLE_GROUP_SHIFT;
		index_offset = amap_table->amap_table_id & INDEX_TABLE_GROUP_MASK;
		table_index = &tdisk->table_index[index_id];
		block = get_amap_table_block(table_index, index_offset);

		if (atomic_test_bit_short(ATABLE_META_DATA_INVALID, &amap_table->flags)) {
			debug_info("amap b_start %llu is dirty block %llu\n", (unsigned long long)amap_table_bstart(amap_table), (unsigned long long)block);
			if (!block) {
				debug_check(!metadata_empty(amap_table->metadata));
				retval = bdev_conditional_free(amap_table_bint(amap_table), amap_table_bstart(amap_table), index_sync_list);
				if (unlikely(retval != 0))
					error = -1;
			}
			amap_table_remove(group, amap_table);
			continue;
		}

		if (block && !atomic_test_bit_short(ATABLE_META_IO_PENDING, &amap_table->flags) && !atomic_test_bit_short(ATABLE_META_DATA_NEW, &amap_table->flags))
			continue;

		if (!atomic_test_bit_short(ATABLE_META_IO_PENDING, &amap_table->flags))
			goto skip;

		atomic_clear_bit_short(ATABLE_META_IO_PENDING, &amap_table->flags);
		amap_table_lock(amap_table);
#if 0
		retval = node_amap_table_sync(amap_table, index_sync_list);
		if (unlikely(retval != 0))
			error = -1;
#endif

		bzero(&iowaiter, sizeof(iowaiter));
		amap_table_start_writes(amap_table, &iowaiter);
		amap_table_unlock(amap_table);

		bdev_marker(amap_table_bint(amap_table)->b_dev, &priv);
		amap_table_end_writes(amap_table);
		bdev_start(amap_table_bint(amap_table)->b_dev, &priv);
		amap_table_end_wait(amap_table, &iowaiter);
		free_iowaiter(&iowaiter);

		if (block && !atomic_test_bit_short(ATABLE_META_DATA_NEW, &amap_table->flags))
			continue;
skip:
		atomic_clear_bit_short(ATABLE_META_DATA_NEW, &amap_table->flags);
		index_id = amap_table->amap_table_id >> INDEX_TABLE_GROUP_SHIFT;
		index_offset = amap_table->amap_table_id & INDEX_TABLE_GROUP_MASK;
		table_index = &tdisk->table_index[index_id];
		if (!block)
			set_amap_table_block(table_index, index_offset, amap_table->amap_table_block);
		bio_meta_init(&bio_meta);
		qs_lib_bio_page(table_index->bint, table_index->b_start, BINT_INDEX_META_SIZE, table_index->metadata, NULL, &bio_meta, QS_IO_WRITE, TYPE_TDISK_INDEX);
		wait_for_bio_meta(&bio_meta);
		bio_meta_destroy(&bio_meta);
	}
	return error;
}

static int
node_tdisk_amaps_sync(struct tdisk *tdisk)
{
	struct amap_table_group *group;
	int i, retval, error = 0;
	struct index_sync_list index_sync_list;

	SLIST_INIT(&index_sync_list);
	for (i = 0; i < tdisk->amap_table_group_max; i++) {
		group = tdisk->amap_table_group[i];
		if (!group)
			continue;
		retval = node_amap_table_group_sync(tdisk, group, &index_sync_list);
		if (unlikely(retval != 0))
			error = -1;
	}

	retval = index_sync_start_io(&index_sync_list, 1);
	if (unlikely(retval != 0)) {
		debug_warn("Failed to issue io for indexes\n");
		error = -1;
	}

	retval = index_sync_wait(&index_sync_list);
	if (unlikely(retval != 0)) {
		debug_warn("Indexes write error\n");
		error = -1;
	}

	return error;
}

static int
node_ha_tdisk_amaps_sync(void)
{
	struct tdisk *tdisk;
	int i, error = 0, retval;

	for (i = 0; i < TL_MAX_DEVICES; i++) {
		tdisk = tdisk_lookup[i];
		if (!tdisk)
			continue;
		retval = node_tdisk_amaps_sync(tdisk);
		if (unlikely(retval != 0)) {
			error = -1;
		}
	}
	return error;
}

static void 
node_tdisk_istate_sync(struct tdisk *tdisk)
{
	struct initiator_state *istate, *tmp;
	struct reservation *reservation, *sync_reservation;

	while ((istate = SLIST_FIRST(&tdisk->sync_istate_list)) != NULL) {
		SLIST_REMOVE_HEAD(&tdisk->sync_istate_list, i_list);
		tmp = device_get_initiator_state(tdisk, istate->i_prt, istate->t_prt, istate->r_prt, istate->init_int, 0, 0);
		if (!tmp) {
			SLIST_INSERT_HEAD(&tdisk->istate_list, istate, i_list);
		}
		else {
			debug_check(!SLIST_EMPTY(&tmp->sense_list));
			tmp->sense_list.slh_first = istate->sense_list.slh_first;
			istate->sense_list.slh_first = NULL;
			istate_free(istate);
			istate_put(tmp);
		}
	}
	reservation = &tdisk->reservation;
	sync_reservation = &tdisk->sync_reservation;
	memcpy(reservation, sync_reservation, offsetof(struct reservation, registration_list));  
	persistent_reservation_clear(&reservation->registration_list);
	reservation->registration_list.slh_first = sync_reservation->registration_list.slh_first;
	bzero(sync_reservation, sizeof(*sync_reservation));
	SLIST_INIT(&sync_reservation->registration_list);
}

static void 
node_ha_tdisk_istate_sync(void)
{
	struct tdisk *tdisk;
	int i;

	for (i = 0; i < TL_MAX_DEVICES; i++) {
		tdisk = tdisk_lookup[i];
		if (!tdisk)
			continue;
		tdisk_reservation_lock(tdisk);
		node_tdisk_istate_sync(tdisk);
		tdisk_reservation_unlock(tdisk);
	}
}

static int
node_ha_monitor(struct ha_config *old_config, int graceful)
{
	int retval;

	debug_info("graceful %d\n", graceful);
	debug_info("fence enabled %d\n", master_config.fence_enabled);
	if (!graceful && master_config.fence_enabled) {
		retval = ha_fence_node();
		if (unlikely(retval != 0))
			return -1;
	}

	retval = node_ha_disable_nocheck(old_config);
	if (retval != 0) {
		debug_error_notify("Disabling ha failed during takeover\n");
		return -1;
	}

	if (graceful || master_config.fence_enabled) {
		debug_info("fence enabled and was successful, disabling extra checks\n");
		return 0;
	}
	else {
		debug_error_notify("Not a graceful shutdown and fence command not specified. Cannot takeover\n");
		return -1;
	}
}

int
node_ha_takeover_pre(struct ha_config *ha_config, int graceful, int from_ha_thr)
{
	int retval;

	debug_info("graceful %d\n", graceful);
	if (node_sync_get_status() != NODE_SYNC_DONE) {
		debug_error_notify("Node sync incomplete, cannot takeover\n");
		node_sync_set_status(NODE_SYNC_NEED_RESYNC);
		return -1;
	}

	retval = ha_read_config(ha_config);
	if (retval != 0) {
		debug_error_notify("Failed to read HA config, cannot takeover\n");
		node_sync_set_status(NODE_SYNC_NEED_RESYNC);
		return -1;
	}

	if (!ha_config->ha_allowed) {
		debug_error_notify("HA disabled by peer node %u, cannot takeover\n", ha_config->ipaddr);
		node_sync_set_status(NODE_SYNC_NEED_RESYNC);
		return -1;
	}

	node_set_in_transition();
	if (!from_ha_thr)
		wait_for_ha_busy();
	retval = node_ha_monitor(ha_config, graceful);
	if (unlikely(retval != 0)) {
		debug_error_notify("Monitoring peer returned failure. Peer possibly still active, cannot take over\n");
		node_sync_set_status(NODE_SYNC_NEED_RESYNC);
		node_clear_in_transition();
		return -1;
	}

	debug_info("disable sync\n");
	if (!node_type_controller())
		node_sync_disable();
	else
		debug_info("not disabling sync as controller takeover\n");

	return 0;
}

int
node_ha_takeover(struct ha_config *ha_config, int graceful)
{
	struct index_sync_list index_sync_list;
	struct amap_sync_list amap_sync_list;

	SLIST_INIT(&index_sync_list);
	SLIST_INIT(&amap_sync_list);

	debug_info("logs takeover\n");
	node_ha_logs_takeover();

	debug_info("hash meta cleanup\n");
	node_ha_meta_hash_cleanup(&amap_sync_list, &index_sync_list);

	debug_info("hash cleanup\n");
	node_ha_hash_cleanup(&amap_sync_list, &index_sync_list);

	debug_info("tdisk amap syncs\n");
	node_ha_tdisk_amaps_sync();

	debug_info("reset log entries\n");
#if 0
	/* replay logs */
	node_ha_logs_replay();
#endif

	debug_info("reset write logs\n");
	/* setup logs */
	bdev_groups_reset_write_logs();

	debug_info("rcache reset\n");
	rcache_reset();

	debug_info("reset bdevs takeover\n");
	/* setup bdevs */
	node_ha_bdevs_takeover();

	debug_info("reset setup log list\n");
	bdev_groups_setup_log_list();

	debug_info("tdisk istate sync\n");
	node_ha_tdisk_istate_sync();

	debug_info("start transaction id %llx\n", (unsigned long long)ntransaction_id);
	node_set_role(NODE_ROLE_MASTER);

	debug_info("bdevs takeover post\n");
	node_ha_bdevs_takeover_post();

	debug_info("mark sync enabled\n");
	node_sync_mark_sync_enabled();

	if (!node_type_controller()) {
		node_ha_disable_nocheck(ha_config);
	}
	else {
		node_sync_takeover_post_send();
		node_ha_enable();
		debug_info("not disabling ha as controller takeover\n");
	}
	node_clear_in_transition();


#if 0
	debug_info("ha disable\n");
	node_ha_disable();
#endif

	debug_info("notify takeover post\n");
	node_sync_notify_takeover(graceful);
	return 0;
}
