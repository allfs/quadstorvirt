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

#ifndef QS_NODE_HA_H_
#define QS_NODE_HA_H_
struct ha_config {
	uint64_t timestamp;
	uint32_t ipaddr;
	uint32_t ha_allowed;
	uint32_t ha_allowed_init;
	uint32_t graceful;
	char magic[16];
};

int node_controller_ha_init(void);
int node_master_ha_init(void);
void node_ha_disable(void);
void node_ha_enable(void);
void node_ha_exit(void);
int node_in_standby(void);
int node_in_transition(void);
int node_ha_takeover_pre(struct ha_config *ha_config, int graceful, int from_ha_thr);
int node_ha_takeover(struct ha_config *ha_config, int graceful);
void ha_init_config(void);
void ha_set_ping_recv(void);
void node_set_in_transition(void);
void node_clear_in_transition(void);
void wait_for_ha_busy(void);

#define HA_MAGIC "dGEmvRG@1quad"

#define HA_PING_TIMEOUT		8000
#define HA_CHECK_TIMEOUT	5000
#define HA_CHECK_TIMEOUT_BUFFER	8000
#define HA_SYNC_TIMEOUT		3000
#define HA_NOTIFY_TIMEOUT	(2 * 60 * 1000)

#endif
