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

#include "bdevgroup.h"
#include "../common/cluster_common.h" 
#include "cluster.h"
#include "node_sync.h"

static SLIST_HEAD(, bdevgroup) group_list = SLIST_HEAD_INITIALIZER(group_list);

struct bdevgroup *group_none;

int
bdev_groups_fix_rids(void)
{
	struct bdevgroup *group;
	int retval, error = 0;
	struct bdevint *bint, *ha_bint;

	ha_bint = bdev_group_get_ha_bint();
	SLIST_FOREACH(group, &group_list, g_list) {
		bint = group->master_bint;
		if (!bint)
			continue;
		retval = bint_fix_rid(bint);
		if (unlikely(retval != 0)) {
			error = -1;
			continue;
		}

		if (group->group_id || ha_bint)
			continue;

		if (atomic_test_bit(GROUP_FLAGS_MASTER, &bint->group_flags))
			continue;

		atomic_set_bit(GROUP_FLAGS_MASTER, &bint->group_flags);
		atomic_set_bit(GROUP_FLAGS_HA_DISK, &bint->group_flags);
		atomic_set_bit(GROUP_FLAGS_DEDUPEMETA, &bint->group_flags);
		atomic_set_bit(GROUP_FLAGS_LOGDATA, &bint->group_flags);
		atomic_set_bit(BINT_IO_PENDING, &bint->flags);
		retval = bint_sync(bint, 1);
		if (unlikely(retval != 0)) {
			error = -1;
			continue;
		}
		bdev_group_set_ha_bint(bint);
	}
	return error;
}

int
bdev_groups_replay_write_logs(void)
{
	struct bdevgroup *group;
	int error = 0;

	SLIST_FOREACH(group, &group_list, g_list) {
		bdev_replay_write_logs(group);
		if (atomic_read(&group->log_error) == 0) {
			bdev_setup_log_list(group);
		}
		else {
			debug_error_notify("Replay of write logs failed for group %s\n", group->name);
			error = -1;
		}
	}
	return error;
}

int
bdev_groups_reset_write_logs(void)
{
	struct bdevgroup *group;
	int error = 0, retval;

	SLIST_FOREACH(group, &group_list, g_list) {
		retval = bdev_reset_write_logs(group);
		if (unlikely(retval != 0))
			error = -1;
	}
	return error;
}

void
bdev_groups_ddtable_wait_sync_busy(void)
{
	struct bdevgroup *group;

	SLIST_FOREACH(group, &group_list, g_list) {
		if (!group->dedupemeta)
			continue;
		if (!atomic_read(&group->ddtable.inited))
			continue;

		ddtable_wait_sync_busy(&group->ddtable);
	}
}

int
bdev_groups_ddtable_load_status(void)
{
	struct bdevgroup *group;
	int status = 0, done;

	SLIST_FOREACH(group, &group_list, g_list) {
		if (!group->dedupemeta)
			continue;
		if (!atomic_read(&group->ddtable.inited))
			continue;

		done = ddtable_load_status(&group->ddtable);
		if (!done) {
			status = -1;
			break;
		}
	}
	return status;
}

void
bdev_groups_ddtable_exit(void)
{
	struct bdevgroup *group;

	SLIST_FOREACH(group, &group_list, g_list) {
		if (!group->dedupemeta)
			continue;
		if (!atomic_read(&group->ddtable.inited))
			continue;

		ddtable_exit(&group->ddtable);
	}
}
void
bdev_groups_setup_log_list(void)
{
	struct bdevgroup *group;

	SLIST_FOREACH(group, &group_list, g_list) {
		bdev_setup_log_list(group);
	}
}

struct bdevgroup *
bdev_group_locate(uint32_t group_id, struct bdevgroup **ret_prev)
{
	struct bdevgroup *prev = NULL;
	struct bdevgroup *group;

	SLIST_FOREACH(group, &group_list, g_list) {
		if (group->group_id == group_id) {
			if (ret_prev)
				*ret_prev = prev;
			return group;
		}
		prev = group;
	}
	return NULL;
}

int
bdev_group_add(struct group_conf *group_conf)
{
	struct bdevgroup *group;

	group = bdev_group_locate(group_conf->group_id, NULL);
	if (group) {
		debug_warn("Pool with id %u already exists\n", group_conf->group_id);
		return -1;
	}

	group = zalloc(sizeof(*group), M_QUADSTOR, Q_WAITOK);
	if (unlikely(!group)) {
		debug_warn("Memory allocation failure\n");
		return -1;
	}

	group->group_id = group_conf->group_id;
	group->dedupemeta = group_conf->dedupemeta;
	group->logdata = group_conf->logdata;
	strcpy(group->name, group_conf->name);

	SLIST_INIT(&group->alloc_list);
	SLIST_INIT(&group->bdev_log_list);
	TAILQ_INIT(&group->glog_list);

	group->wait_on_log = wait_chan_alloc("wait on log");
	group->log_lock = sx_alloc("group log lock");
	group->alloc_lock = sx_alloc("group alloc lock");
	group->log_transaction_id = 1;

	if (!group->group_id)
		group_none = group;

	SLIST_INSERT_HEAD(&group_list, group, g_list);
	return 0;
}

static void
bdev_group_free(struct bdevgroup *group)
{
	wait_chan_free(group->wait_on_log);
	sx_free(group->log_lock);
	sx_free(group->alloc_lock);
	if (group == group_none)
		group_none = NULL;
	free(group, M_QUADSTOR);
}

int
bdev_group_rename(struct group_conf *group_conf)
{
	struct bdevgroup *group;
	struct bdevint *bint;
	char prev_name[GROUP_MAX_NAME_LEN];
	int retval;

	group = bdev_group_locate(group_conf->group_id, NULL);
	if (!group) {
		debug_warn("Cannot locate pool with id %u\n", group_conf->group_id);
		return -1;
	}

	if (atomic_read(&group->log_error)) {
		debug_warn("Pool %s:%u in error state\n", group->name, group->group_id);
		return -1;
	}

	bint = group->master_bint;
	strcpy(prev_name, group->name);
	strcpy(group->name, group_conf->name);

	if (!bint)
		return 0;

	atomic_set_bit(BINT_IO_PENDING, &bint->flags);
	retval = bint_sync(bint, 1);
	if (unlikely(retval != 0)) {
		strcpy(group->name, prev_name);
	}
	return retval;
}

int
bdev_group_remove(struct group_conf *group_conf)
{
	struct bdevgroup *group, *prev;

	group = bdev_group_locate(group_conf->group_id, &prev);
	if (!group) {
		debug_warn("Cannot locate pool with id %u\n", group_conf->group_id);
		return -1;
	}

	if (atomic_read(&group->bdevs) || atomic_read(&group->tdisks)) {
		debug_warn("Pool %s:%u busy bdevs %d vdisks %d\n", group->name, group->group_id, atomic_read(&group->bdevs), atomic_read(&group->tdisks));
		return -1;
	}

	if (prev)
		SLIST_REMOVE_AFTER(prev, g_list); 
	else
		SLIST_REMOVE_HEAD(&group_list, g_list);
	bdev_group_free(group);
	return 0;
}

void
bdev_groups_free(void)
{
	struct bdevgroup *group;

	while ((group = SLIST_FIRST(&group_list)) != NULL) {
		SLIST_REMOVE_HEAD(&group_list, g_list);
		bdev_group_free(group);
	}
}

struct bdevint *ha_bint;
extern wait_chan_t *ha_wait;

void
bdev_group_clear_ha_bint(struct bdevint *bint)
{
	chan_lock(ha_wait);
	if (bint == ha_bint)
		ha_bint = NULL;
	chan_unlock(ha_wait);
}

void
bdev_group_set_ha_bint(struct bdevint *bint)
{
	chan_lock(ha_wait);
	debug_check(ha_bint && ha_bint->bid != bint->bid);
	ha_bint = bint;
	chan_unlock(ha_wait);
}

struct bdevint *
bdev_group_get_ha_bint(void)
{
	struct bdevint *ret;
	chan_lock(ha_wait);
	ret = ha_bint;
	chan_unlock(ha_wait);
	return ret;
}

struct bdevgroup *
bdev_group_get_log_group(struct bdevgroup *group)
{
	if (group->logdata)
		return group;
	else
		return group_none;
}

struct ddtable *
bdev_group_ddtable(struct bdevgroup *group)
{
	if (group->dedupemeta)
		return &group->ddtable;
	else {
		debug_check(!group_none);
		return &group_none->ddtable;
	}
}

