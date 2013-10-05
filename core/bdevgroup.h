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

#ifndef QS_BDEVGROUP_H_
#define QS_BDEVGROUP_H_
#include "bdevmgr.h"
#include "tdisk.h"

struct bdevgroup {
	char name[TDISK_MAX_NAME_LEN];
	SLIST_HEAD(, bdevint) alloc_list;
	TAILQ_HEAD(, log_page) glog_list;
	struct bdev_log_list bdev_log_list;
	atomic_t bdevs;
	atomic_t tdisks;
	atomic_t comp_bdevs;
	atomic_t log_error;
	int dedupemeta;
	int logdata;
	struct bdevint *master_bint;
	sx_t *log_lock;
	sx_t *alloc_lock;
	wait_chan_t *wait_on_log;
	SLIST_ENTRY(bdevgroup) g_list;
	uint32_t group_id;
	atomic_t free_log_entries;
	uint32_t reserved_log_entries;
	int free_idx;
	struct log_page *free_page;
	struct bdevint *eligible;
	uint64_t log_transaction_id;
	atomic64_t free;
	struct ddtable ddtable;
};

struct bdevgroup * bdev_group_locate(uint32_t group_id, struct bdevgroup **ret_prev);
int bdev_group_add(struct group_conf *group_conf);
int bdev_group_remove(struct group_conf *group_conf);
int bdev_group_rename(struct group_conf *group_conf);
void bdev_groups_free(void);

static inline struct bdevint *
bint_get_group_master(struct bdevint *bint)
{
	return (bint->group->master_bint);
}

static inline void
bint_set_group_master(struct bdevint *bint)
{
	struct bdevgroup *group = bint->group;

	debug_check(group->master_bint && group->master_bint != bint);
	group->master_bint = bint;

	if (!group->group_id) {
		group->dedupemeta = 1;
		group->logdata = 1;
		return;
	}

	if (atomic_test_bit(GROUP_FLAGS_DEDUPEMETA, &bint->group_flags))
		group->dedupemeta = 1;

	if (atomic_test_bit(GROUP_FLAGS_LOGDATA, &bint->group_flags))
		group->logdata = 1;
}

static inline void
bint_clear_group_master(struct bdevint *bint)
{
	if (bint->group->master_bint == bint)
		bint->group->master_bint = NULL;
}

static inline int
bint_is_ha_disk(struct bdevint *bint)
{
	return (atomic_test_bit(GROUP_FLAGS_HA_DISK, &bint->group_flags) != 0);
}

static inline int
bint_is_group_master(struct bdevint *bint)
{
	struct bdevgroup *group = bint->group;

	if (!group->group_id && bint->ddmaster)
		return 1;

	return atomic_test_bit(GROUP_FLAGS_MASTER, &bint->group_flags);
}

int bdev_groups_fix_rids(void);
int bdev_groups_replay_write_logs(void);
int bdev_groups_reset_write_logs(void);
void bdev_groups_setup_log_list(void);
void bdev_groups_ddtable_wait_sync_busy(void);

struct bdevint * bdev_group_get_ha_bint(void);
void bdev_group_set_ha_bint(struct bdevint *bint);
void bdev_group_clear_ha_bint(struct bdevint *bint);
struct ddtable * bdev_group_ddtable(struct bdevgroup *);
void bdev_groups_ddtable_exit(void);
static inline uint64_t
 bdev_group_get_avail(struct bdevgroup *group)
{
	return atomic64_read(&group->free);
}
#endif
