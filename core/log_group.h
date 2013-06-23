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

#ifndef QS_LOG_GROUP_H_
#define QS_LOG_GROUP_H_

#include "coredefs.h"
#include "bdevmgr.h"
#include "fastlog.h"
#include "tcache.h"

#define MAX_LOG_GROUPS	(LOG_PAGES_RESERVED/ (LOG_GROUP_MAX_PAGES * LOG_PAGE_SIZE))

struct log_group {
	uint64_t b_start;
	struct bdevint *bint;
	struct log_page *logs[LOG_GROUP_MAX_PAGES];
	sx_t *group_lock;
	LIST_ENTRY(log_group) g_list;
	struct iowaiter_list io_waiters;
	int write_flags;
	atomic_t pending_writes;
	atomic_t refs;
	uint32_t group_id;
};

#define log_group_lock(g)	sx_xlock((g)->group_lock)
#define log_group_unlock(g)				\
do {							\
	debug_check(!sx_xlocked((g)->group_lock));	\
	sx_xunlock((g)->group_lock);			\
} while (0)

int log_group_io(struct log_group *group, struct tcache **ret_tcache);
struct log_group * log_group_alloc(struct bdevint *bint, uint32_t group_id, uint64_t b_start);
void log_group_add_page(struct log_group *log_group, struct log_page *log_page);
void log_group_remove_page(struct log_group *log_group, struct log_page *log_page);
void bint_log_groups_free(struct bdevint *bint);

static inline void
log_group_add_write_page(struct log_group *log_group, struct log_page *log_page)
{
	atomic_set_bit(log_page->log_group_idx, &log_group->write_flags);
}

static inline void
log_group_end_writes(struct log_group *group)
{
	if (atomic_dec_and_test(&group->pending_writes)) {
		log_group_io(group, NULL);
	}
}

static inline void
log_group_start_writes(struct log_page *log)
{
	struct log_group *group = log->group;

	atomic_inc(&group->pending_writes);
}

static inline void
log_end_writes(struct log_page *log, struct iowaiter *iowaiter)
{
	struct iowaiter_list tmp_list;
	struct log_group *group = log->group;

	if (iowaiter) {
		init_iowaiter(iowaiter);
	}

	SLIST_INIT(&tmp_list);
	wait_on_chan_check(log->log_page_wait, !atomic_test_bit_short(LOG_META_DATA_DIRTY, &log->flags));
	log_group_lock(group);
	log_page_lock(log);
	if (iowaiter)
		SLIST_INSERT_HEAD(&log->io_waiters, iowaiter, w_list);
	if (atomic_dec_and_test(&log->pending_writes)) {
		log_group_add_write_page(group, log);
		iowaiters_merge(&tmp_list, &log->io_waiters);
	}
	log_page_unlock(log);

	iowaiters_merge(&group->io_waiters, &tmp_list);
	log_group_end_writes(group);
	log_group_unlock(group);
}

#define log_end_wait(Lg, iwaitr)		iowaiter_end_wait((iwaitr))
#define log_wait_for_done_io(Lg, iwaitr)	iowaiter_wait_for_done_io((iwaitr))

static inline void
log_start_writes(struct log_page *log)
{
	struct log_group *group = log->group;

	log_group_lock(group);
	log_group_start_writes(log);
	log_page_lock(log);
	atomic_inc(&log->pending_writes);
	log_page_unlock(log);
	log_group_unlock(group);
}

static inline void
log_list_start_writes(struct log_info_list *log_list)
{
	struct log_info *log_info;

	SLIST_FOREACH(log_info, log_list, l_list) {
		log_start_writes(log_info->log_page);
	}
}

void log_list_free_error(struct log_info_list *log_list);

static inline void
log_list_end_writes(struct log_info_list *log_list)
{
	struct log_info *log_info;

	SLIST_FOREACH(log_info, log_list, l_list) {
		log_end_writes(log_info->log_page, &log_info->iowaiter);
	}

#if 0
	SLIST_FOREACH(log_info, log_list, l_list) {
		log_wait_for_done_io(log_info->log_page, &log_info->iowaiter);
	}
#endif
}

static inline void
log_list_end_wait(struct log_info_list *log_list)
{
	struct log_info *log_info;

	SLIST_FOREACH(log_info, log_list, l_list) {
		log_end_wait(log_info->log_page, &log_info->iowaiter);
	}
}

static inline uint64_t
log_page_b_start(struct log_page *log_page)
{
	uint64_t b_start = log_page->group->b_start;

	b_start += ((log_page->log_group_idx << LOG_PAGE_SHIFT) >> log_page->group->bint->sector_shift);
	return b_start;
}

#endif
