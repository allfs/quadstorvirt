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

#ifndef QS_FASTLOG_H_
#define QS_FASTLOG_H_

#include "coredefs.h"
#include "amap.h"

enum {
	LOG_PAGE_FULL = -1,
	LOG_PAGE_ERROR = -2,
};

#define log_page_trylock(p)	sx_try_xlock((p)->log_lock)

#define log_page_lock(p)				\
do {							\
	debug_check(sx_xlocked_check((p)->log_lock));	\
	sx_xlock((p)->log_lock);			\
} while (0)

#define log_page_unlock(p)				\
do {							\
	debug_check(!sx_xlocked((p)->log_lock));	\
	sx_xunlock((p)->log_lock);			\
} while (0)

#define WAIT_ON_LOG		1

struct raw_log_page {
	uint64_t transaction_start;
};

struct raw_log_page_v3 {
	uint64_t transaction_start;
	uint16_t pad[3];
	uint16_t csum;
};

struct log_page {
	uint64_t write_id;
	pagestruct_t *metadata;
	struct log_group *group;
	TAILQ_ENTRY(log_page) g_list;
	struct iowaiter_list io_waiters;
	wait_chan_t *log_page_wait;
	sx_t *log_lock;
	int16_t flags;
	uint16_t log_group_idx;
	atomic_t pending_writes;
	atomic_t refs;
	atomic_t pending_transactions;
};

struct log_entry {
	uint64_t transaction_id;
	uint64_t new_block;
	uint64_t lba;
	uint64_t index_write_id;
	uint64_t amap_write_id;
	struct amap *amap;
	struct amap_table *amap_table;
	STAILQ_ENTRY(log_entry) l_list;
	uint16_t target_id;
};
STAILQ_HEAD(log_entry_list, log_entry);

struct v2_log_entry {
	uint64_t bit1;
	uint32_t bit2;
	uint32_t index1;
	uint16_t index2;
	uint32_t amap1;
	uint16_t amap2;
} __attribute__ ((__packed__));

struct write_log_entry {
	uint64_t bit1;
	uint32_t bit2;
	uint16_t bit3;
} __attribute__ ((__packed__));

static inline void
write_log_entry_clear_block(struct write_log_entry *entry)
{
	bzero(entry, sizeof(*entry));
}

#define TARGET_ID_BITS	12
#define LBA_BITS	37 /* 512 TB max addressable */

static inline struct write_log_entry *
log_page_get_entry(struct log_page *log_page, int idx)
{
	struct write_log_entry *entries = (struct write_log_entry *)vm_pg_address(log_page->metadata);
	return &entries[idx];
}

static inline struct v2_log_entry *
log_page_get_v2_entry(struct log_page *log_page, int idx)
{
	struct v2_log_entry *entries = (struct v2_log_entry *)vm_pg_address(log_page->metadata);
	return &entries[idx];
}

static inline void
v2_log_entry_set_block(struct v2_log_entry *entry, uint64_t new_block, uint16_t target_id, uint64_t lba, uint64_t index_write_id, uint64_t amap_write_id)
{
	entry->bit1 = (new_block | ((lba & 0x3FFF) << 50)); /* 50 bits, low 14bits of lba */
	entry->bit2 = ((lba >> 14) | ((((uint32_t)target_id) & 0xFFF) << 20));
 /* 30bits lba - 14 */
	entry->index1 = (uint32_t)(index_write_id & 0xFFFFFFFFULL);
	entry->index2 = (uint16_t)((index_write_id >> 32) & 0xFFFF);
	entry->amap1 = (uint32_t)(amap_write_id & 0xFFFFFFFFULL);
	entry->amap2 = (uint16_t)((amap_write_id >> 32) & 0xFFFF);
}

#define ENTRY_TARGET_ID(ent)		(((ent->bit2 >> 23) & 0x1FF) | ((entry->bit3 & 0x7) << 9))
#define ENTRY_NEW_BLOCK(ent)		(ent->bit1 & 0x3FFFFFFFFFFFF)
#define ENTRY_INDEX_REFS(ent)		((ent->bit3 >> 3) & 0x1FFF)
#define ENTRY_LBA(ent)			((ent->bit2 & 0x7FFFFF) << 14 | (ent->bit1 >> 50))

#define V2_ENTRY_TARGET_ID(ent)		((ent->bit2 >> 20) & 0xFFF)
#define V2_ENTRY_NEW_BLOCK(ent)		(ent->bit1 & 0x3FFFFFFFFFFFF)
#define V2_ENTRY_LBA(ent)		((ent->bit2 & 0xFFFFF) << 14 | (ent->bit1 >> 50))
#define V2_ENTRY_AMAP_WRITE_ID(ent)	(((uint64_t)ent->amap1) | (((uint64_t)ent->amap2) << 32))
#define V2_ENTRY_INDEX_WRITE_ID(ent)	(((uint64_t)ent->index1) | (((uint64_t)ent->index2) << 32))

#define LOG_PAGE_SHIFT		12
#define LOG_PAGE_SIZE		(1U << LOG_PAGE_SHIFT)
#define LOG_PAGES_PER_BINT	(LOG_PAGES_RESERVED >> LOG_PAGE_SHIFT)
#define MAX_LOG_ENTRIES		((LOG_PAGE_SIZE - sizeof(struct raw_log_page)) / sizeof(struct write_log_entry))
#define RAW_LOG_OFFSET		(MAX_LOG_ENTRIES * sizeof(struct write_log_entry))

#define V2_LOG_ENTRIES		((LOG_PAGE_SIZE - sizeof(struct raw_log_page)) / sizeof(struct v2_log_entry))
#define V2_LOG_OFFSET		(V2_LOG_ENTRIES * sizeof(struct v2_log_entry))
#define MAX_LOG_PAGES		(LOG_PAGES_RESERVED >> LOG_PAGE_SHIFT)

struct log_info {
	struct log_page *log_page;
	SLIST_ENTRY(log_info) l_list;
	struct iowaiter iowaiter;
};
SLIST_HEAD(log_info_list, log_info);

struct write_list;
struct log_page * get_free_log_page(struct bdevgroup *group, struct log_info_list *log_list);
void fastlog_insert_transaction(struct pgdata *pgdata, struct tdisk *tdisk, struct log_page *log_page, int insert_idx);
struct ddwork;
void fastlog_add_transaction(struct index_info *index_info, struct tdisk *tdisk, uint64_t lba, struct log_page *log_page, int insert_idx);
void fastlog_clear_transactions(struct tdisk *tdisk, struct pgdata **pglist, int pglist_cnt, struct index_info_list *index_info_list, int log_reserved, int error);

void bdev_setup_log_list(struct bdevgroup *group);

struct bdevint;
int bint_create_logs(struct bdevint *bint, int rw, int max, uint32_t offset);
void log_page_free(struct log_page *log_page);

#define log_page_put(lgp)				\
do {							\
	if (atomic_dec_and_test(&(lgp)->refs))		\
		log_page_free(lgp);			\
} while (0)

#define log_page_get(lgp)	atomic_inc(&(lgp)->refs)

struct bdevgroup;
void bdev_replay_write_logs(struct bdevgroup *);
int bdev_reset_write_logs(struct bdevgroup *);

enum {
	LOG_PAGE_WRITE,
	LOG_PAGE_DELETE,
};

extern uint32_t log_barrier_ticks;

static inline void
log_page_write_barrier(struct log_page *log_page)
{
#ifdef ENABLE_STATS
	uint32_t start_ticks;
#endif
	pagestruct_t *page, *tmp;

	if (!atomic_test_bit_short(LOG_META_DATA_DIRTY, &log_page->flags) || atomic_test_bit_short(META_DATA_CLONED, &log_page->flags))
		return;

	GLOB_TSTART(start_ticks);
	page = vm_pg_alloc(0);
	if (unlikely(!page)) {
		wait_on_chan(log_page->log_page_wait, !atomic_test_bit_short(LOG_META_DATA_DIRTY, &log_page->flags));
	}
	else {
		tmp = log_page->metadata;
		memcpy(vm_pg_address(page), vm_pg_address(tmp), LOG_PAGE_SIZE);
		log_page->metadata = page;
		atomic_set_bit_short(LOG_META_DATA_CLONED, &log_page->flags);
		vm_pg_free(tmp);
	}
	GLOB_TEND(log_barrier_ticks, start_ticks);
}

void fastlog_reserve(struct tdisk *tdisk, struct write_list *wlist, int count);
void bdev_log_add(struct bdevint *bint);
int bdev_log_remove(struct bdevint *bint, int force);
void fastlog_log_list_free(struct log_info_list *log_list);
struct log_group * bint_find_log_group(struct bdevint *bint, int group_id);
struct amap_table * amap_table_recreate(struct tdisk *tdisk, uint64_t lba, uint64_t block);
struct amap * amap_recreate(struct tdisk *tdisk, struct amap_table *amap_table, uint64_t lba, uint64_t block);

#endif
