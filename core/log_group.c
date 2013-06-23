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

#include "log_group.h"
#include "fastlog.h"
#include "tcache.h"
#include "cluster.h"
#include "node_sync.h"

#ifdef FREEBSD 
static void log_group_end_bio(struct bio *bio)
#else
static void log_group_end_bio(struct bio *bio, int err)
#endif
{
	struct tcache *tcache;
#ifdef FREEBSD
	int err = bio->bio_error;
	struct biot *biot = (struct biot *)bio_get_caller(bio);
#endif
	struct log_page *log_page;
	int i;

#ifdef FREEBSD
	tcache = biot->cache;
#else
	tcache = (struct tcache *)bio_get_caller(bio);
#endif

	if (unlikely(err))
	{
		for (i = tcache->start_idx; i < tcache->end_idx; i++) {
			if (!atomic_test_bit(i, &tcache->write_flags))
				continue;

			log_page = tcache->priv.logs[i];
			atomic_set_bit_short(LOG_META_DATA_ERROR, &log_page->flags);
		}
	}

	if (!(atomic_dec_and_test(&tcache->bio_remain)))
		return;

	for (i = tcache->start_idx; i < tcache->end_idx; i++) {
		if (!atomic_test_bit(i, &tcache->write_flags))
			continue;

		log_page = tcache->priv.logs[i];
		atomic_clear_bit_short(LOG_META_DATA_DIRTY, &log_page->flags);
		chan_wakeup(log_page->log_page_wait);
	}
	mtx_lock(tcache->tcache_lock);
	complete_io_waiters(&tcache->io_waiters);
	mtx_unlock(tcache->tcache_lock);

	tcache_free_pages(tcache);
	wait_complete_all(tcache->completion);
	tcache_put(tcache);
}

uint32_t log_group_writes;
uint32_t log_group_bio;
extern uint32_t log_writes;

int
log_group_io(struct log_group *group, struct tcache **ret_tcache)
{
	struct bdevint *bint = group->bint;
	int i;
	int retval;
	struct log_page *log_page;
	struct tcache *tcache;
	struct raw_log_page_v3 *raw_page_v3;
	int start_idx = 0;
	int rw;
	uint16_t csum;

	if (bint->write_cache == WRITE_CACHE_DEFAULT)
		rw = QS_IO_WRITE;
	else if (bint->write_cache == WRITE_CACHE_FUA)
		rw = QS_IO_SYNC;
	else
		rw = QS_IO_SYNC_FLUSH;

	tcache = tcache_alloc(LOG_GROUP_MAX_PAGES);
	tcache->tcache_lock = mtx_alloc("tcache lock");

	atomic_set_bit_short(TCACHE_LOG_WRITE, &tcache->flags);
	tcache->write_flags = group->write_flags;
	tcache->priv.logs = group->logs;
	group->write_flags = 0;

	iowaiters_move(&tcache->io_waiters, &group->io_waiters);
	for (i = 0; i < LOG_GROUP_MAX_PAGES; i++) {
		if (!atomic_test_bit(i, &tcache->write_flags))
			continue;

		if (!start_idx) {
			tcache->start_idx = i;
			start_idx = 1;
		}
		tcache->end_idx = (i + 1);
		log_page = tcache->priv.logs[i];

		log_page_lock(log_page);
		atomic_set_bit_short(LOG_META_DATA_DIRTY, &log_page->flags);
		atomic_clear_bit_short(LOG_META_DATA_CLONED, &log_page->flags);
		node_log_sync_send(log_page, tcache);
		vm_pg_ref(log_page->metadata);
		raw_page_v3 = (struct raw_log_page_v3 *)(((uint8_t *)vm_pg_address(log_page->metadata)) + V2_LOG_OFFSET);
		csum = calc_csum16(vm_pg_address(log_page->metadata), BINT_BMAP_SIZE - sizeof(*raw_page_v3));
		raw_page_v3->csum = csum;
		retval = __tcache_add_page(tcache, log_page->metadata, log_page_b_start(log_page), group->bint, LOG_PAGE_SIZE, rw, log_group_end_bio);
		log_page_unlock(log_page);
		if (unlikely(retval != 0))
			goto err;
		GLOB_INC(log_writes, 1);
	}

	if (!atomic_read(&tcache->bio_remain)) {
		complete_io_waiters(&tcache->io_waiters);
		tcache_put(tcache);
		return 0;
	}

	GLOB_INC(log_group_bio, atomic_read(&tcache->bio_remain));
	__tcache_entry_rw(tcache, rw, log_group_end_bio);
	GLOB_INC(log_group_writes, 1);
	if (!ret_tcache)
		tcache_put(tcache);
	else
		*ret_tcache = tcache;
	return 0;
err:
	tcache_free_pages(tcache);
	tcache_put(tcache);
	return -1;
}

static void
log_group_free(struct log_group *log_group)
{
	sx_free(log_group->group_lock);
	uma_zfree(log_group_cache, log_group);
}

#define log_group_put(lgg)				\
do {							\
	if (atomic_dec_and_test(&(lgg)->refs))		\
		log_group_free(lgg);			\
} while (0)

#define log_group_get(lgg)	atomic_inc(&(lgg)->refs)

static void
bint_log_pages_free(struct log_group *group)
{
	int i;
	struct log_page *log_page;

	for (i = 0; i < LOG_GROUP_MAX_PAGES; i++) {
		log_page = group->logs[i];
		if (!log_page)
			continue;

		wait_on_chan(log_page->log_page_wait, !atomic_test_bit_short(LOG_META_DATA_DIRTY, &log_page->flags));
		log_page_put(log_page);
	}
}

void
bint_log_groups_free(struct bdevint *bint)
{
	struct log_group *log_group, *tvar;

	LIST_FOREACH_SAFE(log_group, &bint->log_group_list, g_list, tvar) {
		LIST_REMOVE(log_group, g_list);
		bint_log_pages_free(log_group);
		log_group_put(log_group);
	}
}

struct log_group *
log_group_alloc(struct bdevint *bint, uint32_t group_id, uint64_t b_start)
{
	struct log_group *log_group;

	log_group = __uma_zalloc(log_group_cache, Q_NOWAIT | Q_ZERO, sizeof(*log_group));
	if (unlikely(!log_group)) {
		debug_warn("Slab allocation failure\n");
		return NULL;
	}

	log_group->b_start = b_start;
	log_group->group_id = group_id;
	log_group->bint = bint;
	atomic_set(&log_group->refs, 1);
	log_group->group_lock = sx_alloc("log group lock");
	SLIST_INIT(&log_group->io_waiters);
	return log_group;
}

void
log_group_remove_page(struct log_group *log_group, struct log_page *log_page)
{
	log_group->logs[log_page->log_group_idx] = NULL;
	log_group_put(log_group);
}

void
log_group_add_page(struct log_group *log_group, struct log_page *log_page)
{
	log_group->logs[log_page->log_group_idx] = log_page;
	log_group_get(log_group);
	return;
}

