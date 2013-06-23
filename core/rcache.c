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

#include "rcache.h"
#include "bdevmgr.h"
#include "ddblock.h"
#include "vdevdefs.h"

extern uint32_t rcache_insert_ticks;
extern uint32_t rcache_lookup_ticks;
extern uint32_t rcache_remove_ticks;
extern uint32_t rcache_lookup_hits;
extern uint32_t rcache_lookups;
extern uint32_t rcache_inserts;
extern uint32_t rcache_removes;

#define RCACHE_FREE_EXIT	1
#define RCACHE_GROUP_SHIFT	9
#define RCACHE_GROUP_SIZE	(1U << RCACHE_GROUP_SHIFT)
#define RCACHE_GROUP_MASK	(RCACHE_GROUP_SIZE - 1)

struct rcache  **rcache_list;
uint32_t rcache_bits;

uint32_t rcache_count;
uint32_t rcache_cached_max;
uint32_t rcache_cached_min;
struct rcache_entry_list glist = TAILQ_HEAD_INITIALIZER(glist);
mtx_t *glist_lock; 
wait_chan_t *rcache_free_wait;
int rcache_flags;
kproc_t *rcache_free_task;

static void
__rcache_entry_free(struct rcache_entry *entry)
{
	vm_pg_free(entry->page);
	ALLOC_COUNTER_INC(rcache_pages_freed);
	uma_zfree(rcache_entry_cache, entry);
}

static void
rcache_check(void)
{
	struct rcache_entry *entry;
	struct rcache *rcache;
	struct rcache_entry_list *lhead;
	uint32_t hashval;

	while (rcache_count > rcache_cached_max) {
		mtx_lock(glist_lock);
		entry = TAILQ_FIRST(&glist);
		TAILQ_REMOVE_INIT(&glist, entry, g_list);
		rcache_count--;
		mtx_unlock(glist_lock);

		hashval = entry->hashval;
		rcache = rcache_list[hashval >> RCACHE_GROUP_SHIFT];
		lhead = &rcache->entry_list[hashval & RCACHE_GROUP_MASK]; 
		mtx_lock(rcache->rcache_lock);
		TAILQ_REMOVE(lhead, entry, r_list);
		__rcache_entry_free(entry);
		mtx_unlock(rcache->rcache_lock);
		GLOB_INC(rcache_removes, 1);
	}
}

static void
rcache_count_check(void)
{
	if (rcache_count > rcache_cached_max) {
		chan_wakeup_one_nointr(rcache_free_wait);
	}
}

#ifdef FREEBSD 
static void rcache_free_thread(void *data)
#else
static int rcache_free_thread(void *data)
#endif
{

	for (;;) {
		wait_on_chan_interruptible(rcache_free_wait, (rcache_count > rcache_cached_max) || kernel_thread_check(&rcache_flags, RCACHE_FREE_EXIT));

		if (kernel_thread_check(&rcache_flags, RCACHE_FREE_EXIT))
			break;
		rcache_check();
	}
#ifdef FREEBSD 
	kproc_exit(0);
#else
	return 0;
#endif
}

static void
rcache_entry_free(struct rcache_entry_list *lhead, struct rcache_entry *entry)
{
	mtx_lock(glist_lock);
	if (!TAILQ_ENTRY_EMPTY(entry, g_list)) {
		rcache_count--;
		TAILQ_REMOVE(&glist, entry, g_list);
		TAILQ_REMOVE(lhead, entry, r_list);
		__rcache_entry_free(entry);
	}
	mtx_unlock(glist_lock);
}

static void
rcache_entry_remove(struct rcache *rcache, uint64_t block, uint32_t hashval)
{
	struct rcache_entry_list *lhead;
	struct rcache_entry *entry;

	lhead = &rcache->entry_list[hashval & RCACHE_GROUP_MASK];

	TAILQ_FOREACH(entry, lhead, r_list) {
		if (entry->block == block) {
			rcache_entry_free(lhead, entry);
			break;
		}
	}
}

void
rcache_remove(uint64_t amap_block)
{
	struct rcache *rcache;
	struct bdevint *bint = bdev_find(BLOCK_BID(amap_block));
	uint32_t hashval;
#ifdef ENABLE_STATS
	uint32_t start_ticks;
#endif

	if (!bint)
		return;

	hashval = hashblock(amap_block, rcache_bits, bint->sector_shift);
	rcache = rcache_list[hashval >> RCACHE_GROUP_SHIFT];	
	GLOB_TSTART(start_ticks);
	GLOB_INC(rcache_removes, 1);
	mtx_lock(rcache->rcache_lock);
	rcache_entry_remove(rcache, amap_block, hashval);
	mtx_unlock(rcache->rcache_lock);
	GLOB_TEND(rcache_remove_ticks, start_ticks);
}

void
rcache_add_to_list(struct rcache_entry_list *lhead, struct pgdata *pgdata)
{
	struct rcache_entry *new;

	if (atomic_test_bit(SKIP_RCACHE_INSERT, &pgdata->flags))
		return;

	new = __uma_zalloc(rcache_entry_cache, Q_NOWAIT, sizeof(*new));
	if (unlikely(!new))
		return;
	
	new->block = pgdata->amap_block;
	vm_pg_ref(pgdata->page);
	ALLOC_COUNTER_INC(rcache_pages_refed);
	new->page = pgdata->page;
	TAILQ_INSERT_HEAD(lhead, new, r_list);
}

static void
rcache_entry_insert(struct rcache_entry *new)
{
	struct rcache *rcache;
	uint64_t block = new->block;
	struct bdevint *bint =  bdev_find(BLOCK_BID(block));
	struct rcache_entry_list *lhead;
	struct rcache_entry *entry;
	uint32_t hashval;

	if (unlikely(!bint)) {
		__rcache_entry_free(new);
		return;
	}

	hashval = hashblock(block, rcache_bits, bint->sector_shift);
	rcache = rcache_list[hashval >> RCACHE_GROUP_SHIFT];
	mtx_lock(rcache->rcache_lock);
	GLOB_INC(rcache_inserts, 1);
	lhead = &rcache->entry_list[hashval & RCACHE_GROUP_MASK]; 
	TAILQ_FOREACH(entry, lhead, r_list) {
		if (entry->block == block) {
			rcache_entry_free(lhead, entry);
			break;
		}
	}

	new->hashval = hashval;
	TAILQ_INSERT_HEAD(lhead, new, r_list);
	mtx_lock(glist_lock);
	TAILQ_INSERT_TAIL(&glist, new, g_list);
	rcache_count++;
	mtx_unlock(glist_lock);
	mtx_unlock(rcache->rcache_lock);
}

void
rcache_list_insert(struct rcache_entry_list *lhead)
{
	struct rcache_entry *new, *next;
#ifdef ENABLE_STATS
	uint32_t start_ticks;
#endif

	if (TAILQ_EMPTY(lhead))
		return;

	GLOB_TSTART(start_ticks);
	TAILQ_FOREACH_SAFE(new, lhead, r_list, next) {
		TAILQ_REMOVE(lhead, new, r_list);
		rcache_entry_insert(new);
	}
	GLOB_TEND(rcache_insert_ticks, start_ticks);

	rcache_check();
}

void
rcache_list_free(struct rcache_entry_list *lhead)
{
	struct rcache_entry *new, *next;

	TAILQ_FOREACH_SAFE(new, lhead, r_list, next) {
		TAILQ_REMOVE(lhead, new, r_list);
		__rcache_entry_free(new);
	}
}

static int
rcache_entry_locate(struct pgdata *pgdata, uint64_t block, int copy)
{
	struct rcache_entry_list *lhead;
	struct rcache_entry *entry;
	struct bdevint *bint = bdev_find(BLOCK_BID(block));
	struct rcache *rcache;
	uint32_t hashval;

	if (unlikely(!bint))
		return 0;

	hashval = hashblock(block, rcache_bits, bint->sector_shift);
	rcache = rcache_list[hashval >> RCACHE_GROUP_SHIFT];
	mtx_lock(rcache->rcache_lock);
	lhead = &rcache->entry_list[hashval & RCACHE_GROUP_MASK]; 
	TAILQ_FOREACH(entry, lhead, r_list) {
		if (entry->block == block) {
			if (!copy) {
				pgdata_free_page(pgdata);
				pgdata_add_page_ref(pgdata, entry->page);
			} else {
				pgdata_copy_page_ref(pgdata, entry->page);
			}

			mtx_lock(glist_lock);
			if (!TAILQ_ENTRY_EMPTY(entry, g_list)) {
				TAILQ_REMOVE(&glist, entry, g_list);
				TAILQ_INSERT_TAIL(&glist, entry, g_list);
			}
			mtx_unlock(glist_lock);
			GLOB_INC(rcache_lookup_hits, 1);
			mtx_unlock(rcache->rcache_lock);
			atomic_set_bit(SKIP_RCACHE_INSERT, &pgdata->flags);
			atomic_set_bit(PGDATA_SKIP_UNCOMP, &pgdata->flags);
			return 1;
		}
	}
	mtx_unlock(rcache->rcache_lock);
	return 0;
}

int
rcache_locate(struct pgdata *pgdata, int copy)
{
	int done;
	int retval;
#ifdef ENABLE_STATS
	uint32_t start_ticks;
#endif

	if (copy) {
		retval = pgdata_alloc_page(pgdata, 0);
		if (unlikely(retval != 0)) {
			debug_warn("allocating for pgdata page failed\n");
			return 0;
		}
	}

	GLOB_TSTART(start_ticks);
	GLOB_INC(rcache_lookups, 1);
	done = rcache_entry_locate(pgdata, pgdata->amap_block, copy);
	GLOB_TEND(rcache_lookup_ticks, start_ticks);
	if (copy)
		atomic_set_bit(SKIP_RCACHE_INSERT, &pgdata->flags);
	return done;
}

void
calc_rcache_bits(void)
{
	uint64_t availmem = qs_availmem;
	int bits = 12;
	uint64_t used;
	uint64_t rcache_reserved_size = (ddtable_global.reserved_size * 70) / 100;
	int rcache_entry_size = sizeof(struct rcache_entry) + PAGE_SIZE;

	used = (1ULL << 31);
	rcache_cached_min = (16 * 1024);
	while (used < availmem) {
		bits++;
		used = (used << 1);
		rcache_cached_min = (rcache_cached_min << 1);
	}
	rcache_cached_max = max_t(uint32_t, rcache_cached_min, (rcache_reserved_size / rcache_entry_size));
	debug_info("rcache cached max %u rcache cached min %u ddtable_global reserved size %u\n", rcache_cached_max, rcache_cached_min, ddtable_global.reserved_size);
}

static void
rcache_entry_list_init(struct rcache *rcache)
{
	int i;
	struct rcache_entry_list *lhead;

	for (i = 0; i < RCACHE_GROUP_SIZE; i++) {
		lhead = &rcache->entry_list[i];
		TAILQ_INIT(lhead);
	}
}

static int 
__rcache_init(void)
{
	int i;
	uint32_t rcache_groups;

	rcache_bits = calc_ddbits();
	calc_rcache_bits();
	rcache_groups = ((1U << rcache_bits) >> RCACHE_GROUP_SHIFT);

	rcache_list = zalloc(sizeof(struct rcache *) * rcache_groups, M_RCACHE, Q_NOWAIT);
	if (unlikely(!rcache_list)) {
		debug_warn("Memory allocation failure\n");
		return -1;
	}

	for (i = 0; i < rcache_groups; i++) {
		struct rcache *rcache;

		rcache = zalloc(sizeof(*rcache), M_RCACHE, Q_NOWAIT);
		if(unlikely(!rcache)) {
			debug_warn("Memory allocation failure\n");
			return -1;
		}
		rcache->rcache_lock = mtx_alloc("rcache lock");
		rcache->entry_list = __uma_zalloc(eightk_cache, Q_NOWAIT, 8192);
		if (unlikely(!rcache->entry_list)) {
			mtx_free(rcache->rcache_lock);
			free(rcache, M_RCACHE);
			return -1;
		}
		rcache_entry_list_init(rcache);
		rcache_list[i] = rcache;
	}
	return 0;
}

void
rcache_update_count(void)
{
	uint64_t ddused_size;
	int entry_size, rcache_entry_size;
	uint64_t rcache_reserved_size = (ddtable_global.reserved_size * 70) / 100;

	entry_size = sizeof(struct ddtable_ddlookup_node) + DDTABLE_LOOKUP_NODE_SIZE;
	rcache_entry_size = sizeof(struct rcache_entry) + DDTABLE_LOOKUP_NODE_SIZE;
	ddused_size = (entry_size * ddtable_global_ddlookup_count());
	if (ddused_size > rcache_reserved_size)
		rcache_reserved_size = 0;
	else
		rcache_reserved_size -= ddused_size;

	rcache_cached_max = max_t(uint32_t, rcache_cached_min, (rcache_reserved_size / rcache_entry_size));
	debug_info("rcache cached max %u rcache_cached_min %u rcache reserved size %llu ddtable_global reserved size %llu ddused_size %llu ddlookup_count %llu\n", rcache_cached_max, rcache_cached_min, (unsigned long long)(rcache_reserved_size), (unsigned long long)ddtable_global.reserved_size, (unsigned long long)ddused_size, (unsigned long long)ddtable_global_ddlookup_count());
	rcache_count_check();
}

int
rcache_init(void)
{
	int retval;

	glist_lock = mtx_alloc("glist lock");
	rcache_free_wait = wait_chan_alloc("rcache free wait");
	retval = __rcache_init();
	if (retval != 0) {
		rcache_exit();
		return -1;
	}

	retval = kernel_thread_create(rcache_free_thread, NULL, rcache_free_task, "rcacheft");
	if (unlikely(retval != 0)) {
		rcache_exit();
		return -1;
	}
	return 0;
}

void
rcache_reset(void)
{
	struct rcache_entry_list *lhead;
	struct rcache_entry *entry, *next;
	struct rcache *rcache;
	int i, j;
	uint32_t rcache_groups;

	if (!rcache_list)
		return;

	rcache_groups = ((1U << rcache_bits) >> RCACHE_GROUP_SHIFT);
	for (j = 0; j < rcache_groups; j++) {
		rcache = rcache_list[j]; 
		if (!rcache)
			continue;

		mtx_lock(rcache->rcache_lock);
		for (i = 0; i < RCACHE_GROUP_SIZE; i++) {
			lhead = &rcache->entry_list[i];
			TAILQ_FOREACH_SAFE(entry, lhead, r_list, next) {
				rcache_entry_free(lhead, entry);
			}
		}
		mtx_unlock(rcache->rcache_lock);
	}
	debug_check(!TAILQ_EMPTY(&glist));
}

static void
__rcache_free(void)
{
	struct rcache_entry_list *lhead;
	struct rcache_entry *entry, *next;
	struct rcache *rcache;
	int i, j;
	uint32_t rcache_groups;

	if (!rcache_list)
		return;

	rcache_groups = ((1U << rcache_bits) >> RCACHE_GROUP_SHIFT);
	for (j = 0; j < rcache_groups; j++) {
		rcache = rcache_list[j]; 
		if (!rcache)
			break;
		mtx_lock(rcache->rcache_lock);
		for (i = 0; i < RCACHE_GROUP_SIZE; i++) {
			lhead = &rcache->entry_list[i];
			TAILQ_FOREACH_SAFE(entry, lhead, r_list, next) {
				rcache_entry_free(lhead, entry);
			}
		}
		mtx_unlock(rcache->rcache_lock);
		rcache_list[j] = NULL;
		mtx_free(rcache->rcache_lock);
		uma_zfree(eightk_cache, rcache->entry_list);
		free(rcache, M_RCACHE);
	}
	free(rcache_list, M_RCACHE);
}

void
rcache_exit(void)
{
	__rcache_free();
	if (rcache_free_task)
		kernel_thread_stop(rcache_free_task, &rcache_flags, rcache_free_wait, RCACHE_FREE_EXIT);
	wait_chan_free(rcache_free_wait);
	mtx_free(glist_lock);
}
