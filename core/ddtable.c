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

#include "ddtable.h"
#include "bdevmgr.h"
#include "amap.h"
#include "tdisk.h"
#include "tcache.h"
#include "qs_lib.h"
#include "vdevdefs.h"
#include "rcache.h"
#include "cluster.h"
#include "node_sync.h"
#include "node_ha.h"
#include "bdevgroup.h"

struct ddtable_stats ddtable_stats;
struct ddtable_global ddtable_global;
static void ddtable_free(struct ddtable *ddtable);
static int ddlookup_check_read_io(struct ddtable *ddtable, struct ddtable_ddlookup_node *ddlookup);
struct locate_spec;
static inline void ddtable_clear_invalid_entries(struct ddtable *ddtable, struct ddtable_ddlookup_node *parent, struct pgdata *pgdata, struct locate_spec *locate_spec, int *insert_idx);

static inline void
ddtable_lock(struct ddtable *ddtable)
{
	mtx_lock(ddtable->ddtable_lock);
}

static inline void
ddtable_unlock(struct ddtable *ddtable)
{
	mtx_unlock(ddtable->ddtable_lock);
}

#ifdef ENABLE_STATS
#define PRINT_STAT(x,y)	printf(x" %llu \n", (unsigned long long)ddtable_stats.y); pause("psg", 10);
#else
#define PRINT_STAT(x,y) do {} while(0)
#endif

static struct ddtable_ddlookup_node * ddtable_ddlookup_node_new(struct ddtable *ddtable, struct ddlookup_list *ddlookup_list, struct index_info **index_info);
static int ddtables_sync(struct ddtable *ddtable, int dd_idx, int max, int rw);

void 
ddtable_ddlookup_node_wait(struct ddtable_ddlookup_node *ddlookup)
{
again:
	while (atomic_test_bit_short(DDLOOKUP_META_DATA_DIRTY, &ddlookup->flags)) {
		node_ddlookup_unlock(ddlookup);
		wait_on_chan(ddlookup->ddlookup_wait, !atomic_test_bit_short(DDLOOKUP_META_DATA_DIRTY, &ddlookup->flags));
		node_ddlookup_lock(ddlookup);
		goto again;
	}
}

void
ddtable_decr_sync_count(struct ddtable *ddtable, struct ddtable_ddlookup_node *ddlookup)
{
	ddtable_lock(ddtable);
	if (!TAILQ_ENTRY_EMPTY(ddlookup, s_list)) {
		TAILQ_REMOVE_INIT(&ddtable->sync_list, ddlookup, s_list);
		atomic_dec(&ddtable->sync_count);
	}
	ddtable_unlock(ddtable);
}

static void
__ddtable_incr_sync_count(struct ddtable *ddtable, struct ddtable_ddlookup_node *ddlookup)
{
	if (TAILQ_ENTRY_EMPTY(ddlookup, s_list)) {
		atomic_inc(&ddtable->sync_count);
		TAILQ_INSERT_TAIL(&ddtable->sync_list, ddlookup, s_list);
	}
	else {
		if (!atomic_test_bit(DDTABLE_IN_SYNC, &ddtable->flags)) {
			TAILQ_REMOVE(&ddtable->sync_list, ddlookup, s_list);
			TAILQ_INSERT_TAIL(&ddtable->sync_list, ddlookup, s_list);
		}
	}
}

void
ddtable_ddlookup_node_dirty(struct ddtable *ddtable, struct ddtable_ddlookup_node *ddlookup)
{
#ifdef ENABLE_STATS
	uint32_t start_ticks;
#endif

	DD_TSTART(start_ticks);

	ddtable_lock(ddtable);
	TAILQ_REMOVE_INIT(&ddtable->ddlookup_list, ddlookup, t_list);
	__ddtable_incr_sync_count(ddtable, ddlookup);

	if (atomic_test_bit_short(DDLOOKUP_META_IO_PENDING, &ddlookup->flags)) {
		ddtable_unlock(ddtable);
		return;
	}

	atomic_set_bit_short(DDLOOKUP_META_IO_PENDING, &ddlookup->flags);
	atomic_set_bit_short(DDLOOKUP_META_DATA_NEEDS_SYNC, &ddlookup->flags);
	if ((atomic_read(&ddtable->sync_count) > LOOKUPS_SYNC_CACHED_COUNT) && !node_in_standby()) {
		atomic_set_bit(DDTABLE_SYNC_START, &ddtable->flags);
		chan_wakeup_one_nointr(ddtable->sync_wait);
	}
	ddtable_unlock(ddtable);
	DD_TEND(node_dirty_ticks, start_ticks);
}

static inline uint32_t
hashstr(unsigned char *str, int *ret_valid)
{
	int i;
	uint32_t hash = 5381;
	int valid = 0;

	for (i = 0; i < SHA256_DIGEST_LENGTH; i++) {
		hash = ((hash << 5) + hash) + str[i]; /* hash * 33 + c */
		if (str[i])
			valid = 1;
	}

	*ret_valid = valid;
	return hash;
}

/* Only two levels */
static inline uint32_t
index_id_from_hash(struct ddtable *ddtable, uint32_t hashval)
{
	return (hashval >> (32 - ddtable->bint->ddbits));
}

static struct ddtable_ddlookup_node *
free_ddlookup_list_first(struct ddtable *ddtable)
{
	struct ddtable_ddlookup_node *ddlookup;

	ddtable_lock(ddtable);
	ddlookup = TAILQ_FIRST(&ddtable->ddlookup_list);
	ddtable_unlock(ddtable);
	return ddlookup;
}

static struct ddtable_ddlookup_node *
free_ddlookup_list_next(struct ddtable *ddtable, struct ddtable_ddlookup_node *ddlookup)
{
	struct ddtable_ddlookup_node *next;

	ddtable_lock(ddtable);
	next = TAILQ_NEXT(ddlookup, t_list);
	ddtable_unlock(ddtable);
	return next;
}

static inline void
ddtable_tail_ddlookup(struct ddtable *ddtable, struct ddtable_ddlookup_node *ddlookup)
{
	if (ddlookup && !ddlookup_is_root(ddlookup)) {
		ddtable_lock(ddtable);
		if (!TAILQ_ENTRY_EMPTY(ddlookup, t_list)) {
			TAILQ_REMOVE(&ddtable->ddlookup_list, ddlookup, t_list);
			TAILQ_INSERT_TAIL(&ddtable->ddlookup_list, ddlookup, t_list);
		}
		ddtable_unlock(ddtable);
	}
}

static inline struct ddtable_node *
ddnode_list_get(struct ddtable *ddtable, uint32_t id)
{
	uint32_t group_id;
	uint32_t ddlookup_id;
	struct node_group *node_group;
	struct ddtable_node *node;

	group_id = id >> NODE_GROUP_SHIFT;
	node_group = ddtable->node_groups[group_id];

	ddlookup_id = id & NODE_GROUP_MASK;
	node = node_group->ddnodes_list[ddlookup_id];
	return node;
}

struct ddtable_node *
node_get(struct ddtable *ddtable, uint64_t b_start)
{
	uint32_t hash_idx;
	struct ddtable_node *node;

	hash_idx = hashblock(b_start, ddtable->bint->ddbits, ddtable->bint->sector_shift);
	node = ddnode_list_get(ddtable, hash_idx);
	node_lock(node);
	return node;
}

static inline int 
ddlookup_busy(struct ddtable_ddlookup_node *ddlookup)
{
	if (atomic_read(&ddlookup->refs) > 1 || atomic_test_bit_short(DDLOOKUP_META_IO_PENDING, &ddlookup->flags) || atomic_test_bit_short(DDLOOKUP_META_DATA_DIRTY, &ddlookup->flags) || atomic_test_bit_short(DDLOOKUP_META_DATA_READ_DIRTY, &ddlookup->flags) || atomic_test_bit_short(DDLOOKUP_META_IO_READ_PENDING, &ddlookup->flags))
		return 1;
	else
		return 0;
}

#ifdef FREEBSD 
static void dd_free_thread(void *data)
#else
static int dd_free_thread(void *data)
#endif
{
	struct ddtable *ddtable = data;
	struct ddtable_ddlookup_node *ddlookup, *next;
	struct ddlookup_list *ddlookup_list;
	struct ddtable_node *node;
	int done;

	for(;;)
	{
		wait_on_chan_interruptible(ddtable->free_wait, atomic_test_bit(DDTABLE_FREE_START, &ddtable->flags) || kernel_thread_check(&ddtable->flags, DDTABLE_FREE_EXIT));
		atomic_clear_bit(DDTABLE_FREE_START, &ddtable->flags);

		if (kernel_thread_check(&ddtable->flags, DDTABLE_FREE_EXIT))
			break;

		if (ddtable_global_can_add_ddlookup())
			continue;

		DD_INC(free_run, 1);

		done = 0;
		ddlookup = free_ddlookup_list_first(ddtable);
		while (ddlookup && (!ddtable_global_can_add_ddlookup())) {
			debug_check(ddlookup_is_root(ddlookup));
			next = free_ddlookup_list_next(ddtable, ddlookup);
			if (ddlookup_is_root(ddlookup)) {
				ddlookup = next;
				continue;
			}
			node = node_get(ddtable, ddlookup->b_start);
			ddlookup_list = ddlookup->ddlookup_list;
			if (ddlookup_list)
				ddlookup_list_lock(ddlookup_list);

			ddtable_lock(ddtable);
			if (ddlookup_busy(ddlookup)) {
				ddtable_unlock(ddtable);
				if (ddlookup_list)
					ddlookup_list_unlock(ddlookup_list);
				node_unlock(node);
				ddlookup = next;
				continue;
			}

			LIST_REMOVE_INIT(ddlookup, n_list);
			if (ddlookup_list)
				SLIST_REMOVE(&ddlookup_list->lhead, ddlookup, ddtable_ddlookup_node, p_list);
			TAILQ_REMOVE_INIT(&ddtable->ddlookup_list, ddlookup, t_list);
			TAILQ_REMOVE_INIT(&ddtable->sync_list, ddlookup, s_list);
			done++;

			ddtable_unlock(ddtable);
			if (ddlookup_list)
				ddlookup_list_unlock(ddlookup_list);
			node_unlock(node);

			DD_INC(free_thread, 1);
			ddtable_ddlookup_node_put(ddlookup);
			ddtable_global_ddlookup_decr();
			ddlookup = next;
			if (kernel_thread_check(&ddtable->flags, DDTABLE_FREE_EXIT))
				break;
		}

		if (kernel_thread_check(&ddtable->flags, DDTABLE_FREE_EXIT))
			break;
		pause("psg", 1000);
	}

#ifdef FREEBSD 
	kproc_exit(0);
#else
	return 0;
#endif
}

void
ddtable_check_count(struct ddtable *ddtable)
{
	ddtable_global_ddlookup_incr();
	rcache_update_count();
#if 0
	if (ddtable_global_can_add_ddlookup())
		return;

	atomic_set_bit(DDTABLE_FREE_START, &ddtable->flags);
	chan_wakeup_one_nointr(ddtable->free_wait);
#endif
}

void
node_insert(struct ddtable *ddtable, struct ddtable_node *node, struct ddtable_ddlookup_node *child)
{
	struct ddtable_ddlookup_node *ddlookup, *prev = NULL;

	LIST_FOREACH(ddlookup, &node->node_list, n_list) {
		if (ddlookup->b_start > child->b_start) {
			break;
		}
		prev = ddlookup;
	}

	if (prev)
		LIST_INSERT_AFTER(prev, child, n_list);
	else
		LIST_INSERT_HEAD(&node->node_list, child, n_list);

	ddtable_lock(ddtable);
	if (TAILQ_ENTRY_EMPTY(child, t_list) && !ddlookup_is_root(child) && !atomic_test_bit_short(DDLOOKUP_META_IO_PENDING, &child->flags) && !atomic_test_bit_short(DDLOOKUP_META_DATA_DIRTY, &child->flags))
		TAILQ_INSERT_TAIL(&ddtable->ddlookup_list, child, t_list);
	ddtable_unlock(ddtable);
}

static int 
node_sync(struct ddtable *ddtable, struct ddtable_node *node)
{
	struct ddtable_ddlookup_node *ddlookup;
	int done = 0;

	LIST_FOREACH(ddlookup, &node->node_list, n_list) {
		node_ddlookup_lock(ddlookup);
		if (atomic_test_bit_short(DDLOOKUP_META_IO_PENDING, &ddlookup->flags)) {
			ddtable_ddlookup_node_wait(ddlookup);
			ddtable_ddlookup_sync(ddtable, ddlookup, 1, -1, 0ULL);
			ddtable_decr_sync_count(ddtable, ddlookup);
			done++;
		}
		node_ddlookup_unlock(ddlookup);
	}
	return done;
}

static void
node_ddtable_ha_free_node(struct ddtable_node *node)
{
#if 0
	struct ddtable_ddlookup_node *ddlookup, *tvar;

	LIST_FOREACH_SAFE(ddlookup, &node->node_list, n_list, tvar) {
#if 0
		wait_on_chan(ddlookup->ddlookup_wait, !atomic_test_bit_short(DDLOOKUP_META_DATA_READ_DIRTY, &ddlookup->flags) && !atomic_test_bit_short(DDLOOKUP_META_DATA_DIRTY, &ddlookup->flags));
#endif
		if (ddlookup->ddlookup_list)
			continue;

		node_ddlookup_lock(ddlookup);
		LIST_REMOVE(ddlookup, n_list);
		ddlookup->n_list.le_next = NULL;
		ddlookup->n_list.le_prev = NULL;
		node_ddlookup_unlock(ddlookup);
		ddtable_ddlookup_node_put(ddlookup);
	}
#endif
}

void
node_ddtable_ha_takeover(struct bdevgroup *group)
{
	int i;
	struct ddtable *ddtable;

	ddtable = &group->ddtable;
	if (!atomic_read(&ddtable->inited))
		return;

	for (i = 0; i < ddtable->max_roots; i++) {
		struct ddtable_node *node;

		node = ddnode_list_get(ddtable, i);
		node_ddtable_ha_free_node(node);
	}
}

static void
node_free(struct ddtable_node *node)
{
	struct ddtable_ddlookup_node *ddlookup, *tvar;

	LIST_FOREACH_SAFE(ddlookup, &node->node_list, n_list, tvar) {
		node_ddlookup_lock(ddlookup);
		LIST_REMOVE(ddlookup, n_list);
		ddlookup->n_list.le_next = NULL;
		ddlookup->n_list.le_prev = NULL;
		node_ddlookup_unlock(ddlookup);
		ddtable_ddlookup_node_put(ddlookup);
	}
}

struct ddtable_ddlookup_node *
node_ddlookup(struct ddtable_node *node, uint64_t b_start)
{
	struct ddtable_ddlookup_node *ddlookup;

	LIST_FOREACH(ddlookup, &node->node_list, n_list) {
		if (ddlookup->b_start >= b_start) {
			if (ddlookup->b_start == b_start) {
				ddtable_ddlookup_node_get(ddlookup);
				return ddlookup;
			}
			break;
		}
	}
	return NULL;
}

static void
ddtable_ddlookup_free_list(struct ddtable *ddtable, struct ddlookup_node_list *lhead)
{
	struct ddtable_ddlookup_node *ddlookup;
	struct ddtable_node *node;

	while ((ddlookup = SLIST_FIRST(lhead)) != NULL) {
		SLIST_REMOVE_HEAD(lhead, p_list);
		wait_on_chan(ddlookup->ddlookup_wait, !atomic_test_bit_short(DDLOOKUP_META_DATA_READ_DIRTY, &ddlookup->flags) && !atomic_test_bit_short(DDLOOKUP_META_DATA_DIRTY, &ddlookup->flags));
		debug_check(atomic_test_bit_short(DDLOOKUP_META_IO_PENDING, &ddlookup->flags) && !node_in_standby());
		node = node_get(ddtable, ddlookup->b_start);
		LIST_REMOVE_INIT(ddlookup, n_list);
		ddtable_lock(ddtable);
		TAILQ_REMOVE_INIT(&ddtable->ddlookup_list, ddlookup, t_list);
		ddtable_unlock(ddtable);
		node_unlock(node);

		ddtable_ddlookup_node_put(ddlookup);
		ddtable_global_ddlookup_decr();
	}
}

void
ddtable_ddlookup_node_free(struct ddtable_ddlookup_node *ddlookup)
{
	debug_check(atomic_test_bit_short(DDLOOKUP_META_IO_PENDING, &ddlookup->flags) && !node_in_standby());

	if (ddlookup->metadata)
		vm_pg_free(ddlookup->metadata);

	DD_INC(ddlookups_freed, 1);
	wait_chan_free(ddlookup->ddlookup_wait);
	sx_free(ddlookup->ddlookup_lock);
	uma_zfree(ddtable_ddlookup_node_cache, ddlookup);
}

#ifdef FREEBSD 
void static ddtable_ddlookup_end_bio(struct bio *bio)
#else
void static ddtable_ddlookup_end_bio(struct bio *bio, int err)
#endif
{
	struct ddtable_ddlookup_node *ddtable_ddlookup = (struct ddtable_ddlookup_node *)bio_get_caller(bio);
#ifdef FREEBSD
	int err = bio->bio_error;
#endif

	if (unlikely(err))
		atomic_set_bit_short(DDLOOKUP_META_DATA_ERROR, &ddtable_ddlookup->flags);

	if (bio_get_command(bio) == QS_IO_WRITE) {
		atomic_clear_bit_short(DDLOOKUP_META_DATA_DIRTY, &ddtable_ddlookup->flags);
	}
	else {
		atomic_clear_bit_short(DDLOOKUP_META_DATA_READ_DIRTY, &ddtable_ddlookup->flags);
	}
	chan_wakeup(ddtable_ddlookup->ddlookup_wait);
	ddtable_ddlookup_node_put(ddtable_ddlookup);
	bio_free_page(bio);
	g_destroy_bio(bio);
}

static int
ddtable_ddlookup_io(struct ddtable *ddtable, struct ddtable_ddlookup_node *ddlookup, int rw, int root_id, uint64_t prev_b_start)
{
	int retval;

	if (rw == QS_IO_WRITE && !atomic_test_bit_short(DDLOOKUP_META_IO_PENDING, &ddlookup->flags))
	{
		debug_check(atomic_test_bit_short(DDLOOKUP_META_IO_READ_PENDING, &ddlookup->flags));
		return 0;
	}
	else if (rw == QS_IO_READ && !atomic_test_bit_short(DDLOOKUP_META_IO_READ_PENDING, &ddlookup->flags))
	{
		debug_check(atomic_test_bit_short(DDLOOKUP_META_IO_PENDING, &ddlookup->flags));
		return 0;
	}


	if (rw == QS_IO_WRITE) {
		atomic_set_bit_short(DDLOOKUP_META_DATA_DIRTY, &ddlookup->flags);
		atomic_clear_bit_short(DDLOOKUP_META_IO_PENDING, &ddlookup->flags);
		atomic_clear_bit_short(DDLOOKUP_META_DATA_CLONED, &ddlookup->flags);
		node_ddlookup_sync_send(ddtable, ddlookup, root_id, prev_b_start);
		DD_INC(ddlookups_synced, 1);
	}
	else {
		atomic_set_bit_short(DDLOOKUP_META_DATA_READ_DIRTY, &ddlookup->flags);
		atomic_clear_bit_short(DDLOOKUP_META_IO_READ_PENDING, &ddlookup->flags);
	}

	ddtable_ddlookup_node_get(ddlookup);
	retval = qs_lib_bio_page(ddtable->bint, ddlookup->b_start, DDTABLE_LOOKUP_NODE_SIZE, ddlookup->metadata, ddtable_ddlookup_end_bio, ddlookup, rw, TYPE_DDLOOKUP);
	if (unlikely(retval != 0)) {
		debug_warn("Failed to load talloc at %llu bid %u\n", (unsigned long long)ddlookup->b_start, ddtable->bint->bid);
		atomic_set_bit_short(DDLOOKUP_META_DATA_ERROR, &ddlookup->flags);
		ddtable_ddlookup_node_put(ddlookup);
	}

	return retval;
}

struct ddtable_ddlookup_node *
ddtable_ddlookup_node_alloc(allocflags_t flags)
{
	struct ddtable_ddlookup_node *ddlookup;

	ddlookup = __uma_zalloc(ddtable_ddlookup_node_cache, Q_NOWAIT | Q_ZERO, sizeof(*ddlookup));
	if (unlikely(!ddlookup)) {
		debug_warn("Memory allocation failure\n");
		return NULL;
	}

	atomic_set(&ddlookup->refs, 1);
	ddlookup->ddlookup_wait = wait_chan_alloc("ddlookup wait");
	ddlookup->ddlookup_lock = sx_alloc("ddlookup lock");

	ddlookup->metadata = vm_pg_alloc(flags);
	if (unlikely(!ddlookup->metadata)) {
		ddtable_ddlookup_node_put(ddlookup);
		return NULL;
	}

	DD_INC(ddlookups_alloced, 1);
	return ddlookup;
}

static uint64_t 
ddlookup_get_next_block(struct ddtable_ddlookup_node *ddlookup)
{
	struct raw_ddtable_ddlookup_node *raw_ddlookup;

	raw_ddlookup = (struct raw_ddtable_ddlookup_node *)(((uint8_t *)vm_pg_address(ddlookup->metadata)) + RAW_LOOKUP_OFFSET);
	return raw_ddlookup->next_block;
}

static inline void
write_raw_ddlookup(struct ddtable_ddlookup_node *ddlookup)
{
	struct raw_ddtable_ddlookup_node *raw_ddlookup;
	uint64_t csum;

	raw_ddlookup = (struct raw_ddtable_ddlookup_node *)(((uint8_t *)vm_pg_address(ddlookup->metadata)) + RAW_LOOKUP_OFFSET);
	raw_ddlookup->num_entries = ddlookup->num_entries;
	csum = calc_csum(vm_pg_address(ddlookup->metadata), DDTABLE_LOOKUP_NODE_SIZE - sizeof(uint64_t));
	raw_ddlookup->csum = csum;
}

static int 
ddtable_ddlookup_read(struct ddtable_ddlookup_node *ddlookup)
{
	struct raw_ddtable_ddlookup_node *raw_ddlookup;
	uint64_t csum;

	if (atomic_test_bit_short(DDLOOKUP_DONE_LOAD, &ddlookup->flags))
		return 0;

	if (atomic_test_bit_short(DDLOOKUP_META_DATA_ERROR, &ddlookup->flags)) {
		debug_warn("Metadata data error for ddlookup at %llu\n", (unsigned long long)ddlookup->b_start);
		return -1;
	}

	raw_ddlookup = (struct raw_ddtable_ddlookup_node *)(((uint8_t *)vm_pg_address(ddlookup->metadata)) + RAW_LOOKUP_OFFSET);

	csum = calc_csum(vm_pg_address(ddlookup->metadata), DDTABLE_LOOKUP_NODE_SIZE - sizeof(uint64_t));
	if (raw_ddlookup->csum != csum) { 
		debug_warn("Metadata csum mismatch at %llu raw lookup csum %llx csum %llx\n", (unsigned long long)ddlookup->b_start, (unsigned long long)raw_ddlookup->csum, (unsigned long long)csum);
		return -1;
	}

	ddlookup->num_entries = raw_ddlookup->num_entries;
	atomic_set_bit_short(DDLOOKUP_DONE_LOAD, &ddlookup->flags);
	DD_INC(hash_count, ddlookup->num_entries);
	return 0;
}

static struct ddtable_ddlookup_node *
ddtable_ddlookup_node_load(struct ddtable *ddtable, uint64_t b_start, struct ddlookup_list *ddlookup_list)
{
	struct ddtable_ddlookup_node *ddlookup;

	ddlookup = ddtable_ddlookup_node_alloc(0);
	if (unlikely(!ddlookup))
		return NULL;

	DD_INC(ddlookups_load, 1);
	ddlookup->b_start = b_start;
	ddlookup->ddlookup_list = ddlookup_list;
	atomic_set_bit_short(DDLOOKUP_META_IO_READ_PENDING, &ddlookup->flags);
	ddtable_check_count(ddtable);
	return ddlookup;
}

static struct ddtable_ddlookup_node *
ddtable_ddlookup_root_load(uint64_t b_start, struct ddlookup_list *ddlookup_list)
{
	struct ddtable_ddlookup_node *ddlookup;

	ddlookup = ddtable_ddlookup_node_alloc(0);
	if (unlikely(!ddlookup))
		return NULL;

	atomic_set_bit_short(DDLOOKUP_META_IO_READ_PENDING, &ddlookup->flags);
	DD_INC(ddlookups_load, 1);
	DD_INC(root_load, 1);
	ddlookup->b_start = b_start;
	atomic_set_bit_short(DDLOOKUP_IS_ROOT, &ddlookup->flags);
	ddlookup->ddlookup_list = ddlookup_list;
	ddtable_global_ddlookup_incr();
	return ddlookup;
}

static struct ddtable_ddlookup_node *
ddtable_ddlookup_list_last(struct ddlookup_list *ddlookup_list, int *error)
{
	struct ddtable_ddlookup_node *ddlookup, *prev = NULL;
	uint64_t next_block;
	int retval;

	ddlookup_list_lock(ddlookup_list);
	ddlookup = SLIST_FIRST(&ddlookup_list->lhead);
	if (ddlookup)
		ddtable_ddlookup_node_get(ddlookup);
	ddlookup_list_unlock(ddlookup_list);

	while (ddlookup) {
		wait_on_chan_check(ddlookup->ddlookup_wait, !atomic_test_bit_short(DDLOOKUP_META_DATA_READ_DIRTY, &ddlookup->flags));

		node_ddlookup_lock(ddlookup);
		retval = ddtable_ddlookup_read(ddlookup);
		node_ddlookup_unlock(ddlookup);

		if (unlikely(retval != 0)) {
			debug_warn("Metadata read failed for node at %llu\n", (unsigned long long)BLOCK_BLOCKNR(ddlookup->b_start));
			*error = -1;
			if (prev)
				ddtable_ddlookup_node_put(prev);
			ddtable_ddlookup_node_put(ddlookup);
			return NULL;
		}

		if (prev) {
			if (atomic_test_bit_short(DDLOOKUP_META_DATA_BUSY, &prev->flags) || atomic_test_bit_short(DDLOOKUP_META_DATA_BUSY, &ddlookup->flags)) {
				ddtable_ddlookup_node_put(ddlookup);
				break;
			}

			next_block = ddlookup_get_next_block(prev);
			if (ddlookup->b_start != BLOCK_BLOCKNR(next_block)) {
				ddtable_ddlookup_node_put(ddlookup);
				break;
			}
			ddtable_ddlookup_node_put(prev);
		}
		prev = ddlookup;
		ddlookup_list_lock(ddlookup_list);
		ddlookup = SLIST_NEXT(ddlookup, p_list);
		if (ddlookup)
			ddtable_ddlookup_node_get(ddlookup);
		ddlookup_list_unlock(ddlookup_list);
	}

	return prev;
}

struct ddlookup_list *
ddlookup_list_get(struct ddtable *ddtable, uint32_t id)
{
	uint32_t group_id;
	uint32_t ddlookup_id;
	struct node_group *node_group;
	struct ddlookup_list *ddlookup_list;

	group_id = id >> NODE_GROUP_SHIFT;
	node_group = ddtable->node_groups[group_id];

	ddlookup_id = id & NODE_GROUP_MASK;
	ddlookup_list = node_group->ddlookup_lists[ddlookup_id];
	return ddlookup_list;
}

static struct ddlookup_list *
ddlookup_list_alloc(struct ddtable *ddtable, uint32_t id)
{
	uint32_t group_id;
	uint32_t ddlookup_id;
	struct node_group *node_group;
	struct ddlookup_list *ddlookup_list;
	struct ddtable_node *node;

	group_id = id >> NODE_GROUP_SHIFT;
	node_group = ddtable->node_groups[group_id];

	ddlookup_id = id & NODE_GROUP_MASK;

	ddlookup_list = __uma_zalloc(ddlookup_list_cache, Q_NOWAIT | Q_ZERO, sizeof(*ddlookup_list));
	if (unlikely(!ddlookup_list)) {
		debug_warn("Slab allocation failure\n");
		return NULL;
	}

	node = __uma_zalloc(ddnode_cache, Q_NOWAIT, sizeof(*node));
	if (unlikely(!node)) {
		debug_warn("Slab allocation failure\n");
		uma_zfree(ddlookup_list_cache, ddlookup_list);
		return NULL;
	}

	SLIST_INIT(&ddlookup_list->lhead);
	ddlookup_list->lhead_lock = mtx_alloc("ddlookup lhead lock");
	ddlookup_list->insert_lock = sx_alloc("ddlookup insert lock");

	LIST_INIT(&node->node_list);
	node->node_lock = sx_alloc("ddnode lock");

	node_group->ddlookup_lists[ddlookup_id] = ddlookup_list;
	node_group->ddnodes_list[ddlookup_id] = node;
	return ddlookup_list;
}

struct ddtable_ddlookup_node *
ddtable_sync_list_next(struct ddtable *ddtable, struct ddtable_ddlookup_node *prev)
{
	struct ddtable_ddlookup_node *ret;

	ddtable_lock(ddtable);
	ret = TAILQ_NEXT(prev, s_list);
	if (ret)
		ddtable_ddlookup_node_get(ret);
	ddtable_unlock(ddtable);
	return ret;
}

struct ddtable_ddlookup_node *
ddtable_sync_list_first(struct ddtable *ddtable)
{
	struct ddtable_ddlookup_node *ret;

	ddtable_lock(ddtable);
	ret = TAILQ_FIRST(&ddtable->sync_list);
	if (ret)
		ddtable_ddlookup_node_get(ret);
	ddtable_unlock(ddtable);
	return ret;
}

static struct ddtable_ddlookup_node *
sync_list_first(struct ddtable *ddtable)
{
	struct ddtable_ddlookup_node *ret;

	ddtable_lock(ddtable);
	ret = TAILQ_FIRST(&ddtable->sync_list);
	if (ret) {
		ddtable_ddlookup_node_get(ret);
		TAILQ_REMOVE_INIT(&ddtable->sync_list, ret, s_list);
		atomic_dec(&ddtable->sync_count);
	}
	ddtable_unlock(ddtable);
	return ret;
}

atomic_t write_requests;

#ifdef FREEBSD 
static void dd_sync_thread(void *data)
#else
static int dd_sync_thread(void *data)
#endif
{
	struct ddtable *ddtable = data;
	struct ddtable_ddlookup_node *ddlookup;
	int i, todo;
	int done;
	struct tpriv priv = { 0 };

	thread_start();

	for(;;)
	{
		wait_on_chan_interruptible(ddtable->sync_wait, atomic_test_bit(DDTABLE_SYNC_START, &ddtable->flags) || kernel_thread_check(&ddtable->flags, DDTABLE_SYNC_EXIT));
		atomic_set_bit(DDTABLE_IN_SYNC_THR, &ddtable->flags);

		DD_INC(sync_run, 1);

		if (kernel_thread_check(&ddtable->flags, DDTABLE_SYNC_EXIT)) {
			atomic_clear_bit(DDTABLE_IN_SYNC_THR, &ddtable->flags);
			chan_wakeup_nointr(ddtable->sync_wait);
			break;
		}

		if (atomic_read(&write_requests)){
			pause("sync psg", 2000);
		}
		else {
			pause("sync psg", 200);
		}

		if (atomic_read(&ddtable->sync_count) < LOOKUPS_SYNC_CACHED_COUNT || atomic_test_bit(DDTABLE_IN_SYNC, &ddtable->flags) || node_in_standby()) {
			debug_info("sync count %d cached count %d\n", atomic_read(&ddtable->sync_count), LOOKUPS_SYNC_CACHED_COUNT);
			atomic_clear_bit(DDTABLE_SYNC_START, &ddtable->flags);
			atomic_clear_bit(DDTABLE_IN_SYNC_THR, &ddtable->flags);
			chan_wakeup_nointr(ddtable->sync_wait);
			continue;
		}

		todo = 8;
		debug_info("ddtable sync count %d\n", atomic_read(&ddtable->sync_count));
		i = 0;
		done = 0;
		bzero(&priv, sizeof(priv));
		while ((ddlookup = sync_list_first(ddtable)) != NULL) {
			node_ddlookup_lock(ddlookup);
			if (atomic_test_bit_short(DDLOOKUP_META_IO_PENDING, &ddlookup->flags) && !atomic_test_bit_short(DDLOOKUP_META_DATA_BUSY, &ddlookup->flags)) {
				if (!priv.data)
					bdev_marker(ddtable->bint->b_dev, &priv);
				ddtable_ddlookup_node_wait(ddlookup);
				ddtable_ddlookup_sync(ddtable, ddlookup, 1, -1, 0ULL);
				ddtable_decr_sync_count(ddtable, ddlookup);
				i++;
			}
			ddtable_lock(ddtable);
			if (!ddlookup_is_root(ddlookup) && TAILQ_ENTRY_EMPTY(ddlookup, t_list))
				TAILQ_INSERT_TAIL(&ddtable->ddlookup_list, ddlookup, t_list);
			ddtable_unlock(ddtable);
			node_ddlookup_unlock(ddlookup);

			ddtable_ddlookup_node_put(ddlookup);
			if ((i >= todo && atomic_read(&write_requests)) || kernel_thread_check(&ddtable->flags, DDTABLE_SYNC_EXIT) || (i > 512) || node_in_standby()) 
				break;

			debug_check(atomic_read(&write_requests) < 0);
			done++;
			if (done == 128) {
#ifdef FREEBSD 
				g_waitidle();
#else
				bdev_start(ddtable->bint->b_dev, &priv);
#endif
				pause("psg", 10);
				done = 0;
			}

		}

		if (priv.data)
			bdev_start(ddtable->bint->b_dev, &priv);

		if ((atomic_read(&ddtable->sync_count) < LOOKUPS_SYNC_CACHED_COUNT)) {
			atomic_clear_bit(DDTABLE_SYNC_START, &ddtable->flags);
			atomic_clear_bit(DDTABLE_IN_SYNC_THR, &ddtable->flags);
			chan_wakeup_nointr(ddtable->sync_wait);
		}
	}

	thread_end();
#ifdef FREEBSD 
	kproc_exit(0);
#else
	return 0;
#endif
}

static int 
ddtable_init(struct ddtable *ddtable, struct bdevint *bint)
{
	uint32_t num_groups;
	int i;

	ddtable->max_roots = (1U << bint->ddbits);
	debug_info("ddbits %d max roots %u\n", ddtable->bint->ddbits, ddtable->max_roots);
	TAILQ_INIT(&ddtable->ddlookup_list);
	TAILQ_INIT(&ddtable->sync_list);
	ddtable->ddtable_lock = mtx_alloc("ddtable lock");
	ddtable->sync_wait = wait_chan_alloc("ddsync wait");
	ddtable->free_wait = wait_chan_alloc("ddfree wait");
	ddtable->load_wait = wait_chan_alloc("ddload wait");

	num_groups = ddtable->max_roots >> NODE_GROUP_SHIFT;
	debug_check(ddtable->max_roots & NODE_GROUP_MASK);
	ddtable->node_groups = zalloc(sizeof(struct node_group *) * num_groups, M_DDTABLE, Q_NOWAIT);
	if (unlikely(!ddtable->node_groups)) {
		debug_warn("Memory allocation failure\n");
		ddtable_free(ddtable);
		return -1;
	}

	for (i = 0; i < num_groups; i++) {
		struct node_group *node_group;

		node_group = __uma_zalloc(node_group_cache, Q_NOWAIT, sizeof(*node_group));
		if (unlikely(!node_group)) {
			debug_warn("Slab allocation failure\n");
			ddtable_free(ddtable);
			return -1;
		}

		node_group->ddlookup_lists = __uma_zalloc(fourk_cache, Q_NOWAIT | Q_ZERO, 4096);
		if (unlikely(!node_group->ddlookup_lists)) {
			debug_warn("Slab allocation failure\n");
			uma_zfree(node_group_cache, node_group);
			ddtable_free(ddtable);
			return -1;
		}

		node_group->ddnodes_list = __uma_zalloc(fourk_cache, Q_NOWAIT | Q_ZERO, 4096);
		if (unlikely(!node_group->ddnodes_list)) {
			debug_warn("Slab allocation failure\n");
			uma_zfree(fourk_cache, node_group->ddlookup_lists);
			uma_zfree(node_group_cache, node_group);
			ddtable_free(ddtable);
			return -1;
		}
		ddtable->node_groups[i] = node_group;
	}
	ddtable->bint = bint;

	return 0;
}

static int
ddtables_sync(struct ddtable *ddtable, int dd_idx, int max, int rw)
{
	int i;
	struct tcache *tcache;
	struct ddtable_ddlookup_node *ddlookup;
	struct ddlookup_list *ddlookup_list;
	int retval;
	int error = 0;

	if (max == dd_idx || (node_in_standby() && rw == QS_IO_WRITE))
		return 0;

	tcache = tcache_alloc((max - dd_idx));
	for (i = dd_idx; i < max; i++) {
		ddlookup_list = ddlookup_list_get(ddtable, i);
		ddlookup = SLIST_FIRST(&ddlookup_list->lhead);
		node_ddlookup_lock(ddlookup);

		if (rw == QS_IO_READ) {
			if (!atomic_test_bit_short(DDLOOKUP_META_IO_READ_PENDING, &ddlookup->flags)) {
				node_ddlookup_unlock(ddlookup);
				continue;
			}
			atomic_clear_bit_short(DDLOOKUP_META_IO_READ_PENDING, &ddlookup->flags);
		} else {
			if (!atomic_test_bit_short(DDLOOKUP_META_IO_PENDING, &ddlookup->flags)) {
				node_ddlookup_unlock(ddlookup);
				continue;
			}
			atomic_clear_bit_short(DDLOOKUP_META_IO_PENDING, &ddlookup->flags);
		}

		if (rw == QS_IO_WRITE) {
			write_raw_ddlookup(ddlookup);
		}

		retval = tcache_add_page(tcache, ddlookup->metadata, ddlookup->b_start, ddtable->bint, DDTABLE_LOOKUP_NODE_SIZE, rw);
		ddtable_decr_sync_count(ddtable, ddlookup);
		node_ddlookup_unlock(ddlookup);
		if (unlikely(retval != 0))
			goto err;

	}

	if (!atomic_read(&tcache->bio_remain)) {
		tcache_put(tcache);
		return 0;
	}

	tcache_entry_rw(tcache, rw);
	wait_for_done(tcache->completion);

	if (atomic_test_bit_short(TCACHE_IO_ERROR, &tcache->flags)) {
		tcache_put(tcache);
		return -1;
	}

	for (i = dd_idx; i < max; i++) {
		ddlookup_list = ddlookup_list_get(ddtable, i);
		ddlookup = SLIST_FIRST(&ddlookup_list->lhead);
		chan_wakeup(ddlookup->ddlookup_wait);
	}

	tcache_put(tcache);
	return error;

err:
	tcache_put(tcache);
	return -1;
}

static void
ddtable_free(struct ddtable *ddtable)
{
	struct node_group *node_group;
	struct ddtable_node *node;
	struct ddlookup_list *ddlookup_list;
	int i, j;
	uint32_t num_groups;

	num_groups = ddtable->max_roots >> NODE_GROUP_SHIFT;

	if (!ddtable->node_groups)
		goto free_locks;

	for (i = 0; i < num_groups; i++) {
		node_group = ddtable->node_groups[i];
		if (!node_group)
			break;
		for (j = 0; j < NODE_GROUP_SIZE; j++) {
			ddlookup_list = node_group->ddlookup_lists[j];
			if (!ddlookup_list)
				continue;
			ddtable_ddlookup_free_list(ddtable, &ddlookup_list->lhead);
			sx_free(ddlookup_list->insert_lock);
			mtx_free(ddlookup_list->lhead_lock);
			uma_zfree(ddlookup_list_cache, ddlookup_list);
		}
	}

	for (i = 0; i < num_groups; i++) {
		node_group = ddtable->node_groups[i];
		if (!node_group)
			break;

		for (j = 0; j < NODE_GROUP_SIZE; j++) {
			node = node_group->ddnodes_list[j];
			if (!node)
				continue;
			sx_free(node->node_lock);
			uma_zfree(ddnode_cache, node);
		}
		if (node_group->ddlookup_lists)
			uma_zfree(fourk_cache, node_group->ddlookup_lists);
		if (node_group->ddnodes_list)
			uma_zfree(fourk_cache, node_group->ddnodes_list);
		uma_zfree(node_group_cache, node_group);
	}
	free(ddtable->node_groups, M_DDTABLE);
free_locks:
	wait_chan_free(ddtable->sync_wait);
	wait_chan_free(ddtable->free_wait);
	wait_chan_free(ddtable->load_wait);
	mtx_free(ddtable->ddtable_lock);
	bzero(ddtable, sizeof(*ddtable));
}

static struct ddtable_ddlookup_node *
ddtable_ddlookup_load_next(struct ddtable *ddtable, struct ddtable_ddlookup_node *child, struct ddlookup_list *ddlookup_list, uint64_t next_block, int *error)
{
	struct ddtable_node *node;
	struct ddtable_ddlookup_node *next;

	node = node_get(ddtable, BLOCK_BLOCKNR(next_block));
	next = node_ddlookup(node, BLOCK_BLOCKNR(next_block));
	if (!next) {
		next = ddtable_ddlookup_node_load(ddtable, BLOCK_BLOCKNR(next_block), ddlookup_list);
		if (unlikely(!next)) {
			node_unlock(node);
			*error = -1;
			return NULL;
		}
		ddtable_ddlookup_node_get(next);
		ddlookup_list_lock(ddlookup_list);
		SLIST_INSERT_AFTER(child, next, p_list);
		ddlookup_list_unlock(ddlookup_list);
		node_insert(ddtable, node, next);
	}
	else if (!next->ddlookup_list) {
		next->ddlookup_list = ddlookup_list;
		ddlookup_list_lock(ddlookup_list);
		SLIST_INSERT_AFTER(child, next, p_list);
		ddlookup_list_unlock(ddlookup_list);
	}
	node_unlock(node);
	return next;
}

static int
ddtable_load_peers(struct ddtable *ddtable)
{
	int i;
	int has_peers;
	int done = 0, error = 0;
	uint64_t next_block;
	struct tpriv priv = { 0 };

	bdev_marker(ddtable->bint->b_dev, &priv);
	while (ddtable_global_can_add_ddlookup() && !kernel_thread_check(&ddtable->flags, DDTABLE_LOAD_EXIT)) {
		has_peers = 0;
		for (i = 0; i < ddtable->max_roots && !kernel_thread_check(&ddtable->flags, DDTABLE_LOAD_EXIT); i++) {
			struct ddtable_ddlookup_node *peer, *next;
			struct ddlookup_list *ddlookup_list;

			ddlookup_list = ddlookup_list_get(ddtable, i);
			peer = ddtable_ddlookup_list_last(ddlookup_list, &error);
			if (error != 0 || !peer)
				return -1;

			if (atomic_test_bit_short(DDLOOKUP_META_DATA_BUSY, &peer->flags)) {
				ddtable_ddlookup_node_put(peer);
				continue;
			}

			next_block = ddlookup_get_next_block(peer);
			if (!next_block) {
				ddtable_ddlookup_node_put(peer);
				continue;
			}

			next = ddtable_ddlookup_load_next(ddtable, peer, ddlookup_list, next_block, &error);
			if (!next || error != 0) {
				ddtable_ddlookup_node_put(peer);
				if (next)
					ddtable_ddlookup_node_put(next);
				debug_warn("Failed to load node at %llu\n", (unsigned long long)BLOCK_BLOCKNR(next_block));
				return -1;
			}

			if (ddlookup_check_read_io(ddtable, next)) {
				DD_INC(async_load, 1);
				done++;
			}
				
			ddtable_ddlookup_node_put(peer);
			ddtable_ddlookup_node_put(next);

			has_peers = 1;
			if (done == 128) {
				done = 0;
#ifdef FREEBSD
				g_waitidle();
#else
				bdev_start(ddtable->bint->b_dev, &priv);
				bdev_marker(ddtable->bint->b_dev, &priv);
#endif
				pause("ddloadthr", 100);
			}
		}

		if (!has_peers)
			break;
	}
	bdev_start(ddtable->bint->b_dev, &priv);
	return 0;
}

#ifdef FREEBSD 
static void dd_load_thread(void *data)
#else
static int dd_load_thread(void *data)
#endif
{
	struct ddtable *ddtable = data;

	thread_start();
	ddtable_load_peers(ddtable);
	wait_on_chan_interruptible(ddtable->load_wait, kernel_thread_check(&ddtable->flags, DDTABLE_LOAD_EXIT));
	thread_end();
#ifdef FREEBSD 
	kproc_exit(0);
#else
	return 0;
#endif
}

void
ddtable_load_thr_start(struct ddtable *ddtable)
{
	debug_check(ddtable->load_task);
	kernel_thread_create(dd_load_thread, ddtable, ddtable->load_task, "ddloadt");
}

int
ddtable_load(struct ddtable *ddtable, struct bdevint *table_bint)
{
	uint64_t table_b_start = (DDTABLE_META_OFFSET) >> table_bint->sector_shift;
	pagestruct_t *page;
	uint32_t offset = 0;
	struct ddtable_ddlookup_node *root;
	int i;
	struct raw_ddtable *raw_table;
	struct ddtable_node *node;
	int retval;
	uint32_t dd_idx = 0;
	int dd_idx_set = 0;
	struct ddlookup_list *ddlookup_list;

	retval = ddtable_init(ddtable, table_bint);
	if (unlikely(retval != 0)) {
		ddtable_free(ddtable);
		return -1;
	}

	page = vm_pg_alloc(0);
	if (unlikely(!page)) {
		ddtable_free(ddtable);
		return -1;
	}

	retval = qs_lib_bio_lba(table_bint, table_b_start, page, QS_IO_READ, TYPE_DDTABLE);
	if (unlikely(retval != 0)) {
		vm_pg_free(page);
		ddtable_free(ddtable);
		return -1;
	}

	raw_table = (struct raw_ddtable *)(vm_pg_address(page));

	for (i = 0; i < ddtable->max_roots; i++) {
		ddlookup_list = ddlookup_list_alloc(ddtable, i);
		if (unlikely(!ddlookup_list))
			goto err;
	}

	for (i = 0; i < ddtable->max_roots; i++) {
		if (!dd_idx_set) {
			dd_idx = i;
			dd_idx_set = 1;
		}

		ddlookup_list = ddlookup_list_get(ddtable, i);

		root = ddtable_ddlookup_root_load(BLOCK_BLOCKNR(raw_table->root[offset]), ddlookup_list);
		if (unlikely(!root)) {
			debug_warn("Cannot alloc root ddtable ddlookup\n");
			goto err;
		}

		node = node_get(ddtable, root->b_start);
		SLIST_INSERT_HEAD(&ddlookup_list->lhead, root, p_list);
		node_insert(ddtable, node, root);
		node_unlock(node);

		offset++;
		if (offset == (BINT_INDEX_META_SIZE / sizeof(uint64_t))) {
			retval = ddtables_sync(ddtable, dd_idx, i+1, QS_IO_READ);
			if (unlikely(retval != 0))
				goto err;

			dd_idx = 0;
			dd_idx_set = 0;

			table_b_start += (BINT_INDEX_META_SIZE >> table_bint->sector_shift);
			retval = qs_lib_bio_lba(table_bint, table_b_start, page, QS_IO_READ, TYPE_DDTABLE);
			if (unlikely(retval != 0))
				goto err;

			offset = 0;
		}
	}

	if (dd_idx_set) {
		retval = ddtables_sync(ddtable, dd_idx, i, QS_IO_READ);
		if (unlikely(retval != 0))
			goto err;
	}

#if 0
	retval = ddtable_load_peers(ddtable);
	if (unlikely(retval != 0))
		goto err;
#endif

	retval = kernel_thread_create(dd_sync_thread, ddtable, ddtable->sync_task, "ddsynct");
	if (unlikely(retval != 0))
		goto err;

	retval = kernel_thread_create(dd_free_thread, ddtable, ddtable->free_task, "ddfreet");
	if (unlikely(retval != 0))
		goto err;

#if 0
	retval = kernel_thread_create(dd_load_thread, ddtable, ddtable->load_task, "ddloadt");
	if (unlikely(retval != 0))
		goto err;
#endif

	vm_pg_free(page);
	rcache_update_count();
	atomic_set(&ddtable->inited, 1);
	atomic_inc(&ddtable_global.cur_ddtables);
	return 0;
err:

	if (ddtable->sync_task)
		kernel_thread_stop(ddtable->sync_task, &ddtable->flags, ddtable->sync_wait, DDTABLE_SYNC_EXIT);

	if (ddtable->free_task)
		kernel_thread_stop(ddtable->free_task, &ddtable->flags, ddtable->free_wait, DDTABLE_FREE_EXIT);

	ddtable_free(ddtable);
	vm_pg_free(page);
	return -1;
}

int
ddtable_create(struct ddtable *ddtable, struct bdevint *table_bint)
{
	struct ddtable_ddlookup_node *ddlookup;
	struct raw_ddtable *raw_table;
	pagestruct_t *page;
	int retval;
	int i;
	uint64_t table_b_start = (DDTABLE_META_OFFSET) >> table_bint->sector_shift;
	struct index_info_list index_info_list;
	uint32_t offset = 0;
	uint32_t dd_idx = 0;
	int dd_idx_set = 0;
	struct ddtable_node *node;
	struct ddlookup_list *ddlookup_list;
	struct index_sync_list index_sync_list;
	struct index_info *index_info;

	retval = ddtable_init(ddtable, table_bint);
	if (unlikely(retval != 0)) {
		ddtable_free(ddtable);
		return -1;
	}

	page = vm_pg_alloc(0);
	if (unlikely(!page)) {
		ddtable_free(ddtable);
		return -1;
	}

	bzero(vm_pg_address(page), PAGE_SIZE);
	raw_table = (struct raw_ddtable *)(vm_pg_address(page));

	TAILQ_INIT(&index_info_list);
	SLIST_INIT(&index_sync_list);
	for (i = 0; i < ddtable->max_roots; i++) {
		ddlookup_list = ddlookup_list_alloc(ddtable, i);
		if (unlikely(!ddlookup_list)) {
			goto err;
		}
	}

	for (i = 0; i < ddtable->max_roots; i++) {

		if (!dd_idx_set) {
			dd_idx = i;
			dd_idx_set = 1;
		}

		ddlookup_list = ddlookup_list_get(ddtable, i);
		ddlookup = ddtable_ddlookup_node_new(ddtable, ddlookup_list, &index_info);
		if (unlikely(!ddlookup)) {
			goto err;
		}
		TAILQ_INSERT_TAIL(&index_info_list, index_info, i_list);

		DD_INC(root_new, 1);
		atomic_set_bit_short(DDLOOKUP_IS_ROOT, &ddlookup->flags);

		node = node_get(ddtable, ddlookup->b_start);
		SET_BLOCK(raw_table->root[offset], ddlookup->b_start, ddtable->bint->bid);
		SLIST_INSERT_HEAD(&ddlookup_list->lhead, ddlookup, p_list);
		node_insert(ddtable, node, ddlookup);
		node_unlock(node);

		offset++;
		if (offset == (BINT_INDEX_META_SIZE/sizeof(uint64_t))) {

			index_list_insert(&index_sync_list, &index_info_list);
			index_sync_start_io(&index_sync_list, 1);
			index_sync_wait(&index_sync_list);
			index_info_wait(&index_info_list);

			retval = ddtables_sync(ddtable, dd_idx, i+1, QS_IO_WRITE);
			if (unlikely(retval != 0))
				goto err;

			retval = qs_lib_bio_lba(table_bint, table_b_start, page, QS_IO_WRITE, TYPE_DDTABLE);
			if (unlikely(retval != 0))
				goto err;

			bzero(vm_pg_address(page), PAGE_SIZE);
			table_b_start += (BINT_INDEX_META_SIZE >> table_bint->sector_shift);
			dd_idx_set = 0;
			offset = 0;
		}
	}

	if (dd_idx_set) {
		index_list_insert(&index_sync_list, &index_info_list);
		index_sync_start_io(&index_sync_list, 1);
		index_sync_wait(&index_sync_list);
		index_info_wait(&index_info_list);

		retval = ddtables_sync(ddtable, dd_idx, i, QS_IO_WRITE);
		if (unlikely(retval != 0))
			goto err;

		retval = qs_lib_bio_lba(table_bint, table_b_start, page, QS_IO_WRITE, TYPE_DDTABLE);
		if (unlikely(retval != 0))
			goto err;
	}

	vm_pg_free(page);

	retval = kernel_thread_create(dd_sync_thread, ddtable, ddtable->sync_task, "ddsynct");
	if (unlikely(retval != 0)) {
		goto err;
	}

	retval = kernel_thread_create(dd_free_thread, ddtable, ddtable->free_task, "ddfreet");
	if (unlikely(retval != 0)) {
		goto err;
	}

	rcache_update_count();
	atomic_set(&ddtable->inited, 1);
	return 0;
err:
	if (ddtable->sync_task)
		kernel_thread_stop(ddtable->sync_task, &ddtable->flags, ddtable->sync_wait, DDTABLE_SYNC_EXIT);

	ddtable_free(ddtable);
	vm_pg_free(page);
	return -1;
}

static void
node_wait(struct ddtable_node *node)
{
	struct ddtable_ddlookup_node *ddlookup;

	LIST_FOREACH(ddlookup, &node->node_list, n_list) {
		wait_on_chan(ddlookup->ddlookup_wait, !atomic_test_bit_short(DDLOOKUP_META_DATA_READ_DIRTY, &ddlookup->flags) && !atomic_test_bit_short(DDLOOKUP_META_DATA_DIRTY, &ddlookup->flags));
	}
}

static void
ddtable_node_wait(struct ddtable *ddtable, int start_idx, int max)
{
	struct ddtable_node *node;
	int i;

	for (i = start_idx; i < max; i++) {
		node = ddnode_list_get(ddtable, i);
		node_wait(node);
	}
}

void
ddtable_exit(struct ddtable *ddtable)
{
	int i;
	struct ddlookup_list *ddlookup_list;
	int dd_idx;
	struct tpriv priv = { 0 };
	int start_idx = 0, write_done = 0, done = 0, retval;

	if (!atomic_read(&ddtable->inited))
		return;

	atomic_clear_bit(DDTABLE_SYNC_ENABLED, &ddtable->flags);
	while (atomic_read(&ddtable->inited) > 1)
		pause("psg", 100);

	if (ddtable->sync_task)
		kernel_thread_stop(ddtable->sync_task, &ddtable->flags, ddtable->sync_wait, DDTABLE_SYNC_EXIT);

	if (ddtable->free_task)
		kernel_thread_stop(ddtable->free_task, &ddtable->flags, ddtable->free_wait, DDTABLE_FREE_EXIT);

	if (ddtable->load_task)
		kernel_thread_stop(ddtable->load_task, &ddtable->flags, ddtable->load_wait, DDTABLE_LOAD_EXIT);

	dd_idx = 0;
	for (i = 0; i < ddtable->max_roots; i++) {
		if (i && (i % 256 == 0)) {
			ddtables_sync(ddtable, dd_idx, i, QS_IO_WRITE);
			dd_idx = i;
		}
	}

	ddtables_sync(ddtable, dd_idx, i, QS_IO_WRITE);
	debug_info("ddtable sync count now %d\n", atomic_read(&ddtable->sync_count));

	bdev_marker(ddtable->bint->b_dev, &priv);
	for (i = 0; i < ddtable->max_roots; i++) {
		struct ddtable_node *node;

		node = ddnode_list_get(ddtable, i);
		retval = node_sync(ddtable, node);
		done += retval;
		write_done += retval;
		if (write_done >= 512 || ((i + 1) == ddtable->max_roots)) {
			bdev_start(ddtable->bint->b_dev, &priv);
			bdev_marker(ddtable->bint->b_dev, &priv);
			write_done = 0;
		}

		if (done >= 2048 || ((i + 1) == ddtable->max_roots)) {
			ddtable_node_wait(ddtable, start_idx, i+1);
			done = 0;
			start_idx = i+1;
		}
	}
	bdev_start(ddtable->bint->b_dev, &priv);

	for (i = 0; i < ddtable->max_roots; i++) {
		ddlookup_list = ddlookup_list_get(ddtable, i);
		if (!ddlookup_list)
			continue;

		ddtable_ddlookup_free_list(ddtable, &ddlookup_list->lhead);
	}

	for (i = 0; i < ddtable->max_roots; i++) {
		struct ddtable_node *node;

		node = ddnode_list_get(ddtable, i);
		node_free(node);
	}

	debug_info("Free ddtable\n");
	ddtable_free(ddtable);

	PRINT_STAT("async_load", async_load);
	PRINT_STAT("sync_load", sync_load);
	PRINT_STAT("hash_load", hash_load);
	PRINT_STAT("find_load", find_load);
	PRINT_STAT("insert_load", insert_load);
	PRINT_STAT("locate_spec_new", locate_spec_new);
	PRINT_STAT("locate_spec_replace", locate_spec_replace);
	PRINT_STAT("locate_spec_misses", locate_spec_misses);
	PRINT_STAT("set_node_failed", set_node_failed);
	PRINT_STAT("set_node_success", set_node_success);
	PRINT_STAT("invalid_amap_entry", invalid_amap_entry);
	PRINT_STAT("invalid_amap_entry_pre", invalid_amap_entry_pre);
	PRINT_STAT("root_new", root_new);
	PRINT_STAT("root_load", root_load);
	PRINT_STAT("ddlookups_alloced", ddlookups_alloced);
	PRINT_STAT("ddlookups_new", ddlookups_new);
	PRINT_STAT("ddlookups_load", ddlookups_load);
	PRINT_STAT("ddlookups_freed", ddlookups_freed);
	PRINT_STAT("sync_run", sync_run);
	PRINT_STAT("sync_thread", sync_thread);
	PRINT_STAT("free_run", free_run);
	PRINT_STAT("free_thread", free_thread);
	PRINT_STAT("hash_remove_misses", hash_remove_misses);
	PRINT_STAT("critical_wait", critical_wait);
	PRINT_STAT("ddlookups_synced", ddlookups_synced);
	PRINT_STAT("hashes", hashes);
	PRINT_STAT("dedupe_blocks", dedupe_blocks);
	PRINT_STAT("transit_blocks", transit_blocks);
	PRINT_STAT("zero_blocks", zero_blocks);
	PRINT_STAT("hash_ddlookup", hash_ddlookups);
	PRINT_STAT("hash_count", hash_count);
	PRINT_STAT("process_queue_ticks", process_queue_ticks);
	PRINT_STAT("delete_block_pre_ticks", delete_block_pre_ticks);
	PRINT_STAT("handle_ddwork_ticks", handle_ddwork_ticks);
	PRINT_STAT("hash_insert_setup_ticks", hash_insert_setup_ticks);
	PRINT_STAT("hash_insert_post_setup_ticks", hash_insert_post_setup_ticks);
	PRINT_STAT("amap_sync_start_ticks", amap_sync_start_ticks);
	PRINT_STAT("log_list_start_ticks", log_list_start_ticks);
	PRINT_STAT("hash_insert_post_ticks", hash_insert_post_ticks);
	PRINT_STAT("log_list_writes_ticks", log_list_writes_ticks);
	PRINT_STAT("cloning_wait_ticks", cloning_wait_ticks);
	PRINT_STAT("index_list_insert_ticks", index_list_insert_ticks);
	PRINT_STAT("index_list_meta_insert_ticks", index_list_meta_insert_ticks);
	PRINT_STAT("delete_block_ticks", delete_block_ticks);
	PRINT_STAT("log_list_end_ticks", log_list_end_ticks);
	PRINT_STAT("amap_sync_post_ticks", amap_sync_post_ticks);
	PRINT_STAT("index_sync_ticks", index_sync_ticks);
	PRINT_STAT("amap_sync_ticks", amap_sync_ticks);
	PRINT_STAT("index_sync_wait_ticks", index_sync_wait_ticks);
	PRINT_STAT("index_info_wait_ticks", index_info_wait_ticks);
	PRINT_STAT("index_info_meta_wait_ticks", index_info_meta_wait_ticks);
	PRINT_STAT("amap_sync_wait_ticks", amap_sync_wait_ticks);
	PRINT_STAT("node_pgdata_sync_ticks", node_pgdata_sync_ticks);
	PRINT_STAT("log_clear_ticks", log_clear_ticks);
	PRINT_STAT("handle_meta_sync_ticks", handle_meta_sync_ticks);
	PRINT_STAT("index_sync_post_ticks", index_sync_post_ticks);
	PRINT_STAT("post_free_ticks", post_free_ticks);
	PRINT_STAT("hash_compute_ticks", hash_compute_ticks);
	PRINT_STAT("compression_ticks", compression_ticks);
	PRINT_STAT("hash_str_ticks", hash_str_ticks);
	PRINT_STAT("hash_ddlookup_ticks", hash_ddlookup_ticks);
	PRINT_STAT("node_dirty_ticks", node_dirty_ticks);
	PRINT_STAT("ddlookup_list_find_ticks", ddlookup_list_find_ticks);
	PRINT_STAT("find_entry_ticks", find_entry_ticks);
	PRINT_STAT("hash_insert_ticks", hash_insert_ticks);
	PRINT_STAT("insert_entry_ticks", insert_entry_ticks);
	PRINT_STAT("insert_find_entry_ticks", insert_find_entry_ticks);
	PRINT_STAT("sanity_check_ticks", sanity_check_ticks);
	PRINT_STAT("set_node_block_ticks", set_node_block_ticks);
	PRINT_STAT("set_hash_ticks", set_hash_ticks);
	PRINT_STAT("load_node_ticks", load_node_ticks);
	PRINT_STAT("ddlookup_barrier_ticks", ddlookup_barrier_ticks);
	PRINT_STAT("get_node_block_ticks", get_node_block_ticks);
	PRINT_STAT("free_block_ticks", free_block_ticks);
	PRINT_STAT("ddlookup_find_node_ticks", ddlookup_find_node_ticks);
	PRINT_STAT("hash_remove_block_ticks", hash_remove_block_ticks);
	PRINT_STAT("process_delete_block_ticks", process_delete_block_ticks);
	PRINT_STAT("process_delete_free_block_ticks", process_delete_free_block_ticks);
	PRINT_STAT("max_refed", max_refed);
	PRINT_STAT("blocks_removed", blocks_removed);
	PRINT_STAT("blocks_replaced", blocks_replaced);
	PRINT_STAT("blocks_inserted", blocks_inserted);
	PRINT_STAT("invalid_node_blocks", invalid_node_blocks);
	PRINT_STAT("invalid_block_refs", invalid_block_refs);
	PRINT_STAT("inline_dedupe", inline_dedupe);
	PRINT_STAT("post_dedupe", post_dedupe);
	PRINT_STAT("post_dedupe_skipped", post_dedupe_skipped);
	PRINT_STAT("peer_count", peer_count);
	PRINT_STAT("peer_load_count", peer_load_count);

	debug_check(!atomic_read(&ddtable_global.cur_ddtables));
	atomic_dec(&ddtable_global.cur_ddtables);
}

static inline void
set_entry_block_time(struct ddblock_entry *entry, uint64_t block)
{
	uint64_t curtime = get_current_time();

	entry->block = (block | ((curtime & 0x3FFF) << AMAP_BLOCK_BITS));
	entry->time = ((curtime >> 14) & 0xFFFF);
}

static inline uint32_t
entry_block_time(struct ddblock_entry *entry)
{
	uint64_t entry_time;

	entry_time = (entry->block >> AMAP_BLOCK_BITS) | (entry->time << 14);
	return entry_time;
}

static inline int 
ddtable_set_node_block(struct ddtable *ddtable, struct pgdata *pgdata, struct bdevint *bint, struct bintindex *index, struct ddtable_ddlookup_node *parent, int insert_idx, int incr, struct index_info_list *index_info_list)
{
#ifdef ENABLE_STATS
	uint32_t tmp_ticks;
#endif
	int retval;
	struct index_info *index_info;
	struct ddblock_entry *entry;

	index_lock(index);
	amap_read_lock(pgdata->amap);
	if (!pgdata_amap_entry_valid(pgdata)) {
		DD_INC(invalid_amap_entry, 1);
		amap_read_unlock(pgdata->amap);
		index_unlock(index);
		return -1;
	}

	DD_TSTART(tmp_ticks);
	retval = bdev_set_node_block(bint, index, BLOCK_BLOCKNR(pgdata->amap_block), parent->b_start);
	DD_TEND(set_node_block_ticks, tmp_ticks);
	if (unlikely(retval != 0)) {
		DD_INC(set_node_failed, 1);
		amap_read_unlock(pgdata->amap);
		index_unlock(index);
		return -1;
	}
	amap_read_unlock(pgdata->amap);

	DD_INC(set_node_success, 1);
	index_info = index_info_clone(pgdata->index_info);
	index_add_iowaiter(index, &index_info->iowaiter);
	index_unlock(index);

	ddtable_ddlookup_write_barrier(parent);
	entry = ddtable_ddlookup_get_block_entry(parent, insert_idx);
	set_entry_block_time(entry, pgdata->amap_block);
	memcpy(entry->hash, pgdata->hash, SHA256_DIGEST_LENGTH);
	if (incr) {
		debug_check(insert_idx != parent->num_entries);
		parent->num_entries++;
	}
	ddtable_ddlookup_node_dirty(ddtable, parent);
	DD_INC(blocks_inserted, 1);
	DD_INC(hash_count, 1);
	TAILQ_INSERT_TAIL(index_info_list, index_info, i_list);
	return 0;
}

static struct ddblock_info *
ddblock_info_get(struct ddtable *ddtable, struct ddtable_ddlookup_node *ddlookup, struct ddblock_entry *entry, int entry_idx, int *status, struct index_info_list *index_info_list, struct write_list *wlist)
{
	struct bdevint *bint;
	struct bintindex *index;
	struct ddblock_info *info;
	struct index_info *index_info;
	uint64_t index_id;
	uint64_t entry_block;
	int retval;
	uint32_t entry_id;

	entry_block = (entry->block & AMAP_BLOCK_MASK);
	bint = bdev_find(BLOCK_BID(entry_block));
	if (unlikely(!bint)) {
		debug_warn("Failed to load bid at %u\n", BLOCK_BID(entry_block));
		*status = DDBLOCK_DEDUPE_DISABLED;
		return NULL;
	}

	index_id = index_id_from_block(bint, BLOCK_BLOCKNR(entry_block), &entry_id);

	wlist_lock(wlist);
	index = bint_locate_index(bint, index_id, index_info_list);
	wlist_unlock(wlist);

	if (unlikely(!index)) {
		debug_warn("Cannot get a index at index_id %llu\n", (unsigned long long)index_id);
		*status = DDBLOCK_DEDUPE_DISABLED;
		return NULL;
	}

	index_info = index_info_alloc();
	if (unlikely(!index_info)) {
		debug_warn("Failed to alloc for index_info\n");
		index_put(index);
		*status = DDBLOCK_DEDUPE_DISABLED;
		return NULL;
	}

	if (atomic_test_bit(META_DATA_READ_DIRTY, &index->flags)) {
		index_info->index = index;
		info = zalloc(sizeof(struct ddblock_info), M_DDBLOCK_INFO, Q_WAITOK);
		info->status = DDBLOCK_ENTRY_INDEX_LOADING;
		*status = DDBLOCK_ENTRY_INDEX_LOADING; 
		info->index_info = index_info;
		return info;
	}

	index_lock(index);
	index_check_load(index);
	if (atomic_test_bit(META_DATA_ERROR, &index->flags)) {
		index_unlock(index);
		index_put(index);
		index_info_free(index_info);
		*status = DDBLOCK_DEDUPE_DISABLED;
		return NULL;
	}

	index_write_barrier(bint, index);
	retval = bint_ref_block(bint, index, entry_id, lba_block_size(entry_block), index_info, ddlookup->b_start);

	if (unlikely(retval != 0)) {
		index_unlock(index);

		ddtable_ddlookup_write_barrier(ddlookup);
		entry = ddtable_ddlookup_get_block_entry(ddlookup, entry_idx);
		bzero(entry, sizeof(*entry));
		ddtable_ddlookup_node_dirty(ddtable, ddlookup);
		*status = DDBLOCK_DEDUPE_DISABLED;
		DD_DEC(hash_count, 1);
		if (retval == BDEV_ERROR_INVALID_NODE_BLOCK) {
			DD_INC(invalid_node_blocks, 1);
		}
		else if (retval == BDEV_ERROR_INVALID_REFS) {
			DD_INC(invalid_block_refs, 1);
		}
		else if (retval == BDEV_ERROR_MAX_REFS) {
			DD_INC(max_refed, 1);
		}
		index_put(index);
		index_info_free(index_info);
		return NULL;
	}
	index_info->b_start = BLOCK_BLOCKNR(entry_block);

	ddtable_ddlookup_write_barrier(ddlookup);
	entry = ddtable_ddlookup_get_block_entry(ddlookup, entry_idx);
	set_entry_block_time(entry, entry_block);

	info = zalloc(sizeof(struct ddblock_info), M_DDBLOCK_INFO, Q_WAITOK);
	info->block = entry_block;
	info->index_info = index_info; 
	index_unlock(index);
	index_put(index);

	wlist_lock(wlist);
	TAILQ_INSERT_TAIL(index_info_list, index_info, i_list);
	wlist_unlock(wlist);
	*status = DDBLOCK_ENTRY_FOUND_DUPLICATE;
	return info;
}

#define DDTABLE_PEER_LIMIT	8

struct locate_spec {
	int new_entry;
	int valid;
	struct ddtable_ddlookup_node *insert_ddlookup;
	int insert_idx;
	int incr;
	uint32_t time;
};

static void
ddtable_add_to_locate_spec(struct locate_spec *locate_spec, struct ddtable_ddlookup_node *ddlookup, int insert_idx, struct ddblock_entry *entry, int incr)
{
	uint32_t entry_time = entry_block_time(entry);

	if (!entry->block || !locate_spec->time || entry_time < locate_spec->time) {
		locate_spec->insert_idx = insert_idx;
		ddtable_ddlookup_node_get(ddlookup);
		if (locate_spec->insert_ddlookup)
			ddtable_ddlookup_node_put(locate_spec->insert_ddlookup);

		locate_spec->insert_ddlookup = ddlookup;
		if (!entry->block)
			locate_spec->new_entry = 1;
		locate_spec->valid = 1;
		locate_spec->incr = incr;
		locate_spec->time = entry_time;
		return;
	}
}

static struct ddblock_info *
ddtable_ddlookup_find_entry(struct bdevgroup *group, struct ddtable *ddtable, struct pgdata *pgdata, struct ddtable_ddlookup_node *parent, index_t *hash, int *error, int *status, struct index_info_list *index_info_list, struct locate_spec *locate_spec, int skip_dd, struct write_list *wlist)
{
	struct ddblock_entry *entry;
	struct ddblock_info *info = NULL;
	struct bdevint *bint;
	uint64_t entry_block;
	int i, retval;

	for (i = 0; i < parent->num_entries; i++) {
		entry = ddtable_ddlookup_get_block_entry(parent, i);
		if (!entry->block) {
			if (locate_spec && !locate_spec->new_entry)
				ddtable_add_to_locate_spec(locate_spec, parent, i, entry, 0);
			continue;
		}

		entry_block = (entry->block & AMAP_BLOCK_MASK);
		bint = bdev_find(BLOCK_BID(entry_block));
		if (!bint) {
			debug_info("Clearing entry for bid %u for id %d blocknr %llu\n", BLOCK_BID(entry_block), i, (unsigned long long)parent->b_start);
			ddtable_ddlookup_write_barrier(parent);
			entry = ddtable_ddlookup_get_block_entry(parent, i);
			bzero(entry, sizeof(*entry));
			ddtable_ddlookup_node_dirty(ddtable, parent);
			if (locate_spec && !locate_spec->new_entry) {
				ddtable_add_to_locate_spec(locate_spec, parent, i, entry, 0);
			}
			continue;
		}

//		if (memcmp(entry->hash, hash, SHA256_DIGEST_LENGTH) == 0) {
		if (hash_equal((uint64_t *)entry->hash, (uint64_t *)hash)) {
			if (skip_dd) {
				ddtable_clear_invalid_entries(ddtable, parent, pgdata, NULL, NULL);
				retval = ddtable_set_node_block(ddtable, pgdata, pgdata->index_info->index->subgroup->group->bint, pgdata->index_info->index, parent, i, 0, index_info_list);
				if (retval == 0)
					DD_INC(blocks_replaced, 1);
				*error = -1;
				return NULL;
			}

			if (bint && bint->group != group) {
				if (locate_spec && !locate_spec->new_entry) {
					ddtable_add_to_locate_spec(locate_spec, parent, i, entry, 0);
				}
				continue;
			}

			info = ddblock_info_get(ddtable, parent, entry, i, status, index_info_list, wlist);
			return info;
		}

		if (locate_spec && !locate_spec->new_entry) {
			ddtable_add_to_locate_spec(locate_spec, parent, i, entry, 0);
		}
	}

	if (locate_spec && !locate_spec->new_entry && parent->num_entries != DDTABLE_LOOKUP_NODE_MAX_BLOCKS) {
		entry = ddtable_ddlookup_get_block_entry(parent, parent->num_entries);
		if (unlikely(entry->block)) {
			debug_warn("num entries %d MAX BLOCKS %d\n", parent->num_entries, (int)DDTABLE_LOOKUP_NODE_MAX_BLOCKS);
			ddtable_ddlookup_write_barrier(parent);
			entry = ddtable_ddlookup_get_block_entry(parent, parent->num_entries);
			bzero(entry, sizeof(*entry));
			ddtable_ddlookup_node_dirty(ddtable, parent);
		}
		ddtable_add_to_locate_spec(locate_spec, parent, parent->num_entries, entry, 1);
	}

	return NULL;
}

static struct ddblock_info *
ddtable_hash_ddlookup(struct bdevgroup *group, struct pgdata *pgdata, int *error, int *status, struct write_list *wlist)
{
	struct ddtable *ddtable = bdev_group_ddtable(group);
	index_t *hash = (index_t *)(pgdata->hash);
	struct ddtable_ddlookup_node *child, *next;
	struct ddblock_info *info;
	index_t root_id;
	uint32_t hashval = pgdata->hashval;
	struct ddlookup_node_list *lhead;
	struct ddlookup_list *ddlookup_list;
	uint64_t next_block;
#ifdef ENABLE_STATS
	uint32_t start_ticks;
#endif
	int retval;

	DD_INC(hash_ddlookups, 1);
	*error = 0;
	*status = 0;
	root_id = index_id_from_hash(ddtable, hashval);
	ddlookup_list = ddlookup_list_get(ddtable, root_id);
	lhead = &ddlookup_list->lhead;

	DD_TSTART(start_ticks);
	ddlookup_list_lock(ddlookup_list);
	child = SLIST_FIRST(lhead);
	ddtable_ddlookup_node_get(child);
	ddlookup_list_unlock(ddlookup_list);
	DD_TEND(ddlookup_list_find_ticks, start_ticks);

	while (child) {

		wait_on_chan_check(child->ddlookup_wait, !atomic_test_bit_short(DDLOOKUP_META_DATA_READ_DIRTY, &child->flags));

		DD_TSTART(start_ticks);
		node_ddlookup_lock(child);
		retval = ddtable_ddlookup_read(child);
		if (unlikely(retval != 0)) {
			node_ddlookup_unlock(child);
			ddtable_ddlookup_node_put(child);
			*error = -1;
			return NULL;
		}

		info = ddtable_ddlookup_find_entry(group, ddtable, NULL, child, hash, error, status, &wlist->index_info_list, NULL, 0, wlist);
		node_ddlookup_unlock(child);

		DD_TEND(find_entry_ticks, start_ticks);
		if (info || *status || *error) {
			ddtable_ddlookup_node_put(child);
			return info;
		}

		next_block = ddlookup_get_next_block(child);
		if (!next_block) {
			ddlookup_list_lock(ddlookup_list);
			next = SLIST_NEXT(child, p_list);
			if (next)
				ddtable_ddlookup_node_get(next);
			ddlookup_list_unlock(ddlookup_list);
			if (!next) {
				ddtable_ddlookup_node_put(child);
				break;
			}

			if (ddlookup_check_read_io(ddtable, next))
				DD_INC(hash_load, 1);
			ddtable_tail_ddlookup(ddtable, next);
			ddtable_ddlookup_node_put(child);
			child = next;
			continue;
		}

		ddlookup_list_lock(ddlookup_list);
		next = SLIST_NEXT(child, p_list);
		if (next)
			ddtable_ddlookup_node_get(next);
		ddlookup_list_unlock(ddlookup_list);
		if (!next || next->b_start != BLOCK_BLOCKNR(next_block)) {
			if (next)
				ddtable_ddlookup_node_put(next);

			next = ddtable_ddlookup_load_next(ddtable, child, ddlookup_list, next_block, error);
			if (unlikely(*error != 0 || !next)) {
				ddtable_ddlookup_node_put(child);
				if (next)
					ddtable_ddlookup_node_put(next);
				*error = -1;
				return NULL;
			}
		}
		if (ddlookup_check_read_io(ddtable, next))
			DD_INC(hash_load, 1);
		ddtable_tail_ddlookup(ddtable, next);
		ddtable_ddlookup_node_put(child);
		child = next;
	}
	return NULL;
}

void
scan_dedupe_data(struct bdevgroup *group, struct pgdata *pgdata, struct write_list *wlist)
{
	struct ddblock_info *info;
	int error, status;
#ifdef ENABLE_STATS
	uint32_t start_ticks;
#endif
	int valid = 0;

#if 0
	if (atomic_test_bit(DDBLOCK_ZERO_BLOCK, &pgdata->flags)) {
		DD_INC(zero_blocks, 1);
		return;
	}

	if (!tdisk->enable_deduplication || atomic_test_bit(DDBLOCK_DEDUPE_DISABLED, &pgdata->flags)) {
		atomic_set_bit(DDBLOCK_DEDUPE_DISABLED, &pgdata->flags);
		return;
	}
#endif

#if 0
	DD_TSTART(start_ticks);
	ddblock_hash_compute(pgdata);
	DD_TEND(hash_compute_ticks, start_ticks);
#endif

#if 0
	if (atomic_test_bit(DDBLOCK_ZERO_BLOCK, &pgdata->flags) || !tdisk->enable_deduplication) {
		if (!tdisk->enable_deduplication)
			atomic_set_bit(DDBLOCK_DEDUPE_DISABLED, &pgdata->flags);

		if (atomic_test_bit(DDBLOCK_ZERO_BLOCK, &pgdata->flags)) {
			DD_INC(zero_blocks, 1);
		}
		return;
	}
#endif

	DD_TSTART(start_ticks);
	pgdata->hashval = hashstr(pgdata->hash, &valid);
	DD_TEND(hash_str_ticks, start_ticks);

	if (!valid) {
		debug_check(1);
		atomic_set_bit(DDBLOCK_DEDUPE_DISABLED, &pgdata->flags);
		return;
	}

	DD_TSTART(start_ticks);
	info = ddtable_hash_ddlookup(group, pgdata, &error, &status, wlist);
	DD_TEND(hash_ddlookup_ticks, start_ticks);
	if (unlikely(error != 0)) {
		atomic_set_bit(DDBLOCK_DEDUPE_DISABLED, &pgdata->flags);
		debug_check(info);
	}
	else {
		if (status)
			atomic_set_bit(status, &pgdata->flags);

		if (info) {
			if (status == DDBLOCK_ENTRY_FOUND_DUPLICATE) {
				pgdata->amap_block = info->block;
				debug_check(!pgdata->amap_block);
				pgdata->index_info = info->index_info;
				free(info, M_DDBLOCK_INFO);
				DD_INC(inline_dedupe, 1);
				DD_INC(dedupe_blocks, 1);
			}
			else if (status == DDBLOCK_ENTRY_INDEX_LOADING) {
				pgdata->ddblock_info = info;
			}
			else {
				debug_check(1);
				free(info, M_DDBLOCK_INFO);
			}
		}
	}
	return;
}

static struct ddtable_ddlookup_node *
ddtable_ddlookup_node_new(struct ddtable *ddtable, struct ddlookup_list *ddlookup_list, struct index_info **ret_index_info)
{
	uint64_t b_start;
	struct ddtable_ddlookup_node *ddlookup;
	struct index_info *index_info;

	ddlookup = ddtable_ddlookup_node_alloc(VM_ALLOC_ZERO);
	if (unlikely(!ddlookup))
		return NULL;

	DD_INC(ddlookups_new, 1);

	index_info = index_info_alloc();
	b_start = __bdev_alloc_block(ddtable->bint, DDTABLE_LOOKUP_NODE_SIZE, index_info, TYPE_META_BLOCK);
	if (unlikely(!b_start)) {
		debug_warn("Allocating for a new ddlookup failed\n");
		index_info_free(index_info);
		ddtable_ddlookup_node_put(ddlookup);
		return NULL;
	}

	*ret_index_info = index_info;
	ddlookup->ddlookup_list = ddlookup_list;
	ddlookup->b_start = b_start;
	atomic_set_bit_short(DDLOOKUP_DONE_LOAD, &ddlookup->flags);
#if 0
	ddtable_ddlookup_node_dirty(ddlookup);
#endif
	atomic_set_bit_short(DDLOOKUP_META_IO_PENDING, &ddlookup->flags);
	atomic_set_bit_short(DDLOOKUP_META_DATA_NEEDS_SYNC, &ddlookup->flags);
	ddtable_check_count(ddtable);
	return ddlookup;
}

int
ddtable_ddlookup_sync(struct ddtable *ddtable, struct ddtable_ddlookup_node *ddlookup, int async, int root_id, uint64_t prev_b_start)
{
	struct raw_ddtable_ddlookup_node *raw_ddlookup;
	int retval;
	uint32_t num_entries = 0;

	if (node_in_standby())
		return 0;

	raw_ddlookup = (struct raw_ddtable_ddlookup_node *)(((uint8_t *)vm_pg_address(ddlookup->metadata)) + RAW_LOOKUP_OFFSET);
	num_entries = raw_ddlookup->num_entries;
	write_raw_ddlookup(ddlookup);

	retval = ddtable_ddlookup_io(ddtable, ddlookup, QS_IO_WRITE, root_id, prev_b_start);
	if (unlikely(retval != 0)) {
		goto rollback;
	}

	if (async)
		return 0;

	wait_on_chan(ddlookup->ddlookup_wait, !atomic_test_bit_short(DDLOOKUP_META_DATA_DIRTY, &ddlookup->flags));

	if (unlikely(atomic_test_bit_short(DDLOOKUP_META_DATA_ERROR, &ddlookup->flags))) {
		goto rollback;
	}
	return 0;

rollback:
	debug_warn("Failed to sync ddlookup at %llu\n", (unsigned long long)ddlookup->b_start);
	atomic_clear_bit_short(DDLOOKUP_META_DATA_ERROR, &ddlookup->flags);
	raw_ddlookup->num_entries = num_entries;
	return -1;
}

static int
ddlookup_check_read_io(struct ddtable *ddtable, struct ddtable_ddlookup_node *ddlookup)
{
	if (!atomic_test_bit_short(DDLOOKUP_META_IO_READ_PENDING, &ddlookup->flags))
		return 0;
	node_ddlookup_lock(ddlookup);
	ddtable_ddlookup_io(ddtable, ddlookup, QS_IO_READ, -1, 0ULL);
	node_ddlookup_unlock(ddlookup);
	return 1;
}

struct ddtable_ddlookup_node *
ddtable_ddlookup_find_node(struct ddtable *ddtable, uint64_t node_block)
{
	struct ddtable_node *node;
	struct ddtable_ddlookup_node *ddlookup;
	int retval;

	node = node_get(ddtable, BLOCK_BLOCKNR(node_block));
	ddlookup = node_ddlookup(node, BLOCK_BLOCKNR(node_block));
	if (!ddlookup) {
		ddlookup = ddtable_ddlookup_node_load(ddtable, BLOCK_BLOCKNR(node_block), NULL);
		if (unlikely(!ddlookup)) {
			node_unlock(node);
			return NULL;
		}
		DD_INC(hash_remove_misses, 1);
		ddtable_ddlookup_node_get(ddlookup);
		node_insert(ddtable, node, ddlookup);
	}
	node_unlock(node);
	if (ddlookup_check_read_io(ddtable, ddlookup))
		DD_INC(find_load, 1);

	wait_on_chan_check(ddlookup->ddlookup_wait, !atomic_test_bit_short(DDLOOKUP_META_DATA_READ_DIRTY, &ddlookup->flags));

	if (atomic_test_bit_short(DDLOOKUP_META_DATA_ERROR, &ddlookup->flags)) {
		ddtable_ddlookup_node_put(ddlookup);
		return NULL;
	}

	node_ddlookup_lock(ddlookup);
	retval = ddtable_ddlookup_read(ddlookup);
	if (unlikely(retval != 0)) {
		debug_warn("node ddlookup metadata read failed\n");
		node_ddlookup_unlock(ddlookup);
		ddtable_ddlookup_node_put(ddlookup);
		return NULL;
	}

	return ddlookup;
}

void
ddtable_hash_remove_block(struct ddtable *ddtable, struct ddtable_ddlookup_node *ddlookup, uint64_t block)
{
	struct ddblock_entry *entry;
	uint64_t entry_block;
	int i;

	for (i = 0; i < ddlookup->num_entries; i++) {
		entry = ddtable_ddlookup_get_block_entry(ddlookup, i);
		entry_block = (entry->block & AMAP_BLOCK_MASK);
		if (entry_block != block) {
			debug_check(entry->block && BLOCK_BLOCKNR(entry->block) == BLOCK_BLOCKNR(block) && BLOCK_BID(entry->block) == BLOCK_BID(block));
			continue;
		}
		ddtable_ddlookup_write_barrier(ddlookup);
		entry = ddtable_ddlookup_get_block_entry(ddlookup, i);
		bzero(entry, sizeof(*entry));
		ddtable_ddlookup_node_dirty(ddtable, ddlookup);
		DD_INC(blocks_removed, 1);
		DD_DEC(hash_count, 1);
		break;
	}
}

static inline int
block_entry_valid(uint32_t index_offset, uint32_t index_blocks, uint32_t block_index_offset, uint32_t block_index_blocks)
{
	if (index_offset >= block_index_offset && index_offset < (block_index_offset + block_index_blocks))
		return 0;

	if (block_index_offset >= index_offset && block_index_offset < (index_offset + index_blocks))
		return 0;

	return 1;
}

static inline void
ddtable_clear_invalid_entries(struct ddtable *ddtable, struct ddtable_ddlookup_node *parent, struct pgdata *pgdata, struct locate_spec *locate_spec, int *insert_idx)
{
	struct ddblock_entry *entry;
	struct bintindex *index;
	struct bdevint *bint;
	uint64_t index_id;
	uint32_t index_offset;
	uint32_t index_blocks;
	uint64_t block_index_id;
	uint32_t block_index_offset;
	uint32_t block_index_blocks;
	int i, meta_shift;

	index = pgdata->index_info->index;
	bint = index->subgroup->group->bint;
	meta_shift = bint_meta_shift(bint);

	index_id = index_id_from_block(bint, BLOCK_BLOCKNR(pgdata->amap_block), &index_offset);
	index_blocks = lba_block_size(pgdata->amap_block) >> meta_shift;


	entry = ddtable_ddlookup_get_block_entry(parent, 0);
	for (i = 0; i < parent->num_entries; i++) {
		if (!entry->block) {
			if (insert_idx)
				*insert_idx = i;
			if (locate_spec)
				locate_spec->valid = 0;
			entry++;
			continue;
		}

		if (BLOCK_BID(entry->block) != bint->bid) {
			entry++;
			continue;
		}

		block_index_id = index_id_from_block(bint, BLOCK_BLOCKNR(entry->block), &block_index_offset);
		if (block_index_id != index_id) {
			entry++;
			continue;
		}

		block_index_blocks = lba_block_size(entry->block) >> meta_shift;
		if (block_entry_valid(index_offset, index_blocks, block_index_offset, block_index_blocks)) {
			entry++;
			continue;
		}

		debug_info("Invalid older hash entry %llu found while inserting %llu\n", (unsigned long long)(entry->block & AMAP_BLOCK_MASK), (unsigned long long)pgdata->amap_block);

		ddtable_ddlookup_write_barrier(parent);
		entry = ddtable_ddlookup_get_block_entry(parent, i);
		bzero(entry, sizeof(*entry));
		ddtable_ddlookup_node_dirty(ddtable, parent);
		if (insert_idx)
			*insert_idx = i;
		if (locate_spec)
			locate_spec->valid = 0;
		entry++;
	}
}

static int 
ddtable_ddlookup_insert_entry(struct ddtable *ddtable, struct pgdata *pgdata, struct ddtable_ddlookup_node *parent, struct index_info_list *index_info_list, struct locate_spec *locate_spec)
{
	int insert_idx = -1;
	int incr = 0;
	struct bdevint *bint;
#ifdef ENABLE_STATS
	uint32_t start_ticks;
#endif
	struct bintindex *index;

	DD_TSTART(start_ticks);
	index = pgdata->index_info->index;
	bint = index->subgroup->group->bint;

	ddtable_clear_invalid_entries(ddtable, parent, pgdata, locate_spec, &insert_idx);

	DD_TEND(sanity_check_ticks, start_ticks);
	if (locate_spec && locate_spec->valid) {
		insert_idx = locate_spec->insert_idx;
		incr = locate_spec->incr;
		if (locate_spec->new_entry)
			DD_INC(locate_spec_new, 1);
		else
			DD_INC(locate_spec_replace, 1);
	}
	else {
		DD_INC(locate_spec_misses, 1);
	}

	if (insert_idx < 0) {
		if (parent->num_entries == DDTABLE_LOOKUP_NODE_MAX_BLOCKS) {
			return -1;
		}
		insert_idx = parent->num_entries;
		incr = 1;
	}

	DD_TSTART(start_ticks);
	ddtable_set_node_block(ddtable, pgdata, bint, pgdata->index_info->index, parent, insert_idx, incr, index_info_list);
	DD_TEND(set_hash_ticks, start_ticks);
	return 0;
}

static void
locate_spec_free(struct locate_spec *locate_spec)
{
	if (!locate_spec->insert_ddlookup)
		return;

	ddtable_ddlookup_node_put(locate_spec->insert_ddlookup);
	locate_spec->valid = 0;
	locate_spec->insert_ddlookup = NULL;
}

void
ddtable_hash_insert(struct bdevgroup *group, struct pgdata *pgdata, struct index_info_list *index_info_list, struct ddspec_list *ddspec_list)
{
	struct ddtable *ddtable = bdev_group_ddtable(group);
	struct ddtable_ddlookup_node *child, *next, *last = NULL;
	struct index_info *index_info;
	index_t *hash = (index_t *)(pgdata->hash);
	uint32_t hashval = pgdata->hashval;
	index_t root_id;
	uint64_t next_block;
	struct ddlookup_node_list *lhead;
	struct ddtable_node *node;
	struct ddlookup_list *ddlookup_list;
	struct locate_spec lspec;
	struct ddsync_spec *sync_spec;
	int retval, error = 0, status = 0;
#ifdef ENABLE_STATS
	uint32_t start_ticks, tmp_ticks;
#endif

	DD_INC(hashes, 1);
	root_id = index_id_from_hash(ddtable, hashval);
	ddlookup_list = ddlookup_list_get(ddtable, root_id);
	lhead = &ddlookup_list->lhead;

	ddlookup_list_lock(ddlookup_list);
	child = SLIST_FIRST(lhead);
	ddtable_ddlookup_node_get(child);
	ddlookup_list_unlock(ddlookup_list);

	bzero(&lspec, sizeof(lspec));
	ddlookup_list_insert_lock(ddlookup_list);
	DD_TSTART(tmp_ticks);
	while (child) {

		wait_on_chan_check(child->ddlookup_wait, !atomic_test_bit_short(DDLOOKUP_META_DATA_READ_DIRTY, &child->flags));

		node_ddlookup_lock(child);
		retval = ddtable_ddlookup_read(child);
		if (unlikely(retval != 0)) {
			debug_warn("node ddlookup metadata read failed\n");
			node_ddlookup_unlock(child);
			ddtable_ddlookup_node_put(child);
			ddlookup_list_insert_unlock(ddlookup_list);
			return;
		}

		status = 0;
		ddtable_ddlookup_find_entry(group, ddtable, pgdata, child, hash, &error, &status, index_info_list, &lspec, 1, NULL);
		node_ddlookup_unlock(child);
		if (error) {
			locate_spec_free(&lspec);
			ddtable_ddlookup_node_put(child);
			ddlookup_list_insert_unlock(ddlookup_list);
			return;
		}

		next_block = ddlookup_get_next_block(child);
		if (!next_block) {
			ddlookup_list_lock(ddlookup_list);
			next = SLIST_NEXT(child, p_list);
			if (next)
				ddtable_ddlookup_node_get(next);
			ddlookup_list_unlock(ddlookup_list);
			if (!next) {
				last = child;
				break;
			}
			if (ddlookup_check_read_io(ddtable, next))
				DD_INC(insert_load, 1);
			ddtable_tail_ddlookup(ddtable, next);
			ddtable_ddlookup_node_put(child);
			child = next;
			continue;
		}

		ddlookup_list_lock(ddlookup_list);
		next = SLIST_NEXT(child, p_list);
		if (next)
			ddtable_ddlookup_node_get(next);
		ddlookup_list_unlock(ddlookup_list);
		if (!next || next->b_start != BLOCK_BLOCKNR(next_block)) {
			if (next)
				ddtable_ddlookup_node_put(next);

			next = ddtable_ddlookup_load_next(ddtable, child, ddlookup_list, next_block, &error);
			if (unlikely(error != 0 || !next)) {
				ddtable_ddlookup_node_put(child);
				if (next)
					ddtable_ddlookup_node_put(next);
				ddlookup_list_insert_unlock(ddlookup_list);
				return;
			}
		}
		if (ddlookup_check_read_io(ddtable, next))
			DD_INC(insert_load, 1);
		ddtable_tail_ddlookup(ddtable, next);
		ddtable_ddlookup_node_put(child);
		child = next;
	}
	DD_TEND(load_node_ticks, tmp_ticks);

	if (ddspec_list && ddtable_global_can_add_ddlookup() && lspec.valid && !lspec.new_entry) {
		locate_spec_free(&lspec);
	}

	if (lspec.valid) {
		child = lspec.insert_ddlookup;
		node_ddlookup_lock(child);
		DD_TSTART(start_ticks);
		ddtable_ddlookup_insert_entry(ddtable, pgdata, child, index_info_list, &lspec);
		DD_TEND(insert_entry_ticks, start_ticks);
		node_ddlookup_unlock(child);
		locate_spec_free(&lspec);
		debug_check(!last);
		ddtable_ddlookup_node_put(last);
		ddlookup_list_insert_unlock(ddlookup_list);
		return;
	}

	locate_spec_free(&lspec);
	if (!ddspec_list || !ddtable_global_can_add_ddlookup()) {
		debug_check(!last);
		ddtable_ddlookup_node_put(last);
		ddlookup_list_insert_unlock(ddlookup_list);
		return;
	}

	child = ddtable_ddlookup_node_new(ddtable, ddlookup_list, &index_info);
	if (unlikely(!child)) {
		debug_check(!last);
		ddtable_ddlookup_node_put(last);
		ddlookup_list_insert_unlock(ddlookup_list);
		return;
	}

	DD_TSTART(start_ticks);
	ddtable_ddlookup_insert_entry(ddtable, pgdata, child, index_info_list, NULL);
	DD_TEND(insert_entry_ticks, start_ticks);

	ddtable_ddlookup_node_get(child);
	sync_spec = zalloc(sizeof(struct ddsync_spec), M_DDTABLE, Q_WAITOK);
	debug_check(!last);
	node_ddlookup_lock(last);
	atomic_set_bit_short(DDLOOKUP_META_DATA_BUSY, &last->flags);
	node_ddlookup_unlock(last);
	atomic_set_bit_short(DDLOOKUP_META_DATA_BUSY, &child->flags);
	sync_spec->last = last;
	sync_spec->child = child;
	sync_spec->root_id = root_id;
	sync_spec->index_info = index_info;
	TAILQ_INSERT_TAIL(index_info_list, index_info, i_list);
	STAILQ_INSERT_TAIL(ddspec_list, sync_spec, d_list);

	node = node_get(ddtable, child->b_start);
	ddlookup_list_lock(ddlookup_list);
	SLIST_INSERT_AFTER(last, child, p_list);
	ddlookup_list_unlock(ddlookup_list);
	node_insert(ddtable, node, child);
	node_unlock(node);
	DD_INC(peer_count, 1);
	ddlookup_list_insert_unlock(ddlookup_list);
	return;
}
