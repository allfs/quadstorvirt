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

#ifndef QS_RCACHE_H_
#define QS_RCACHE_H_

#include "coredefs.h"

struct rcache;
struct rcache_entry_list;
struct rcache_entry {
	pagestruct_t *page;
	uint64_t block;
	uint32_t hashval;
	TAILQ_ENTRY(rcache_entry) r_list;
	TAILQ_ENTRY(rcache_entry) g_list;
};
TAILQ_HEAD(rcache_entry_list, rcache_entry);

struct rcache {
	struct rcache_entry_list *entry_list;
	mtx_t *rcache_lock;
};

int rcache_locate(struct pgdata *pgdata, int copy);
void rcache_insert(struct pgdata *pgdata);
void rcache_remove(uint64_t amap_block);

void rcache_exit(void);
int rcache_init(void);
void rcache_add_to_list(struct rcache_entry_list *lhead, struct pgdata *pgdata);
void rcache_list_insert(struct rcache_entry_list *lhead);
void rcache_list_free(struct rcache_entry_list *lhead);
void rcache_remove_bdev(uint32_t bid);
void rcache_update_count(void);
void calc_rcache_bits(void);
void rcache_reset(void);

#define RCACHE_CACHED_MAX	(128 * 1024)
#endif
