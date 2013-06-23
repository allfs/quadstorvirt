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

#ifndef QS_DDTHREAD_H_
#define QS_DDTHREAD_H_

#include "coredefs.h"
#include "fastlog.h"
#include "gdevq.h"

struct ddthread {
	kproc_t *task;
	SLIST_ENTRY(ddthread) d_list;
	int exit_flags;
	int id;
};

//#define MAX_DDTHREADS		(MAX_GDEVQ_THREADS / 3)
#define MAX_DDTHREADS		MAX_GDEVQ_THREADS

enum {
	DDTHREAD_RUN	= 0x01,
	DDTHREAD_EXIT	= 0x02,
};

struct ddwork {
	uint64_t transaction_id;
	uint64_t newmeta_transaction_id;
	struct pgdata **pglist;
	uint16_t pglist_cnt;
	int log_reserved;
	struct index_info_list index_info_list;
	struct index_info_list meta_index_info_list;
	STAILQ_ENTRY(ddwork) w_list;
	struct amap_sync_list amap_sync_list;
	struct index_sync_list index_sync_list;
	struct log_info_list log_list;
	struct tdisk *tdisk;
};

STAILQ_HEAD(ddwork_list, ddwork);
void ddthread_insert(struct ddwork *ddwork);
void ddthread_wait_for_empty(void);
int init_ddthreads(void);
void exit_ddthreads(void);
int handle_amap_sync(struct amap_sync_list *amap_sync_list);
int handle_amap_sync_wait(struct amap_sync_list *amap_sync_list);
void amap_check_sync_list(struct amap *amap, struct amap_sync_list *amap_sync_list, struct pgdata *pgdata, uint64_t write_id);

void process_delete_block(struct ddtable *ddtable, uint64_t old_block, struct index_info_list *index_info_list, struct index_sync_list *index_sync_list, struct index_info_list *search_index_info_list, int type);

#endif
