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

#ifndef IO_H_
#define IO_H_

#ifdef FREEBSD 
#include "corebsd.h"
#else
#include "coreext.h"
#endif
#include "rawdefs.h"
#include <exportdefs.h>

enum {
	DDTABLE_SYNC_ENABLED,
	DDTABLE_IN_SYNC,
	DDTABLE_SYNC_START,
	DDTABLE_FREE_START,
	DDTABLE_IN_SYNC_THR,
	DDTABLE_SYNC_EXIT,
	DDTABLE_FREE_EXIT,
	DDTABLE_LOAD_EXIT,
};

enum {
	BINT_IO_PENDING,
	BINT_DATA_DIRTY,
	BINT_SYNC_ENABLED,
	BINT_LOAD_DONE,
	BINT_IN_SYNC_DATA,
	BINT_ALLOC_INSERTED,
	BINT_FREE_START,
	BINT_LOAD_START,
	BINT_FREE_EXIT,
	BINT_SYNC_EXIT,
	BINT_LOAD_EXIT,
};

enum {
	LOG_META_IO_READ_PENDING,
	LOG_META_IO_PENDING,
	LOG_META_DATA_DIRTY,
	LOG_META_DATA_READ_DIRTY,
	LOG_META_DATA_CLONED,
	LOG_META_DATA_ERROR,
};

enum {
	META_IO_PENDING,
	META_DATA_DIRTY,
	META_DATA_ERROR,
	META_IO_READ_PENDING,
	META_DATA_READ_DIRTY,
	META_DATA_CLONED,
	META_DATA_ASYNC,
	META_LOAD_DONE,
	META_CSUM_CHECK_DONE,
	META_WRITE_PENDING,
	META_DATA_UNMAP,
	META_INDEX_UNMARKED_FULL,
};

enum {
	TCACHE_FLAG_UNUSED,
	TCACHE_LOG_WRITE,
	TCACHE_IO_ERROR,
	TCACHE_COMP_BIOT,
};

#define DEBUG_CHECK_BIO_ERR(bio,err) do {	\
	if (unlikely(err))			\
	{					\
		debug_warn("bio err");		\
	}					\
} while (0)

#define EPOCH_2011	1293840000U

static inline uint64_t
align_size(uint64_t size, int boundary)
{
	uint64_t adjust;

	adjust = (size + (boundary - 1)) & -(boundary);
	return (adjust);
}

static inline uint16_t
net_calc_csum16(uint8_t *buf, int len)
{
        int i;
        uint16_t csum = 0;

        for (i = 0; i < len ; i+=sizeof(uint16_t))
        {
                uint16_t val = *((uint16_t *)(buf+i));
                csum += val;
        }
        return ~(csum);
}

static inline uint16_t
calc_csum16(uint8_t *buf, int len)
{
        int i;
        uint64_t csum = 0;

        for (i = 0; i < len ; i+=8)
        {
                uint64_t val = *((uint64_t *)(buf+i));
                csum += val;
        }
        return ~(csum);
}

static inline uint64_t
calc_csum(uint8_t *buf, int len)
{
        int i;
        uint64_t csum = 0;

        for (i = 0; i < len ; i+=8)
        {
                uint64_t val = *((uint64_t *)(buf+i));
                csum ^= val;
        }
        return (csum);
}

extern uma_t *node_sync_post_cache;
extern uma_t *node_sock_cache;
extern uma_t *node_comm_cache;
extern uma_t *node_msg_cache;
extern uma_t *ddqueue_cache;
extern uma_t *tcache_cache;
extern uma_t *ctio_cache;
extern uma_t *pgdata_cache;
extern uma_t *group_cache;
extern uma_t *index_lookup_cache;
extern uma_t *subgroup_cache;
extern uma_t *index_cache;
extern uma_t *subgroup_index_cache;
extern uma_t *ddtable_ddlookup_node_cache;
extern uma_t *aio_meta_cache;
extern uma_t *amap_cache;
extern uma_t *lba_write_cache;
extern uma_t *amap_index_cache;
extern uma_t *amap_sync_cache;
extern uma_t *amap_table_cache;
extern uma_t *amap_table_group_cache;
extern uma_t *ddlookup_list_cache;
extern uma_t *ddnode_cache;
extern uma_t *node_group_cache;
extern uma_t *index_info_cache;
extern uma_t *index_sync_cache;
extern uma_t *log_cache;
extern uma_t *log_entry_cache;
extern uma_t *log_group_cache;
extern uma_t *rcache_entry_cache;
extern uma_t *ddwork_cache;
extern uma_t *hash_cache;
extern uma_t *gdevq_cache;
extern uma_t *ddthread_cache;
extern uma_t *fourk_cache;
extern uma_t *eightk_cache;
extern uma_t *tdisk_cache;
#ifdef FREEBSD
extern uma_t *biot_cache;
extern uma_t *biot_page_cache;
#endif
extern mtx_t *glbl_lock;
extern sx_t *clone_info_lock;
extern sx_t *rep_comm_lock;

struct index_info;
struct ddblock_info;
struct log_page;
struct amap_table;
struct amap;

STAILQ_HEAD(pgdata_wlist, pgdata);
struct pgdata {
	pagestruct_t *page;
	uint16_t pg_len;
	uint16_t pg_offset;
	uint16_t write_size;
	int16_t log_offset;
	int flags;
	uint32_t hashval;
	pagestruct_t *verify_page;
	uint8_t hash[32];
	struct amap_table *amap_table;
	struct amap *amap;
	struct pgdata *comp_pgdata;
	uint64_t amap_block;
	uint64_t old_amap_block;
	uint64_t lba;
	uint64_t amap_write_id;
	STAILQ_ENTRY(pgdata) t_list;
	STAILQ_ENTRY(pgdata) a_list;
	STAILQ_ENTRY(pgdata) w_list;
	struct log_page *log_page;
	struct index_info *index_info;
	struct ddblock_info *ddblock_info;
	wait_compl_t *completion;
};

#define pgdata_page_address(pgdta)	vm_pg_address((pgdta)->page)

static inline void
pgdata_free_page(struct pgdata *pgdata)
{
	if (pgdata->page) {
		vm_pg_free(pgdata->page);
		pgdata->page = NULL;
		ALLOC_COUNTER_INC(pgdata_pages_freed);
	}
}

static inline int
pgdata_alloc_page(struct pgdata *pgdata, allocflags_t flags)
{
	if (pgdata->page)
		return 0;

	pgdata->page = vm_pg_alloc(flags);
	if (unlikely(!pgdata->page))
		return -1;
	ALLOC_COUNTER_INC(pgdata_pages_alloced);
	return 0;
}

static inline void
pgdata_copy_page_ref(struct pgdata *dest, pagestruct_t *page)
{
	memcpy(pgdata_page_address(dest), vm_pg_address(page), LBA_SIZE);
}

static inline void
pgdata_add_page_ref(struct pgdata *dest, pagestruct_t *page)
{
	vm_pg_ref(page);
	dest->page = page;
	ALLOC_COUNTER_INC(pgdata_pages_refed);
}

static inline void
pgdata_copy_ref(struct pgdata *dest, struct pgdata *src)
{
	memcpy(pgdata_page_address(dest), pgdata_page_address(src), LBA_SIZE);
}

static inline void
pgdata_zero_page(struct pgdata *dest)
{
	bzero(pgdata_page_address(dest), LBA_SIZE);
}

static inline void
pgdata_add_ref(struct pgdata *dest, struct pgdata *src)
{
	pgdata_add_page_ref(dest, src->page);
}

static inline void
pgdata_move(struct pgdata *dest, struct pgdata *src)
{
	dest->page = src->page;
}

static inline void
pgdata_free(struct pgdata *pgdata)
{
	pgdata_free_page(pgdata);
	debug_check(!pgdata->completion);
	wait_completion_free(pgdata->completion);
	uma_zfree(pgdata_cache, pgdata);
}

static inline void
pgdata_free_norefs(struct pgdata *pgdata)
{
	debug_check(!pgdata->completion);
	wait_completion_free(pgdata->completion);
	uma_zfree(pgdata_cache, pgdata);
}

static inline void
pglist_free(struct pgdata **pglist, int pglist_cnt)
{
	int i;

	for (i = 0; i < pglist_cnt; i++)
		pgdata_free(pglist[i]);
	free(pglist, M_PGLIST);
}

static inline void
pglist_free_norefs(struct pgdata **pglist, int pglist_cnt)
{
	int i;

	for (i = 0; i < pglist_cnt; i++)
		pgdata_free_norefs(pglist[i]);
	free(pglist, M_PGLIST);
}

#include "../export/qsio_ccb.h"
int pgdata_allocate_data(struct qsio_scsiio *ctio, uint32_t num_blocks, allocflags_t flags);

static inline struct pgdata **
pgdata_allocate_pglist(int nsegs, allocflags_t flags)
{
	struct pgdata **pglist;

	pglist = zalloc(sizeof(struct pgdata *) * nsegs, M_PGLIST, flags);
	if (unlikely(!pglist)) {
		debug_warn("Allocation failure nsegs %d, flags %u\n", nsegs, flags);
		return NULL;
	}

	return pglist;
}

static inline struct pgdata **
pgdata_allocate(uint32_t num_blocks, allocflags_t flags)
{
	struct pgdata **pglist, *pgtmp;
	int i, retval;
	
	pglist = pgdata_allocate_pglist(num_blocks, flags);
	if (unlikely(!pglist)) {
		debug_warn("allocating pglist for count %d failed\n", num_blocks);
		return NULL;
	}

	for (i = 0; i < num_blocks; i++) {
		pgtmp = __uma_zalloc(pgdata_cache, flags | Q_ZERO, sizeof(*pgtmp));
		if (unlikely(!pgtmp)) {
			pglist_free(pglist, i);
			return NULL;
		}
		pgtmp->completion = wait_completion_alloc("pgdata compl"); 

		pglist[i] = pgtmp;

		pgtmp->pg_len = LBA_SIZE;
		retval = pgdata_alloc_page(pgtmp, 0);
		if (unlikely(retval != 0)) {
			debug_warn("allocating for pgdata page failed\n");
			pglist_free(pglist, i+1);
			return NULL;
		}
	}
	return pglist;
}

static inline struct pgdata **
pgdata_allocate_nopage(uint32_t num_blocks, allocflags_t flags)
{
	int i;
	struct pgdata **pglist, *pgtmp;

	pglist = pgdata_allocate_pglist(num_blocks, flags);
	if (unlikely(!pglist)) {
		debug_warn("allocating pglist for count %d failed\n", num_blocks);
		return NULL;
	}

	for (i = 0; i < num_blocks; i++) {

		pgtmp = __uma_zalloc(pgdata_cache, flags | Q_ZERO, sizeof(*pgtmp));
		if (unlikely(!pgtmp)) {
			pglist_free(pglist, i);
			return NULL;
		}
		pgtmp->completion = wait_completion_alloc("pgdata compl"); 
		pglist[i] = pgtmp;
		pgtmp->pg_len = LBA_SIZE;
	}
	return pglist;
}

void ctio_free_all(struct qsio_scsiio *ctio);

static inline void
ctio_free_data(struct qsio_scsiio *ctio)
{
	if (!ctio->dxfer_len)
		return;

	if (ctio->pglist_cnt)
	{
		if (!ctio_norefs(ctio))
			pglist_free((void *)ctio->data_ptr, ctio->pglist_cnt);
		else
			pglist_free_norefs((void *)ctio->data_ptr, ctio->pglist_cnt);
	}
	else
	{
		free(ctio->data_ptr, M_CTIODATA);
	}
	ctio->data_ptr = NULL;
	ctio->dxfer_len = 0;
	ctio->pglist_cnt = 0;
}

static inline struct qsio_scsiio *
ctio_new(allocflags_t flags)
{
	return __uma_zalloc(ctio_cache, flags | Q_ZERO, sizeof(struct qsio_scsiio)); 
}

void calc_sector_bits(uint32_t sector_size, uint32_t *sector_shift);

enum {
	COMP_ALG_LZF	= 0x00,
	COMP_ALG_LZ4	= 0x01,
};

#define COMP_ALG_SHIFT	14
#define COMP_ALG_MASK	((1 << COMP_ALG_SHIFT) - 1)

#define SET_COMP_SIZE(ptr, csize, alg)	(*((uint16_t *)(ptr)) = (csize | (alg << COMP_ALG_SHIFT)))

int qs_deflate_block(struct pgdata *pgdata, struct pgdata *comp_pgdata, uint32_t *comp_size, void *wrkmem, int algo);
int qs_inflate_block(pagestruct_t *comp_page, int comp_pglen, pagestruct_t *uncomp_page);

/* timeouts */
extern int stale_initiator_timeout;
extern int mirror_recv_timeout;
extern int mirror_send_timeout;
extern int mirror_sync_timeout;
extern int mirror_sync_recv_timeout;
extern int mirror_sync_send_timeout;
extern int client_send_timeout;
extern int controller_recv_timeout;
extern int node_sync_timeout;
extern int ha_check_timeout;
extern int ha_ping_timeout;
extern atomic_t kern_inited;
extern struct node_config recv_config;

#define SET_NODE_TIMEOUT(ndcfg, vl, vlmn, vlmx)				\
do {									\
	if (ndcfg->vl && ndcfg->vl >= vlmn && ndcfg->vl <= vlmx) {	\
		vl = (ndcfg->vl * 1000);				\
	}								\
} while(0);

static inline uint32_t
get_elapsed(uint32_t timestamp)
{
	uint32_t cur_ticks = ticks;

	if (cur_ticks >= timestamp)
		return (cur_ticks - timestamp);
	else {
		uint32_t diff = (0xFFFFFFFF - timestamp);
		return (diff + cur_ticks);
	}
}

#define wait_on_chan_check(chn, condition)			\
do {								\
	if (!(condition))					\
		wait_on_chan(chn, condition);			\
} while (0)

#define wait_on_chan_interruptible_check(chn, condition)	\
do {								\
	if (!(condition))					\
		wait_on_chan_interruptible(chn, condition);	\
} while (0)

enum {
	ERR_CODE_GENERIC = -1,
	ERR_CODE_NOSPACE = -2,
};

#define debug_warn_notify(fmt,args...)									\
do {													\
	struct usr_notify msg;										\
	bzero(&msg, sizeof(msg));									\
	snprintf(msg.notify_msg, sizeof(msg.notify_msg) -1 , fmt, ##args);				\
	debug_warn(fmt,##args);										\
	node_usr_notify_msg(USR_NOTIFY_WARN, 0, &msg);							\
} while (0)

#define debug_error_notify(fmt,args...)									\
do {													\
	struct usr_notify msg;										\
	bzero(&msg, sizeof(msg));									\
	snprintf(msg.notify_msg, sizeof(msg.notify_msg) -1 , fmt, ##args);				\
	debug_warn(fmt,##args);										\
	node_usr_notify_msg(USR_NOTIFY_ERR, 0, &msg);							\
} while (0)

#define debug_info_notify(fmt,args...)									\
do {													\
	struct usr_notify msg;										\
	bzero(&msg, sizeof(msg));									\
	snprintf(msg.notify_msg, sizeof(msg.notify_msg) -1 , "%s:%d " fmt, __FUNCTION__, __LINE__, ##args);	\
	node_usr_notify_msg(USR_NOTIFY_INFO, 0, &msg);							\
} while (0)

#endif /* IO_H_ */
