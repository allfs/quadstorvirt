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

#include "coredefs.h"
#include "bdevmgr.h"
#include "vdevdefs.h"
#include "gdevq.h"
#include "ddthread.h"
#include "fastlog.h"
#include "log_group.h"
#include "rcache.h"
#include <exportdefs.h>
#include "cluster.h"
#include "node_sock.h"
#include "node_sync.h"
#include "node_ha.h"
#include "bdevgroup.h"
#include "../common/cluster_common.h" 
#include "node_mirror.h"
#include "tdisk.h"
#include "lz4.h"
#include "copymgr.h"

struct qs_kern_cbs kcbs;
uint64_t qs_availmem;

int stale_initiator_timeout = STALE_INITIATOR_TIMEOUT;
int mirror_recv_timeout = MIRROR_RECV_TIMEOUT;
int mirror_send_timeout = MIRROR_SEND_TIMEOUT;
int mirror_sync_timeout = MIRROR_SYNC_TIMEOUT;
int mirror_sync_recv_timeout = MIRROR_SYNC_RECV_TIMEOUT;
int mirror_sync_send_timeout = MIRROR_SYNC_SEND_TIMEOUT;
int client_send_timeout = CLIENT_SEND_TIMEOUT;
int controller_recv_timeout = CONTROLLER_RECV_TIMEOUT;
int node_sync_timeout = NODE_SYNC_TIMEOUT;
int ha_check_timeout = HA_CHECK_TIMEOUT;
int ha_ping_timeout = HA_PING_TIMEOUT;

int
qs_deflate_block(struct pgdata *pgdata, struct pgdata *comp_pgdata, uint32_t *comp_size, void *wrkmem, int algo)
{
	uint8_t *out_buf, *in_buf;
	int retval;

	out_buf = (uint8_t *)pgdata_page_address(comp_pgdata);
	in_buf = (uint8_t *)pgdata_page_address(pgdata);

	/* 2 bytes for comp size information */
	switch (algo) {
	case COMP_ALG_LZF:
		retval = lzf_compress(in_buf, LBA_SIZE, out_buf+sizeof(uint16_t), LBA_SIZE - 1026, wrkmem);
		break;
	case COMP_ALG_LZ4:
		retval = LZ4_compress_limitedOutput(wrkmem, in_buf, out_buf+sizeof(uint16_t), LBA_SIZE, LBA_SIZE - 1026);
		break;
	default:
		debug_check(1);
		retval = 0;
	}

	if (!retval) {
		return -1;
	}

	SET_COMP_SIZE(out_buf, retval, algo);
	*comp_size = (retval + sizeof(uint16_t));
	return 0;
}

int
qs_inflate_block(pagestruct_t *comp_page, int comp_pglen, pagestruct_t *uncomp_page)
{
	uint8_t *out_buf, *in_buf;
	int retval;
	uint16_t stored_comp_size, comp_size, algo;

	out_buf = (uint8_t *)vm_pg_address(uncomp_page);
	in_buf = (uint8_t *)vm_pg_address(comp_page);

	stored_comp_size = *((uint16_t *)(in_buf));
	comp_size = stored_comp_size & COMP_ALG_MASK;
	algo = stored_comp_size >> COMP_ALG_SHIFT;

	if (comp_size > comp_pglen)
		return -1;

	switch (algo) {
	case COMP_ALG_LZF:
		retval = lzf_decompress(in_buf+sizeof(uint16_t), comp_size, out_buf, LBA_SIZE);
		break;
	case COMP_ALG_LZ4:
		retval = LZ4_uncompress_unknownOutputSize(in_buf+sizeof(uint16_t), out_buf, comp_size, LBA_SIZE);
		break;
	default:
		debug_check(1);
		retval = 0;
	}
	if (retval != LBA_SIZE)
		return -1;
	return 0;
}

void
calc_sector_bits(uint32_t sector_size, uint32_t *sector_shift)
{
	uint32_t shift;

	shift = 0;
	while ((sector_size >>= 1))
	{
		shift++;
	}
	*sector_shift = shift;
	return;
}

uma_t *write_bmap_cache;
uma_t *group_write_bmap_cache;
uma_t *node_sync_post_cache;
uma_t *node_sock_cache;
uma_t *node_comm_cache;
uma_t *node_msg_cache;
uma_t *ddqueue_cache;
uma_t *tcache_cache;
uma_t *ctio_cache;
uma_t *pgdata_cache;
uma_t *group_cache;
uma_t *index_lookup_cache;
uma_t *subgroup_cache;
uma_t *index_cache;
uma_t *subgroup_index_cache;
uma_t *ddtable_ddlookup_node_cache;
uma_t *aio_meta_cache;
uma_t *istate_cache;
uma_t *amap_cache;
uma_t *lba_write_cache;
uma_t *amap_index_cache;
uma_t *amap_sync_cache;
uma_t *amap_table_cache;
uma_t *amap_table_group_cache;
uma_t *ddlookup_list_cache;
uma_t *ddnode_cache;
uma_t *node_group_cache;
uma_t *index_info_cache;
uma_t *index_sync_cache;
uma_t *log_cache;
uma_t *log_entry_cache;
uma_t *log_group_cache;
uma_t *rcache_entry_cache;
uma_t *ddwork_cache;
uma_t *hash_cache;
uma_t *gdevq_cache;
uma_t *ddthread_cache;
uma_t *fourk_cache;
uma_t *eightk_cache;
uma_t *tdisk_cache;
uma_t *chan_cache;
uma_t *compl_cache;
#ifdef FREEBSD
uma_t *biot_cache;
uma_t *biot_page_cache;
uma_t *mtx_cache;
uma_t *sx_cache;
#endif

#ifdef ENABLE_STATS
#define PRINT_STAT(x,y)	printf(x" %llu \n", (unsigned long long)y); pause("psg", 10);
#else
#define PRINT_STAT(x,y) do {} while(0)
#endif

struct mdaemon_info mdaemon_info;
atomic_t kern_inited;
atomic_t itf_enabled;

struct interface_list cbs_list;
sx_t *cbs_lock;
sx_t *gchain_lock;
sx_t *clone_info_lock;
sx_t *rep_comm_lock;
sx_t *sync_lock;
sx_t *rod_lock;
mtx_t *glob_stats_lock;
mtx_t *tdisk_lookup_lock;
mtx_t *glbl_lock;
wait_chan_t *gpglist_wait;
wait_chan_t *ha_wait;

struct tdisk *tdisks[TL_MAX_DEVICES];

struct pgdata pgzero;
uint8_t *pgzero_addr;

static void
mdaemon_set_info(struct mdaemon_info *info)
{
	memcpy(&mdaemon_info, info, sizeof(*info));
}

static void
exit_caches(void)
{
	debug_info("group_write_bmap_cache_free\n");
	if (group_write_bmap_cache)
		__uma_zdestroy("qs_group_write_bmap", group_write_bmap_cache);

	debug_info("write_bmap_cache_free\n");
	if (write_bmap_cache)
		__uma_zdestroy("qs_write_bmap", write_bmap_cache);

	debug_info("node_msg_cache_free\n");
	if (node_msg_cache)
		__uma_zdestroy("qs_node_msg", node_msg_cache);

	debug_info("node_sync_post_cache_free\n");
	if (node_sync_post_cache)
		__uma_zdestroy("qs_node_sync_post", node_sync_post_cache);

	debug_info("node_sock_cache_free\n");
	if (node_sock_cache)
		__uma_zdestroy("qs_node_sock", node_sock_cache);

	debug_info("node_comm_cache_free\n");
	if (node_comm_cache)
		__uma_zdestroy("qs_node_comm", node_comm_cache);

	debug_info("tcache_cache_free\n");
	if (tcache_cache)
		__uma_zdestroy("qs_tcache", tcache_cache);

	debug_info("ddqueue_cache_free\n");
	if (ddqueue_cache)
		__uma_zdestroy("qs_ddqueue", ddqueue_cache);

	debug_info("ctio_cache_free\n");
	if (ctio_cache)
		__uma_zdestroy("qs_ctio", ctio_cache);

	debug_info("pgdata_cache_free\n");
	if (pgdata_cache)
		__uma_zdestroy("qs_pgdata", pgdata_cache);

	debug_info("index_info_cache_free\n");
	if (index_info_cache)
		__uma_zdestroy("qs_index_info", index_info_cache);

	debug_info("index_sync_cache_free\n");
	if (index_sync_cache)
		__uma_zdestroy("qs_index_sync", index_sync_cache);

	debug_info("log_cache_free\n");
	if (log_cache)
		__uma_zdestroy("qs_log", log_cache);

	debug_info("hash_cache_free\n");
	if (hash_cache)
		__uma_zdestroy("qs_hash", hash_cache);

	debug_info("gdevq_cache_free\n");
	if (gdevq_cache)
		__uma_zdestroy("qs_gdevq", gdevq_cache);

	debug_info("ddthread_cache_free\n");
	if (ddthread_cache)
		__uma_zdestroy("qs_ddthread", ddthread_cache);

	debug_info("tdisk_cache_free\n");
	if (tdisk_cache)
		__uma_zdestroy("qs_tdisk", tdisk_cache);

	debug_info("4k_cache_free\n");
	if (fourk_cache)
		__uma_zdestroy("qs_4k", fourk_cache);

	debug_info("8k_cache_free\n");
	if (eightk_cache)
		__uma_zdestroy("qs_8k", eightk_cache);

	debug_info("log_entry_cache_free\n");
	if (log_entry_cache)
		__uma_zdestroy("qs_log_entry", log_entry_cache);

	debug_info("log_group_cache_free\n");
	if (log_group_cache)
		__uma_zdestroy("qs_log_group", log_group_cache);

	debug_info("rcache_entry_cache_free\n");
	if (rcache_entry_cache)
		__uma_zdestroy("qs_rcache_entry", rcache_entry_cache);

	debug_info("ddwork_cache_free\n");
	if (ddwork_cache)
		__uma_zdestroy("qs_ddwork", ddwork_cache);

	debug_info("subgroup_cache_free\n");
	if (subgroup_cache)
		__uma_zdestroy("qs_subgroup", subgroup_cache);

	debug_info("group_cache_free\n");
	if (group_cache)
		__uma_zdestroy("qs_group", group_cache);

	debug_info("index_lookup_cache_free\n");
	if (index_lookup_cache)
		__uma_zdestroy("qs_index_lookup", index_lookup_cache);

	debug_info("index_cache_free\n");
	if (index_cache)
		__uma_zdestroy("qs_index", index_cache);

	debug_info("index_cache_free\n");
	if (subgroup_index_cache)
		__uma_zdestroy("qs_subgroup_index", subgroup_index_cache);

	debug_info("ddtable_ddlookup_node_cache_free\n");
	if (ddtable_ddlookup_node_cache)
		__uma_zdestroy("qs_ddtable_ddlookup_node", ddtable_ddlookup_node_cache);

	debug_info("ddlookup_list_cache_free\n");
	if (ddlookup_list_cache)
		__uma_zdestroy("qs_ddlookup_list", ddlookup_list_cache);

	debug_info("ddnode_cache_free\n");
	if (ddnode_cache)
		__uma_zdestroy("qs_ddnode", ddnode_cache);

	debug_info("node_group_cache_free\n");
	if (node_group_cache)
		__uma_zdestroy("qs_node_group", node_group_cache);

	debug_info("amap_table_cache_free\n");
	if (amap_table_cache)
		__uma_zdestroy("qs_amap_table", amap_table_cache);

	debug_info("amap_table_group_cache_free\n");
	if (amap_table_group_cache)
		__uma_zdestroy("qs_amap_table_group", amap_table_group_cache);

	debug_info("lba_write_cache_free\n");
	if (lba_write_cache)
		__uma_zdestroy("qs_lba_write", lba_write_cache);

	debug_info("aio_meta_cache_free\n");
	if (aio_meta_cache)
		__uma_zdestroy("qs_aio_meta", aio_meta_cache);

	debug_info("istate_cache_free\n");
	if (istate_cache)
		__uma_zdestroy("qs_istate", istate_cache);

	debug_info("amap_cache_free\n");
	if (amap_cache)
		__uma_zdestroy("qs_amap", amap_cache);

	debug_info("amap_index_cache_free\n");
	if (amap_index_cache)
		__uma_zdestroy("qs_amap_index", amap_index_cache);

	debug_info("amap_sync_cache_free\n");
	if (amap_sync_cache)
		__uma_zdestroy("qs_amap_sync", amap_sync_cache);

	debug_info("chan_cache_free\n");
	if (chan_cache)
		__uma_zdestroy("qs_wait_chan", chan_cache);

	debug_info("compl_cache_free\n");
	if (compl_cache)
		__uma_zdestroy("qs_wait_compl", compl_cache);

#ifdef FREEBSD
	debug_info("biot_cache_free\n");
	if (biot_cache)
		uma_zdestroy(biot_cache);

	debug_info("biot_page_cache_free\n");
	if (biot_page_cache)
		uma_zdestroy(biot_page_cache);

	debug_info("mtx_cache_free\n");
	if (mtx_cache)
		uma_zdestroy(mtx_cache);

	debug_info("sx_cache_free\n");
	if (sx_cache)
		uma_zdestroy(sx_cache);
#endif
}

#ifdef FREEBSD 
#define CREATE_CACHE(vr,nm,s)				\
do {							\
	vr = uma_zcreate(nm,s, NULL, NULL, NULL, NULL, 0, 0);	\
} while(0);
#else
#define CREATE_CACHE(vr,nm,s)				\
do {							\
	vr = uma_zcreate(nm,s);			\
} while(0);
#endif

static int
init_caches(void)
{
	CREATE_CACHE(group_write_bmap_cache, "qs_group_write_bmap", sizeof(struct group_write_bmap));
	if (!group_write_bmap_cache) {
		debug_warn("Cannot create group_write_bmap cache\n");
		return -1;
	}

	CREATE_CACHE(write_bmap_cache, "qs_write_bmap", sizeof(struct write_bmap));
	if (!write_bmap_cache) {
		debug_warn("Cannot create write_bmap cache\n");
		return -1;
	}

	CREATE_CACHE(node_msg_cache, "qs_node_msg", sizeof(struct node_msg));
	if (!node_msg_cache) {
		debug_warn("Cannot create node_msg cache\n");
		return -1;
	}

	CREATE_CACHE(node_sync_post_cache, "qs_node_sync_post", sizeof(struct node_sync_post));
	if (!node_sync_post_cache) {
		debug_warn("Cannot create node_sync_post cache\n");
		return -1;
	}

	CREATE_CACHE(node_sock_cache, "qs_node_sock", sizeof(struct node_sock));
	if (!node_sock_cache) {
		debug_warn("Cannot create node_sock cache\n");
		return -1;
	}

	CREATE_CACHE(node_comm_cache, "qs_node_comm", sizeof(struct node_comm));
	if (!node_comm_cache) {
		debug_warn("Cannot create node_comm cache\n");
		return -1;
	}

	CREATE_CACHE(tcache_cache, "qs_tcache", sizeof(struct tcache));
	if (!tcache_cache) {
		debug_warn("Cannot create tcache cache\n");
		return -1;
	}

	CREATE_CACHE(ddqueue_cache, "qs_ddqueue", sizeof(struct ddqueue));
	if (!ddqueue_cache) {
		debug_warn("Cannot create ddqueue cache\n");
		return -1;
	}

	CREATE_CACHE(ctio_cache, "qs_ctio", sizeof(struct qsio_scsiio));
	if (!ctio_cache) {
		debug_warn("Cannot create ctio cache\n");
		return -1;
	}

	CREATE_CACHE(pgdata_cache, "qs_pgdata", sizeof(struct pgdata));
	if (!pgdata_cache) {
		debug_warn("Cannot create pgdata cache\n");
		return -1;
	}

	CREATE_CACHE(index_info_cache, "qs_index_info", sizeof(struct index_info));
	if (!index_info_cache) {
		debug_warn("Cannot create index info cache\n");
		return -1;
	}

	CREATE_CACHE(index_sync_cache, "qs_index_sync", sizeof(struct index_sync));
	if (!index_sync_cache) {
		debug_warn("Cannot create index sync cache\n");
		return -1;
	}

	CREATE_CACHE(log_cache, "qs_log", sizeof(struct log_page));
	if (!log_cache) {
		debug_warn("Cannot create log page cache\n");
		return -1;
	}

	CREATE_CACHE(hash_cache, "qs_hash", SHA256_DIGEST_LENGTH);
	if (!hash_cache) {
		debug_warn("Cannot create hash page cache\n");
		return -1;
	}

	CREATE_CACHE(gdevq_cache, "qs_gdevq", sizeof(struct qs_gdevq));
	if (!gdevq_cache) {
		debug_warn("Cannot create gdevq cache\n");
		return -1;
	}

	CREATE_CACHE(ddthread_cache, "qs_ddthread", sizeof(struct ddthread));
	if (!ddthread_cache) {
		debug_warn("Cannot create ddthread cache\n");
		return -1;
	}

	CREATE_CACHE(tdisk_cache, "qs_tdisk", sizeof(struct tdisk));
	if (!tdisk_cache) {
		debug_warn("Cannot create tdisk cache\n");
		return -1;
	}

	CREATE_CACHE(fourk_cache, "qs_4k", 4096);
	if (!fourk_cache) {
		debug_warn("Cannot create 4k cache\n");
		return -1;
	}

	CREATE_CACHE(eightk_cache, "qs_8k", 8192);
	if (!eightk_cache) {
		debug_warn("Cannot create 8k cache\n");
		return -1;
	}

	CREATE_CACHE(log_entry_cache, "qs_log_entry", sizeof(struct log_entry));
	if (!log_entry_cache) {
		debug_warn("Cannot create log entry cache\n");
		return -1;
	}

	CREATE_CACHE(log_group_cache, "qs_log_group", sizeof(struct log_group));
	if (!log_group_cache) {
		debug_warn("Cannot create log entry cache\n");
		return -1;
	}

	CREATE_CACHE(rcache_entry_cache, "qs_rcache_entry", sizeof(struct rcache_entry));
	if (!rcache_entry_cache) {
		debug_warn("Cannot create rcache_entry cache\n");
		return -1;
	}

	CREATE_CACHE(ddwork_cache, "qs_ddwork", sizeof(struct ddwork));
	if (!ddwork_cache) {
		debug_warn("Cannot create ddwork cache\n");
		return -1;
	}

	CREATE_CACHE(subgroup_cache, "qs_subgroup", sizeof(struct index_subgroup));
	if (unlikely(!subgroup_cache)) {
		return -1;
	}

	CREATE_CACHE(group_cache, "qs_group", sizeof(struct index_group));
	if (unlikely(!group_cache)) {
		return -1;
	}

	CREATE_CACHE(index_lookup_cache, "qs_index_lookup", sizeof(struct index_lookup));
	if (unlikely(!index_lookup_cache)) {
		return -1;
	}

	CREATE_CACHE(index_cache, "qs_index", sizeof(struct bintindex));
	if (unlikely(!index_cache)) {
		return -1;
	}

	CREATE_CACHE(subgroup_index_cache, "qs_subgroup_index", INDEX_GROUP_MAX_SUBGROUPS * sizeof(struct index_subgroup *));
	if (unlikely(!subgroup_index_cache)) {
		return -1;
	}

	CREATE_CACHE(ddtable_ddlookup_node_cache, "qs_ddtable_ddlookup_node", sizeof(struct ddtable_ddlookup_node));
	if (unlikely(!ddtable_ddlookup_node_cache)) {
		return -1;
	}

	CREATE_CACHE(amap_table_cache, "qs_amap_table", sizeof(struct amap_table));
	if (unlikely(!amap_table_cache)) {
		return -1;
	}

	CREATE_CACHE(amap_table_group_cache, "qs_amap_table_group", sizeof(struct amap_table_group));
	if (unlikely(!amap_table_group_cache)) {
		return -1;
	}

	CREATE_CACHE(ddlookup_list_cache, "qs_ddlookup_list", sizeof(struct ddlookup_list));
	if (unlikely(!ddlookup_list_cache)) {
		return -1;
	}

	CREATE_CACHE(ddnode_cache, "qs_ddnode", sizeof(struct ddtable_node));
	if (unlikely(!ddnode_cache)) {
		return -1;
	}

	CREATE_CACHE(node_group_cache, "qs_node_group", sizeof(struct node_group));
	if (unlikely(!node_group_cache)) {
		return -1;
	}

	CREATE_CACHE(aio_meta_cache, "qs_aio_meta", sizeof(struct aio_meta));
	if (unlikely(!aio_meta_cache)) {
		return -1;
	}

	CREATE_CACHE(istate_cache, "qs_istate", sizeof(struct initiator_state));
	if (unlikely(!istate_cache)) {
		return -1;
	}

	CREATE_CACHE(amap_cache, "qs_amap", sizeof(struct amap));
	if (unlikely(!amap_cache)) {
		return -1;
	}

	CREATE_CACHE(lba_write_cache, "qs_lba_write", sizeof(struct lba_write));
	if (unlikely(!lba_write_cache)) {
		return -1;
	}

	CREATE_CACHE(amap_index_cache, "qs_amap_index", (AMAPS_PER_AMAP_TABLE * sizeof(struct amap *)));
	if (unlikely(!amap_index_cache)) {
		return -1;
	}

	CREATE_CACHE(amap_sync_cache, "qs_amap_sync", sizeof(struct amap_sync));
	if (unlikely(!amap_sync_cache)) {
		return -1;
	}

	CREATE_CACHE(chan_cache, "qs_wait_chan", sizeof(wait_chan_t));
	if (unlikely(!chan_cache)) {
		return -1;
	}

	CREATE_CACHE(compl_cache, "qs_wait_compl", sizeof(wait_compl_t));
	if (unlikely(!compl_cache)) {
		return -1;
	}

#ifdef FREEBSD
	CREATE_CACHE(biot_cache, "qs_biot", sizeof(struct biot));
	if (unlikely(!biot_cache)) {
		return -1;
	}

	CREATE_CACHE(biot_page_cache, "qs_biot_page", ((MAXPHYS >> LBA_SHIFT) * sizeof(pagestruct_t *)));
	if (unlikely(!biot_page_cache)) {
		return -1;
	}

	CREATE_CACHE(sx_cache, "qs_sx", sizeof(sx_t));
	if (unlikely(!sx_cache)) {
		return -1;
	}

	CREATE_CACHE(mtx_cache, "qs_mtx", sizeof(mtx_t));
	if (unlikely(!mtx_cache)) {
		return -1;
	}
#endif

	return 0;
}

static void
exit_globals(void)
{
	sx_free(gchain_lock);
	sx_free(cbs_lock);
	sx_free(clone_info_lock);
	sx_free(rep_comm_lock);
	sx_free(sync_lock);
	sx_free(rod_lock);
	mtx_free(glob_stats_lock);
	mtx_free(tdisk_lookup_lock);
	mtx_free(ddtable_global.global_lock);
	mtx_free(glbl_lock);
#ifdef ENABLE_STATS
	mtx_free(ddtable_stats.stats_lock);
#endif
	wait_chan_free(gpglist_wait);
	wait_chan_free(ha_wait);
}

static void
device_detach_interfaces(void)
{
	struct qs_interface_cbs *iter;
	struct qs_interface_cbs *fc;

again:
	fc = NULL;
	sx_xlock(cbs_lock);
	LIST_FOREACH(iter, &cbs_list, i_list) {
		if (!iter->detach_interface)
			continue;
		fc = iter;
		break;
	}
	sx_xunlock(cbs_lock);
	if (!fc)
		return;

	(*fc->detach_interface)();
	goto again;
}

#ifdef ALLOC_TRACKING
DEFINE_ALLOC_COUNTER(pages_alloced);
DEFINE_ALLOC_COUNTER(pages_freed);
DEFINE_ALLOC_COUNTER(pages_refed);
DEFINE_ALLOC_COUNTER(pgdata_pages_alloced);
DEFINE_ALLOC_COUNTER(pgdata_pages_freed);
DEFINE_ALLOC_COUNTER(pgdata_pages_refed);
DEFINE_ALLOC_COUNTER(rcache_pages_freed);
DEFINE_ALLOC_COUNTER(rcache_pages_refed);
#endif

static int 
__kern_exit(void)
{
	int i;

	debug_print("kern_inited; %d\n", atomic_read(&kern_inited));
	if (!atomic_read(&kern_inited))
		return 0;

	atomic_set(&itf_enabled, 0);
	atomic_set(&kern_inited, 0);
	clone_info_list_complete();

	debug_print("disable devices\n");
	for (i = 0; i < TL_MAX_DEVICES; i++) {
		struct tdisk *tdisk = tdisks[i];

		if (!tdisk)
			continue;
		tdisk_stop_threads(tdisk);
		cbs_disable_device(tdisk);
		tdisk_mirror_exit(tdisk);
	}

	debug_print("copy manager exit\n");
	copy_manager_exit();

	debug_print("node cleanups wait\n");
	node_cleanups_wait();

	debug_print("node ha exit\n");
	node_ha_exit();

	for (i = 0; i < TL_MAX_DEVICES; i++) {
		struct tdisk *tdisk = tdisks[i];

		if (!tdisk)
			continue;

		debug_print("wait for %s istate list\n", tdisk_name(tdisk));
		device_wait_all_initiators(&tdisk->istate_list);
		debug_print("done wait for %s istate list\n", tdisk_name(tdisk));
		tdisk_sync(tdisk, 0);
		cbs_remove_device(tdisk);
	}

	debug_print("detach interfaces\n");
	device_detach_interfaces();

	debug_print("node recv exit\n");
	node_recv_exit();

	debug_print("exit gdevq threads\n");
	exit_gdevq_threads();

	debug_print("node sync exit threads\n");
	node_sync_exit_threads();

	debug_print("exit ddthreads\n");
	exit_ddthreads();

	for (i = 0; i < TL_MAX_DEVICES; i++)
	{
		struct tdisk *tdisk = tdisks[i];

		if (!tdisk)
			continue;

		while (atomic_read(&tdisk->refs) > 1) {
			debug_print("wait for tdisk %s\n", tdisk_name(tdisk));
			processor_yield();
			pause("psg", 500);
		}

		tdisk_put(tdisk);
	}

	debug_print("node usr exit\n");
	node_usr_exit();

	debug_print("node exit\n");
	node_exit();

	debug_print("ddtable exit\n");
	bdev_groups_ddtable_exit();

	debug_print("bdev finalize\n");
	bdev_finalize();

	debug_print("rcache exit\n");
	rcache_exit();

	debug_print("groups free\n");
	bdev_groups_free();

	debug_print("clear fc rules\n");
	target_clear_fc_rules(0);

	debug_print("end\n");
	return 0;
}

static int
pgzero_init(void)
{
	int retval;

	retval = pgdata_alloc_page(&pgzero, VM_ALLOC_ZERO);
	if (unlikely(retval != 0)) {
		debug_warn("Cannot allocate zero page\n");
		return -1;
	}

	pgzero.pg_len = LBA_SIZE;
	pgzero_addr = (uint8_t *)pgdata_page_address(&pgzero);
	return 0;
}

static void
pgzero_exit(void)
{
	pgdata_free_page(&pgzero);
}

#ifdef ENABLE_STATS
extern uint64_t bio_reads;
extern uint64_t bio_read_size;
extern uint64_t bio_writes;
extern uint64_t bio_write_size;
extern uint32_t index_lookup_writes;
extern uint32_t index_writes;
extern uint32_t bint_writes;
extern uint32_t amap_table_writes;
extern uint32_t amap_writes;
extern uint32_t ddlookup_writes;
extern uint32_t ddtable_writes;
extern uint32_t log_writes;
extern uint32_t log_group_writes;
extern uint32_t log_group_bio;
extern uint32_t tdisk_index_writes;
extern uint32_t index_lookup_reads;
extern uint32_t index_reads;
extern uint32_t bint_reads;
extern uint32_t amap_table_reads;
extern uint32_t amap_reads;
extern uint32_t ddlookup_reads;
extern uint32_t ddtable_reads;
extern uint32_t log_reads;
extern uint32_t tdisk_index_reads;
extern uint32_t subgroup_read_bio;
extern uint32_t subgroup_write_bio;
extern uint32_t subgroup_writes;
extern uint32_t subgroup_reads;


uint32_t memcmp_ticks;
uint32_t bint_eligible_ticks;
uint32_t log_barrier_ticks;
uint32_t rcache_insert_ticks;
uint32_t rcache_lookup_ticks;
uint32_t rcache_remove_ticks;
uint32_t rcache_lookup_hits;
uint32_t rcache_lookups;
uint32_t rcache_inserts;
uint32_t rcache_removes;
uint32_t log_reserve_waits;

uint32_t delete_index_wait_ticks;
uint32_t wait_for_read_timeout_ticks;
uint32_t wait_for_write_ticks;
uint32_t wait_for_write_count;
uint32_t node_master_write_pre_ticks;
uint32_t node_master_lba_write_setup_ticks;
uint32_t node_master_scan_write_ticks;
uint32_t node_master_write_spec_setup_ticks;
uint32_t node_master_write_setup_send_ticks;
uint32_t node_master_cmd_generic_ticks;
uint32_t node_master_read_cmd_ticks;
uint32_t node_master_read_data_ticks;
uint32_t node_master_read_done_ticks;
uint32_t node_master_write_cmd_ticks;
uint32_t node_master_xcopy_read_ticks;
uint32_t node_master_xcopy_write_ticks;
uint32_t node_master_verify_data_ticks;
uint32_t node_master_write_comp_done_ticks;
uint32_t node_master_write_done_ticks;
uint32_t node_master_write_post_pre_ticks;
uint32_t node_master_write_data_unaligned_ticks;
uint32_t node_master_write_data_ticks;

uint32_t ddlookup_sync_count;
uint32_t ddlookup_sync_ticks;
uint32_t ddlookup_sync_post_count;
uint32_t ddlookup_sync_post_ticks;
uint32_t log_sync_count;
uint32_t log_sync_ticks;
uint32_t log_sync_post_count;
uint32_t log_sync_post_ticks;
uint32_t index_lookup_sync_count;
uint32_t index_lookup_sync_ticks;
uint32_t index_sync_count;
uint32_t index_sync_ticks;
uint32_t index_sync_post_count;
uint32_t index_sync_post_ticks;
uint32_t amap_sync_count;
uint32_t amap_sync_ticks;
uint32_t amap_sync_post_count;
uint32_t amap_sync_post_ticks;
uint32_t amap_table_sync_count;
uint32_t amap_table_sync_ticks;
uint32_t amap_table_sync_post_count;
uint32_t amap_table_sync_post_ticks;
uint32_t amap_meta_sync_count;
uint32_t amap_meta_sync_ticks;
uint32_t amap_table_meta_sync_count;
uint32_t amap_table_meta_sync_ticks;
uint32_t table_index_sync_count;
uint32_t table_index_sync_ticks;
uint32_t reservation_sync_ticks;
uint32_t reservation_sync_count;
uint32_t sense_state_sync_ticks;
uint32_t sense_state_sync_count;
uint32_t istate_clear_sync_ticks;
uint32_t istate_clear_sync_count;
uint32_t registration_sync_ticks;
uint32_t registration_sync_count;
uint32_t registration_clear_sync_ticks;
uint32_t registration_clear_sync_count;
uint32_t tdisk_sync_ticks;
uint32_t tdisk_sync_count;
uint32_t pgdata_sync_complete_ticks;
uint32_t pgdata_sync_complete_count;
uint32_t pgdata_sync_client_done_ticks;
uint32_t pgdata_sync_client_done_count;
uint32_t pgdata_sync_start_ticks;
uint32_t pgdata_sync_start_count;
uint32_t bint_sync_ticks;
uint32_t bint_sync_count;
uint32_t sync_send_bytes;
uint32_t sync_page_send_bytes;
#endif

static void
init_globals(void)
{
	gchain_lock = sx_alloc("qs gchain lock");
	cbs_lock = sx_alloc("qs cbs lock");
	clone_info_lock = sx_alloc("qs clone info lock");
	rep_comm_lock = sx_alloc("qs rep comm lock");
	sync_lock = sx_alloc("node sync lock");
	rod_lock = sx_alloc("rod lock");
	glob_stats_lock = mtx_alloc("glob stats lock");
	tdisk_lookup_lock = mtx_alloc("tdisk lookup lock");
	glbl_lock = mtx_alloc("glbl lock");
	gpglist_wait = wait_chan_alloc("gpglistwt");
	ha_wait = wait_chan_alloc("ha wait");
	ddtable_global.global_lock = mtx_alloc("ddtable global lock");
#ifdef ENABLE_STATS
	ddtable_stats.stats_lock = mtx_alloc("ddtable stats lock");
#endif
	calc_mem_restrictions(qs_availmem);
}

static int
coremod_load_done(void)
{
	int retval;

	if (!atomic_read(&kern_inited))
		return -1;

	retval = node_usr_init();
	if (unlikely(retval != 0)) {
		debug_warn("Cannot init usr sockets. Fatal error...\n");
		return -1;
	}

	if (!node_type_client() && !node_type_master()) {
		retval = 0;
		if (node_type_controller()) {
			retval = node_controller_ha_init();
			if (unlikely(retval < 0)) {
				debug_warn_notify("node controller ha init failed\n");
				return -1;
			}
		}

		if (!node_in_standby() && !retval) {
			bdevs_load_post();
			retval = bdev_groups_replay_write_logs();
			if (retval == 0) {
				bdevs_fix_rids();
				bdevs_load_ddtables_post();
				tdisk_load_amaps();
			}
		}

	}
	else if (node_type_master()) {
		node_master_ha_init();
	}
	return retval;
}

static int
coremod_reset_logs(void)
{
	int retval;

	if (!atomic_read(&kern_inited))
		return -1;

	retval = bdev_groups_reset_write_logs();
	if (unlikely(retval != 0))
		return -1;

	tdisk_load_amaps();
	return 0;
}

int
kern_interface_init(struct qs_kern_cbs *kern_cbs)
{
	int retval;

	kern_cbs->vdisk_clone = vdisk_clone;
	kern_cbs->vdisk_clone_status = vdisk_clone_status;
	kern_cbs->vdisk_clone_cancel = vdisk_clone_cancel;
	kern_cbs->vdisk_mirror = vdisk_mirror;
	kern_cbs->vdisk_mirror_status = vdisk_mirror_status;
	kern_cbs->vdisk_mirror_cancel = vdisk_mirror_cancel;
	kern_cbs->vdisk_mirror_remove = vdisk_mirror_remove;
	kern_cbs->node_config = node_config;
	kern_cbs->node_status = node_status;
	kern_cbs->mdaemon_set_info = mdaemon_set_info;
	kern_cbs->bdev_add_new = bdev_add_new;
	kern_cbs->bdev_remove = bdev_remove;
	kern_cbs->bdev_add_stub = bdev_add_stub;
	kern_cbs->bdev_remove_stub = bdev_remove_stub;
	kern_cbs->bdev_get_info = bdev_get_info;
	kern_cbs->bdev_ha_config = bdev_ha_config;
	kern_cbs->bdev_unmap_config = bdev_unmap_config;
	kern_cbs->bdev_wc_config = bdev_wc_config;
	kern_cbs->bdev_add_group = bdev_group_add; 
	kern_cbs->bdev_delete_group = bdev_group_remove; 
	kern_cbs->bdev_rename_group = bdev_group_rename; 
	kern_cbs->coremod_load_done = coremod_load_done;
	kern_cbs->coremod_reset_logs = coremod_reset_logs;
	kern_cbs->coremod_exit = __kern_exit;
	kern_cbs->ddtable_load_status = bdev_groups_ddtable_load_status;
	kern_cbs->target_load_vdisk = target_load_disk;
	kern_cbs->target_attach_vdisk = target_attach_disk;
	kern_cbs->target_modify_vdisk = target_modify_disk;
	kern_cbs->target_delete_vdisk = target_delete_disk;
	kern_cbs->target_delete_vdisk_post = target_delete_disk_post;
	kern_cbs->target_vdisk_stats = target_disk_stats;
	kern_cbs->target_vdisk_reset_stats = target_disk_reset_stats;
	kern_cbs->target_new_vdisk = target_new_disk;
	kern_cbs->target_new_vdisk_stub = target_new_disk_stub;
	kern_cbs->target_delete_vdisk_stub = target_delete_disk_stub;
	kern_cbs->target_disable_vdisk_stub = target_disable_disk_stub;
	kern_cbs->target_resize_vdisk = target_resize_disk;
	kern_cbs->target_rename_vdisk = target_rename_disk;
	kern_cbs->target_set_role = target_set_role;
	kern_cbs->target_add_fc_rule = target_add_fc_rule;
	kern_cbs->target_remove_fc_rule = target_remove_fc_rule;
	kern_cbs->sock_state_change = node_sock_state_change;
	kern_cbs->sock_read_avail = node_sock_read_avail;
	kern_cbs->sock_write_avail = node_sock_write_avail;
	if (!kern_cbs->hash_compute)
		kern_cbs->hash_compute = ddblock_hash_compute_fallback; 

	memcpy(&kcbs, kern_cbs, sizeof(kcbs));

	qs_availmem = get_availmem();

	retval = pgzero_init();
	if (unlikely(retval != 0))
		return -1;

	retval = init_caches();
	if (unlikely(retval != 0)) {
		pgzero_exit();
		return -1;
	}

	init_globals();
	retval = rcache_init();
	if (unlikely(retval != 0)) {
		pgzero_exit();
		exit_globals();
		exit_caches();
		return -1;
	}

	retval = init_gdevq_threads();
	if (unlikely(retval != 0)) {
		rcache_exit();
		pgzero_exit();
		exit_globals();
		exit_caches();
		return -1;
	}

	retval = node_sync_init_threads();
	if (unlikely(retval != 0)) {
		exit_gdevq_threads();
		rcache_exit();
		pgzero_exit();
		exit_globals();
		exit_caches();
		return -1;
	}

	retval = init_ddthreads();
	if (unlikely(retval != 0)) {
		node_sync_exit_threads();
		exit_gdevq_threads();
		rcache_exit();
		pgzero_exit();
		exit_globals();
		exit_caches();
		return -1;
	}

	retval = copy_manager_init();
	if (unlikely(retval != 0)) {
		exit_ddthreads();
		node_sync_exit_threads();
		exit_gdevq_threads();
		rcache_exit();
		pgzero_exit();
		exit_globals();
		exit_caches();
		return -1;
	}

	node_init();
	atomic_set(&kern_inited, 1);
	atomic_set(&itf_enabled, 1);
	return 0;
}

extern uint32_t recv_pages_ticks;
extern uint64_t sock_reads;
extern uint64_t sock_writes;
extern uint64_t sock_page_writes;
extern uint64_t index_locate_hits;
extern uint64_t index_locate_misses;
extern uint64_t index_locate_iters;
extern uint32_t locate_index_ticks;

extern uint32_t master_register_ticks;
extern uint32_t master_unregister_ticks;
extern uint32_t master_read_cmd_ticks;
extern uint32_t master_read_io_done_ticks;
extern uint32_t master_read_done_ticks;
extern uint32_t master_write_cmd_ticks;
extern uint32_t master_write_io_done_ticks;
extern uint32_t master_write_done_ticks;
extern uint32_t master_cmd_generic_ticks;
extern uint32_t master_verify_data_ticks;
extern uint32_t master_comp_done_ticks;
extern uint32_t master_write_data_ticks;
extern uint32_t master_read_data_ticks;

void
kern_interface_exit(void)
{
	PRINT_STAT("subgroup_read_bio", subgroup_read_bio);
	PRINT_STAT("subgroup_reads", subgroup_reads);
	PRINT_STAT("delete_index_wait_ticks", delete_index_wait_ticks);
	PRINT_STAT("amap_writes", amap_writes);
	PRINT_STAT("amap_table_writes", amap_table_writes);
	PRINT_STAT("log_writes", log_writes);
	PRINT_STAT("index_writes", index_writes);
	PRINT_STAT("ddlookup_sync_count", ddlookup_sync_count);
	PRINT_STAT("ddlookup_sync_ticks", ddlookup_sync_ticks);
	PRINT_STAT("ddlookup_sync_post_count", ddlookup_sync_post_count);
	PRINT_STAT("ddlookup_sync_post_ticks", ddlookup_sync_post_ticks);
	PRINT_STAT("log_sync_count", log_sync_count);
	PRINT_STAT("log_sync_ticks", log_sync_ticks);
	PRINT_STAT("log_sync_post_count", log_sync_post_count);
	PRINT_STAT("log_sync_post_ticks", log_sync_post_ticks);
	PRINT_STAT("index_lookup_sync_count", index_lookup_sync_count);
	PRINT_STAT("index_lookup_sync_ticks", index_lookup_sync_ticks); 
	PRINT_STAT("index_sync_count", index_sync_count); 
	PRINT_STAT("index_sync_ticks", index_sync_ticks); 
	PRINT_STAT("index_sync_post_count", index_sync_post_count); 
	PRINT_STAT("index_sync_post_ticks", index_sync_post_ticks); 
	PRINT_STAT("amap_sync_count", amap_sync_count); 
	PRINT_STAT("amap_sync_ticks", amap_sync_ticks); 
	PRINT_STAT("amap_sync_post_count", amap_sync_post_count); 
	PRINT_STAT("amap_sync_post_ticks", amap_sync_post_ticks);
	PRINT_STAT("amap_table_sync_count", amap_table_sync_count);
	PRINT_STAT("amap_table_sync_ticks", amap_table_sync_ticks);
	PRINT_STAT("amap_table_sync_post_count", amap_table_sync_post_count);
	PRINT_STAT("amap_table_sync_post_ticks", amap_table_sync_post_ticks);
	PRINT_STAT("amap_meta_sync_count", amap_meta_sync_count);
	PRINT_STAT("amap_meta_sync_ticks", amap_meta_sync_ticks);
	PRINT_STAT("amap_table_meta_sync_count", amap_table_meta_sync_count);
	PRINT_STAT("amap_table_meta_sync_ticks", amap_table_meta_sync_ticks);
	PRINT_STAT("table_index_sync_count", table_index_sync_count);
	PRINT_STAT("table_index_sync_ticks", table_index_sync_ticks);
	PRINT_STAT("reservation_sync_ticks", reservation_sync_ticks);
	PRINT_STAT("reservation_sync_count", reservation_sync_count);
	PRINT_STAT("sense_state_sync_ticks", sense_state_sync_ticks);
	PRINT_STAT("sense_state_sync_ticks", sense_state_sync_ticks);
	PRINT_STAT("istate_clear_sync_ticks", istate_clear_sync_ticks);
	PRINT_STAT("istate_clear_sync_count", istate_clear_sync_count);
	PRINT_STAT("registration_sync_ticks", registration_sync_ticks);
	PRINT_STAT("registration_sync_count", registration_sync_count);
	PRINT_STAT("registration_clear_sync_ticks", registration_clear_sync_ticks);
	PRINT_STAT("registration_clear_sync_count", registration_clear_sync_count);
	PRINT_STAT("tdisk_sync_ticks", tdisk_sync_ticks);
	PRINT_STAT("tdisk_sync_count", tdisk_sync_count);
	PRINT_STAT("pgdata_sync_complete_ticks", pgdata_sync_complete_ticks);
	PRINT_STAT("pgdata_sync_complete_count", pgdata_sync_complete_count);
	PRINT_STAT("pgdata_sync_client_done_ticks", pgdata_sync_client_done_ticks);
	PRINT_STAT("pgdata_sync_client_done_count", pgdata_sync_client_done_count);
	PRINT_STAT("pgdata_sync_start_ticks", pgdata_sync_start_ticks);
	PRINT_STAT("pgdata_sync_start_count", pgdata_sync_start_count);
	PRINT_STAT("bint_sync_ticks", bint_sync_ticks);
	PRINT_STAT("bint_sync_count", bint_sync_count);
	PRINT_STAT("sync_send_bytes", sync_send_bytes);
	PRINT_STAT("sync_page_send_bytes", sync_page_send_bytes);
	PRINT_STAT("wait_for_read_timeout_ticks", wait_for_read_timeout_ticks);
	PRINT_STAT("wait_for_write_ticks", wait_for_write_ticks);
	PRINT_STAT("wait_for_write_count", wait_for_write_count);
	PRINT_STAT("node_master_write_pre_ticks", node_master_write_pre_ticks);
	PRINT_STAT("node_master_lba_write_setup_ticks", node_master_lba_write_setup_ticks);
	PRINT_STAT("node_master_scan_write_ticks", node_master_scan_write_ticks);
	PRINT_STAT("node_master_write_spec_setup_ticks", node_master_write_spec_setup_ticks);
	PRINT_STAT("node_master_write_setup_send_ticks", node_master_write_setup_send_ticks);
	PRINT_STAT("node_master_cmd_generic_ticks", node_master_cmd_generic_ticks);
	PRINT_STAT("node_master_read_cmd_ticks", node_master_read_cmd_ticks);
	PRINT_STAT("node_master_read_data_ticks", node_master_read_data_ticks);
	PRINT_STAT("node_master_read_done_ticks", node_master_read_done_ticks);
	PRINT_STAT("node_master_write_cmd_ticks", node_master_write_cmd_ticks);
	PRINT_STAT("node_master_xcopy_read_ticks", node_master_xcopy_read_ticks);
	PRINT_STAT("node_master_xcopy_write_ticks", node_master_xcopy_write_ticks);
	PRINT_STAT("node_master_verify_data_ticks", node_master_verify_data_ticks);
	PRINT_STAT("node_master_write_comp_done_ticks", node_master_write_comp_done_ticks);
	PRINT_STAT("node_master_write_done_ticks", node_master_write_done_ticks);
	PRINT_STAT("node_master_write_post_pre_ticks", node_master_write_post_pre_ticks);
	PRINT_STAT("node_master_write_data_unaligned_ticks", node_master_write_data_unaligned_ticks);
	PRINT_STAT("node_master_write_data_ticks", node_master_write_data_ticks);


	PRINT_STAT("master_register_ticks", master_register_ticks);
	PRINT_STAT("master_unregister_ticks", master_unregister_ticks);
	PRINT_STAT("master_read_cmd_ticks", master_read_cmd_ticks);
	PRINT_STAT("master_read_io_done_ticks", master_read_io_done_ticks);
	PRINT_STAT("master_read_done_ticks", master_read_done_ticks);
	PRINT_STAT("master_read_data_ticks", master_read_data_ticks);
	PRINT_STAT("master_write_cmd_ticks", master_write_cmd_ticks);
	PRINT_STAT("master_write_io_done_ticks", master_write_io_done_ticks);
	PRINT_STAT("master_write_done_ticks", master_write_done_ticks);
	PRINT_STAT("master_write_data_ticks", master_write_data_ticks);
	PRINT_STAT("master_verify_data_ticks", master_verify_data_ticks);
	PRINT_STAT("master_comp_done_ticks", master_comp_done_ticks);
	PRINT_STAT("master_cmd_generic_ticks", master_cmd_generic_ticks);

	PRINT_STAT("index_locate_hits", index_locate_hits);
	PRINT_STAT("index_locate_misses", index_locate_misses);
	PRINT_STAT("index_locate_iters", index_locate_iters);
	PRINT_STAT("locate_index_ticks", locate_index_ticks);

	PRINT_STAT("sock_reads", sock_reads);
	PRINT_STAT("sock_writes", sock_writes);
	PRINT_STAT("sock_page_writes", sock_page_writes);

	PRINT_STAT("recv_pages_ticks", recv_pages_ticks);
	PRINT_STAT("memcmp_ticks", memcmp_ticks);
	PRINT_STAT("rcache_lookup_hits", rcache_lookup_hits);
	PRINT_STAT("rcache_inserts", rcache_inserts);
	PRINT_STAT("rcache_insert_ticks", rcache_insert_ticks);
	PRINT_STAT("rcache_removes", rcache_removes);
	PRINT_STAT("rcache_remove_ticks", rcache_remove_ticks);
	PRINT_STAT("rcache_lookups", rcache_lookups);
	PRINT_STAT("rcache_lookup_ticks", rcache_lookup_ticks);
	__kern_exit();
	exit_globals();
	exit_caches();
	pgzero_exit();
	PRINT_ALLOC_COUNTER(pages_alloced);
	PRINT_ALLOC_COUNTER(pages_freed);
	PRINT_ALLOC_COUNTER(pages_refed);
	PRINT_ALLOC_COUNTER(pgdata_pages_alloced);
	PRINT_ALLOC_COUNTER(pgdata_pages_freed);
	PRINT_ALLOC_COUNTER(pgdata_pages_refed);
	PRINT_ALLOC_COUNTER(rcache_pages_freed);
	PRINT_ALLOC_COUNTER(rcache_pages_refed);
}

struct qs_interface_cbs *
device_interface_locate(int interface)
{
	struct qs_interface_cbs *iter;

	sx_xlock(cbs_lock);
	LIST_FOREACH(iter, &cbs_list, i_list) {
		if (iter->interface == interface) {
			sx_xunlock(cbs_lock);
			return iter;
		}
	}
	sx_xunlock(cbs_lock);
	return NULL;
}

int
__device_unregister_interface(struct qs_interface_cbs *cbs)
{
	struct qs_interface_cbs *iter;
	int found = -1;

	sx_xlock(cbs_lock);
	LIST_FOREACH(iter, &cbs_list, i_list) {
		if (iter->interface != cbs->interface)
			continue;
		LIST_REMOVE(iter, i_list);
		free(iter, M_CBS);
		found = 0;
		break;
	}
	sx_xunlock(cbs_lock);
	return found;
}

int
__device_register_interface(struct qs_interface_cbs *cbs)
{
	struct qs_interface_cbs *new;

	sx_xlock(cbs_lock);
	if (!atomic_read(&itf_enabled)) {
		sx_xunlock(cbs_lock);
		return -1;
	}

	new = zalloc(sizeof(*new), M_CBS, Q_WAITOK);
	cbs->ctio_new = ctio_new;
	cbs->ctio_allocate_buffer = ctio_allocate_buffer;
	cbs->ctio_free_data = ctio_free_data;
	cbs->ctio_free_all = ctio_free_all;
	cbs->ctio_write_length = ctio_write_length;
	cbs->pgdata_free_page = pgdata_free_page;
	cbs->get_device = get_device;
	cbs->device_tid = device_tid;
	cbs->bus_from_lun = bus_from_lun;
	cbs->write_lun = __write_lun;
	cbs->device_end_lba = device_end_lba;
	cbs->device_lba_shift = device_lba_shift;
	cbs->device_name = tdisk_name;
	cbs->device_set_vhba_id = device_set_vhba_id;
	cbs->device_set_hpriv = device_set_hpriv;
	cbs->device_send_ccb = device_send_ccb;
	cbs->device_send_notify = device_send_notify;
	cbs->device_istate_abort_task = device_istate_abort_task;
	cbs->device_istate_abort_task_set = device_istate_abort_task_set;
	cbs->device_istate_queue_ctio = device_istate_queue_ctio;
	cbs->device_queue_ctio = device_queue_ctio;
	cbs->device_queue_ctio_list = device_queue_ctio_list;
	cbs->device_queue_ctio_direct = gdevq_insert_ccb;
	cbs->device_remove_ctio = device_remove_ctio;
	cbs->device_check_cmd = tdisk_check_cmd;
	cbs->device_allocate_buffers = device_allocate_buffers;
	cbs->device_allocate_cmd_buffers = device_allocate_cmd_buffers;
	cbs->device_target_reset = tdisk_reset;
	cbs->device_free_initiator = device_free_initiator;
	cbs->fc_initiator_check = fc_initiator_check;
	cbs->get_tprt = node_get_tprt;

	memcpy(new, cbs, sizeof(*new));
	LIST_INSERT_HEAD(&cbs_list, new, i_list);
	sx_xunlock(cbs_lock);
	return 0;
}
