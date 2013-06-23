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

#include "gdevq.h"
#include "ddtable.h"
#include "tdisk.h"
#include "cluster.h"
#include "bdevgroup.h"
#include "sense.h"
#include "vdevdefs.h"


struct ccb_list pending_queue = STAILQ_HEAD_INITIALIZER(pending_queue);
struct ccb_list master_pending_queue = STAILQ_HEAD_INITIALIZER(master_pending_queue);
struct clone_data_list pending_tqueue = STAILQ_HEAD_INITIALIZER(pending_tqueue);
struct pgdata_wlist pending_write_queue = STAILQ_HEAD_INITIALIZER(pending_write_queue);
struct pgdata_wlist pending_comp_queue = STAILQ_HEAD_INITIALIZER(pending_comp_queue);
struct ddqueue_wlist pending_dedupe_queue = STAILQ_HEAD_INITIALIZER(pending_dedupe_queue);

static SLIST_HEAD(, qs_gdevq) devq_list = SLIST_HEAD_INITIALIZER(devq_list);
static SLIST_HEAD(, qs_gdevq) mdevq_list = SLIST_HEAD_INITIALIZER(mdevq_list);
static SLIST_HEAD(, qs_sdevq) sdevq_list = SLIST_HEAD_INITIALIZER(sdevq_list);
static SLIST_HEAD(, qs_sdevq) tdevq_list = SLIST_HEAD_INITIALIZER(tdevq_list);
static SLIST_HEAD(, qs_sdevq) ddevq_list = SLIST_HEAD_INITIALIZER(ddevq_list);
static SLIST_HEAD(, qs_cdevq) cdevq_list = SLIST_HEAD_INITIALIZER(cdevq_list);

wait_chan_t *devq_wait;
wait_chan_t *mdevq_wait;
wait_chan_t *tdevq_wait;
wait_chan_t *devq_write_wait;
wait_chan_t *devq_comp_wait;
wait_chan_t *devq_dedupe_wait;

static atomic_t mdevq_pending;

static inline struct pgdata *
get_next_pgdata(void)
{
	struct pgdata *pgdata;

	if (STAILQ_EMPTY(&pending_write_queue))
		return NULL;

	chan_lock(devq_write_wait);
	pgdata = STAILQ_FIRST(&pending_write_queue);
	if (pgdata)
		STAILQ_REMOVE_HEAD(&pending_write_queue, w_list);
	chan_unlock(devq_write_wait);
	return pgdata;
}

static inline struct pgdata *
get_next_comp_pgdata(void)
{
	struct pgdata *pgdata;

	if (STAILQ_EMPTY(&pending_comp_queue))
		return NULL;

	chan_lock(devq_comp_wait);
	pgdata = STAILQ_FIRST(&pending_comp_queue);
	if (pgdata)
		STAILQ_REMOVE_HEAD(&pending_comp_queue, w_list);
	chan_unlock(devq_comp_wait);
	return pgdata;
}

static inline struct qsio_hdr *
get_next_ccb(void)
{
	struct qsio_hdr *ccb;

	if (STAILQ_EMPTY(&pending_queue))
		return NULL;

	chan_lock(devq_wait);
	ccb = STAILQ_FIRST(&pending_queue);
	if (ccb)
		STAILQ_REMOVE_HEAD(&pending_queue, c_list);
	chan_unlock(devq_wait);
	return ccb;
}

void
mdevq_wait_for_empty(void)
{
	while (!STAILQ_EMPTY(&master_pending_queue) || atomic_read(&mdevq_pending))
		processor_yield();
}

static inline struct qsio_hdr *
get_next_master_ccb(void)
{
	struct qsio_hdr *ccb;

	if (STAILQ_EMPTY(&master_pending_queue))
		return NULL;

	chan_lock(mdevq_wait);
	ccb = STAILQ_FIRST(&master_pending_queue);
	if (ccb) {
		atomic_inc(&mdevq_pending);
		STAILQ_REMOVE_HEAD(&master_pending_queue, c_list);
	}
	chan_unlock(mdevq_wait);
	return ccb;
}

static inline struct ddqueue *
get_next_ddqueue(void)
{
	struct ddqueue *ddqueue;

	if (STAILQ_EMPTY(&pending_dedupe_queue))
		return NULL;

	chan_lock(devq_dedupe_wait);
	ddqueue = STAILQ_FIRST(&pending_dedupe_queue);
	if (ddqueue)
		STAILQ_REMOVE_HEAD(&pending_dedupe_queue, q_list);
	chan_unlock(devq_dedupe_wait);
	return ddqueue;
}

static void
devq_process_dedupe_queue(void)
{
	struct ddqueue *ddqueue;
#ifdef ENABLE_STATS
	uint32_t start_ticks;
#endif

	while ((ddqueue = get_next_ddqueue()) != NULL) {
		TDISK_TSTART(start_ticks);
		scan_dedupe_data(ddqueue->tdisk->group, ddqueue->pgdata, ddqueue->wlist);
		wait_complete_all(ddqueue->pgdata->completion);
		TDISK_TEND(ddqueue->wlist->tdisk, scan_dedupe_ticks, start_ticks);
		uma_zfree(ddqueue_cache, ddqueue);
	}
}

static void
devq_process_write_queue(void)
{
	struct pgdata *pgdata;
#ifdef ENABLE_STATS
	uint32_t start_ticks;
#endif

	while ((pgdata = get_next_pgdata()) != NULL) {
		DD_TSTART(start_ticks);
		ddblock_hash_compute(pgdata);
		DD_TEND(hash_compute_ticks, start_ticks);
		wait_complete_all(pgdata->completion);
	}
}

static void
devq_process_comp_queue(struct qs_cdevq *devq)
{
	struct pgdata *pgdata;
#ifdef ENABLE_STATS
	uint32_t start_ticks;
#endif
	struct pgdata *comp_pgdata;
	int retval;
	uint32_t comp_size, block_size;

	while ((pgdata = get_next_comp_pgdata()) != NULL) {
		DD_TSTART(start_ticks);
		comp_pgdata = __uma_zalloc(pgdata_cache, Q_NOWAIT | Q_ZERO, sizeof(*comp_pgdata));
		if (unlikely(!comp_pgdata)) {
			wait_complete_all(pgdata->completion);
			DD_TEND(compression_ticks, start_ticks);
			continue;
		}

		comp_pgdata->completion = wait_completion_alloc("pgdata compl");
		retval = pgdata_alloc_page(comp_pgdata, 0);
		if (unlikely(retval != 0)) {
			pgdata_free(comp_pgdata);
			wait_complete_all(pgdata->completion);
			DD_TEND(compression_ticks, start_ticks);
			continue;
		}
		retval = qs_deflate_block(pgdata, comp_pgdata, &comp_size, devq->wrkmem, COMP_ALG_LZ4);
		if (unlikely(retval != 0)) {
			pgdata_free(comp_pgdata);
			wait_complete_all(pgdata->completion);
			DD_TEND(compression_ticks, start_ticks);
			continue;
		}
		block_size = align_size(comp_size, 1024);
		if (block_size < LBA_SIZE) {
			pgdata->comp_pgdata = comp_pgdata;
			comp_pgdata->pg_len = block_size;
		}
		else {
			pgdata_free(comp_pgdata);
		}
		wait_complete_all(pgdata->completion);
		DD_TEND(compression_ticks, start_ticks);
	}
}

int
gdevq_abort_task(uint64_t i_prt[], uint64_t t_prt[], uint8_t init_int, uint32_t task_tag)
{
	struct qsio_hdr *ccb_h;
	struct qsio_scsiio *ctio;

	debug_info("aborting task for tag %x\n", task_tag);
	STAILQ_FOREACH(ccb_h, &pending_queue, c_list) {
		ctio = (struct qsio_scsiio *)(ccb_h);
		debug_info("ctio task tag %x task tag %x\n", ctio->task_tag, task_tag);
		if (ctio->task_tag != task_tag || !port_equal(ctio->i_prt, i_prt) || !port_equal(ctio->t_prt, t_prt) || ctio->init_int != init_int)
			continue;

		debug_info("aborting task with tag %x\n", task_tag);
		ccb_h->flags |= QSIO_CTIO_ABORTED;
		return 1;
	}
	return 0;
}

void
gdevq_abort_tasks_for_initiator(uint64_t i_prt[], uint64_t t_prt[], uint8_t init_int)
{
	struct qsio_hdr *ccb_h;
	struct qsio_scsiio *ctio;

	STAILQ_FOREACH(ccb_h, &pending_queue, c_list) {
		ctio = (struct qsio_scsiio *)(ccb_h);
		if (port_equal(ctio->i_prt, i_prt) && port_equal(ctio->t_prt, t_prt) && ctio->init_int == init_int)
			ccb_h->flags |= QSIO_CTIO_ABORTED;
	}
}

void
gdevq_abort_tasks(struct tdisk *tdisk, uint64_t i_prt[], uint64_t t_prt[], uint8_t init_int)
{
	struct qsio_hdr *ccb_h;
	struct qsio_scsiio *ctio;

	STAILQ_FOREACH(ccb_h, &pending_queue, c_list) {
		if (ccb_h->tdisk == tdisk) {
			ctio = (struct qsio_scsiio *)(ccb_h);
			ccb_h->flags |= QSIO_CTIO_ABORTED;
			if (!port_equal(ctio->i_prt, i_prt) || !port_equal(ctio->t_prt, t_prt) || ctio->init_int != init_int)
				ccb_h->flags |= QSIO_SEND_ABORT_STATUS;
		}
	}
}

void
gdevq_abort_tasks_other_initiators(uint64_t i_prt[], uint64_t t_prt[], uint8_t init_int)
{
	struct qsio_hdr *ccb_h;
	struct qsio_scsiio *ctio;

	STAILQ_FOREACH(ccb_h, &pending_queue, c_list) {
		ctio = (struct qsio_scsiio *)(ccb_h);
		if (port_equal(ctio->i_prt, i_prt) && port_equal(ctio->t_prt, t_prt) && ctio->init_int == init_int) {
			ccb_h->flags |= QSIO_CTIO_ABORTED;
			ccb_h->flags |= QSIO_SEND_ABORT_STATUS;
		}
	}
}

void
mdevq_abort_tasks(struct tdisk *tdisk, uint64_t i_prt[], uint64_t t_prt[], uint8_t init_int)
{
	struct qsio_hdr *ccb_h;
	struct qsio_scsiio *ctio;

	STAILQ_FOREACH(ccb_h, &master_pending_queue, c_list) {
		if (ccb_h->tdisk == tdisk) {
			ctio = (struct qsio_scsiio *)(ccb_h);
			ccb_h->flags |= QSIO_CTIO_ABORTED;
			if (!port_equal(ctio->i_prt, i_prt) || !port_equal(ctio->t_prt, t_prt) || ctio->init_int != init_int)
				ccb_h->flags |= QSIO_SEND_ABORT_STATUS;
		}
	}
}

static int
is_aligned_write(struct qsio_scsiio *ctio)
{
	struct tdisk *tdisk = ctio->ccb_h.tdisk;
	uint8_t *cdb = ctio->cdb;
	uint64_t lba;
	uint32_t transfer_length;
	int unaligned;

	switch (cdb[0]) {
	case READ_6:
	case WRITE_6:
		lba = READ_24((cdb[1] & 0x1F), cdb[2], cdb[3]);
		transfer_length = cdb[4];
		if (!transfer_length)
			transfer_length = 256;
		break;
	case READ_10: 
	case WRITE_10: 
		lba = be32toh(*(uint32_t *)(&cdb[2]));
		transfer_length = be16toh(*(uint16_t *)(&cdb[7]));
		break;
	case READ_12:
	case WRITE_12:
		lba = be32toh(*(uint32_t *)(&cdb[2]));
		transfer_length = be32toh(*(uint32_t *)(&cdb[6]));
		break;
	case READ_16:
	case WRITE_16:
		lba = be64toh(*(uint64_t *)(&cdb[2]));
		transfer_length = be32toh(*(uint32_t *)(&cdb[10]));
		break;
	default:
		return 0;
	}

	if (!transfer_length)
		return 0;

	unaligned = is_unaligned_write(tdisk, lba, transfer_length);
	return unaligned ? 0 : 1;
}

static int
ctio_check_alloc(struct qsio_scsiio *ctio)
{
	struct tdisk *tdisk = ctio->ccb_h.tdisk;
	int retval;
	uint32_t num_blocks = 0;
	int dxfer_len, aligned;

	if (ctio->init_int != TARGET_INT_LOCAL)
		return 0;

	switch (ctio->cdb[0]) {
	case WRITE_6:
	case WRITE_10:
	case WRITE_12:
	case WRITE_16:
	case WRITE_SAME:
	case WRITE_SAME_16:
	case EXTENDED_COPY:
	case COMPARE_AND_WRITE:
		if (ctio->data_ptr)
			return 0;
		retval = ctio_write_length(ctio, tdisk, &num_blocks, &dxfer_len);  
		if (unlikely(retval != 0))
			goto err;

		if (!num_blocks)
			return 0;

		if (ctio_bio_aligned(ctio))
			aligned = is_aligned_write(ctio);
		else
			aligned = 0;

		if (aligned)
			retval = device_allocate_buffers_nopage(ctio, num_blocks, Q_NOWAIT);
		else
			retval = device_allocate_buffers(ctio, num_blocks, Q_NOWAIT);
		if (unlikely(retval != 0))
			goto err;
		ctio->dxfer_len = dxfer_len;
		if (aligned)
			ctio_map_bio(ctio);
		else
			copy_in_request_buffer(ctio);
		break;
	case MODE_SELECT_6:
	case MODE_SELECT_10:
	case PERSISTENT_RESERVE_OUT:
	case UNMAP:
		if (ctio->data_ptr)
			return 0;
		retval = device_allocate_cmd_buffers(ctio, Q_NOWAIT);
		if (unlikely(retval != 0))
			goto err;
		copy_in_request_buffer2(ctio);
		break;
	case READ_6:
	case READ_10:
	case READ_12:
	case READ_16:
		if (tdisk->remote || tdisk->enable_deduplication)
			return 0;
		if (!ctio_bio_aligned(ctio))
			return 0;
		if (!is_aligned_write(ctio))
			return 0;
		retval = ctio_write_length(ctio, tdisk, &num_blocks, &dxfer_len);  
		if (unlikely(retval != 0))
			goto err;
		if (!num_blocks)
			return 0;
		retval = device_allocate_buffers_nopage(ctio, num_blocks, Q_NOWAIT);
		if (unlikely(retval != 0))
			goto err;
		ctio_map_bio(ctio);
		return 0;
	default:
		return 0;
	}

	if (is_write_cmd(ctio))
		gdevq_write_insert(ctio->ccb_h.tdisk, ctio);

	return 0;
err:
	ctio_construct_sense(ctio, SSD_CURRENT_ERROR, SSD_KEY_HARDWARE_ERROR, 0, INTERNAL_TARGET_FAILURE_ASC, INTERNAL_TARGET_FAILURE_ASCQ);
	return -1;
}

/* process_queue returns only after draining the queue */
static void
devq_process_queue(void)
{
	struct qsio_hdr *ccb_h;
	struct qsio_scsiio *ctio;
	int retval;

	while ((ccb_h = get_next_ccb()) != NULL) {
		ctio = (struct qsio_scsiio *)(ccb_h);

		if (unlikely(ccb_h->flags & QSIO_CTIO_ABORTED)) {
			if (is_write_cmd(ctio))
				wait_for_pgdata((struct pgdata **)ctio->data_ptr, ctio->pglist_cnt);
			ctio_free_data(ctio);
			device_send_ccb(ctio);
			continue;
		}

		retval = ctio_check_alloc(ctio);
		if (retval != 0) {
			device_send_ccb(ctio);
			continue;
		}

		/* process the commands.  */
		if (((struct tdisk *)ccb_h->tdisk)->remote)
			node_client_proc_cmd(ccb_h->tdisk, ccb_h);
		else
			tdisk_proc_cmd(ccb_h->tdisk, ccb_h);
	}
}

static struct clone_data *
get_next_clone_data(void)
{
	struct clone_data *clone_data;

	if (STAILQ_EMPTY(&pending_tqueue))
		return NULL;

	chan_lock(tdevq_wait);
	clone_data = STAILQ_FIRST(&pending_tqueue);
	if (clone_data)
		STAILQ_REMOVE_HEAD(&pending_tqueue, c_list);
	chan_unlock(tdevq_wait);
	return clone_data;
}

static void
tdevq_process_queue(void)
{
	struct clone_data *clone_data;

	while ((clone_data = get_next_clone_data()) != NULL) {
		switch (clone_data->type) {
		case CLONE_DATA_CLONE:
			amap_clone_data(clone_data);
			break;
		case CLONE_DATA_MIRROR:
			amap_mirror_data(clone_data);
			break;
		case CLONE_DATA_DELETE:
			amap_delete_data(clone_data);
			break;
#if 0
		case CLONE_DATA_RESIZE:
			amap_resize_data(clone_data);
			break;
#endif
		default:
			debug_check(1);
		}
	}
}

static void
mdevq_process_queue(void)
{
	struct qsio_hdr *ccb_h;

	while ((ccb_h = get_next_master_ccb()) != NULL)
	{
		if (unlikely(ccb_h->flags & QSIO_CTIO_ABORTED)) {
			struct qsio_scsiio *ctio = (struct qsio_scsiio *)(ccb_h);
			if (is_write_cmd(ctio))
				wait_for_pgdata((struct pgdata **)ctio->data_ptr, ctio->pglist_cnt);
			ctio_free_data(ctio);
			device_send_ccb(ctio);
			atomic_dec(&mdevq_pending);
			continue;
		}

		/* process the commands.  */
		node_master_proc_cmd(ccb_h->tdisk, ccb_h);
		atomic_dec(&mdevq_pending);
	}
}

#ifdef FREEBSD 
static void devq_thread(void *data)
#else
static int devq_thread(void *data)
#endif
{
	struct qs_gdevq *devq;

	devq = (struct qs_gdevq *)data;
	__sched_prio(curthread, QS_PRIO_INOD);

	thread_start();

	for (;;)
	{
		wait_on_chan_interruptible(devq_wait, !STAILQ_EMPTY(&pending_queue) || kernel_thread_check(&devq->exit_flags, GDEVQ_EXIT));

		devq_process_queue();

		if (unlikely(kernel_thread_check(&devq->exit_flags, GDEVQ_EXIT)))
		{
			break;
		}
	}

	thread_end();
#ifdef FREEBSD 
	kproc_exit(0);
#else
	return 0;
#endif
}

#ifdef FREEBSD 
static void mdevq_thread(void *data)
#else
static int mdevq_thread(void *data)
#endif
{
	struct qs_gdevq *devq;

	devq = (struct qs_gdevq *)data;
	__sched_prio(curthread, QS_PRIO_INOD);

	thread_start();

	for (;;)
	{
		wait_on_chan_interruptible(mdevq_wait, !STAILQ_EMPTY(&master_pending_queue) || kernel_thread_check(&devq->exit_flags, GDEVQ_EXIT));

		mdevq_process_queue();

		if (unlikely(kernel_thread_check(&devq->exit_flags, GDEVQ_EXIT)))
		{
			break;
		}
	}

	thread_end();
#ifdef FREEBSD 
	kproc_exit(0);
#else
	return 0;
#endif
}

#ifdef FREEBSD 
static void tdevq_thread(void *data)
#else
static int tdevq_thread(void *data)
#endif
{
	struct qs_sdevq *devq;

	devq = (struct qs_sdevq *)data;
	__sched_prio(curthread, QS_PRIO_INOD);

	thread_start();

	for (;;)
	{
		wait_on_chan_interruptible(tdevq_wait, !STAILQ_EMPTY(&pending_tqueue) || kernel_thread_check(&devq->exit_flags, GDEVQ_EXIT));
		tdevq_process_queue();

		if (unlikely(kernel_thread_check(&devq->exit_flags, GDEVQ_EXIT))) {
			break;
		}
	}

	thread_end();
#ifdef FREEBSD 
	kproc_exit(0);
#else
	return 0;
#endif
}

#ifdef FREEBSD 
static void sdevq_thread(void *data)
#else
static int sdevq_thread(void *data)
#endif
{
	struct qs_sdevq *devq;

	devq = (struct qs_sdevq *)data;
	__sched_prio(curthread, QS_PRIO_INOD);

	for (;;)
	{
		wait_on_chan_interruptible(devq_write_wait, !STAILQ_EMPTY(&pending_write_queue) || kernel_thread_check(&devq->exit_flags, GDEVQ_EXIT));
		devq_process_write_queue();

		if (unlikely(kernel_thread_check(&devq->exit_flags, GDEVQ_EXIT)))
		{
			break;
		}
	}
#ifdef FREEBSD 
	kproc_exit(0);
#else
	return 0;
#endif
}

#ifdef FREEBSD 
static void ddevq_thread(void *data)
#else
static int ddevq_thread(void *data)
#endif
{
	struct qs_sdevq *devq;

	devq = (struct qs_sdevq *)data;
	__sched_prio(curthread, QS_PRIO_INOD);

	thread_start();

	for (;;)
	{
		wait_on_chan_interruptible(devq_dedupe_wait, !STAILQ_EMPTY(&pending_dedupe_queue) || kernel_thread_check(&devq->exit_flags, GDEVQ_EXIT));
		devq_process_dedupe_queue();

		if (unlikely(kernel_thread_check(&devq->exit_flags, GDEVQ_EXIT)))
		{
			break;
		}
	}

	thread_end();
#ifdef FREEBSD 
	kproc_exit(0);
#else
	return 0;
#endif
}

#ifdef FREEBSD 
static void cdevq_thread(void *data)
#else
static int cdevq_thread(void *data)
#endif
{
	struct qs_cdevq *devq;

	devq = (struct qs_cdevq *)data;
	__sched_prio(curthread, QS_PRIO_INOD);

	for (;;)
	{
		wait_on_chan_interruptible(devq_comp_wait, !STAILQ_EMPTY(&pending_comp_queue) || kernel_thread_check(&devq->exit_flags, GDEVQ_EXIT));
		devq_process_comp_queue(devq);

		if (unlikely(kernel_thread_check(&devq->exit_flags, GDEVQ_EXIT)))
		{
			break;
		}
	}
#ifdef FREEBSD 
	kproc_exit(0);
#else
	return 0;
#endif
}

static struct qs_gdevq *
init_devq(int id, void *thr_func, char *name)
{
	struct qs_gdevq *devq;
	int retval;

	devq = __uma_zalloc(gdevq_cache, Q_NOWAIT | Q_ZERO, sizeof(*devq));
	if (unlikely(!devq)) {
		debug_warn("Slab allocation failure\n");
		return NULL;
	}
	devq->id = id;

	retval = kernel_thread_create(thr_func, devq, devq->task, "%s_%d", name, id);
	if (unlikely(retval != 0)) {
		debug_warn("Failed to run devq\n");
		uma_zfree(gdevq_cache, devq);
		return NULL;
	}
	return devq;
}

static struct qs_sdevq *
init_sdevq(int id, void *thr_func, char *thr_fmt)
{
	struct qs_sdevq *devq;
	int retval;

	devq = zalloc(sizeof(struct qs_sdevq), M_SDEVQ, Q_NOWAIT);
	if (unlikely(!devq)) {
		debug_warn("Failed to allocate a new devq\n");
		return NULL;
	}
	devq->id = id;

	retval = kernel_thread_create(thr_func, devq, devq->task, thr_fmt, id);
	if (unlikely(retval != 0)) {
		debug_warn("Failed to run devq\n");
		free(devq, M_SDEVQ);
		return NULL;
	}
	return devq;
}

static struct qs_cdevq *
init_cdevq(int id)
{
	struct qs_cdevq *devq;
	int retval;

	devq = zalloc(sizeof(struct qs_cdevq), M_SDEVQ, Q_NOWAIT);
	if (unlikely(!devq)) {
		debug_warn("Failed to allocate a new devq\n");
		return NULL;
	}
	devq->id = id;

	retval = kernel_thread_create(cdevq_thread, devq, devq->task, "cdevq_%d", id);
	if (unlikely(retval != 0)) {
		debug_warn("Failed to run devq\n");
		free(devq, M_SDEVQ);
		return NULL;
	}
	return devq;
}

int
init_gdevq_threads(void)
{
	int i;
	struct qs_gdevq *devq;
	struct qs_sdevq *sdevq;
	struct qs_cdevq *cdevq;
	int cpu_count = get_cpu_count();

	devq_wait = wait_chan_alloc("gdevq wait");
	mdevq_wait = wait_chan_alloc("mdevq wait");
	tdevq_wait = wait_chan_alloc("tdevq wait");
	devq_write_wait = wait_chan_alloc("gdevq write wait");
	devq_comp_wait = wait_chan_alloc("gdevq comp wait");
	devq_dedupe_wait = wait_chan_alloc("gdevq dedupe wait");

	for (i = 0; i < cpu_count; i++) {
		sdevq = init_sdevq(i, sdevq_thread, "sdevq_%d");
		if (unlikely(!sdevq)) {
			debug_warn("Failed to init sdevq at i %d\n", i);
			return -1;
		}
		SLIST_INSERT_HEAD(&sdevq_list, sdevq, s_list);
	}

	for (i = 0; i < MAX_GDEVQ_THREADS; i++) {
		sdevq = init_sdevq(i, ddevq_thread, "ddevq_%d");
		if (unlikely(!sdevq)) {
			debug_warn("Failed to init ddevq at i %d\n", i);
			return -1;
		}
		SLIST_INSERT_HEAD(&ddevq_list, sdevq, s_list);
	}

	for (i = 0; i < MAX_GDEVQ_THREADS; i++) {
		sdevq = init_sdevq(i, tdevq_thread, "tdevq_%d");
		if (unlikely(!sdevq)) {
			debug_warn("Failed to init tdevq at i %d\n", i);
			return -1;
		}
		SLIST_INSERT_HEAD(&tdevq_list, sdevq, s_list);
	}

	for (i = 0; i < cpu_count; i++) {
		cdevq = init_cdevq(i);
		if (unlikely(!cdevq)) {
			debug_warn("Failed to init cdevq at i %d\n", i);
			return -1;
		}
		SLIST_INSERT_HEAD(&cdevq_list, cdevq, c_list);
	}

	for (i = 0; i < MAX_GDEVQ_THREADS; i++) {
		devq = init_devq(i, devq_thread, "gdevq");
		if (unlikely(!devq)) {
			debug_warn("Failed to init devq at i %d\n", i);
			return -1;
		}
		SLIST_INSERT_HEAD(&devq_list, devq, d_list);
	}

	for (i = 0; i < MAX_GDEVQ_THREADS; i++) {
		devq = init_devq(i, mdevq_thread, "mdevq");
		if (unlikely(!devq)) {
			debug_warn("Failed to init devq at i %d\n", i);
			return -1;
		}
		SLIST_INSERT_HEAD(&mdevq_list, devq, d_list);
	}
	return 0;
}

void
exit_gdevq_threads(void)
{
	struct qs_gdevq *devq;
	struct qs_sdevq *sdevq;
	struct qs_sdevq *ddevq;
	struct qs_cdevq *cdevq;
	int err;

	while ((devq = SLIST_FIRST(&devq_list)) != NULL) {
		SLIST_REMOVE_HEAD(&devq_list, d_list);
		err = kernel_thread_stop(devq->task, &devq->exit_flags, devq_wait, GDEVQ_EXIT);
		if (err) {
			debug_warn("Shutting down qs devq failed\n");
			continue;
		}
		uma_zfree(gdevq_cache, devq);
	}

	while ((devq = SLIST_FIRST(&mdevq_list)) != NULL) {
		SLIST_REMOVE_HEAD(&mdevq_list, d_list);
		err = kernel_thread_stop(devq->task, &devq->exit_flags, mdevq_wait, GDEVQ_EXIT);
		if (err) {
			debug_warn("Shutting down qs devq failed\n");
			continue;
		}
		uma_zfree(gdevq_cache, devq);
	}

	while ((ddevq = SLIST_FIRST(&ddevq_list)) != NULL) {
		SLIST_REMOVE_HEAD(&ddevq_list, s_list);
		err = kernel_thread_stop(ddevq->task, &ddevq->exit_flags, devq_dedupe_wait, GDEVQ_EXIT);
		if (err) {
			debug_warn("Shutting down qs ddevq failed\n");
			continue;
		}
		free(ddevq, M_SDEVQ);
	}

	while ((sdevq = SLIST_FIRST(&sdevq_list)) != NULL) {
		SLIST_REMOVE_HEAD(&sdevq_list, s_list);
		err = kernel_thread_stop(sdevq->task, &sdevq->exit_flags, devq_write_wait, GDEVQ_EXIT);
		if (err) {
			debug_warn("Shutting down qs sdevq failed\n");
			continue;
		}
		free(sdevq, M_SDEVQ);
	}

	while ((sdevq = SLIST_FIRST(&tdevq_list)) != NULL) {
		SLIST_REMOVE_HEAD(&tdevq_list, s_list);
		err = kernel_thread_stop(sdevq->task, &sdevq->exit_flags, tdevq_wait, GDEVQ_EXIT);
		if (err) {
			debug_warn("Shutting down qs sdevq failed\n");
			continue;
		}
		free(sdevq, M_SDEVQ);
	}

	while ((cdevq = SLIST_FIRST(&cdevq_list)) != NULL) {
		SLIST_REMOVE_HEAD(&cdevq_list, c_list);
		err = kernel_thread_stop(cdevq->task, &cdevq->exit_flags, devq_comp_wait, GDEVQ_EXIT);
		if (err) {
			debug_warn("Shutting down qs cdevq failed\n");
			continue;
		}
		free(cdevq, M_SDEVQ);
	}

	wait_chan_free(devq_wait);
	wait_chan_free(mdevq_wait);
	wait_chan_free(tdevq_wait);
	wait_chan_free(devq_write_wait);
	wait_chan_free(devq_comp_wait);
	wait_chan_free(devq_dedupe_wait);
}
