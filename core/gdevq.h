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

#ifndef QUADSTOR_GDEVQ_H_
#define QUADSTOR_GDEVQ_H_

#include "coredefs.h"
#include "tdisk.h"
#include "lzfP.h"

#define MAX_GDEVQ_THREADS		256
//#define MAX_GDEVQ_THREADS		4

struct qs_gdevq {
	kproc_t *task;
	SLIST_ENTRY(qs_gdevq) d_list;
	int exit_flags;
	int id;
};

struct qs_sdevq {
	kproc_t *task;
	SLIST_ENTRY(qs_sdevq) s_list;
	int exit_flags;
	int id;
};

struct qs_cdevq {
	uint8_t wrkmem[sizeof(LZF_STATE)];
	kproc_t *task;
	SLIST_ENTRY(qs_cdevq) c_list;
	int exit_flags;
	int id;
};

#define GDEVQ_EXIT		0x02

extern struct ccb_list pending_queue;
extern struct ccb_list master_pending_queue;
extern struct clone_data_list pending_tqueue;
extern struct pgdata_wlist pending_write_queue;
extern struct pgdata_wlist pending_comp_queue;
extern struct ddqueue_wlist pending_dedupe_queue;
extern wait_chan_t *devq_wait;
extern wait_chan_t *mdevq_wait;
extern wait_chan_t *tdevq_wait;
extern wait_chan_t *devq_write_wait;
extern wait_chan_t *devq_dedupe_wait;
extern wait_chan_t *devq_comp_wait;

void mdevq_wait_for_empty(void);

static inline void 
device_send_ccb(struct qsio_scsiio *ctio)
{
	struct qsio_hdr *ccb_h;
	int norefs = ctio_norefs(ctio);
	/* Basically call the *_send_ccb function for the ccb */

	ccb_h = &ctio->ccb_h;
	ctio->ccb_h.flags = QSIO_DIR_IN | QSIO_SEND_STATUS | QSIO_TYPE_CTIO;
	if (ctio->dxfer_len)
		ctio->ccb_h.flags |= QSIO_DATA_DIR_IN;
	if (norefs)
		ctio_set_norefs(ctio);
 
	(*ccb_h->queue_fn)(ctio);
}

static inline void
wait_for_pgdata(struct pgdata **pglist, int pglist_cnt)
{
	struct pgdata *pgdata;
	int i;

	for (i = 0; i < pglist_cnt; i++) {
		pgdata = pglist[i];
		wait_for_done(pgdata->completion);
	}
}

static inline void
mark_complete(struct pgdata *pgdata)
{
	pgdata->completion->done = 1;
	atomic_set_bit(PGDATA_HASH_CHECK_DONE, &pgdata->flags);
}

static inline void
gdevq_write_insert(struct tdisk *tdisk, struct qsio_scsiio *ctio)
{
	int i;
	struct pgdata *pgdata;
	struct pgdata **pglist;
	int enable_deduplication = tdisk->enable_deduplication;

	pglist = (struct pgdata **)(ctio->data_ptr);
	if (!enable_deduplication) {
		for (i = 0; i < ctio->pglist_cnt; i++) {
			pgdata = pglist[i];
			atomic_set_bit(DDBLOCK_DEDUPE_DISABLED, &pgdata->flags);
			mark_complete(pgdata);
		}
		return;
	}

	chan_lock(devq_write_wait);
	for (i = 0; i < ctio->pglist_cnt; i++) {
		pgdata = pglist[i];
		STAILQ_INSERT_TAIL(&pending_write_queue, pgdata, w_list);
	}
	chan_wakeup_unlocked(devq_write_wait);
	chan_unlock(devq_write_wait);
}

static inline void
gdevq_comp_insert(struct pgdata *pgdata)
{
	init_wait_completion(pgdata->completion);
	atomic_set_bit(PGDATA_COMP_ENABLED, &pgdata->flags);
	chan_lock(devq_comp_wait);
	STAILQ_INSERT_TAIL(&pending_comp_queue, pgdata, w_list);
	chan_wakeup_one_unlocked(devq_comp_wait);
	chan_unlock(devq_comp_wait);
}

#define ctio_clustered(cto)		((cto)->ccb_h.flags & QSIO_CLUSTERED)

static inline int
is_write_cmd(struct qsio_scsiio *ctio)
{
	switch (ctio->cdb[0]) {
		case WRITE_6:
		case WRITE_10:
		case WRITE_12:
		case WRITE_16:
		case COMPARE_AND_WRITE:
			return 1;
	}
	return 0;
}

static inline void
mdevq_insert_ccb(struct qsio_hdr *ccb_h)
{
	struct qsio_scsiio *ctio = (struct qsio_scsiio *)(ccb_h);

	chan_lock(mdevq_wait);
	ctio->ccb_h.flags |= QSIO_IN_DEVQ;
	STAILQ_INSERT_TAIL(&master_pending_queue, ccb_h, c_list);
	chan_wakeup_one_unlocked(mdevq_wait);
	chan_unlock(mdevq_wait);
}

static inline void
gdevq_insert_ccb(struct qsio_hdr *ccb_h)
{
	struct qsio_scsiio *ctio = (struct qsio_scsiio *)(ccb_h);

	if (ctio_clustered(ctio)) {
		mdevq_insert_ccb(ccb_h);
		return;
	}

	if (ctio->init_int != TARGET_INT_LOCAL && is_write_cmd(ctio))
		gdevq_write_insert(ccb_h->tdisk, ctio);
	chan_lock(devq_wait);
	ctio->ccb_h.flags |= QSIO_IN_DEVQ;
	STAILQ_INSERT_TAIL(&pending_queue, ccb_h, c_list);
	chan_wakeup_one_unlocked(devq_wait);
	chan_unlock(devq_wait);
	return;
}

int init_gdevq_threads(void);
void exit_gdevq_threads(void);
int gdevq_abort_task(uint64_t i_prt[], uint64_t t_prt[], uint8_t init_int, uint32_t task_tag);
void gdevq_abort_tasks(struct tdisk *tdisk, uint64_t i_prt[], uint64_t t_prt[], uint8_t init_int);
void gdevq_abort_tasks_other_initiators(uint64_t i_prt[], uint64_t t_prt[], uint8_t init_int);
void gdevq_abort_tasks_for_initiator(uint64_t i_prt[], uint64_t t_prt[], uint8_t init_int);
void mdevq_abort_tasks(struct tdisk *tdisk, uint64_t i_prt[], uint64_t t_prt[], uint8_t init_int);

struct ddqueue {
	struct tdisk *tdisk;
	struct pgdata *pgdata;
	struct write_list *wlist;
	STAILQ_ENTRY(ddqueue) q_list;
};
STAILQ_HEAD(ddqueue_wlist, ddqueue);

static inline void
gdevq_dedupe_insert(struct tdisk *tdisk, struct pgdata *pgdata, struct write_list *wlist)
{
	struct ddqueue *ddqueue;

	ddqueue = __uma_zalloc(ddqueue_cache, Q_WAITOK, sizeof(*ddqueue));
	ddqueue->pgdata = pgdata;
	ddqueue->wlist = wlist;
	ddqueue->tdisk = tdisk;

	init_wait_completion(pgdata->completion);
	chan_lock(devq_dedupe_wait);
	STAILQ_INSERT_TAIL(&pending_dedupe_queue, ddqueue, q_list);
	chan_wakeup_one_unlocked(devq_dedupe_wait);
	chan_unlock(devq_dedupe_wait);
}

static inline void
clone_data_insert(struct clone_data *clone_data, struct clone_data_list *queue_list)
{
	chan_lock(tdevq_wait);
	STAILQ_INSERT_TAIL(&pending_tqueue, clone_data, c_list);
	STAILQ_INSERT_TAIL(queue_list, clone_data, q_list);
	chan_wakeup_one_unlocked(tdevq_wait);
	chan_unlock(tdevq_wait);
}
#endif
