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

#include "ldev_geom.h"
#include "exportdefs.h"
#include "missingdefs.h"

mtx_t ldev_stats_lock;
static int ldev_new_device_cb(struct tdisk *newdevice);
static int ldev_update_device_cb(struct tdisk *newdevice, int tid, void *hpriv);
static int ldev_remove_device_cb(struct tdisk *removedevice, int tid, void *hpriv);
static void ldev_disable_device_cb(struct tdisk *removedevice, int tid, void *hpriv);

struct qs_interface_cbs icbs = {
	.new_device = ldev_new_device_cb,
	.update_device = ldev_update_device_cb,
	.remove_device = ldev_remove_device_cb,
	.disable_device = ldev_disable_device_cb,
	.interface = TARGET_INT_LOCAL,
};

MALLOC_DEFINE(M_LDEV, "ldev", "QUADStor ldev allocs");
struct g_class g_ldev_class = {
	.name = "QUADSTOR::LDEV",
	.version = G_VERSION,
};

DECLARE_GEOM_CLASS(g_ldev_class, g_ldev);
#ifdef ENABLE_STATS
uint32_t queue_jiffies;
uint32_t queue_ctio_jiffies;
uint32_t copy_write_jiffies;
uint32_t ctio_new_jiffies;
uint32_t copy_read_jiffies;

#define LDEV_TSTART(sjiff)	(sjiff = jiffies)
#define LDEV_TEND(count,sjiff)				\
do {								\
	mtx_lock(&ldev_stats_lock);				\
	count += (jiffies - sjiff);				\
	mtx_unlock(&ldev_stats_lock);				\
} while (0)

#define LDEV_INC(count,val)					\
do {									\
	mtx_lock(&ldev_stats_lock);				\
	count += val;						\
	mtx_unlock(&ldev_stats_lock);				\
} while (0)
#define PRINT_STAT(x,y)	printf(x" %llu \n", (unsigned long long)y); pause("psg", 10);
#else
#define LDEV_TSTART(sjiff)		do {} while (0)
#define LDEV_TEND(count,sjiff)		do {} while (0)
#define LDEV_INC(count,val)		do {} while (0)
#define PRINT_STAT(x,y)			do {} while (0)
#endif


static void 
copy_out_request_buffer(struct pgdata **pglist, int pglist_cnt, struct bio *bp)
{
	int i;
	uint32_t offset = 0, min_len;

	for (i = 0; i < pglist_cnt; i++) { 
		struct pgdata *pgtmp = pglist[i];
		min_len = min_t(int, pgtmp->pg_len, (bp->bio_length - offset));
		memcpy(bp->bio_data+offset, page_address(pgtmp->page) + pgtmp->pg_offset, min_len);
		offset += min_len;
	}
}

static void
ldev_send_ccb(void *ccb_void)
{
	struct qsio_scsiio *ctio = (struct qsio_scsiio *)ccb_void;
	struct vhba_priv *vhba_priv;
	struct bio *bp;
	struct ccb_list ctio_list;

	STAILQ_INIT(&ctio_list);
	(*icbs.device_remove_ctio)(ctio, &ctio_list);
	vhba_priv = &ctio->ccb_h.priv.vpriv;
	bp = vhba_priv->ccb;

	switch (ctio->scsi_status) {
	case SCSI_STATUS_OK:
		break;
	case SCSI_STATUS_RESERV_CONFLICT:
		g_io_deliver(bp, EPERM);
		goto send;
	case SCSI_STATUS_BUSY:
		g_io_deliver(bp, EAGAIN);
		goto send;
	case SCSI_STATUS_CHECK_COND:
	default:
		g_io_deliver(bp, EIO);
		goto send;
	}

	if (bp->bio_cmd == BIO_READ) {
		if (ctio->dxfer_len != bp->bio_length) {
			g_io_deliver(bp, EIO);
			goto send;
		}
		if (!ctio_norefs(ctio))
			copy_out_request_buffer((struct pgdata **)ctio->data_ptr, ctio->pglist_cnt, bp);
	}
	bp->bio_completed = bp->bio_length;
	g_io_deliver(bp, 0);

send:
	(*icbs.ctio_free_all)(ctio);
	(*icbs.device_queue_ctio_list)(&ctio_list);
}

struct unmap_block_descriptor {
	uint64_t lba;
	uint32_t num_blocks;
	uint32_t rsvd;
} __attribute__ ((__packed__));

static int 
create_unmap_request(struct qsio_scsiio *ctio, struct bio *bp, uint32_t lba_shift)
{
	uint8_t *ptr;
	struct unmap_block_descriptor *desc;
	int retval;

	retval = (*icbs.device_allocate_cmd_buffers)(ctio, Q_NOWAIT);
	if (unlikely(retval != 0))
		return -1;

	desc = (struct unmap_block_descriptor *)(ctio->data_ptr + 8);
	desc->lba = htobe64(bp->bio_offset >> lba_shift); 
	desc->num_blocks = htobe32(bp->bio_length >> lba_shift);
	ptr = ctio->data_ptr;
	*(uint16_t *)(ptr) = htobe16(6 + sizeof(*desc));
	*(uint16_t *)(ptr + 2) = htobe16(sizeof(*desc));
	return 0;
}

static inline void 
copy_in_request_buffer(struct pgdata **pglist, int pglist_cnt, struct bio *bp)
{
	int i;
	uint32_t offset = 0, min_len;

	for (i = 0; i < pglist_cnt; i++) { 
		struct pgdata *pgdata = pglist[i];
		min_len = min_t(int, pgdata->pg_len, (bp->bio_length - offset));
		memcpy(page_address(pgdata->page), bp->bio_data+offset, min_len);
		offset += min_len;
	}
}

static uint64_t t_prt;
static void
ldev_start(struct bio *bp)
{
	struct ldev_geom *ldev;
	struct tdisk *device;
	struct qsio_scsiio *ctio;
	struct vhba_priv *vhba_priv;
	uint8_t *cdb;
	uint64_t lba;
	uint32_t num_blocks;
	int retval;
#ifdef ENABLE_STATS
	uint32_t start_jiffies, tmp_jiffies;
#endif
	uint32_t lba_shift;

	ldev = bp->bio_to->geom->softc;
	if (atomic_read(&ldev->disabled)) {
		g_io_deliver(bp, EPERM);
		return;
	}

	switch (bp->bio_cmd) {
	case BIO_FLUSH:
	case BIO_READ:
	case BIO_WRITE:
	case BIO_DELETE:
		break;
	case BIO_GETATTR:
		if (g_handleattr_int(bp, "GEOM::candelete", 1)) {
			return;
		}
	default:
		g_io_deliver(bp, EOPNOTSUPP);
		return;
	}

	device = ldev->device;
	lba_shift = (*icbs.device_lba_shift)(device);
	if (bp->bio_cmd != BIO_FLUSH) {
		if ((lba_shift == LBA_SHIFT && (bp->bio_length & LBA_MASK)) || (bp->bio_length & 0x1FF)) {
			g_io_deliver(bp, EINVAL);
			return;
		}

		if (!bp->bio_length) {
			g_io_deliver(bp, 0);
			return;
		}
	}

	lba = bp->bio_offset >> lba_shift;
	num_blocks = bp->bio_length >> lba_shift;

	LDEV_TSTART(tmp_jiffies);
	ctio = (*icbs.ctio_new)(M_WAITOK);
	LDEV_TEND(ctio_new_jiffies, tmp_jiffies);

	if (unlikely(!t_prt))
		t_prt = (*icbs.get_tprt)();

	ctio->i_prt[0] = LDEV_HOST_ID;
	ctio->t_prt[0] = t_prt;
	ctio->init_int = TARGET_INT_LOCAL;
	ctio->r_prt = LDEV_RPORT_START;
	cdb = ctio->cdb;
	switch (bp->bio_cmd) {
	case BIO_WRITE:
		cdb[0] = WRITE_16;
		break;
	case BIO_READ:
		cdb[0] = READ_16;
		break;
	case BIO_FLUSH:
		cdb[0] = SYNCHRONIZE_CACHE;
		break;
	case BIO_DELETE:
		cdb[0] = UNMAP;
		break;
	}

	if (bp->bio_cmd != BIO_DELETE) {
		*(uint64_t *)(&cdb[2]) = htobe64(lba);
		*(uint32_t *)(&cdb[10]) = htobe32(num_blocks);
	}
	else {
		*(uint16_t *)(&cdb[7]) = htobe16(8 + sizeof(struct unmap_block_descriptor));
		retval = create_unmap_request(ctio, bp, lba_shift);
		if (retval != 0) {
			(*icbs.ctio_free_all)(ctio);
			g_io_deliver(bp, ENOMEM);
			return;
		}
	}

	ctio->ccb_h.flags = QSIO_DIR_OUT;
	ctio->ccb_h.tdisk = device;
	ctio->ccb_h.queue_fn = ldev_send_ccb;
	if (!(bp->bio_flags & BIO_ORDERED) && bp->bio_cmd != BIO_FLUSH)
		ctio->task_attr = MSG_SIMPLE_TASK;
	else
		ctio->task_attr = MSG_ORDERED_TASK;

	vhba_priv = &ctio->ccb_h.priv.vpriv;
	vhba_priv->ccb = bp;

	LDEV_TSTART(tmp_jiffies);
	(*icbs.device_queue_ctio)(device, ctio);
	LDEV_TEND(queue_ctio_jiffies, tmp_jiffies);

	LDEV_TEND(queue_jiffies, start_jiffies);
}

static int
ldev_access(struct g_provider *pp, int acr, int acw, int ace)
{
	return 0;
}

static void
ldev_disable_device_cb(struct tdisk *removedevice, int tid, void *hpriv)
{
	struct ldev_geom *ldev;

 	ldev = hpriv;
	if (ldev)
		atomic_set(&ldev->disabled, 1);
}

static int
ldev_remove_device_cb(struct tdisk *removedevice, int tid, void *hpriv)
{
	struct ldev_geom *ldev;
	struct g_provider *pp;

 	ldev = hpriv;
	if (!ldev)
		return -1;

	g_topology_lock();
	pp = ldev->pp;
	pp->private = NULL;
	g_wither_geom(pp->geom, ENXIO);
	g_topology_unlock();
	free(ldev, M_LDEV);

	return 0;
}

static int
ldev_update_device_cb(struct tdisk *newdevice, int tid, void *hpriv)
{
	struct ldev_geom *ldev;
	struct g_provider *pp;
	uint64_t end_lba;
	uint32_t lba_shift;

 	ldev = hpriv;
	if (!ldev)
		return 0;

	end_lba = (*icbs.device_end_lba)(newdevice);
	lba_shift = (*icbs.device_lba_shift)(newdevice);

	g_topology_lock();
	pp = ldev->pp;
	pp->mediasize = end_lba << lba_shift;
	pp->sectorsize = 1U << lba_shift;
	g_topology_unlock();
	return 0;
}

static int
ldev_new_device_cb(struct tdisk *newdevice)
{
	struct ldev_geom *ldev;
	struct g_provider *pp;
	struct g_geom *gp;
	uint64_t end_lba;
	uint32_t lba_shift;
	char *name;

	ldev = zalloc(sizeof(struct ldev_geom), M_LDEV, M_WAITOK);
	ldev->device = newdevice;

	g_topology_lock();

	name = (*icbs.device_name)(newdevice);
	gp = g_new_geomf(&g_ldev_class, "quadstor::ldev::%s", name);
	gp->softc = ldev;
	gp->start = ldev_start;
	gp->access = ldev_access;
	ldev->gp = gp;

	end_lba = (*icbs.device_end_lba)(newdevice);
	lba_shift = (*icbs.device_lba_shift)(newdevice);

	pp = g_new_providerf(gp, "quadstor/%s", name);
	pp->mediasize = end_lba << lba_shift;
	pp->sectorsize = 1U << lba_shift;
	g_error_provider(pp, 0);
	ldev->pp = pp;

	g_topology_unlock();
	(*icbs.device_set_hpriv)(newdevice, ldev);
	return 0;
}

static void
ldev_exit(void)
{
	PRINT_STAT("queue_jiffies", queue_jiffies);
	PRINT_STAT("queue_ctio_jiffies", queue_ctio_jiffies);
	PRINT_STAT("ctio_new_jiffies", ctio_new_jiffies);
	PRINT_STAT("copy_write_jiffies", copy_write_jiffies);
	device_unregister_interface(&icbs);
}

static int
ldev_init(void)
{
	int retval;

	mtx_lock_initt(&ldev_stats_lock, "qs ldev stats");
	retval = device_register_interface(&icbs);
	if (retval != 0)
		return -1;
	return 0;
}

static int
event_handler(struct module *module, int event, void *arg) {
	int retval = 0;
	switch (event) {
	case MOD_LOAD:
		retval = ldev_init();
		break;
	case MOD_UNLOAD:
		ldev_exit();
		break;
	default:
		retval = EOPNOTSUPP;
		break;
	}
        return retval;
}

static moduledata_t ldevmod_info = {
    "ldevmod",    /* module name */
     event_handler,  /* event handler */
     NULL            /* extra data */
};

DECLARE_MODULE(ldevmod, ldevmod_info, SI_SUB_DRIVERS, SI_ORDER_MIDDLE);
MODULE_DEPEND(ldevmod, tldev, 1, 1, 2);
