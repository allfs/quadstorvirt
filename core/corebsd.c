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
#include "tcache.h"
#include "bdevmgr.h"
#include "node_sock.h"

MALLOC_DEFINE(M_QUADSTOR, "quads", "QUADStor allocations");
MALLOC_DEFINE(M_QSOCK, "quad sock", "QUADStor allocations");
MALLOC_DEFINE(M_CBS, "quad cbs", "QUADStor allocations");
MALLOC_DEFINE(M_SYNC_THR, "quad sync thr", "QUADStor allocations");
MALLOC_DEFINE(M_CLIENT_NODE, "quad client node", "QUADStor allocations");
MALLOC_DEFINE(M_CLONE_AMAP_TABLE, "quad clone amap table", "QUADStor allocations");
MALLOC_DEFINE(M_CLONE_AMAP, "quad clone amap", "QUADStor allocations");
MALLOC_DEFINE(M_CLONE_DATA, "quad clone data", "QUADStor allocations");
MALLOC_DEFINE(M_CLONE_THR, "quad clone thr", "QUADStor allocations");
MALLOC_DEFINE(M_CLONE_INFO, "quad clone info", "QUADStor allocations");
MALLOC_DEFINE(M_REPLICATION, "quad replication", "QUADStor allocations");
MALLOC_DEFINE(M_GROUP_BMAP, "quad group bmap", "QUADStor allocations");
MALLOC_DEFINE(M_WLIST, "quad wlist", "QUADStor allocations");
MALLOC_DEFINE(M_PGLIST, "quad pg list", "QUADStor allocations");
MALLOC_DEFINE(M_SENSEINFO, "quad sense info", "QUADStor allocations");
MALLOC_DEFINE(M_CTIODATA, "quad ctio data", "QUADStor allocations");
MALLOC_DEFINE(M_PAGE_LIST, "quad page list", "QUADStor allocations");
MALLOC_DEFINE(M_NODE_RMSG, "quad node rmsg", "QUADStor allocations");
MALLOC_DEFINE(M_BINDEX, "quad bindex", "QUADStor bindex allocations");
MALLOC_DEFINE(M_BINT, "quad bint", "QUADStor bint allocations");
MALLOC_DEFINE(M_BDEVGROUP, "quad bdevgroup", "QUADStor bdevgroup allocations");
MALLOC_DEFINE(M_BIOMETA, "quad biometa", "QUADStor biometa allocations");
MALLOC_DEFINE(M_RESERVATION, "quad reservation", "QUADStor reservation allocations");
MALLOC_DEFINE(M_RCACHE, "quad rcache", "QUADStor rcache allocations");
MALLOC_DEFINE(M_RCACHEBIO, "quad rcache bio", "QUADStor rcache bio allocations");
MALLOC_DEFINE(M_DEVQ, "quad devq", "QUADStor devq allocations");
MALLOC_DEFINE(M_SDEVQ, "quad sdevq", "QUADStor devq allocations");
MALLOC_DEFINE(M_SCSIREQUEST, "quad scsi request", "QUADStor scsi allocations");
MALLOC_DEFINE(M_SGLIST, "quad sglist", "QUADStor sglist allocations");
MALLOC_DEFINE(M_WRKMEM, "quad wrkmem", "QUADStor wrkmem allocations");
MALLOC_DEFINE(M_TABLEINDEX, "quad tdisk table index", "QUADStor allocations");
MALLOC_DEFINE(M_AMAPTABLEGROUP, "quad amaptable group", "QUADStor allocations");
MALLOC_DEFINE(M_INDEXGROUP, "quad indexgroup", "QUADStor allocations");
MALLOC_DEFINE(M_DDTABLE, "quad ddtable", "QUADStor allocations");
MALLOC_DEFINE(M_DDBLOCK_INFO, "quad ddblock info", "QUADStor allocations");
MALLOC_DEFINE(M_PGDATA_POST, "quad pgdata post", "QUADStor allocations");
MALLOC_DEFINE(M_LOG_INFO, "quad log info", "QUADStor allocations");
MALLOC_DEFINE(M_LOG_CONT, "quad log cont", "QUADStor allocations");
MALLOC_DEFINE(M_ECOPY, "quad ecopy", "QUADStor allocations");
int
tcache_need_new_bio(struct tcache *tcache, struct biot *biot, uint64_t b_start, struct bdevint *bint, int stat)
{
	if (biot->bint != bint) {
#ifdef ENABLE_STATS
		if (stat)
			tcache->bint_misses++;
#endif
		return 1;
	}

	if ((biot->b_start + (biot->dxfer_len >> bint->sector_shift)) != b_start) {
		debug_info("biot b_start %llu biot dxfer len %d b_start %llu\n", (unsigned long long)biot->b_start, biot->dxfer_len, (unsigned long long)b_start);
#ifdef ENABLE_STATS
		if (stat)
			tcache->bstart_misses++;
#endif
		return 1;
	}
	else {
		if (biot->dxfer_len & LBA_MASK)
			return 1;
		return 0;
	}
}

struct biot *
biot_alloc(struct bdevint *bint, uint64_t b_start, void *cache)
{
	struct biot *biot;

	biot = __uma_zalloc(biot_cache, Q_NOWAIT | Q_ZERO, sizeof(*biot));
	if (unlikely(!biot)) {
		debug_warn("Slab allocation failure\n");
		return NULL;
	}

	biot->pages = __uma_zalloc(biot_page_cache, Q_NOWAIT, ((MAXPHYS >> LBA_SHIFT) * sizeof(pagestruct_t *)));
	if (unlikely(!biot->pages)) {
		debug_warn("Slab allocation failure\n");
		uma_zfree(biot_cache, biot);
		return NULL;
	}

	biot->bint = bint;
	biot->b_start = b_start;
	biot->cache = cache;
	biot->max_pages = (MAXPHYS >> LBA_SHIFT);

	return biot;
}

struct bio *
bio_get_new(struct bdevint *bint, void *end_bio_func, void *consumer, uint64_t b_start, int bio_vec_count, int rw)
{
	struct bio *bio;

	bio = g_alloc_bio();
	bio->bio_offset = b_start << bint->sector_shift;
	bio->bio_done = end_bio_func;
	bio->bio_caller1 = consumer;
	bio_set_command(bio, rw);
	return bio;
}

int
biot_add_page(struct biot *biot, pagestruct_t *page, int pg_length)
{
	if ((biot->dxfer_len + pg_length) > MAXPHYS || (biot->page_count == biot->max_pages))
		return 0;

	biot->pages[biot->page_count] = page;
	biot->page_count++;
	biot->dxfer_len += pg_length;
	return pg_length;
}

int
bdev_unmap_support(iodev_t *iodev)
{
	return 1;
}

int
bio_unmap(iodev_t *iodev, void *cp, uint64_t block, uint32_t blocks, uint32_t shift, void *callback, void *priv)
{
	struct bio *bio;

	bio = g_alloc_bio();
	bio->bio_cmd = BIO_DELETE;
	bio->bio_offset = block << shift;
	bio->bio_done = callback;
	bio->bio_caller1 = priv;
	bio->bio_length = blocks << shift;
	bio->bio_bcount = bio->bio_length;
	g_io_request(bio, cp);
	return 0;
}
  
void
send_biot(struct biot *biot, int rw, void *endfn)
{
	struct bio *bio;

	bio = bio_get_new(biot->bint, endfn, biot, biot->b_start, 1, rw);
	if (biot->bio_data) {
		bio->bio_data = biot->bio_data;
	}
	else {
		while (!(biot->pbase = kmem_alloc_nofault(kernel_map, PAGE_SIZE * biot->page_count)))
			pause("psg", 10);
		pmap_qenter(biot->pbase, biot->pages, biot->page_count); 
		bio->bio_data = (caddr_t)(biot->pbase);
	}
	bio->bio_length = biot->dxfer_len;
	bio->bio_bcount = bio->bio_length;
	biot->bio = bio;
	g_io_request(bio, biot->bint->cp);
}

void
g_destroy_biot(struct biot *biot)
{
	if (biot->pbase) {
		pmap_qremove(biot->pbase, biot->page_count);
		kmem_free(kernel_map, biot->pbase, biot->page_count * PAGE_SIZE);
	}

	if (biot->bio_data)
		free(biot->bio_data, M_QUADSTOR);

	if (biot->pages)
		uma_zfree(biot_page_cache, biot->pages);

	if (biot->bio)
		g_destroy_bio(biot->bio);

	uma_zfree(biot_cache, biot);
}

static int
sock_setopt(sock_t *sys_sock, int level, int name, int opt)
{
	struct sockopt sopt;
	int retval;

	sopt.sopt_dir = SOPT_SET;
	sopt.sopt_level = level;
	sopt.sopt_name = name;
	sopt.sopt_val = (caddr_t)&opt;
	sopt.sopt_valsize = sizeof(opt);
	sopt.sopt_td = NULL;
	retval = sosetopt(sys_sock->sock, &sopt);
	return retval;
}

void
sock_nopush(sock_t *sys_sock, int set)
{
	sock_setopt(sys_sock, IPPROTO_TCP, TCP_NOPUSH, set);
}

sock_t *
sock_create(void *priv)
{
	sock_t *sys_sock;
	int retval;

	sys_sock = zalloc(sizeof(*sys_sock), M_QSOCK, M_WAITOK);

	retval = socreate(AF_INET, &sys_sock->sock, SOCK_STREAM, IPPROTO_TCP, curthread->td_ucred, curthread);
	if (unlikely(retval != 0)) {
		free(sys_sock, M_QSOCK);
		return NULL;
	}

	sys_sock->priv = priv;
	return sys_sock;
}

static inline void
uio_fill(struct uio *uio, struct iovec *iov, int iovcnt, ssize_t resid, int rw)
{
	uio->uio_iov = iov;
	uio->uio_iovcnt = iovcnt;
	uio->uio_offset = 0;
	uio->uio_resid = resid;
	uio->uio_rw = rw;
	uio->uio_segflg = UIO_SYSSPACE;
	uio->uio_td = curthread;
}

static inline void 
map_result(int *result, struct uio *uio, int len)
{
	int res = *result;

	if (res) {
		if (uio->uio_resid != len) {
			res = (len - uio->uio_resid);
		}
		else
			res = -(res);
	} else {
		res = len - uio->uio_resid;
		if (!res)
			res = -(EAGAIN);
	}
	*result = res;
}

int
sock_read(sock_t *sys_sock, void *buf, int len)
{
	struct uio uio;
	struct iovec iov[1];
	int res, flags = MSG_DONTWAIT | MSG_NOSIGNAL;

	iov[0].iov_base = buf;
	iov[0].iov_len = len;

	uio_fill(&uio, iov, 1, len, UIO_READ);
	res = soreceive(sys_sock->sock, NULL, &uio, NULL, NULL, &flags);
	map_result(&res, &uio, len);
	if (res > 0)
		return res;
	else if (res == -EAGAIN || res == -EINTR)
		return 0;
	else
		return res;
}

static int sock_write_avail(struct socket *so, void *arg, int waitflag)
{
	sock_t *sys_sock = arg;
	struct node_sock *node_sock = sys_sock->priv;

	if ((so->so_state & SS_ISCONNECTED) && node_sock->state != SOCK_STATE_CONNECTED) {
		node_sock_state_change(sys_sock->priv, SOCK_STATE_CONNECTED);
	}
	else if ((so->so_state & SS_ISDISCONNECTING || so->so_state & SS_ISDISCONNECTED) && node_sock->state != SOCK_STATE_CLOSED) {
		node_sock_state_change(sys_sock->priv, SOCK_STATE_CLOSED);
		return (SU_OK);
	}

	node_sock_write_avail(sys_sock->priv);
	return SU_OK;
}

static int sock_read_avail(struct socket *so, void *arg, int waitflag)
{
	sock_t *sys_sock = arg;
	struct node_sock *node_sock = sys_sock->priv;

	if ((so->so_state & SS_ISCONNECTED) && node_sock->state != SOCK_STATE_CONNECTED) {
		node_sock_state_change(sys_sock->priv, SOCK_STATE_CONNECTED);
	}
	else if ((so->so_state & SS_ISDISCONNECTING || so->so_state & SS_ISDISCONNECTED) && node_sock->state != SOCK_STATE_CLOSED) {
		node_sock_state_change(sys_sock->priv, SOCK_STATE_CLOSED);
		return (SU_OK);
	}

	if (so->so_rcv.sb_cc || !(so->so_rcv.sb_state & SBS_CANTRCVMORE))
		node_sock_read_avail(sys_sock->priv);

	return SU_OK;
}

int
sock_write(sock_t *sys_sock, void *buf, int len)
{
	struct uio uio;
	struct iovec iov[1];
	int res, flags = MSG_DONTWAIT | MSG_NOSIGNAL;

	iov[0].iov_base = buf;
	iov[0].iov_len = len;

	uio_fill(&uio, iov, 1, len, UIO_WRITE);
	res = sosend(sys_sock->sock, NULL, &uio, NULL, NULL, flags, curthread);
	map_result(&res, &uio, len);
	if (res > 0)
		return res;
	else if (res == -EAGAIN || res == -EINTR)
		return 0;
	else
		return res;
}

int
sock_write_page(sock_t *sys_sock, pagestruct_t *page, int offset, int len)
{
	return sock_write(sys_sock, vm_pg_address(page)+offset, len);
}

static void
sock_activate(sock_t *sys_sock)
{
	struct socket *so = sys_sock->sock;

	SOCK_LOCK(so);
	soupcall_set(so, SO_RCV, sock_read_avail, sys_sock);
	SOCK_UNLOCK(so);
	SOCKBUF_LOCK(&so->so_snd);
	soupcall_set(so, SO_SND, sock_write_avail, sys_sock);
	SOCKBUF_UNLOCK(&so->so_snd);
}

int
sock_bind(sock_t *sys_sock, uint32_t addr, uint16_t port)
{
	int retval;
	struct socket *sock = sys_sock->sock;
	struct sockaddr_in saddr_in;

	bzero(&saddr_in, sizeof(saddr_in));
	saddr_in.sin_len = sizeof(saddr_in);
	saddr_in.sin_family = AF_INET;
	saddr_in.sin_port = htons(port);
	saddr_in.sin_addr.s_addr = addr;
	sock_activate(sys_sock);

	retval = sock_setopt(sys_sock, SOL_SOCKET, SO_REUSEADDR, 1);
	if (retval != 0)
		return retval;

	retval = sobind(sock, (struct sockaddr *)&saddr_in, curthread);
	if (retval != 0)
		return retval;

	retval = solisten(sock, 1024, curthread);
	return retval; 
}

int
sock_connect(sock_t *sys_sock, uint32_t addr, uint32_t local_addr, uint16_t port)
{
	int retval;
	struct socket *sock = sys_sock->sock;
	struct sockaddr_in saddr_in;

	if (!local_addr || (local_addr == addr))
		goto skip_bind;

	bzero(&saddr_in, sizeof(saddr_in));
	saddr_in.sin_len = sizeof(saddr_in);
	saddr_in.sin_family = AF_INET;
	saddr_in.sin_addr.s_addr = local_addr;

	retval = sobind(sock, (struct sockaddr *)&saddr_in, curthread);
	if (retval != 0)
		return retval;

skip_bind:
	bzero(&saddr_in, sizeof(saddr_in));
	saddr_in.sin_len = sizeof(saddr_in);
	saddr_in.sin_family = AF_INET;
	saddr_in.sin_port = htons(port);
	saddr_in.sin_addr.s_addr = addr;

	sock_activate(sys_sock);
	retval = soconnect(sock, (struct sockaddr *)&saddr_in, curthread);
	if (retval != 0)
		return retval;
	sock_setopt(sys_sock, IPPROTO_TCP, TCP_NODELAY, 1);
	return 0;
}

sock_t *
sock_accept(sock_t *sys_sock, void *priv, int *error, uint32_t *ipaddr)
{
	struct socket *so;
	struct socket *head = sys_sock->sock;
	sock_t *new_sys_sock;
	struct sockaddr_in *saddr_in;

	new_sys_sock = zalloc(sizeof(*new_sys_sock), M_QSOCK, M_WAITOK);
	new_sys_sock->priv = priv;
	ACCEPT_LOCK();
	so = TAILQ_FIRST(&head->so_comp);
	if (!so) {
		ACCEPT_UNLOCK();
		free(new_sys_sock, M_QSOCK);
		return NULL;
	}
	new_sys_sock->sock = so;
	TAILQ_REMOVE(&head->so_comp, so, so_list);
	head->so_qlen--;
	SOCK_LOCK(so);
	so->so_qstate &= ~SQ_COMP;
	so->so_head = NULL;
	soref(so);
	soupcall_set(so, SO_RCV, sock_read_avail, new_sys_sock);
        so->so_state |= SS_NBIO;
        SOCK_UNLOCK(so);
	SOCKBUF_LOCK(&so->so_snd);
	soupcall_set(so, SO_SND, sock_write_avail, new_sys_sock);
	SOCKBUF_UNLOCK(&so->so_snd);
        ACCEPT_UNLOCK();
	soaccept(so, (struct sockaddr **)&new_sys_sock->saddr);
	saddr_in = (struct sockaddr_in *)(new_sys_sock->saddr);
	*ipaddr = saddr_in->sin_addr.s_addr;
	sock_setopt(new_sys_sock, IPPROTO_TCP, TCP_NODELAY, 1);
        return new_sys_sock;
}

void
sock_close(sock_t *sys_sock, int linger)
{
	struct socket *so = sys_sock->sock;

	if (!linger)
		sock_setopt(sys_sock, SOL_SOCKET, SO_LINGER, 0);

	SOCK_LOCK(so);
	soupcall_clear(so, SO_RCV);
	SOCK_UNLOCK(so);
	SOCKBUF_LOCK(&so->so_snd);
	soupcall_clear(so, SO_SND);
	SOCKBUF_UNLOCK(&so->so_snd);
	soshutdown(so, SHUT_WR|SHUT_RD);
	soclose(so);
}

void
sock_free(sock_t *sys_sock)
{
	if (sys_sock->saddr)
		free(sys_sock->saddr, M_SONAME);
	free(sys_sock, M_QSOCK);
}

int
sock_has_read_data(sock_t *sys_sock)
{
	struct file filetmp;
	int error, avail = 0;
	struct socket *so;
	struct node_sock *node_sock;

	filetmp.f_data = sys_sock->sock;
	filetmp.f_cred = NULL;

	error = soo_ioctl(&filetmp, FIONREAD, &avail, NULL, curthread);
	if (error)
		return 0;

	if (avail > 0)
		return avail;

	so = sys_sock->sock;
	node_sock = sys_sock->priv;
	if ((so->so_rcv.sb_state & SBS_CANTRCVMORE) && (node_sock->state == SOCK_STATE_CONNECTED))
                node_sock_state_change(node_sock, SOCK_STATE_CLOSED);

	return 0;
}

int
sock_has_write_space(sock_t *sys_sock)
{
	struct file filetmp;
	int error, avail = 0;

	filetmp.f_data = sys_sock->sock;
	filetmp.f_cred = NULL;

	error = soo_ioctl(&filetmp, FIONSPACE, &avail, NULL, curthread);
	if (error)
		return 0;

	return (avail > 0) ? 1 : 0; 
}

int
bio_get_command(struct bio *bio)
{
	if (bio->bio_cmd == BIO_READ)
		return QS_IO_READ;
	else
		return QS_IO_WRITE;
}

void
bio_set_command(struct bio *bio, int cmd)
{
	switch (cmd) {
	case QS_IO_READ:
		bio->bio_cmd = BIO_READ;
		break;
	case QS_IO_WRITE:
	case QS_IO_SYNC:
	case QS_IO_SYNC_FLUSH:
		bio->bio_cmd = BIO_WRITE;
		break;
	default:
		debug_check(1);
	}
}

void
__sched_prio(struct thread *thr, int prio)
{
	int set_prio = 0;

	switch (prio) {
	case QS_PRIO_SWP:
		set_prio = PSWP;
		break;
	case QS_PRIO_INOD:
		set_prio = PINOD;
		break;
	default:
		debug_check(1);
	}
	thread_lock(thr);
	sched_prio(thr, set_prio);
	thread_unlock(thr);
}

void kern_panic(char *msg)
{
	debug_check(1);
	panic(msg);
}

void
copy_in_request_buffer2(struct qsio_scsiio *ctio)
{
	debug_check(1);
}

int
ctio_bio_aligned(struct qsio_scsiio *ctio)
{
	struct vhba_priv *vhba_priv = &ctio->ccb_h.priv.vpriv;
	struct bio *bio = vhba_priv->ccb; 
	pagestruct_t *start, *end, *next;

	if (PAGE_SIZE != LBA_SIZE)
		return 0;

	if (bio->bio_length <= LBA_SIZE || bio->bio_length & LBA_MASK)
		return 0;

	if ((vm_offset_t)bio->bio_data & PAGE_MASK)
		return 0;

	start = virt_to_page(bio->bio_data);
	end = virt_to_page(bio->bio_data + (LBA_SIZE - 1));
	next = virt_to_page(bio->bio_data + LBA_SIZE);
	if (start != end || end == next)
		return 0;
	return 1;
}

void 
ctio_map_bio(struct qsio_scsiio *ctio)
{
	struct vhba_priv *vhba_priv = &ctio->ccb_h.priv.vpriv;
	struct bio *bp = vhba_priv->ccb; 
	struct pgdata **pglist = (struct pgdata **)ctio->data_ptr, *pgdata;
	int pglist_cnt = ctio->pglist_cnt;
	pagestruct_t *page;
	int offset, i;

	for (i = 0, offset = 0; i < pglist_cnt; i++, offset += LBA_SIZE) {
		page = virt_to_page(bp->bio_data + offset);
		pgdata = pglist[i];
		pgdata->page = page;
	}
	ctio_set_norefs(ctio);
}

void 
copy_in_request_buffer(struct qsio_scsiio *ctio)
{
	struct vhba_priv *vhba_priv = &ctio->ccb_h.priv.vpriv;
	struct bio *bp = vhba_priv->ccb; 
	struct pgdata **pglist = (struct pgdata **)ctio->data_ptr;
	int pglist_cnt = ctio->pglist_cnt, i;
	uint32_t offset = 0, min_len;

	for (i = 0; i < pglist_cnt; i++) { 
		struct pgdata *pgdata = pglist[i];
		min_len = min_t(int, pgdata->pg_len, (bp->bio_length - offset));
		memcpy(page_address(pgdata->page), bp->bio_data+offset, min_len);
		offset += min_len;
	}
}

#define kern_panic	panic
