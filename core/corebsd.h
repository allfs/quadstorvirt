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

#ifndef QS_COREBSD_H_
#define QS_COREBSD_H_

#include <sys/types.h>
#include <sys/systm.h>
#include <sys/param.h>
#include <sys/limits.h>
#include <sys/kernel.h>
#include <sys/lock.h>
#include <sys/sx.h>
#include <sys/mutex.h>
#include <sys/proc.h>
#include <sys/condvar.h>
#include <sys/queue.h>
#include <sys/bio.h>
#include <sys/stack.h>
#include <sys/kthread.h>
#include <sys/sched.h>
#include <sys/smp.h>
#include <sys/endian.h>
#include <sys/uio.h>
#include <sys/vnode.h>
#include <sys/fcntl.h>
#include <sys/mount.h>
#include <sys/namei.h>
#include <sys/socket.h>
#include <sys/sysproto.h>
#include <sys/socketvar.h>
#include <sys/file.h>
#include <sys/filio.h>
#include <sys/syscallsubr.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <vm/vm.h>
#include <vm/vm_kern.h>
#include <vm/vm_page.h>
#include <vm/uma.h>
#include <vm/vm_extern.h>
#include <geom/geom.h>
#include "asmdefs.h"
#include <cam/scsi/scsi_all.h>
#include <cam/scsi/scsi_da.h>
#include <cam/scsi/scsi_message.h>

typedef int allocflags_t;
typedef struct vm_page pagestruct_t;
typedef struct sx sx_t;
typedef struct mtx mtx_t;
typedef struct cv cv_t;
typedef struct uma_zone uma_t;
typedef struct vnode iodev_t;
typedef struct proc kproc_t;

#define __uma_zalloc(cachep, aflags, len)	uma_zalloc(cachep, aflags)
#define __uma_zdestroy(name, ucache)		uma_zdestroy(ucache)
#define sys_memset	memset

extern uma_t *chan_cache;
extern uma_t *compl_cache;
extern uma_t *sx_cache;
extern uma_t *mtx_cache;

#define Q_WAITOK	M_WAITOK
#define Q_NOWAIT	M_WAITOK
#define Q_NOWAIT_INTR	M_NOWAIT
#define Q_ZERO		M_ZERO

#ifdef CLANG_CHECK
void * zalloc(unsigned long size, struct malloc_type *type, int flags);
#else
static inline void * 
zalloc(unsigned long size, struct malloc_type *type, int flags)
{
	void *ptr;

	ptr = malloc(size, type, flags | Q_ZERO);
	return ptr;
}
#endif

static inline mtx_t *
mtx_alloc(char *name)
{
	mtx_t *mtx;

	mtx = __uma_zalloc(mtx_cache, Q_WAITOK | Q_ZERO, sizeof(*mtx));
	mtx_init(mtx, name, NULL, MTX_DEF);
	return mtx;
}

static inline void
mtx_lock_intr(mtx_t *mtx, unsigned long *flags)
{
	mtx_lock(mtx);
}

static inline void
mtx_unlock_intr(mtx_t *mtx, unsigned long *flags)
{
	mtx_unlock(mtx);
}

static inline void
mtx_free(mtx_t *mtx)
{
	uma_zfree(mtx_cache, mtx);
}

static inline sx_t *
sx_alloc(char *name)
{
	sx_t *sx;

	sx = __uma_zalloc(sx_cache, Q_WAITOK | Q_ZERO, sizeof(*sx));
	sx_init(sx, name);
	return sx;
}

static inline void
sx_free(sx_t *sx)
{
	uma_zfree(sx_cache, sx);
}

typedef struct wait_chan {
	struct mtx chan_lock;
	struct cv chan_cond;
} wait_chan_t;

typedef struct wait_compl {
	struct mtx chan_lock;
	struct cv chan_cond;
	int done;
} wait_compl_t;

static inline void
wait_chan_init(wait_chan_t *chan, const char *name)
{
	mtx_init(&chan->chan_lock, name, NULL, MTX_DEF);
	cv_init(&chan->chan_cond, name);
}

static inline wait_chan_t *
wait_chan_alloc(char *name)
{
	wait_chan_t *chan;

	chan = __uma_zalloc(chan_cache, Q_WAITOK | Q_ZERO, sizeof(*chan));
	wait_chan_init(chan, name);
	return chan;
}

static inline void
wait_compl_init(wait_compl_t *chan, const char *name)
{
	mtx_init(&chan->chan_lock, name, NULL, MTX_DEF);
	cv_init(&chan->chan_cond, name);
	chan->done = 0;
}

static inline wait_compl_t *
wait_completion_alloc(char *name)
{
	wait_compl_t *chan;

	chan = __uma_zalloc(compl_cache, Q_WAITOK | Q_ZERO, sizeof(*chan));
	wait_compl_init(chan, name);
	return chan;
}

static inline void
init_wait_completion(wait_compl_t *chan)
{
	mtx_lock(&chan->chan_lock);
	chan->done = 0;
	mtx_unlock(&chan->chan_lock);
}

static inline void
wait_chan_free(wait_chan_t *chan)
{
	uma_zfree(chan_cache, chan);
}

static inline void
wait_completion_free(wait_compl_t *chan)
{
	uma_zfree(compl_cache, chan);
}

#define wait_on_chan_locked(chn, condition)			\
do {								\
	while (!(condition)) {					\
		cv_wait(&chn->chan_cond, &chn->chan_lock);	\
	}							\
} while (0)

#define wait_on_chan(chn, condition)				\
do {								\
	mtx_lock(&chn->chan_lock);				\
	while (!(condition)) {					\
		cv_wait(&chn->chan_cond, &chn->chan_lock);	\
	}							\
	mtx_unlock(&chn->chan_lock);				\
} while (0)

#define wait_on_chan_timeout(chn, condition, timo)		\
({								\
	int __ret = 0, ___ret;						\
	mtx_lock(&chn->chan_lock);				\
	while (!(condition)) {					\
		__ret = cv_timedwait(&chn->chan_cond, &chn->chan_lock, timo);	\
		if (__ret)					\
			break;					\
	}							\
	mtx_unlock(&chn->chan_lock);				\
	___ret = !__ret;						\
	___ret;							\
})

#define wait_on_chan_interruptible(chn, condition)		\
do {								\
	int __ret = 0;						\
	mtx_lock(&chn->chan_lock);				\
	while (!(condition)) {					\
		__ret = cv_wait_sig(&chn->chan_cond, &chn->chan_lock);	\
		if (__ret)					\
			break;					\
	}							\
	mtx_unlock(&chn->chan_lock);				\
} while (0)

#define wait_on_chan_intr wait_on_chan

#define wait_on_chan_uncond(chan)				\
do {								\
	cv_wait(&chan->chan_cond, &chan->chan_lock);		\
} while (0)

static inline void
chan_wakeup_one(wait_chan_t *chan)
{
	mtx_lock(&chan->chan_lock);
	cv_signal(&chan->chan_cond);
	mtx_unlock(&chan->chan_lock);
}

#define chan_wakeup_unlocked(chn)	cv_broadcast(&(chn)->chan_cond)
#define chan_wakeup_one_unlocked(chn)	cv_signal(&(chn)->chan_cond)

static inline void
chan_wakeup(wait_chan_t *chan)
{
	mtx_lock(&chan->chan_lock);
	cv_broadcast(&chan->chan_cond);
	mtx_unlock(&chan->chan_lock);
}

#define chan_wakeup_nointr		chan_wakeup
#define chan_wakeup_one_nointr		chan_wakeup_one

static inline void
wait_complete(wait_compl_t *chan)
{
	mtx_lock(&chan->chan_lock);
	chan->done = 1;
	cv_signal(&chan->chan_cond);
	mtx_unlock(&chan->chan_lock);
}

static inline void
wait_complete_all(wait_compl_t *chan)
{
	mtx_lock(&chan->chan_lock);
	chan->done = 1;
	cv_broadcast(&chan->chan_cond);
	mtx_unlock(&chan->chan_lock);
}

#define wait_for_done(cmpl)	wait_on_chan((cmpl), (cmpl)->done)
#define wait_for_done_timeout(cmpl, timo)	wait_on_chan_timeout((cmpl), (cmpl)->done, timo)

typedef struct bio bio_t;

#ifdef DEBUG
#define debug_info	printf
#else
#define debug_info(fmt,args...)	do {} while (0)
#endif

#define debug_print(fmt,args...) printf("%s:%d " fmt, __FUNCTION__, __LINE__, ##args)
#define debug_warn(fmt,args...) printf("WARN: %s:%d " fmt, __FUNCTION__, __LINE__, ##args)
#define debug_check(x)				\
do {						\
	if ((x)) {				\
		struct stack st;		\
		printf("Warning at %s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__);		\
		stack_save(&st);		\
		stack_print(&st);		\
	}					\
} while (0)

int bio_get_command(struct bio *bio);
void bio_set_command(struct bio *bio, int cmd);

#define bio_get_length(b)	(b->bio_length)
#define bio_get_caller(b)	(b->bio_caller1)

static inline int 
bio_add_page(bio_t *bio, void *ptr, unsigned int len)
{
	bio->bio_data = ptr;
	bio->bio_length = len;
	bio->bio_bcount = bio->bio_length;
	return 0;
}

int bio_unmap(iodev_t *iodev, void *cp, uint64_t offset, uint32_t size, uint32_t shift, void *callback, void *priv);

int bdev_unmap_support(iodev_t *iodev);

#define vm_pg_address(pgad)	((caddr_t)(PHYS_TO_DMAP(VM_PAGE_TO_PHYS((vm_page_t)pgad))))

static inline pagestruct_t *
vm_pg_alloc(allocflags_t flags)
{
	pagestruct_t *__ret;
	__ret = vm_page_alloc(NULL, 0, VM_ALLOC_NOOBJ | VM_ALLOC_WIRED | flags);
	if (__ret && flags == VM_ALLOC_ZERO && !(__ret->flags & PG_ZERO))
		bzero(vm_pg_address(__ret), PAGE_SIZE);
	ALLOC_COUNTER_INC(pages_alloced);
	return __ret;
}

#if __FreeBSD_version < 900032
static inline void
vm_pg_free(pagestruct_t *pp)
{
	vm_page_lock_queues();
	vm_page_unwire(pp, 0);
	if (pp->wire_count == 0 && pp->object == NULL)
		vm_page_free(pp);
	vm_page_unlock_queues();
}
#else
static inline void
vm_pg_free(pagestruct_t *pp)
{
	vm_page_lock(pp);
	vm_page_lock_assert(pp, MA_OWNED);
	vm_page_unwire(pp, 0);
	if (pp->wire_count == 0 && pp->object == NULL) {
		vm_page_free(pp);
		ALLOC_COUNTER_INC(pages_freed);
	}
	vm_page_unlock(pp);
}
#endif

#if __FreeBSD_version < 900032
static inline void
vm_pg_ref(pagestruct_t *page)
{
	vm_page_lock_queues();
	vm_page_wire(page);
	ALLOC_COUNTER_INC(pages_refed);
	vm_page_unlock_queues();
}
#else
static inline void
vm_pg_ref(pagestruct_t *pp)
{
	vm_page_lock(pp);
	vm_page_lock_assert(pp, MA_OWNED);
	vm_page_wire(pp);
	ALLOC_COUNTER_INC(pages_refed);
	vm_page_unlock(pp);
}
#endif

static inline void
vm_pg_unref(pagestruct_t *page)
{
	vm_pg_free(page);
}

static inline void
bio_free_page(struct bio *bio)
{
	vm_pg_free(bio->bio_caller2);
}

static inline int
kernel_thread_check(int *flags, int bit)
{
	if (atomic_test_bit(bit, flags))
		return 1;
	else
		return 0;
}

#define kernel_thread_create(fn,dt,tsk,fmt,args...)		\
({								\
	int __ret = 0;						\
	__ret = kproc_create(fn,dt,&tsk,0,0,fmt,##args);	\
	__ret;							\
})

static inline int 
kernel_thread_stop(kproc_t *task, int *flags, wait_chan_t *chan, int bit)
{
	mtx_lock(&chan->chan_lock);
	atomic_set_bit(bit, flags);
	cv_broadcast(&chan->chan_cond);
	msleep(task, &chan->chan_lock, 0, "texit", 0);
	atomic_clear_bit(bit, flags);
	mtx_unlock(&chan->chan_lock);
	return 0;
}

#define chan_lock(chan)		mtx_lock(&(chan)->chan_lock)
#define chan_unlock(chan)	mtx_unlock(&(chan)->chan_lock)

static inline void
chan_lock_intr(wait_chan_t *chan, unsigned long *flags)
{
	chan_lock(chan);
}

static inline void
chan_unlock_intr(wait_chan_t *chan, unsigned long *flags)
{
	chan_unlock(chan);
}

typedef struct g_geom g_geom_t;
typedef struct g_consumer g_consumer_t;
struct bdevint;
struct biot;
struct tcache;
int tcache_need_new_bio(struct tcache *tcache, struct biot *biot, uint64_t b_start, struct bdevint *bint, int stat);

typedef struct biot {
	pagestruct_t **pages;
	vm_offset_t pbase;
	uint8_t *bio_data;
	struct bio *bio;
	void *cache;
	struct bdevint *bint;
	struct biot *comp_biot;
	uint64_t b_start;
	int dxfer_len;
	uint16_t page_count;
	uint16_t max_pages; 
	int comp_biot_offset;
	SLIST_ENTRY(biot) b_list;
} biot_t;

void __sched_prio(struct thread *thr, int prio);

static inline int
get_cpu_count(void)
{
	return mp_ncpus;
}

static inline uint64_t
get_availmem(void)
{
	return (physmem << PAGE_SHIFT);
}

void send_biot(struct biot *biot, int rw, void *endfn);
void g_destroy_biot(struct biot *biot);
struct biot * biot_alloc(struct bdevint *bint, uint64_t b_start, void *cache);
int biot_add_page(struct biot *biot, pagestruct_t *page, int pg_length);
struct bio * bio_get_new(struct bdevint *bint, void *end_bio_func, void *consumer, uint64_t b_start, int bio_vec_count, int rw);

static inline unsigned long 
get_current_time(void)
{
	uint32_t secs;
	struct bintime bt;

	bintime(&bt);
	secs = bt.sec;

	if (secs < EPOCH_2011)
		return 0;
	else
		return (secs - EPOCH_2011);
}

MALLOC_DECLARE(M_QUADSTOR);
MALLOC_DECLARE(M_CBS);
MALLOC_DECLARE(M_QSOCK);
MALLOC_DECLARE(M_SYNC_THR);
MALLOC_DECLARE(M_CLIENT_NODE);
MALLOC_DECLARE(M_CLONE_AMAP_TABLE);
MALLOC_DECLARE(M_CLONE_AMAP);
MALLOC_DECLARE(M_CLONE_DATA);
MALLOC_DECLARE(M_CLONE_THR);
MALLOC_DECLARE(M_CLONE_INFO);
MALLOC_DECLARE(M_REPLICATION);
MALLOC_DECLARE(M_GROUP_BMAP);
MALLOC_DECLARE(M_WLIST);
MALLOC_DECLARE(M_PAGE_LIST);
MALLOC_DECLARE(M_PGLIST);
MALLOC_DECLARE(M_SENSEINFO);
MALLOC_DECLARE(M_CTIODATA);
MALLOC_DECLARE(M_NODE_RMSG);
MALLOC_DECLARE(M_BINDEX);
MALLOC_DECLARE(M_BINT);
MALLOC_DECLARE(M_BDEVGROUP);
MALLOC_DECLARE(M_BIOMETA);
MALLOC_DECLARE(M_RESERVATION);
MALLOC_DECLARE(M_RCACHE);
MALLOC_DECLARE(M_RCACHEBIO);
MALLOC_DECLARE(M_RTRANS);
MALLOC_DECLARE(M_DEVQ);
MALLOC_DECLARE(M_SDEVQ);
MALLOC_DECLARE(M_SCSIREQUEST);
MALLOC_DECLARE(M_SGLIST);
MALLOC_DECLARE(M_WRKMEM);
MALLOC_DECLARE(M_TABLEINDEX);
MALLOC_DECLARE(M_AMAPTABLEGROUP);
MALLOC_DECLARE(M_INDEXGROUP);
MALLOC_DECLARE(M_DDTABLE);
MALLOC_DECLARE(M_DDBLOCK_INFO);
MALLOC_DECLARE(M_PGDATA_POST);
MALLOC_DECLARE(M_LOG_INFO);
MALLOC_DECLARE(M_LOG_CONT);
MALLOC_DECLARE(M_ECOPY);

#define processor_yield	uio_yield
struct tpriv;
static inline void
bdev_start(iodev_t *iodev, struct tpriv *tpriv) { }
static inline void
bdev_marker(iodev_t *iodev, struct tpriv *tpriv) { }

#define thread_start()	do {} while(0)
#define thread_end()	do {} while(0)
#define msecs_to_ticks(ms)	(((ms)*hz)/1000)
#define ticks_to_msecs(t)	(1000*(t) / hz)

typedef struct sys_sock {
	struct socket *sock;
	struct sockaddr *saddr;
	int saddr_len;
	void *priv;
	void *state_change;
	void *data_ready;
	void *write_space;
} sock_t;

sock_t* sock_create(void *priv);
int sock_read(sock_t *sock, void *buf, int len);
int sock_write(sock_t *sock, void *buf, int len);
int sock_write_page(sock_t *sock, pagestruct_t *page, int offset, int len);
sock_t * sock_accept(sock_t *sys_sock, void *priv, int *error, uint32_t *ipaddr);
int sock_connect(sock_t *sys_sock, uint32_t addr, uint32_t local_addr, uint16_t port);
int sock_bind(sock_t *sys_sock, uint32_t addr, uint16_t port);
void sock_close(sock_t *sys_sock, int linger);
void sock_free(sock_t *sys_sock);
int sock_has_write_space(sock_t *sys_sock);
int sock_has_read_data(sock_t *sys_sock);
void sock_nopush(sock_t *sys_sock, int set);
void kern_panic(char *msg);
struct qsio_scsiio;

#define sx_xlocked_check(lk)	((sx_xholder((lk)) == curthread))

#if __FreeBSD_version >= 900032
#define uio_yield()	kern_yield(PRI_UNCHANGED)
#endif

#define page_address(pgad)	((caddr_t)(PHYS_TO_DMAP(VM_PAGE_TO_PHYS((vm_page_t)pgad))))
#define virt_to_page(x)		PHYS_TO_VM_PAGE(vtophys((x)))

int ctio_bio_aligned(struct qsio_scsiio *ctio);
void ctio_map_bio(struct qsio_scsiio *ctio);
void copy_in_request_buffer(struct qsio_scsiio *ctio);
void copy_in_request_buffer2(struct qsio_scsiio *ctio);

#endif
