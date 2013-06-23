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

#include "tcache.h"
#include "bdevmgr.h"

struct tcache *
tcache_alloc(int bio_count)
{
	struct tcache *tcache;

	tcache = __uma_zalloc(tcache_cache, Q_WAITOK | Q_ZERO, sizeof(*tcache)); 
	atomic_set(&tcache->refs, 1);
	tcache->completion = wait_completion_alloc("tcache compl");
	SLIST_INIT(&tcache->priv.meta_list);
	SLIST_INIT(&tcache->io_waiters);
#ifdef FREEBSD
	tcache->bio_list = zalloc((bio_count * sizeof(struct biot *)), M_RCACHEBIO, Q_WAITOK);
	SLIST_INIT(&tcache->biot_list);
#else
	tcache->bio_list = zalloc((bio_count * sizeof(struct bio *)), M_RCACHEBIO, Q_WAITOK);
#endif
	tcache->bio_count = bio_count;
	return tcache;
}

#ifdef FREEBSD
void
tcache_free_pages(struct tcache *tcache)
{
	int i;
	pagestruct_t *page;

	for (i = 0; i < tcache->bio_count; i++)
	{
		struct biot *biot;
		int j;

		biot = tcache->bio_list[i];
		if (!biot)
			break;

		for (j = 0; j < biot->page_count; j++) {
			page = biot->pages[j];
			vm_pg_free(page);
		}
	}
}
#else
void
tcache_free_pages(struct tcache *tcache)
{
	int i;

	for (i = 0; i < tcache->bio_count; i++)
	{
		bio_t *bio;

		bio = tcache->bio_list[i];
		if (!bio)
			break;
		bio_free_pages(bio);
	}
}
#endif

void
tcache_free(struct tcache *tcache)
{
	int i;
#ifdef FREEBSD
	struct biot *biot;
#endif

	for (i = 0; i < tcache->bio_count; i++)
	{
		if (!tcache->bio_list[i])
			break;
#ifdef FREEBSD
		g_destroy_biot(tcache->bio_list[i]);
#else
		g_destroy_bio(tcache->bio_list[i]);
#endif
	}

#ifdef FREEBSD
	while ((biot = SLIST_FIRST(&tcache->biot_list)) != NULL) {
		SLIST_REMOVE_HEAD(&tcache->biot_list, b_list);
		g_destroy_biot(biot);
	}
#endif

	free(tcache->bio_list, M_RCACHEBIO);
	wait_completion_free(tcache->completion);
	if (tcache->tcache_lock)
		mtx_free(tcache->tcache_lock);
	uma_zfree(tcache_cache, tcache);
}

#ifdef FREEBSD 
void tcache_end_bio(struct bio *bio)
#else
void tcache_end_bio(struct bio *bio, int err)
#endif
{
	struct tcache *tcache;
#ifdef FREEBSD
	int err = bio->bio_error;
	struct biot *biot = (struct biot *)bio_get_caller(bio);
#endif

#ifdef FREEBSD
	tcache = biot->cache;
#else
	tcache = (struct tcache *)bio_get_caller(bio);
#endif

	if (unlikely(err))
		atomic_set_bit_short(TCACHE_IO_ERROR, &tcache->flags);

	if (!(atomic_dec_and_test(&tcache->bio_remain)))
		return;

	wait_complete(tcache->completion);
	tcache_put(tcache);
}

#ifdef FREEBSD
static struct biot *
#else
static struct bio *
#endif
tcache_bio_locate(struct tcache *tcache, uint64_t b_start, struct bdevint *bint)
{
#ifdef FREEBSD
	struct biot *bio = NULL;
#else
	struct bio *bio = NULL;
#endif
	int i;
	int count = atomic_read(&tcache->bio_remain);

	for (i = 0; i < count; i++) {
		bio = tcache->bio_list[i];
		if (!tcache_need_new_bio(tcache, bio, b_start, bint, 0))
			break;
	}
	return bio;
}

int
__tcache_add_page(struct tcache *tcache, pagestruct_t *page, uint64_t b_start, struct bdevint *bint, int size, int rw, void *end_bio)
{
#ifdef FREEBSD
	struct biot *bio = NULL;
#else
	struct bio *bio = NULL;
	uint32_t max_pages;
#endif
	int retval;

	if (rw == QS_IO_WRITE)
		bio = tcache->bio_list[tcache->last_idx];
	else 
		bio = tcache_bio_locate(tcache, b_start, bint);

	if (bio && tcache_need_new_bio(tcache, bio, b_start, bint, 1)) {
		tcache->last_idx++;
		bio = NULL;
	}

	if (tcache->last_idx >= tcache->bio_count) {
		debug_warn("last idx %d bio count %d bio remain %d\n", tcache->last_idx, tcache->bio_count, atomic_read(&tcache->bio_remain));
		debug_check(1);
		return -1;
	}
again:
	if (!bio) {
#ifdef FREEBSD
		bio = biot_alloc(bint, b_start, tcache);
#else
		max_pages = min_t(int, tcache->bio_count - tcache->pages, bio_get_max_pages(bint->b_dev));
		if (unlikely(max_pages <= 0))
			max_pages = 32;
		bio = bio_get_new(bint, end_bio, tcache, b_start, max_pages, rw);
#endif
		if (unlikely(!bio)) {
			return -1;
		}

		tcache->bio_list[tcache->last_idx] = bio;
		atomic_inc(&tcache->bio_remain);
	}

#ifdef FREEBSD
	retval = biot_add_page(bio, page, size);
#else
	retval = bio_add_page(bio, page, size, 0); 
#endif
	if (unlikely(retval != size)) {
#ifndef FREEBSD 
		if (unlikely(!bio_get_length(bio)))
			return -1;
#endif
		tcache->last_idx++;

#ifdef ENABLE_STATS
		tcache->page_misses++;
#endif
		bio = NULL;
		goto again;
	}
	tcache->pages++;
	return 0;
}

int
tcache_add_page(struct tcache *tcache, pagestruct_t *page, uint64_t b_start, struct bdevint *bint, int size, int rw)
{
	return __tcache_add_page(tcache, page, b_start, bint, size, rw, tcache_end_bio);
}

void
tcache_read_comp(struct tcache *tcache)
{
#ifdef FREEBSD
	struct biot *biot, *comp_biot;
	int i;

	if (!atomic_test_bit(TCACHE_COMP_BIOT, &tcache->flags))
		return;

	for (i = 0; i < tcache->bio_count; i++) {
		biot = tcache->bio_list[i];
		if (!biot)
			break;
		comp_biot = biot->comp_biot;
		if (!comp_biot)
			continue;
		memcpy(vm_pg_address(biot->pages[0]), comp_biot->bio_data + biot->comp_biot_offset, biot->dxfer_len); 
	}
#endif
}

#ifdef FREEBSD
static inline void
bint_unplug(struct bdevint *bint)
{
	if (bint->write_cache != WRITE_CACHE_DEFAULT)
		g_io_flush(bint->cp);
}

static struct biot *
tcache_check_comp(struct tcache *tcache, int *ret_idx, int bio_count, int rw)
{
	int i = *ret_idx, j;
	struct biot *biot, *prev, *start, *comp_biot;
	uint8_t *bio_data;
	int dxfer_len = 0, offset;

	start = prev = tcache->bio_list[i++];
	for (j = i; j < bio_count; j++) {
		biot = tcache->bio_list[j];
		if (biot->bint != prev->bint)
			break;
		if (biot->dxfer_len >= LBA_SIZE || biot->page_count != 1)
			break;
		if ((prev->b_start + (prev->dxfer_len >> prev->bint->sector_shift)) != biot->b_start)
			break;
		if ((dxfer_len + biot->dxfer_len + start->dxfer_len) > MAXPHYS)
			break;
		dxfer_len += biot->dxfer_len;
		prev = biot;
	}

	if (!dxfer_len)
		return 0;

	dxfer_len += start->dxfer_len;

	bio_data = malloc(dxfer_len, M_QUADSTOR, M_WAITOK);
	comp_biot = biot_alloc(start->bint, start->b_start, tcache);
	comp_biot->bio_data = bio_data;
	comp_biot->dxfer_len = dxfer_len;
	offset = 0;
	atomic_inc(&tcache->bio_remain);
	for (i = *ret_idx; i < j; i++) {
		biot = tcache->bio_list[i];
		if (rw == QS_IO_WRITE)
			memcpy(bio_data + offset, vm_pg_address(biot->pages[0]), biot->dxfer_len);
		else {
			biot->comp_biot = comp_biot;
			biot->comp_biot_offset = offset;
		}
		atomic_dec(&tcache->bio_remain);
		offset += biot->dxfer_len;
	}
	atomic_set_bit(TCACHE_COMP_BIOT, &tcache->flags);

	*ret_idx = i - 1;
	SLIST_INSERT_HEAD(&tcache->biot_list, comp_biot, b_list);
	return comp_biot;
}

void
__tcache_entry_rw(struct tcache *tcache, int rw, void *end_bio)
{
	int i, count;
	struct bdevint *prev_b_dev = NULL, *b_dev;
	int log = atomic_test_bit(TCACHE_LOG_WRITE, &tcache->flags);

	tcache_get(tcache);
	count = atomic_read(&tcache->bio_remain);
	for (i = 0; i < count; i++)
	{
		struct biot *bio = tcache->bio_list[i];
		struct biot *comp_bio = NULL;

		if (bio->dxfer_len < LBA_SIZE) {
			comp_bio = tcache_check_comp(tcache, &i, count, rw);
			if (comp_bio)
				bio = comp_bio;
		}

		b_dev = bio->bint;
		send_biot(bio, rw, end_bio);
		if (log && prev_b_dev && (b_dev != prev_b_dev)) {
			bint_unplug(prev_b_dev);
		}
		prev_b_dev = b_dev;
	}

	if (log && prev_b_dev) {
		bint_unplug(prev_b_dev);
	}
}
void
tcache_entry_rw(struct tcache *tcache, int rw)
{
	__tcache_entry_rw(tcache, rw, tcache_end_bio);
}
#else
void
__tcache_entry_rw(struct tcache *tcache, int rw, void *end_bio)
{
	tcache_entry_rw(tcache, rw);
}

void
tcache_entry_rw(struct tcache *tcache, int rw)
{
	int i;
	iodev_t *prev_b_dev = NULL, *b_dev;
	int count;
	struct tpriv priv = { 0 };
	int log = atomic_test_bit_short(TCACHE_LOG_WRITE, &tcache->flags);

	bzero(&priv, sizeof(priv));
	tcache_get(tcache);
	count = atomic_read(&tcache->bio_remain);
	for (i = 0; i < count; i++) {
		struct bio *bio = tcache->bio_list[i];

		b_dev = send_bio(bio);
		if (prev_b_dev && ((b_dev != prev_b_dev) || log)) {
			if (!priv.data || log) {
				bdev_start(prev_b_dev, &priv);
				bdev_marker(b_dev, &priv);
			}
		}
		else if (!prev_b_dev) {
			bdev_marker(b_dev, &priv);
		}
		prev_b_dev = b_dev;
	}

	if (prev_b_dev) {
		bdev_start(prev_b_dev, &priv);
	}
}
#endif
