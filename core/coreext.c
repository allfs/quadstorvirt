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

/*
 * Core defs for other operating systems.
 */
#include "coreext.h"
#include "bdevmgr.h"
#include "tcache.h"

void
sys_memset(void *dest, int c, int size)
{
	unsigned char *s = dest;
	while (size--)
		*s++ = c;
}

void
bdev_sync(struct bdevint *bint)
{
	(*kcbs.bdev_sync)(bint->b_dev);
}

void
free(void *ptr, int mtype)
{
	(*kcbs.free)(ptr);
}

void * 
zalloc(size_t size, int type, int flags)
{
	return (*kcbs.zalloc)(size, type, flags);
}

static struct tpriv tpriv;

void
thread_start(void)
{
	(*kcbs.thread_start)(&tpriv);
	return;
}

void
thread_end(void)
{
	(*kcbs.thread_end)(&tpriv);
	return;
}

bio_t *
bio_get_new(struct bdevint *bint, void *end_bio_func, void *consumer, uint64_t b_start, int bio_vec_count, int rw)
{
	uint64_t bi_sector = BIO_SECTOR(b_start, bint->sector_shift);
	iodev_t *iodev = bint->b_dev;
	bio_t *bio;

	bio = (*kcbs.g_new_bio)(iodev, end_bio_func, consumer, bi_sector, bio_vec_count, rw);
	return bio; 
}

int
tcache_need_new_bio(struct tcache *tcache, bio_t *bio, uint64_t b_start, struct bdevint *bint, int stat)
{
	int nr_sectors;
	uint64_t bi_block;

	if (bint->b_dev != (*kcbs.bio_get_iodev)(bio)) {
#ifdef ENABLE_STATS
		if (stat)
			tcache->bint_misses++;
#endif
		return 1;
	}

	nr_sectors = (*kcbs.bio_get_nr_sectors)(bio);
	bi_block = BIO_SECTOR(b_start, bint->sector_shift);
	if ((((*kcbs.bio_get_start_sector)(bio)) + nr_sectors) != bi_block) {
#ifdef ENABLE_STATS
		if (stat) {
			debug_info("bi sector %llu nr sectors %d bi block %llu\n", (*kcbs.bio_get_start_sector)(bio), nr_sectors, bi_block);
			tcache->bstart_misses++;
		}
#endif
		return 1;
	}
	else
		return 0;
}
