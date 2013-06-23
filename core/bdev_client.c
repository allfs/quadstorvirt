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
#include "ddtable.h"
#include "fastlog.h"
#include "bdevgroup.h"

int
bdev_remove_stub(struct bdev_info *binfo)
{
	struct bdevint *bint;

	sx_xlock(gchain_lock);
	bint = bint_list[binfo->bid];
	if (!bint) {
		sx_xunlock(gchain_lock);
		return 0;
	}

	if (bint->log_disk) {
		struct bdevgroup *bdevgroup = bint->group;

		debug_check(bdevgroup->reserved_log_entries);
		bdev_log_remove(bint, 1);
		bdev_log_list_remove(bint, 1);
	}

	bdev_list_remove(bint);
	if (bint->ddmaster)
		ddtable_exit(&bint->group->ddtable);

	atomic_dec(&bint->group->bdevs);
	bint_free(bint, 0);
	sx_xunlock(gchain_lock);
	return 0;
}

int
bdev_add_stub(struct bdev_info *binfo)
{
	struct bdevint *bint;
	int retval;

	bint = bdev_find(binfo->bid);
	if (bint)
		return 0;

	bint = zalloc(sizeof(struct bdevint), M_BINT, Q_NOWAIT);
	if (unlikely(!bint))
	{
		debug_warn("Cannot allocate for a new bint\n");
		return -1;
	}

	bint->group = bdev_group_locate(binfo->group_id, NULL);
	if (unlikely(!bint->group)) {
		debug_warn("Cannot locate pool at %u\n", binfo->group_id);
		free(bint, M_BINT);
		return -1;
	}

	bint->bint_lock = mtx_alloc("bint lock");
	bint->stats_lock = mtx_alloc("bint stats lock");
	bint->alloc_lock = sx_alloc("bint alloc lock");
	SLIST_INIT(&bint->free_list);
	TAILQ_INIT(&bint->index_list);
	LIST_INIT(&bint->log_group_list);
	bint->sync_wait = wait_chan_alloc("bint sync wait");
	bint->load_wait = wait_chan_alloc("bint load wait");
	bint->free_wait = wait_chan_alloc("bint free wait");

	bint->bid = binfo->bid;
	bint->ddmaster = binfo->ddmaster;
	memcpy(bint->vendor, binfo->vendor, sizeof(bint->vendor));
	memcpy(bint->product, binfo->product, sizeof(bint->product));
	memcpy(bint->serialnumber, binfo->serialnumber, sizeof(bint->serialnumber));
	retval = bint_dev_open(bint, binfo);
	if (unlikely(retval != 0))
	{
		wait_chan_free(bint->sync_wait);
		wait_chan_free(bint->load_wait);
		wait_chan_free(bint->free_wait);
		mtx_free(bint->bint_lock);
		mtx_free(bint->stats_lock);
		sx_free(bint->alloc_lock);
		free(bint, M_BINT);
		return -1;
	}

	bint->b_start = BDEV_META_OFFSET >> bint->sector_shift;
	bdev_list_insert(bint);
	atomic_inc(&bint->group->bdevs);
	return 0;
}
