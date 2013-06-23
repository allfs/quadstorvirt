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

#include "tdisk.h"
#include "vdevdefs.h"
#include <exportdefs.h>
#include "bdevgroup.h"

extern struct tdisk *tdisks[];

int
target_delete_disk_stub(struct tdisk_info *tdisk_info, unsigned long arg)
{
	struct tdisk *tdisk;

	tdisk = tdisk_locate_remove(tdisk_info->target_id);
	if (!tdisk)
		return 0;

	cbs_remove_device(tdisk);
	tdisk_remove(tdisk_info->tl_id, tdisk->target_id);
	while (atomic_read(&tdisk->refs) > 1)
		processor_yield();

	tdisk_put(tdisk);
	return 0;
}

int
target_disable_disk_stub(struct tdisk_info *tdisk_info, unsigned long arg)
{
	struct tdisk *tdisk;

	tdisk = tdisk_locate(tdisk_info->target_id);
	if (tdisk) {
		cbs_disable_device(tdisk);
		device_wait_all_initiators(&tdisk->istate_list);
		tdisk_put(tdisk);
	}
	return 0;
}

int
target_new_disk_stub(struct tdisk_info *tdisk_info, unsigned long arg)
{
	struct tdisk *tdisk;
	int tl_id;
#ifndef FREEBSD
	int retval;
#endif

	tl_id = get_next_device_id();
	if (tl_id < 0) {
		debug_warn("Failed to get a new device id\n");
		return -1;
	}

	tdisk = __uma_zalloc(tdisk_cache, Q_NOWAIT | Q_ZERO, sizeof(*tdisk));
	if (unlikely(!tdisk)) {
		debug_warn("Slab allocation failure\n");
		return -1;
	}

	tdisk->group = bdev_group_locate(tdisk_info->group_id, NULL);
	if (unlikely(!tdisk->group)) {
		debug_warn("Cannot locate pool at id %u\n", tdisk_info->group_id);
		tdisk_put(tdisk);
		return -1;
	}

	atomic_set(&tdisk->refs, 1);
	strcpy(tdisk->name, tdisk_info->name);
	tdisk->enable_deduplication = tdisk_info->enable_deduplication;
	tdisk->enable_compression = tdisk_info->enable_compression;
	tdisk->enable_verify = tdisk_info->enable_verify;
	tdisk->force_inline = tdisk_info->force_inline;
	tdisk->lba_shift = tdisk_info->lba_shift;
	tdisk->remote = 1;
	if (!tdisk->lba_shift)
		tdisk->lba_shift = LBA_SHIFT;
	tdisk->end_lba = (tdisk_info->size >> tdisk->lba_shift);
	tdisk->target_id = tdisk_info->target_id;
	tdisk_init(tdisk);
	tdisk_initialize(tdisk, tdisk_info->serialnumber);

	tdisk->bus = tl_id;
	tdisk_insert(tdisk, tl_id, tdisk_info->target_id);
	tdisk_info->tl_id = tl_id;

	if (tdisk_info->attach) {
		cbs_new_device(tdisk, 0);
		tdisk_info->iscsi_tid = tdisk->iscsi_tid;
		tdisk_info->vhba_id = tdisk->vhba_id;
	}

	memcpy(tdisk_info->serialnumber, tdisk->unit_identifier.serial_number, 32);
#ifdef FREEBSD
	memcpy((void *)arg, tdisk_info, offsetof(struct tdisk_info, q_entry));
#else
	retval = copyout(tdisk_info, (void *)arg, offsetof(struct tdisk_info, q_entry));
	if (unlikely(retval != 0)) {
		target_delete_disk(tdisk_info, arg);
		return -1;
	}
#endif
	return 0;
}
