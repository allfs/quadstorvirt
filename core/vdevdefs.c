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
#include "reservation.h"
#include "vdevdefs.h"
#include "scsidefs.h"
#include "sense.h"
#include "tdisk.h"
#include "cluster.h"
#include <exportdefs.h>

void
device_add_sense(struct initiator_state *istate, uint8_t error_code, uint8_t sense_key, uint32_t info, uint8_t asc, uint8_t ascq)
{
	struct sense_info *sinfo, *iter, *prev = NULL;
	struct qs_sense_data *sense;
	int count = 1;

	sinfo = zalloc(sizeof(struct sense_info), M_SENSEINFO, Q_WAITOK);
	sense = &sinfo->sense_data;
	fill_sense_info(sense, error_code, sense_key, info, asc, ascq);
	mtx_lock(istate->istate_lock);
	SLIST_FOREACH(iter, &istate->sense_list, s_list) {
		prev = iter;
		count++;
	}

	if (prev) {
		SLIST_INSERT_AFTER(prev, sinfo, s_list);
	}
	else
		SLIST_INSERT_HEAD(&istate->sense_list, sinfo, s_list);

	if (count > MAX_UNIT_ATTENTIONS) {
		iter = SLIST_FIRST(&istate->sense_list);
		SLIST_REMOVE_HEAD(&istate->sense_list, s_list);
		free(iter, M_SENSEINFO);
	}

	mtx_unlock(istate->istate_lock);
	return;
}

int
device_request_sense(struct qsio_scsiio *ctio, struct initiator_state *istate)
{
	struct qs_sense_data tmp;
	struct qs_sense_data *sense;
	uint8_t *cdb = ctio->cdb;
	int allocation_length;
	struct sense_info *sense_info = NULL;
	int sense_len;

	allocation_length = cdb[4];

	ctio->scsi_status = SCSI_STATUS_OK;
	if (!device_has_sense(istate)) {
		sense = &tmp;
		bzero(sense, sizeof(struct qs_sense_data));
		sense->error_code = SSD_CURRENT_ERROR;
		sense->flags = SSD_KEY_NO_SENSE;
		sense->add_sense_code = NO_ADDITIONAL_SENSE_INFORMATION_ASC;
		sense->add_sense_code_qual = NO_ADDITIONAL_SENSE_INFORMATION_ASCQ;
		sense->extra_len =
			offsetof(struct qs_sense_data, extra_bytes) -
			offsetof(struct qs_sense_data, cmd_spec_info);
	}
	else
	{
		sense_info = device_get_sense(istate);
		sense = &sense_info->sense_data;
	}
	sense_len = SENSE_LEN(sense);

	ctio->dxfer_len = min_t(int, sense_len, allocation_length);
	ctio_allocate_buffer(ctio, ctio->dxfer_len, Q_WAITOK);
	memcpy(ctio->data_ptr, sense, ctio->dxfer_len);

	if (sense_info)
		free(sense_info, M_SENSEINFO);
	/* send ccb */
	return 0;
}

int
device_find_sense(struct initiator_state *istate, uint8_t sense_key, uint8_t asc, uint8_t ascq)
{
	struct sense_info *sinfo;
	struct qs_sense_data *sense;

	mtx_lock(istate->istate_lock);
	SLIST_FOREACH(sinfo, &istate->sense_list, s_list) {
		sense = &sinfo->sense_data;
		if (sense->flags == sense_key &&
		    sense->add_sense_code == asc &&
		    sense->add_sense_code_qual == ascq)
		{
			mtx_unlock(istate->istate_lock);
			return 0;
		}
	}
	mtx_unlock(istate->istate_lock);
	return -1;
}

/* called under lock */
void
device_unit_attention(struct tdisk *tdisk, int all, uint64_t i_prt[], uint64_t t_prt[], uint8_t init_int, uint8_t asc, uint8_t ascq, int ignore_dup)
{
	struct initiator_state *istate;
	int retval;

	SLIST_FOREACH(istate, &tdisk->istate_list, i_list) {
		if (!all && iid_equal(istate->i_prt, istate->t_prt, istate->init_int, i_prt, t_prt, init_int))
		{
			continue;
		}

		if (ignore_dup)
		{
			retval = device_find_sense(istate, SSD_KEY_UNIT_ATTENTION, asc, ascq);
			if (retval == 0)
				continue;
		}
		device_add_sense(istate, SSD_CURRENT_ERROR, SSD_KEY_UNIT_ATTENTION, 0, asc, ascq);
	}
}

void
device_wait_all_initiators(struct istate_list *lhead)
{
	struct initiator_state *iter;

	SLIST_FOREACH(iter, lhead, i_list) {
		wait_on_chan(iter->istate_wait, TAILQ_EMPTY(&iter->queue_list));
	}
}

void
device_free_all_initiators(struct istate_list *lhead)
{
	struct initiator_state *iter;

	while ((iter = SLIST_FIRST(lhead)) != NULL) {
		SLIST_REMOVE_HEAD(lhead, i_list);
		free_initiator_state(iter);
	}
}

void
device_free_stale_initiators(struct istate_list *lhead)
{
	struct initiator_state *iter, *prev = NULL;
	unsigned long elapsed;

	SLIST_FOREACH(iter, lhead, i_list) {
		elapsed = get_elapsed(iter->timestamp);
		if (ticks_to_msecs(elapsed) < stale_initiator_timeout) {
			prev = iter;
			continue;
		}

		if (prev)
			SLIST_REMOVE_AFTER(prev, i_list);
		else
			SLIST_REMOVE_HEAD(lhead, i_list);
		free_initiator_state(iter);
	}
}

void
device_init_naa_identifier(struct logical_unit_naa_identifier *naa_identifier, char *serial_number)
{
	naa_identifier->code_set = 0x01;
	naa_identifier->identifier_type = UNIT_IDENTIFIER_NAA;
	naa_identifier->identifier_length = sizeof(struct logical_unit_naa_identifier) - offsetof(struct logical_unit_naa_identifier, naa_id);
	memcpy(naa_identifier->naa_id, serial_number, 16);
	naa_identifier->naa_id[0] = 0x6e;
}

void
device_init_unit_identifier(struct logical_unit_identifier *unit_identifier, char *vendor_id, char *product_id, int serial_len)
{
	unit_identifier->code_set = 0x02; /*logical unit idenifier */
	unit_identifier->identifier_type = UNIT_IDENTIFIER_T10_VENDOR_ID;
	sys_memset(unit_identifier->vendor_id, ' ', 8);
	strncpy(unit_identifier->vendor_id, vendor_id, strlen(vendor_id));
	sys_memset(unit_identifier->product_id, ' ', 16);
	strncpy(unit_identifier->product_id, product_id, strlen(product_id));
	unit_identifier->identifier_length = offsetof(struct logical_unit_identifier, serial_number) - offsetof(struct logical_unit_identifier, vendor_id);
	unit_identifier->identifier_length += serial_len;
}

extern sx_t *cbs_lock;
extern struct interface_list cbs_list;

void
cbs_disable_device(struct tdisk *tdisk)
{
	struct qs_interface_cbs *cbs;

	if (!atomic_test_bit(VDISK_ATTACHED, &tdisk->flags))
		return;

	sx_xlock(cbs_lock);
	LIST_FOREACH(cbs, &cbs_list, i_list) {
		if (cbs->interface == TARGET_INT_ISCSI)
			(*cbs->disable_device)(tdisk, tdisk->iscsi_tid, tdisk->hpriv);
		else
			(*cbs->disable_device)(tdisk, tdisk->vhba_id, tdisk->hpriv);
	}
	sx_xunlock(cbs_lock);
}

void
cbs_remove_device(struct tdisk *tdisk)
{
	struct qs_interface_cbs *cbs;
	int retval;

	sx_xlock(cbs_lock);
	if (!atomic_test_bit(VDISK_ATTACHED, &tdisk->flags)) {
		sx_xunlock(cbs_lock);
		return;
	}

	atomic_clear_bit(VDISK_ATTACHED, &tdisk->flags);
	LIST_FOREACH(cbs, &cbs_list, i_list) {
		if (cbs->interface == TARGET_INT_ISCSI)
			retval = (*cbs->remove_device)(tdisk, tdisk->iscsi_tid, tdisk->hpriv);
		else
			retval = (*cbs->remove_device)(tdisk, tdisk->vhba_id, tdisk->hpriv);
		if (retval == 0)
			tdisk_put(tdisk);
	}
	sx_xunlock(cbs_lock);
}

void
cbs_update_device(struct tdisk *tdisk)
{
	struct qs_interface_cbs *cbs;

	if (!atomic_test_bit(VDISK_ATTACHED, &tdisk->flags))
		return;

	sx_xlock(cbs_lock);
	LIST_FOREACH(cbs, &cbs_list, i_list) {
		if (!cbs->update_device)
			continue;
		if (cbs->interface == TARGET_INT_ISCSI)
			(*cbs->update_device)(tdisk, tdisk->iscsi_tid, tdisk->hpriv);
		else
			(*cbs->update_device)(tdisk, tdisk->vhba_id, tdisk->hpriv);
	}
	sx_xunlock(cbs_lock);

}

void
cbs_new_device(struct tdisk *tdisk, int notify_usr)
{
	struct qs_interface_cbs *cbs;
	int retval;

	sx_xlock(cbs_lock);
	if (atomic_test_bit(VDISK_ATTACHED, &tdisk->flags)) {
		sx_xunlock(cbs_lock);
		return;
	}
	LIST_FOREACH(cbs, &cbs_list, i_list) {
		tdisk_get(tdisk);
		retval = (*cbs->new_device)(tdisk);
		if (retval < 0)
			tdisk_put(tdisk);
	}
	atomic_set_bit(VDISK_ATTACHED, &tdisk->flags);
	sx_xunlock(cbs_lock);
	if (notify_usr)
		node_usr_send_vdisk_attached(tdisk);
}

extern struct tdisk *tdisks[];
extern mtx_t *tdisk_lookup_lock;

struct tdisk *
get_device(uint32_t bus)
{
	struct tdisk *tdisk;

	if (bus >= TL_MAX_DEVICES)
		return NULL;

	mtx_lock(tdisk_lookup_lock);
	tdisk = tdisks[bus];
	if (tdisk) {
		if (!atomic_test_bit(VDISK_ATTACHED, &tdisk->flags))
			tdisk = NULL;
		else
			tdisk_get(tdisk);
	}
	mtx_unlock(tdisk_lookup_lock);
	return tdisk;
}

int
get_next_device_id(void)
{
	int i;

	for (i = 0; i < TL_MAX_DEVICES; i++)
	{
		if (!tdisks[i])
			return i;
	}
	return -1;	
}

static int
__device_istate_abort_task(struct tdisk *tdisk, uint64_t i_prt[], uint64_t t_prt[], int init_int, uint32_t task_tag)
{
	struct initiator_state *istate;
	int task_found, task_exists;

	tdisk_reservation_lock(tdisk);
	istate = device_get_initiator_state(tdisk, i_prt, t_prt, 0, init_int, 0, 1);
	tdisk_reservation_unlock(tdisk);
	if (!istate)
		return 0;

	task_exists = 0;
	chan_lock(devq_wait);
	task_found = istate_abort_task(istate, i_prt, t_prt, init_int, task_tag, &task_exists);
	if (task_found) {
		chan_unlock(devq_wait);
		atomic16_set(&istate->blocked, 0);
		chan_wakeup(istate->istate_wait);
		istate_put(istate);
		return task_found;
	}
	task_found = gdevq_abort_task(i_prt, t_prt, init_int, task_tag);
	chan_unlock(devq_wait);
	while (!task_found && task_exists) {
		debug_info("task not found, but exists\n");
		pause("psg", 1000);
		task_exists = istate_task_exists(istate, task_tag);
	}
	atomic16_set(&istate->blocked, 0);
	chan_wakeup(istate->istate_wait);
	istate_put(istate);
	return task_found;
}

int
device_istate_abort_task(struct tdisk *tdisk, uint64_t i_prt[], uint64_t t_prt[], int init_int, uint32_t task_tag)
{
	int task_found, i;

	if (tdisk) {
		return __device_istate_abort_task(tdisk, i_prt, t_prt, init_int, task_tag);
	}

	for (i = 0; i < TL_MAX_DEVICES; i++) {
		mtx_lock(tdisk_lookup_lock);
		tdisk = tdisks[i]; 
		if (tdisk)
			tdisk_get(tdisk);
		mtx_unlock(tdisk_lookup_lock);
		if (!tdisk)
			continue;
		task_found = __device_istate_abort_task(tdisk, i_prt, t_prt, init_int, task_tag);
		tdisk_put(tdisk);
		if (task_found)
			return task_found;
	}
	return 0;
}

static void
__device_istate_abort_task_set(struct tdisk *tdisk, uint64_t i_prt[], uint64_t t_prt[], int init_int)
{
	struct initiator_state *istate;

	tdisk_reservation_lock(tdisk);
	istate = device_get_initiator_state(tdisk, i_prt, t_prt, 0, init_int, 0, 1);
	tdisk_reservation_unlock(tdisk);
	if (!istate)
		return;
	chan_lock(devq_wait);
	istate_abort_task_set(istate);
	gdevq_abort_tasks_for_initiator(i_prt, t_prt, init_int);
	chan_unlock(devq_wait);
	wait_on_chan(istate->istate_wait, TAILQ_EMPTY(&istate->queue_list));
	atomic16_set(&istate->blocked, 0);
	chan_wakeup(istate->istate_wait);
	istate_put(istate);
}

void
device_istate_abort_task_set(struct tdisk *tdisk, uint64_t i_prt[], uint64_t t_prt[], int init_int)
{
	int i;

	if (tdisk) {
		__device_istate_abort_task_set(tdisk, i_prt, t_prt, init_int);
		return;
	}

	for (i = 0; i < TL_MAX_DEVICES; i++) {
		mtx_lock(tdisk_lookup_lock);
		tdisk = tdisks[i]; 
		if (tdisk)
			tdisk_get(tdisk);
		mtx_unlock(tdisk_lookup_lock);
		if (!tdisk)
			continue;
		__device_istate_abort_task_set(tdisk, i_prt, t_prt, init_int);
		tdisk_put(tdisk);
	}
}

void
device_free_initiator(uint64_t i_prt[], uint64_t t_prt[], int init_int, struct tdisk *tdisk)
{
	int i;

	debug_info("i_prt %llx %llx t_prt %llx %llx init int %d tdisk %p\n", (unsigned long long)i_prt[0], (unsigned long long)i_prt[1], (unsigned long long)t_prt[0], (unsigned long long)t_prt[1], init_int, tdisk);
	if (tdisk) {
		device_free_initiator_state2(tdisk, i_prt, t_prt, init_int);
		return;
	}

	for (i = 0; i < TL_MAX_DEVICES; i++) {
		mtx_lock(tdisk_lookup_lock);
		tdisk = tdisks[i]; 
		if (tdisk)
			tdisk_get(tdisk);
		mtx_unlock(tdisk_lookup_lock);
		if (!tdisk)
			continue;
		device_free_initiator_state2(tdisk, i_prt, t_prt, init_int);
		tdisk_put(tdisk);
	}
}

int
pgdata_allocate_data(struct qsio_scsiio *ctio, uint32_t num_blocks, allocflags_t flags)
{
	struct pgdata **pglist;

	pglist = pgdata_allocate(num_blocks, flags);
	if (unlikely(!pglist))
	{
		debug_warn("Allocation for pglist of num_blocks %u failed\n", num_blocks);
		return -1;
	}
	ctio->data_ptr = (void *)pglist;
	ctio->pglist_cnt = num_blocks;
	ctio->dxfer_len = num_blocks << LBA_SHIFT;
	return 0;
}

static int
pgdata_allocate_data_nopage(struct qsio_scsiio *ctio, uint32_t num_blocks, allocflags_t flags)
{
	struct pgdata **pglist;

	pglist = pgdata_allocate_nopage(num_blocks, flags);
	if (unlikely(!pglist))
	{
		debug_warn("Allocation for pglist of num_blocks %u failed\n", num_blocks);
		return -1;
	}
	ctio->data_ptr = (void *)pglist;
	ctio->pglist_cnt = num_blocks;
	ctio->dxfer_len = num_blocks << LBA_SHIFT;
	return 0;
}

int
device_allocate_buffers_nopage(struct qsio_scsiio *ctio, uint32_t num_blocks, allocflags_t flags)
{
	if (!num_blocks)
		return 0;

	pgdata_allocate_data_nopage(ctio, num_blocks, flags);
	if (!ctio->data_ptr) {
		debug_warn("Allocating ctio data_ptr failed num_blocks %u\n", num_blocks);
		return -1;
	}
	ctio->ccb_h.flags |= QSIO_DATA_DIR_OUT;
	return 0;
}

int
device_allocate_buffers(struct qsio_scsiio *ctio, uint32_t num_blocks, allocflags_t flags)
{
	/* Allocate for the data transfer */
	if (!num_blocks)
		return 0;

	pgdata_allocate_data(ctio, num_blocks, flags);
	if (!ctio->data_ptr) {
		debug_warn("Allocating ctio data_ptr failed num_blocks %u\n", num_blocks);
		return -1;
	}
	ctio->ccb_h.flags |= QSIO_DATA_DIR_OUT;
	return 0;
}

int
device_allocate_cmd_buffers(struct qsio_scsiio *ctio, allocflags_t flags)
{
	uint8_t *cdb = ctio->cdb;
	uint16_t parameter_list_length;

	switch (cdb[0])
	{
		case MODE_SELECT_6:
			parameter_list_length = cdb[4];
			break;
		case MODE_SELECT_10:
		case PERSISTENT_RESERVE_OUT:
		case UNMAP:
			parameter_list_length = be16toh(*(uint16_t *)(&cdb[7]));
			break;
		default:
			parameter_list_length = 0;
			debug_check(1);
	}

	debug_info("cdb %x parameter_list_length %d\n", cdb[0], parameter_list_length);
	ctio_allocate_buffer(ctio, parameter_list_length, flags);
	if (!ctio->data_ptr)
	{
		return -1;
	}
	ctio->ccb_h.flags |= QSIO_DATA_DIR_OUT;
	return 0;
}

void
ctio_free_all(struct qsio_scsiio *ctio)
{
	ctio_free_data(ctio);
	if (ctio->istate)
		istate_put(ctio->istate);
	ctio_free_sense(ctio);
	uma_zfree(ctio_cache, ctio);
}

static struct fc_rule_list fc_rule_list = TAILQ_HEAD_INITIALIZER(fc_rule_list);

static void
tdisk_revalidate_istates(struct tdisk *tdisk)
{
	struct istate_list *istate_list = &tdisk->istate_list;
	struct initiator_state *iter;

	tdisk_reservation_lock(tdisk);
	SLIST_FOREACH(iter, istate_list, i_list) {
		if (iter->init_int == TARGET_INT_FC)
			iter->disallowed = fc_initiator_check(iter->i_prt, tdisk);
	}
	tdisk_reservation_unlock(tdisk);
}

static void
update_istates(void)
{
	struct tdisk *tdisk;
	int i;

	for (i = 0; i < TL_MAX_DEVICES; i++) {
		mtx_lock(tdisk_lookup_lock);
		tdisk = tdisks[i]; 
		if (tdisk)
			tdisk_get(tdisk);
		mtx_unlock(tdisk_lookup_lock);
		if (!tdisk)
			continue;
		tdisk_revalidate_istates(tdisk);
		tdisk_put(tdisk);
	}
}

int
target_add_fc_rule(struct fc_rule_config *fc_rule_config)
{
	struct fc_rule *fc_rule, *iter;

	fc_rule = zalloc(sizeof(*fc_rule), M_QUADSTOR, Q_WAITOK);
	if (unlikely(!fc_rule)) {
		debug_warn("Memory allocation failure\n");
		return -1;
	}

	port_fill(fc_rule->wwpn, fc_rule_config->wwpn);
	fc_rule->target_id = fc_rule_config->target_id;
	fc_rule->rule = fc_rule_config->rule;
	debug_info("wwpn %llx %llx target id %u rule %d\n", (unsigned long long)fc_rule->wwpn[0], (unsigned long long)fc_rule->wwpn[1], fc_rule->target_id, fc_rule->rule);

	mtx_lock(glbl_lock);
	TAILQ_FOREACH(iter, &fc_rule_list, r_list) {
		if (port_equal(iter->wwpn, fc_rule->wwpn) && iter->target_id == fc_rule->target_id) {
			iter->rule = fc_rule->rule;
			mtx_unlock(glbl_lock);
			free(fc_rule, M_QUADSTOR);
			update_istates();
			return 0;
		}
	}
	if (!fc_rule->wwpn[0] && !fc_rule->wwpn[1])
		TAILQ_INSERT_HEAD(&fc_rule_list, fc_rule, r_list);
	else
		TAILQ_INSERT_TAIL(&fc_rule_list, fc_rule, r_list);
	mtx_unlock(glbl_lock);
	update_istates();
	return 0;
}

int
target_remove_fc_rule(struct fc_rule_config *fc_rule_config)
{
	struct fc_rule *iter;

	mtx_lock(glbl_lock);
	TAILQ_FOREACH(iter, &fc_rule_list, r_list) {
		if (port_equal(iter->wwpn, fc_rule_config->wwpn) && iter->target_id == fc_rule_config->target_id) {
			TAILQ_REMOVE(&fc_rule_list, iter, r_list);
			mtx_unlock(glbl_lock);
			free(iter, M_QUADSTOR);
			update_istates();
			return 0;
		}
	}
	mtx_unlock(glbl_lock);
	return 0;
}

void
target_clear_fc_rules(uint32_t target_id)
{
	struct fc_rule *iter, *next;

	mtx_lock(glbl_lock);
	TAILQ_FOREACH_SAFE(iter, &fc_rule_list, r_list, next) {
		if (target_id > 0 && iter->target_id != target_id)
			continue;

		TAILQ_REMOVE(&fc_rule_list, iter, r_list);
		free(iter, M_QUADSTOR);
	}
	mtx_unlock(glbl_lock);
}

int
fc_initiator_check(uint64_t wwpn[], void *device)
{
	struct fc_rule *iter;
	int rule_wwpn = -1;
	int rule_target = -1;
	int rule_all_wwpn = -1;
	int rule_all_target = -1;
	struct tdisk *tdisk = device;
	uint32_t target_id = tdisk->target_id;

	debug_info("wwpn %llx %llx target id %u\n", (unsigned long long)wwpn[0], (unsigned long long)wwpn[1], tdisk->target_id);
	mtx_lock(glbl_lock);
	if (TAILQ_EMPTY(&fc_rule_list)) {
		mtx_unlock(glbl_lock);
		return FC_RULE_ALLOW;
	}

	TAILQ_FOREACH(iter, &fc_rule_list, r_list) {
		debug_info("iter wwpn %llx %llx target id %u\n", (unsigned long long)iter->wwpn[0], (unsigned long long)iter->wwpn[1], iter->target_id);
		if (port_equal(iter->wwpn, wwpn) && iter->target_id == target_id) {
			debug_info("found match %llx %llx tdisk %s rule %d\n", (unsigned long long)wwpn[0], (unsigned long long)wwpn[1], tdisk_name(tdisk), iter->rule);
			mtx_unlock(glbl_lock);
			return iter->rule;
		}

		if (port_equal(iter->wwpn, wwpn) && !iter->target_id)
			rule_wwpn = iter->rule;
		else if (iter->target_id == target_id)
			rule_target = iter->rule;
		else if (!iter->wwpn[0])
			rule_all_wwpn = iter->rule;
		else if (!iter->target_id)
			rule_all_target = iter->rule;
	}
	mtx_unlock(glbl_lock);
	debug_info("found match %llx %llx tdisk %s rule_wwpn %d rule_target %d rule all wwpn %d rule all target %d\n", (unsigned long long)wwpn[0], (unsigned long long)wwpn[1], tdisk_name(tdisk), rule_wwpn, rule_target, rule_all_wwpn, rule_all_target);
	if (rule_wwpn > 0)
		return rule_wwpn;
	else if (rule_target > 0)
		return rule_target;
	else if (rule_all_wwpn > 0)
		return rule_all_wwpn;
	else if (rule_all_target > 0)
		return rule_all_target;
	else
		return FC_RULE_ALLOW;
}
