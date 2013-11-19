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

#ifndef QS_VDISK_SYNC_H_
#define QS_VDISK_SYNC_H_

int tdisk_mirror_load(struct tdisk *tdisk);
int tdisk_mirror_exit(struct tdisk *tdisk);
int tdisk_mirror_set_role(struct tdisk *tdisk, int mirror_role);
int tdisk_mirror_setup(struct tdisk *tdisk, struct clone_info *clone_info, char *sys_rid);
int tdisk_mirror_remove(struct tdisk *tdisk, int attach);
int tdisk_mirror_end(struct tdisk *tdisk);
int tdisk_mirror_cmd_generic(struct tdisk *tdisk, struct qsio_scsiio *ctio, int pcmd);
int tdisk_mirror_cmd_generic_nocheck(struct tdisk *tdisk, struct qsio_scsiio *ctio, int pcmd);
int tdisk_mirror_extended_copy_read(struct tdisk *tdisk, struct qsio_scsiio *ctio, struct tdisk *dest_tdisk, uint64_t lba, uint64_t dest_lba, uint32_t num_blocks, uint32_t *xchg_id);
int tdisk_mirror_cmd_generic2(struct tdisk *tdisk, struct qsio_scsiio *ctio);
int __tdisk_mirror_read(struct tdisk *tdisk, struct qsio_scsiio *ctio, struct pgdata ***ret_pglist, int *ret_pglist_cnt, uint64_t lba, uint32_t transfer_length);
int tdisk_mirror_write_setup(struct tdisk *tdisk, struct qsio_scsiio *ctio, struct write_list *wlist, uint64_t lba, uint32_t transfer_length, int cw, uint32_t xchg_id);
int tdisk_mirror_check_verify(struct tdisk *tdisk, struct qsio_scsiio *ctio, struct write_list *wlist);
int tdisk_mirror_check_comp(struct tdisk *tdisk, struct qsio_scsiio *ctio, struct write_list *wlist);
int tdisk_mirror_check_io(struct tdisk *tdisk, struct qsio_scsiio *ctio, struct write_list *wlist);
int tdisk_mirror_write_post_pre(struct tdisk *tdisk, struct qsio_scsiio *ctio, struct write_list *wlist);
int tdisk_mirror_write_done_pre(struct tdisk *tdisk, struct qsio_scsiio *ctio, struct write_list *wlist);
int tdisk_mirror_write_done_post(struct tdisk *tdisk, struct write_list *wlist);
void tdisk_mirror_write_done_wait(struct tdisk *tdisk, struct write_list *wlist);
int tdisk_mirror_write_error(struct tdisk *tdisk, struct qsio_scsiio *ctio, struct write_list *wlist);
int tdisk_mirror_update_properties(struct tdisk *tdisk, struct vdisk_update_spec *spec);
int tdisk_mirror_resize(struct tdisk *tdisk, uint64_t new_size);

void node_mirror_state(struct node_sock *sock, struct raw_node_msg *raw);
void node_mirror_resync_done(struct node_sock *sock, struct raw_node_msg *raw);
void node_mirror_resync_start(struct node_sock *sock, struct raw_node_msg *raw);
void node_mirror_peer_shutdown(struct node_sock *sock, struct raw_node_msg *raw);
void node_mirror_set_role(struct node_sock *sock, struct raw_node_msg *raw);
void node_mirror_setup(struct node_sock *sock, struct raw_node_msg *raw);
void node_mirror_remove(struct node_sock *sock, struct raw_node_msg *raw);
void node_mirror_write_error(struct node_sock *sock, struct raw_node_msg *raw, struct queue_list *queue_list, mtx_t *queue_lock);
void node_mirror_update_vdisk_properties(struct node_sock *sock, struct raw_node_msg *raw);
void node_mirror_vdisk_resize(struct node_sock *sock, struct raw_node_msg *raw);
void node_mirror_load_done(struct node_sock *sock, struct raw_node_msg *raw);
void node_mirror_load_error(struct node_sock *sock, struct raw_node_msg *raw);
void node_mirror_registration_sync_recv(struct node_sock *sock, struct raw_node_msg *raw);
void node_mirror_reservation_sync_recv(struct node_sock *sock, struct raw_node_msg *raw);
void node_mirror_registration_clear_recv(struct node_sock *sock, struct raw_node_msg *raw);

#define MIRROR_SYNC_TIMEOUT		8000

int tdisk_mirror_ready(struct tdisk *tdisk);

static inline int
tdisk_mirroring_configured(struct tdisk *tdisk)
{
	return (atomic_test_bit(MIRROR_FLAGS_CONFIGURED, &tdisk->mirror_state.mirror_flags));
}

static inline int
tdisk_mirroring_disabled(struct tdisk *tdisk)
{
	return (atomic_test_bit(MIRROR_FLAGS_DISABLED, &tdisk->mirror_state.mirror_flags));
}

int tdisk_mirror_peer_failure(struct tdisk *tdisk, int manual);

int tdisk_clear_write_bitmap(struct tdisk *tdisk);

static inline int
tdisk_mirror_master(struct tdisk *tdisk)
{
	return (tdisk->mirror_state.mirror_role == MIRROR_ROLE_MASTER);
}

static inline void
tdisk_mirroring_resync_clear(struct tdisk *tdisk)
{
	atomic_clear_bit(MIRROR_FLAGS_NEED_RESYNC, &tdisk->mirror_state.mirror_flags);
	atomic_clear_bit(MIRROR_FLAGS_IN_RESYNC, &tdisk->mirror_state.mirror_flags);
	if (tdisk_mirror_master(tdisk))
		atomic_set_bit(MIRROR_FLAGS_WRITE_BITMAP_VALID, &tdisk->mirror_state.mirror_flags);
	tdisk_clear_write_bitmap(tdisk);
}

static inline void
tdisk_mirroring_enable_write_bitmap(struct tdisk *tdisk)
{
	int retval;

	if (atomic_test_bit(MIRROR_FLAGS_NEED_RESYNC, &tdisk->mirror_state.mirror_flags))
		return;

	retval = tdisk_clear_write_bitmap(tdisk);
	if (retval) {
		debug_check(1);
		atomic_clear_bit(MIRROR_FLAGS_WRITE_BITMAP_VALID, &tdisk->mirror_state.mirror_flags);
		return;
	}
	atomic_set_bit(MIRROR_FLAGS_WRITE_BITMAP_VALID, &tdisk->mirror_state.mirror_flags);
}

static inline int 
tdisk_mirroring_in_resync(struct tdisk *tdisk)
{
	return atomic_test_bit(MIRROR_FLAGS_IN_RESYNC, &tdisk->mirror_state.mirror_flags);
}

static inline int 
tdisk_mirroring_need_resync(struct tdisk *tdisk)
{
	return (atomic_test_bit(MIRROR_FLAGS_NEED_RESYNC, &tdisk->mirror_state.mirror_flags) || atomic_test_bit(MIRROR_FLAGS_IN_RESYNC, &tdisk->mirror_state.mirror_flags));
}

static inline void
tdisk_mirroring_set_invalid(struct tdisk *tdisk)
{
	atomic_set_bit(MIRROR_FLAGS_STATE_INVALID, &tdisk->mirror_state.mirror_flags);
}

static inline int 
tdisk_mirroring_invalid(struct tdisk *tdisk)
{
	return atomic_test_bit(MIRROR_FLAGS_STATE_INVALID, &tdisk->mirror_state.mirror_flags);
}

static inline void 
tdisk_mirroring_resync_set(struct tdisk *tdisk)
{
	atomic_set_bit(MIRROR_FLAGS_NEED_RESYNC, &tdisk->mirror_state.mirror_flags);
}

static inline void
tdisk_mirroring_enable(struct tdisk *tdisk)
{
	atomic_clear_bit(MIRROR_FLAGS_DISABLED, &tdisk->mirror_state.mirror_flags);
}

static inline void
tdisk_set_next_role(struct tdisk *tdisk, int role)
{
	tdisk->mirror_state.next_role = role;
}

static inline void 
tdisk_set_mirror_role(struct tdisk *tdisk, int role)
{
	tdisk->mirror_state.mirror_role = role;
	tdisk->mirror_state.next_role = 0;
}

static inline int
mirror_state_master(struct mirror_state *mirror_state)
{
	return (mirror_state->mirror_role == MIRROR_ROLE_MASTER);
}

int tdisk_lba_needs_mirror_sync(struct tdisk *tdisk, uint64_t lba);
void tdisk_mirror_checks(struct tdisk *tdisk);

#endif
