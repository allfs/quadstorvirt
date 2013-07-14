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

#ifndef QS_IETADM_H_
#define QS_IETADM_H_
#include <apicommon.h>
int ietadm_default_settings(void *conn, struct tdisk_info *tdisk_info, struct iscsiconf *srcconf);
int ietadm_mod_target(int tid, struct iscsiconf *iscsiconf, struct iscsiconf *oldconf);
int ietadm_add_target(int tid, struct iscsiconf *iscsiconf);
int ietadm_delete_target(int tid);
int ietadm_delete(void);
int ietadm_qload_done(void);
void ietadm_check(void);
#endif
