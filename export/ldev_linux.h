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

#ifndef QS_LDEV_LINUX_H_
#define QS_LDEV_LINUX_H_

#include "linuxdefs.h"

struct ldev_priv {
	struct tdisk *device;
	struct qs_devq *devq;
	atomic_t pending_cmds;
	atomic_t disabled;
};

#define LDEV_NAME	"QUADStor ldev"
#define LDEV_HOST_ID	15

struct qsio_scsiio;
void ldev_proc_cmd(struct qsio_scsiio *ctio);
#endif

