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

#ifndef QS_IOCTLDEFS_H_
#define QS_IOCTLDEFS_H_ 1

#include "commondefs.h"

struct msgblock {
	unsigned char block[512];
};

/* List of IOCTLS */
#define TL_MAGIC			'k'

#define TLTARGIOCNEWBLKDEV		_IOWR(TL_MAGIC, 1, struct bdev_info)
#define TLTARGIOCDELBLKDEV		_IOWR(TL_MAGIC, 2, struct bdev_info)
#define TLTARGIOCGETBLKDEV		_IOWR(TL_MAGIC, 3, struct bdev_info)
#define TLTARGIOCDAEMONSETINFO		_IOWR(TL_MAGIC, 4, struct mdaemon_info)
#define TLTARGIOCCHECKDISKS		_IOWR(TL_MAGIC, 5, int)
#define TLTARGIOCLOADDONE		_IO(TL_MAGIC, 6) 
#define TLTARGIOCENABLEDEVICE		_IOWR(TL_MAGIC, 7, uint32_t)
#define TLTARGIOCDISABLEDEVICE		_IOWR(TL_MAGIC, 8, uint32_t)
#define TLTARGIOCNEWTDISK		_IOWR(TL_MAGIC, 9, struct tdisk_info)
#define TLTARGIOCLOADTDISK		_IOWR(TL_MAGIC, 10, struct tdisk_info)
#define TLTARGIOCDELETETDISK		_IOWR(TL_MAGIC, 11, struct tdisk_info)
#define TLTARGIOCATTACHTDISK		_IOWR(TL_MAGIC, 12, struct tdisk_info)
#define TLTARGIOCMODIFYTDISK		_IOWR(TL_MAGIC, 13, struct tdisk_info)
#define TLTARGIOCTDISKSTATS		_IOWR(TL_MAGIC, 14, struct tdisk_info) 
#define TLTARGIOCTDISKRESETSTATS	_IOWR(TL_MAGIC, 15, struct tdisk_info)
#define TLTARGIOCBINTRESETSTATS		_IOWR(TL_MAGIC, 16, uint32_t)
#define TLTARGIOCRESETLOGS		_IO(TL_MAGIC, 17) 
#define TLTARGIOCUNLOAD			_IO(TL_MAGIC, 18) 
#define TLTARGIOCNODECONFIG		_IOWR(TL_MAGIC, 19, struct node_config) 
#define TLTARGIOCNEWBDEVSTUB		_IOWR(TL_MAGIC, 20, struct bdev_info) 
#define TLTARGIOCDELETEBDEVSTUB		_IOWR(TL_MAGIC, 21, struct bdev_info) 
#define TLTARGIOCNEWTDISKSTUB		_IOWR(TL_MAGIC, 22, struct tdisk_info)
#define TLTARGIOCDELETETDISKSTUB	_IOWR(TL_MAGIC, 23, struct tdisk_info)
#define TLTARGIOCCLONEVDISK		_IOWR(TL_MAGIC, 24, struct clone_config)
#define TLTARGIOCCLONESTATUS		_IOWR(TL_MAGIC, 25, struct clone_config)
#define TLTARGIOCCLONECANCEL		_IOWR(TL_MAGIC, 26, struct clone_config)
#define TLTARGIOCMIRRORVDISK		_IOWR(TL_MAGIC, 27, struct clone_config)
#define TLTARGIOCMIRRORSTATUS		_IOWR(TL_MAGIC, 28, struct clone_config)
#define TLTARGIOCMIRRORCANCEL		_IOWR(TL_MAGIC, 29, struct clone_config)
#define TLTARGIOCDISABLETDISKSTUB	_IOWR(TL_MAGIC, 30, struct tdisk_info)
#define TLTARGIOCRESIZETDISK		_IOWR(TL_MAGIC, 31, struct tdisk_info)
#define TLTARGIOCADDGROUP		_IOWR(TL_MAGIC, 32, struct group_conf)
#define TLTARGIOCDELETEGROUP		_IOWR(TL_MAGIC, 33, struct group_conf)
#define TLTARGIOCHACONFIG		_IOWR(TL_MAGIC, 34, struct bdev_info)
#define TLTARGIOCNODESTATUS		_IOWR(TL_MAGIC, 35, struct node_config) 
#define TLTARGIOCMIRRORREMOVE		_IOWR(TL_MAGIC, 36, struct clone_config)
#define TLTARGIOCADDFCRULE		_IOWR(TL_MAGIC, 37, struct fc_rule_config)
#define TLTARGIOCREMOVEFCRULE		_IOWR(TL_MAGIC, 38, struct fc_rule_config)
#define TLTARGIOCDELETETDISKPOST	_IOWR(TL_MAGIC, 39, struct tdisk_info)
#define TLTARGIOCUNMAPCONFIG		_IOWR(TL_MAGIC, 40, struct bdev_info)
#define TLTARGIOCRENAMEGROUP		_IOWR(TL_MAGIC, 41, struct group_conf)
#define TLTARGIOCRENAMETDISK		_IOWR(TL_MAGIC, 42, struct tdisk_info)
#define TLTARGIOCWCCONFIG		_IOWR(TL_MAGIC, 43, struct bdev_info)
#define TLTARGIOCSETMIRRORROLE		_IOWR(TL_MAGIC, 44, struct tdisk_info)

#endif
