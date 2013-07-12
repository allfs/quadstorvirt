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

#ifndef QS_RAWDEFS_H_
#define QS_RAWDEFS_H_

#define BLOCK_BLOCKNR_BITS		38	
#define BLOCK_BLOCKNR_MASK		((1ULL << BLOCK_BLOCKNR_BITS) - 1)
/* 44 bits of block */
#define BLOCK_BLOCKNR(block)		((uint64_t)(block & BLOCK_BLOCKNR_MASK))

#define BLOCK_BID_BITS			9
#define BLOCK_BID_MASK			((1ULL << BLOCK_BID_BITS) - 1)	
/* 15 bits of bid */
#define BLOCK_BID(block)		(((uint32_t)((block >> BLOCK_BLOCKNR_BITS) & BLOCK_BID_MASK)))

#define SET_BLOCK(block,blocknr,bid)	(block = ((((uint64_t)(bid)) << BLOCK_BLOCKNR_BITS) | blocknr))

#define BDEV_META_RESERVED	262144
#define BDEV_META_OFFSET	BDEV_META_RESERVED
#define BDEV_HA_OFFSET		(BDEV_META_OFFSET - LBA_SIZE)

#define LOG_PAGES_RESERVED	(64 * 1024 * 1024)
#define LOG_PAGES_OFFSET	(BDEV_META_RESERVED + BDEV_META_SIZE)
#define TDISK_RESERVED_OFFSET	(LOG_PAGES_OFFSET + LOG_PAGES_RESERVED)
#define TDISK_RESERVED_SIZE	(TL_MAX_TDISKS * BINT_INDEX_META_SIZE) 
#define DDTABLE_META_OFFSET	(TDISK_RESERVED_OFFSET + TDISK_RESERVED_SIZE)
#define BDEV_META_SIZE		4096
#define BINT_TAIL_RESERVED	(TDISK_RESERVED_SIZE + BDEV_META_RESERVED + BDEV_META_SIZE)

#define INDEX_ID_GROUP_SHIFT	15
#define INDEX_ID_GROUP_MASK	((1U << INDEX_ID_GROUP_SHIFT) - 1)
#define MAX_INDEXES_PER_GROUP	(1U << INDEX_ID_GROUP_SHIFT)

#define INDEX_ID_SUBGROUP_SHIFT	9	
#define INDEX_ID_SUBGROUP_MASK	((1U << INDEX_ID_SUBGROUP_SHIFT) - 1)
#define MAX_INDEXES_PER_SUBGROUP (1U << INDEX_ID_SUBGROUP_SHIFT)

#define INDEX_GROUP_MAX_SUBGROUPS (MAX_INDEXES_PER_GROUP / MAX_INDEXES_PER_SUBGROUP)
#define INDEX_LOOKUP_MAP_SIZE	4096
#define INDEX_CACHE_COUNT	32

#define BINT_INDEX_META_SIZE	4096

/* Maximum logical disk size of 256 TB */
#define BINT_DDTABLE_OFFSET	(BDEV_META_OFFSET + BDEV_META_SIZE)
#define BINT_INDEX_LOOKUP_SIZE	4096
#define BINT_INDEX_LOOKUP_SHIFT	15 /* 64k above * 8 bits */	

#define BINT_BMAP_SIZE	(4096)
typedef uint64_t bmapentry_t;

#define BMAP_BLOCK_BITS		13	
#define NODE_ENTRY_BITS  	(BLOCK_BLOCKNR_BITS + 11) /* Upto 512 node entries can be referenced */
//#define BMAP_ENTRIES	((BINT_BMAP_SIZE * 8) / BMAP_BLOCK_BITS)
#define BMAP_ENTRIES		1280	
#define BMAP_ENTRIES_UNCOMP	640U
#define NODE_META_ENTRIES	329 
#define NODE_META_OFFSET	((BMAP_ENTRIES * BMAP_BLOCK_BITS) / 8)
#define BMAP_BLOCK_BITS_UNCOMP 	(BMAP_BLOCK_BITS + BLOCK_BLOCKNR_BITS)

#define MAX_UNIT_ATTENTIONS	8
#define STALE_INITIATOR_TIMEOUT	(60 * 60 * 1000) /* 1 hour */
#define INITIATOR_NAME_MAX	256

#endif
