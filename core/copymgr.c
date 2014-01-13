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
#include "sense.h"
#include "vdevdefs.h"
#include "tcache.h"
#include "copymgr.h"

struct block_range_descriptor {
	uint64_t lba;
	uint32_t num_blocks;
	uint32_t reserved;
};

struct populate_token_header {
	uint16_t populate_token_data_length;
	uint8_t immed;
	uint8_t rsvd;
	uint32_t inactivity_timeout;
	uint32_t rod_type;
	uint16_t rsvd1;
	uint16_t block_device_range_descriptor_length;
	struct block_range_descriptor descriptor[0];
} __attribute__ ((__packed__));

struct rod_token_features {
	uint16_t third_party_copy_descriptor_type;
	uint16_t third_party_copy_descriptor_length;
	uint8_t remote_tokens;
	uint8_t rsvd[11];
	uint32_t minimum_token_lifetime;
	uint32_t maximum_token_lifetime;
	uint32_t maximum_token_inactivity_timeout;
	uint8_t rsvd1[18];
	uint16_t device_specific_features_length;
} __attribute__ ((__packed__));

struct rod_type_descriptor {
	uint32_t rod_type;
	uint8_t token_out;
	uint8_t rsvd;
	uint16_t preference_indication;
	uint8_t rsvd1[56];
} __attribute__ ((__packed__));

struct supported_rod_types {
	uint16_t third_party_copy_descriptor_type;
	uint16_t third_party_copy_descriptor_length;
	uint16_t rsvd;
	uint16_t rod_type_descriptors_length;
	struct rod_type_descriptor descriptor[0];
} __attribute__ ((__packed__));

struct generic_copy_operations {
	uint16_t third_party_copy_descriptor_type;
	uint16_t third_party_copy_descriptor_length;
	uint32_t total_concurrent_copies;
	uint32_t maximum_identified_concurrent_copies;
	uint16_t maximum_segment_length;
	uint8_t data_segment_granularity;
	uint8_t inline_data_granularity;
	uint8_t rsvd[18];
} __attribute__ ((__packed__));

struct block_rod_device_specific_features {
	uint8_t device_type;
	uint8_t rsvd;
	uint16_t descriptor_length;
	uint16_t rsvd1;
	uint16_t optimal_block_rod_length_granularity;
	uint64_t maximum_bytes_in_block_rod;
	uint64_t optimal_bytes_in_block_rod_transfer;
	uint64_t optimal_bytes_to_token_per_segment;
	uint64_t optimal_bytes_from_token_per_segment;
	uint64_t rsvd2;
} __attribute__ ((__packed__));

struct block_device_rod_token_limits {
	uint16_t third_party_copy_descriptor_type;
	uint16_t third_party_copy_descriptor_length;
	uint8_t vendor_specific[6];
	uint16_t maximum_range_descriptors;
	uint32_t maximum_inactivity_timeout;
	uint32_t default_inactivity_timeout;
	uint64_t maximum_token_transfer_size;
	uint64_t optimal_transfer_count;
} __attribute__ ((__packed__));

#define MAXIMUM_RANGE_DESCRIPTORS	1
#define MINIMUM_TOKEN_LIFETIME		300
#define MAXIMUM_TOKEN_LIFETIME		600
#define MAXIMUM_INACTIVITY_TIMEOUT	60
#define DEFAULT_INACTIVITY_TIMEOUT	35
#define MAXIMUM_BYTES_IN_BLOCK_ROD	(4 * 1024 * 1024)
#define TOTAL_CONCURRENT_COPIES		8

#define POINT_IN_TIME_COPY_DEFAULT	0x00800000U
#define POINT_IN_TIME_COPY_CV		0x00800001U
#define POINT_IN_TIME_COPY_PERSISTENT	0x00800002U

struct rod_entry {
	struct block_range_descriptor descriptor;
	struct index_info_list index_info_list;
	struct pgdata **pglist;
	uint64_t lba;
	uint64_t lba_diff;
	int pglist_cnt;
	uint32_t num_blocks;
	TAILQ_ENTRY(rod_entry) r_list;
};

enum {
	ROD_POPULATE_TOKEN_CMD,
	ROD_WRITE_TOKEN_CMD,
};

enum {
	COPY_OPERATION_OK	= 0x01,
	COPY_OPERATION_ERROR	= 0x02,
	COPY_OPERATION_INPROGRESS	= 0x10,
	COPY_OPERATION_INPROGRESS_FG	= 0x11,
	COPY_OPERATION_INPROGRESS_BG	= 0x12,
};


struct rod_token_spec {
	uint64_t rod_identifier;
	struct tdisk *src_tdisk;
	TAILQ_ENTRY(rod_token_spec) t_list;
	TAILQ_HEAD(, rod_entry) rod_entry_list;
	uint32_t rod_type;
	uint32_t timestamp;
	uint32_t timeout;
	uint32_t list_identifier;
	uint64_t i_prt[2];
	uint64_t t_prt[2];
	uint8_t init_int;
	uint8_t cmd_type;
	uint8_t copy_operation_status;
	uint64_t read_transfer_count;
	uint64_t write_transfer_count;
	uint8_t del_token;
	atomic_t refs;
};

TAILQ_HEAD(rod_token_list, rod_token_spec);
extern sx_t *rod_lock;
uint64_t rod_identifier;

struct rod_token_list rod_token_list = TAILQ_HEAD_INITIALIZER(rod_token_list);

static int
tdisk_copy_generic_copy_operations_descriptor(uint8_t *buffer)
{
	struct generic_copy_operations *ops;

	ops = (struct generic_copy_operations *)buffer;
	ops->third_party_copy_descriptor_type = htobe16(0x8001);
	ops->third_party_copy_descriptor_length = htobe16(0x0020);
	ops->total_concurrent_copies = htobe32(TOTAL_CONCURRENT_COPIES);
	ops->maximum_identified_concurrent_copies = htobe32(TOTAL_CONCURRENT_COPIES);
	return (sizeof(*ops));
}

static int
tdisk_copy_supported_third_party_commands_descriptor(uint8_t *buffer)
{
	*(uint16_t *)(&buffer[0]) = htobe16(0x0001);
	*(uint16_t *)(&buffer[2]) = htobe16(12); /* Including pad */

	buffer[4] = EXTENDED_COPY;
	buffer[5] = 0x03;
	buffer[6] = SERVICE_ACTION_EXTENDED_COPY_LID1;
	buffer[7] = SERVICE_ACTION_POPULATE_TOKEN;
	buffer[8] = SERVICE_ACTION_WRITE_USING_TOKEN;
	buffer[9] = RECEIVE_COPY_RESULTS;
	buffer[10] = 0x02;
	buffer[11] = SERVICE_ACTION_RECEIVE_COPY_STATUS_LID1;
	buffer[12] = SERVICE_ACTION_RECEIVE_ROD_TOKEN_INFORMATION;
	return (16);
}

static int
tdisk_copy_rod_token_features_descriptor(uint8_t *buffer)
{
	struct rod_token_features *features;
	struct block_rod_device_specific_features *block_features;
	int descriptor_length;

	features = (struct rod_token_features *)(buffer);
	features->third_party_copy_descriptor_type = htobe16(0x0106);
	descriptor_length = (sizeof(*features) + sizeof(*block_features) - 4);
	features->third_party_copy_descriptor_length = htobe16(descriptor_length);
	features->remote_tokens = 0x04;
	features->minimum_token_lifetime = htobe32(MINIMUM_TOKEN_LIFETIME);
	features->maximum_token_lifetime = htobe32(MAXIMUM_TOKEN_LIFETIME);
	features->maximum_token_inactivity_timeout = htobe32(MAXIMUM_INACTIVITY_TIMEOUT);
	features->device_specific_features_length = htobe16(sizeof(*block_features));
	block_features = (struct block_rod_device_specific_features *)(buffer + sizeof(*features));
	block_features->device_type = T_DIRECT;
	block_features->descriptor_length = htobe16(0x002C);
	block_features->maximum_bytes_in_block_rod = htobe64(MAXIMUM_BYTES_IN_BLOCK_ROD);
	return (descriptor_length + 4);
}

static int 
tdisk_copy_block_device_rod_token_limits_descriptor(struct tdisk *tdisk, uint8_t *buffer)
{
	struct block_device_rod_token_limits *rod_limits;

	rod_limits = (struct block_device_rod_token_limits *)buffer;
	rod_limits->third_party_copy_descriptor_length = htobe16(0x0020);
	rod_limits->maximum_range_descriptors = htobe16(MAXIMUM_RANGE_DESCRIPTORS);
	rod_limits->maximum_inactivity_timeout = htobe32(MAXIMUM_INACTIVITY_TIMEOUT);
	rod_limits->default_inactivity_timeout = htobe32(DEFAULT_INACTIVITY_TIMEOUT);
	rod_limits->maximum_token_transfer_size = htobe64(MAXIMUM_BYTES_IN_BLOCK_ROD >> tdisk->lba_shift);
	return (sizeof(*rod_limits));
}

static int
tdisk_copy_supported_rod_types_descriptor(uint8_t *buffer)
{
	struct supported_rod_types *types;
	struct rod_type_descriptor *descriptor;
	uint32_t rod_type = 0;
	int i, descriptor_length;

	types = (struct supported_rod_types *)buffer;
	types->third_party_copy_descriptor_type = htobe16(0x0108);
	descriptor_length = sizeof(*types) + (3 * sizeof(*descriptor)) - 4;
	types->third_party_copy_descriptor_length = htobe16(descriptor_length);

	for (i = 0; i < 3; i++) {
		descriptor = &types->descriptor[i];
		switch (i) {
		case 0:
			rod_type = POINT_IN_TIME_COPY_DEFAULT;
			break;
		case 1:
			rod_type = POINT_IN_TIME_COPY_CV;
			break;
		case 2:
			rod_type = POINT_IN_TIME_COPY_PERSISTENT;
			break;
		}
		descriptor->rod_type = htobe32(rod_type);
		descriptor->token_out = 0x3 | 0x80;
	}
	return (descriptor_length + 4);
}

int
tdisk_copy_third_party_copy_vpd_page(struct tdisk *tdisk, uint8_t *buffer, int allocation_length)
{
	struct third_party_vpd_page *page;
	int offset, min_len;

	page = (struct third_party_vpd_page *)(buffer);
	bzero(page, sizeof(*page));
	offset = sizeof(*page);
	offset += tdisk_copy_block_device_rod_token_limits_descriptor(tdisk, buffer+offset);
	offset += tdisk_copy_supported_third_party_commands_descriptor(buffer+offset);
	offset += tdisk_copy_rod_token_features_descriptor(buffer+offset);
	offset += tdisk_copy_supported_rod_types_descriptor(buffer+offset);
	offset += tdisk_copy_generic_copy_operations_descriptor(buffer+offset);
	page->device_type = T_DIRECT;
	page->page_code = THIRD_PARTY_COPY_VPD_PAGE;
	page->page_length = htobe16(offset - sizeof(*page));
	min_len = min_t(int, offset, allocation_length);
	return min_len;
}

static struct rod_token_spec * 
rod_token_generate(struct tdisk *tdisk, struct qsio_scsiio *ctio, uint32_t list_identifier, uint32_t rod_type, uint32_t timeout, uint8_t cmd_type)
{
	struct rod_token_spec *token;

	token = zalloc(sizeof(*token), M_ROD_TOKEN, Q_WAITOK);
	tdisk_get(tdisk);
	token->src_tdisk = tdisk;
	token->rod_type = rod_type;
	token->timeout = timeout;
	token->timestamp = ticks;
	token->copy_operation_status = COPY_OPERATION_INPROGRESS;
	
	token->list_identifier = list_identifier;
	token->cmd_type = cmd_type;
	atomic_set(&token->refs, 1);
	port_fill(token->i_prt, ctio->i_prt);
	port_fill(token->t_prt, ctio->t_prt);
	token->init_int = ctio->init_int;
	TAILQ_INIT(&token->rod_entry_list);
	return token;
}

static void
rod_entry_error_free(struct tdisk *tdisk, struct rod_entry *entry)
{
	struct pgdata **pglist = entry->pglist;
	int pglist_cnt = entry->pglist_cnt;

	free_block_refs(tdisk, &entry->index_info_list);
	pgdata_free_amaps(pglist, pglist_cnt);
	pglist_free(pglist, pglist_cnt);
	free(entry, M_ROD_TOKEN_ENTRY);
}

static void
rod_token_error_free(struct rod_token_spec *token)
{
	struct tdisk *tdisk = token->src_tdisk;
	struct rod_entry *entry;

	while ((entry = TAILQ_FIRST(&token->rod_entry_list)) != NULL) {
		TAILQ_REMOVE(&token->rod_entry_list, entry, r_list);
		rod_entry_error_free(tdisk, entry);
	}

	tdisk_put(tdisk);
	free(token, M_ROD_TOKEN);
}

static int
rod_token_add_descriptor(struct tdisk *tdisk, struct qsio_scsiio *ctio, struct rod_token_spec *token, struct block_range_descriptor *descriptor)
{
	struct rod_entry *entry;
	struct lba_write *lba_write;
	uint64_t lba;
	uint32_t num_blocks;
	int retval;

	lba = be64toh(descriptor->lba);
	num_blocks = be32toh(descriptor->num_blocks);

	entry = zalloc(sizeof(*entry), M_ROD_TOKEN_ENTRY, Q_WAITOK);
	entry->lba = lba;
	if (tdisk->lba_shift != LBA_SHIFT) {
		entry->lba_diff = (lba - (lba & ~0x7ULL));
	}
	entry->num_blocks = num_blocks;

	TAILQ_INIT(&entry->index_info_list);
	lba_write = tdisk_add_lba_write(tdisk, lba, num_blocks, 0, QS_IO_READ, 0);
	retval = __tdisk_cmd_ref_int(tdisk, tdisk, ctio, &entry->pglist, &entry->pglist_cnt, lba - entry->lba_diff, num_blocks + entry->lba_diff, &entry->index_info_list, 0, 1);
	tdisk_remove_lba_write(tdisk, &lba_write);
	if (unlikely(retval != 0)) {
		free(entry, M_ROD_TOKEN_ENTRY);
		return -1;
	}
	TAILQ_INSERT_TAIL(&token->rod_entry_list, entry, r_list);
	return 0;
}

static void
rod_token_put(struct rod_token_spec *token)
{
	sx_xlock(rod_lock);
	atomic_dec(&token->refs);
	if (!token->del_token || atomic_read(&token->refs) > 1) {
		sx_xunlock(rod_lock);
		return;
	}
	TAILQ_REMOVE(&rod_token_list, token, t_list);
	sx_xunlock(rod_lock);
	rod_token_error_free(token);
}

static struct rod_token_spec * 
rod_token_find_for_list_identifier(struct tdisk *tdisk, struct qsio_scsiio *ctio, uint32_t list_identifier)
{
	struct rod_token_spec *token;

	TAILQ_FOREACH(token, &rod_token_list, t_list) {
		if (token->list_identifier != list_identifier)
			continue;
		if (!iid_equal(token->i_prt, token->t_prt, token->init_int, ctio->i_prt, ctio->t_prt, ctio->init_int))
			continue;
		token->timestamp = ticks;
		atomic_inc(&token->refs);
		return token;
	}
	return NULL;
}

static int
lba_in_range(uint64_t first_lba_start, uint64_t first_lba_end, uint64_t second_lba_start, uint64_t second_lba_end)
{
	if (first_lba_end <= second_lba_start)
		return 0;

	if (second_lba_end <= first_lba_start)
		return 0;

	return 1;
}

static int
descriptor_valid(struct tdisk *tdisk, struct qsio_scsiio *ctio, struct block_range_descriptor *head, struct block_range_descriptor *descriptor, int max, int skip_id)
{
	struct block_range_descriptor *tmp;
	uint64_t lba_start, lba_end;
	uint64_t tmp_lba_start, tmp_lba_end;
	uint32_t num_blocks;
	int i;

	lba_start = be64toh(descriptor->lba);
	num_blocks = be32toh(descriptor->num_blocks);
	lba_end = lba_start + num_blocks;

	if (reached_eom(tdisk, lba_start, num_blocks)) {
		ctio_free_data(ctio);
		ctio_construct_sense(ctio, SSD_CURRENT_ERROR, SSD_KEY_ILLEGAL_REQUEST, 0, LOGICAL_BLOCK_ADDRESS_OUT_OF_RANGE_ASC, LOGICAL_BLOCK_ADDRESS_OUT_OF_RANGE_ASCQ);
		return 0;
	}

	for (i = 0; i < max; i++) {
		if (i == skip_id)
			continue;
		tmp = &head[i];
		tmp_lba_start = be64toh(tmp->lba);
		tmp_lba_end = tmp_lba_start + be32toh(tmp->num_blocks);
		if (lba_in_range(lba_start, lba_end, tmp_lba_start, tmp_lba_end)) {
			ctio_free_data(ctio);
			tdisk_invalid_field_in_parameter_list_sense(tdisk, ctio);
			return 0;
		}
	}
	return num_blocks;
}

void
tdisk_cmd_populate_token(struct tdisk *tdisk, struct qsio_scsiio *ctio)
{
	uint8_t *cdb = ctio->cdb;
	struct populate_token_header *header;
	struct block_range_descriptor *descriptor;
	struct rod_token_spec *token, *tmp;
	struct pgdata **pglist, *pgdata;
	uint64_t transfer_size = 0, descriptor_size;
	uint32_t parameter_list_length, rod_type, timeout;
	uint32_t list_identifier;
	uint16_t descriptor_length, num_descriptors;
	int retval = 0, i;
	uint8_t rtv;

	parameter_list_length = be32toh(*(uint32_t *)(&cdb[10]));
	if (!parameter_list_length) {
		ctio_free_data(ctio);
		goto send;
	}

	if (parameter_list_length < 16) {
		ctio_free_data(ctio);
		tdisk_parameter_list_length_error_sense(tdisk, ctio);
		goto send;
	}

	pglist = (struct pgdata **)(ctio->data_ptr);
	pgdata = pglist[0];
	header = (struct populate_token_header *)(pgdata_page_address(pgdata));
	if (be16toh(header->populate_token_data_length) < 0x1E) {
		ctio_free_data(ctio);
		tdisk_invalid_field_in_parameter_list_sense(tdisk, ctio);
		goto send;
	}

	rtv = READ_BIT(cdb[1], 1);
	rod_type = be32toh(header->rod_type);
	if (rtv) {
		switch (rod_type) {
		case POINT_IN_TIME_COPY_DEFAULT:
		case POINT_IN_TIME_COPY_CV:
		case POINT_IN_TIME_COPY_PERSISTENT:
			break;
		default:
			ctio_free_data(ctio);
			tdisk_invalid_field_in_parameter_list_sense(tdisk, ctio);
			goto send;
		}
	}
	else
		rod_type = POINT_IN_TIME_COPY_DEFAULT;

	if (header->inactivity_timeout) {
		timeout = be32toh(header->inactivity_timeout);
		if (timeout > MAXIMUM_INACTIVITY_TIMEOUT) {
			ctio_free_data(ctio);
			tdisk_invalid_field_in_parameter_list_sense(tdisk, ctio);
			goto send;
		}
	}
	else
		timeout = DEFAULT_INACTIVITY_TIMEOUT;

	descriptor_length = be16toh(header->block_device_range_descriptor_length);
	if (descriptor_length < 16) {
		ctio_free_data(ctio);
		tdisk_invalid_field_in_parameter_list_sense(tdisk, ctio);
		goto send;
	}
 
	num_descriptors = descriptor_length/sizeof(*descriptor);
	if (num_descriptors > MAXIMUM_RANGE_DESCRIPTORS) {
		ctio_free_data(ctio);
		ctio_construct_sense(ctio, SSD_CURRENT_ERROR, SSD_KEY_ILLEGAL_REQUEST, 0, TOO_MANY_SEGMENT_DESCRIPTORS_ASC, TOO_MANY_SEGMENT_DESCRIPTORS_ASCQ);
		goto send;
	}

	for (i = 0; i < num_descriptors; i++) {
		descriptor = &header->descriptor[i];
		descriptor_size = descriptor_valid(tdisk, ctio, header->descriptor, descriptor, num_descriptors, i);
		if (!descriptor_size)
			goto send;
		transfer_size += descriptor_size;
	}

	if ((transfer_size << tdisk->lba_shift) > MAXIMUM_BYTES_IN_BLOCK_ROD) {
		ctio_free_data(ctio);
		tdisk_invalid_field_in_parameter_list_sense(tdisk, ctio);
		goto send;
	}

	list_identifier = be32toh(*(uint32_t *)(&cdb[6]));
	token = rod_token_generate(tdisk, ctio, list_identifier, rod_type, timeout, ROD_POPULATE_TOKEN_CMD);

	for (i = 0; i < num_descriptors; i++) {
		descriptor = &header->descriptor[i];
		retval = rod_token_add_descriptor(tdisk, ctio, token, descriptor);
		if (unlikely(retval)) {
			goto cleanup;
		}
	}

	sx_xlock(rod_lock);
	tmp = rod_token_find_for_list_identifier(tdisk, ctio, list_identifier);
	if (tmp) {
		rod_token_put(tmp);
		sx_xunlock(rod_lock);
		ctio_free_data(ctio);
		tdisk_invalid_field_in_parameter_list_sense(tdisk, ctio);
		goto cleanup;
	}

	token->copy_operation_status = COPY_OPERATION_OK;
	token->rod_identifier = ++rod_identifier;
	token->read_transfer_count = transfer_size;
	TDISK_STATS_ADD(tdisk, populate_token_size, transfer_size << tdisk->lba_shift);
	TAILQ_INSERT_TAIL(&rod_token_list, token, t_list);
	sx_xunlock(rod_lock);
	ctio_free_data(ctio);
	device_send_ccb(ctio);
	return;
cleanup:
	rod_token_error_free(token);
send:
	device_send_ccb(ctio);
}

struct receive_rod_token_information_header {
	uint32_t available_data;
	uint8_t response_to_service_action;
	uint8_t copy_operation_status;
	uint16_t operation_counter;
	uint32_t estimated_status_update_delay;
	uint8_t extended_copy_completion_status;
	uint8_t length_of_sense_data_field;
	uint8_t sense_data_length;
	uint8_t transfer_count_units;
	uint64_t transfer_count;
	uint16_t segments_processed;
	uint8_t rsvd[6];
	uint32_t rod_token_descriptor_length;
} __attribute__ ((__packed__));

struct rod_token_format {
	uint32_t rod_type;
	uint16_t rsvd;
	uint16_t rod_token_length;
	uint64_t copy_manager_rod_token_identifier;
	uint8_t creator_logical_unit_descriptor[32];
	uint64_t number_of_bytes_represented1;
	uint64_t number_of_bytes_represented0;
	uint8_t rsvd1[32];
	uint8_t device_specific_data[32];
	uint8_t target_device_descriptor[32];
	uint8_t extended_rod_token_data[32];
	uint8_t pad[320];
} __attribute__ ((__packed__));

static void
fill_naa_identifier(uint8_t *buffer, struct logical_unit_naa_identifier *naa_identifier)
{
	buffer[0] = 0xE4;
	buffer[1] = T_DIRECT;
	memcpy(buffer+4, naa_identifier, sizeof(*naa_identifier));
}

static int 
fill_rod_token(struct tdisk *tdisk, uint8_t *buffer, struct rod_token_spec *token)
{
	struct rod_token_format *format = (struct rod_token_format *)buffer;
	struct logical_unit_naa_identifier *naa_identifier;
	uint32_t *extended_rod_token_data;

	format->rod_type = htobe32(token->rod_type);
	format->rod_token_length = htobe16(sizeof(*format) - 8);
	format->copy_manager_rod_token_identifier = htobe64(token->rod_identifier);
	fill_naa_identifier(format->creator_logical_unit_descriptor, &tdisk->naa_identifier); 
	naa_identifier = (struct logical_unit_naa_identifier *)format->target_device_descriptor;
	memcpy(naa_identifier, &tdisk->naa_identifier, sizeof(*naa_identifier));
	naa_identifier->identifier_type |= (0x10 << 4);
	extended_rod_token_data = (uint32_t *)(format->extended_rod_token_data);
	extended_rod_token_data[0] = ticks;
	extended_rod_token_data[1] = ticks;
	return (sizeof(*format));
}

int 
tdisk_cmd_receive_rod_token_information(struct tdisk *tdisk, struct qsio_scsiio *ctio)
{
	uint8_t *cdb = ctio->cdb;
	struct receive_rod_token_information_header *header;
	struct rod_token_spec *token;
	uint32_t list_identifier;
	uint32_t allocation_length;
	int max_allocation_length;
	int avail, min_len, rod_length;

	allocation_length = be32toh(*((uint32_t *)(&cdb[10])));
	if (!allocation_length)
		return 0;

	list_identifier = be32toh(*((uint32_t *)(&cdb[2])));
	sx_xlock(rod_lock);
	token = rod_token_find_for_list_identifier(tdisk, ctio, list_identifier);
	sx_xunlock(rod_lock);
	if (!token) {
		tdisk_invalid_field_in_cdb_sense(tdisk, ctio);
		return 0;
	}

	max_allocation_length = max_t(int, 512, allocation_length);
	ctio_allocate_buffer(ctio, max_allocation_length, Q_NOWAIT);
	if (unlikely(!ctio->data_ptr)) {
		rod_token_put(token);
		return -1;
	}

	bzero(ctio->data_ptr, ctio->dxfer_len);
	header = (struct receive_rod_token_information_header *)ctio->data_ptr;
	if (token->cmd_type == ROD_POPULATE_TOKEN_CMD) {
		header->response_to_service_action = 0x10;
		header->transfer_count = htobe64(token->read_transfer_count);
	} else {
		header->response_to_service_action = 0x11;
		header->transfer_count = htobe64(token->write_transfer_count);
	}
	header->copy_operation_status = token->copy_operation_status;
	header->transfer_count_units = 0xF1;

	avail = sizeof(*header) - 4;
	if (token->cmd_type == ROD_POPULATE_TOKEN_CMD) {
		rod_length = fill_rod_token(tdisk, ctio->data_ptr + sizeof(*header) + 2, token);
		avail += (rod_length + 2);
		header->rod_token_descriptor_length = htobe32(rod_length + 2);
	}
	rod_token_put(token);
	header->available_data = htobe32(avail);

	min_len = min_t(int,  (avail + 4), allocation_length);
	ctio->dxfer_len = min_len;
	return 0;
}

struct write_using_token_header {
	uint16_t write_using_token_data_length;
	uint8_t immed;
	uint8_t rsvd[5];
	uint64_t offset_into_rod;
	uint8_t rod_token[512];
	uint8_t rsvd1[6];
	uint16_t block_device_range_descriptor_length;
	struct block_range_descriptor descriptor[0];
} __attribute__ ((__packed__));

static struct rod_token_spec *
rod_token_find(struct tdisk *tdisk, struct qsio_scsiio *ctio, uint64_t rod_identifier)
{
	struct rod_token_spec *token;

	TAILQ_FOREACH(token, &rod_token_list, t_list) {
		if (token->rod_identifier == rod_identifier) {
			token->timestamp = ticks;
			atomic_inc(&token->refs);
			return token;
		}
	}

	return NULL;
}

static struct rod_entry * 
rod_entry_locate(struct rod_token_spec *token, uint32_t offset_blocks, uint32_t *start_block)
{
	struct rod_entry *entry;
	uint64_t done_blocks = 0;

	TAILQ_FOREACH(entry, &token->rod_entry_list, r_list) {
		if ((entry->num_blocks + done_blocks) <= offset_blocks) {
			done_blocks += entry->num_blocks;
			continue;
		}
		*start_block = (offset_blocks - done_blocks);
		return entry;
	}
	return NULL;
}

static int
read_from_rod_entry(struct tdisk *tdisk, struct qsio_scsiio *ctio, uint32_t blocks, struct pgdata ***ret_pglist, int *ret_pglist_cnt, struct rod_entry *entry, int rod_idx, int rod_pglist_cnt)
{
	struct tcache *tcache;
	struct pgdata *pgdata, *src_pgdata, **pglist;
	struct bdevint *bint, *prev_bint = NULL;
	uint64_t amap_entry_block;
	struct amap_table_list table_list;
	struct index_info_list index_info_list;
	struct pgdata_wlist read_list;
	struct rcache_entry_list rcache_list;
	int pglist_cnt, i, retval;

	STAILQ_INIT(&table_list);
	TAILQ_INIT(&index_info_list);
	STAILQ_INIT(&read_list);
	TAILQ_INIT(&rcache_list);

	pglist_cnt = rod_pglist_cnt - rod_idx;
	debug_check(pglist_cnt <= 0);
 
	pglist = pgdata_allocate_nopage(pglist_cnt, Q_NOWAIT);
	if (!pglist)
		return -1;

	tcache = tcache_alloc(pglist_cnt);

	for (i = rod_idx; i < rod_pglist_cnt; i++) {
		src_pgdata = entry->pglist[i];
		pgdata = pglist[i];
		amap_entry_block = src_pgdata->amap_block;
		pgdata->amap_block = amap_entry_block;
		if (!amap_entry_block) {
			atomic_set_bit(DDBLOCK_ZERO_BLOCK, &pgdata->flags);
			atomic_set_bit(PGDATA_SKIP_DDCHECK, &pgdata->flags);
			atomic_set_bit(PGDATA_SKIP_UNCOMP, &pgdata->flags);
			pgdata_add_ref(pgdata, &pgzero);
			continue;
		}
		if (!prev_bint || (prev_bint->bid != BLOCK_BID(amap_entry_block))) {
			bint = bdev_find(BLOCK_BID(amap_entry_block));
			if (unlikely(!bint)) {
				debug_warn("Cannot locate bint at bid %u\n", BLOCK_BID(amap_entry_block));
				goto err;
			}
			prev_bint = bint;
		}
		else {
			bint = prev_bint;
		}

		retval = pgdata_alloc_page(pgdata, 0);
		if (unlikely(retval != 0)) {
			debug_warn("allocating for pgdata page failed\n");
			goto err;
		}

		if (pgdata_in_read_list(tdisk, pgdata, &read_list, 0))
			continue;

		if (rcache_locate(pgdata, 0))
			continue;

		retval = tcache_add_page(tcache, pgdata->page, BLOCK_BLOCKNR(amap_entry_block), bint, lba_block_size(amap_entry_block), QS_IO_READ);
		if (unlikely(retval != 0)) {
			debug_warn("Failed to add page to tcache\n");
			goto err;
		}
	}

	if (!atomic_read(&tcache->bio_remain))
		goto skip_io;

	tcache_entry_rw(tcache, QS_IO_READ);
	wait_for_done(tcache->completion);

	if (atomic_test_bit_short(TCACHE_IO_ERROR, &tcache->flags))
		goto err;

	tcache_read_comp(tcache);
skip_io:
	retval = pgdata_post_read_io(pglist, pglist_cnt, &rcache_list, 1, 0, 0);
	rcache_list_insert(&rcache_list);
	if (unlikely(retval != 0))
		goto err;

	tcache_put(tcache);
	*ret_pglist = pglist;
	*ret_pglist_cnt = pglist_cnt;
	return 0;
err:
	tcache_put(tcache);
	pgdata_free_amaps(pglist, pglist_cnt);
	pglist_free(pglist, pglist_cnt);
	*ret_pglist = NULL;
	*ret_pglist_cnt = 0;
	rcache_list_free(&rcache_list);
	return -1;
}

static int
rod_entry_amap_modified(struct tdisk *tdisk, struct rod_entry *entry, int rod_idx, int rod_pglist_cnt)
{
	struct pgdata *pgdata;
	struct amap *amap = NULL;
	struct amap_table *amap_table = NULL;
	struct amap_table_list table_list;
	struct index_info_list index_info_list;
	uint64_t amap_entry_block;
	uint32_t entry_id;
	int i, retval, modified = 0;

	STAILQ_INIT(&table_list);
	TAILQ_INIT(&index_info_list);
	for (i = rod_idx; i < rod_pglist_cnt; i++) {
		pgdata = entry->pglist[i];
		retval = lba_unmapped(tdisk, pgdata->lba, pgdata, &table_list, amap_table, amap);
		if (retval < 0) {
			modified = 1;
			goto out;
		}
		amap_table = pgdata->amap_table;
		amap = pgdata->amap;
	}

	retval = pgdata_check_table_list(&table_list, &index_info_list, NULL, QS_IO_READ, 0);
	if (unlikely(retval != 0)) {
		modified = 1;
		goto out;
	}

	for (i = rod_idx; i < rod_pglist_cnt; i++) {
		pgdata = entry->pglist[i];
		amap = pgdata->amap;
		if (!amap) {
			if (pgdata->amap_block) {
				modified = 1;
				break;
			}
			continue;
		}

		entry_id = amap_entry_id(amap, pgdata->lba);
		amap_read_lock(amap);
		amap_entry_block = amap_entry_get_block(amap, entry_id);
		amap_read_unlock(amap);
		if (pgdata->amap_block != amap_entry_block) {
			modified = 1;
			break;
		}
	}
out:
	pgdata_free_amaps(entry->pglist, entry->pglist_cnt);
	return modified;
}

static int
copy_to_dest_range(struct qsio_scsiio *ctio, struct tdisk *dest_tdisk, uint64_t dest_lba, uint32_t dest_blocks, struct tdisk *src_tdisk, uint64_t src_lba, uint32_t src_blocks, struct rod_entry *entry, int rod_idx, int rod_pglist_cnt, int *skip_send)
{
	struct lba_write *lba_write;
	struct pgdata **pglist;
	struct index_info_list index_info_list;
	uint64_t lba_diff;
	uint32_t xchg_id;
	int mirror_enabled, use_refs;
	int unaligned, retval;
	int pglist_cnt, amap_modified;
	uint32_t size;

	TAILQ_INIT(&index_info_list);

	size = src_blocks << src_tdisk->lba_shift;
	if (entry->lba_diff)
		unaligned = 1;
	else
		unaligned = is_unaligned_extended_copy(src_tdisk, src_lba, dest_lba, size);
	xchg_id = 0;
	mirror_enabled = 0;
	use_refs = 0;

	debug_check(rod_pglist_cnt > entry->pglist_cnt);
	lba_write = tdisk_add_lba_write(src_tdisk, src_lba, src_blocks, 0, QS_IO_READ, 0);
	if (!unaligned)
		amap_modified = rod_entry_amap_modified(src_tdisk, entry, rod_idx, rod_pglist_cnt);
	else
		amap_modified = 1;
	if (!unaligned && !amap_modified) {
		retval = extended_copy_mirror_check(src_tdisk, ctio, dest_tdisk, src_lba, dest_lba, src_blocks, &mirror_enabled, &use_refs, &xchg_id);
		if (unlikely(retval != 0)) {
			tdisk_remove_lba_write(src_tdisk, &lba_write);
			return -1;
		}

		retval = __tdisk_cmd_ref_int(src_tdisk, dest_tdisk, ctio, &pglist, &pglist_cnt, src_lba, src_blocks, &index_info_list, mirror_enabled, use_refs);
		tdisk_remove_lba_write(src_tdisk, &lba_write);
		if (unlikely(retval != 0))
			return -1;
	}
	else {
		pglist = NULL;
		retval = read_from_rod_entry(src_tdisk, ctio, src_blocks, &pglist, &pglist_cnt, entry, rod_idx, rod_pglist_cnt);
		tdisk_remove_lba_write(src_tdisk, &lba_write);
		if (unlikely(retval != 0))
			return -1;
		if (src_tdisk->lba_shift != LBA_SHIFT) {
			int pg_offset;
			struct pgdata *pgdata;

			lba_diff = (src_lba - (src_lba & ~0x7ULL));
			pg_offset = (lba_diff << src_tdisk->lba_shift);
			pgdata = pglist[0];
			pgdata->pg_offset = pg_offset;
			pgdata->pg_len -= pg_offset;
			if (pg_offset) {
				retval = remap_pglist_for_write(&pglist, &pglist_cnt, size);
				if (unlikely(retval != 0)) {
					return -1;
				}
			}
		}
	}

	ctio->dxfer_len = size;
	ctio->data_ptr = (void *)pglist;
	ctio->pglist_cnt = pglist_cnt;
	pglist_calc_hash(dest_tdisk, pglist, pglist_cnt, mirror_enabled, use_refs);
	retval = __tdisk_cmd_write(dest_tdisk, ctio, dest_lba, dest_blocks, 0, 0, &index_info_list, 0, 0, xchg_id);
	if (unlikely(retval != 0)) {
		free_block_refs(dest_tdisk, &index_info_list);
		*skip_send = 1;
		return -1;
	}
	debug_check(!TAILQ_EMPTY(&index_info_list));
	return 0;
}

static int
rod_token_process_descriptor(struct tdisk *tdisk, struct qsio_scsiio *ctio, struct rod_token_spec *token, struct block_range_descriptor *descriptor, uint64_t *ret_offset_into_rod, int *skip_send)
{
	struct tdisk *src_tdisk = token->src_tdisk;
	struct rod_entry *entry;
	uint64_t dest_lba, src_lba;
	uint32_t dest_num_blocks, src_num_blocks, from_blocks, to_blocks;
	uint64_t offset_into_rod = *ret_offset_into_rod;
	uint32_t span, offset_blocks, start_block;
	uint32_t src_size, src_end_size, dest_size, min_size, rod_idx, rod_pglist_cnt;
	int retval;

	dest_lba = be64toh(descriptor->lba);
	dest_num_blocks = be32toh(descriptor->num_blocks);

	span = offset_into_rod << tdisk->lba_shift;
	offset_blocks = span >> src_tdisk->lba_shift;

	entry = rod_entry_locate(token, offset_blocks, &start_block);
	if (unlikely(!entry)) {
		ctio_free_data(ctio);
		tdisk_invalid_field_in_parameter_list_sense(tdisk, ctio);
		return -1;
	}

	while (entry && dest_num_blocks) {
		src_lba = entry->lba + start_block;
		src_num_blocks = entry->num_blocks - start_block;
		src_size = (start_block + entry->lba_diff) << src_tdisk->lba_shift;
		src_end_size = src_size + (src_num_blocks << src_tdisk->lba_shift);
		rod_idx = src_size >> LBA_SHIFT;
		rod_pglist_cnt = src_end_size >> LBA_SHIFT;
		if (src_end_size & LBA_MASK)
			rod_pglist_cnt++;
		if (!src_num_blocks) {
			start_block = 0;
			entry = TAILQ_NEXT(entry, r_list);
			continue;
		}
		src_size = src_num_blocks << src_tdisk->lba_shift;
		dest_size = dest_num_blocks << tdisk->lba_shift;
		min_size = min_t(uint32_t, src_size, dest_size);
		from_blocks = min_size >> src_tdisk->lba_shift;
		to_blocks = min_size >> tdisk->lba_shift;
		retval = copy_to_dest_range(ctio, tdisk, dest_lba, to_blocks, src_tdisk, src_lba, from_blocks, entry, rod_idx, rod_pglist_cnt, skip_send); 
		if (unlikely(retval != 0)) {
			goto err;
		}
		dest_num_blocks -= to_blocks;
		dest_lba += to_blocks;
		start_block += from_blocks;
		if (start_block == entry->num_blocks) {
			start_block = 0;
			entry = TAILQ_NEXT(entry, r_list);
		}
	}

	return 0;
err:
	token->copy_operation_status = COPY_OPERATION_ERROR;
	return -1;
}

void
tdisk_cmd_write_using_token(struct tdisk *tdisk, struct qsio_scsiio *ctio)
{
	uint8_t *cdb = ctio->cdb;
	struct rod_token_spec *token = NULL;
	struct write_using_token_header *header;
	struct rod_token_format *format;
	struct block_range_descriptor *descriptor;
	struct pgdata **pglist, *pgdata;
	uint64_t rod_identifier;
	uint64_t offset_into_rod;
	uint64_t transfer_size = 0, descriptor_size;
	uint32_t list_identifier;
	uint32_t parameter_list_length;
	int i, retval, pglist_cnt, skip_send = 0;
	uint16_t descriptor_length, num_descriptors, token_data_length;
	uint8_t del_token;

	parameter_list_length = be32toh(*(uint32_t *)(&cdb[10]));
	if (!parameter_list_length) {
		ctio_free_data(ctio);
		goto send;
	}

	if (parameter_list_length < 552) {
		ctio_free_data(ctio);
		tdisk_invalid_field_in_cdb_sense(tdisk, ctio);
		goto send;
	}

	list_identifier = be32toh(*((uint32_t *)(&cdb[6])));

	pglist = (struct pgdata **)(ctio->data_ptr);
	pglist_cnt = ctio->pglist_cnt;
	pgdata = pglist[0];
	header = (struct write_using_token_header *)(pgdata_page_address(pgdata));
	token_data_length = be16toh(header->write_using_token_data_length);
	descriptor_length = be16toh(header->block_device_range_descriptor_length);
	del_token = (header->immed >> 1) & 0x01;

	if (token_data_length < 550) {
		ctio_free_data(ctio);
		tdisk_invalid_field_in_parameter_list_sense(tdisk, ctio);
		goto send;
	}

	if (token_data_length != (534 + descriptor_length)) {
		ctio_free_data(ctio);
		tdisk_invalid_field_in_parameter_list_sense(tdisk, ctio);
		goto send;
	}

	num_descriptors = descriptor_length/sizeof(*descriptor);
	if (num_descriptors > MAXIMUM_RANGE_DESCRIPTORS) {
		ctio_free_data(ctio);
		ctio_construct_sense(ctio, SSD_CURRENT_ERROR, SSD_KEY_ILLEGAL_REQUEST, 0, TOO_MANY_SEGMENT_DESCRIPTORS_ASC, TOO_MANY_SEGMENT_DESCRIPTORS_ASCQ);
		goto send;
	}

	for (i = 0; i < num_descriptors; i++) {
		descriptor = &header->descriptor[i];
		descriptor_size = descriptor_valid(tdisk, ctio, header->descriptor, descriptor, num_descriptors, i);
		if (!descriptor_size)
			goto send;
		transfer_size += descriptor_size;
	}

	if ((transfer_size << tdisk->lba_shift) > MAXIMUM_BYTES_IN_BLOCK_ROD) {
		ctio_free_data(ctio);
		tdisk_invalid_field_in_parameter_list_sense(tdisk, ctio);
		goto send;
	}

	format = (struct rod_token_format *)(header->rod_token);
	rod_identifier = be64toh(format->copy_manager_rod_token_identifier);
	offset_into_rod = be64toh(header->offset_into_rod);

	sx_xlock(rod_lock);
	token = rod_token_find(tdisk, ctio, rod_identifier); 
	if (!token) {
		sx_xunlock(rod_lock);
		ctio_free_data(ctio);
		ctio_construct_sense(ctio, SSD_CURRENT_ERROR, SSD_KEY_ILLEGAL_REQUEST, 0, INVALID_TOKEN_OPERATION_TOKEN_UNKNOWN_ASC, INVALID_TOKEN_OPERATION_TOKEN_UNKNOWN_ASCQ);
		goto send;
	}
	if (del_token)
		token->del_token = 1;
	sx_xunlock(rod_lock);

	if (token->src_tdisk->lba_shift != tdisk->lba_shift) {
		ctio_free_data(ctio);
		ctio_construct_sense(ctio, SSD_CURRENT_ERROR, SSD_KEY_ILLEGAL_REQUEST, 0, UNREACHABLE_COPY_TARGET_ASC, UNREACHABLE_COPY_TARGET_ASCQ);
		goto send;
	}

	ctio->data_ptr = NULL;
	ctio->pglist_cnt = 0;
	ctio->dxfer_len = 0;
	token->list_identifier = list_identifier;
	token->cmd_type = ROD_WRITE_TOKEN_CMD; 

	for (i = 0; i < num_descriptors; i++) {
		descriptor = &header->descriptor[0];
		retval = rod_token_process_descriptor(tdisk, ctio, token, descriptor, &offset_into_rod, &skip_send);
		if (unlikely(retval)) {
			pglist_free(pglist, pglist_cnt);
			goto send;
		}
	}

	token->copy_operation_status = COPY_OPERATION_OK;
	token->write_transfer_count += transfer_size;
	TDISK_STATS_ADD(tdisk, write_using_token_size, transfer_size << tdisk->lba_shift);
	rod_token_put(token);
	pglist_free(pglist, pglist_cnt);
	device_send_ccb(ctio);
	return;
send:
	if (token)
		rod_token_put(token);
	if (!skip_send)
		device_send_ccb(ctio);
}

kproc_t *copy_mgr_task;
wait_chan_t *copy_mgr_wait;
int copy_mgr_flags;

enum {
	COPY_MGR_EXIT,
};

static void
copy_mgr_free_timedout_tokens(void)
{
	struct rod_token_spec *token, *next;
	unsigned long elapsed;

	TAILQ_FOREACH_SAFE(token, &rod_token_list, t_list, next) {
		elapsed = get_elapsed(token->timestamp);
		if (ticks_to_msecs(elapsed) < (token->timeout * 1000))
			continue;
		debug_check(atomic_read(&token->refs) > 1);
		TAILQ_REMOVE(&rod_token_list, token, t_list);
		rod_token_error_free(token);
	}

}

#ifdef FREEBSD 
static void copy_mgr_thr(void *data)
#else
static int copy_mgr_thr(void *data)
#endif
{
	while (1) {
		wait_on_chan_timeout(copy_mgr_wait, kernel_thread_check(&copy_mgr_flags, COPY_MGR_EXIT), 10000);
		if (kernel_thread_check(&copy_mgr_flags, COPY_MGR_EXIT))
			break;
		sx_xlock(rod_lock);
		copy_mgr_free_timedout_tokens();
		sx_xunlock(rod_lock);
	}

#ifdef FREEBSD 
	kproc_exit(0);
#else
	return 0;
#endif
}

int
copy_manager_init(void)
{
	int retval;

	copy_mgr_wait = wait_chan_alloc("copy mgr wait");

	retval = kernel_thread_create(copy_mgr_thr, NULL, copy_mgr_task, "copymgrthr");
	if (unlikely(retval != 0))
		return retval;

	return 0;
}


void
copy_manager_exit(void)
{
	struct rod_token_spec *token;
	int err = 0;

	if (copy_mgr_task) {
		err = kernel_thread_stop(copy_mgr_task, &copy_mgr_flags, copy_mgr_wait, COPY_MGR_EXIT);
	}
	sx_xlock(rod_lock);
	while ((token = TAILQ_FIRST(&rod_token_list)) != NULL) {
		debug_check(atomic_read(&token->refs) > 1);
		TAILQ_REMOVE(&rod_token_list, token, t_list);
		rod_token_error_free(token);
	}
	sx_xunlock(rod_lock);
	if (!err && copy_mgr_wait) {
		wait_chan_free(copy_mgr_wait);
	}

}
