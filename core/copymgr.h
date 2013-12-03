#ifndef QS_COPYMGR_H_
#define QS_COPYMGR_H_
#include "vdevdefs.h"

struct tdisk;

#define SERVICE_ACTION_EXTENDED_COPY_LID1	0x00
#define SERVICE_ACTION_POPULATE_TOKEN		0x10
#define SERVICE_ACTION_WRITE_USING_TOKEN	0x11

#define SERVICE_ACTION_RECEIVE_COPY_STATUS_LID1		0x00
#define SERVICE_ACTION_RECEIVE_COPY_OPERATING_PARAMETERS	0x03
#define SERVICE_ACTION_RECEIVE_ROD_TOKEN_INFORMATION	0x07

void tdisk_cmd_populate_token(struct tdisk *tdisk, struct qsio_scsiio *ctio);
int tdisk_copy_third_party_copy_vpd_page(struct tdisk *tdisk, uint8_t *buffer, int allocation_length);
int tdisk_cmd_receive_rod_token_information(struct tdisk *tdisk, struct qsio_scsiio *ctio);
void tdisk_cmd_write_using_token(struct tdisk *tdisk, struct qsio_scsiio *ctio);
int copy_manager_init(void);
void copy_manager_exit(void);
#endif
