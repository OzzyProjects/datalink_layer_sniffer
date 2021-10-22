/* Header of new bluetooth sniffer engine */

#ifndef BLUESOCK_H
#define BLUESOCK_H

#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdint.h>
#include <string.h>
#include <sys/time.h>

// Some Bluetooth Protocols families

#define BLUESOCK_TYPE_HCI				1001
#define BLUESOCK_TYPE_UART				1002
#define BLUESOCK_TYPE_BCSP				1003
#define BLUESOCK_TYPE_3WIRE				1004

#define BLUESOCK_TYPE_EXTENDED_HCI		2001
#define BLUESOCK_TYPE_EXTENDED_PHY		2002

// List of available opcodes for the capture now

#define BLUESOCK_OPCODE_NEW_INDEX		0
#define BLUESOCK_OPCODE_DEL_INDEX		1
#define BLUESOCK_OPCODE_COMMAND_PKT		2
#define BLUESOCK_OPCODE_EVENT_PKT		3
#define BLUESOCK_OPCODE_ACL_TX_PKT		4
#define BLUESOCK_OPCODE_ACL_RX_PKT		5
#define BLUESOCK_OPCODE_SCO_TX_PKT		6
#define BLUESOCK_OPCODE_SCO_RX_PKT		7


typedef struct bluesock_hdr{

	uint8_t		id[8];
	uint32_t	version;
	uint32_t	type;

} __attribute__ ((packed)) bluesock_hdr;


#define BLUESOCK_HDR_SIZE (sizeof(struct bluesock_hdr))


// I won't use the writting part, i'm not interested

typedef struct bluesock_pkt {

	uint32_t	size;
	uint32_t	len;
	uint32_t	flags;
	uint32_t	drops;	
	uint64_t	ts;
	uint8_t		data[0];

} __attribute__ ((packed)) bluesock_pkt;


#define BLUESOCK_PKT_SIZE (sizeof(struct bluesock_pkt))


typedef enum BLUESOCK_STATUS {

	BLUESOCK_STATUS_EXIT_SUCCUES = 0,
	BLUESOCK_STATUS_ERROR_INVALID_FD,
	BLUESOCK_STATUS_ERROR_IO_FILE,
	BLUESOCK_STATUS_ERROR_SOCKET,
	BLUESOCK_STATUS_ERROR_ACCESS_DENIED,
	BLUESOCK_STATUS_ERROR_INVALID_PARAM,
	BLUESOCK_STATUS_ERROR_FATAL_ERROR,
	
} BLUESOCK_STATUS;


static uint32_t get_flags_from_opcode(uint16_t);
static uint16_t get_opcode_from_flags(uint8_t, uint32_t);

BLUESOCK_STATUS bluesock_create(const char *path, uint32_t type);
BLUESOCK_STATUS bluesock_write(struct timeval *tv, uint32_t flags, const void *data, uint16_t size);
BLUESOCK_STATUS bluesock_write_hci(struct timeval *tv, uint16_t index, uint16_t opcode, const void *data, uint16_t size);
BLUESOCK_STATUS bluesock_write_phy(struct timeval *tv, uint16_t frequency, const void *data, uint16_t size);
BLUESOCK_STATUS bluesock_open(const char *path, uint32_t *type);
BLUESOCK_STATUS bluesock_read_hci(struct timeval *tv, uint16_t *index, uint16_t *opcode, void *data, uint16_t *size);
BLUESOCK_STATUS bluesock_read_phy(struct timeval *tv, uint16_t *frequency, void *data, uint16_t *size);
void bluesock_close(void);

#endif