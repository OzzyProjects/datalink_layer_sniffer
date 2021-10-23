/* 
Header of new bluetooth sniffer engine 
Now, it is based  and implemented to work with HCI as main prottocol but it will be able to 
manage OBEX, L2CAP and ATT Encapsulations.
*/

/* Header of new bluetooth sniffer engine */

#ifndef BLUESOCK_H
#define BLUESOCK_H

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdint.h>
#include <string.h>
#include <sys/time.h>


#define BLUESOCK_EXIT_SUCCESS			0
#define BLUESOCK_EXIT_FAILURE			-1


#define BLUESOCK_LIST_ERRORS_LENGTH		6
#define BLUESOCKK_ERROR_LENGTH			64
#define BLUESOCK_ID_LENGTH 				8


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


// Messages value errors

#define BLUESOCK_STATUS_EXIT_SUCCUES 			0
#define BLUESOCK_STATUS_ERROR_INVALID_FD		-1
#define BLUESOCK_STATUS_ERROR_IO_FILE 			-2
#define BLUESOCK_STATUS_ERROR_SOCKET 			-3
#define BLUESOCK_STATUS_ERROR_ACCESS_DENIED 	-4
#define BLUESOCK_STATUS_ERROR_INVALID_PARAM 	-5
#define BLUESOCK_STATUS_ERROR_FATAL_ERROR	 	-6
	

/*********************************************** STRUCTURES /***********************************************/


typedef struct bluesock_hdr{

	uint8_t		id[BLUESOCK_ID_LENGTH];
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


typedef struct hcidump_data {
	
	uint16_t index;
	int sock_
	fd;

} __attribute__((packed)) hcidump_data;


#define HCIDUMP_DATA_SIZE (sizeof(struct hcidump_data));

/*********************************************** CALLBACK FUNCTIONS /***********************************************/

static void callback_error(int, char*);
static void stack_internal_callback(int, uint32_t, void*);
static void device_callback(int, uint32_t, void *);

/**************************************************Usefull fontions **************************************************/

static uint32_t get_flags_from_opcode(uint16_t opcode);
static uint16_t get_opcode_from_flags(uint8_t, uint32_t);

/************************************************** HCI SOCKETS PART  **************************************************/

static int bluesock_device_info(int, uint16_t, uint8_t*, uint8_t*, bdaddr_t*, char*);
static void bluesock_device_list(int, int, char*);
static int bluesock_create(const char*, uint32_t);
static int bluesock_open_hci_dev(uint16_t, char*);
static int open_stack_internal(void);

static int bluesock_read_phy(struct timeval*, uint16_t* void*, uint16_t*);

static int hcidump_tracing(void);

static void bluesock_free_data(void *);
void bluesock_close(void);


#endif
