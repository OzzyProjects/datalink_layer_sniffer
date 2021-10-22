/* New sniffing module for Bluetooth only*/
/* Many things to do but i think it's a good idea */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#define BLUESOCK  0x77

#include <sys/stat.h>
#include <arpa/inet.h>

#undef BLUESOCK

#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>

#include "bluesock.h"

#ifndef BLUESOCK

#define BLUESOCK_ID_LENGTH  0x8

#endif


static const uint8_t bluesock_id[BLUESOCK_ID_LENGTH] = { 0x62, 0x74, 0x73, 0x6e, 0x6f, 0x6f, 0x70, 0x00 };

static const uint32_t bluesock_version = 1;
static uint32_t bluesock_type = 0;

static int bluesock_fd = -1;
static uint16_t bluesock_index = 0xffff;


BLUESOCK_STATUS bluesock_create(const char *path, uint32_t type){

	bluesock_hdr sock_hdr;
	ssize_t bytes_written;

	if (bluesock_fd >= 0)
		return BLUESOCK_ERROR_INVALID_FD;

	bluesock_fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
	if (bluesock_fd < 0)
		return BLUESOCK_ERROR_ACCESS_FILE;

	bluesock_type = type;

	memcpy(sock_hdr.id, bluesock_id, sizeof(bluesock_id));

	sock_hdr.version = htonl(bluesock_version);
	sock_hdr.type = htonl(bluesock_type);

	bytes_written = write(bluesock_fd, &sock_hdr, BLUESOCK_HDR_SIZE);

	if (written < 0){

		close(bluesock_fd);
		bluesock_fd = -1;
		return BLUESOCK_ERROR_ACCESS_FILE;
	}

	return BLUESOCK_STATUS_EXIT_SUCCES;
}


BLUESOCK_STATUS bluesock_write(struct timeval *tv, uint32_t flags, const void *data, uint16_t size){

	struct bluesock_pkt pkt;
	uint64_t ts;
	ssize_t bytes_written;

	ts = (tv->tv_sec - 946684800ll) * 1000000ll + tv->tv_usec;

	pkt.size  = htonl(size);
	pkt.len   = htonl(size);
	pkt.flags = htonl(flags);
	pkt.drops = htonl(0);
	pkt.ts    = hton64(ts + 0x00E03AB44A676000ll);

	bytes_written = write(bluesock_fd, &pkt, BLUESOCK_PKT_SIZE);

	if (written < 0)
		return BLUESOCK_ERROR_ACCESS_FILE;

	if (data && size > 0){

		bytes_written = write(bluesock_fd, data, size);

		if (bytes_written < 0)
			return BLUESOCK_ERROR_ACCESS_FILE;
	}

	return BLUESOCK_STATUS_EXIT_SUCCES;
}


static uint32_t get_flags_from_opcode(uint16_t opcode){

	switch (opcode) {

		case bluesock_OPCODE_NEW_INDEX:
		case bluesock_OPCODE_DEL_INDEX:
			break;
		case bluesock_OPCODE_COMMAND_PKT:
			return 0x02;
		case bluesock_OPCODE_EVENT_PKT:
			return 0x03;
		case bluesock_OPCODE_ACL_TX_PKT:
			return 0x00;
		case bluesock_OPCODE_ACL_RX_PKT:
			return 0x01;
		case bluesock_OPCODE_SCO_TX_PKT:
		case bluesock_OPCODE_SCO_RX_PKT:
		break;
	}

	return 0xff;
}


BLUESOCK_STATUS bluesock_write_phy(struct timeval *tv, uint16_t frequency, const void *data, uint16_t size){

	uint32_t flags;

	if (!tv || bluesock_fd < 0){
		return BLUESOCK_ERROR_INVALID_PARAM
	}

	switch (bluesock_type){

		case BLUESOCK_TYPE_EXTENDED_PHY:
			flags = (1 << 16) | frequency;
			break;

		default:
			return BLUESOCK_ERROR_INVALID_PARAM;
	}

	bluesock_write(tv, flags, data, size);

	return BLUESOCK_STATUS_EXIT_SUCCES;
}

BLUESOCK_STATUS bluesock_open(const char* pathtfile, uint32_t *type){

	bluesock_hdr blue_hdr;
	ssize_t len;

	if (bluesock_fd >= 0) {
		fprintf(stderr, "Too many open files\n");
		return BLUESOCK_ERROR_ACCESS_FILE;
	}

	bluesock_fd = open(pathtfile, O_RDONLY | O_CLOEXEC);

	if (bluesock_fd < 0){
		perror("ERROR : Failed to open file\n");
		return BLUESOCK_ERROR_ACCESS_FILE;
	}

	len = read(bluesock_fd, &hdr, BLUESOCK_HDR_SIZE);

	if (len < 0 || len != bluesock_HDR_SIZE){

		fprintf(stderr, " ERROR : Failed to read header");
		close(bluesock_fd);
		bluesock_fd = -1;
		return BLUESOCK_ERROR_ACCESS_FILE;
	}

	if (memcmp(blue_hdr.id, bluesock_id, sizeof(bluesock_id))){

		fprintf(stderr, "Invalid btsnoop header\n");
		close(bluesock_fd);
		bluesock_fd = -1;
		return BLUESOCK_ERROR_ACCESS_FILE;
	}

	if (ntohl(blue_hdr.version) != bluesock_version){

		fprintf(stderr, "ERROR : Corrupted bluesock version running\n");
		close(bluesock_fd);
		bluesock_fd = -1;
		return BLUESOCK_ERROR_FATAL_ERROR;
	}

	bluesock_type = ntohl(blue_hdr.type);

	if (type)
		*type = bluesock_type;

	return BLUESOCK_STATUS_EXIT_SUCCES;
}

static uint16_t get_opcode_from_flags(uint8_t type, uint32_t flags){

	switch (type){

	case HCI_COMMAND_PKT:
		return BLUE_OPCODE_COMMAND_PKT;

	case HCI_ACLDATA_PKT:
		if (flags & 0x01)
			return BLUESOCK_OPCODE_ACL_RX_PKT;
		else
			return BLUESOCK_OPCODE_ACL_TX_PKT;

	case HCI_SCODATA_PKT:
		if (flags & 0x01)
			return BLUESOCK_OPCODE_SCO_RX_PKT;
		else
			return BLUESOCK_OPCODE_SCO_TX_PKT;

	case HCI_EVENT_PKT:
		return BLUESOCK_OPCODE_EVENT_PKT;

	case 0xff:
		if (flags & 0x02) {
			if (flags & 0x01)
				return BLUESOCK_OPCODE_EVENT_PKT;
			else
				return BLUESOCK_OPCODE_COMMAND_PKT;
		} 
		else {
			if (flags & 0x01)
				return BLUESOCK_OPCODE_ACL_RX_PKT;
			else
				return BLUESOCK_OPCODE_ACL_TX_PKT;
		}

		break;

	default:
		return BLUESOCK_ERROR_INVALID_PARAM;
	}

	return 0xff;
}

BLUESOCK_STATUS bluesock_read_hci(struct timeval *tv, uint16_t *index, uint16_t *opcode, void *data, uint16_t *size){

	struct bluesock_pkt pkt;
	uint32_t to_read, flags;
	uint64_t ts;
	uint8_t pkt_type;
	ssize_t len;

	if (bluesock_fd < 0)
		return BLUESOCK_ERROR_INVALID_PARAM;

	len = read(bluesock_fd, &pkt, BLUESOCK_PKT_SIZE);

	if (len == 0)
		return BLUESOCK_ERROR_INVALID_PARAM;

	if (len < 0 || len != BLUESOCK_PKT_SIZE){

		fprintf("ERROR : Failed to read packet\n");
		close(bluesock_fd);
		bluesock_fd = -1;
		return  BLUESOCK_STATUS_ERROR_IO_ERROR;
	}

	to_read = ntohl(pkt.size);
	flags = ntohl(pkt.flags);

	ts = ntoh64(pkt.ts) - 0x00E03AB44A676000ll;
	tv->tv_sec = (ts / 1000000ll) + 946684800ll;
	tv->tv_usec = ts % 1000000ll;

	switch (bluesock_type){

		case BLUESOCK_TYPE_HCI:
			*index = 0;
			*opcode = get_opcode_from_flags(0xff, flags);
			break;

	case BLUESOCK_TYPE_UART:
		len = read(bluesock_fd, &pkt_type, 1);

		if (len < 0){

			fprintf("ERROR : Failed to read packet\n");
			close(bluesock_fd);
			bluesock_fd = -1;
			return BLUESOCK_STATUS_ERROR_IO_ERROR;
		}

		toread--;
		*index = 0;
		*opcode = get_opcode_from_flags(pkt_type, flags);
		break;

	case BLUESOCK_TYPE_EXTENDED_HCI:
		*index = flags >> 16;
		*opcode = flags & 0xffff;
		break;

	default:
		fprintf(stderr, "ERROR : Unknown packet type\n");
		close(bluesock_fd);
		bluesock_fd = -1;
		return BLUESOCK_ERROR_INVALID_PARAM;
	}

	len = read(bluesock_fd, data, toread);

	if (len < 0){
		fprintf("ERROR : Failed to read data\n");
		close(bluesock_fd);
		bluesock_fd = -1;
		return BLUESOCK_STATUS_ERROR_IO_ERROR;
	}

	*size = toread;

	return BLUESOCK_STATUS_EXIT_SUCCES;
}

BLUESOCK_STATUS bluesock_read_phy(struct timeval *tv, uint16_t *frequency, void *data, uint16_t *size){

	struct bluesock_pkt pkt;
	uint32_t toread, flags;
	uint64_t ts;
	ssize_t len;

	if (bluesock_fd < 0)
		return BLUESOCK_ERROR_INVALID_PARAM;

	len = read(bluesock_fd, &pkt, BLUESOCK_PKT_SIZE);

	if (len == 0)
		return BLUESOCK_ERROR_ACCESS_FILE;

	if (len < 0 || len != BLUESOCK_PKT_SIZE){

		fprintf(stderr, "Failed to read packet\n");
		close(bluesock_fd);
		bluesock_fd = -1;
		return BLUESOCK_ERROR_ACCESS_FILE;
	}

	toread = ntohl(pkt.size);
	flags = ntohl(pkt.flags);

	ts = ntoh64(pkt.ts) - 0x00E03AB44A676000ll;
	tv->tv_sec = (ts / 1000000ll) + 946684800ll;
	tv->tv_usec = ts % 1000000ll;

	switch (bluesock_type){

		case bluesock_TYPE_EXTENDED_PHY:
			if ((flags >> 16) != 1)
				break;
			*frequency = flags & 0xffff;

		break;

		default:
			fprintf(stderr, "ERROR : Unknown packet type\n");
			close(bluesock_fd);
			bluesock_fd = -1;
			return BLUESOCK_ERROR_INVALID_PARAM;
	}

	len = read(bluesock_fd, data, toread);

	if (len < 0){

		fprintf(stderr, "ERROR : Unknown packet type\n");
		close(bluesock_fd);
		bluesock_fd = -1;
		return BLUESOCK_ERROR_INVALID_PARAM;
	}

	*size = toread;

	return BLUESOCK_STATUS_EXIT_SUCCES;
}

void bluesock_close(void){

	if (bluesock_fd < 0)
		return;

	close(bluesock_fd);
	bluesock_fd = -1;

	bluesock_index = 0xffff;
}
