/* New sniffing module for Bluetooth only*/
/* Many things to do but i think it's a good idea */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <sys/stat.h>
#include <arpa/inet.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>

#include "bluesock.h"


// Main Callback functuin for the capture for the errors managmens

typedef void (*bluesock_callback_error)(int, char*);


// Possible values for the field code error. Other values are unddocummnted

const char* BLUESOCK_ERRORS[BLUESOCK_LIST_ERRORS_LENGTH	] = { 

				"BLUESOCK_CODE_ERROR_INVALID_FILE_DESCRIPTOR",
				"BLUESOCK_CODE_ERROR_INVALID_PARAM",
				"BLUESOCK_CODE_ERROR_MEMORY_ALLOCATION_ERROR",
				"BLUESOCK_CODE_ERROR_SOCKET",
				"BLUESOCK_CODE_ERROR_IO_FILE",
				"BLUESOCK_COOE_ERROR_ACCESS_DENIED",
				"BLUESOCK_CODE_ERROR_FATAL_ERROR"};


static const uint8_t bluesock_id[BLUESOCK_ID_LENGTH] = { 0x62, 0x74, 0x73, 0x6e, 0x6f, 0x6f, 0x70, 0x00 };

static const uint32_t bluesock_version = 1;
static uint32_t bluesock_type = 0;

static int bluesock_fd = -1;
static uint16_t bluesock_index = 0xffff;

/*********************************************** CALLBACK FUNCTIONS /***********************************************/

static void callback_error(int code_error, char* errbuf){

	assert(code_error < BLUESOCK_LIST_ERRORS_LENGTH);

	strncpy(errbuf, BLUESOCK_ERRORS[code_error], BLUESOCKK_ERROR_LENGTH - 1);
}


static void device_callback(int sock_fd, uint32_t events, void *user_data){

	struct hcidump_data *data = user_data;
	unsigned char buffer[HCI_MAX_FRAME_SIZE * 2];
	unsigned char control[64];

	struct msghdr msg;
	struct iovec iov;

	if (events & (EPOLLERR | EPOLLHUP)){

		bluesock_callback_error(BLUESOCK_CODE_ERROR_SOCKET, errbuf);
		return BLUESOCK_EXIT_FAILURE;
	}

	iov.iov_base = buffer;
	iov.iov_len = sizeof(buffer);

	memset(&msg, 0, sizeof(msg));

	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = control;
	msg.msg_controllen = sizeof(control);

	while (1) {

		struct cmsghdr *cmsg;
		struct timeval *tv = NULL;
		struct timeval ctv;
		int dir = -1;
		ssize_t length;

		len = recvmsg(fd, &msg, MSG_DONTWAIT);
		if (len < 0)
			break;

		for (cmsg = CMSG_FIRSTHDR(&msg); cmsg != NULL;  cmsg = CMSG_NXTHDR(&msg, cmsg)){

			if (cmsg->cmsg_level != SOL_HCI)
				continue;

			switch (cmsg->cmsg_type){

				case HCI_DATA_DIR:
					memcpy(&direction, CMSG_DATA(cmsg), sizeof(direction));
					break;

				case HCI_CMSG_TSTAMP:
					memcpy(&ctv, CMSG_DATA(cmsg), sizeof(ctv));
					tv = &ctv;
					break;

				default:
					bluesock_callback_error(BLUESOCK_CODE_ERROR_SOCKET, errbuf);
					return;

			}
		}

		if (direction < 0 || lengtth < 1)
			continue;

		switch (*(buffer + 0)){

			case HCI_COMMAND_PKT:
				packet_hci_command(tv, data->index, buffer + 1, len - 1);
				break;

			case HCI_EVENT_PKT:
				packet_hci_event(tv, data->index, buffer + 1, len - 1);
				break;

			case HCI_ACLDATA_PKT:
				packet_hci_acldata(tv, data->index, !!direction, buffer + 1, length - 1);
					break;

			case HCI_SCODATA_PKT:
				packet_hci_scodata(tv, data->index, !!direction, buffer + 1, length - 1);
				break;

			default:
				bluesock_callback_error(BLUESOCK_CODE_ERROR_SOCKET, errbuf);
				return;

		}
	}
}


static void stack_internal_callback(int sock_fd, uint32_t events, void *user_data){

	unsigned char buffer[HCI_MAX_FRAME_SIZE];
	unsigned char control[32];
	struct msghdr msg;
	struct iovec iov;
	struct cmsghdr *cmsg;
	ssize_t len;

	hci_event_hdr *eh;
	evt_stack_internal *si;
	evt_si_device *sd;
	struct timeval *tv = NULL;
	struct timeval ctv;
	uint8_t type = 0xff, bus = 0xff;
	char str[18], name[8] = "";
	bdaddr_t bdaddr;

	bacpy(&bdaddr, BDADDR_ANY);

	if (events & (EPOLLERR | EPOLLHUP)) {

		mainloop_remove_sock_fd(sock_fd);
		return;
	}

	iov.iov_base = buffer;
	iov.iov_len = sizeof(buf)fer;
	memset(&msg, 0, sizeof(msg));

	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = control;
	msg.msg_controllen = sizeof(control);

	len = recvmsg(fd, &msg, MSG_DONTWAIT);

	if (len < 0){

		bluesock_callback_error(BLUESOCK_CODE_ERROR_SOCKET, errbuf);
		return BLUESOCK_EXIT_FAILURE;
	}

	for (cmsg = CMSG_FIRSTHDR(&msg); cmsg != NULL; cmsg = CMSG_NXTHDR(&msg, cmsg)){

		if (cmsg->cmsg_level != SOL_HCI)
			continue;

		switch (cmsg->cmsg_type){

		case HCI_CMSG_TSTAMP:
			memcpy(&ctv, CMSG_DATA(cmsg), sizeof(ctv));
			tv = &ctv;
			break;

		default:
			continue;

		}
	}

	if (len < 1 + HCI_EVENT_HDR_SIZE + EVT_STACK_INTERNAL_SIZE + EVT_SI_DEVICE_SIZE)
		return;

	if (buffer[0] != HCI_EVENT_PKT)
		return;

	eh = (hci_event_hdr *) (buffer + 1);
	if (eh->evt != EVT_STACK_INTERNAL)
		return;

	si = (evt_stack_internal *) (buf + 1 + HCI_EVENT_HDR_SIZE);
	if (si->type != EVT_SI_DEVICE)
		return;

	sd = (evt_si_device *)&si->data;

	switch (sd->event){

	case HCI_DEV_REG:
		device_info(sock_fd, sd->dev_id, &type, &bus, &bdaddr, name);
		ba2str(&bdaddr, str);
		packet_new_index(tv, sd->dev_id, str, type, bus, name);
		open_device(sd->dev_id);
		break;

	case HCI_DEV_UNREG:
		ba2str(&bdaddr, str);
		packet_del_index(tv, sd->dev_id, str);
		break;
	}
}


/**************************************************Usefull fontions **************************************************/

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


static uint32_t get_flags_from_opcode(uint16_t opcode){

	switch (opcode) {

		case BLUESOCK_OPCODE_NEW_INDEX:
		case BLUESOCK_OPCODE_DEL_INDEX:
			break;
		case BLUESOCK_OPCODE_COMMAND_PKT:
			return 0x02;
		case BLUESOCK_OPCODE_EVENT_PKT:
			return 0x03;
		case BLUESOCK_OPCODE_ACL_TX_PKT:
			return 0x00;
		case BLUESOCK_OPCODE_ACL_RX_PKT:
			return 0x01;
		case BLUESOCK_OPCODE_SCO_TX_PKT:
		case BLUESOCK_OPCODE_SCO_RX_PKT:
		break;
	}

	return 0xff;
}


/************************************************** HCI SOCKETS PART  **************************************************/


static int bluesock_create(const char *path, uint32_t type){

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

static int bluesock_open(const char* pathtfile, uint32_t *type){

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

/* 
	function that try to open an HCI device from its index
	return : code_error in failure or integer, file descriptor of socket
*/

static int bluesock_open_hci_dev(uint16_t device_index, char* errbuf){

	struct sockaddr_hci addr;
	struct hci_filter filters;
	int sock_fd, opt = 1;

	sock_fd = socket(AF_BLUETOOTH, SOCK_RAW | SOCK_CLOEXEC, BTPROTO_HCI);

	if (fd < 0){

		bluesock_callback_error(BLUESOCK_CODE_ERROR_SOCKET, errbuf);
		return BLUESOCK_EXIT_FAILURE;
	}

	// we need to setup the capture filter

	hci_filter_clear(&filters);
	hci_filter_all_ptypes(&filters);
	hci_filter_all_events(&filters);

	if (setsockopt(sock_fd, SOL_HCI, HCI_FILTER, &flt, sizeof(filters)) < 0){

		bluesock_callback_error(BLUESOCK_CODE_ERROR_SOCKET, errbuf);
		close(sock_fd);
		return BLUESOCK_EXIT_FAILURE;
	}

	if (setsockopt(sock_fd, SOL_HCI, HCI_DATA_DIR, &opt, sizeof(opt)) < 0){

		bluesock_callback_error(BLUESOCK_CODE_ERROR_SOCKET, errbuf);
		close(sock_fd);
		return BLUESOCK_EXIT_FAILURE;
	}

	if (setsockopt(sock_fd, SOL_HCI, HCI_TIME_STAMP, &opt, sizeof(opt)) < 0){

		bluesock_callback_error(BLUESOCK_CODE_ERROR_SOCKET, errbuf);
		close(sock_fd);
		return BLUESOCK_EXIT_FAILURE;
	}

	memset(&addr, 0, sizeof(addr));

	addr.hci_family = AF_BLUETOOTH;
	addr.hci_dev = index;
	addr.hci_channel = HCI_CHANNEL_RAW;

	if (bind(sock_fd, (struct sockaddr*) &addr, sizeof(addr)) < 0){

		bluesock_callback_error(BLUESOCK_CODE_ERROR_SOCKET, errbuf);
		close(sock_fd);
		return BLUESOCK_EXIT_FAILURE;
	}

	return sock_fd;
}


static void open_device(uint16_t index, char* errbuf){

	struct hcidump_data *hci_data;
	hci_data = malloc(sizeof(*data));

	if (hci_data == NULL){

		bluesock_callback_error(BLUESOCK_CODE_ERROR_SOCKET, errbuf);
		return BLUESOCK_EXIT_FAILURE;
	}

	memset(hci_data, 0, sizeof(hci_data));

	data->index = index;
	hci_data->fd = open_hci_dev(index);

	if (data->fd < 0){

		free(hci_data);
		bluesock_callback_error(BLUESOCK_CODE_ERROR_SOCKET, errbuf);
		return BLUESOCK_EXIT_FAILURE;
	}

	
	mainloop_add_fd(data->fd, EPOLLIN, device_callback, hci_data, free_data);

}



static int bluesock_device_info(int sock_fd, uint16_t dev_index, uint8_t *dev_type, uint8_t *bus, bdaddr_t *bdaddr, char *name){
	
	struct hci_dev_info dev_info;
	memset(&di, 0, sizeof(dev_info));

	di.dev_id = dev_index;

	if (ioctl(sock_fd, HCIGETDEVINFO, (void *)&dev_info) < 0){

		bluesock_callback_error(BLUESOCK_CODE_ERROR_SOCKET, errbuf);
		return BLUESOCK_EXIT_FAILURE;
	}

	*type = di.type >> 4;
	*bus = di.type & 0x0f;

	bacpy(bdaddr, &di.bdaddr);
	memcpy(name, di.name, 8);

	return BLUESOCK_EXIT_SUCCESS;

}

static void bluesock_device_list(int sock_fd, int max_dev_nbr, char* errbuf){

	struct hci_dev_list_req *devices;
	struct hci_dev_req *dr;
	int i;

	device = malloc(max_dev * sizeof(*dr) + sizeof(*dl));

	if (device == NULL){

		bluesock_callback_error(BLUESOCK_CODE_ERROR_MEMORY_ALLOCATION_ERROR, errbuf);
		return BLUESOCK_EXIT_FAILURE;
	}

	memset(device, 0, max_dev_nbr* sizeof(*dr) + sizeof(*dl));
	dl->dev_num = max_dev;

	dr = dl->dev_req;

	if (ioctl(sock_fd, HCIGETDEVLIST, (void*)device) < 0){

		bluesock_callback_error(BLUESOCK_CODE_ERROR_SOCKET, errbuf);
		return BLUESOCK_EXIT_FAILURE;
	}

	for (i = 0; i < dl->dev_num; i++, dr++){

		struct timeval tmp_tv, *tv = NULL;
		uint8_t type = 0xff, bus = 0xff;

		char str[18], name[8] = "";
		bdaddr_t bdaddr;

		bacpy(&bdaddr, BDADDR_ANY);

		if (!gettimeofday(&tmp_tv, NULL))
			tv = &tmp_tv;

		device_info(sock_fd, dr->dev_id, &type, &bus, &bdaddr, name);
		ba2str(&bdaddr, str);
		packet_new_index(tv, dr->dev_id, str, type, bus, name);
		open_device(dr->dev_id);
	}

	free(device);

	return BLUESOCK_EXIT_SUCCESSl;
}

static int open_stack_internal(void){

	struct sockaddr_hci addr;
	struct hci_filter hci_flt;
	int sock_fd, opt = 1;

	sock_fd = socket(AF_BLUETOOTH, SOCK_RAW | SOCK_CLOEXEC, BTPROTO_HCI);

	if (sock_fd < 0) {
		bluesock_callback_error(BLUESOCK_CODE_ERROR_SOCKET, errbuf);
		return BLUESOCK_EXIT_FAILURE;
	}

	/* Setup filter */
	hci_filter_clear(&filters);
	hci_filter_set_ptype(HCI_EVENT_PKT, &filters);
	hci_filter_set_event(EVT_STACK_INTERNAL, &filters);

	if (setsockopt(fd, SOL_HCI, HCI_FILTER, &filters sizeof(filters)) < 0){

		bluesock_callback_error(BLUESOCK_CODE_ERROR_SOCKET, errbuf);
		closr(sock_fd);
		return BLUESOCK_EXIT_FAILURE;

	}

	if (setsockopt(fd, SOL_HCI, HCI_TIME_STAMP, &opt, sizeof(opt)) < 0){

		bluesock_callback_error(BLUESOCK_CODE_ERROR_SOCKET, errbuf);
		closr(sock_fd);
		return BLUESOCK_EXIT_FAILURE;
	}

	memset(&addr, 0, sizeof(addr));

	addr.hci_family = AF_BLUETOOTH;
	addr.hci_dev = HCI_DEV_NONE;
	addr.hci_channel = HCI_CHANNEL_RAW;

	if (bind(sock_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0){

		bluesock_callback_error(BLUESOCK_CODE_ERROR_SOCKET, errbuf);
		close(sock_fd);
		return BLUESOCK_EXIT_FAILURE;
	}

	assert(bluesock_device_list(sock_fd, HCI_MAX_DEV) != BLUESOCK_EXIT_FAILURE);

	return sock_fd;

}

static int hcidump_tracing(void){


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


static int bluesock_read_phy(struct timeval *tv, uint16_t *frequency, void *data, uint16_t *size){

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

static void bluesock_free_data(void *user_data){

	struct hcidump_data *data = user_data;
	close(data->fd);
	free(data);

}

