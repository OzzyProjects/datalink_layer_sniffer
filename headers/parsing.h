#ifndef PARSING_H
#define PARSING_H

#define ETHERTYPE_IPV6			0x86dd
#define ETHERTYPE_IEEE_8021Q	0x8100
#define ETHERTYPE_EAPOL			0x888e
#define ETHERTYPE_IPX_NOVELL    0x8137

// IPv6 protocols numbers (most common or interesting one)

#define IPV6_TCP		0x06
#define IPV6_UDP		0x11
#define IPV6_ICMP   	0x3A

// IP protocols numbers (most common or interesting one)

#define IPV4_ICMP		0x01
#define IPV4_IGMP		0x02
#define IPV4_TCP		0x06
#define IPV4_UDP		0x11
#define IPV4_EIGRP		0x58
#define IPV4_SCTP		0x84


// HCI H4 PROTOCOL VALUES

// HCCI H4 Type
#define HCI_H4_TYPE_COMMAND	 		0x01
#define HCI_H4_TYPE_ACL_DATA	 	0x02
#define HCI_H4_TYPE_SCO_DATA	 	0x03
#define HCI_H4_TYPE_EVENT	 		0x04

// Event code
#define HCI_H4_EVENT_INQUIRY_COMPLETE						0x01
#define HCI_H4_EVENT_CONNECT_COMPLETE						0x03
#define HCI_H4_EVENT_CONNEXION_REQUEST						0x04
#define HCI_H4_EVENT_DECONNEXION_COMPLETE					0x05
#define HCI_H4_EVENT_AUTH_COMPLETE							0x06
#define HCI_H4_EVENT_REMOTE_NAME_REQUEST_COMPLETE			0x07
#define HCI_H4_EVENT_COMMAND_STATUS							0x08
#define HCI_H4_EVENT_ENCRYPTION_CHANGE						0x0f
#define HCI_H4_EVENT_READ_REMOTE_SUPPORTED_FEATURES			0x0b
#define HCI_H4_EVENT_COMMAND_COMPLETE						0x0e
#define HCI_H4_EVENT_EXTENDED_INQUIRY_RESULT				0x2f


// Linux SLL PROTOCOL VALUES

// SLL type field

#define LINUX_SLL_HOST			0x0
#define LINUX_SLL_BROADCAST		0x1
#define LINUX_SLL_MULTICAST		0x2
#define LINUX_SLL_OTHERHOST		0x3
#define LINUX_SLL_OUTGOING		0x4


// Linux IMPB over I2C VALUES

#define LINUX_IMPB_FLAGS_PROMISCUOUS_MODE_ENABLED		0x00000001
#define LINUX_IMPB_FLAGS_PROMISCUOUS_MODE_DISABLED		0x00000002
#define LINUX_IMPB_FLAGS_WENT_OFFLINE					0x00000004
#define LINUX_IMPB_FLAGS_WENT_OFFLINE_2					0x00000008
#define LINUX_IMPB_FLAGS_ATTACHED_TO_I2C_BUS			0x00000010
#define LINUX_IMPB_FLAGS_DETACHED_TO_I2C_BUS			0x00000020
#define LINUX_IMPB_FLAGS_PROMISC_BUFFER_IS_OVERFLOWED	0x00000040
#define LINUX_IMPB_FLAGS_PROMISC_BUFFER_NOTFULL			0x00000080
#define LINUX_IMPB_FLAGS_I2C_DATA_IS_OVERFLOWED			0x00000100
#define LINUX_IMPB_FLAGS_I2C_DATA_NO_LONGER_FULL		0x00000120


// UPX PROTOCOL VALUES

#define IPX_FRAME_NONE		0
#define IPX_FRAME_SNAP		1
#define IPX_FRAME_8022		2
#define IPX_FRAME_ETHERII	3
#define IPX_FRAME_8023		4
#define IPX_FRAME_TR_8022	5

// NBNS and DNS source/dest port

#define NBNS_PORT		0x0089
#define DNS_PORT 		0x0035
#define MDNS_PORT  		0x14e9


// DNS PROTOCOL VALUES
#define DNS_OPCODE_QUERRY		0x00
#define DNS_OPCODE_STATUS		0x02
#define DNS_OPCODE_NOTIFY		0x04
#define DNS_OPCODE_UPGRADE		0x05

#define DNS_RCODE_NOERROR		0x00
#define DNS_RCODE_FORMERR		0x01
#define DNS_RCODE_SERVFAIL		0x02
#define DNS_RCODE_NOTIMP		0x04
#define DNS_RCODE_REFUSED		0x05


// HOMEPLUG PROTOCOLS
#define ETHERTYPE_HOMEPLUG     			0x887b
#define ETHERTYPE_HOMEPLUG_POWERLINE    0x88e1

#define HOMEPLUG_AV_GET_DEVICE_SW_VERSION_REQ_LEN   (3 + 47)
#define HOMEPLUG_AV_GET_DEVICE_SW_VERSION_REQ_TYPE  0x00
#define HOMEPLUG_AV_GET_DEVICE_SW_VERSION_RES_TYPE  0x01

#define HOMEPLUG_AV_REQ_BRIDGE 					0x6020
#define HOMEPLUG_AV_GET_BEACON_REQ      		0x603c
#define HOMEPLUG_AV_GET_BEACON_CNF      		0x603d
#define HOMEPLUG_AV_ISP_DETECTION_REPORT_IND  	0x0066


// LLTD PROTOCOL
#define ETHERTYPE_LLDT  		0x88d9
#define ETHERTYPE_IEEE1905_1    0x893a
#define ETHERTYPE_PROFINET_DCP	0x8892


// Profinet values for service id field
#define PROFINET_DCP_SERVICE_ID_GET        0x03
#define PROFINET_DCP_SERVICE_ID_SET        0x04
#define PROFINET_DCP_SERVICE_ID_IDENTIFY   0x05
#define PROFINET_DCP_SERVICE_ID_HELLO      0x06


// Profinet values for service type field
#define PROFINET_DCP_SERVICE_TYPE_REQUEST              0x00
#define PROFINET_DCP_SERVICE_TYPE_RESPONSE_SUCCESS     0x01
#define PROFINET_DCP_SERVICE_TYPE_RESPONSE_UNSUPPORTED 0x05


// Profinet values for option field
#define PROFINET_DCP_OPTION_IP                 0x01
#define PROFINET_DCP_OPTION_DEVICE             0x02
#define PROFINET_DCP_OPTION_DHCP               0x03
#define PROFINET_DCP_OPTION_RESERVED           0x04
#define PROFINET_DCP_OPTION_CONTROL            0x05
#define PROFINET_DCP_OPTION_DEVICEINITIATIVE   0x06
#define PROFINET_DCP_OPTION_ALL				0xff


// LLTD values  for function field
#define LLTD_FUNCTION_DISCOVER 		0x00
#define LLTD_FUNCTION_HELLO 		0x01
#define LLTD_FUNCTION_QUERRY 		0x06
#define LLTD_FUNCTION_QUERRY_RESP 	0x07
#define LLTD_FUNCTION_RESET 		0x08


// LLTD values for service type field
#define LLTD_SERVICE_TYPE_DISCOVERY 		0x00
#define LLTD_SERVICE_TYPE_QUICK_DISCOVERY 	0x01
#define LLTD_SERVICE_TYPE_QOS_DIAGNOSTICS 	0X02


#define ARP_OPCODE_REQUEST 	0x01
#define ARP_OPCODE_REPLY 	0x02


#define IGMP_MESSAGE_MEMBERSHIP_QUERRY 		0x11
#define IGMPV1_MESSAGE_MEMBERSHIP_REPORT 	0x12
#define IGMPV2_MESSAGE_MEMBERSHIP_REPORT 	0X16
#define IGMPV3_MESSAGE_MEMBERSHIP_REPORT	0X22
#define IGMP_MESSAGE_LEAVE_GROUP			0X17

#define ICMPV6_TYPE_ROUTER_SOL		0x87


// OSI Layer 2 protocols

// Bluetooth protocols
void parse_hci_h4_type_field(uint8_t);
void parse_hci_h4_event_code_field(uint8_t);

void parse_sll_type_field(uint16_t);
void parse_linux_ipmb_flags_field(uint64_t);

// OSI Layer 3 protocols

void parse_homeplug_av_type_field(uint16_t);
void parse_homeplug_av_version_field(uint16_t);

void parse_arp_opcode_field(uint8_t);

void parse_lltd_function_field(uint8_t);
void parse_lltd_service_type_field(uint8_t);

void parse_profinet_dcp_service_id_field(uint8_t);
void parse_profinet_dcp_service_type_field(uint8_t);
void parse_profinet_dcp_option_field(uint8_t);

void parse_igmp_message_type_field(uint8_t);

void parse_icmp_type_field(uint8_t);

// OSI Layer 7 protocols

void parse_dns_opcode_field(uint8_t);
void parse_dns_rcode_field(uint8_t);

#endif

