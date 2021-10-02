#ifndef PARSING_H
#define PARSING_H

// HOMEPLUG PROTOCOLS
#define ETHERTYPE_HOMEPLUG     0x887b
#define ETHERTYPE_HOMEPLUG_POWERLINE    0x88e1
#define HOMEPLUG_AV_REQ_BRIDGE 0x6020

// LLTD PROTOCOL
#define ETHERTYPE_LLDT  0x88d9

#define ETHERTYPE_IEEE1905_1    0x893a

#define IPV6_ICMP   0x003A


// PN-DCP values for service id field
#define PNDCP_SERVICE_ID_GET        0x03
#define PNDCP_SERVICE_ID_SET        0x04
#define PNDCP_SERVICE_ID_IDENTIFY   0x05
#define PNDCP_SERVICE_ID_HELLO      0x06

#define PNDCP_SERVICE_TYPE_REQUEST              0x00
#define PNDCP_SERVICE_TYPE_RESPONSE_SUCCESS     0x01
#define PNDCP_SERVICE_TYPE_RESPONSE_UNSUPPORTED 0x05

#define PNDCP_OPTION_IP                 0x01
#define PNDCP_OPTION_DEVICE             0x02
#define PNDCP_OPTION_DHCP               0x03
#define PNDCP_OPTION_RESERVED           0x04
#define PNDCP_OPTION_CONTROL            0x05
#define PNDCP_OPTION_DEVICEINITIATIVE   0x06
#define PNDCP_OPTION_ALL				0xff

// LLTD values  for function field
#define LLTD_FUNCTION_DISCOVER 		0x0
#define LLTD_FUNCTION_HELLO 		0x1
#define LLTD_FUNCTION_QUERRY 		0x6
#define LLTD_FUNCTION_QUERRY_RESP 	0x7
#define LLTD_FUNCTION_RESET 		0x8

// LLTD values for service type field
#define LLTD_SERVICE_TYPE_DISCOVERY 		0x0
#define LLTD_SERVICE_TYPE_QUICK_DISCOVERY 	0x1
#define LLTD_SERVICE_TYPE_QOS_DIAGNOSTICS 	0X2

#define ARP_OPCODE_REQUEST 	0x1
#define ARP_OPCODE_REPLY 	0x2

#define IGMP_MESSAGE_MEMBERSHIP_QUERRY 		0x11
#define IGMPV1_MESSAGE_MEMBERSHIP_REPORT 	0x12
#define IGMPV2_MESSAGE_MEMBERSHIP_REPORT 	0X16
#define IGMPV3_MESSAGE_MEMBERSHIP_REPORT	0X22
#define IGMP_MESSAGE_LEAVE_GROUP			0X17

void parse_arp_opcode_field(uint8_t);

void parse_lltd_function_field(uint8_t);
void parse_lltd_service_type_field(uint8_t);

void parse_pndcp_service_id_field(uint8_t);
void parse_pndcp_service_type_field(uint8_t);
void parse_pndcp_option_field(uint8_t);

void parse_igmp_message_type_field(uint8_t);

#endif
