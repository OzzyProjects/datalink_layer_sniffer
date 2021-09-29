#ifndef PARSING_H
#define PARSING_H

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

void parse_igmp_message_type_field(uint8_t);

#endif