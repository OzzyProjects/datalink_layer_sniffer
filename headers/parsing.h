/* Header file */

#ifndef PARSING_H
#define PARSING_H


#define LLC_CONTROL_FIELD_FORMAT_XID		0xaf

// ETHERTYPE VALUES

#define ETHERTYPE_IPV6					0x86dd
#define ETHERTYPE_IEEE_8021Q			0x8100
#define ETHERTYPE_EAPOL					0x888e
#define ETHERTYPE_IPX_NOVELL    		0x8137

#define ETHERTYPE_HOMEPLUG     			0x887b
#define ETHERTYPE_HOMEPLUG_POWERLINE    0x88e1

#define ETHERTYPE_LLDT  				0x88d9
#define ETHERTYPE_IEEE1905_1    		0x893a
#define ETHERTYPE_PROFINET_DCP			0x8892


// ------------------------------------- IPV4 PROTOCOL NUMBER VALUES

#define IPV4_ICMP		0x01
#define IPV4_IGMP		0x02
#define IPV4_TCP		0x06
#define IPV4_UDP		0x11
#define IPV4_EIGRP		0x58
#define IPV4_SCTP		0x84


// ------------------------------------- IPV6 PROTOCOL NUMBER VALUES

#define IPV6_TCP		0x06
#define IPV6_UDP		0x11
#define IPV6_ICMP   	0x3A


// ------------------------------------- UDP PROTOCOL NUMBER VALUES

#define UDP_PORT_DEST_DNS					0x0035
#define UDP_PORT_DEST_NTP					0x007b
#define UDP_PORT_DEST_SNMP				 	0x00a1
#define UDP_PORT_DEST_NBNS				 	0x0089
#define UDP_PORT_DEST_NETBIOS				0x008a
#define UDP_PORT_DEST_MDNS				 	0x14e9
#define UDP_PORT_DEST_LLMNR				 	0x14eb
#define UDP_PORT_DEST_CANON_BJNP 			0x21a4
#define UDP_ETHERCAT_OVER_UDP_SOURCE_PORT  	0x88a4


/*********************************************** OSI LAYER 2 PROTOCOLS ***********************************************/

// ------------------------------------- IEEE 802.3 LLC PROTOCOL

// IEEE 802.3 LLC Control Filed

#define LLC_CONTROL_FIELD_FORMAT_UI 			0x03
#define LLC_CONTROL_FIELD_FORMAT_DISC			0x43
#define LLC_CONTROL_FIELD_FORMAT_UA				0x63
#define LLC_CONTROL_FIELD_FORMAT_DM				0x0f
#define LLC_CONTROL_FIELD_FORMAT_XID_SABME		0x6f	
#define LLC_CONTROL_FIELD_FORMAT_XID			0xaf


// ------------------------------------- HCI H4 PROTOCOL VALUES (BLUETOOTH)

#define HCI_H4_MAX_KEY_LENGTH		64
#define HCI_H4_MAX_DEVICE_LENGTH	64

// HCCI H4 Type Field

#define HCI_H4_TYPE_COMMAND	 		0x01
#define HCI_H4_TYPE_ACL_DATA	 	0x02
#define HCI_H4_TYPE_SCO_DATA	 	0x03
#define HCI_H4_TYPE_EVENT	 		0x04

// HCI H4 Event Field

#define HCI_H4_EVENT_INQUIRY_COMPLETE						0x01
#define HCI_H4_EVENT_CONNECT_COMPLETE						0x03
#define HCI_H4_EVENT_CONNEXION_REQUEST						0x04
#define HCI_H4_EVENT_DECONNEXION_COMPLETE					0x05
#define HCI_H4_EVENT_AUTH_COMPLETE							0x06
#define HCI_H4_EVENT_REMOTE_NAME_REQUEST_COMPLETE			0x07
#define HCI_H4_EVENT_ENCRYPTION_CHANGE						0x08
#define HCI_H4_EVENT_NUMBER_COMPLETE_PACKAGES				0x13
#define HCI_H4_EVENT_MODE_CHANGE							0x14
#define HCI_H4_EVENT_LINK_KEY_NOTIFICATION					0x18
#define HCI_H4_EVENT_READ_REMOTE_SUPPORTED_FEATURES			0x0b
#define HCI_H4_EVENT_COMMAND_COMPLETE						0x0e
#define HCI_H4_EVENT_COMMAND_STATUS							0x0f
#define HCI_H4_EVENT_EXTENDED_INQUIRY_RESULT				0x2f
#define HCI_H4_EVENT_LE_META								0x3e
#define HCI_H4_EVENT_INTEL_VENDOR_SPECIFIC					0xff

// HCI H4 Command Field

#define HCI_H4_COMMAND_LE_SET_SCAN_ENABLED					0x2042
#define HCI_H4_COMMAND_SENT_INQUIRY							0x0401
#define HCI_H4_COMMAND_READ_REMOTE_EXTENDED_FEATURES		0x041c
#define HCI_H4_COMMAND_CREATE_CONNEXION						0x0405
#define HCI_H4_COMMAND_LINK_KEY_REQUUEST_REPLY				0x040b
#define HCI_H4_COMMAND_READ_CURRENT_IAP_SETTINGS			0x0c39
#define HCI_H4_COMMAND_READ_VOICE_SETTINGS					0x0c45

// L2CAP Cid Command Field

#define L2CAP_CID_ATTRIBUTE_PROTOCOL 						0x0004
#define L2CAP_CID_SECURITY_MANAGER_PROTOCOL 				0x0006
#define L2CAP_CID_RESERVED 									0x0007
#define L2CAP_CID_SIGNALING_CHANNEL 						0x004d

// SMP Opcode Field

#define SMP_OPCODE_PAIRING_REQUEST							0x01
#define SMP_OPCODE_PAIRING_RESPONSE							0x02
#define SMP_OPCODE_PAIRING_CONFIRM							0x03
#define SMP_OPCODE_PAIRING_RANDOM							0x04
#define SMP_OPCODE_PAIRING_PUBLIC_KEY						0x0c


// ------------------------------------- Linux SLL PROTOCOL VALUES

// Linux SLL Type Field

#define LINUX_SLL_HOST			0x0
#define LINUX_SLL_BROADCAST		0x1
#define LINUX_SLL_MULTICAST		0x2
#define LINUX_SLL_OTHERHOST		0x3
#define LINUX_SLL_OUTGOING		0x4


// ------------------------------------- LINUX IMPB over I2C VALUES


#define LINUX_IPMB_FLAGS_PROMISCUOUS_MODE_ENABLED		0x00000001
#define LINUX_IPMB_FLAGS_PROMISCUOUS_MODE_DISABLED		0x00000002
#define LINUX_IPMB_FLAGS_WENT_OFFLINE					0x00000004
#define LINUX_IPMB_FLAGS_WENT_OFFLINE_2					0x00000008
#define LINUX_IPMB_FLAGS_ATTACHED_TO_I2C_BUS			0x00000010
#define LINUX_IPMB_FLAGS_DETACHED_TO_I2C_BUS			0x00000020
#define LINUX_IPMB_FLAGS_PROMISC_BUFFER_IS_OVERFLOWED	0x00000040
#define LINUX_IPMB_FLAGS_PROMISC_BUFFER_NOTFULL			0x00000080
#define LINUX_IPMB_FLAGS_I2C_DATA_IS_OVERFLOWED			0x00000100
#define LINUX_IPMB_FLAGS_I2C_DATA_NO_LONGER_FULL		0x00000120


/*********************************************** OSI LAYER 3 PROTOCOLS ***********************************************/


// ------------------------------------- IPX PROTOCOL VALUES

#define IPX_FRAME_NONE					0x00
#define IPX_FRAME_SNAP					0x01
#define IPX_FRAME_8022					0x02
#define IPX_FRAME_ETHERII				0x03
#define IPX_FRAME_8023					0x04
#define IPX_FRAME_TR_8022				0x05

// ------------------------------------- IEEE 1905 1A CONTROL PROTOCOL

// Message Type Field

#define IEEE_19051A_TOPOLOGY_DISCOVERY_MESSAGE                     	0x0000
#define IEEE_19051A_TOPOLOGY_NOTIFICATION_MESSAGE                  	0x0001
#define IEEE_19051A_TOPOLOGY_QUERY_MESSAGE                         	0x0002
#define IEEE_19051A_TOPOLOGY_RESPONSE_MESSAGE                      	0x0003
#define IEEE_19051A_VENDOR_SPECIFIC_MESSAGE                        	0x0004
#define IEEE_19051A_LINK_METRIC_QUERY_MESSAGE                      	0x0005
#define IEEE_19051A_AP_AUTOCONFIGURATION_RENEW_MESSAGE				0x000a

// ------------------------------------- HOMEPLUG PROTOCOLS FAMILY

#define HOMEPLUG_AV_GET_DEVICE_SW_VERSION_REQ_LEN   (3 + 47)
#define HOMEPLUG_AV_GET_DEVICE_SW_VERSION_REQ_TYPE  0x00
#define HOMEPLUG_AV_GET_DEVICE_SW_VERSION_RES_TYPE  0x01

#define HOMEPLUG_AV_REQ_BRIDGE 					0x6020
#define HOMEPLUG_AV_GET_BEACON_REQ      		0x603c
#define HOMEPLUG_AV_GET_BEACON_CNF      		0x603d
#define HOMEPLUG_AV_ISP_DETECTION_REPORT_IND  	0x0066

// ------------------------------------- PROFINET PROTOCOL

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

#define PROFINET_DCP_OPTION_IP                 	0x01
#define PROFINET_DCP_OPTION_DEVICE             	0x02
#define PROFINET_DCP_OPTION_DHCP               	0x03
#define PROFINET_DCP_OPTION_RESERVED           	0x04
#define PROFINET_DCP_OPTION_CONTROL            	0x05
#define PROFINET_DCP_OPTION_DEVICEINITIATIVE   	0x06
#define PROFINET_DCP_OPTION_ALL					0xff

// ------------------------------------- LLTD OVER I2C PROTOCOL

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

// ------------------------------------- ARP PROTOCOL

#define ARP_OPCODE_REQUEST 	0x01
#define ARP_OPCODE_REPLY 	0x02

// ------------------------------------- IGMP PROTOCOL

#define IGMP_MESSAGE_MEMBERSHIP_QUERRY 		0x11
#define IGMPV1_MESSAGE_MEMBERSHIP_REPORT 	0x12
#define IGMPV2_MESSAGE_MEMBERSHIP_REPORT 	0X16
#define IGMPV3_MESSAGE_MEMBERSHIP_REPORT	0X22
#define IGMP_MESSAGE_LEAVE_GROUP			0X17

// ------------------------------------- ICMPV6 PROTOCOL

#define ICMPV6_TYPE_ECHO_REQUEST							0x80
#define ICMPV6_TYPE_ECHO_REPLY								0x81
#define ICMPV6_TYPE_ROUTER_SOLICITATION						0x85
#define ICMPV6_TYPE_NEIGHBOOR_SOLICITATION					0x87
#define ICMPV6_TYPE_NEIGHBOOR_ADVERTISEMENT					0x88
#define ICMPV6_TYPE_REDIRECT								0x89
#define ICMPV6_TYPE_MULTICAST_LISTENER_REPORT_MESSAGE		0x8f

// ------------------------------------------------------------------------ OSI Layer 5 protocols

// NETBIOS PROTOCOL VALUES

#define SMB_COMMAND_TRANS_REQUEST			0x25

#define BROWSER_COMMAND_HOST_ANNOUNCEMENT				0x01
#define BROWSER_COMMAND_REQUEST_ANNOUNCEMENT			0x02
#define BROWSER_COMMAND_ELECTION_REQUEST 				0x08
#define BROWSER_COMMAND_WORKGROUP_ANNOUNCEMENT			0x0c
#define BROWSER_COMMAND_LOCAL_MASTER_ANNOUNCEMENT		0x0f

// ------------------------------------------------------------------------ OSI Layer 7 protocols

// ------------------------------------- DNS PROTOCOL VALUES

#define DNS_OPCODE_QUERRY		0x00
#define DNS_OPCODE_STATUS		0x02
#define DNS_OPCODE_NOTIFY		0x04
#define DNS_OPCODE_UPGRADE		0x05

#define DNS_RCODE_NOERROR		0x00
#define DNS_RCODE_FORMERR		0x01
#define DNS_RCODE_SERVFAIL		0x02
#define DNS_RCODE_NOTIMP		0x04
#define DNS_RCODE_REFUSED		0x05

// NBNS and DNS source/dest port

#define NBNS_PORT		0x0089
#define DNS_PORT 		0x0035
#define MDNS_PORT  		0x14e9


// ------------------------------------------------------------------------ OSI Layer 2 protocols

// LLC Protocol
void parse_llc_control_field(uint8_t);

// Bluetooth protocols
void parse_hci_h4_command_type(unsigned char*, int);
void parse_hci_h4_event_type(unsigned char*, int);

void parse_hci_h4_type_field(uint8_t);
void parse_hci_h4_event_code_field(uint8_t);

void parse_sll_type_field(uint16_t);
void parse_linux_ipmb_flags_field(uint64_t);

// ------------------------------------------------------------------------ OSI Layer 3 protocols


void parse_ieee_19051a_message_type_field(uint16_t);

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
void parse_icmpv6_type_field(uint8_t);

// ------------------------------------------------------------------------ OSI Layer 7 protocols


void parse_dns_opcode_field(uint8_t);
void parse_dns_rcode_field(uint8_t);

#endif

