/* Includes */

#include "sock_utils.h"
#include "parsing.h"


/************************************* BLUETOOTH **************************************/

// Parsing and Displaying HCI_H4 Command Type Packets

void parse_hci_h4_command_type(unsigned char* real_header, int size){

	
	// We need to get the command opcode to parse thne packet
	uint16_t opcode = __my_swab16(*((uint16_t*)(real_header + 2)));

	switch(opcode){

		// Command Complete Packet

        case HCI_H4_EVENT_COMMAND_COMPLETE:

        	print_hci_h4_command_complete_header(real_header);
        	break;


        case HCI_H4_COMMAND_CREATE_CONNEXION:

            printf("   |-Command Opcode (Create Connexion)  : %x\n", opcode);
            printf("   |-Param Length                       : %x\n", *((uint8_t*)(real_header + 4)));
            printf("   |-Device MAC                         : %02X-%02X-%02X-%02X-%02X-%02X\n", *((uint8_t*)(real_header + 5)), *((uint8_t*)(real_header + 6)) , *((uint8_t*)(real_header + 7)), 
                *((uint8_t*)(real_header + 8)), *((uint8_t*)(real_header + 9)), *((uint8_t*)(real_header + 10)));

            printf("   |-Page Scan Mode                     : %x\n", *((uint8_t*)(real_header + 11)));
            printf("   |-Packet Type                        : %x\n", ntohs(*((uint16_t*)(real_header + 12))));
            printf("   |-Clock Offset                       : %x\n", ntohs(*((uint16_t*)(real_header + 14)) >> 15) & 0x1);
            break;

        case HCI_H4_COMMAND_LINK_KEY_REQUUEST_REPLY:

            printf("   |-Command Opcode (Link Key Reply)  : %x\n", opcode);
            printf("   |-Param Length                     : %x\n", (uint8_t)(*(real_header + 4)));            
            printf("   |-Device MAC                       : %02X-%02X-%02X-%02X-%02X-%02X\n", (uint8_t)(*(real_header + 5)), (uint8_t)(*(real_header + 6)), (uint8_t)(*(real_header + 7)), 
                (uint8_t)(*(real_header + 8)), (uint8_t)(*(real_header + 9)), (uint8_t)(*(real_header + 10)));

            printf("   |-Link Key                         : ");
            print_char_to_hex(real_header, 11, size - 11);
            break;

        case HCI_H4_COMMAND_READ_REMOTE_EXTENDED_FEATURES:

			printf("   |-Command Opcode (Read Remote Extended Features)  	: %x\n", opcode);
            printf("   |-Param Length                                       : %x\n", *((uint8_t*)(real_header + 4)));
            printf("   |-Connexion Handle                                   : %x\n", ntohs(*((uint16_t*)(real_header + 5))));
            printf("   |-Page Number                                        : %x\n", *((uint8_t*)(real_header + 7)));
            break;

        case HCI_H4_COMMAND_SENT_INQUIRY:

            printf("   |-Command Opcode (Inquiry)         : %x\n", opcode);
            printf("   |-Param Length                     : %x\n", *((uint8_t*)(real_header + 4)));
            printf("   |-LAP                              : %02x%02x%02x\n", *((uint8_t*)(real_header + 7)), *((uint8_t*)(real_header + 6)), *((uint8_t*)(real_header + 5)));
            printf("   |-Num Response                     : %x\n", (uint8_t)(*(real_header + 8)));
            break;

        case HCI_H4_COMMAND_LE_SET_SCAN_ENABLED:

            printf("   |-Command Opcode (Set Scan Enabled)      : %x\n", opcode);
            printf("   |-Param Length                           : %x\n", *((uint8_t*)(real_header + 4)));
            printf("   |-Scan Enabled                           : %x\n", *((uint8_t*)(real_header + 5)));
            printf("   |-Filter Duplicate                       : %x\n", *((uint8_t*)(real_header + 6)));
            printf("   |-Duration                               : %x\n", ntohs(*((uint16_t*)(real_header + 8))));
            printf("   |-Period                                 : %x\n", ntohs(*((uint16_t*)(real_header + 11))));
            break;

        default:
            printf("   |-Command Opcode (Unknown)               : %x\n", opcode);
    }

}

// Parsing and Displaying HCI_H4 Event Type Packets

void parse_hci_h4_event_type(unsigned char* real_header, int size){


	uint8_t event = *((uint8_t*)(real_header + 2)); 

	switch(event){

        case HCI_H4_EVENT_REMOTE_NAME_REQUEST_COMPLETE:
        	break;

        case HCI_H4_EVENT_EXTENDED_INQUIRY_RESULT:

 		    printf("   |-Event Type (Extended Inquiry Result)   : %x\n", event);
            printf("   |-Param Length                           : %x\n", *((uint8_t*)(real_header + 3)));
            printf("   |-Number of Responses                    : %x\n", *((uint8_t*)(real_header + 4)));
           	printf("   |-Device MAC                             : %02X-%02X-%02X-%02X-%02X-%02X\n", *((uint8_t*)(real_header + 5)), *((uint8_t*)(real_header + 6)) , 
                *((uint8_t*)(real_header + 7)), *((uint8_t*)(real_header + 8)), *((uint8_t*)(real_header + 9)), *((uint8_t*)(real_header + 10)));

            printf("   |-Port Scan Repetiton Mode               : %x\n", *((uint8_t*)(real_header + 11)));
            printf("   |-Class Device                           : %02x%02x%02x\n", *((uint8_t*)(real_header + 14)), *((uint8_t*)(real_header + 13)), *((uint8_t*)(real_header + 12)));
            printf("   |-Clock Offset                           : %x\n", ntohs(*((uint16_t*)(real_header + 15))));
            printf("   |-RSSI                                   : %x\n", ntohs(*((uint16_t*)(real_header + 17))));
            printf("   |-Extended Inquiry Data                  :\n");
            print_char_to_hex(real_header, 19, size);
            break;

        case HCI_H4_EVENT_ENCRYPTION_CHANGE:

            printf("   |-Event Type (Encryption Change)     : %x\n", event);
            printf("   |-Param Length                       : %x\n", *((uint8_t*)(real_header + 3)));
            printf("   |-status                             : %x\n", ntohs(*((uint16_t*)(real_header + 4))));
            printf("   |-Connexion Handle                   : %x\n", ntohs(*((uint16_t*)(real_header + 6))));
            printf("   |-Encryption Handle                  : %x\n", *((uint8_t*)(real_header + 8)));
            break;

        case HCI_H4_EVENT_LINK_KEY_NOTIFICATION:

            printf("   |-Event Type (Link Key Notification) : %x\n", *((uint8_t*)(real_header + 2)));
            printf("   |-Param Length                       : %x\n", *((uint8_t*)(real_header + 3)));
            printf("   |-Device MAC                         : %02X-%02X-%02X-%02X-%02X-%02X\n", *((uint8_t*)(real_header + 4)), *((uint8_t*)(real_header + 5)) , 
                *((uint8_t*)(real_header + 6)), *((uint8_t*)(real_header + 7)), *((uint8_t*)(real_header + 8)), *((uint8_t*)(real_header + 9)));

            // getting the encryption key 

            printf("   |-Key                                : ");
            print_char_to_hex(real_header, 10, size - 1);
            
            printf("   |-Key Type                           : %x\n", *((uint8_t*)(real_header + size - 1)));
            break;


        case HCI_H4_EVENT_INTEL_VENDOR_SPECIFIC:

            printf("   |-Event Type (Encryption Change)     : %x\n", event);
            printf("   |-Param Length                       : %x\n", *((uint8_t*)(real_header + 3)));
            printf("   |-status                             : %x\n", ntohs(*((uint16_t*)(real_header + 4))));
            printf("   |-Connexion Handle                   : %x\n", ntohs(*((uint16_t*)(real_header + 6))));
            printf("   |-Encryption Handle                  : %x\n", *((uint8_t*)(real_header + 8)));
            break;

        case HCI_H4_EVENT_NUMBER_COMPLETE_PACKAGES:

            printf("   |-Event Type (Number of Complete Packages)       : %x\n", event);
            printf("   |-Param Length                                   : %x\n", *((uint8_t*)(real_header + 3)));
            printf("   |-Number of Connexion Handles                    : %x\n", *((uint8_t*)(real_header + 4)));
            printf("   |-Connexion Handle                               : %x\n", ntohs(*((uint16_t*)(real_header + 5))));
            printf("   |-Number of Complete Packages                    : %x\n", ntohs(*((uint16_t*)(real_header + 7))));
            break;

        case HCI_H4_EVENT_LE_META:

            printf("   |-Event Type (LE Meta)               : %x\n", event);
            printf("   |-Param Length                       : %x\n", *((uint8_t*)(real_header + 3)));
            printf("   |-Sub Event                          : %x\n", *((uint8_t*)(real_header + 4)));
            printf("   |-Connexion Handle                   : %x\n", ntohs(*((uint16_t*)(real_header + 5))));
            printf("   |-Max TX Octets                      : %x\n", ntohs(*((uint16_t*)(real_header + 7))));
            printf("   |-Max TX Time                        : %x\n", ntohs(*((uint16_t*)(real_header + 9))));
            printf("   |-Max RX Octets                      : %x\n", ntohs(*((uint16_t*)(real_header + 11))));
            break;

        default:
            printf("   |-Event Type                         : %x\t", event);
            parse_hci_h4_event_code_field(event);
    }
}

// parsing the HCI H4 Event Code field

void parse_hci_h4_event_code_field(uint8_t event_code){

 	switch(event_code){

		case HCI_H4_EVENT_INQUIRY_COMPLETE:
			printf("(Inquiry Complete)\n");
		break;

		case HCI_H4_EVENT_CONNECT_COMPLETE: 
			printf("(Connexion Complete)\n");
		break;

		case HCI_H4_EVENT_CONNEXION_REQUEST:
			printf("(Connexion Request)\n");
		break;

		case HCI_H4_EVENT_MODE_CHANGE:
			printf("(Mode Change)\n");
		break;

		case HCI_H4_EVENT_DECONNEXION_COMPLETE:
			printf("(Deconnexion Complete)\n");
		break;

		case HCI_H4_EVENT_AUTH_COMPLETE:
			printf("(Authentification Complete)\n");
		break;

		case HCI_H4_EVENT_REMOTE_NAME_REQUEST_COMPLETE:
			printf("(Remote Name Request)\n");
		break;

		case HCI_H4_EVENT_COMMAND_STATUS: 
			printf("(Command Status)\n");
		break;

		case HCI_H4_EVENT_ENCRYPTION_CHANGE:
			printf("(Encryption Change)\n");
		break;

		case HCI_H4_EVENT_READ_REMOTE_SUPPORTED_FEATURES:
			printf("(Read Remote Supported Features)\n");
		break;

		case HCI_H4_EVENT_COMMAND_COMPLETE:
			printf("(Command Complete)\n");
		break;

		case HCI_H4_EVENT_EXTENDED_INQUIRY_RESULT:
			printf("(Extended Inquiry Result)\n");
		break;

		default:
			printf("(Unknown | Invalid)\n");
	}

}


void parse_hci_h4_type_field(uint8_t type_field){

	switch(type_field){

		case HCI_H4_TYPE_COMMAND: 
			printf("(Command)\n");
		break;

		case HCI_H4_TYPE_ACL_DATA:
			printf("(ACL Data)\n");
		break;

		case HCI_H4_TYPE_SCO_DATA:
			printf("(SCO Data)\n");
		break;

		case HCI_H4_TYPE_EVENT:
			printf("(Event)\n");
		break;

		default:
			printf("(Invalid)\n");
	}

}

void parse_sll_type_field(uint16_t type_field){

	switch(type_field){

		case LINUX_SLL_HOST: 
			printf("(Host)\n");
		break;

		case LINUX_SLL_BROADCAST:
			printf("(Broadcast)\n");
		break;

		case LINUX_SLL_MULTICAST:
			printf("(Multicast)\n");
		break;

		case LINUX_SLL_OTHERHOST:
			printf("(Other host)\n");
		break;

		case LINUX_SLL_OUTGOING:
			printf("(Outgoing)\n");
		break;

		default:
			printf("(Unknown | Invalid)\n");
	}

}

/************************************* LLC PROTOCOL **************************************/

void parse_llc_control_field(uint8_t ctrl_field){

	switch(ctrl_field){

		case LLC_CONTROL_FIELD_FORMAT_UI: 
			printf("(Format UI)\n");
			break;

		case LLC_CONTROL_FIELD_FORMAT_DISC:
			printf("(Format DISC)\n");
			break;

		case LLC_CONTROL_FIELD_FORMAT_UA:
			printf("(Format UA)\n");
			break;

		case LLC_CONTROL_FIELD_FORMAT_DM:
			printf("(Format DM)\n");
			break;

		case LLC_CONTROL_FIELD_FORMAT_XID_SABME:
			printf("(Format XID SABME)\n");
			break;

		case LLC_CONTROL_FIELD_FORMAT_XID:
			printf("(Format XID)\n");
			break;

		default:
			printf("(Not implemented or Unknown\n");
	}

}


/************************************* OTHER OSI LAYER 2 PROTOCOLS **************************************/

// Parsing IPMB over I2C Flags with all registered values

void parse_linux_ipmb_flags_field(uint64_t flags){

	switch(flags){

		case LINUX_IPMB_FLAGS_PROMISCUOUS_MODE_ENABLED: 
			printf("(Promisc Mode Enabled)\n");
			break;

		case LINUX_IPMB_FLAGS_PROMISCUOUS_MODE_DISABLED:
			printf("(Promisc Mode Disabled)\n");
			break;

		case LINUX_IPMB_FLAGS_WENT_OFFLINE:
			printf("(Went Offline)\n");
			break;

		case LINUX_IPMB_FLAGS_WENT_OFFLINE_2:
			printf("(Went Offline)\n");
			break;

		case LINUX_IPMB_FLAGS_ATTACHED_TO_I2C_BUS:
			printf("(Attached to I2C Bus)\n");
			break;

		case LINUX_IPMB_FLAGS_DETACHED_TO_I2C_BUS:
			printf("(Detached to I2C Bus)\n");
			break;

		case LINUX_IPMB_FLAGS_PROMISC_BUFFER_IS_OVERFLOWED:
			printf("(Promisc Buffer is Overflowed)\n");
			break;

		case LINUX_IPMB_FLAGS_PROMISC_BUFFER_NOTFULL:
			printf("(Promisc Buffer No Longer Full)\n");
			break;

		case LINUX_IPMB_FLAGS_I2C_DATA_IS_OVERFLOWED:
			printf("(I2C Data is Overflowed)\n");
			break;

		case LINUX_IPMB_FLAGS_I2C_DATA_NO_LONGER_FULL:
			printf("(I2C Data No Longer Full)\n");
			break;

		default:
			printf("(Unknown | Invalid)\n");
	}

}


void parse_arp_opcode_field(uint8_t opcode_field){

	switch(opcode_field){

		case ARP_OPCODE_REQUEST: 
			printf("(Request)\n");
		break;

		case ARP_OPCODE_REPLY:
			printf("(Reply)\n");
		break;

		default:
			printf("(Unknown | Invalid)\n");
	}

}

void parse_profinet_dcp_service_id_field(uint8_t service_id){

	switch(service_id){

		case PROFINET_DCP_SERVICE_ID_GET: 
			printf("GET\n");
			break;

		case PROFINET_DCP_SERVICE_ID_SET: 
			printf("SET\n");
			break;

		case PROFINET_DCP_SERVICE_ID_IDENTIFY: 
			printf("IDENTIFY\n");
			break;

		case PROFINET_DCP_SERVICE_ID_HELLO: 
			printf("HELLO\n");
			break;

		default:
			printf("Unknown Value\n");

	}
}


void parse_ieee_19051a_message_type_field(uint16_t msg_type){


	switch(msg_type){

		case IEEE_19051A_TOPOLOGY_DISCOVERY_MESSAGE: 
			printf("(Topology Discovery)\n");
			break;

		case IEEE_19051A_TOPOLOGY_NOTIFICATION_MESSAGE : 
			printf("(Topology Notification)\n");
			break;

		case IEEE_19051A_TOPOLOGY_QUERY_MESSAGE: 
			printf("(Topology Query)\n");
			break;

		case IEEE_19051A_TOPOLOGY_RESPONSE_MESSAGE: 
			printf("(Topology Response\n");
			break;

		case IEEE_19051A_VENDOR_SPECIFIC_MESSAGE: 
			printf("(Vendor Specific)\n");
			break;

		case IEEE_19051A_LINK_METRIC_QUERY_MESSAGE: 
			printf("(Link Metric Query\n");
			break;
 
 		case IEEE_19051A_AP_AUTOCONFIGURATION_RENEW_MESSAGE: 
			printf("(AP AUtoconfiguration Renew\n");
			break;

		default:
			printf("Other Value or Unknown Value\n");

	}

}



void parse_homeplug_av_type_field(uint16_t type){

	switch(type){

		case HOMEPLUG_AV_REQ_BRIDGE: 
			printf("(Bridge Info Request)\n");
			break;

		case HOMEPLUG_AV_GET_BEACON_REQ: 
			printf("(Beacon Request)\n");
			break;

		case HOMEPLUG_AV_GET_BEACON_CNF: 
			printf("(Beacon Configuration)\n");
			break;

		case HOMEPLUG_AV_ISP_DETECTION_REPORT_IND: 
			printf("(Report ISP Detection)\n");
			break;

		default:
			printf("Unknown Value\n");

	}
}

void parse_profinet_dcp_service_type_field(uint8_t service_type){

	switch(service_type){

		case PROFINET_DCP_SERVICE_TYPE_REQUEST: 
			printf("Request\n");
			break;

		case PROFINET_DCP_SERVICE_TYPE_RESPONSE_SUCCESS: 
			printf("Response Succes\n");
			break;

		case PROFINET_DCP_SERVICE_TYPE_RESPONSE_UNSUPPORTED: 
			printf("Response Unsupported\n");
			break;

		default:
			printf("Unknown Value\n");

	}
}

void parse_profinet_dcp_option_field(uint8_t option){

	switch(option){

		case PROFINET_DCP_OPTION_IP: 
			printf("IP\n");
			break;

		case PROFINET_DCP_OPTION_DEVICE: 
			printf("Device\n");
			break;

		case PROFINET_DCP_OPTION_DHCP: 
			printf("DHCP\n");
			break;

		case PROFINET_DCP_OPTION_RESERVED: 
			printf("Reserved\n");
			break;

		case PROFINET_DCP_OPTION_CONTROL: 
			printf("Control\n");
			break;

		case PROFINET_DCP_OPTION_DEVICEINITIATIVE: 
			printf("Device initiative\n");
			break;

		case PROFINET_DCP_OPTION_ALL: 
			printf("ALL\n");
			break;

		default:
			printf("Manufacturer or Unknown\n");

	}
}

// parse the LLTD field function with the most common values

void parse_lltd_function_field(uint8_t function_field){

	switch(function_field){

		case LLTD_FUNCTION_DISCOVER: 
			printf("(Discover)\n");
			break;

		case LLTD_FUNCTION_HELLO: 
			printf("(Hello)\n");
			break;

		case LLTD_FUNCTION_QUERRY: 
			printf("(Querry)\n");
			break;

		case LLTD_FUNCTION_QUERRY_RESP: 
			printf("(Response)\n");
			break;

		case LLTD_FUNCTION_RESET : 
			printf("(Reset) WARNING\n");
			break;
		default:
			printf("(Unknown)\n");

	}

}

// parse the LLTD field service type with the most common values

void parse_lltd_service_type_field(uint8_t service_field){

	switch(service_field){

		case LLTD_SERVICE_TYPE_DISCOVERY: 
			printf("(Topology Discovery)\n");
		break;

		case LLTD_SERVICE_TYPE_QUICK_DISCOVERY: 
			printf("(Quick Discovery)\n");
		break;

		case LLTD_SERVICE_TYPE_QOS_DIAGNOSTICS: 
			printf("(QOS Diagnostics)\n");
		break;

		default:
			printf("(Unknown | Invalid)\n");

	}

}

// parsing ICMP type field with the most common values

void parse_icmp_type_field(uint8_t type_field){

	switch(type_field){

		case ICMP_ECHOREPLY: 
			printf("(Echo Reply)\n");
		break;

		case ICMP_DEST_UNREACH: 
			printf("(Dest Unreachable)\n");
		break;

		case ICMP_REDIRECT: 
			printf("(Redirection)\n");
		break;

		case ICMP_ECHO: 
			printf("(Echo Request)\n");
		break;

		case ICMP_TIMESTAMP: 
			printf("(Timestamp)\n");
		break;

		case ICMP_TIMESTAMPREPLY: 
			printf("(Timestamp Reply)\n");
		break;

		default:
			printf("(Unknown | Invalid)\n");

	}
}


// parsing ICMPv6 (also known as NDP) type field with the most common values

void parse_icmpv6_type_field(uint8_t type_field){

	switch(type_field){

		case ICMPV6_TYPE_ECHO_REQUEST: 
			printf("(Echo Request)\n");
		break;

		case ICMPV6_TYPE_ECHO_REPLY: 
			printf("(Echo Reply)\n");
		break;

		case ICMPV6_TYPE_ROUTER_SOLICITATION: 
			printf("(Router Solicitation)\n");
		break;

		case ICMPV6_TYPE_NEIGHBOOR_SOLICITATION: 
			printf("(Neighboor Solicitation)\n");
		break;

		case ICMPV6_TYPE_NEIGHBOOR_ADVERTISEMENT: 
			printf("(Neighboor Advertisement)\n");
		break;

		case ICMPV6_TYPE_REDIRECT: 
			printf("(Redirect)\n");
		break;

		case ICMPV6_TYPE_MULTICAST_LISTENER_REPORT_MESSAGE: 
			printf("(Multicast Listener Report Message)\n");
		break;

		default:
			printf("(Unknown | Invalid)\n");

	}
}


// parse the IGMP field service type with the most common values

void parse_igmp_message_type_field(uint8_t message_field){
	
	switch(message_field){

		case IGMP_MESSAGE_MEMBERSHIP_QUERRY: 
			printf("(Membership Querry)\n");
			break;

		case IGMPV1_MESSAGE_MEMBERSHIP_REPORT: 
			printf("(IGMPV1 Membership Report)\n");
			break;

		case IGMPV2_MESSAGE_MEMBERSHIP_REPORT: 
			printf("(IGMPV2 Membership Report)\n");
			break;

		case IGMPV3_MESSAGE_MEMBERSHIP_REPORT: 
			printf("(IGMPV3 Membership Report)\n");
			break;

		case IGMP_MESSAGE_LEAVE_GROUP: 
			printf("(Leave Group)\n");
			break;

		default:
			printf("(Unknown | Invalid)\n");

	}

}


// parsing DNS header fields with the most common values

void parse_dns_opcode_field(uint8_t opcode){

	switch(opcode){

		case DNS_OPCODE_QUERRY: 
			printf("(Querry)\n");
			break;

		case DNS_OPCODE_STATUS: 
			printf("(Status)\n");
			break;

		case DNS_OPCODE_NOTIFY: 
			printf("(Notify)\n");
			break;

		case DNS_OPCODE_UPGRADE: 
			printf("(Upgrade)\n");
			break;

		default:
			printf("(Unknown | Invalid)\n");

	}	

}

void parse_dns_rcode_field(uint8_t rcode){

	switch(rcode){

		case DNS_RCODE_NOERROR: 
			printf("(No error)\n");
			break;

		case DNS_RCODE_FORMERR: 
			printf("(Formerr)\n");
			break;

		case DNS_RCODE_SERVFAIL: 
			printf("(Servfail)\n");
			break;

		case DNS_RCODE_NOTIMP: 
			printf("(No timp)\n");
			break;

		case DNS_RCODE_REFUSED: 
			printf("(Refused)\n");
			break;

		default:
			printf("(Unknown | Invalid)\n");

	}	

}
