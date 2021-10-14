/* Includes */

#include "sock_utils.h"
#include "parsing.h"

/************************************* IN PROGRESS *************************************/

int load_oui_address_from_file(char* filename, uint32_t max_entries, char** oui_addr_list){

	size_t read;
	size_t len;
	char *line_buff;

	FILE* database = fopen(filename, "r");
	oui_addr_list = malloc(sizeof(char*) * max_entries);

	if (database == NULL || oui_addr_list == NULL){
		return -1;
	}

	uint32_t i = 0;

	while ((read = getline(&line_buff, &len, database)) != -1){

		oui_addr_list[i] = malloc(sizeof(char) * MAX_LENGTH_OUI_ENTRY);

		if (oui_addr_list[i] != NULL){
			memcpy(oui_addr_list[i], line_buff, read + 1);
			*(oui_addr_list + i)[read] = '\0';
			++i;
		}
		else{
			fclose(database);
			return -1;
		}
    }

    fclose(database);

    printf("OUI address database loaded : %u entries\n");
    return i;

}

void get_oui_infos(char* oui_addr, char** oui_database, size_t database_len){

	uint32_t low = 0;
	uint32_t mid;
	uint32_t high = database_len - 1;

	 while(low <= high)
	 {
		mid = (low + high) / 2;

		char* current_oui_addr = strtok(oui_database[mid], "\t");

		if (strcmp(oui_addr, current_oui_addr) == 0){
			char* oui_info = strchr(oui_database[mid], strlen(current_oui_addr));
		 	printf("%s\n", oui_info);
		}
		else if(strcmp(oui_addr, current_oui_addr) > 0){
		 	high = high;
		 	low = mid + 1;
		}
		else{
		 	low = low;
		 	high = mid - 1;
		 }
	}

	printf("Entry not found in file\n");	
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
