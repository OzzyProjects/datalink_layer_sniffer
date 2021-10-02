/* Includes */

#include "sock_utils.h"
#include "parsing.h"

/************************************* IN PROGRESS *************************************/

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

void parse_pndcp_service_id_field(uint8_t service_id){

	switch(service_id){

		case PNDCP_SERVICE_ID_GET: 
			printf("GET\n");
			break;

		case PNDCP_SERVICE_ID_SET: 
			printf("SET\n");
			break;

		case PNDCP_SERVICE_ID_IDENTIFY: 
			printf("IDENTIFY\n");
			break;

		case PNDCP_SERVICE_ID_HELLO: 
			printf("HELLO\n");
			break;

		default:
			printf("Unknown Value\n");

	}
}

void parse_pndcp_service_type_field(uint8_t service_type){

	switch(service_type){

		case PNDCP_SERVICE_TYPE_REQUEST: 
			printf("Request\n");
			break;

		case PNDCP_SERVICE_TYPE_RESPONSE_SUCCESS: 
			printf("Response Succes\n");
			break;

		case PNDCP_SERVICE_TYPE_RESPONSE_UNSUPPORTED: 
			printf("Response Unsupported\n");
			break;

		default:
			printf("Unknown Value\n");

	}
}

void parse_pndcp_option_field(uint8_t option){

	switch(option){

		case PNDCP_OPTION_IP: 
			printf("IP\n");
			break;

		case PNDCP_OPTION_DEVICE: 
			printf("Device\n");
			break;

		case PNDCP_OPTION_DHCP: 
			printf("DHCP\n");
			break;

		case PNDCP_OPTION_RESERVED: 
			printf("Reserved\n");
			break;

		case PNDCP_OPTION_CONTROL: 
			printf("Control\n");
			break;

		case PNDCP_OPTION_DEVICEINITIATIVE: 
			printf("Device initiative\n");
			break;

		case PNDCP_OPTION_ALL: 
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
