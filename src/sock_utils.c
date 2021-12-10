#include "sock_utils.h"
#include "parsing.h"

static int DATALINK_SIZE;

/************************************* IN PROGRESS *************************************/

/* checksum function, non implemented yet */

uint16_t in_cksum(uint16_t *addr, int len){

    int nleft = len;
    uint32_t sum = 0;
    uint16_t *w = addr;
    uint16_t answer = 0;

    while (nleft > 1) {
        sum += *w;
        nleft -= 2;
        w++;
    }

    // If an odd byte is left
    if (nleft == 1) {
        *(unsigned char *) (&answer) = *(unsigned char *)w;
        sum += answer;
    }

    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    answer = ~sum;

    return answer;
}

/*********************************************** OSI LAYER 2 PROTOCOLS ***********************************************/

// function used to process each OSI Layer 2 packets to allow them to be dissected

void process_layer2_packet(unsigned char* buffer, int size, int datalink_type){

	// the function pointer that displays the datalink header of the packet and the var ethertype will be
	// used by some OSI datalink protocols which are Ethernet compliant (some padding bytes at the beginning etc...)
	// Exemple : Linux SLL or some 802.1x protocols
	 	
	void (*print_datalink_header)(unsigned char*, int);
	uint16_t ethertype;
	
    // parsing the datalink type to proper dissect the packet after

    switch(datalink_type){

        // the datalink type is not supported by capture card or an error occured
        case PCAP_ERROR_NOT_ACTIVATED:
            fprintf(stderr, "\nFATAL ERROR : Failed to get the data link type !\n");
           	exit(EXIT_FAILURE);
           	break;
           	
			// for the datalink type RAW, we do not use a specific header struct but we'gonna try to 
			// mananage it specifically based on it's size etc...        
        case DLT_RAW:
           	printf("\nRAW DATALINK\n");
            DATALINK_SIZE = 0;
            break;

        // Linux SLL = 16 Header bytes but it is Ethernet based (specific to monitor mode)
        case DLT_LINUX_SLL:

            printf("\nLinux SLL\n");
            DATALINK_SIZE = SLL_HDR_LEN;
            sll_header* sllhdr = (sll_header*)buffer;
       		print_datalink_header = &print_linux_sll_header;
       		
       		// getting the ethertype number and processing frame
        	ethertype = ntohs(sllhdr->sll_protocol);
        	process_ethernet_frame(buffer, size, ethertype, print_datalink_header);
            break;

        // Ethernet = 14 Header Bytes
        case DLT_EN10MB:

            printf("\nEthernet\n");
           	DATALINK_SIZE = ETH2_HEADER_LEN;
           	struct ethhdr *eth = (struct ethhdr *)buffer;
        	print_datalink_header = &print_ethernet_header;
        		
        	// getting the ethertype number and processing frame
        	ethertype = ntohs(eth->h_proto);

            if (ethertype < 800){
                process_802_3_frame(buffer, size);
            }
            else{
                process_ethernet_frame(buffer, size, ethertype, print_datalink_header);
            }

            break;

         // Bluetooth HCI H4 datalink layer protocol = 2 Header Bytes
        case DLT_BLUETOOTH_HCI_H4_WITH_PHDR:
            printf("\nDLT_BLUETOOTH_HCI_H4_WITH_PHDR\n");
            DATALINK_SIZE = HCI_H4_HDR_LEN;
            parse_bluetooth_packet(buffer, size);
            break;
            
			// Many wireless protocols are based on this norm        
        case DLT_IEEE802_11:
            printf("\nIEEE802 11 (not implemented yet )\n");
            DATALINK_SIZE = 0;
            break;

        // IPMB/IPMI Layer 2 protocol (Not Implemented Yet)
        case DLT_IPMB_LINUX:
            printf("\nIPMB/IPMI\n");
            DATALINK_SIZE = IPMB_HDR_LEN;
            print_linux_ipmb_pseudo_header(buffer, size);
            break;

        default:
            printf("\nERROR: Unknown Datalink type or Datalink type is not implemented yet\n");
            exit(EXIT_FAILURE);
    }

    return;

}



/*********************************************** 802.11 PROTOCOLS (RADIOTAP) ***********************************************/

/*********************************************** 802.3 FRAME ***********************************************/

// Printing IEEE 802.3 Frame Header

void print_802_3_frame_header(unsigned char* buffer){

    struct ieee_802_3_frame_header* _802_3_hdr = (struct ieee_802_3_frame_header*)buffer;

    printf("\nIEEE 802.3 Frame Header\n\n");

    printf("   |-Destination Address    : %02X-%02X-%02X-%02X-%02X-%02X\n", _802_3_hdr->mac_dest[0] , _802_3_hdr->mac_dest[1] , _802_3_hdr->mac_dest[2] , 
        _802_3_hdr->mac_dest[3] , _802_3_hdr->mac_dest[4] , _802_3_hdr->mac_dest[5]);

    printf("   |-Source Address         : %02X-%02X-%02X-%02X-%02X-%02X\n", _802_3_hdr->mac_src[0] , _802_3_hdr->mac_src[1] , 
        _802_3_hdr->mac_src[2] , _802_3_hdr->mac_src[3] , _802_3_hdr->mac_src[4] , _802_3_hdr->mac_src[5]);

    printf("   |-Length                 : %x\n", ntohs(_802_3_hdr->length));

}


// Printing IEEE 802.3 LLC Header

void print_llc_header(unsigned char* buffer, int* offset){

    struct llc_header* llc_hdr = (struct llc_header*)(buffer + *offset);

    // we compute the new offset avalaible by increment it by the size of the actual struct
    *offset += sizeof(struct llc_header);

    printf("\nLLC Header\n\n");

    printf("   |-DSAP                   : %x\n", llc_hdr->dsap);
    printf("   |-SSAP                   : %x\n", llc_hdr->ssap);

    printf("   |-Control Field          : %x\t", llc_hdr->ctrl_field);
    parse_llc_control_field(llc_hdr->ctrl_field);

    if (llc_hdr->ctrl_field == LLC_CONTROL_FIELD_FORMAT_UI){

        printf("   |-Organisation Code      : %02X%02X%02X\n", *((uint8_t*)(buffer + *offset)), *((uint8_t*)(buffer + *offset + 1)),
            *((uint8_t*)(buffer + *offset + 2)));
        printf("   |-PID                    : %x\n", *((uint8_t*)(buffer + *offset + 3)));

        // 4 bytes : the size of two more fields for UI format -> updating the current offset value
        *offset += 4;

    }

    else if (llc_hdr->ctrl_field == LLC_CONTROL_FIELD_FORMAT_XID){

        struct llc_basic_xid_header* xid_hdr = (struct llc_basic_xid_header*)(buffer + *offset);

        printf("   |-XID Format             : %x\n", xid_hdr->xid_format);
        printf("   |-LLC Types              : %x\n", xid_hdr->llc_types);
        printf("   |-Windows Size           : %x\n", xid_hdr->windows_size);

        // updating the current offset value
        *offset += sizeof(struct llc_basic_xid_header);

    }

    else{

        printf("This LLC Type  %x is not implemented yet ! In Progress...\n", llc_hdr->ctrl_field);
    }

}


// Processing the IEEE 802.3 Frame

void process_802_3_frame(unsigned char* buffer, int size __attribute__((unused))){

    int offset = sizeof(struct ieee_802_3_frame_header);

    uint8_t llc_ctrl_field = *((uint8_t*)(buffer + offset + 2));

    print_802_3_frame_header(buffer);

    print_llc_header(buffer, &offset);

}


/*********************************************** ETHERNET PROTOCOLS ***********************************************/

// Processing ethernet frame by ethertype

void process_ethernet_frame(unsigned char* buffer, int size, uint16_t proto, void (*print_datalink_header)(unsigned char*, int)){

    switch(proto){

        case ETHERTYPE_ARP:
            printf("\nARP frame there!\n");
            print_datalink_header(buffer, size);
            print_arp_header(buffer);
            break;

        case ETHERTYPE_IEEE1905_1:
            printf("\nETHERTYPE_IEEE1905_1 frame there!\n");
            print_datalink_header(buffer, size);
            print_ieee_1905_header(buffer);
            break;

        case ETHERTYPE_HOMEPLUG:
            printf("\nETHERTYPE_HOMEPLUG frame there!\n");
            print_datalink_header(buffer, size);
            print_homeplug_header(buffer);
            break;

        case ETHERTYPE_HOMEPLUG_POWERLINE:
            printf("\nETHERTYPE_HOMEPLUG_POWERLINE frame there!\n");
            print_datalink_header(buffer, size);
            print_homeplug_av_header(buffer);
            break;

        case ETHERTYPE_LLDT:
            printf("\nLLDT frame there!\n");
            print_datalink_header(buffer, size);
            print_lltd_header(buffer);
            break;

        case ETHERTYPE_PROFINET_DCP:
            printf("\nPROFINET_DCP frame there!\n");
            print_datalink_header(buffer, size);
            print_profinet_dcp_header(buffer);
            break;

        case ETHERTYPE_IP:
            printf("\nIP frame there!\n");
            print_datalink_header(buffer, size);
            process_ip_packet(buffer, size);
            break;

        case ETHERTYPE_IPV6:
            printf("\nIPv6 frame there!\n");
            print_datalink_header(buffer, size);
            print_ip6_header(buffer, size);
            break;

        case ETHERTYPE_IEEE_8021Q:
            printf("\nIEEE_8021Q frame there!\n");
            print_datalink_header(buffer, size);
            print_vlan_ieee8021q_header(buffer, size);
            break;

        case ETHERTYPE_EAPOL:
            printf("\nEAPOL frame there!\n");
            print_datalink_header(buffer, size);
            break;

        default:
            printf("\n********* UNKNOWN frame there! **********\n");
            print_datalink_header(buffer, size);
            print_data(buffer, size);
    }
}


/*********************************************** OSI LAYER 2 PROTOCOLS ***********************************************/


/*********************************************** BLUETOOTH PROTOCOLS ***********************************************/


// function which processes each HCI H4 packets (family of Bluetoooth protocols) and manages encapsulation with some other
// ones lile L2CAP, NBEP, ATT and OBEX

void parse_bluetooth_packet(unsigned char* buffer, int size){

    // We ureceive the packets with 3 bytes of padding or reserved, so we skip them to get the real offset of packet

    buffer += HCI_H4_PRE_HEADER_LENGTH;
    size -= HCI_H4_PRE_HEADER_LENGTH;
    
    // Printing the minimalist HCI H4 pseudo header
    print_hci_h4_header(buffer);

    // And we get the type of packet to perform them the dissection
    uint8_t hci_h4_type = *((uint8_t*)(buffer + 1));

    if (hci_h4_type == HCI_H4_TYPE_COMMAND){
        parse_hci_h4_command_type(buffer, size);
    } 

    else if (hci_h4_type == HCI_H4_TYPE_EVENT){
        parse_hci_h4_event_type(buffer, size);
    }

    else if (hci_h4_type == HCI_H4_TYPE_ACL_DATA){
        parse_acl_packet(buffer, size);
    }

    else{
        printf("\nUnknown or HCI_H4 SCO Packet : %x\n", hci_h4_type);
        print_char_to_hex(buffer, 0, size);
    }

}


// parsing the elemental hci h4 header (work in progress)

void print_hci_h4_header(unsigned char* buffer){

    // Printing the basic HCI_H4 Header

    hci_h4_header* hcih4_hdr = (hci_h4_header*)buffer;

    printf("\nHCI_H4 Header\n\n");
    printf("   |-Direction           : %x\n", hcih4_hdr->dir);
    printf("   |-Type                : %x\t", hcih4_hdr->type);
    parse_hci_h4_type_field(hcih4_hdr->type);

}


// function which prints and parse the ACL (Asynchronous Connections Less Link) packets

void parse_acl_packet(unsigned char* buffer, int size){

    // We extract in the first time the ACL Header to print it

    l2cap_header* l2cap_hdr = (l2cap_header*)(buffer + HCI_H4_HDR_LEN + sizeof(acl_packet_header));

    int offset = HCI_H4_HDR_LEN + sizeof(acl_packet_header) + sizeof(l2cap_header);

    print_acl_packet_header(buffer);

    printf("\nL2CAP Header\n\n");
    printf("   |-length             : %x\n", ntohs(l2cap_hdr->length));
    printf("   |-CID                : %x\n", ntohs(l2cap_hdr->cid));

    // And we dispach the packet payload according to the header fields

    if (ntohs(l2cap_hdr->cid) == L2CAP_CID_SIGNALING_CHANNEL){

        printf("   |-Commande Information          : %x\n", ntohs(*((uint16_t*)(buffer + offset))));
        printf("   |-Command Identifier            : %x\n", *((uint8_t*)(buffer + offset + 2)));
        printf("   |-Commande Length               : %x\n", ntohs(*((uint16_t*)(buffer + offset + 3))));
        printf("   |-Information Type              : %x\n", ntohs(*((uint16_t*)(buffer + offset + 5))));
    }

    else if (ntohs(l2cap_hdr->cid) == L2CAP_CID_RESERVED){
        printf("L2CAP CID Reserved\n");
        print_char_to_hex(buffer, offset, size);
    }

    else if (ntohs(l2cap_hdr->cid) == L2CAP_CID_SECURITY_MANAGER_PROTOCOL){
        parse_bluetooth_smp_packet(buffer, size);
    }

    else{
        printf("\nUnknown CID or Not implemented Yet\n");        
        print_char_to_hex(buffer, offset, size);
    }

}

// Displaying the HCI_H4 Command Complete Packet

void print_hci_h4_command_complete_header(unsigned char* buffer){

    hci_h4_command_complete_header* cmphdr = (hci_h4_command_complete_header*)(buffer + HCI_H4_HDR_LEN);

    printf("   |-Event Code         : %x\n", cmphdr->event_code);
    printf("   |-Param Length       : %x\n", cmphdr->param_len);
    printf("   |-Allowed packages   : %x\n", cmphdr->allowed_cmd_packets);
    printf("   |-command Opcode     : %x\n", ntohs(cmphdr->command_opcode)); 
    printf("   |-Status             : %x\n", cmphdr->status);   

}


// Displaying the HCI_H4 Remote Name Request Packet

void print_hci_h4_rem_name_request(unsigned char* buffer){

    hci_h4_rem_name_req* rem_request = (hci_h4_rem_name_req*)(buffer + HCI_H4_HDR_LEN);

    printf("   |-Param Length       : %x\n", rem_request->param_len);
    printf("   |-status             : %x\n", rem_request->status);
    printf("   |-Device MAC         : %02X-%02X-%02X-%02X-%02X-%02X\n", rem_request->src_addr[0] , rem_request->src_addr[1] , rem_request->src_addr[2], 
        rem_request->src_addr[3], rem_request->src_addr[4] , rem_request->src_addr[5]);

    printf("   |-Device Name        : %s\n", rem_request->remote_name);

}

// parsing and printing the L2CAP Header

void print_acl_packet_header(unsigned char* buffer){
    
    acl_packet_header* aclhdr = (acl_packet_header*)(buffer + HCI_H4_HDR_LEN);
    
    printf("\n\nACL Packet Header\n");
    printf("   |-Connexion Handle        : %x\n", aclhdr->connexion_handle);
    printf("   |-PB Flag                 : %x\n", aclhdr->pb_flag);
    printf("   |-BC Flag                 : %x\n", aclhdr->bc_flag);
    printf("   |-Data Length             : %x\n", ntohs(aclhdr->data_len));

}

void print_attribute_protocol_packet(unsigned char* buffer){

    int offset = HCI_H4_HDR_LEN + sizeof(acl_packet_header) + sizeof(l2cap_header);

    uint16_t opcode = ntohs(*((uint16_t*)(buffer + offset)));
    uint16_t length = ntohs(*((uint16_t*)(buffer + offset + 2)));
    
    printf("\n\nBLUETOOTH Attribute Protocol Packet\n");
    printf("   |-Opcode           : %x\n", opcode);
    printf("   |-Length           : %x\n", length);

}

// Parsing Bluetooth Security Protocol Packets 

void parse_bluetooth_smp_packet(unsigned char* buffer, int size __attribute__((unused))){
    
    int public_key_size;
    unsigned char public_key_1[SMP_PUBLIC_KEY_MAX_LENGTH];

    printf("\n\nBluetooth Security Protocol Header\n");
    int offset = HCI_H4_HDR_LEN + sizeof(struct l2cap_header);

    // We need first to get the SMP opcode because it's him that determimes the entire packet format
    uint8_t smp_opcode = *((uint8_t*)(buffer));

    switch(smp_opcode){

        // Pairing Key Request and Pairing Key Response have exactly the same format so we threat them together
        case SMP_OPCODE_PAIRING_REQUEST:
        case SMP_OPCODE_PAIRING_RESPONSE:
            printf("   |-Opcode                            : %x\n", *((uint8_t*)(buffer + offset)));
            printf("   |-IO Capabilities                   : %x\n", *((uint8_t*)(buffer + offset + 1)));
            printf("   |-OOB Data Flags                    : %x\n", *((uint8_t*)(buffer + offset + 2)));
            printf("   |-Authentification Flages           : %x\n", *((uint8_t*)(buffer + offset + 3)));
            printf("   |-Initiation Key Distrib            : %x\n", *((uint8_t*)(buffer + offset + 4)));
            break;

        case SMP_OPCODE_PAIRING_CONFIRM:
            printf("   |-Opcode (Pairing Key Confirm)      : %x\n", *((uint8_t*)(buffer + offset)));
            printf("   |-Confirm values                    : %s\n", buffer + offset + 1);
            break;

        case SMP_OPCODE_PAIRING_RANDOM:
            printf("   |-Opcode (Pairing Key Confirm)      : %x\n", *((uint8_t*)(buffer + offset)));
            printf("   |-Random values                     : %s\n", buffer + offset + 1);
            break;

        // if it's a Pairing Public Key, we need first to calculate the key size from the L2CAP header
        //  the 2 public keys shared have for sure the same size
        case SMP_OPCODE_PAIRING_PUBLIC_KEY:

            // Getting the public key size from the L2CAP header
            public_key_size = (int)((*((uint8_t*)(buffer + offset)) -1) / 2);
            memcpy(&public_key_1, buffer + offset + 1, public_key_size);

            printf("   |-Public Key 1                   : %s\n", public_key_1);
            printf("   |-Random values                  : %s\n", buffer + offset + 1 + public_key_size);
            break;

        default:
            printf("   |-Unknown Opcode                  : %x\n", *((uint8_t*)(buffer + offset)));
    }

}



// Printing Ethernet Header

void print_ethernet_header(unsigned char* buffer){

    struct ethhdr *eth = (struct ethhdr *)buffer;
    
    printf("\nEthernet Header\n\n");
    printf("   |-Destination Address    : %02X-%02X-%02X-%02X-%02X-%02X\n", eth->h_dest[0] , eth->h_dest[1] , eth->h_dest[2] , 
        eth->h_dest[3] , eth->h_dest[4] , eth->h_dest[5]);

    printf("   |-Source Address         : %02X-%02X-%02X-%02X-%02X-%02X\n", eth->h_source[0] , eth->h_source[1] , 
        eth->h_source[2] , eth->h_source[3] , eth->h_source[4] , eth->h_source[5]);

    printf("   |-Protocol               : %x\n", ntohs(eth->h_proto));

}


/*********************************************** ETHERCAT PROTOCOL ***********************************************/


void print_ethercat_frame_header(unsigned char* buffer){

    uint16_t ethercat_hdr = FIRST_TWO_BYTES(buffer);

    printf("\nETHERCAT Frame Headerr\n\n");
    printf("   |-EtherCAT Length            : %x\n", ETHERCAT_LEN(ethercat_hdr));
    printf("   |-EtherCAT (Reserved)        : %x\n", ETHERCAT_RES(ethercat_hdr));
    printf("   |-EtherCAT Command           : %x\n", ETHERCAT_COMMAND(ethercat_hdr));

}

void print_ethercat_datagram_header(unsigned char* buffer, int* offset){

    struct ethercat_datagram_header* ethcat_dgram = (struct ethercat_datagram_header*)(buffer + *offset);

    printf("\nETHERCAT Datagram Header\n\n");

    printf("   |-Command                : %x\n", ethcat_dgram->command);
    printf("   |-Index                  : %x\n", ethcat_dgram->index);
    printf("   |-Slave Address          : %x\n", ntohs(ethcat_dgram->slave_addr));
    printf("   |-Offset Address         : %x\n", ntohs(ethcat_dgram->offset_addr));
    printf("   |-Length                 : %x\n", ntohs(ethcat_dgram->length));
    printf("   |-Interrupt              : %x\n", ntohs(ethcat_dgram->interrupt));

    *offset = sizeof(struct ethercat_datagram_header);

}


// Printing linux SLL header

void print_linux_sll_header(unsigned char* buffer){

    sll_header* sllhdr = (sll_header*)buffer;
    
    printf("\nLinux SLL Header\n\n");
    printf("   |-Type                   : %x\t", ntohs(sllhdr->sll_pkttype));
    parse_sll_type_field(ntohs(sllhdr->sll_pkttype));

    printf("   |-Link Type              : %x\n", ntohs(sllhdr->sll_hatype));
    printf("   |-Link Address Length    : %x\n", ntohs(sllhdr->sll_halen));

    // Printing the datalink address
    printf("   |-Link Address           : ");

    unsigned short i = 0;
    while(i < SLL_ADDRLEN){
        (i < SLL_ADDRLEN - 1) ? printf("%02X-", sllhdr->sll_addr[i]) : printf("%02X", sllhdr->sll_addr[i]);
        i++;
    }
    printf("\n   |-Protocol             : %x\n", ntohs(sllhdr->sll_protocol));

}


void print_linux_ipmb_pseudo_header(unsigned char* buffer, int size __attribute__((unused))){

    struct ipmb_header* ipmbhdr = (struct ipmb_header*)buffer;

    printf("\nLinux IMPB over I2C Header\n\n");

    printf("   |-Bus Number             : %x\t", ipmbhdr->bus_number);
    printf("   |-Type                   : %x\t%s\n", ipmbhdr->type, (ipmbhdr->type & 0x1) ? "Regular" : "Event");

    printf("   |-Flags                  : %x\t", ntohl(ipmbhdr->flags));
    parse_linux_ipmb_flags_field(ntohl(ipmbhdr->flags));

    printf("   |-Hardware Address       : %x\n", ipmbhdr->hardware_addr);

}


void print_vlan_ieee8021q_header(unsigned char* buffer, int size){

    struct vlan_ieee8021q_header* vlan_hdr = (struct vlan_ieee8021q_header*)(buffer + DATALINK_SIZE);

    printf("\nIEEE_8021Q VLAN Header\n\n");
    printf("   |-Priority       : %x\t%s\n", vlan_hdr->priority, (vlan_hdr->priority == 0) ? "(Best Effort)" : "(Normal)");

    // Parsing DEI field
    printf("   |-DEI            : %x\t%s\n", vlan_hdr->dei, ((vlan_hdr->dei & 0x1 ) == 0) ? "(Ineligible)" : "(Eligible)");
    printf("   |-ID             : %x\n", vlan_hdr->id);
    printf("   |-Type           : %x\n", ntohs(vlan_hdr->type));

    // Parsing the VLAN Type to process correctly the protocol(s) encapsulated in the VLAN frame

    switch(ntohs(vlan_hdr->type)){

        case ETHERTYPE_HOMEPLUG:
            print_homeplug_header(buffer + sizeof(struct vlan_ieee8021q_header));
        break;

        case ETHERTYPE_HOMEPLUG_POWERLINE:
            print_homeplug_av_header(buffer + sizeof(struct vlan_ieee8021q_header));
        break;

        case ETHERTYPE_ARP:
            print_arp_header(buffer + sizeof(struct vlan_ieee8021q_header));
        break;

        case ETHERTYPE_IPV6:
            print_ip6_header(buffer, size);
        break;

        default:
            printf("\nUnknown VLAN frame !\n");
    }
}



/*********************************************** OSI LAYER 3 PROTOCOLS ***********************************************/

// process ip packet by its protocol number

void process_ip_packet(unsigned char* buffer, int size){

    //Get the IP Header part of this packet , excluding the ethernet header

    struct iphdr *iph = (struct iphdr*)(buffer + DATALINK_SIZE);

    switch (iph->protocol)
    {
        case IPV4_ICMP: 
            print_icmp_packet(buffer , size);
            break;
        
        case IPV4_IGMP: 
            print_igmp_header(buffer, size);
            break;
        
        case IPV4_TCP:
            print_tcp_packet(buffer , size);
            break;
        
        case IPV4_UDP: 
            print_udp_packet(buffer , size);
            break;

        case IPV4_EIGRP:
            printf("EIGRP Packet (TO DO)\n");
            break;

        case IPV4_SCTP:
            print_sctp_header(buffer);
            break;
        
        default:
            printf("\nUnknown IP Packet there : %x\n", iph->protocol);
            print_data(buffer, size);
    }
}


void print_arp_header(unsigned char* buffer){

    arp_header *arphdr = (arp_header*)(buffer + DATALINK_SIZE);

    printf("\nARP Header\n\n");
    printf("   |-Hardware Type      : %x\n", ntohs(arphdr->hardware_type));
    printf("   |-Protocol Type      : %x\n", ntohs(arphdr->protocol_type));
    
    printf("   |-Opcode             : %x\t", ntohs(arphdr->opcode));
    parse_arp_opcode_field(ntohs(arphdr->opcode));

    printf("\n   |-Source MAC Address : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X\n",arphdr->sender_mac[0],arphdr->sender_mac[1],arphdr->sender_mac[2],arphdr->sender_mac[3],arphdr->sender_mac[4],arphdr->sender_mac[5]);
    printf("   |-Dest MAC Address   : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X\n",arphdr->target_mac[0],arphdr->target_mac[1],arphdr->target_mac[2],arphdr->target_mac[3],arphdr->target_mac[4],arphdr->target_mac[5]);
    printf("   |-Source IP Address  : %d.%d.%d.%d\n", arphdr->sender_ip[0],arphdr->sender_ip[1],arphdr->sender_ip[2],arphdr->sender_ip[3]);
    printf("   |-Dest IP Address    : %d.%d.%d.%d\n", arphdr->target_ip[0],arphdr->target_ip[1],arphdr->target_ip[2],arphdr->target_ip[3]);

}


void print_homeplug_av_header(unsigned char* buffer){

    uint16_t type;

    homeplug_av_header* home_av_hdr = (homeplug_av_header*)(buffer + DATALINK_SIZE);

    // getting type from unsigned short
    type = ntohs(*((uint16_t*)(buffer + DATALINK_SIZE + sizeof(home_av_hdr->protocol))));

    printf("\nHomeplug AV Header\n\n");

    printf("   |-Protocol           : %x\n", home_av_hdr->protocol);
    //parse_homeplug_av_version_field(home_av_hdr->protocol);

    printf("   |-Type               : %x\t", type);
    parse_homeplug_av_type_field(type);

    printf("   |-Frag               : %x\n", home_av_hdr->frag);

}


/* Some protocols here used to manage Zeroconf (only basic network-tools) */ 

void print_homeplug_header(unsigned char* buffer){

    homeplug_header* home_hdr = (homeplug_header*)(buffer + DATALINK_SIZE);

    printf("\nHomeplug Header\n\n");

    printf("   |-Control Field    : %x\n", home_hdr->ctrl_field);
    printf("   |-MAC Entry        : %x\n", home_hdr->mac_entry);
    printf("   |-Entry Length     : %x\n", home_hdr->entry_length);
    printf("   |-Vendor Specific  : %02x%02X%02X\n", home_hdr->spe_vendor[0], home_hdr->spe_vendor[1],home_hdr->spe_vendor[2]);
}


void print_ieee_1905_header(unsigned char* buffer){

    ieee_1905_header* ieee_hdr = (ieee_1905_header*)(buffer + DATALINK_SIZE);

    printf("\nIEEE 1905.1 Header\n\n");

    printf("   |-Message version        : %x\n", ieee_hdr->msg_version);

    printf("   |-Message type           : %x\t", ntohs(ieee_hdr->msg_type));
    parse_ieee_19051a_message_type_field(ntohs(ieee_hdr->msg_type));

    printf("   |-Message ID             : %x\n", ntohs(ieee_hdr->msg_id));
    printf("   |-Frag ID                : %x\n", ieee_hdr->frag_id);
    printf("   |-Last Frag              : %x\n", ieee_hdr->last_frag);

    /* TODO : parse TLV */  
}


// Basic Dissector Function Packets for LLTD

void print_lltd_header(unsigned char* buffer){

    lltd_header* lltd_hdr = (lltd_header*)(buffer + DATALINK_SIZE);

    printf("\nLLTD Header\n\n");

    printf("   |-Version               : %x\n", lltd_hdr->version);
    printf("   |-Service Type          : %x\t", lltd_hdr->service_type);
    parse_lltd_service_type_field(lltd_hdr->service_type);

    printf("   |-Reserved              : %x\n", lltd_hdr->reserved);
    printf("   |-Function              : %x\t", lltd_hdr->function);
    parse_lltd_function_field(lltd_hdr->function);

    printf("   |-Real Dest MAC Address : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X\n",lltd_hdr->real_dest[0],lltd_hdr->real_dest[1],
        lltd_hdr->real_dest[2],lltd_hdr->real_dest[3],lltd_hdr->real_dest[4],lltd_hdr->real_dest[5]);
    printf("   |-Real Src MAC Address  : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X\n",lltd_hdr->real_src[0],lltd_hdr->real_src[1],
        lltd_hdr->real_src[2],lltd_hdr->real_src[3],lltd_hdr->real_src[4],lltd_hdr->real_src[5]);
}


void print_profinet_dcp_header(unsigned char* buffer){

    profinet_dcp_header* dcp_hdr = (profinet_dcp_header*)(buffer + DATALINK_SIZE);

    printf("\nProfinet DCP Header\n");
    printf("   |-Frame ID              : %x\n", ntohs(dcp_hdr->frame_id));
    printf("   |-Service ID            : %x\t", dcp_hdr->serv_id);
    parse_profinet_dcp_service_id_field(dcp_hdr->serv_id);
    printf("   |-Service Type          : %x\t", dcp_hdr->serv_type);
    parse_profinet_dcp_service_type_field(dcp_hdr->serv_type);
    printf("   |-Xid                   : %x\n", ntohl(dcp_hdr->xid));
    printf("   |-Option                : %x\t", dcp_hdr->option);
    parse_profinet_dcp_option_field(dcp_hdr->option);
    printf("   |-Suboption             : %x\n", dcp_hdr->sub_option);
}



void print_igmp_header(unsigned char* buffer, int size){

    
    unsigned short iphdrlen;

    struct iphdr *iph = (struct iphdr *)(buffer  + DATALINK_SIZE);
    iphdrlen = iph->ihl*4;

    struct igmp *ighdr = (struct igmp*)(buffer + DATALINK_SIZE + iphdrlen);

    printf("\n\n***********************IGMP Packet*************************\n"); 

    print_ip_header(buffer, size);

    printf("\nIGMP Header\n");

    printf("   |-Type            : %x\t", ighdr->igmp_type);
    parse_igmp_message_type_field(ighdr->igmp_type);

    printf("\n   |-Code            : %x\n", ighdr->igmp_code);
    printf("   |-Checksum        : %x\n", ntohs(ighdr->igmp_cksum));
    printf("   |-Group           : %s\n", inet_ntoa(ighdr->igmp_group));


}


// display SCTP Header

void print_sctp_header(unsigned char* buffer){

    sctp_header* sctphdr = (sctp_header*)(buffer + DATALINK_SIZE);

    printf("\nSCTP Header\n\n");
    printf("   |-Source Port    : %x\n", ntohs(sctphdr->src_port));
    printf("   |-Dest Port      : %x\n", ntohs(sctphdr->dst_port));
    printf("   |-V Tag          : %x\n", __my_swab32(sctphdr->v_tag));
    printf("   |-CRC            : %x\n", __my_swab32(sctphdr->crc));

}

/*********************************** OSI LAYER 3 PROTOCOL STRUCTS ***********************************/


void print_ip_header(unsigned char* buffer, int size __attribute__((unused))){

    struct sockaddr_in source,dest;
        
    struct iphdr *iph = (struct iphdr *)(buffer + DATALINK_SIZE);
    
    memset(&source, 0, sizeof(source));
    source.sin_addr.s_addr = iph->saddr;
    
    memset(&dest, 0, sizeof(dest));
    dest.sin_addr.s_addr = iph->daddr;
    
    printf("\nIP Header\n\n");
    printf("   |-IP Version        : %x\n", iph->version);
    printf("   |-IP Header Length  : %x DWORDS or %x Bytes\n", iph->ihl, iph->ihl*4);
    printf("   |-Type Of Service   : %x\n", iph->tos);
    printf("   |-IP Total Length   : %x  Bytes(size of Packet)\n", ntohs(iph->tot_len));
    printf("   |-Identification    : %x\n", ntohs(iph->id));
    printf("   |-Fragment Field    : %x\t%s\n", ntohs(iph->frag_off), (iph->frag_off & IP_DF) ? "Dont Frag" : "More Frag");
    printf("   |-TTL               : %x\n", iph->ttl);
    printf("   |-Protocol          : %x\n", iph->protocol);
    printf("   |-Checksum          : %x\n", ntohs(iph->check));
    printf("   |-Source IP         : %s\n", inet_ntoa(source.sin_addr));
    printf("   |-Destination IP    : %s\n", inet_ntoa(dest.sin_addr));
}

/* print ip6 header */

void print_ip6_header(unsigned char* buffer, int size __attribute__((unused))){

    char addrstr[INET6_ADDRSTRLEN];

    struct ipv6hdr* iphdr = (struct ipv6hdr*)(buffer + DATALINK_SIZE);
    int offset __attribute__((unused)) = DATALINK_SIZE + ntohs(iphdr->payload_len);

    printf("\nIPv6 Header\n\n");

    printf("   |-Version         : %x\n", iphdr->version);
    printf("   |-Priority        : %x\n", iphdr->priority);
    printf("   |-Flow label      : %02X%02X%02X\n", iphdr->flow_lbl[0], iphdr->flow_lbl[1], iphdr->flow_lbl[2]);
    printf("   |-Payload len     : %x\n", ntohs(iphdr->payload_len));
    printf("   |-Next header     : %x\n", iphdr->nexthdr);
    printf("   |-Hop limit       : %x\n", iphdr->hop_limit);

    inet_ntop(AF_INET6, &iphdr->saddr, addrstr, sizeof(addrstr));
    printf("   |-Source IP       : %s\n", addrstr);

    inet_ntop(AF_INET6, &iphdr->daddr, addrstr, sizeof(addrstr));
    printf("   |-Destination IP  : %s\n", addrstr);

    if (iphdr->nexthdr != 0){

        // parsing IPv6 protocol

        switch(iphdr->nexthdr){

            case IPV6_ICMP:
                print_icmpv6_packet(buffer, ETH2_HEADER_LEN + sizeof(struct ipv6hdr), size);
                break;

            case IPV6_TCP:
                print_tcp_packet(buffer, size);
                break;

            case IPV6_UDP:
                print_udp_packet(buffer, size);
                break;

            default:
                printf("\nUnknown IPv6 Packet there : %x\n", iphdr->nexthdr);
                print_data(buffer, size);
        }
    }

}


/* 
Dissector in progress to game etc... 
The use of ICMPv6 as NDP Protocol is not yet immplemented but , there will be a niew version
*/

void print_icmpv6_packet(unsigned char* buffer, int offset, int size){

    size_t icmp6_len;
    int header_size;


    if (*((uint8_t*)(buffer + offset)) == ICMPV6_TYPE_ROUTER_SOLICITATION){

        char target_ip[INET6_ADDRSTRLEN];

        struct icmp6_NDP_header* icmp6 = (struct icmp6_NDP_header*)(buffer + offset);
        icmp6_len = sizeof(icmp6_NDP_header);

        printf("\n\nICMPv6_NDP Header\n");

        printf("   |-Type            : %x\t", icmp6->type);
        parse_icmpv6_type_field(icmp6->type);

        printf("   |-Code            : %x\n", icmp6->code);
        printf("   |-Checksum        : %x\n", ntohs(icmp6->cksum));
        printf("   |-Subtype         : %x\n", icmp6->sub_type);
        printf("   |-Length          : %x\n", icmp6->length);

        inet_ntop(AF_INET6, &icmp6->target_ip, target_ip, sizeof(target_ip));

        printf("   |-Target IP       : %s\n", target_ip);
        printf("   |-Target MAC      : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n", icmp6->target_mac[0] , icmp6->target_mac[1] , icmp6->target_mac[2] , 
            icmp6->target_mac[3] , icmp6->target_mac[4] , icmp6->target_mac[5]);

    }

    else{

        struct icmp6_header *icmp6 = (struct icmp6_header*)(buffer + offset);
        icmp6_len = sizeof(icmp6_header);

        printf("\n\nICMPv6 Header\n");

        printf("   |-Type            : %x\t", icmp6->type);
        parse_icmpv6_type_field(icmp6->type);

        printf("   |-Code            : %x\n", icmp6->code);
        printf("   |-Checksum        : %x\n", ntohs(icmp6->cksum));

        if ((icmp6->type == ICMP6_ECHO_REQUEST) || (icmp6->type == ICMP6_ECHO_REPLY)){

            printf("   |-ICMPv6 ID       : %x\n", icmp6->data >> 16);
            printf("   |-ICMPv6 Sequence : %x\n", icmp6->data & 0x0000ffff);
        }
    }

    header_size = offset + icmp6_len;

    printf("\n");
    printf("                        DATA Dump                         ");
    printf("\n");

    printf("IPv6 Header\n");
    print_data(buffer + DATALINK_SIZE, size - offset);

    printf("ICMPv6 Header\n");
    print_data(buffer + offset, icmp6_len);
        
    printf("Data Payload\n");    
    print_data(buffer + header_size, size - header_size);
    
}


/*********************************** OSI LAYER 4 PROTOCOL STRUCTS ***********************************/


// display TCP Header

void print_tcp_packet(unsigned char* buffer, int size){
    
    struct iphdr *iph = (struct iphdr *)( buffer  + DATALINK_SIZE);

    // size of ip header
    unsigned short iphdrlen = iph->ihl * 4;
    
    struct tcphdr *tcph = (struct tcphdr*)(buffer + iphdrlen + DATALINK_SIZE);
            
    int header_size =  DATALINK_SIZE + iphdrlen + tcph->doff*4;
    
    printf("\n\n***********************TCP Packet*************************\n");  
        
    print_ip_header(buffer,size);
        
    printf("\nTCP Header\n\n");

    printf("   |-Source Port           : %x\n", ntohs(tcph->source));
    printf("   |-Destination Port      : %x\n", ntohs(tcph->dest));
    printf("   |-Sequence Number       : %x\n", __my_swab32(tcph->seq));
    printf("   |-Acknowledge Number    : %x\n", __my_swab32(tcph->ack_seq));
    printf("   |-Header Length         : %x DWORDS or %x BYTES\n" ,tcph->doff, tcph->doff*4);
    printf("   |-CWR Flag              : %x\n", __my_swab32(tcph->cwr));
    printf("   |-ECN Flag              : %x\n", __my_swab32(tcph->ece));
    printf("   |-Urgent Flag           : %x\n", tcph->urg);
    printf("   |-Acknowledgement Flag  : %x\t%s\n", tcph->ack, (tcph->ack & 0x1 ? "ACK (WARNING)" : ""));
    printf("   |-Push Flag             : %x\n", tcph->psh);
    printf("   |-Reset Flag            : %x\n", tcph->rst);
    printf("   |-Synchronise Flag      : %x\t%s\n", tcph->syn, (tcph->syn & 0x1 ? "SYN (WARNING)" : ""));
    printf("   |-Finish Flag           : %x\n", tcph->fin);
    printf("   |-Window                : %x\n", ntohs(tcph->window));
    printf("   |-Checksum              : %x\n", ntohs(tcph->check));
    printf("   |-Urgent Pointer        : %x\t%s\n", tcph->urg_ptr, (tcph->urg_ptr & 0x1 ? "URG (WARNING)" : ""));
    printf("\n");
    printf("                        DATA Dump                         ");
    printf("\n");
        
    printf("IP Header\n");
    print_data(buffer+DATALINK_SIZE, iphdrlen);
        
    printf("TCP Header\n");
    print_data(buffer + iphdrlen + DATALINK_SIZE, tcph->doff*4);
        
    printf("Data Payload\n");    
    print_data(buffer+header_size, size-header_size);
                        
}



void print_nbns_header(unsigned char* buffer){
    
    struct iphdr *iph = (struct iphdr *)(buffer + DATALINK_SIZE);

    // size of ip header
    unsigned short iphdrlen = iph->ihl * 4;
    
    struct nbns_header* nbns_hdr = (struct nbns_header*)(buffer + iphdrlen + DATALINK_SIZE + sizeof(struct udphdr));
                
    printf("\n\n***********************NBNS Packet*************************\n");  
        
    printf("\nNBNS Header\n\n");

    printf("   |-Transaction ID : %x\n", ntohs(nbns_hdr->trans_id));
    printf("   |-Response       : %x\n", nbns_hdr->response);
    printf("   |-Broadcast      : %x\n", nbns_hdr->broadcast & 0x1);
    printf("   |-Question       : %x\n", ntohs(nbns_hdr->questions)); 
    printf("   |-Answer RR      : %x\n",ntohs(nbns_hdr->answer_rr));
    printf("   |-Auth RR        : %x\n",ntohs(nbns_hdr->auth_rr));
    printf("   |-Additional RR  : %x\n",ntohs(nbns_hdr->adds_rr));

}


void print_udp_packet(unsigned char *buffer , int size){
    
    struct iphdr *iph = (struct iphdr *)(buffer + DATALINK_SIZE);

    // size of ip header
    unsigned short iphdrlen = iph->ihl * 4;
    
    struct udphdr *udph = (struct udphdr*)(buffer + iphdrlen  + DATALINK_SIZE);
    
    int header_size =  DATALINK_SIZE + iphdrlen + sizeof(struct udphdr);
    
    printf("\n\n***********************UDP Packet*************************\n");
    
    print_ip_header(buffer,size);           
    
    printf("\nUDP Header\n\n");

    printf("   |-Source Port      : %d\n" , ntohs(udph->source));
    printf("   |-Destination Port : %d\n" , ntohs(udph->dest));
    printf("   |-UDP Length       : %x\n" , ntohs(udph->len));
    printf("   |-UDP Checksum     : %x\n" , ntohs(udph->check));
    printf("\n");
    printf("                        DATA Dump                         ");
    printf("\n");

    // let's manage dns, mdns and nbns packages
    
    process_udp_encapsulation(buffer, header_size, size, ntohs(udph->dest));
    
    printf("\n");
    printf("IP Header\n");
    print_data(buffer+DATALINK_SIZE , iphdrlen);
        
    printf("UDP Header\n");
    print_data(buffer + iphdrlen + DATALINK_SIZE, sizeof(struct udphdr));
        
    printf("Data Payload\n");    
    
    //Move the pointer ahead and reduce the size of string
    print_data(buffer + header_size, size - header_size);
    
}


// function whose purpose is to manage UDP encapsulation based on packet source port

void process_udp_encapsulation(unsigned char* buffer, int offset, int size, int dest_port){


    switch(dest_port){
        
        case UDP_PORT_DEST_DNS:
            print_dns_packet(buffer);
            break;

        case UDP_PORT_DEST_NTP:
            print_ntp_packet(buffer, offset);
            break;

        case UDP_PORT_DEST_NBNS:
            print_nbns_header(buffer);
            break;

        case UDP_PORT_DEST_NETBIOS:
            print_netbios_datagram_header(buffer, offset, size);
            break;

        case UDP_PORT_DEST_MDNS:
            print_dns_packet(buffer);
            break;

        case UDP_PORT_DEST_CANON_BJNP:
            print_canon_bjnp_header(buffer, offset);
            break;

        default:
            break;

    }

}


// Displays Network Time Protocol Packet (NTP)


void print_ntp_packet(unsigned char* buffer, int offset){

    struct ntp_packet* ntpckt = (struct ntp_packet*)(buffer + offset);

    printf("\nNTP Header\n\n");

    printf("   |-Flags                  : %x\n", ntpckt->flags);
    printf("   |-Stratum:               : %x\n", ntpckt->stratum);
    printf("   |-Poll                   : %x\n", ntpckt->poll);
    printf("   |-Precision              : %x\n", ntpckt->precision);
    printf("   |-Root Delay             : %u\n", __my_swab32(ntpckt->root_delay));
    printf("   |-Root Dispersion        : %u\n", __my_swab32(ntpckt->root_dispersion));
    printf("   |-Reference ID           : %02X%02X%02X%02X\n", ntpckt->reference_id[0], ntpckt->reference_id[1], ntpckt->reference_id[2], ntpckt->reference_id[3]);
    printf("   |-Reference Timestamp    : %u.%u\n", ntpckt->ref_ts_sec, ntpckt->ref_ts_frac);
    printf("   |-Origin Timestamp       : %u.%u\n", ntpckt->origin_ts_sec, ntpckt->origin_ts_frac);
    printf("   |-Receive Timestamp      : %u.%u\n", ntpckt->recv_ts_sec, ntpckt->recv_ts_frac);
    printf("   |-Transmit Timestamp     : %u.%u\n", ntpckt->trans_ts_sec, ntpckt->trans_ts_frac);

}


/* function used to extract string field in Netbios packet because it's kinda hard to do it proprely in another way
   it's about non fixed strings with one char suffix
    - buffer    : unsigned char pointer to packet
    - offset    : int pointer standing for current offset, will be updated during the call
    - name      : char pointer that will be assignated to the string extracted
*/


int extract_netbios_datagramm_name(unsigned char* buffer, int* offset, char* name){

    // firstable, we save the base offset to compute after possible overflow troubles
    int base_offset = *offset;

    // 0x20 is the value of highest netbios suffix value + every char below are also non printable
    while(*(buffer + *offset) <= 0x20 && *offset - base_offset < NETBIOS_DATAGRAM_NAME_LENGTH)
        ++*offset;

    // finally, index will be size of netbios name
    int name_index = 0;

    // we can now iterate over consecutive printable chars = concrete netbios name without garbage prefix and suffix
    while (*(buffer + *offset) > 0x20 && name_index < NETBIOS_DATAGRAM_NAME_LENGTH){
        name[name_index] = (char)(*(buffer + *offset));
        ++*offset;
        name_index++;
    }

    // null terminated string for sure
    name[name_index] = '\0';

    // we continue to loop over non printable chars ( = Netbios suffix names)

    while(*(buffer + *offset) <= 0x20 &&  *offset - base_offset < NETBIOS_DATAGRAM_NAME_LENGTH)
        ++*offset;

    // and we have now the current offset up to date and we can return the size of netbios name string + 1 (null char added at the end)
    return ++name_index;
}


// Displays the NETBIOS Datagram Header

void print_netbios_datagram_header(unsigned char* buffer, int offset, int size){

    // the last two fields are null terminated strings with non fixed size
    char src_name[NETBIOS_DATAGRAM_NAME_LENGTH];
    char dst_name[NETBIOS_DATAGRAM_NAME_LENGTH];

    // we compute the new offset value 
    int new_offset = offset + sizeof(struct netbios_datagram_header);

    struct netbios_datagram_header* nbios_hdr = (struct netbios_datagram_header*)(buffer + offset);

    printf("\nNETBIOS DATAGRAM Header\n\n");

    printf("   |-Message Type           : %x\n" , nbios_hdr->msg_type);
    printf("   |-Flags                  : %x\n" , nbios_hdr->flags);
    printf("   |-Datagram ID            : %x\n" , ntohs(nbios_hdr->dgram_id));
    printf("   |-IP Source              : %s\n" , inet_ntoa(nbios_hdr->ip_src));
    printf("   |-Port Source            : %x\n" , ntohs(nbios_hdr->port_src));
    printf("   |-Datagram Length        : %x\n" , ntohs(nbios_hdr->dgram_len));
    printf("   |-Offset                 : %x\n" , ntohs(nbios_hdr->offset));

    // from the base header, we can get the last two fields header : source name and destination name
    // because it's two null terminated non fixed size strings

    extract_netbios_datagramm_name(buffer, &new_offset, src_name);
    printf("   |-Source Name            : %s\n" , src_name);

    extract_netbios_datagramm_name(buffer, &new_offset, dst_name);
    printf("   |-Destination Name       : %s\n" , dst_name);

    printf("\n\nSIZE OF SRC NAME : %lu\n\n", strlen(src_name));
    // now, we can display the next protocol header, SMB, based on new offset

    print_smb_header(buffer, new_offset, size);

}


// Displays the Service Message Block Header

void print_smb_header(unsigned char* buffer, int offset, int size){

    struct smb_header* smbhdr = (struct smb_header*)(buffer + offset);

    // we compute the new offset to get the new valid one after the struct
    int new_offset = offset + sizeof(struct smb_header);

    printf("\nSERVER MESSAGE BLOCK Header\n\n");

    printf("   |-Server Componant       : %x\n" , __my_swab32(smbhdr->smb_cmpt));
    printf("   |-Server Command         : %x\n" , smbhdr->smb_command);
    printf("   |-Error Class            : %x\n" , smbhdr->error_class);
    printf("   |-Error Class            : %x\n" , ntohs(smbhdr->error_code));
    printf("   |-Flags 1                : %x\n" , smbhdr->flags);
    printf("   |-Flags 2                : %x\n" , ntohs(smbhdr->flags2));
    printf("   |-Process ID High        : %x\n" , ntohs(smbhdr->process_id_high));
    printf("   |-Signature              : %x\n" , ntohl(smbhdr->signature));
    printf("   |-Tree ID                : %x\n" , ntohs(smbhdr->tree_id));
    printf("   |-Process ID             : %x\n" , ntohs(smbhdr->process_id));
    printf("   |-User ID                : %x\n" , ntohs(smbhdr->user_id));
    printf("   |-Multiplex ID           : %x\n" , ntohs(smbhdr->multiplex_id));

    // next, we parse the last part of header according to server command type field (in progress)
    // now only one value for SMB command is processed

    if (smbhdr->smb_command == SMB_COMMAND_TRANS_REQUEST){

        print_smb_command_trans_request(buffer, &new_offset); 
    }
    else{
        printf("The SMB Command %x is not yet implemented ! In Progress...\n", smbhdr->smb_command);
    }

    print_smb_mailslot_header(buffer, new_offset, size);

}


// Displays the part of SMB Header when it's Trans Command SMB packet

void print_smb_command_trans_request(unsigned char* buffer, int* offset){


    // the transaction name is the last field of SMB Header :  non fixed size string
    char transaction_name[SMB_COMMAND_TRANSACTION_NAME_LENGTH];
    int transac_name_size = 0;

    struct smb_command_trans_request* smb_trans_cmd = (struct smb_command_trans_request*)(buffer + *offset);

    // we compute the new offset value to be able to process the next steps
    int new_offset = *offset + sizeof(struct smb_command_trans_request);

    printf("\nSMB Command Trans Request\n\n");

    printf("   |-Word Count                 : %x\n" , smb_trans_cmd->word_cnt);
    printf("   |-Total Parameters           : %x\n" , __my_swab16(smb_trans_cmd->total_param));
    printf("   |-Total Data Count           : %x\n" , __my_swab16(smb_trans_cmd->total_data_cnt));
    printf("   |-Max Parameters Count       : %x\n" , ntohs(smb_trans_cmd->max_param_cnt));
    printf("   |-Max Data Count             : %x\n" , ntohs(smb_trans_cmd->max_data_cnt));
    printf("   |-Max Setup Count            : %x\n" , smb_trans_cmd->max_setup_cnt);
    printf("   |-Flags                      : %x\n" , ntohs(smb_trans_cmd->flags));
    printf("   |-Timeout                    : %x\n" , __my_swab32(smb_trans_cmd->timeout));
    printf("   |-Parameters Count           : %x\n" , ntohs(smb_trans_cmd->param_cnt));
    printf("   |-Parame Offset              : %x\n" , ntohs(smb_trans_cmd->param_offset));
    printf("   |-Data Count                 : %x\n" , ntohs(smb_trans_cmd->data_cnt));
    printf("   |-Data Offset                : %x\n" , ntohs(smb_trans_cmd->data_offset));
    printf("   |-Setup Count                : %x\n" , ntohs(smb_trans_cmd->setup_cnt));
    printf("   |-Byte Count (BCC)           : %x\n" , __my_swab16(smb_trans_cmd->byte_cnt));

    // we can extract from the SMB packet, the string field transaction name

    transac_name_size = extract_netbios_datagramm_name(buffer, &new_offset, transaction_name);

    if (transac_name_size != NETBIOS_DATAGRAM_NAME_LENGTH){

        printf("   |-Transaction Name           : %s\n" , transaction_name);

    }

}

// Displays the SMB MAILSLOT Header (allways encapsulated in Netbios packets)

void print_smb_mailslot_header(unsigned char* buffer, int offset, int size){

    // last field of maislot header, null terminated non fixed size string
    char mailslot_name[MAILSLOT_NAME_MAX_LENGTH];
    int mailslot_name_size = 0;

    struct smb_mailslot_header* smb_mslot_hdr = (struct smb_mailslot_header*)(buffer + offset);

    // we compute the new offset value for the last field : mailslot name
    int new_offset = offset + sizeof(struct smb_mailslot_header);

    printf("\nSMB MAILSLOT Header\n\n");

    printf("   |-Opcode             : %x\n", ntohs(smb_mslot_hdr->opcode));
    printf("   |-Priority           : %x\n", ntohs(smb_mslot_hdr->priority));
    printf("   |-Class              : %x\n", ntohs(smb_mslot_hdr->mclass));
    printf("   |-Size               : %x\n", ntohs(smb_mslot_hdr->size));

    mailslot_name_size = extract_netbios_datagramm_name(buffer, &new_offset, mailslot_name);
    printf("   |-Mailslot Name      : %s\n", mailslot_name);

    if (mailslot_name_size <= MAILSLOT_NAME_MAX_LENGTH + 1){

        // after printing the mailslot header, we can now display the browser packet
        print_microsoft_browser_packet(buffer, new_offset, size);

    }

}


// The top OSI Layer Porotocol based on SMB : Microsoft Browser
// this function parses the Browser Packets according to their Browser Command values
// Honestly this is one of the most ball breaker protocol : boring and tricky

void print_microsoft_browser_packet(unsigned char* buffer, int offset, int size){

    
    printf("\nMICROSOFT BROWSER Packet\n\n");

    // we need to get the command value before processing packet
    uint8_t browser_command = *((uint8_t*)(buffer + offset));

    // for these command values, the packet struct is the same
    if (browser_command == BROWSER_COMMAND_HOST_ANNOUNCEMENT || browser_command == BROWSER_COMMAND_LOCAL_MASTER_ANNOUNCEMENT ||
        browser_command == BROWSER_COMMAND_WORKGROUP_ANNOUNCEMENT){

        print_browser_announcement_packet(buffer, offset, size);

    }
    else if (browser_command == BROWSER_COMMAND_ELECTION_REQUEST){

        print_browser_election_request_packet(buffer, offset, size);

    }

    else{

        printf("The Browser Command %x is not yet implemented ! In Progress...\n", browser_command);        

    }

}

// The top OSI Layer Porotocol based on SMB : Microsoft Browser
// Here a particular type of Browser packet is processed : Browser Announcement Packet

void print_browser_announcement_packet(unsigned char* buffer, int offset, int size){

    // we compute the new offset value for the last field : host comment, non fixed size string 
    int new_offset = offset + sizeof(struct browser_announcement_packet);

    struct browser_announcement_packet* announ_pkt = (struct browser_announcement_packet*)(buffer + offset);

    printf("   |-Command                    : %x\n" , announ_pkt->command);
    printf("   |-Update Count               : %x\n" , announ_pkt->update_cnt);
    printf("   |-Update Period              : %x\n" , ntohl(announ_pkt->update_period));
    printf("   |-Host Name                  : %s\n" , announ_pkt->host_name);
    printf("   |-Windows Version            : %x\n" , ntohs(announ_pkt->windows_ver));
    printf("   |-OS Major Version           : %x\n" , announ_pkt->os_maj_version);
    printf("   |-OS Minor Version           : %x\n" , announ_pkt->os_min_version);
    printf("   |-Server Type                : %x\n" , ntohl(announ_pkt->server_type));
    printf("   |-Browser Major Version      : %x\n" , announ_pkt->os_maj_version);
    printf("   |-Browser Minor Version      : %x\n" , announ_pkt->os_min_version);
    printf("   |-Signature                  : %x\n" , ntohs(announ_pkt->os_min_version));

    printf("   |-Host Comment               : ");
    fwrite(buffer + new_offset, sizeof(char), size - new_offset, stdout);
    printf("\n");

}

// The top OSI Layer Porotocol based on SMB : Microsoft Browser
// Here a particular type of Browser packet is processed : Browser Election Request Packet

void print_browser_election_request_packet(unsigned char* buffer, int offset, int size){

    // we compute the new offset value for the last field : host comment, non fixed size string 
    int new_offset = offset + sizeof(struct browser_election_request_packet);

    struct browser_election_request_packet* elect_packet = (struct browser_election_request_packet*)(buffer + offset);

    printf("   |-Command                    : %x\n" , elect_packet->command);
    printf("   |-Election Version           : %x\n" , elect_packet->election_ver);
    printf("   |-Election Desire            : %x\n" , elect_packet->election_desire);
    printf("   |-Browser Major Version      : %x\n" , elect_packet->browser_maj_ver);
    printf("   |-Browser Minor Version      : %x\n" , elect_packet->browser_min_ver);
    printf("   |-Election OS                : %x\n" , elect_packet->election_os);

    printf("   |-Server Name                : ");
    fwrite(buffer + new_offset, sizeof(char), size - new_offset, stdout);
    printf("\n");

}


// Displays BJNP Protocol Header (a custom protocol by Canon and a preferential choice to exploit)

void print_canon_bjnp_header(unsigned char* buffer, int offset){


    struct canon_bjnp_header* bjnp_hdr = (struct canon_bjnp_header*)(buffer + offset);

    printf("\nCANON BJNP Header\n\n");

    printf("   |-ID                 : %x\n", ntohl(bjnp_hdr->id));
    printf("   |-Type               : %x\n", bjnp_hdr->type);
    printf("   |-Code               : %x\n", bjnp_hdr->code);
    printf("   |-Sequence Number    : %x\n", ntohl(bjnp_hdr->seq_nbr));
    printf("   |-Session ID         : %x\n", ntohs(bjnp_hdr->session_id));
    printf("   |-Payload Length     : %x\n", ntohl(bjnp_hdr->payload_len));

}


// Displays LLMNR Protocol Header

void print_llmnr_header(unsigned char* buffer, int offset){

    struct llmnr_header* llmnr_hdr = (struct llmnr_header*)(buffer + offset);

    printf("\nLLMNR Header\n\n");

    printf("   |-Transaction ID         : %x\n" , ntohs(llmnr_hdr->trans_id));
    printf("   |-Flags                  : %x\n" , ntohs(llmnr_hdr->flags));
    printf("   |-Question               : %x\n" , ntohs(llmnr_hdr->question));
    printf("   |-Answer RR              : %x\n" , ntohs(llmnr_hdr->answer_rr));
    printf("   |-Authority RR           : %x\n" , ntohs(llmnr_hdr->auth_rr));
    printf("   |-Additionnal RR         : %x\n" , ntohs(llmnr_hdr->adds_rr));

}


void print_icmp_packet(unsigned char* buffer , int size){
    
    struct iphdr *iph = (struct iphdr *)(buffer + DATALINK_SIZE);
    
    // size of ip header
    unsigned short iphdrlen = iph->ihl * 4;

    struct icmp_header *icmph = (struct icmp_header *)(buffer + iphdrlen + DATALINK_SIZE);
    
    int header_size =  sizeof(struct ethhdr) + iphdrlen + sizeof(icmph);
    
    printf("\n***********************ICMP Packet*************************\n"); 
    
    print_ip_header(buffer , size);
        
    printf("\n\nICMP Header\n");
    printf("   |-Type :          : %x\t", icmph->type);
    parse_icmp_type_field(icmph->type);
    printf("   |-Code            : %x\n", icmph->code);
    printf("   |-Checksum        : %x\n", ntohs(icmph->checksum));
    printf("   |-ID              : %x\n", ntohs(icmph->un.echo.id));
    printf("   |-Sequence        : %x\n", ntohs(icmph->un.echo.sequence));
    printf("   |-Gateway         : %x\n", icmph->un.gateway);
    printf("   |-Mysterious      : %x\n", ntohs(icmph->un.frag.__unused));
    printf("\n");
    printf("                        DATA Dump                         ");
    printf("\n");

    printf("IP Header\n");
    print_data(buffer,iphdrlen);
        
    printf("UDP Header\n");
    print_data(buffer + iphdrlen , sizeof(icmph));
        
    printf("Data Payload\n");    
    print_data(buffer + header_size, size - header_size);

}


void print_dns_packet(unsigned char* buffer){
    
    struct iphdr *iph = (struct iphdr *)(buffer  + DATALINK_SIZE);

    // size of ip header
    unsigned short iphdrlen = iph->ihl * 4;
    
    struct dns_header *dndh = (struct dns_header*)(buffer + iphdrlen + DATALINK_SIZE + sizeof(struct udphdr));
        
    printf("\nDNS Header\n\n");

    // dissecting the opcode field
    printf("   |-Opcode         : %x\t",dndh->opcode);
    parse_dns_opcode_field(dndh->opcode);

    // same for the rcode
    printf("   |-R code         : %x\t",dndh->rcode);
    parse_dns_rcode_field(dndh->rcode);

    printf("   |-Q count        : %x\n", ntohs(dndh->q_count));
    printf("   |-Answer         : %x\n", ntohs(dndh->ans_count));
    printf("   |-Auth count     : %x\n", ntohs(dndh->auth_count));
    printf("   |-Additional     : %x\n", ntohs(dndh->add_count));

}


/* 
This function is usefull to display all interfaces available on the pc
[In Progress] : New registered (and so existing values), will be add soon
If the verbose_mode variable is set, the function displayq device flags as plein text for each device
An Update will come soon to allow PCI devices discover too and a D-Bus monitor will be implemented
*/

int print_devices_list(uint8_t verbose_mode){

    pcap_if_t *first_if;
    pcap_if_t *cur_if;
    char* plein_text_flags;
    
    char errbuf[PCAP_ERRBUF_SIZE];

    if (pcap_findalldevs(&first_if, errbuf) < 0){

        fprintf(stderr, "ERROR pcap_findalldevs init error: %s\n", errbuf);
        return -1;
    }
    

    for (cur_if = first_if ; cur_if ; cur_if = cur_if->next){

        printf("Name : %s\t| Description : %s\t| Flags : %x\n", cur_if->name, cur_if->description, cur_if->flags);
        
		// if thr verbose mode is set ip, the function displays flags as plein text

        if (verbose_mode){

            plein_text_flags = get_readable_device_flags(cur_if->flags);

            if (plein_text_flags == NULL){
                fprintf(stderr, "ERROR : Couldn't display the device flags as plein text\n");
                pcap_freealldevs(first_if);
                return -1;                
            }

            else{
                printf("Flags : %s\n", plein_text_flags);
            }

            free(plein_text_flags);
        }
    }  

    pcap_freealldevs(first_if);

    return 0;

}


/*
function that that takes in input an uint32_t as flags, and return from raw flags a plein text flags
return NULL if an error occured or a char pointer to the string
*/

char* get_readable_device_flags(int device_flags){

    const char* flags[] = {"LOOPBACK, ", "UP, ", "RUNNING, ", "WIRELESS, ", "STATUS_CONNECTED, ""STATUS_NOT_AVAILABLE, ",
			   "STATUS_UNKNOWN, ", "STATUS_NOT_APPLICABLE, "};

    int index = 0;
    char* readable_flags = malloc(sizeof(char) * READABLE_DEVICE_FLAGS_LENGTH);
    
    // malloc() fail ? return the NULL pointer

    if (readable_flags == NULL){
        fprintf(stderr, "ERROR : Memmory allocation failed for the device flags. Please retry with Valgrind\n");
        return readable_flags;
    }
    
    //  Let's check the status of the device 

	if ((device_flags & PCAP_IF_CONNECTION_STATUS_CONNECTED) != 0){
        memcpy(readable_flags + index, flags[5], strlen(flags[5]));
        index += strlen(flags[5]);
    }

    else { 
        memcpy(readable_flags + index, flags[6], strlen(flags[6]));
        index += strlen(flags[6]);
    }
    
    // applying all flags to  build a string instead of bitmasks

    if ((device_flags & PCAP_IF_LOOPBACK) != 0){
        memcpy(readable_flags, flags[0], strlen(flags[0]));
        index += strlen(flags[0]);
    }

    if ((device_flags & PCAP_IF_UP) != 0){
        memcpy(readable_flags + index, flags[1], strlen(flags[1]));
        index += strlen(flags[1]);
    }

    if ((device_flags & PCAP_IF_RUNNING) != 0){
        memcpy(readable_flags + index, flags[2], strlen(flags[2]));
        index += strlen(flags[2]);
    }

    if ((device_flags & PCAP_IF_WIRELESS) != 0){
        memcpy(readable_flags + index, flags[3], strlen(flags[3]));
        index += strlen(flags[3]);
    }

    *(readable_flags + index - 2) = '\0';

    return readable_flags;

}


/* 
selecting the first device available on the machine (used only if no device was provided
return  value : -1 in failure (no device available) or 0 if success
*/

int get_random_device(char* device){

    pcap_if_t *first_if;
    char errbuf[PCAP_ERRBUF_SIZE];

    if (pcap_findalldevs(&first_if, errbuf) < 0) {

        fprintf(stderr, "ERROR : pcap_findalldevs couldn't find any device: %s\n", errbuf);
        return -1;
    }

    strncpy(device, first_if->name, IFNAMSIZ -1);

    pcap_freealldevs(first_if);

    return 0;
}


/* print raw data in ASCII and hex values */

void print_data(unsigned char* data , int size){

    int i , j;
    for(i=0 ; i < size ; i++)
    {
        if( i!=0 && i%16==0)   //if one line of hex printing is complete...
        {
            printf("         ");
            for(j=i-16 ; j<i ; j++)
            {
                if(data[j]>=32 && data[j]<=127)
                    printf("%c",(unsigned char)data[j]); //if its a number or alphabet
                               else printf("."); //otherwise print a dot
            }
            printf("\n");
        }               if(i%16==0) printf("   ");
            printf(" %02X",(unsigned int)data[i]);
                       if( i==size-1)  //print the last spaces
        {
            for(j=0;j<15-i%16;j++){
              printf("   "); //extra spaces
            }
                       printf("         ");
                       for(j=i-i%16 ; j<=i ; j++)
            {
                if(data[j]>=32 && data[j]<=127){
                    printf("%c",(unsigned char)data[j]);
                }
                else                {
                  printf(".");
                }
            }
        printf( "\n" );
        }
    }
}

/* 
printing current timestamp + number for each frame to get the most infos as possible
Usefull for post-traitment with AWK, Perl or Python
*/

void print_info_packet(unsigned int num_pckt){

    time_t now = time(NULL);
    struct tm*tm_struct = localtime(&now);
    printf("\n+ LOCAL TIME [%02d:%02d:%02d] | PACKET NBR : [%u]\n", tm_struct->tm_hour,
        tm_struct->tm_min , tm_struct->tm_sec, num_pckt);

}


/*
Printing a buffer of bytes from specified offset
Usefull th extract non fixed size strings in the middle of of payload
*/

void print_char_to_hex(unsigned char* buffer, int offset, int size){

    int i = offset;

    while(i < size){

        // insert a line feed every 32 bytes to get a cleaner display
        if (i % 32 == 0)
            printf("\n");

        printf("%02X", *(buffer + i));
        ++i;
    }

    printf("\n");
}
