#include "sock_utils.h"
#include "parsing.h"

/************************************* IN PROGRESS *************************************/

// checksum function, non implemented yet

uint16_t in_cksum(uint16_t *addr, int len){

    int nleft = len;
    uint32_t sum = 0;
    uint16_t *w = addr;
    uint16_t answer = 0;

    // Adding 16 bits sequentially in sum
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

// processing frame by ethertype

void process_frame(unsigned char* buffer, int size){

    struct ethhdr *eth = (struct ethhdr *)buffer;
    uint16_t proto = ntohs(eth->h_proto);

    switch(proto){

        case ETHERTYPE_ARP:
            printf("\nARP frame there!\n");
            print_ethernet_header(buffer, size);
            print_arp_header(buffer);
            break;

        case ETHERTYPE_IEEE1905_1:
            printf("\nETHERTYPE_IEEE1905_1 frame there!\n");
            print_ethernet_header(buffer , size);
            print_ieee_1905_header(buffer, size);
            break;

        case ETHERTYPE_HOMEPLUG:
            printf("\nETHERTYPE_HOMEPLUG frame there!\n");
            print_ethernet_header(buffer , size);
            print_homeplug_header(buffer);
            break;

        case ETHERTYPE_HOMEPLUG_POWERLINE:
            printf("\nETHERTYPE_HOMEPLUG_POWERLINE frame there!\n");
            print_ethernet_header(buffer , size);
            print_homeplug_av_header(buffer);
            break;

        case ETHERTYPE_LLDT:
            printf("\nLLDT frame there!\n");
            print_ethernet_header(buffer, size);
            print_lltd_header(buffer);
            break;

        case ETHERTYPE_PROFINET_DCP:
            printf("\nPROFINET_DCP frame there!\n");
            print_ethernet_header(buffer, size);
            print_profinet_dcp_header(buffer);
            break;

        case ETHERTYPE_IP:
            printf("\nIP frame there!\n");
            process_ip_packet(buffer, size);
            break;

        case ETHERTYPE_IPV6:
            printf("\nIPv6 frame there!\n");
            print_ip6_header(buffer, size);
            break;

        default:
            printf("\n********* UNKNOWN frame there! **********\n");
            print_ethernet_header(buffer , size);
    }
}

// process ip packet by its protocol number

void process_ip_packet(unsigned char* buffer, int size){

    //Get the IP Header part of this packet , excluding the ethernet header

    struct iphdr *iph = (struct iphdr*)(buffer + ETH2_HEADER_LEN);

    switch (iph->protocol)
    {
        case 1:  //ICMP Protocol
            print_icmp_packet(buffer , size);
            break;
        
        case 2:  //IGMP Protocol
            print_igmp_header(buffer, size);
            break;
        
        case 6:  //TCP Protocol
            print_tcp_packet(buffer , size);
            break;
        
        case 17: //UDP Protocol
            print_udp_packet(buffer , size);
            break;
        
        default: //Some Other Protocol like ARP etc.
            printf("\nUnknown IP Packet there : %x\n", iph->protocol);
            print_data(buffer, size);
    }
}

void print_ethernet_header(unsigned char* buffer, int size){

    struct ethhdr *eth = (struct ethhdr *)buffer;
    
    printf("\nEthernet Header\n\n");
    printf("   |-Destination Address : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n", eth->h_dest[0] , eth->h_dest[1] , eth->h_dest[2] , eth->h_dest[3] , eth->h_dest[4] , eth->h_dest[5] );
    printf("   |-Source Address      : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n", eth->h_source[0] , eth->h_source[1] , eth->h_source[2] , eth->h_source[3] , eth->h_source[4] , eth->h_source[5] );
    printf("   |-Protocol            : %x\n", ntohs(eth->h_proto));
}

void print_arp_header(unsigned char* buffer){

    arp_header *arphdr = (arp_header*)(buffer + ETH2_HEADER_LEN);

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

    homeplug_av_header* home_av_hdr = (homeplug_av_header*)(buffer + ETH2_HEADER_LEN);

    printf("\nHomeplug AV Header\n");
    printf("   |-Protocol  : %x\n", home_av_hdr->protocol);
    printf("   |-Type      : %x\t\n", htons(home_av_hdr->type));
        if (htons(home_av_hdr->type) == HOMEPLUG_AV_REQ_BRIDGE)
        printf("\t(Get Bridge Information Request)\n");
    else
        printf("(Unknown Type)\n");
    printf("   |-Frag     : %x\n", home_av_hdr->frag);

}

void print_homeplug_header(unsigned char* buffer){

    homeplug_header* home_hdr = (homeplug_header*)(buffer + ETH2_HEADER_LEN);

    printf("\nHomeplug Header\n\n");
    printf("   |-Control Field    : %x\n", home_hdr->ctrl_field);
    printf("   |-MAC Entry        : %x\n", home_hdr->mac_entry);
    printf("   |-Entry Length     : %x\n", home_hdr->entry_length);
    printf("   |-Vendor Specific  : %02x%02X%02X\n", home_hdr->spe_vendor[0], home_hdr->spe_vendor[1],home_hdr->spe_vendor[2]);
}

void print_ieee_1905_header(unsigned char* buffer, int size){

    ieee_1905_header* ieee_hdr = (ieee_1905_header*)(buffer + ETH2_HEADER_LEN);

    printf("\nIEEE 1905.1 Header\n\n");
    printf("   |-Message version    : %x\n", ieee_hdr->msg_version);
    printf("   |-Message type       : %x\n", ntohs(ieee_hdr->msg_type));
    printf("   |-Message ID         : %x\n", ntohs(ieee_hdr->msg_id));

    /* TODO : parse TLV */  
}

void print_lltd_header(unsigned char* buffer){

    lltd_header* lltd_hdr = (lltd_header*)(buffer + ETH2_HEADER_LEN);

    printf("\nLLTD Header\n");
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

    profinet_dcp_header* dcp_hdr = (profinet_dcp_header*)(buffer + ETH2_HEADER_LEN);

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
    struct iphdr *iph = (struct iphdr *)(buffer  + ETH2_HEADER_LEN);
    iphdrlen = iph->ihl*4;

    struct igmp *ighdr = (struct igmp*)(buffer + ETH2_HEADER_LEN + iphdrlen);

    printf("\n\n***********************IGMP Packet*************************\n"); 

    print_ip_header(buffer,size);

    printf("\nIGMP Header\n");

    printf("   |-Type      : %x\t\n", ighdr->igmp_type);
    parse_igmp_message_type_field(ighdr->igmp_type);

    printf("\n   |-Code      : %x\n", ighdr->igmp_code);
    printf("   |-Checksum  : %x\n", ntohs(ighdr->igmp_cksum));
    printf("   |-Group     : %x\n", inet_ntoa(ighdr->igmp_group));

    printf("\n###########################################################\n");

}

void print_ip_header(unsigned char* buffer, int size){

    struct sockaddr_in source,dest;

    print_ethernet_header(buffer , size);
  
    unsigned short iphdrlen;
        
    struct iphdr *iph = (struct iphdr *)(buffer + ETH2_HEADER_LEN);
    iphdrlen =iph->ihl*4;
    
    memset(&source, 0, sizeof(source));
    source.sin_addr.s_addr = iph->saddr;
    
    memset(&dest, 0, sizeof(dest));
    dest.sin_addr.s_addr = iph->daddr;
    
    printf("\nIP Header\n");
    printf("   |-IP Version        : %d\n",(unsigned int)iph->version);
    printf("   |-IP Header Length  : %d DWORDS or %d Bytes\n",(unsigned int)iph->ihl,((unsigned int)(iph->ihl))*4);
    printf("   |-Type Of Service   : %d\n",(unsigned int)iph->tos);
    printf("   |-IP Total Length   : %d  Bytes(size of Packet)\n",ntohs(iph->tot_len));
    printf("   |-Identification    : %d\n",ntohs(iph->id));
    //printf("   |-Reserved ZERO Field   : %d\n",(unsigned int)iphdr->ip_reserved_zero);
    //printf("   |-Dont Fragment Field   : %d\n",(unsigned int)iphdr->ip_dont_fragment);
    //printf("   |-More Fragment Field   : %d\n",(unsigned int)iphdr->ip_more_fragment);
    printf("   |-TTL               : %d\n",(unsigned int)iph->ttl);
    printf("   |-Protocol          : %d\n",(unsigned int)iph->protocol);
    printf("   |-Checksum          : %d\n",ntohs(iph->check));
    printf("   |-Source IP         : %s\n",inet_ntoa(source.sin_addr));
    printf("   |-Destination IP    : %s\n",inet_ntoa(dest.sin_addr));
}

/* print ip6 header */

void print_ip6_header(unsigned char* buffer, int size){

    char addrstr[INET6_ADDRSTRLEN];

    struct ipv6hdr* iphdr = (struct ipv6hdr*)buffer;
    int offset = ETH2_HEADER_LEN + ntohs(iphdr->payload_len);

    print_ethernet_header(buffer , size);

    printf("\nIPv6 Header\n");

    printf("   |-Version         : %x\n", iphdr->version);
    printf("   |-Priority        : %x\n", iphdr->priority);
    printf("   |-Flow label      : %02X%02X%02X\n", iphdr->flow_lbl[0], iphdr->flow_lbl[1], iphdr->flow_lbl[2]);
    printf("   |-Payload len     : %x\n", ntohs(iphdr->payload_len));
    printf("   |-Next header     : %x\n", iphdr->nexthdr);
    printf("   |-Hop limit       : %x\n", iphdr->hop_limit);

    inet_ntop(AF_INET6, &iphdr->saddr, addrstr, sizeof(addrstr));
    printf("   |-Source IP      : %s\n", addrstr);

    inet_ntop(AF_INET6, &iphdr->daddr, addrstr, sizeof(addrstr));
    printf("   |-Destination IP : %s\n", addrstr);

    if (iphdr->nexthdr == IPV6_ICMP){
        print_icmpv6_packet(buffer, offset, size);
    }

}

void print_tcp_packet(unsigned char* buffer, int size){
    
    struct iphdr *iph = (struct iphdr *)( buffer  + ETH2_HEADER_LEN);

    // size of ip header
    unsigned short iphdrlen = iph->ihl * 4;
    
    struct tcphdr *tcph = (struct tcphdr*)(buffer + iphdrlen + ETH2_HEADER_LEN);
            
    int header_size =  sizeof(struct ethhdr) + iphdrlen + tcph->doff*4;
    
    printf("\n\n***********************TCP Packet*************************\n");  
        
    print_ip_header(buffer,size);
        
    printf("\nTCP Header\n");
    printf("   |-Source Port           : %d\n",ntohs(tcph->source));
    printf("   |-Destination Port      : %d\n",ntohs(tcph->dest));
    printf("   |-Sequence Number       : %d\n",ntohl(tcph->seq));
    printf("   |-Acknowledge Number    : %d\n",ntohl(tcph->ack_seq));
    printf("   |-Header Length         : %d DWORDS or %d BYTES\n" ,(unsigned int)tcph->doff,(unsigned int)tcph->doff*4);
    //printf("   |-CWR Flag : %d\n",(unsigned int)tcph->cwr);
    //printf("   |-ECN Flag : %d\n",(unsigned int)tcph->ece);
    printf("   |-Urgent Flag           : %d\n",(unsigned int)tcph->urg);
    printf("   |-Acknowledgement Flag  : %d\n",(unsigned int)tcph->ack);
    printf("   |-Push Flag             : %d\n",(unsigned int)tcph->psh);
    printf("   |-Reset Flag            : %d\n",(unsigned int)tcph->rst);
    printf("   |-Synchronise Flag      : %d\n",(unsigned int)tcph->syn);
    printf("   |-Finish Flag           : %d\n",(unsigned int)tcph->fin);
    printf("   |-Window                : %d\n",ntohs(tcph->window));
    printf("   |-Checksum              : %d\n",ntohs(tcph->check));
    printf("   |-Urgent Pointer        : %d\n",tcph->urg_ptr);
    printf("\n");
    printf("                        DATA Dump                         ");
    printf("\n");
        
    printf("IP Header\n");
    print_data(buffer+ETH2_HEADER_LEN,iphdrlen);
        
    printf("TCP Header\n");
    print_data(buffer+iphdrlen,tcph->doff*4);
        
    printf("Data Payload\n");    
    print_data(buffer+header_size, size-header_size);
                        
    printf("\n###########################################################\n");
}

void print_dns_packet(unsigned char* buffer, int size){
    
    struct iphdr *iph = (struct iphdr *)( buffer  + ETH2_HEADER_LEN);

    // size of ip header
    unsigned short iphdrlen = iph->ihl * 4;
    
    dns_header *dndh = (dns_header*)(buffer + iphdrlen + ETH2_HEADER_LEN + sizeof(struct udphdr));
            
    int header_size =  sizeof(struct udphdr) + sizeof(struct ethhdr) + iphdrlen;
    
    printf("\n\n***********************DNS Packet*************************\n");  
        
    printf("\nDNS Header\n\n");

    if (dndh->qr)
        printf("   |-DNS query type\n");
    else
        printf("   |-DNS response type\n");

    printf("   |-Opcode         : %x\n",dndh->opcode);
    printf("   |-R code         : %x\n",dndh->rcode);
    printf("   |-Q count        : %x\n",ntohs(dndh->q_count)); 
    printf("   |-Answer         : %x\n",ntohs(dndh->ans_count));
    printf("   |-Auth count     : %x\n",ntohs(dndh->auth_count));
    printf("   |-Additional     : %x\n",ntohs(dndh->add_count));

    printf("\n###########################################################\n");
}

void print_nbns_header(unsigned char* buffer, int size){
    
    struct iphdr *iph = (struct iphdr *)(buffer  + ETH2_HEADER_LEN);

    // size of ip header
    unsigned short iphdrlen = iph->ihl * 4;
    
    nbns_header* nbns_hdr = (nbns_header*)(buffer + iphdrlen + ETH2_HEADER_LEN + sizeof(struct udphdr));
            
    int header_size =  sizeof(struct udphdr) + sizeof(struct ethhdr) + iphdrlen;
    
    printf("\n\n***********************NBNS Packet*************************\n");  
        
    printf("\nNBNS Header\n\n");

    printf("   |-Transaction ID : %x\n", ntohs(nbns_hdr->trans_id));
    printf("   |-Response       : %x\n", nbns_hdr->response);
    printf("   |-Broadcast      : %x\n", nbns_hdr->broadcast);
    printf("   |-Question       : %x\n", ntohs(nbns_hdr->questions)); 
    printf("   |-Answer RR      : %x\n",ntohs(nbns_hdr->answer_rr));
    printf("   |-Auth RR        : %x\n",ntohs(nbns_hdr->auth_rr));
    printf("   |-Additional RR  : %x\n",ntohs(nbns_hdr->adds_rr));

    printf("\n###########################################################\n");
}

void print_udp_packet(unsigned char *buffer , int size){
    
    struct iphdr *iph = (struct iphdr *)(buffer +  ETH2_HEADER_LEN);

    // size of ip header
    unsigned short iphdrlen = iph->ihl * 4;
    
    struct udphdr *udph = (struct udphdr*)(buffer + iphdrlen  + ETH2_HEADER_LEN);
    
    int header_size =  sizeof(struct ethhdr) + iphdrlen + sizeof(udph);
    
    printf("\n\n***********************UDP Packet*************************\n");
    
    print_ip_header(buffer,size);           
    
    printf("\nUDP Header\n");
    printf("   |-Source Port      : %d\n" , ntohs(udph->source));
    printf("   |-Destination Port : %d\n" , ntohs(udph->dest));
    printf("   |-UDP Length       : %d\n" , ntohs(udph->len));
    printf("   |-UDP Checksum     : %d\n" , ntohs(udph->check));
    printf("\n");
    printf("                        DATA Dump                         ");
    printf("\n");

    // let's manage dns, mdns and nbns packages
    
    if (ntohs(udph->source) == DNS_PORT || ntohs(udph->source) == MDNS_PORT) 
        print_dns_packet(buffer, size);
    else if(ntohs(udph->source) == NBNS_PORT)
        print_nbns_header(buffer, size);
    
    printf("\n");
    printf("IP Header\n");
    print_data(buffer+ETH2_HEADER_LEN , iphdrlen);
        
    printf("UDP Header\n");
    print_data(buffer+iphdrlen, sizeof(udph));
        
    printf("Data Payload\n");    
    
    //Move the pointer ahead and reduce the size of string
    print_data(buffer+header_size, size-header_size);
    
    printf("\n###########################################################\n");
}

void print_icmp_packet(unsigned char* buffer , int size){
    
    struct iphdr *iph = (struct iphdr *)(buffer + ETH2_HEADER_LEN);
    
    // size of ip header
    unsigned short iphdrlen = iph->ihl * 4;

    struct icmp_header *icmph = (struct icmp_header *)(buffer + iphdrlen + ETH2_HEADER_LEN);
    
    int header_size =  sizeof(struct ethhdr) + iphdrlen + sizeof(icmph);
    
    printf("\n***********************ICMP Packet*************************\n"); 
    
    print_ip_header(buffer , size);
        
    printf("\n\nICMP Header\n");
    printf("   |-Type :          : %x\t", icmph->type);
            
    if(icmph->type == 11){
        printf("(TTL Expired)\n");
    }
    else if(icmph->type == ICMP_ECHOREPLY){
        printf("(ICMP Echo Reply)\n");
    }
    
    printf("   |-Code          : %x\n", icmph->code);
    printf("   |-Checksum      : %x\n", ntohs(icmph->checksum));
    printf("   |-ID            : %x\n", ntohs(icmph->un.echo.id));
    printf("   |-Sequence      : %x\n", ntohs(icmph->un.echo.sequence));
    printf("   |-Gateway       : %lu\n", icmph->un.gateway);
    printf("   |-Mysterious    : %x\n", ntohs(icmph->un.frag.__unused));
    printf("\n");
    printf("                        DATA Dump                         ");
    printf("\n");

    printf("IP Header\n");
    print_data(buffer,iphdrlen);
        
    printf("UDP Header\n");
    print_data(buffer + iphdrlen , sizeof(icmph));
        
    printf("Data Payload\n");    
    
    print_data(buffer + header_size, size-header_size);
    
    printf("\n###########################################################\n");
}

/* print icmp6 packet */

void print_icmpv6_packet(unsigned char* buffer, int offset, int size){

    icmp6_header *icmp6 = (icmp6_header*)(buffer + offset);
    int header_size = offset + sizeof(icmp6);

    printf("\n\nICMPv6 Header\n");
    printf("   |-Type            : %x\n", icmp6->type);
    printf("   |-Code            : %x\n", icmp6->code);
    printf("   |-Checksum        : %x\n", icmp6->cksum);

    if ((icmp6->type == ICMP6_ECHO_REQUEST) || (icmp6->type == ICMP6_ECHO_REPLY)){

        printf("   |-ICMPv6 ID      : %x\n", icmp6->data >> 16);
        printf("   |-ICMPv6 Sequence : %x\n", icmp6->data & 0x0000ffff);
    }

    printf("\n");
    printf("                        DATA Dump                         ");
    printf("\n");

    printf("IPv6 Header\n");
    print_data(buffer + ETH2_HEADER_LEN, size - offset);

    printf("ICMPv6 Header\n");
    print_data(buffer + offset, sizeof(icmp6));
        
    printf("Data Payload\n");    
    print_data(buffer + header_size, size - header_size);
    
    printf("\n###########################################################\n");
}


// just a function to print interfaces list 

void print_itf_list(){

    pcap_if_t *first_if;
    char errbuf[PCAP_ERRBUF_SIZE];

    if (pcap_findalldevs(&first_if, errbuf) < 0) {
        fprintf(stderr, "pcap_findalldevs: %s\n", errbuf);
        exit(EXIT_FAILURE);
    }

    pcap_if_t *cur_if;
    for (cur_if = first_if ; cur_if ; cur_if = cur_if->next){
        printf("name = %s\t, description= %s\t, flags= %x\n", cur_if->name, cur_if->description, cur_if->flags);
    }  

    pcap_freealldevs(first_if);

}

// print raw data in ASCII and hex values 

void print_data(unsigned char* data , int size){

    int i , j;
    for(i=0 ; i < size ; i++)
    {
        if( i!=0 && i%16==0)   //if one line of hex printing is complete...
        {
            printf("         ");
            for(j=i-16 ; j<i ; j++)
            {
                if(data[j]>=32 && data[j]<=128)
                    printf("%c",(unsigned char)data[j]); //if its a number or alphabet
                
                else printf("."); //otherwise print a dot
            }
            printf("\n");
        } 
        
        if(i%16==0) printf("   ");
            printf(" %02X",(unsigned int)data[i]);
                
        if( i==size-1)  //print the last spaces
        {
            for(j=0;j<15-i%16;j++) 
            {
              printf("   "); //extra spaces
            }
            
            printf("         ");
            
            for(j=i-i%16 ; j<=i ; j++)
            {
                if(data[j]>=32 && data[j]<=128) 
                {
                    printf("%c",(unsigned char)data[j]);
                }
                else 
                {
                  printf(".");
                }
            }
            
            printf( "\n" );
        }
    }
}

void print_hex_ascii_line(const u_char *payload, int len, int offset){

    int i;
    int gap;
    const u_char *ch;

    /* offset */
    printf("%05d   ", offset);

    /* hex */
    ch = payload;
    for(i = 0; i < len; i++) {
        printf("%02x ", *ch);
        ch++;
        /* print extra space after 8th byte for visual aid */
        if (i == 7)
            printf(" ");
    }
    /* print space to handle line less than 8 bytes */
    if (len < 8)
        printf(" ");

    /* fill hex gap with spaces if not full line */
    if (len < 16) {
        gap = 16 - len;
        for (i = 0; i < gap; i++) {
            printf("   ");
        }
    }
    
    printf("   ");

    /* ascii (if printable) */
    ch = payload;
    for(i = 0; i < len; i++) {
        if (isprint(*ch))
            printf("%c", *ch);
        else
            printf(".");
        ch++;
    }

    printf("\n");

}

// print current time of the capture for each frame

void print_current_time(){

    time_t now = time(NULL);
    struct tm *tm_struct = localtime(&now);
    printf("\n[LOCAL TIME %02d:%02d:%02d]", tm_struct->tm_hour , tm_struct->tm_min , tm_struct->tm_sec);

}
