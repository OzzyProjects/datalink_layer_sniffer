##include "sock_utils.h"
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

        case ETHERTYPE_IP:
            printf("\nIP frame there!\n");
            process_ip_packet(buffer, size);
            break;

        case ETH_P_IPV6:
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
    printf("   |-Protocol            : %x \n", ntohs(eth->h_proto));
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

void print_pn_dcp_header(unsigned char* buffer){

    pndcp_header* pndcp_hdr = (pndcp_header*)(buffer + ETH2_HEADER_LEN);

    printf("\nPN-DCP Header\n");
    printf("   |-Service ID            : %x\t", pndcp_hdr->serv_id);
    parse_pndcp_service_id_field(pndcp_hdr->serv_id);
    printf("   |-Service Type          : %x\t", pndcp_hdr->serv_type);
    parse_pndcp_service_type_field(pndcp_hdr->serv_type);
    printf("   |-Xid                   : %x\n", ntohl(pndcp_hdr->xid));
    printf("   |-Option                : %x\t", pndcp_hdr->option);
    parse_pndcp_option_field(pndcp_hdr->option);
    printf("   |-Suboption             : %x\n", pndcp_hdr->sub_option);
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

    ipv6_header* iphdr = (ipv6_header*)buffer;
    int offset = ETH2_HEADER_LEN + ntohs(iphdr->length);

    print_ethernet_header(buffer , size);

    printf("\nIPv6 Header\n");

    printf("   |-Version         : %x\n", iphdr->version >> 4);
    printf("   |-Traffic class   : %x\n", iphdr->traffic_class >> 20);
    printf("   |-Flow label      : %x\n", ntohl(iphdr->flow_label & 0x000fffff));
    printf("   |-Payload len     : %x\n", ntohs(iphdr->length));
    printf("   |-Next header     : %x\n", iphdr->next_header);
    printf("   |-Hop limit       : %x\n", iphdr->hop_limit);

    inet_ntop(AF_INET6, &iphdr->src, addrstr, sizeof(addrstr));
    printf("   |-Source IP      : %s\n", addrstr);

    inet_ntop(AF_INET6, &iphdr->dst, addrstr, sizeof(addrstr));
    printf("   |-Destination IP : %s\n", addrstr);

    if (iphdr->next_header == IPV6_ICMP){
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

    if (ntohs(udph->source) == 53) 
        print_dns_packet(buffer, size);
    
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


// nbr = max interfaces number in the list

int get_itf_list(char** itf_list, int nbr){

    struct ifaddrs *ifaddr, *ifa;

    if (getifaddrs(&ifaddr) == -1) {
        return -1;
    }

    int itf_nbr = 0;
    for (ifa = ifaddr; ifa; ifa = ifa->ifa_next){

        if (itf_nbr == nbr)
            break;

        // test if interface exists, if it is running and if different loopback
        if (ifa->ifa_addr != NULL && (ifa->ifa_flags & IFF_RUNNING) != 0 && strcmp("lo", ifa->ifa_name) != 0){
            itf_list[itf_nbr] = (char*)malloc(strlen(ifa->ifa_name)+1);
            strncpy(itf_list[itf_nbr], ifa->ifa_name, strlen(ifa->ifa_name)+1);
            printf("interface : %s | %x\n", itf_list[itf_nbr], ifa->ifa_flags);
            itf_nbr++;
        }
    } 

    freeifaddrs(ifaddr);

    return itf_nbr; 
}

// set up the socket in promiscuous too

int setup_promiscuous_mode(int sock, int device_index){

    struct packet_mreq mreq;
    memset(&mreq,0,sizeof(mreq));

    mreq.mr_ifindex = device_index;
    mreq.mr_type = PACKET_MR_PROMISC;
    
    if (setsockopt(sock, SOL_PACKET, PACKET_ADD_MEMBERSHIP, (void*)&mreq, sizeof(mreq)) < 0) {
        perror("setsockopt error while adding PACKET_ADD_MEMBERSHIP option\n");
        return -1;
    }

    printf("\nDEBUG\t\t: promiscuous mode successfully enabled\n\n");

    return 1;
}

// get interface index and set some options to make a nice sock

int get_itf_index(int sock, const char* itf_name) {
    
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));

    strncpy(ifr.ifr_name, itf_name, sizeof(ifr.ifr_name));

    /* Set the old flags plus the IFF_PROMISC flag */

    ifr.ifr_flags |= IFF_PROMISC;

    if (ioctl (sock, SIOCSIFFLAGS, &ifr) < 0){
        perror ("Error: Could not set flag IFF_PROMISC");
        return -1;
    }
    
    if (ioctl(sock, SIOCGIFINDEX, &ifr) < 0){
        perror("error while getting interface index\n");
        return -1;
    }

    printf("\nDEBUG\t\t: successfully get the interface index\n\n");

    int opt = 1;
    
    // another trick to set up interface in promiscuous mode
    
    if (setsockopt(sock, SOL_SOCKET, PACKET_MR_PROMISC,&opt, sizeof(opt)) < 0) {
        printf("Server-setsockopt() error for PACKET_MR_PROMISC\n");
        return -1;
    }

    static const int32_t sock_qdisc_bypass = 1;
    int32_t sock_qdisc_ret = setsockopt(sock, SOL_PACKET, PACKET_QDISC_BYPASS, &sock_qdisc_bypass, sizeof(sock_qdisc_bypass));

    if (sock_qdisc_ret == -1) {
        perror("Can't enable QDISC bypass on socket\n");
        return -1;
    }

    if (setsockopt(sock, SOL_SOCKET, SO_BINDTODEVICE, (void *)&ifr, sizeof(ifr)) < 0) {
        perror("setsockopt error while adding SO_BINDTODEVICE\n");
        return -1;
    }

    printf("\nDEBUG\t\t: setting setsockopt options DONE !\n\n");

    //assert(setup_promiscuous_mode(sock, ifr.ifr_ifindex) > 0);

    return ifr.ifr_ifindex;
}

// last step : binding the socket to the device

int bind_sock(int sock, int itf_index){

    struct sockaddr_ll sock_addr;
    memset((void*)&sock_addr, 0, sizeof(struct sockaddr_ll));

    sock_addr.sll_family = AF_PACKET;
    sock_addr.sll_protocol = htons(ETH_P_ALL);
    sock_addr.sll_ifindex = itf_index;

    if (bind(sock, (struct sockaddr *)&sock_addr, sizeof(struct sockaddr_ll)) < 0){
        perror("fatal error while binding the socket\n");
        return -1;
    }

    printf("\nDEBUG\t\t: socket ready to listen\n");

    return 0;
}

// creates and set up socket (setsockopt() etc...) from an interface name to bind with

int init_sock(const char *itf){

    int sock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));

    if (sock == -1) {
        perror("error while creating socket\n");
        return -1;
    }

    // getting interface index and setting it to god mode level

    int itf_index = get_itf_index(sock, itf);

    if (itf_index < 0){
        perror("fatal error occured while setting sock options\n");
        return -1;
    }

    printf("DEBUG : interface index : %x\n", itf_index);

    //assert(bind_sock(sock, itf_index) == 0);

    return sock;

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

// print current time of the capture for each frame

void print_current_time(){

    time_t now = time(NULL);
    struct tm *tm_struct = localtime(&now);
    printf("\n[LOCAL TIME %02d:%02d:%02d]", tm_struct->tm_hour , tm_struct->tm_min , tm_struct->tm_sec);

}
