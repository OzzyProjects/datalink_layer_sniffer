#include "sock_utils.h"

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

    if (itf_nbr < nbr){
        char** temp = realloc(itf_list, sizeof(char*) * itf_nbr);
        if (temp == NULL)
            return -1;
        else
            itf_list = temp;
    }

    return itf_nbr; 
} 

int get_itf_index(int sock, const char* itf_name) {
    
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));

    if (strlen(itf_name) > IFNAMSIZ) {
        return -1;
    }

    strncpy(ifr.ifr_name, itf_name, sizeof(ifr.ifr_name));

    if (ioctl(sock, SIOCGIFFLAGS, &ifr) < 0){
        perror ("Error: Could not retrive the flags from the device.\n");
        return -1;
    }

    /* Set the old flags plus the IFF_PROMISC flag */
    ifr.ifr_flags |= IFF_PROMISC;
    if (ioctl (sock, SIOCSIFFLAGS, &ifr) < 0){
        perror ("Error: Could not set flag IFF_PROMISC");
        return -1;
    }
    
    printf ("DEBUG : entering promiscuous mode ok\n");
    
    if (ioctl(sock, SIOCGIFINDEX, &ifr) < 0){
        perror("error while getting interface index\n");
        return -1;
    }

    int opt = 1;

    if (setsockopt(sock, SOL_SOCKET, PACKET_MR_PROMISC,&opt, sizeof(opt)) < 0) {
        printf("Server-setsockopt() error for PACKET_MR_PROMISC\n");
        return -1;
    }

    if (setsockopt(sock, SOL_SOCKET, SO_BINDTODEVICE, (void *)&ifr, sizeof(ifr)) < 0) {
        perror("Server-setsockopt() error for SO_BINDTODEVICE");
        return -1;
    }

    printf("DEBUG : setting setsockopt for PACKET_MR_PROMISC and SO_BINDTODEVICE ok\n");


    return ifr.ifr_ifindex;
}

int bind_sock(int sock, int itf_index){

    struct sockaddr_ll addr;
    memset((void*)&addr, 0, sizeof(struct sockaddr_ll));
    addr.sll_family = PF_PACKET;
    addr.sll_protocol = htons(ETH_P_ALL);
    addr.sll_ifindex = itf_index;

    if (bind(sock,(struct sockaddr *)&addr, sizeof(struct sockaddr_ll)) < 0){
        perror("error while binding the socket\n");
        return -1;
    }

    return 0;
}

int init_sock(const char *itf){

    int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));

    if (sock == -1) {
        perror("error while creating socket\n");
        return -1;
    }

    int itf_index = get_itf_index(sock, itf);
    assert(itf_index != -1);

    printf("DEBUG : itf index : %d\n", itf_index);

    assert(bind_sock(sock, itf_index) == 0);

    return sock;

}

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
    *(unsigned char *) (&answer) = *(unsigned char *) w;
    sum += answer;
  }

  sum = (sum >> 16) + (sum & 0xffff);
  sum += (sum >> 16);
  answer = ~sum;

  return answer;
}

void process_frame(unsigned char* buffer, int size){

    struct ethhdr *eth = (struct ethhdr *)buffer;
    uint16_t proto = ntohs(eth->h_proto);

    switch(proto){

        case ETHERTYPE_ARP:
        printf("\nARP frame there!\n");
        process_arp_packet(buffer);
        break;

        case ETHERTYPE_IEEE1905_1:
        printf("\nETHERTYPE_IEEE1905_1 frame there!\n");
        print_ethernet_header(buffer , size);
        break;

        case ETHERTYPE_HOMEPLUG:
        printf("\nETHERTYPE_HOMEPLUG frame there!\n");
        print_ethernet_header(buffer , size);
        break;

        case ETHERTYPE_HOMEPLUG_POWERLINE:
        printf("\nETHERTYPE_HOMEPLUG_POWERLINE frame there!\n");
        print_ethernet_header(buffer , size);
        break;

        case ETHERTYPE_IP:
        process_ip_packet(buffer, size);
        break;

        default:
        printf("\n********* UNKNOWN frame there! **********\n");
        print_ethernet_header(buffer , size);
    }
}

void process_ip_packet(unsigned char* buffer, int size)
{
    //Get the IP Header part of this packet , excluding the ethernet header
    struct iphdr *iph = (struct iphdr*)(buffer + ETH2_HEADER_LEN);
    printf("ip protocol : %x\n", iph->protocol);
    switch (iph->protocol)
    {
        case 1:  //ICMP Protocol
            print_icmp_packet(buffer , size);
            break;
        
        case 2:  //IGMP Protocol
            print_igmp_packet(buffer, size);
            break;
        
        case 6:  //TCP Protocol
            print_tcp_packet(buffer , size);
            break;
        
        case 17: //UDP Protocol
            print_udp_packet(buffer , size);
            break;
        
        default: //Some Other Protocol like ARP etc.
            print_data(buffer, size);
            break;
    }
}

void print_ethernet_header(unsigned char* buffer, int size)
{
    struct ethhdr *eth = (struct ethhdr *)buffer;
    
    printf("\n");
    printf("Ethernet Header\n");
    printf("   |-Destination Address : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n", eth->h_dest[0] , eth->h_dest[1] , eth->h_dest[2] , eth->h_dest[3] , eth->h_dest[4] , eth->h_dest[5] );
    printf("   |-Source Address      : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n", eth->h_source[0] , eth->h_source[1] , eth->h_source[2] , eth->h_source[3] , eth->h_source[4] , eth->h_source[5] );
    printf("   |-Protocol            : %x \n", ntohs(eth->h_proto));
}

void process_arp_packet(unsigned char* buffer){

    arp_header *arphdr = (arp_header*)(buffer + ETH2_HEADER_LEN);
    printf("ARP Header\n");
    printf("hardware type : %u\n", ntohs(arphdr->hardware_type));
    printf("protocol type : %u\n", ntohs(arphdr->protocol_type));
    printf("opcode : %u\n", ntohs(arphdr->opcode));
    printf("source mac address : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X\n",arphdr->sender_mac[0],arphdr->sender_mac[1],arphdr->sender_mac[2],arphdr->sender_mac[3],arphdr->sender_mac[4],arphdr->sender_mac[5]);
    printf("dest mac address : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X\n",arphdr->target_mac[0],arphdr->target_mac[1],arphdr->target_mac[2],arphdr->target_mac[3],arphdr->target_mac[4],arphdr->target_mac[5]);
    printf("source ip address : %d.%d.%d.%d\n", arphdr->sender_ip[0],arphdr->sender_ip[1],arphdr->sender_ip[2],arphdr->sender_ip[3]);
    printf("dest ip address : %d.%d.%d.%d\n", arphdr->target_ip[0],arphdr->target_ip[1],arphdr->target_ip[2],arphdr->target_ip[3]);

}

void print_igmp_packet(unsigned char* buffer, int size){

    unsigned short iphdrlen;
    struct iphdr *iph = (struct iphdr *)(buffer  + ETH2_HEADER_LEN);
    iphdrlen = iph->ihl*4;

    struct igmp *ighdr = (struct igmp*)(buffer + ETH2_HEADER_LEN + iphdrlen);

    printf("\n\n***********************IGMP Packet*************************\n"); 

    print_ip_header(buffer,size);

    printf("\nIGMP Header\n");
    printf("   |-Type : %x\n", ighdr->igmp_type);
    printf("   |-Code : %x\n", ighdr->igmp_code);
    printf("   |-Checksum : %x\n", ntohs(ighdr->igmp_cksum));
    printf("   |-Group : %s\n", inet_ntoa(ighdr->igmp_group));

    printf("\n###########################################################");

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
    
    printf("\n");
    printf("IP Header\n");
    printf("   |-IP Version        : %d\n",(unsigned int)iph->version);
    printf("   |-IP Header Length  : %d DWORDS or %d Bytes\n",(unsigned int)iph->ihl,((unsigned int)(iph->ihl))*4);
    printf("   |-Type Of Service   : %d\n",(unsigned int)iph->tos);
    printf("   |-IP Total Length   : %d  Bytes(size of Packet)\n",ntohs(iph->tot_len));
    printf("   |-Identification    : %d\n",ntohs(iph->id));
    //printf("   |-Reserved ZERO Field   : %d\n",(unsigned int)iphdr->ip_reserved_zero);
    //printf("   |-Dont Fragment Field   : %d\n",(unsigned int)iphdr->ip_dont_fragment);
    //printf("   |-More Fragment Field   : %d\n",(unsigned int)iphdr->ip_more_fragment);
    printf("   |-TTL      : %d\n",(unsigned int)iph->ttl);
    printf("   |-Protocol : %d\n",(unsigned int)iph->protocol);
    printf("   |-Checksum : %d\n",ntohs(iph->check));
    printf("   |-Source IP        : %s\n",inet_ntoa(source.sin_addr));
    printf("   |-Destination IP   : %s\n",inet_ntoa(dest.sin_addr));
}

void print_tcp_packet(unsigned char* buffer, int size)
{
    unsigned short iphdrlen;
    
    struct iphdr *iph = (struct iphdr *)( buffer  + ETH2_HEADER_LEN);
    iphdrlen = iph->ihl*4;
    
    struct tcphdr *tcph = (struct tcphdr*)(buffer + iphdrlen + ETH2_HEADER_LEN);
            
    int header_size =  sizeof(struct ethhdr) + iphdrlen + tcph->doff*4;
    
    printf("\n\n***********************TCP Packet*************************\n");  
        
    print_ip_header(buffer,size);
        
    printf("\nTCP Header\n");
    printf("   |-Source Port      : %u\n",ntohs(tcph->source));
    printf("   |-Destination Port : %u\n",ntohs(tcph->dest));
    printf("   |-Sequence Number    : %u\n",ntohl(tcph->seq));
    printf("   |-Acknowledge Number : %u\n",ntohl(tcph->ack_seq));
    printf("   |-Header Length      : %d DWORDS or %d BYTES\n" ,(unsigned int)tcph->doff,(unsigned int)tcph->doff*4);
    //printf("   |-CWR Flag : %d\n",(unsigned int)tcph->cwr);
    //printf("   |-ECN Flag : %d\n",(unsigned int)tcph->ece);
    printf("   |-Urgent Flag          : %d\n",(unsigned int)tcph->urg);
    printf("   |-Acknowledgement Flag : %d\n",(unsigned int)tcph->ack);
    printf("   |-Push Flag            : %d\n",(unsigned int)tcph->psh);
    printf("   |-Reset Flag           : %d\n",(unsigned int)tcph->rst);
    printf("   |-Synchronise Flag     : %d\n",(unsigned int)tcph->syn);
    printf("   |-Finish Flag          : %d\n",(unsigned int)tcph->fin);
    printf("   |-Window         : %d\n",ntohs(tcph->window));
    printf("   |-Checksum       : %d\n",ntohs(tcph->check));
    printf("   |-Urgent Pointer : %d\n",tcph->urg_ptr);
    printf("\n");
    printf("                        DATA Dump                         ");
    printf("\n");
        
    printf("IP Header\n");
    print_data(buffer+ETH2_HEADER_LEN,iphdrlen);
        
    printf("TCP Header\n");
    print_data(buffer+iphdrlen,tcph->doff*4);
        
    printf("Data Payload\n");    
    print_data(buffer+header_size, size-header_size);
                        
    printf("\n###########################################################");
}

void print_dns_packet(unsigned char* buffer, int size)
{
    unsigned short iphdrlen;
    
    struct iphdr *iph = (struct iphdr *)( buffer  + ETH2_HEADER_LEN);
    iphdrlen = iph->ihl*4;
    
    struct dnshdr *dndh = (struct dnshdr*)(buffer + iphdrlen + ETH2_HEADER_LEN + sizeof(struct udphdr));
            
    int header_size =  sizeof(struct udphdr) + sizeof(struct ethhdr) + iphdrlen;
    
    printf("\n\n***********************DNS Packet*************************\n");  
        
    printf("\nDNS Header\n");
    printf("   |-Opcode      : %u\n",dndh->opcode);
    printf("   |-R code : %u\n",dndh->rcode);
    printf("   |-Q count    : %u\n",ntohs(dndh->q_count)); 
    printf("   |-Answer    : %u\n",ntohs(dndh->ans_count));
    printf("   |-Auth count    : %u\n",ntohs(dndh->auth_count));
    printf("   |-Additional    : %u\n",ntohs(dndh->add_count));

    printf("\n###########################################################");
}

void print_udp_packet(unsigned char *buffer , int size)
{
    
    unsigned short iphdrlen;
    
    struct iphdr *iph = (struct iphdr *)(buffer +  ETH2_HEADER_LEN);
    iphdrlen = iph->ihl*4;
    
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

    if (ntohs(udph->source) == 53) print_dns_packet(buffer, size);
    
    printf("\n");
    printf("IP Header\n");
    print_data(buffer+ETH2_HEADER_LEN , iphdrlen);
        
    printf("UDP Header\n");
    print_data(buffer+iphdrlen, sizeof(udph));
        
    printf("Data Payload\n");    
    
    //Move the pointer ahead and reduce the size of string
    print_data(buffer+header_size, size-header_size);
    
    printf("\n###########################################################");
}

void print_icmp_packet(unsigned char* buffer , int size){
    
    unsigned short iphdrlen;
    
    struct iphdr *iph = (struct iphdr *)(buffer + ETH2_HEADER_LEN);
    iphdrlen = iph->ihl * 4;
    
    struct icmpheader *icmph = (struct icmpheader *)(buffer + iphdrlen + ETH2_HEADER_LEN);
    
    int header_size =  sizeof(struct ethhdr) + iphdrlen + sizeof icmph;
    
    printf("\n***********************ICMP Packet*************************\n"); 
    
    print_ip_header(buffer , size);
        
    printf("\nICMP Header\n");
    printf("   |-Type : %d", icmph->type);
            
    if(icmph->type == 11){
        printf("  (TTL Expired)\n");
    }
    else if(icmph->type == ICMP_ECHOREPLY){
        printf("  (ICMP Echo Reply)\n");
    }
    
    printf("   |-Code : %d\n", icmph->code);
    printf("   |-Checksum : %d\n", ntohs(icmph->checksum));
    printf("   |-ID       : %d\n", ntohs(icmph->un.echo.id));
    printf("   |-Sequence : %d\n", ntohs(icmph->un.echo.sequence));
    printf("   |-Gateway : %lu\n", icmph->un.gateway);
    printf("   |-Mysterious : %d\n", ntohs(icmph->un.frag.__unused));
    printf("\n");
    printf("                        DATA Dump                         ");
    printf("\n");

    printf("IP Header\n");
    print_data(buffer,iphdrlen);
        
    printf("UDP Header\n");
    print_data(buffer + iphdrlen , sizeof(icmph));
        
    printf("Data Payload\n");    
    
    //Move the pointer ahead and reduce the size of string
    //why i cannot no more capture icmp ?
    print_data(buffer + header_size, size-header_size);
    
    printf("\n###########################################################");
}

void print_data(unsigned char* data , int size)
{
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
