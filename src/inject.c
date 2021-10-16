/********************** active sniffing TODO *****************************/

// the purpose would be to to send various frames/packets to perform MITM sniffing with packets forwarding
// with ARP poisonning, IGMP snooping etc... in progress

// crafting our own ARP spoofing packet to perform ARP poisonning to the target address
// it would be a broadcast response or a selective response to a real ARP querry

#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
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

int init_sock(const char *device_name, int* dev_index){

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
