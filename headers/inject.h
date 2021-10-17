/********************** active sniffing TODO *****************************/

/* NOT IMPLEMENTED YET */

#ifndef INJECT_H
#define INJECT_H

#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <fcntl.h>
#include <pthread.h>
#include <time.h>
#include <stddef.h>

#include "sock_utils.h"
#include "parsing.h"
#include "string_utils.h"

#define BROADCAST_ADDR (uint8_t[6]){0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}

// pseudo struct for icmp packet

typedef struct icmp_packet {

	struct ethhdr eth;
    struct iphdr ip;
    struct icmphdr icmp;
    u_char data[52];

} icmp_packet;

typedef struct arp_packet {

    uint16_t hardware_type;
    uint16_t protocol_type;
    uint8_t hardware_len;
    uint8_t protocol_len;
    uint16_t opcode;
    uint8_t sender_mac[MAC_LENGTH];
    uint8_t sender_ip[IPV4_LENGTH];
    uint8_t target_mac[MAC_LENGTH];
    uint8_t target_ip[IPV4_LENGTH];

} arp_packet;

typedef struct opt_struct{

	int socket;
	int sleep_time;
	int ttl;
	int packets_nbr;
	int packet_size;
	struct sockaddr_in* target_addr;
	unsigned char* packet;

	
} opt_struct;

//the thread function

void *connection_handler(void*);
unsigned char *get_target_mac_address(int, const char*);

// perform ARP poisoning packets

int get_device_index(int, const char*);
struct ethhdr* create_arp_packet(const uint16_t, const uint8_t*, const char*, const uint8_t*, const char*);
int send_broadcast_arp_packet(int, struct sockaddr_ll*, const uint8_t*, const char*, const char*);
int start_arp_spoofing_attack(int, struct sockaddr_ll*, const uint8_t*, const char*, const uint8_t*, const char*, const uint8_t*);
int launch_arp_spoofing_attack(const char*, const char*, const char*);
int start_arp_poisonning(char*);

// perform ICMP redirecting here

int create_icmp_sock(int);
unsigned short cksum(unsigned short*, int);
int start_icmp_snooping(unsigned char*, struct sockaddr_in*, int, int, int, int);
unsigned char* send_icmp_packet(unsigned char*, int, struct sockaddr_in*);

#endif
