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

// pseudo struct for icmp packet

typedef struct icmp_packet {

	struct ethhdr eth;
    struct iphdr ip;
    struct icmphdr icmp;
    u_char data[52];

} icmp_packet;

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

// perform ARP poisoning packets

unsigned char* pack_arp_spoofing_packet(unsigned char*, unsigned char*, unsigned char*, unsigned char*,
    unsigned char*);

int get_device_index(int, const char*);
int init_arp_sock(const char*, int*);
int start_arp_poisonning(char*);

// perform ICMP snooping here

int create_icmp_sock(int);
unsigned short cksum(unsigned short*, int);
int start_icmp_snooping(unsigned char*, struct sockaddr_in*, int, int, int, int);
unsigned char* send_icmp_packet(unsigned char*, int, struct sockaddr_in*);

#endif
