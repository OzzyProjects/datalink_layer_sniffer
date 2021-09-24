#ifndef SOCKUTILS_H
#define SOCKUTILS_H

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
#include <unistd.h>

#include <sys/time.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <linux/if_packet.h>
#include <net/ethernet.h> 
#include <ifaddrs.h>
#include <netinet/ip_icmp.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <netinet/ip.h>
#include <linux/if_arp.h> 
#include <netinet/igmp.h>

#define ___my_swab16(x) \
    ((u_int16_t)( \
    (((u_int16_t)(x) & (u_int16_t)0x00ffU) << 8) | \
    (((u_int16_t)(x) & (u_int16_t)0xff00U) >> 8) ))

#define ___my_swab32(x) \
    ((u_int32_t)( \
    (((u_int32_t)(x) & (u_int32_t)0x000000ffUL) << 24) | \
    (((u_int32_t)(x) & (u_int32_t)0x0000ff00UL) <<  8) | \
    (((u_int32_t)(x) & (u_int32_t)0x00ff0000UL) >>  8) | \
    (((u_int32_t)(x) & (u_int32_t)0xff000000UL) >> 24) ))

#define ETHERTYPE_IEEE1905_1    0x893a
#define ETHERTYPE_HOMEPLUG     0x887b
#define ETHERTYPE_HOMEPLUG_POWERLINE    0x88e1
#define ETH_P_ALL   0x0003

#define BUFF_SIZE 65536
#define ETH2_HEADER_LEN 14
#define HW_TYPE 1
#define MAC_LENGTH 6
#define IPV4_LENGTH 4
#define ARP_REQUEST 0x01
#define ARP_REPLY 0x02
#define ITF_MAX_NBR 0x10
#define MTU 1472

typedef struct {

    char src_addr[100];
    char dest_addr[100];
    u_int32_t type;
    char *payload;
    u_int32_t payload_size;

} icmp_packet;

typedef struct {

    uint16_t hardware_type;
    uint16_t protocol_type;
    unsigned char hardware_len;
    unsigned char protocol_len;
    uint16_t opcode;
    unsigned char sender_mac[MAC_LENGTH];
    unsigned char sender_ip[IPV4_LENGTH];
    unsigned char target_mac[MAC_LENGTH];
    unsigned char target_ip[IPV4_LENGTH];

} __attribute__((packed)) arp_header;

typedef struct icmpheader {

    u_int8_t type;
    u_int8_t code;
    u_int16_t checksum;
    
    union{
        struct echo
        {
            u_int16_t id;
            u_int16_t sequence;
        } echo;
            u_int32_t gateway;
        struct frag
        {
            u_int16_t __unused;
            u_int16_t mtu;
        } frag;
    } un;

} icmpheader;

typedef struct dnshdr {

    unsigned short id;
 
    unsigned char rd :1;
    unsigned char tc :1;
    unsigned char aa :1;
    unsigned char opcode :4;
    unsigned char qr :1;
 
    unsigned char rcode :4;
    unsigned char cd :1;
    unsigned char ad :1;
    unsigned char z :1;
    unsigned char ra :1;
 
    unsigned short q_count;
    unsigned short ans_count;
    unsigned short auth_count;
    unsigned short add_count;

} dnshdr;


typedef struct {

    struct ethhdr eth;
    uint16_t padding;
    unsigned char buffer[64]; 
    
} perso;

int get_itf_list(char**, int);
int get_itf_index(int, const char*); 
int init_sock(const char*);
int bind_sock(int, int);
void print_ethernet_header(unsigned char*, int);
void process_ip_packet(unsigned char* , int);
void process_frame(unsigned char* , int);
void process_arp_packet(unsigned char*);
void print_ip_header(unsigned char* , int);
void print_tcp_packet(unsigned char * , int );
void print_udp_packet(unsigned char * , int );
void print_icmp_packet(unsigned char* , int );
void print_igmp_packet(unsigned char*, int);

void print_dns_packet(unsigned char*, int);

void print_data(unsigned char* , int);
uint16_t in_cksum(uint16_t *addr, int len);

#endif