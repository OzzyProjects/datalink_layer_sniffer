#ifndef SOCKUTILS_H
#define SOCKUTILS_H

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
#include <unistd.h>
#include <time.h>
#include <ctype.h>

#include <sys/time.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <net/if.h>
#include <linux/if_packet.h>
#include <net/ethernet.h> 
#include <netinet/ip_icmp.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <netinet/ip.h>
#include <netinet/igmp.h>
#include <netinet/icmp6.h>
#include <linux/ipv6.h>

#include <pcap.h>


/********************* Usefull macros *********************/

// Really Helpfull function for low level netwoork  programmming

#define FORCE_INLINE __attribute__((always_inline)) inline

#define __my_swab16(x) \
    ((u_int16_t)( \
    (((u_int16_t)(x) & (u_int16_t)0x00ffU) << 8) | \
    (((u_int16_t)(x) & (u_int16_t)0xff00U) >> 8) ))

#define __my_swab32(x) \
    ((u_int32_t)( \
    (((u_int32_t)(x) & (u_int32_t)0x000000ffUL) << 24) | \
    (((u_int32_t)(x) & (u_int32_t)0x0000ff00UL) <<  8) | \
    (((u_int32_t)(x) & (u_int32_t)0x00ff0000UL) >>  8) | \
    (((u_int32_t)(x) & (u_int32_t)0xff000000UL) >> 24) ))

// get low or high nibble from byte

#define HIGH_NI(X) ((uint8_t)(X) >> 4) & 0xF
#define LOW_NI(X) (uint8_t)(X) & 0xF
#define SWP_NI(X) (((uint8_t)(X) & 0x0F) << 4) | (((uint8_t)(X) & 0xF0) >> 4)

// Check whether the "len" bytes of data starting at "offset" is entirely 
// inside the captured data for this packet

#define BYTE_IN_FRM(offset, captured_len, len) \
    ((uint32_t)(offset) + (uint32_t)(len) > (uint32_t)(offset) && \
    (uint32_t)(offset) + (uint32_t)(len) <= (uint32_t)(captured_len))


// Number of bytes between two pointers

#define NB_B_PTR(ptr1, ptr2) ((uint32_t)(((const uint8_t *)(ptr1) - \
    (const uint8_t *)(ptr2)))

// IP Address packing

#define IP_PCK(ip) (((ip) << 0 * 10) | ((ip) << 1 * 10) | \
    ((ip) << 2 * 10) | ((ip) << 3 * 10))

// Bitwise Operations Macros

// check for one bit at nth offset
#define CK_BIT(X, n) (((X) >> (n)) & 0x1)

// set the nth bit (X : integer, n : offset)
#define SET_BIT(X, n) ((X) |= (1U << (n)))

#define CLR_BIT(X, n) ((X) &= (~(1U << (n))))

#define GET_F_LW_B(X, n) ((X) & ~(~0x0UL << (n)))

#define FST_2_BY(X) __my_swab16(*((uint16_t*)(X)))

#define FST_4_BY(X) __my_swab32(*((uint32_t*)(X)))

#define B_AT_OFF(buff, off) (uint8_t)(*((uint8_t*)((buff) + (off))))

#define FR_B_OFF(buff, off) __my_swab32(*(((uint32_t*)((buff) + (off))))) 

#define T_B_OFF(buff, off) __my_swab16(*(((uint16_t*)((buff) + (off))))) 

#define F_B_OFF(buff, off) (uint8_t)(*(((uint8_t*)((buff) + (off)))))


// ETHERCAT macros field extractors

#define E_CAT_LEN(X) (uint16_t)(((__my_swab16(X)) & 0x7FFUL))

#define E_CAT_RES(X) (uint8_t)((((__my_swab16(X)) >> 11UL) & 0x1UL))

#define E_CAT_COM(X) (uint8_t)(((__my_swab16(X)) >> 12UL))

// -------------------------------------- HOMEPLUG macros extractor

// extract message ID
#define HM_PLG_ID(X) (uint8_t)((GET_F_LW_B((X), 6)))

// extract direction
#define HM_PLG_DIR(X) (uint8_t)((((X) >> 6) & 0x2))

#define HM_AV_LT_FRG(X) (uint8_t)(((X) & MSK_HI_BIT))

#define HM_AV_REL_IND(X) (uint8_t)(((X) & MSK_2NH_HI_BIT))

// ---------------- NBNS macros extractor (flags)


#define MDNS_TYPE_M(X) (uint16_t)(((X) & (1 << 15)))

#define MDNS_TYPE_Q(X) (uint16_t)((((X) >> 7) & 0x78))

#define MDNS_IS_RC(X) (uint16_t)((((X) >> 9) & 0x1))

#define MDNS_IS_BRCT(X) (uint16_t)((((X) >> 4) & 0x1))


// ----------------- DNS macros extractor (flags) 

#define DNS_TYPE_M(X) (uint16_t)((((X) >> 15) & 0x1))

#define DNS_OPC(X) (uint16_t)((((X) >> 11) & 0xF))

#define DNS_IS_AUTH(X) (uint16_t)((((X) >> 10) & 0x1))

#define DNS_IS_REC(X) (uint16_t)((((X) >> 8) & 0x1))

#define DNS_RPL_CD(X) (uint16_t)((X) & 0xF)


// ----------------- NTP Macros extractor (flags)

#define NTP_IS_WRN(X) (uint8_t)((((X) >> 6) & 0x3))

#define NTP_VER(X) (uint8_t)((((X) >> 3) & 0x7))

#define NTP_MODE(X) (uint8_t)((X) & 0x7)

#define __INT_TO_UCHAR_PTR(x) ((u_char*)(intptr_t)(x))
#define __UCHAR_PTR_TO_INT(x) ((int)(intptr_t)(x))


/* Filter TCP segments to port 80

static struct sock_filter bpfcode[8] = {
    { OP_LDH, 0, 0, 12          },  
    { OP_JEQ, 0, 5, ETH_P_IP    },  
    { OP_LDB, 0, 0, 23          },  
    { OP_JEQ, 0, 3, IPPROTO_TCP },  
    { OP_LDH, 0, 0, 36          },  
    { OP_JEQ, 0, 1, 80          },  
    { OP_RET, 0, 0, -1,         },  
    { OP_RET, 0, 0, 0           },                                                                                                                                                                                                   

}; */

// IP protocols numbers (most common or interesting one)

#define IPV4_ICMP       0x01
#define IPV4_IGMP       0x02
#define IPV4_TCP        0x06
#define IPV4_UDP        0x11
#define IPV4_EIGRP      0x58
#define IPV4_SCTP       0x84


// 3 bytes of padding before all HCI_H4 packets

#define HCI_H4_PRE_HEADER_LENGTH        3

#define ETHERNET_MTU                    1500
#define ARP_SPOOFING_PACKET_SIZE        42
#define SLL_ADDRLEN                     8
#define SLL_HDR_LEN                     16
#define IPMB_HDR_LEN                    6 
#define HCI_H4_HDR_LEN                   2     

#define BUFSIZE                         65000
#define ETH2_HEADER_LEN                 14
#define MAC_LENGTH                      6
#define IPV4_LENGTH                     4
#define HCI_H4_DEVICE_NAME_LENGTH       32
#define SMP_PUBLIC_KEY_MAX_LENGTH       128

#define NETBIOS_DATAGRAM_NAME_LENGTH            64
#define SMB_COMMAND_TRANSACTION_NAME_LENGTH     64

// because i don't know the specifications about mailslot name max length, i've fixed to the same value as windows max path length
#define MAILSLOT_NAME_MAX_LENGTH        64
#define BROWSER_HOSTNAME_LENGTH         64

#define PCAP_FILTER_SIZE                64
#define RECORD_FILENAME_SIZE            32
#define MAX_PACKETS_NUMBER_LENGTH       128
#define READABLE_DEVICE_FLAGS_LENGTH    128   

#define PCAP_NETMASK_UNKNOWN        0xffffffff

#define IPX_NODE_LEN        6
#define IPX_MTU             576


//typedef void (*)(unsigned char*, int) hdr_funct_ptr;

/*********************************** OSI LAYER 2 FRAME STRUCTS ***********************************/


typedef struct ieee_802_3_frame_header{

    uint8_t mac_dest[MAC_LENGTH];
    uint8_t mac_src[MAC_LENGTH];
    uint16_t length;

} __attribute__((packed)) ieee_802_3_frame_header;



/*********************************** OSI LAYER 2 PROTOCOL STRUCTS ***********************************/


// Logigal Link Control Header encapsulated into 802.3 frames

typedef struct llc_header {

    uint8_t dsap;
    uint8_t ssap;
    uint8_t ctrl_field;

} __attribute__((packed)) llc_header;


// Basic Xid Struct Header (an LLC format type among others)

typedef struct llc_basic_xid_header {

    uint8_t xid_format;
    uint8_t llc_types;
    uint8_t windows_size;


} __attribute__((packed)) llc_basic_xid_header;



// HCI_H4 PROTOCOL (BLUETOOTH)

typedef struct hci_h4_header {

    uint8_t dir;
    uint8_t type;
    
} __attribute__((packed)) hci_h4_header;


// Pseudo Header for HCI_H4 Event Packets

typedef struct pseudo_hci_event_header {

    uint8_t event_code;
    uint8_t param_len;
    uint16_t connexion_handle;

    
} __attribute__((packed)) pseudo_hci_event_header;


// Struct of HCI_H4 Command Complete Header

typedef struct hci_h4_command_complete_header {

    uint8_t event_code;
    uint8_t param_len;
    uint8_t allowed_cmd_packets;
    uint16_t command_opcode;
    uint8_t status;

    
} __attribute__((packed)) hci_h4_command_complete_header;


// Pseudo Header for HCI_H4 Remote Request Names Packets

typedef struct hci_h4_rem_name_req {

    uint8_t param_len;
    uint8_t status;
    char src_addr[MAC_LENGTH];
    char remote_name[HCI_H4_DEVICE_NAME_LENGTH];


} __attribute__((packed)) hci_h4_rem_name_req;


// LPCAP Protocol Header for encapsulation

typedef struct l2cap_header {

    uint16_t length;
    uint16_t cid;
    
} __attribute__((packed)) l2cap_header;


// L2CAP Protocol Header with no encapsulation

typedef struct acl_packet_header {

    uint16_t connexion_handle   : 12;
    uint16_t pb_flag            : 2;
    uint16_t bc_flag            : 2;
    uint16_t data_len;
    
} __attribute__((packed)) acl_packet_header;


// Bluetooth Security Protocol Pairing Querry/Response

typedef struct bluetooth_smp_pairing_packet {

    uint8_t opcode;
    uint8_t io_cap;
    uint8_t oob_data_flags;
    uint8_t auth_flags;
    uint8_t init_key_distrib;


} __attribute__((packed)) bluetooth_smp_pairing_packet;


// BNEF Protocol Header Struct with Encapsulation

typedef struct bnep_header {

    uint8_t bnep_type;
    uint8_t ctrl_type;

    
} __attribute__((packed)) bnep_header;


// Attribute Data struct for Bluetooth Attribute Protocol

typedef struct att_attribute_data {

    uint16_t handle;
    uint16_t properties;
    uint16_t value_handle;
    uint16_t uuid;


} __attribute__((packed)) att_attribute_data; 

// 802.11 Protocols (Known also as Radiotap)

typedef struct radiotap_header {

    uint8_t hdr_revision;
    uint8_t hdr_pad;
    uint16_t hdr_len;


} radiotap_header;


// Linux SLL Header Struct (usefull in mode monitor)

typedef struct sll_header {

    uint16_t sll_pkttype;
    uint16_t sll_hatype;
    uint16_t sll_halen; 
    uint8_t  sll_addr[SLL_ADDRLEN];
    uint16_t sll_protocol; 

} sll_header;


// IMPB/IPMI over I2C Linux Pseudo Header

typedef struct ipmb_header {

    uint8_t bus_number      : 7;
    uint8_t type            : 1;
    uint64_t flags;
    uint8_t hardware_addr;
    
}  __attribute__((packed)) ipmb_header;



// RADIOTAP Generic Header Struct (in progress)

typedef struct ieee80211_radiotap_header {

    uint8_t    it_version;
    uint8_t    it_pad;
    uint16_t   it_len;
    uint32_t   it_present;

} __attribute__((__packed__)) ieee80211_radiotap_header;


/*********************************** OSI LAYER 3 PROTOCOL STRUCTS ***********************************/


// VLAN 802 1Q Protocol Header Struct

typedef struct vlan_ieee8021q_header {

    uint16_t priority   : 3;
    uint16_t dei        : 1;
    uint16_t id         : 12;
    uint16_t type;

} __attribute__((packed)) vlan_ieee8021q_header;


// SCTP Header Struct

typedef struct sctp_header {

    uint16_t  src_port;
    uint16_t  dst_port;
    uint32_t  v_tag;
    uint32_t  crc;

} __attribute__((packed)) sctp_header;


// IEEE 1905 1a Header (probably the most cheated protoool overall)

typedef struct ieee_1905_header {

    uint8_t msg_version;
    uint8_t reserved;
    uint16_t msg_type;
    uint16_t msg_id;
    uint8_t frag_id;
    uint8_t last_frag;

} __attribute__((packed)) ieee_1905_header;


// LLTD PROTOCOL Protocol Header Struct

typedef struct lltd_header {

    uint8_t version;
    uint8_t service_type;
    uint8_t reserved;
    uint8_t function;
    unsigned char real_dest[MAC_LENGTH];
    unsigned char real_src[MAC_LENGTH];

} __attribute__((packed)) lltd_header;


// HOMEPLUG AV (POWERLINE) Header (the same purpose than IEEE 1905 1a but Wireless based)


typedef struct homeplug_av_header {

    uint8_t protocol;
    uint16_t type;
    uint8_t frag;

} __attribute__((packed)) homeplug_av_header;


// HOMEPLUG PROTOCOL Standard Header Struct

typedef struct homeplug_header {

    uint8_t ctrl_field;
    uint8_t mac_entry;
    uint8_t entry_length;
    unsigned char spe_vendor[3];

} __attribute__((packed)) homeplug_header;


// PN-DCP PROTOCOL Header Struct (usefull when working with PLC)

typedef struct profinet_dcp_header {

    uint16_t frame_id;
    uint8_t serv_id;
    uint8_t serv_type;
    uint32_t xid;
    uint16_t resp_delay;
    uint16_t data_len;
    uint8_t option;
    uint8_t sub_option;
    uint16_t block_len; 

} __attribute__((packed)) profinet_dcp_header;


// IPv6 PROTOCOL Header Struct

typedef struct ipv6_header {

    unsigned int
        version : 4,
        traffic_class : 8,
        flow_label : 20;

    uint16_t length;
    uint8_t  next_header;
    uint8_t  hop_limit;

    struct in6_addr src;
    struct in6_addr dst;

} __attribute__((packed)) ipv6_header;


// ICMPv6 PROTOCOL Pseudo Header Struct

typedef struct icmp6_header{

    uint8_t type;
    uint8_t code;
    uint16_t cksum;

    // for id and seqno fields 
    uint32_t data;

} __attribute__((packed)) icmp6_header;


// ICMPv6 NDP Header Struct

typedef struct icmp6_NDP_header {

    uint8_t type;
    uint8_t code;
    uint16_t cksum;
    uint32_t reserved;
    struct in6_addr target_ip;
    uint8_t sub_type;
    uint8_t length;
    char target_mac[MAC_LENGTH];


} __attribute__((packed)) icmp6_NDP_header;


// ARP PROTOCOL Packet Struct

typedef struct arp_header {

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


// ICMPv4 PROTCOL Header Struct

typedef struct icmp_header {

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

} __attribute__((packed)) icmp_header;


// Various DHCP Protocol Strcuts (Not Implemented Yet)

typedef struct dhcpc_result_s {

    struct in_addr serverid;
    struct in_addr ipaddr;
    struct in_addr netmask;
    struct in_addr dnsaddr;
    struct in_addr default_router;
    uint32_t lease_time;

} dhcpc_result_t;


typedef struct dhcp_msg_s {

    uint8_t op;
    uint8_t htype;
    uint8_t hlen;
    uint8_t hops;
    uint32_t xid;
    uint16_t secs;
    uint16_t flags;
    uint32_t ciaddr;
    uint32_t yiaddr;
    uint32_t nsiaddr;
    uint32_t ngiaddr;
    uint8_t chaddr[16];
    uint8_t sname[64];
    uint8_t file[128];
    uint32_t cookie;
    uint8_t options[308];

} __attribute__((packed)) dhcp_msg_t;


/*********************************** OSI LAYER 5 PROTOCOL STRUCTS ***********************************/


// NTP Protocol Packet struct

typedef struct ntp_packet {

    uint8_t flags;
    uint8_t stratum;
    uint8_t poll;
    uint8_t precision;
    uint32_t root_delay;
    uint32_t root_dispersion;
    uint8_t reference_id[4];
    uint32_t ref_ts_sec;
    uint32_t ref_ts_frac;
    uint32_t origin_ts_sec;
    uint32_t origin_ts_frac;
    uint32_t recv_ts_sec;
    uint32_t recv_ts_frac;
    uint32_t trans_ts_sec;
    uint32_t trans_ts_frac;

} __attribute__((__packed__)) ntp_packet; 



// NETBIOS DATAGRAMM Protocol struct

typedef struct netbios_datagram_header {

    uint8_t msg_type;
    uint8_t flags;
    uint16_t dgram_id;
    struct in_addr ip_src;
    uint16_t port_src;
    uint16_t dgram_len;
    uint16_t offset;

    //unsigned char* src_name;
    //unsigned char* dst_name;


} __attribute__((packed)) netbios_datagram_header;



// SMB Protocol Header Struct

typedef struct smb_header {

    uint32_t smb_cmpt;
    uint8_t smb_command;
    uint8_t error_class;
    uint8_t reserved;
    uint16_t error_code;
    uint8_t flags;
    uint16_t flags2;
    uint16_t process_id_high;
    uint64_t signature;
    uint16_t reserved2;
    uint16_t tree_id;
    uint16_t process_id;
    uint16_t user_id;
    uint16_t multiplex_id;


} __attribute__((packed)) smb_header;



// SMB struct for SMB Command Trans Request Packets

typedef struct smb_command_trans_request {

    uint8_t word_cnt;
    uint16_t total_param;
    uint16_t total_data_cnt;
    uint16_t max_param_cnt;
    uint16_t max_data_cnt;
    uint8_t max_setup_cnt;
    uint8_t reserved;
    uint16_t flags;
    uint32_t timeout;
    uint16_t reserved2;
    uint16_t param_cnt;
    uint16_t param_offset;
    uint16_t data_cnt;
    uint16_t data_offset;
    uint8_t setup_cnt;
    uint8_t reserved3;
    uint16_t byte_cnt;

    // unsigned char* trans_name


} __attribute__((packed)) smb_command_trans_request;



// SMB MAILSLOT Protocol Header Struct

typedef struct smb_mailslot_header {

    uint16_t opcode;
    uint16_t priority;
    uint16_t mclass;
    uint16_t size;
    // unsigned char* mailslot_name, a string ending by null char

} __attribute__((packed)) smb_mailslot_header;



// BROWSER announcement packet struct

typedef struct browser_announcement_packet {


    uint8_t command;
    uint8_t update_cnt;
    uint64_t update_period;
    char host_name[BROWSER_HOSTNAME_LENGTH];
    uint16_t windows_ver;
    uint8_t os_maj_version;
    uint8_t os_min_version;
    uint64_t server_type;
    uint8_t browser_maj_ver;
    uint8_t browser_min_ver;
    uint16_t signature;

    // char* host_comment

} __attribute__((packed)) browser_announcement_packet;



// BROWSER Election Request packet struct

typedef struct browser_election_request_packet {

    uint8_t command;
    uint8_t election_ver;
    uint8_t election_desire;
    uint8_t browser_maj_ver;
    uint8_t browser_min_ver;
    uint8_t election_os;
    uint64_t uptime;

    // char* server_name


} __attribute__((packed)) browser_election_request_packet;



// CANON BJNP Protocol Packet struct (kinda weird this one )

typedef struct canon_bjnp_header {

    uint64_t id;
    uint8_t type;
    uint8_t code;
    uint64_t seq_nbr;
    uint16_t session_id;
    uint64_t payload_len;


} __attribute__((packed)) canon_bjnp_header;



// LLMNR Protocol Header Struct

typedef struct llmnr_header {

    uint16_t trans_id;
    uint16_t flags;
    uint16_t question;
    uint16_t answer_rr;
    uint16_t auth_rr;
    uint16_t adds_rr;

} __attribute__((packed)) llmnr_header;


/*********************************** OSI LAYER 7 PROTOCOL STRUCTS ***********************************/

// DNS PROTOCOL Header Struct

typedef struct dns_header {

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

} __attribute__((packed)) dns_header;


// NBNS Common Header Struct

typedef struct nbns_header {

    uint8_t trans_id;
    uint8_t response    : 1;
    uint8_t opcode      : 4;
    uint8_t res         : 1;
    uint8_t trunc       : 1;
    uint8_t recursion   : 1;
    uint8_t broadcast   : 4;
    uint8_t padding     : 4;
    uint16_t questions;
    uint16_t answer_rr;
    uint16_t auth_rr;
    uint16_t adds_rr;

} __attribute__((packed)) nbns_header;


/************************************* Functions declarations *************************************/


// Usefull generic functions

int print_devices_list(uint8_t);
char* get_readable_device_flags(int);
int get_random_device(char*);

uint16_t in_cksum(uint16_t*, int);
void print_info_packet(unsigned int);

void print_char_to_hex(unsigned char*, int, int);
void print_data(unsigned char*, int);


// ---------------- OSI Layer 2/3 Protocol Functions

void process_802_3_frame(unsigned char*, int);
void print_802_3_frame_header(unsigned char*);
void print_llc_header(unsigned char*, int*);

void process_ethernet_frame(unsigned char* , int, uint16_t, void (*)(unsigned char*, int));
void process_layer2_packet(unsigned char* , int, int);
void parse_bluetooth_packet(unsigned char*, int);

void print_attribute_protocol_packet(unsigned char*);

void print_hci_h4_header(unsigned char*);
void print_hci_h4_rem_name_request(unsigned char*);
void print_hci_h4_command_complete_header(unsigned char*);

void parse_bluetooth_smp_packet(unsigned char*, int);

void parse_acl_packet(unsigned char*, int);
void print_acl_packet_header(unsigned char*);
void print_ethernet_header(unsigned char*);
void print_linux_sll_header(unsigned char*);
void print_linux_ipmb_pseudo_header(unsigned char*, int);


// ---------------- OSI Layer 3 protocols functions

void print_vlan_ieee8021q_header(unsigned char*, int);
void print_homeplug_av_header(unsigned char*);
void print_homeplug_header(unsigned char*);
void print_ieee_1905_header(unsigned char*);
void print_lltd_header(unsigned char*);
void print_arp_header(unsigned char*);
void print_profinet_dcp_header(unsigned char*);
void print_icmp_packet(unsigned char* , int );
void print_igmp_header(unsigned char*, int);
void print_icmpv6_packet(unsigned char*, int, int);

void process_ip_packet(unsigned char* , int);
void print_ip_header(unsigned char* , int);
void print_ip6_header(unsigned char*, int);
void print_sctp_header(unsigned char*);


// ---------------- OSI Layer 4 protocol functions


void print_tcp_packet(unsigned char* , int);
void print_udp_packet(unsigned char* , int);


// ---------------- OSI Layer 5 protocol functions


void process_udp_encapsulation(unsigned char*, int, int, int);

void print_ntp_packet(unsigned char*, int);

// NETBIOS / SMB Protocols (tricky and smart DNS bypass which still works)

void print_netbios_datagram_header(unsigned char*, int, int);

void print_smb_header(unsigned char*, int, int);
void print_smb_command_trans_request(unsigned char*, int*);
void print_smb_mailslot_header(unsigned char*, int, int);
void print_microsoft_browser_packet(unsigned char*, int, int);
void print_browser_announcement_packet(unsigned char*, int, int);
void print_browser_election_request_packet(unsigned char*, int, int);
int extract_netbios_datagramm_name(unsigned char*, int*, char*);

// BJNP : the custom protocol protocol implemented by Canon to interact with Pixma devices (nice target to exploit)

void print_canon_bjnp_header(unsigned char*, int);


// ---------------- OSI Layer 7 protocol functions


void print_dns_packet(unsigned char*);
void print_nbns_header(unsigned char*);

// agressive sniffing TODO = active sniffing (ARP poisonning etc...)

#endif
