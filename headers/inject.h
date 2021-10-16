/********************** active sniffing TODO *****************************/

#ifndef INJECT_H
#define INJECT_H

#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>

#include "sock_utils.h"

// inject ARP poisoning packets

unsigned char* pack_arp_spoofing_packet(unsigned char*, unsigned char*, unsigned char*, unsigned char*,
    unsigned char*);

int get_device_index(int, const char*);
int init_sock(const char*, int*);

#endif