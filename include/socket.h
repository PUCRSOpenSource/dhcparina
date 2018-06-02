#pragma once

#include <net/if.h>
#define BUFFSIZE 1518

unsigned char buffer[BUFFSIZE];
char* IF_NAME;
char *ip_str;
int ip_int;
int sockd;
char *hostname;
struct ifreq ifr;
struct ifreq mac_address;
struct ifreq ip_address;
struct ether_header* eth_header;
struct iphdr* ip_header;
struct tcphdr* tcp_header;
struct udphdr* udp_header;
struct icmphdr* icmp_header;
struct dhcp_packet* dhcp_header;

void setup();
int start(int argc, char* argv[]);
