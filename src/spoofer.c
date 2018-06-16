#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <net/if.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <linux/if_packet.h>
#include <arpa/inet.h>
#include <unistd.h>
#include "spoofer.h"
#include "checksum.h"

static void fill_ethernet()
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

void fill_ip()
{
	struct iphdr* header;
	header = (struct iphdr*) (send_buffer + sizeof(struct ether_header));

	//TODO: Change this to get correct ip from machine and fake ip for victim.
	char *dst_addr="192.168.1.120";

	header->ihl = 5;
	header->version = 4;
	header->tot_len = htons(336);
	header->ttl = 16;
	header->protocol = IPPROTO_UDP;
	header->saddr = inet_addr(ip_str);
	header->daddr = inet_addr(dst_addr);
	header->check = in_cksum((unsigned short *)header, sizeof(struct iphdr));
}

void
send_dhcp(unsigned char type)
{
	fill_ethernet();
	fill_ip();
	/*fill_udp();*/
	/*fill_dhcp(type);*/

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
	to.sll_ifindex = 2; // interface index on which packets will be sent
	size_t i;
	for ( i = 0; i < 6; i++)
	{
		addr[i] = eth_header->ether_shost[i];
	}

	memcpy (to.sll_addr, addr, 6);
	len = sizeof(struct sockaddr_ll);

	sendto(sock, (char *) send_buffer, sizeof(send_buffer), 0, (struct sockaddr*) &to, len);
	close(sock);
	printf("( ͡° ͜ʖ ͡°) Mandei o safado\n");
}
