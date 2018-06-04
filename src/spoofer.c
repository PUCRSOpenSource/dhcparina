#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/ether.h>
#include <linux/if_packet.h>
#include <arpa/inet.h>
#include <unistd.h>
#include "spoofer.h"

void
send_dhcp(unsigned char type)
{
	/*fill_ethernet();*/
	/*fill_ip();*/
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

	sendto(sock, (char *) buffer, sizeof(buffer), 0, (struct sockaddr*) &to, len);
	close(sock);
}
