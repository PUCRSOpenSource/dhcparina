#include <stdio.h>
#include <stdlib.h>
#include <linux/udp.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <string.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <unistd.h>
#include "socket.h"

void
setup()
{
	if((sockd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0)
	{
		printf("Socket could not be created.\n");
		exit(1);
	}

	strcpy(ifr.ifr_name, IF_NAME);

	if(ioctl(sockd, SIOCGIFINDEX, &ifr) < 0)
	{
		printf("Error in ioctl!\n");
		exit(1);
	}

	eth_header  = (struct ether_header*) buffer;
	ip_header   = (struct iphdr*)   (buffer + sizeof(struct ether_header));
	tcp_header  = (struct tcphdr*)  (buffer + (sizeof(struct ether_header) + sizeof(struct iphdr)));
	udp_header  = (struct udphdr*)  (buffer + (sizeof(struct ether_header) + sizeof(struct iphdr)));
	dhcp_header = (struct dhcp_packet*)  (buffer + (sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct udphdr)));

	ioctl(sockd, SIOCGIFFLAGS, &ifr);
	ifr.ifr_flags |= IFF_PROMISC;
	ioctl(sockd, SIOCSIFFLAGS, &ifr);

	int fd;
	fd = socket(PF_INET, SOCK_DGRAM, 0);
	memset(&mac_address, 0x00, sizeof(mac_address));
	strcpy(mac_address.ifr_name, IF_NAME);
	ioctl(fd, SIOCGIFHWADDR, &mac_address);
	strcpy(ip_address.ifr_name, IF_NAME);
	ioctl(fd, SIOCGIFADDR, &ip_address);
	close(fd);
	struct in_addr x =  ((struct sockaddr_in *)&ip_address.ifr_addr)->sin_addr;
	uint32_t y = x.s_addr;
	ip_int = htonl(y);
	ip_str = inet_ntoa(((struct sockaddr_in *)&ip_address.ifr_addr)->sin_addr);
}

int
start(int argc, char* argv[])
{

	if(argc <= 1)
	{
		printf("Format:           \n");
		printf("  ./main interface\n");
		return 0;
	}
	IF_NAME = argv[1];

	setup();

	return 0;
}
