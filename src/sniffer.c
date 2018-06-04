#include <stdio.h>
#include <stdlib.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <string.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <unistd.h>
#include "sniffer.h"
#include "spoofer.h"

static void
process_dhcp(void)
{
	unsigned char* options = dhcp_header->options;
	int i = 4;
	while (1)
	{
		unsigned char type = options[i++];
		if (type == 255)
			break;
		unsigned char len = options[i++];
		if (type == 53)
		{
			if (options[i] == 1)
			{
				send_dhcp(2);
			}
			else
			{
				if (options[i] == 3)
				{
					send_dhcp(5);
				}
			}
		}
		if (type == 12)
		{
			hostname = malloc(len + 1);
			strcpy(hostname, (const char*) &options[i]);
			hostname[len] = '\0';
		}
		i += len;
	}
}

static void
process_udp(void)
{
	unsigned int port_dest = (unsigned int) ntohs(udp_header->dest);
	if (port_dest == 67)
		process_dhcp();
}

static void
process_ip(void)
{
	unsigned int ip_protocol = (unsigned int) ip_header->protocol;

	if (ip_protocol == 0x11)
	{
		printf("( ͡° ͜ʖ ͡°) It's UDP!!\n");
		process_udp();
	}
	else
	{
		if (ip_header->protocol == 6 && (ntohs(tcp_header->dest) == 80 || ntohs(tcp_header->dest) == 8080))
		{
			printf("( ͡° ͜ʖ ͡°) It's HTTP, duck yissss!!\n");
			/*char* http_header_start = (char*) (buffer + (sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct tcphdr)));*/
			/*parse_host_from_http(http_header_start);*/
		}
	}
}

static void
sniffer(void)
{
	while (1)
	{
		recv(sockd, (char*) &buffer, sizeof(buffer), 0x0);

		u_int16_t ether_type = ntohs(eth_header->ether_type);
		if (ether_type == 0x0800)
		{
			printf("┬┴┬┴┤ ͜ʖ ͡°) Got a sassy IP packet\n");
			process_ip();
		}
	}
}

void
setup(void)
{
	if ((sockd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0)
	{
		printf("Socket could not be created.\n");
		exit(1);
	}

	strcpy(ifr.ifr_name, IF_NAME);

	if (ioctl(sockd, SIOCGIFINDEX, &ifr) < 0)
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
	struct in_addr x =  ((struct sockaddr_in*)&ip_address.ifr_addr)->sin_addr;
	uint32_t y = x.s_addr;
	ip_int = htonl(y);
	ip_str = inet_ntoa(((struct sockaddr_in*)&ip_address.ifr_addr)->sin_addr);
}

int
start(int argc, char* argv[])
{

	if (argc <= 1)
	{
		printf("Format:           \n");
		printf("  ./main interface\n");
		return 0;
	}
	IF_NAME = argv[1];

	setup();
	sniffer();


	return 0;
}
