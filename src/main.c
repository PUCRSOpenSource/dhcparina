#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <string.h>
#include <unistd.h>
#include <inttypes.h>
#include <netinet/ip.h>
#include <net/if.h>  //ifr structure
#include <netinet/ether.h> //ethernet header
#include <netinet/in.h> //protocols definitions
#include <arpa/inet.h> //functions to work with IP addresses
#include <linux/tcp.h>
#include <linux/udp.h>
#include <netinet/in_systm.h> //data types

#include "dhcp.h"
#include "checksum.h"

#define BUFFSIZE 1518

/* Ethernet frame types */
#define ETHER_TYPE_IPv4 0x0800

unsigned char read_buffer[BUFFSIZE];
unsigned char write_buffer[BUFFSIZE];

int sockd;
struct ifreq ifr;
struct ifreq mac_address;
struct ifreq ip_address;
unsigned int ip_int;
char* ip_str;

// Headers for accessing the read_buffer
struct ether_header* r_eh;
struct iphdr* r_iphdr;
struct udphdr* r_udp_header;

// Headers for accessing the write_buffer
struct ether_header* w_eh;
struct iphdr* w_iphdr;
struct udphdr* w_udp_header;

void
setup(char* argv[])
{
	if ((sockd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0)
	{
		printf("Error when creating socket\n");
		exit(1);
	}

	// Set interface to promiscuous mode
	strcpy(ifr.ifr_name, argv[1]);
	if (ioctl(sockd, SIOCGIFINDEX, &ifr) < 0)
	{
		printf("error in ioctl!");
	}
	ioctl(sockd, SIOCGIFFLAGS, &ifr);
	ifr.ifr_flags |= IFF_PROMISC;
	ioctl(sockd, SIOCSIFFLAGS, &ifr);

	//Read mac address
	memset(&mac_address, 0x00, sizeof(mac_address));
	strcpy(mac_address.ifr_name, argv[1]);
	ioctl(sockd, SIOCGIFHWADDR, &mac_address);

	//Read and convert our IP to int and char[]
	strcpy(ip_address.ifr_name, argv[1]);
	ioctl(sockd, SIOCGIFADDR, &ip_address);
	struct in_addr aux_for_getting_ip =  ((struct sockaddr_in*) &ip_address.ifr_addr)->sin_addr;
	uint32_t aux_for_getting_ip_2 = aux_for_getting_ip.s_addr;
	ip_int = htonl(aux_for_getting_ip_2);
	ip_str = inet_ntoa(((struct sockaddr_in*) &ip_address.ifr_addr)->sin_addr);

	//Setup access pointers for read_buffer
	r_eh = (struct ether_header*) read_buffer;
	r_iphdr = (struct iphdr*) (read_buffer + sizeof(struct ether_header));
	r_udp_header = (struct udphdr*) (read_buffer + (sizeof(struct ether_header) + sizeof(struct iphdr)));

	//Setup access pointers for write_buffer
	w_eh = (struct ether_header*) write_buffer;
	w_iphdr = (struct iphdr*) (write_buffer + sizeof(struct ether_header));
	w_udp_header = (struct udphdr*) (write_buffer + (sizeof(struct ether_header) + sizeof(struct iphdr)));
}

int
sniff(void)
{
	while (1)
	{
		memset(read_buffer, 0, BUFFSIZE);
		recv(sockd, (char*) &read_buffer, sizeof(read_buffer), 0x0);

		uint16_t ethernet_type = ntohs(r_eh->ether_type);

		if (ethernet_type == ETHER_TYPE_IPv4)
		{
			if (r_iphdr->protocol == 17) // Check if it's UDP protocol
			{
				unsigned int port_dest = (unsigned int) ntohs(r_udp_header->dest);
				if (port_dest == 67)
				{
					fprintf(stderr, "Read a DHCP discover or request.\n");
					return 0;
				}
			}
		}
	}
	return 1;
}

int
send_dhcp_discover(char* dst_addr)
{
	fprintf(stderr, "Gonna build a DHCP offer!\n");
	memset(write_buffer, 0, BUFFSIZE);

	//Fill ethernet header
	w_eh->ether_type = htons(ETHER_TYPE_IPv4);
	for (int i = 0; i < 6; i++)
	{
		w_eh->ether_shost[i] = mac_address.ifr_hwaddr.sa_data[i];
		w_eh->ether_dhost[i] = r_eh->ether_shost[i];
	}

	//Fill ip header
	w_iphdr->ihl = 5;
	w_iphdr->version = 4;
	w_iphdr->tot_len = htons(336);
	w_iphdr->ttl = 16;
	w_iphdr->protocol = IPPROTO_UDP;
	w_iphdr->saddr = inet_addr(ip_str);
	w_iphdr->daddr = inet_addr(dst_addr);
	w_iphdr->check = in_cksum((unsigned short*) w_iphdr, sizeof(struct iphdr));

	return 0;
}

int
main(int argc, char* argv[])
{
	if (argc < 3)
	{
		printf("./main <interface_name> <ip_for_spoof>\n");
		return 1;
	}

	setup(argv);
	sniff();
	send_dhcp_discover(argv[2]);

	return 0;
}
