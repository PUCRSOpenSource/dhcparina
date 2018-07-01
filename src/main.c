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
#define ETHER_TYPE_IPv4 0x0800

#define DEBUG 1

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
struct dhcp_packet* r_dhcp_header;

// Headers for accessing the write_buffer
struct ether_header* w_eh;
struct iphdr* w_iphdr;
struct udphdr* w_udp_header;
struct dhcp_packet* w_dhcp_header;

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
	r_dhcp_header = (struct dhcp_packet*) (read_buffer + (sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct udphdr)));


	//Setup access pointers for write_buffer
	w_eh = (struct ether_header*) write_buffer;
	w_iphdr = (struct iphdr*) (write_buffer + sizeof(struct ether_header));
	w_udp_header = (struct udphdr*) (write_buffer + (sizeof(struct ether_header) + sizeof(struct iphdr)));
	w_dhcp_header = (struct dhcp_packet*) (write_buffer + (sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct udphdr)));
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

	//Fill udp header
	w_udp_header->source = htons(67);
	w_udp_header->dest = htons(68);
	w_udp_header->len = htons(0x13c);
	w_udp_header->check = htons(0);

	//Fill dhcp header
	w_dhcp_header->op = 2;
	w_dhcp_header->htype = 1;
	w_dhcp_header->hlen = 6;
	w_dhcp_header->hops = 0;
	w_dhcp_header->xid = r_dhcp_header->xid;
	w_dhcp_header->secs = 0;
	w_dhcp_header->flags = 0;
	w_dhcp_header->ciaddr = r_dhcp_header->ciaddr;
	inet_aton(dst_addr, &w_dhcp_header->yiaddr);
	w_dhcp_header->siaddr = r_dhcp_header->siaddr;
	w_dhcp_header->giaddr = r_dhcp_header->giaddr;
	for (int i = 0; i < 6; i++)
	{
		w_dhcp_header->chaddr[i] = r_eh->ether_shost[i];
	}
	//Fill magic cookie
	w_dhcp_header->options[0] = 0x63;
	w_dhcp_header->options[1] = 0x82;
	w_dhcp_header->options[2] = 0x53;
	w_dhcp_header->options[3] = 0x63;
	//Fill message type
	w_dhcp_header->options[4] = 53;
	w_dhcp_header->options[5] = 1;
	w_dhcp_header->options[6] = 2; // will need to be parametrized later
	//Fill server identifier
	w_dhcp_header->options[7] = 54;
	w_dhcp_header->options[8] = 4;
	w_dhcp_header->options[9] = (ip_int >> 24) & 255;
	w_dhcp_header->options[10] = (ip_int >> 16) & 255;
	w_dhcp_header->options[11] = (ip_int >> 8) & 255;
	w_dhcp_header->options[12] = ip_int & 255;
	//Fill dhcp subnet mask
	w_dhcp_header->options[13] = 1;
	w_dhcp_header->options[14] = 4;
	w_dhcp_header->options[15] = 255;
	w_dhcp_header->options[16] = 255;
	w_dhcp_header->options[17] = 255;
	w_dhcp_header->options[18] = 0;
	//Fill dhcp address lease time
	w_dhcp_header->options[19] = 51;
	w_dhcp_header->options[20] = 4;
	w_dhcp_header->options[21] = 0;
	w_dhcp_header->options[22] = 1;
	w_dhcp_header->options[23] = 56;
	w_dhcp_header->options[24] = 128;
	//Fill dhcp router
	w_dhcp_header->options[25] = 3;
	w_dhcp_header->options[26] = 4;
	w_dhcp_header->options[27] = (ip_int >> 24) & 255;
	w_dhcp_header->options[28] = (ip_int >> 16) & 255;
	w_dhcp_header->options[29] = (ip_int >> 8) & 255;
	w_dhcp_header->options[30] = ip_int & 255;
	//Fill dhcp dns
	w_dhcp_header->options[31] = 6;
	w_dhcp_header->options[32] = 4;
	w_dhcp_header->options[33] = (ip_int >> 24) & 255;
	w_dhcp_header->options[34] = (ip_int >> 16) & 255;
	w_dhcp_header->options[35] = (ip_int >> 8) & 255;
	w_dhcp_header->options[36] = ip_int & 255;
	//Fill dhcp broadcast
	w_dhcp_header->options[37] = 28;
	w_dhcp_header->options[38] = 4;
	w_dhcp_header->options[39] = 255;
	w_dhcp_header->options[40] = 255;
	w_dhcp_header->options[41] = 255;
	w_dhcp_header->options[42] = 255;
	//Fill end =D
	w_dhcp_header->options[43] = 0xff;

#ifdef DEBUG
	FILE* f = fopen("write_buffer", "w");
	fwrite(write_buffer, sizeof(unsigned char) * BUFFSIZE, 1, f);
	fclose(f);
	system("od -Ax -tx1 -v write_buffer > wireshark");
#endif

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
