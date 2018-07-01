#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <string.h>
#include <unistd.h>
#include <inttypes.h>
#include <netinet/ip.h>

#include <net/if.h>  //estrutura ifr
#include <netinet/ether.h> //header ethernet
#include <netinet/in.h> //definicao de protocolos
#include <arpa/inet.h> //funcoes para manipulacao de enderecos IP
#include <linux/tcp.h>
#include <linux/udp.h>

#include <netinet/in_systm.h> //tipos de dados

#include "dhcp.h"

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
print_packet(struct ether_header* eh, struct ip* iphdr, struct tcphdr* th)
{
	fprintf(stderr, "----------------------------------------------\n");
	fprintf(stderr, "               ETHERNET\n");
	fprintf(stderr, "Destination Address: %x:%x:%x:%x:%x:%x\n", eh->ether_dhost[0],eh->ether_dhost[1],eh->ether_dhost[2],eh->ether_dhost[3],eh->ether_dhost[4],eh->ether_dhost[5]);
	fprintf(stderr, "     Source Address: %x:%x:%x:%x:%x:%x\n", eh->ether_shost[0],eh->ether_shost[1],eh->ether_shost[2],eh->ether_shost[3],eh->ether_shost[4],eh->ether_shost[5]);
	fprintf(stderr, "               Type: %" PRIu16 "\n\n", ntohs(eh->ether_type));
	fprintf(stderr, "                 IPV4\n");
	fprintf(stderr, "      Header length: %x\n", iphdr->ip_hl);
	fprintf(stderr, "            Version: %x\n", iphdr->ip_v);
	fprintf(stderr, "    Type of service: %x\n", iphdr->ip_tos);
	fprintf(stderr, "       Total length: %x\n", iphdr->ip_len);
	fprintf(stderr, "     Identification: %x\n", iphdr->ip_id);
	fprintf(stderr, "    Fragment offset: %x\n", iphdr->ip_off);
	fprintf(stderr, "       Time to live: %x\n", iphdr->ip_ttl);
	fprintf(stderr, "           Protocol: %x\n", iphdr->ip_p);
	fprintf(stderr, "           Checksum: %x\n", iphdr->ip_sum);
	fprintf(stderr, "          IP Source: %s\n", inet_ntoa(iphdr->ip_src));
	fprintf(stderr, "     IP Destination: %s\n\n", inet_ntoa(iphdr->ip_dst));
	fprintf(stderr, "                  TCP\n");
	fprintf(stderr, "             Source: %d\n", ntohs(th->source));
	fprintf(stderr, "               Dest: %d\n", ntohs(th->dest));
	fprintf(stderr, "                Seq: %x\n", ntohs(th->seq));
	fprintf(stderr, "            Ack Seq: %x\n", ntohs(th->ack_seq));
	fprintf(stderr, "        Data Offset: %x\n", ntohs(th->doff));
	fprintf(stderr, "           Reserved: %x\n", ntohs(th->res1));
	fprintf(stderr, "                cwr: %x\n", ntohs(th->cwr));
	fprintf(stderr, "                ece: %x\n", ntohs(th->ece));
	fprintf(stderr, "                urg: %x\n", ntohs(th->urg));
	fprintf(stderr, "                ack: %x\n", ntohs(th->ack));
	fprintf(stderr, "                psh: %x\n", ntohs(th->psh));
	fprintf(stderr, "                rst: %x\n", ntohs(th->rst));
	fprintf(stderr, "                syn: %x\n", ntohs(th->syn));
	fprintf(stderr, "                fin: %x\n", ntohs(th->fin));
	fprintf(stderr, "             Window: %x\n", ntohs(th->window));
	fprintf(stderr, "              Check: %x\n", ntohs(th->check));
	fprintf(stderr, "     Urgent Pointer: %x\n", ntohs(th->urg_ptr));
	fprintf(stderr, "----------------------------------------------\n");
	fprintf(stderr, "\n");
}

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
	/*w_iphdr->check = in_cksum((unsigned short *)header, sizeof(struct iphdr));*/

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
