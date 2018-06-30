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
#define ETHER_TYPE_IPv6 0x86DD

unsigned char buff[BUFFSIZE];

int sockd;
int on;
struct ifreq ifr;

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
		printf("Erro na criacao do socket.\n");
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
}

int
sniff(void)
{
	while (1)
	{
		memset(buff, 0, BUFFSIZE);
		recv(sockd,(char *) &buff, sizeof(buff), 0x0);

		struct ether_header* eh = (struct ether_header*) buff;
		uint16_t ethernet_type = ntohs(eh->ether_type);

		if (ethernet_type == ETHER_TYPE_IPv4)
		{
			struct ip* iphdr = (struct ip*) (buff + sizeof(struct ether_header));

			if (iphdr->ip_p == 17) // Check if it's UDP protocol
			{
				struct udphdr* udp_header = (struct udphdr*) (buff + (sizeof(struct ether_header) + sizeof(struct iphdr)));
				unsigned int port_dest = (unsigned int) ntohs(udp_header->dest);
				if (port_dest == 67)
				{
					fprintf(stderr, "UDP\n");
				}
			}
		}
	}
}

int
main(int argc, char* argv[])
{

	setup(argv);
	sniff();

	return 0;
}
