#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <errno.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define PROMISCUOUS 1
#define NONPROMISCUOUS 0

//ETHERNET header struct
struct ether_header* eh;

//IP header struct
struct ip* iph;

//TCP header struct
struct tcphdr* tcph;

void pcap_test(u_char *useless, const struct pcap_pkthdr *pkthdr,
					const u_char *packet)
{
	unsigned short ether_type;
	u_char* ether_smac;
	u_char* ether_dmac;
	char* ip_sip;
	char* ip_dip;
	u_int16_t tcp_sport;
	u_int16_t tcp_dport;
	int i;

	//get ethernet header 
	eh = (struct ether_header *)packet;

	//find ether_type, source & destination mac
	ether_type = ntohs(eh->ether_type);
	ether_smac = eh->ether_shost;
	ether_dmac = eh->ether_dhost;

	//print ethernet part
	printf("Ethernet Source mac : ");
	for(i=0;i<6;i++)
	{
		printf("%s%02x", (i==0)? "":"-", *(ether_smac++));
	}
	printf("\n");

	 printf("Ethernet Destination  mac : ");
	for(i=0;i<6;i++)
	{
		printf("%s%02x", (i==0)? "":"-", *(ether_dmac++));
	}
	printf("\n");

	//get IP header
	//to get it we have to add the size of ethernet header
	packet += sizeof(struct ether_header);

	//if IP packet
	if(ether_type == ETHERTYPE_IP)
	{
		//print IP part
		iph = (struct ip*)packet;
		ip_sip = inet_ntoa(iph->ip_src);
		ip_dip = inet_ntoa(iph->ip_dst);

		printf("Source IP : %s\n", ip_sip);
                printf("Destination IP : %s\n", ip_dip);

		//if TCP packet -> print TCP part
		if(iph->ip_p == IPPROTO_TCP)
		{
		tcph = (struct tcp*)(packet + iph->ip_hl*4);
		printf("TCP Src Port : %d\n", ntohs(tcph->source));
		printf("TCP Dst Port : %d\n", ntohs(tcph->dest));
		}



		//packet = packet +iph->ip_hl*4 + tcph->th_off*4;

		for(i=0;i<iph->ip_hl*4 + tcph->th_off*4;i++)
		{
			packet++;
		}
		for(i=0;i<6;i++)
			printf("%02x", *(packet++));

		printf("\n");
		}
	else
	{
		printf("NONE IP packet \n");
	}

}

int main(int argc, char **argv)
{
	char *dev;	//using network device
	char *net;	//network address
	char *mask;	//network mask address

	bpf_u_int32 netp;
	bpf_u_int32 maskp;

	char errbuf[PCAP_ERRBUF_SIZE];
	int ret;
	struct pcap_pkthdr hdr;
	struct in_addr net_addr, mask_addr;

	const u_char *packet;

	struct bpf_program fp;

	pcap_t *pcd;	//packet capture descriptor

	if(argc < 2 ){printf("argc wrong\n");exit(1);}

	//get using device
	dev = pcap_lookupdev(errbuf);
	if(dev == NULL)
	{
		printf("%s\n", errbuf);
		exit(1);
	}
	printf("DEVICE = %s\n", dev);

	//get network & mask info using dev
	ret = pcap_lookupnet(dev, &netp, &maskp, errbuf);
	if(ret == -1)
	{
		printf("%s\n", errbuf);
		exit(1);
	}

	//network & mask info to A.B.C.D form
	net_addr.s_addr = netp;
	net = inet_ntoa(net_addr);
	printf("NET : %s\n", net);

	mask_addr.s_addr = maskp;
	mask = inet_ntoa(mask_addr);
	printf("MSK : %s\n", mask);

	//packet capture for dev
	//make packet capture descriptor
	pcd = pcap_open_live(dev, BUFSIZ, PROMISCUOUS, -1, errbuf);
	if(pcd == NULL)
	{
		printf("%s\n", errbuf);
		exit(1);
	}

	//paket capture
	pcap_loop(pcd, atoi(argv[1]), pcap_test, NULL);
	return 0;
}
