#include <cstdio>
#include <pcap.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <unistd.h>
#include "ethhdr.h"
#include "tcphdr.h"
#include "iphdr.h"
#include "main.h"

char *dev;
char *pattern;

uint16_t ip_check(uint16_t *buffer, int size){
	uint32_t sum = 0;

	if (size % 2 == 1)
		size += 1;

    for (int i = 0; i < size / 2; i++)
        sum += buffer[i];

	while (sum >> 16) {
		sum = (sum & 0xFFFF) + (sum >> 16);
	}

	return ((uint16_t)(~sum));
}

uint16_t tcp_check(uint16_t check1, uint16_t check2){
	uint32_t sum = check1 + check2;
	return ((sum & 0xffff) + (sum >> 16));
}

void redirect_packet(pcap_t *handle, const u_char *packet, int size, int res, int sockfd)
{
	EthIpTcpHdr	*ethIpTcpHdr = (EthIpTcpHdr *)packet;

	// eth header
    if (ethIpTcpHdr->ethHdr_.type() != EthHdr::Ip4) return;

	// ip header
    uint32_t ippkt_len = ntohs(ethIpTcpHdr->ipHdr_.total_len);
    if (ethIpTcpHdr->ipHdr_.proto != IpHdr::tcp) return;

	// tcp header
    uint32_t tcphdr_len = ethIpTcpHdr->tcpHdr_.th_off * 4;
    uint32_t tcpdata_len = ippkt_len - sizeof(IpHdr) - tcphdr_len;
    if (tcpdata_len == 0) return;
		
	char *data = (char*)(packet + sizeof(EthHdr) + sizeof(IpHdr) + tcphdr_len);
	if(strstr(data, pattern) == NULL) return;

	// Forward Packet
	EthIpTcpHdr* forward_packet = (EthIpTcpHdr *)malloc(sizeof(EthIpTcpHdr));
	memcpy(forward_packet, packet, sizeof(EthIpTcpHdr));

	PseudoHdr* pseudoHdr;
	pseudoHdr = (PseudoHdr *)malloc(sizeof(PseudoHdr));
	memset(pseudoHdr, 0, sizeof(PseudoHdr));
	pseudoHdr->src_addr = ethIpTcpHdr->ipHdr_.sip_;
	pseudoHdr->dst_addr = ethIpTcpHdr->ipHdr_.dip_;
	pseudoHdr->protocol = ethIpTcpHdr->ipHdr_.proto;
	pseudoHdr->tcp_len = htons(sizeof(TcpHdr));

	forward_packet->ipHdr_.total_len = htons(sizeof(IpHdr) + tcphdr_len);
	forward_packet->ipHdr_.check = ip_check((uint16_t*)&forward_packet->ipHdr_, sizeof(IpHdr));
		
	forward_packet->tcpHdr_.flags = TH_RST | TH_ACK;
	forward_packet->tcpHdr_.th_off = (sizeof(TcpHdr) / 4);
	forward_packet->tcpHdr_.check = tcp_check(ip_check((uint16_t*)&forward_packet->tcpHdr_, sizeof(TcpHdr)), ip_check((uint16_t*)pseudoHdr, sizeof(PseudoHdr)));

	if (pcap_sendpacket(handle, reinterpret_cast<const u_char*>(forward_packet), sizeof(EthIpTcpHdr))) 
		printf("pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));

	// backward packet
	EthIpTcpHdr* backward_packet = (EthIpTcpHdr *)malloc(sizeof(EthIpTcpHdr) + sizeof(REDIRECT_MSG));
	if (backward_packet == NULL) {
	    perror("malloc failed");
    	close(sockfd);
	    free(forward_packet);
    	free(pseudoHdr);
    	return;
	}
	memcpy(backward_packet, packet, sizeof(EthIpTcpHdr));

	pseudoHdr->src_addr = ethIpTcpHdr->ipHdr_.dip_;
	pseudoHdr->dst_addr = ethIpTcpHdr->ipHdr_.sip_;
	pseudoHdr->tcp_len = htons(sizeof(TcpHdr) + sizeof(REDIRECT_MSG));

	backward_packet->ethHdr_.dmac_ = ethIpTcpHdr->ethHdr_.smac_;
	backward_packet->ethHdr_.smac_ = ethIpTcpHdr->ethHdr_.dmac_;

	backward_packet->ipHdr_.total_len = htons(sizeof(IpHdr) + sizeof(TcpHdr) + sizeof(REDIRECT_MSG));
	backward_packet->ipHdr_.ttl = 128;
	backward_packet->ipHdr_.sip_ = ethIpTcpHdr->ipHdr_.dip_;
	backward_packet->ipHdr_.dip_ = ethIpTcpHdr->ipHdr_.sip_;
	backward_packet->ipHdr_.check = 0;
	backward_packet->ipHdr_.check = ip_check((uint16_t*)&backward_packet->ipHdr_, sizeof(IpHdr));

	backward_packet->tcpHdr_.sport = ethIpTcpHdr->tcpHdr_.dport;
	backward_packet->tcpHdr_.dport = ethIpTcpHdr->tcpHdr_.sport;
	backward_packet->tcpHdr_.acknum = htonl(ntohl(ethIpTcpHdr->tcpHdr_.seqnum) + tcpdata_len);
	backward_packet->tcpHdr_.seqnum = ethIpTcpHdr->tcpHdr_.acknum;
	backward_packet->tcpHdr_.flags = TH_ACK | TH_FIN;
	backward_packet->tcpHdr_.th_off = 5;
	backward_packet->tcpHdr_.check = 0;

	memcpy((char *)backward_packet + sizeof(EthIpTcpHdr), REDIRECT_MSG, sizeof(REDIRECT_MSG));
	backward_packet->tcpHdr_.check = tcp_check(ip_check((uint16_t*)&backward_packet->tcpHdr_, sizeof(TcpHdr) + sizeof(REDIRECT_MSG)), ip_check((uint16_t*)pseudoHdr, sizeof(PseudoHdr)));

	struct sockaddr_in sockaddr;
	sockaddr.sin_family = AF_INET;
	sockaddr.sin_port = ethIpTcpHdr->tcpHdr_.sport;
	sockaddr.sin_addr.s_addr = ethIpTcpHdr->ipHdr_.sip_;

	if (sendto(sockfd, &backward_packet->ipHdr_, sizeof(IpHdr) + sizeof(TcpHdr) + sizeof(REDIRECT_MSG), 0, (struct sockaddr *)&sockaddr, sizeof(sockaddr)) < 0)
    	perror("sendto Error");

	free(backward_packet);

	close(sockfd);

	free(forward_packet);
	free(pseudoHdr);
}

int main(int argc, char* argv[]){
	if(argc != 3){
		usage();
		return -1;
	}

	dev = argv[1];
	pattern = argv[2];
	char errbuf[PCAP_ERRBUF_SIZE];

	pcap_t* handle = pcap_open_live(dev, BUF_SIZE, 1, 1, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "Couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}

	int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
	if(sockfd < 0){
		perror("socket Error");
		return -1;
	}

	int on = 1;
	if(setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on)) < 0){
		perror("Could not set socket option");
		return -1;
	}

	while(true){
		struct pcap_pkthdr* header;
		const u_char* packet;

		int res = pcap_next_ex(handle, &header, &packet);

		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
			break;
		}

		redirect_packet(handle, packet, header->caplen, res, sockfd);
	}
}