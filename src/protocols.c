/**
 * Print simple information about IP protocol
 * @param unsigned char *packet a given packet
 */
void print_ip_simple(const unsigned char *packet){
	//point to IP header(14 ehternet)
	struct ip *ipheader = (struct ip *)(packet+14);

	char dst[INET_ADDRSTRLEN], src[INET_ADDRSTRLEN];

	inet_ntop(AF_INET, &ipheader->ip_src, src, INET_ADDRSTRLEN);
	inet_ntop(AF_INET, &ipheader->ip_dst, dst, INET_ADDRSTRLEN);

	printf("src ip %s ---> ",src);
	printf("dst ip %s\n",dst);
}

/**
 * Print full information about IP protocol
 * @param unsigned char *packet a given packet
 */
void print_ip_full(const unsigned char *packet){
	//point to IP header(14 ehternet)
	struct ip *ipheader = (struct ip *)(packet+14);

	char dst[INET_ADDRSTRLEN], src[INET_ADDRSTRLEN];

	inet_ntop(AF_INET, &ipheader->ip_src, src, INET_ADDRSTRLEN);
	inet_ntop(AF_INET, &ipheader->ip_dst, dst, INET_ADDRSTRLEN);

	printf("src ip %s ---> ",src);
	printf("dst ip %s\n",dst);
	printf("version %u\n",ipheader->ip_v);
	printf("tos %u\n",ipheader->ip_tos);
	printf("tot len %u\n",ntohs(ipheader->ip_len));
	printf("id %u\n",ntohs(ipheader->ip_len));
	printf("frag offset %u\n",ntohs(ipheader->ip_off));
	printf("ttl %d\n",ipheader->ip_ttl);
	printf("protocol %d\n",ipheader->ip_p);
	printf("check 0x%x\n\n",ntohs(ipheader->ip_sum));
}

/**
 * Print simple information about TCP protocol
 * @param unsigned char *packet a given packet
 */

void print_tcp_simple(const unsigned char *packet){
	//point to TCP header (14 ethernet + 20 IP)		
	struct tcphdr *tcpheader = (struct tcphdr *)(packet+34); 

	print_ip_simple(packet);
	printf("src port %d ---> dst port %d\n\n",ntohs(tcpheader->source),ntohs(tcpheader->dest));
}

/**
 * Print full information about TCP protocol
 * @param unsigned char *packet a given packet
 */
void print_tcp_full(const unsigned char *packet){
	//point to TCP header (14 ethernet + 20 IP)		
	struct tcphdr *tcpheader = (struct tcphdr *)(packet+34); 

	print_ip_simple(packet);
	printf("src port %d ---> dst port %d\n",ntohs(tcpheader->source),ntohs(tcpheader->dest));
	printf("seq num  %u      ack num  %u\n",ntohl(tcpheader->seq),ntohl(tcpheader->ack_seq));
	printf("FIN SYN RST PSH ACK URG\n");
	printf(" %d   %d   %d   %d   %d   %d\n", ntohs(tcpheader->fin) > 0 ? 1 : 0,ntohs(tcpheader->syn) > 0 ? 1 : 0,ntohs(tcpheader->rst) > 0 ? 1 : 0,ntohs(tcpheader->psh) > 0 ? 1 : 0,ntohs(tcpheader->ack) > 0 ? 1 : 0,ntohs(tcpheader->urg) > 0 ? 1 : 0);
	printf("window %u\n", ntohs(tcpheader->window));
	printf("checksum 0x%x\n", ntohs(tcpheader->check));
	printf("urg ptr %d\n\n", ntohs(tcpheader->urg_ptr));
}

/**
 * Print information about UDP protocol
 * @param unsigned char *packet a given packet
 */
void print_udp(const unsigned char *packet){
	//point to UDP header (14 ethernet + 20 IP)
	struct udphdr *udpheader = (struct udphdr *)(packet+34);

	print_ip_simple(packet);
	printf("src port %d ---> dst port %d\n", ntohs(udpheader->source), ntohs(udpheader->dest));
	printf("dgram len %d\n",ntohs(udpheader->len));
	printf("checksum  0x%x\n\n",ntohs(udpheader->check));
}

/**
 * Print information about ICMP protocol
 * @param unsigned char *packet a given packet
 */
void print_icmp(const unsigned char *packet){
	struct icmp *icmphdr = (struct icmp *)(packet+34);

	print_ip_simple(packet);
	printf("Type %u\t Code %u\t Checksum 0x%x\n\n", icmphdr->type, icmphdr->code, ntohs(icmphdr->checksum));
}

/**
 * Print information about ARP protocol
 * @param unsigned char *packet a given packet
 */
void print_arp(const unsigned char *packet){
	struct arp *arphdr = (struct arp *)(packet+14);
	int i;

	printf("Hardware type 0x%04x | Protocol type 0x%04x\n", ntohs(arphdr->hw_type), ntohs(arphdr->proto_type));
	printf("Hardware addr len %u | Protocol add len %u\n", arphdr->hlen, arphdr->plen);
	printf("Operation 0x%04x\n", ntohs(arphdr->operation));
	printf("Sender MAC: ");
	for(i = 0 ; i < 6 ; i++) printf("%02x:", arphdr->sha[i]);
	printf("\nSender IP: ");
	for(i = 0 ; i < 4 ; i++) printf("%u.", arphdr->spa[i]);
	printf("\nTarget MAC: ");
	for(i = 0 ; i < 6 ; i++) printf("%02x:", arphdr->tha[i]);
	printf("\nTarget IP: ");
	for(i = 0 ; i < 4 ; i++) printf("%u.", arphdr->tpa[i]);
	printf("\n\n");
}
