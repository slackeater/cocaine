/**
 * Print simple information about TCP protocol
 * @param unsigned char *packet a given packet
 */
void print_tcp_simple(const unsigned char *packet){
	struct tcphdr *tcp = (struct tcphdr *)(packet+34);
	printf("src port %d ---> dst port %d\n\n",ntohs(tcp->source),ntohs(tcp->dest));
}

/**
 * Print full information about TCP protocol
 * @param unsigned char *packet a given packet
 */
void print_tcp_full(const unsigned char *packet){
	struct tcphdr *tcp = (struct tcphdr *)(packet+34);
	printf("src port %d ---> dst port %d\n",ntohs(tcp->source),ntohs(tcp->dest));
	printf("seq num  %u      ack num  %u\n",ntohl(tcp->seq),ntohl(tcp->ack_seq));
	printf("FIN SYN RST PSH ACK URG\n");
	printf(" %d   %d   %d   %d   %d   %d\n", ntohs(tcp->fin) > 0 ? 1 : 0,ntohs(tcp->syn) > 0 ? 1 : 0,ntohs(tcp->rst) > 0 ? 1 : 0,ntohs(tcp->psh) > 0 ? 1 : 0,ntohs(tcp->ack) > 0 ? 1 : 0,ntohs(tcp->urg) > 0 ? 1 : 0);
	printf("window %u\n", ntohs(tcp->window));
	printf("checksum 0x%x\n", ntohs(tcp->check));
	printf("urg ptr %d\n\n", ntohs(tcp->urg_ptr));

	//printf("Payload: %s\n",(packet+34+sizeof(struct tcphdr)));
}

/**
 * Print information about UDP protocol
 * @param unsigned char *packet a given packet
 */
void print_udp(const unsigned char *packet){
	struct udphdr *udp = (struct udphdr *)(packet+34);
	printf("src port %d ---> dst port %d\n", ntohs(udp->source), ntohs(udp->dest));
	printf("dgram len %d\n",ntohs(udp->len));
	printf("checksum  0x%x\n\n",ntohs(udp->check));
}

/**
 * Print information about ICMP protocol
 * @param unsigned char *packet a given packet
 */
void print_icmp(const unsigned char *packet){
	struct icmphdr *icmp = (struct icmphdr *)(packet+34);
	printf("Type %u\t Code %u\t Checksum 0x%x\n\n", icmp->type, icmp->code, ntohs(icmp->checksum));
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

/**
 * Select and call the function relative to the choosed protocol
 * @param u_int8_t ip_protocol the type of protocol that can be found 
 * in the protocol field of IP
 * @param const unsigned char *packet the captured packet
 */
void select_protocol(u_int8_t ip_protocol, const unsigned char *packet){
	switch(ip_protocol){
		case 1: 	//ICMP
			print_icmp(packet);
			break;
		case 6: 	//TCP
			(strcmp(view, "full") == 0) ? print_tcp_full(packet) : print_tcp_simple(packet);
			break;
		case 17: 	//UDP
			print_udp(packet);
			break;

	}
}

/**
 * Print simple information about IP protocol
 * @param unsigned char *packet a given packet
 */
void print_ip_simple(const unsigned char *packet){
	struct ip *iphdr = (struct ip *)(packet+14);
	char dst[INET_ADDRSTRLEN], src[INET_ADDRSTRLEN];

	inet_ntop(AF_INET, &iphdr->ip_src, src, INET_ADDRSTRLEN);
	inet_ntop(AF_INET, &iphdr->ip_dst, dst, INET_ADDRSTRLEN);

	printf("src ip %s ---> ",src);
	printf("dst ip %s\n",dst);
	
	select_protocol(iphdr->ip_p, packet);
}

/**
 * Print full information about IP protocol
 * @param unsigned char *packet a given packet
 */
void print_ip_full(const unsigned char *packet){
	struct ip *iphdr = (struct ip *)(packet+14);
	char dst[INET_ADDRSTRLEN], src[INET_ADDRSTRLEN];
	char *checksum_correct = "(correct)";

	inet_ntop(AF_INET, &iphdr->ip_src, src, INET_ADDRSTRLEN);
	inet_ntop(AF_INET, &iphdr->ip_dst, dst, INET_ADDRSTRLEN);

	printf("src ip %s ---> ",src);
	printf("dst ip %s\n",dst);
	printf("version %u\n",iphdr->ip_v);
	printf("tos %u\n",iphdr->ip_tos);
	printf("tot len %u\n",ntohs(iphdr->ip_len));
	printf("id %u\n",ntohs(iphdr->ip_len));
	printf("frag offset %u\n",ntohs(iphdr->ip_off));
	printf("ttl %d\n",iphdr->ip_ttl);
	printf("protocol %d\n",iphdr->ip_p);
	printf("IP checksum 0x%x",ntohs(iphdr->ip_sum));

	if(compute_sum && compute_checksum_ipv4(iphdr))
		printf(" %s\n", checksum_correct);
	else
		printf("\n");

	select_protocol(iphdr->ip_p, packet);
}


/**
 * Print the packets based on the applied filter
 * @param const unsigned char *packet the captured packet
 */
void print_packet(const unsigned char *packet){
	struct ether_header *ethhdr;
	ethhdr = (struct ether_header *)(packet);

	switch(htons(ethhdr->ether_type)){
		case ETHERTYPE_IP:
			(strcmp(view, "full") == 0) ? print_ip_full(packet) : print_ip_simple(packet);
			break;
		case ETHERTYPE_ARP:
			print_arp(packet);
			break;
	}	

}


