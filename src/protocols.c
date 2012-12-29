/**
 * Print simple information about TCP protocol
 * @param unsigned char *packet a given packet
 */
void print_tcp_simple(const unsigned char *packet){
	struct tcphdr *tcp = (struct tcphdr *)(packet+34);
	printf("-------------------------\n");
	printf("src port %d ---> dst port %d\n\n",ntohs(tcp->source),ntohs(tcp->dest));
}

/**
 * Print full information about TCP protocol
 * @param unsigned char *packet a given packet
 */
void print_tcp_full(const unsigned char *packet){
	struct tcphdr *tcp = (struct tcphdr *)(packet+34);
	printf("-------------------------\n");
	printf("src port %d ---> dst port %d\n",ntohs(tcp->source),ntohs(tcp->dest));
	printf("seq num  %u, ack num  %u\n",ntohl(tcp->seq),ntohl(tcp->ack_seq));
	printf("flags [ %s   %s   %s   %s   %s   %s ]\n", ntohs(tcp->fin) > 0 ? "FIN" : "0",ntohs(tcp->syn) > 0 ? "SYN" : "0",ntohs(tcp->rst) > 0 ? "RST" : "0",ntohs(tcp->psh) > 0 ? "PSH" : "0",ntohs(tcp->ack) > 0 ? "ACK" : "0",ntohs(tcp->urg) > 0 ? "URG" : "0");
	printf("window %u\n", ntohs(tcp->window));
	printf("TCP checksum 0x%x\n", ntohs(tcp->check));
	printf("urg ptr %d\n\n", ntohs(tcp->urg_ptr));
}

/**
 * Print information about UDP protocol
 * @param unsigned char *packet a given packet
 */
void print_udp(const unsigned char *packet){
	struct udphdr *udp = (struct udphdr *)(packet+34);
	printf("-------------------------\n");
	printf("src port %d ---> dst port %d\n", ntohs(udp->source), ntohs(udp->dest));
	printf("dgram len %d\n",ntohs(udp->len));
	printf("UDP checksum  0x%x\n\n",ntohs(udp->check));
}

/**
 * Print information about ICMP protocol
 * @param unsigned char *packet a given packet
 */
void print_icmp(const unsigned char *packet){
	struct icmphdr *icmp = (struct icmphdr *)(packet+34);
	char *icmp_msg_string = "";
	printf("-------------------------\n");

	switch(icmp->type){
		case ICMP_ECHOREPLY:
			icmp_msg_string = "echo reply";
			break;
		case ICMP_DEST_UNREACH:
			icmp_msg_string = "dest unreachable";
			break;
		case ICMP_SOURCE_QUENCH:
			icmp_msg_string = "source quench";
			break;
		case ICMP_REDIRECT:
			icmp_msg_string = "redirect";
			break;
		case ICMP_ECHO:
			icmp_msg_string = "echo request";
			break;
		case ICMP_TIME_EXCEEDED:
			icmp_msg_string = "time exceeded";
			break;
		case ICMP_PARAMETERPROB:
			icmp_msg_string = "parameter problem";
			break;
		case ICMP_TIMESTAMP:
			icmp_msg_string = "timestamp request";
			break;
		case ICMP_TIMESTAMPREPLY:
			icmp_msg_string = "timestamp reply";
			break;
		case ICMP_INFO_REQUEST:
			icmp_msg_string = "information request";
			break;
		case ICMP_INFO_REPLY:
			icmp_msg_string = "information reply";
			break;
		case ICMP_ADDRESS:
			icmp_msg_string = "address mask request";
			break;
		case ICMP_ADDRESSREPLY:
			icmp_msg_string = "address mask reply";
			break;
	}

	printf("Type %u (%s)\n", icmp->type, icmp_msg_string);
	printf("Code %u\t Checksum 0x%x\n\n", icmp->code, ntohs(icmp->checksum));
}

/**
 * Print information about ARP protocol
 * @param unsigned char *packet a given packet
 */
void print_arp(const unsigned char *packet){
	struct arp *arphdr = (struct arp *)(packet+14);
	int i;

	printf("-------------------------\n");
	printf("Hardware type 0x%04x | Protocol type 0x%04x\n", ntohs(arphdr->hw_type), ntohs(arphdr->proto_type));
	printf("Hardware addr len %u | Protocol add len %u\n", arphdr->hlen, arphdr->plen);
	printf("Operation 0x%04x\n", ntohs(arphdr->operation));
	printf("Sender MAC: ");
	for(i = 0 ; i < 5 ; i++) printf("%02x:", arphdr->sha[i]);
	printf("%02x", arphdr->sha[5]);

	printf("\nSender IP: ");
	for(i = 0 ; i < 3 ; i++) printf("%u.", arphdr->spa[i]);
	printf("%u", arphdr->spa[3]);

	printf("\nTarget MAC: ");
	for(i = 0 ; i < 5 ; i++) printf("%02x:", arphdr->tha[i]);
	printf("%02x", arphdr->sha[5]);

	printf("\nTarget IP: ");
	for(i = 0 ; i < 3 ; i++) printf("%u.", arphdr->tpa[i]);
	printf("%u", arphdr->tpa[3]);

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
			(view == 1) ? print_tcp_full(packet) : print_tcp_simple(packet);
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
	//char *dest_var;

	inet_ntop(AF_INET, &iphdr->ip_src, src, INET_ADDRSTRLEN);
	inet_ntop(AF_INET, &iphdr->ip_dst, dst, INET_ADDRSTRLEN);

	//resolveAddressToName(iphdr->ip_src.s_addr, dest_var);

	printf("-------------------------\nsrc ip %s ---> dst ip %s\n", src, dst);
	select_protocol(iphdr->ip_p, packet);
}

/**
 * Print full information about IP protocol
 * @param unsigned char *packet a given packet
 */
void print_ip_full(const unsigned char *packet){
	struct ip *iphdr = (struct ip *)(packet+14);
	char dst[INET_ADDRSTRLEN], src[INET_ADDRSTRLEN];
	char *checksum_correct = "(correct)", *protocol_string = "";
	//char *hostname =  "blabla";

	inet_ntop(AF_INET, &iphdr->ip_src, src, INET_ADDRSTRLEN);
	inet_ntop(AF_INET, &iphdr->ip_dst, dst, INET_ADDRSTRLEN);

	printf("src ip %s ---> ",src);
	printf("dst ip %s\n",dst);
	printf("version %u\t  \ttos %u\n",iphdr->ip_v, iphdr->ip_tos);
	printf("tot len %u\t  \tidentification %u\n",ntohs(iphdr->ip_len), ntohs(iphdr->ip_len));
	unsigned short fragment_offset = ntohs(iphdr->ip_off);
	printf("flags [ %s %s %s ] \n", (fragment_offset&IP_RF) != 0 ? "RF" : "0", fragment_offset&IP_DF ? "DF" : "0", fragment_offset&IP_MF ? "MF" : "0");
	printf("frag offset %u\t  \tttl %d\n",fragment_offset&IP_OFFMASK, iphdr->ip_ttl);

	switch(iphdr->ip_p){
		case IPPROTO_ICMP:
			protocol_string = "ICMP";
			break;
		case IPPROTO_TCP:
			protocol_string = "TCP";
			break;
		case IPPROTO_UDP:
			protocol_string = "UDP";
			break;
	}

	printf("protocol %d (%s)\t  \tIP checksum 0x%x",iphdr->ip_p, protocol_string, ntohs(iphdr->ip_sum));

	//if the -c option is specified
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
			(view == 1) ? print_ip_full(packet): print_ip_simple(packet);
			break;
		case ETHERTYPE_ARP:
			print_arp(packet);
			break;
	}

}
