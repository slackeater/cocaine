/**
 * Print simple information about TCP protocol
 * @param unsigned char *packet a given packet
 */
void print_tcp_simple(const unsigned char *packet){
	struct tcphdr *tcp = (struct tcphdr *)(packet+34);

	printf("--------- TCP Header --------\n");
	printf("src port %d ---> dst port %d\n",ntohs(tcp->source),ntohs(tcp->dest));

	print_payload(packet);
}

/**
 * Print full information about TCP protocol
 * @param unsigned char *packet a given packet
 */
void print_tcp_full(const unsigned char *packet){
	struct tcphdr *tcp = (struct tcphdr *)(packet+34);
	printf("--------- TCP Header --------\n");
	printf("src port %d ---> dst port %d\n",ntohs(tcp->source),ntohs(tcp->dest));
	printf("seq num  %u, ack num  %u\n",ntohl(tcp->seq),ntohl(tcp->ack_seq));
	printf("flags [ %s   %s   %s   %s   %s   %s ]\n", ntohs(tcp->fin) > 0 ? "FIN" : "0",ntohs(tcp->syn) > 0 ? "SYN" : "0",ntohs(tcp->rst) > 0 ? "RST" : "0",ntohs(tcp->psh) > 0 ? "PSH" : "0",ntohs(tcp->ack) > 0 ? "ACK" : "0",ntohs(tcp->urg) > 0 ? "URG" : "0");
	printf("window %u\n", ntohs(tcp->window));
	printf("TCP checksum 0x%x\n", ntohs(tcp->check));
	printf("urg ptr %d\n\n", ntohs(tcp->urg_ptr));

	print_payload(packet);
}

/**
 * Print information about the DNS protocol
 * @param unsigned cahr *packet a given packet
 */
void print_dns(const unsigned char *packet){

	int question_size = 0;
	int offset = 0;
	struct dnshdr *dns = (struct dnshdr *)(packet+42);
	unsigned short int *type, *class, *data_length;
	unsigned short question_rr, answer_rr, authority_rr, additional_rr;
	unsigned char flags_bit[16];
	int i, cname_chars;

	printf("------- DNS --------\n\n");
	printf("Transaction ID: 0x%hx\n", ntohs(dns->trans_id));

	itob(flags_bit, 16, ntohs(dns->flags));

	printf("Flags: 0x%X (%s)\n", ntohs(dns->flags), flags_bit);

	question_rr = ntohs(dns->questions);
	answer_rr = ntohs(dns->answer_rr);
	authority_rr = ntohs(dns->authority_rr);
	additional_rr = ntohs(dns->additional_rr);

	if(question_rr > 0){
		printf("Questions Count: %hu\n", question_rr);
		printf("\t --> Name: ");	

		//54 is the beginning of the DNS section
		print_dns_name(packet, 54, &question_size);

		//printf("Question size: %d\n", question_size);

		type = (unsigned short int *)&packet[54+question_size];
		printf("\t --> Type: %hx\n", htons(*type));

		class = (unsigned short int *)&packet[54+question_size+2];

		printf("\t --> Class: %hx\n", htons(*class));

		//end of question section
		offset = 54+question_size+4;
	}

	if(answer_rr > 0){
		printf("Answer Count: %hu\n", answer_rr);

		for(i = 1 ; i <= answer_rr ; i++){

			printf("\n\t --> Name: ");

			if(packet[offset] == 0xc0){ //compression is used
			//	printf("INDEX %d\n", 42+packet[offset+1]);
				print_dns_name(packet, 42+packet[offset+1], &question_size);
			}

			type = (unsigned short *)&packet[offset+2];
			data_length = (unsigned short *)&packet[offset+10];

			printf("\t --> Type: %hx\n",htons(*type));
			printf("\t --> Class: %hx\n", htons(*(unsigned short *)&packet[offset+4])); 
			printf("\t --> TTL (seconds): %d\n", htonl(*(unsigned int *)&packet[offset+6])); 
			printf("\t --> Data length: %d\n", htons(*data_length)); 

			if(htons(*type) == 5){
				printf("\t --> Primaryname: ");
				int name_length = packet[offset+12];

				for(cname_chars = 1 ; cname_chars <= name_length ; cname_chars++)
					printf("%c", packet[offset+12+cname_chars]);

				printf(".");

				if(packet[offset+12+name_length+1] == 0xc0)
					print_dns_name(packet, 42+packet[offset+12+name_length+2], &question_size);
			}	
			else{
				printf("\t --> Addr: %d.%d.%d.%d\n\n", packet[offset+12],packet[offset+13],packet[offset+14],packet[offset+15]); 
			}

			offset += 12+htons(*data_length);

		}

		printf("\t Test: %x\n", packet[offset]);

	}

	if(authority_rr > 0){
		printf("Authority Count: %hu\n", ntohs(dns->authority_rr));
	}

	if(additional_rr > 0){
		printf("Additional Count: %hu\n", ntohs(dns->additional_rr));
	}
}

/**
 * Print information about UDP protocol
 * @param unsigned char *packet a given packet
 */
void print_udp(const unsigned char *packet){
	struct udphdr *udp = (struct udphdr *)(packet+34);
	printf("\n\n-------- UDP Header --------\n\n");
	printf("src port %d ---> dst port %d\n", ntohs(udp->source), ntohs(udp->dest));
	printf("dgram len %d\n",ntohs(udp->len));
	printf("UDP checksum  0x%x\n\n",ntohs(udp->check));

	if(ntohs(udp->source) == 53 || ntohs(udp->dest) == 53){
		print_dns(packet);
	}
}
/**
 * Print information about ICMP protocol
 * @param unsigned char *packet a given packet
 */
void print_icmp(const unsigned char *packet){
	struct icmphdr *icmp = (struct icmphdr *)(packet+34);
	char *icmp_msg_string = "";
	printf("-------- ICMP --------\n");

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

	printf("-------- ARP Header --------\n");
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
	char *src_name, *dst_name;

	if(resolve_name){
		src_name = malloc(MAX_HOST_NAME);
		dst_name = malloc(MAX_HOST_NAME);

		//try to get a name for the ip address
		resolve_address_to_name(iphdr->ip_src.s_addr, src_name);
		resolve_address_to_name(iphdr->ip_dst.s_addr, dst_name);

		printf("\n-------- IP Header --------\n\nsrc %s ---> dst %s", src_name, dst_name);

		free(src_name);
		free(dst_name);
	}
	else{
		//print IP directly
		inet_ntop(AF_INET, &iphdr->ip_src, src, INET_ADDRSTRLEN);
		inet_ntop(AF_INET, &iphdr->ip_dst, dst, INET_ADDRSTRLEN);

		printf("\n--------- IP Header --------\n\nsrc ip %s ---> dst ip %s", src, dst);
	}

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
	char *src_name, *dst_name;

	printf("\n-------- IP Header ---------\n\n");

	if(resolve_name){
		src_name = malloc(MAX_HOST_NAME);
		dst_name = malloc(MAX_HOST_NAME);

		//try to get a name for the ip address
		resolve_address_to_name(iphdr->ip_src.s_addr, src_name);
		resolve_address_to_name(iphdr->ip_dst.s_addr, dst_name);

		printf("src %s ---> ", src_name);		
		printf("dst %s", dst_name);		

		free(src_name);
		free(dst_name);
	}
	else{
		//print IP directly
		inet_ntop(AF_INET, &iphdr->ip_src, src, INET_ADDRSTRLEN);
		inet_ntop(AF_INET, &iphdr->ip_dst, dst, INET_ADDRSTRLEN);

		printf("src ip %s ---> ",src);
		printf("dst ip %s",dst);
	}

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
