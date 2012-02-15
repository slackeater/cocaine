#include <time.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <pcap.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <netinet/ether.h>
#include <netinet/ip_icmp.h>
#include <net/if_arp.h>
#include <linux/udp.h>
#include <math.h>
#include <sys/types.h>
#include "header.h"
#include "func.c"
#include "protocols.c"

int main(int argc, char *argv[]){
	check_user();
	int c, mode = 1; //default promiscous mode with mode = 1
	char *interface = NULL, *expression;
	bpf_u_int32 netaddr=0, mask=0;
	struct bpf_program filter;
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *descr = NULL;
	struct pcap_pkthdr pkthdr;
	const unsigned char *packet= NULL;
	struct sigaction act;
	
	start_sniff = time(NULL); //start sniff time

	act.sa_sigaction = sighandler;
	act.sa_flags = SA_SIGINFO;

	//options management
	while((c = getopt(argc,argv,"m:hi:v:e:c::")) != -1){
		switch(c){
			case 'i':
				interface = optarg;
				break;
			case 'm':
				mode = atoi(optarg);
				break;
			case 'v':
				view = optarg;
				break;	
			case 'h':
				help();
				break;
			case 'e':
				expression = optarg;
				break;
			case 'c':
				compute_sum = 1;
				break;
		}
	}

	if(expression != NULL && interface != NULL){
		descr = pcap_open_live(interface, MAXCAPUTERBYTES, mode, 512, errbuf);

		if(descr == NULL){
			perror(errbuf);
			exit(1);
		}

		if(pcap_lookupnet(interface,&netaddr,&mask,errbuf) == -1){
			perror(errbuf);
			exit(1);
		}

		if(pcap_compile(descr, &filter, expression,1,mask) == -1){
			perror(pcap_geterr(descr));
			exit(1);
		}

		if(pcap_setfilter(descr,&filter) == -1){
			perror(pcap_geterr(descr));
			exit(1);
		}

		//action to bo taken when SIGINT occurs
		sigaction(SIGINT, &act, NULL);

		while(1){
			//get packet
			packet = pcap_next(descr,&pkthdr);

			if(packet != NULL){
				printf("Packet #: %d - Packet size: %d KB - %s", ++pktcount, pkthdr.len, ctime(&pkthdr.ts.tv_sec));
				pkt_tot_size += pkthdr.len;

				print_packet(packet);
		/*		if(strcmp(expression,"tcp") == 0)
					strcmp("full", view) == 0 ? print_tcp_full(packet) : print_tcp_simple(packet);
				else if(strcmp(expression,"udp") == 0)
					print_udp(packet);
				else if(strcmp(expression,"ip") == 0)
					strcmp("full", view) == 0 ? print_ip_full(packet) : print_ip_simple(packet);
				else if(strcmp(expression,"icmp") == 0)
					print_icmp(packet);
				else if(strcmp(expression,"arp") == 0)
					print_arp(packet);
					*/
			}
		}
	}
	else{
		fprintf(stderr,"Please choose an interface and a expression\n");
	}

	return 0;
}
