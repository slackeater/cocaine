#include <time.h>
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
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
#include <sys/socket.h>
#include <netdb.h>
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
	while((c = getopt(argc,argv,"m:hi:e:c::inv")) != -1){
		switch(c){
			case 'i':
				interface = optarg;
				break;
			case 'm':
				mode = atoi(optarg);
				break;
			case 'v':
				view = 1; //verbose
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
			case 'n':
				resolve_name = 1;
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
				printf("\033[0;34mPacket #: %d\033[0m - Packet size: %d Bytes - %s", ++pktcount, pkthdr.len, ctime(&pkthdr.ts.tv_sec));
				pkt_tot_size += pkthdr.len;
				
				print_packet(packet);
			}
		}
	}
	else{
		fprintf(stderr,"Please choose an interface and a expression\n");
	}

	return 0;
}
