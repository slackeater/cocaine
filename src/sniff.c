#include <time.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <pcap.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <linux/udp.h>
#include <math.h>
#include "func.c"
#include "proto_headers.h"
#include "protocols.c"

#define MAXCAPUTERBYTES 2048

int pktcount = 0, pkt_tot_size = 0;
time_t start_sniff;

void sighandler(int signum, siginfo_t *info, void *ptr){
	printf("\nTime elapsed:\t%.0f seconds\n", difftime(time(NULL), start_sniff));
	printf("Total number of packet sniffed:\t%d\n", pktcount);
	printf("Total size of packet sniffed:\t%d KB\n", pkt_tot_size);
	exit(1);
}


int main(int argc, char *argv[]){
	int c, mode = 1; //default promiscous
	char *interface = NULL, *protocol = NULL, *view = "simple";
	bpf_u_int32 netaddr=0, mask=0;
	struct bpf_program filter;
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *descr = NULL;
	struct pcap_pkthdr pkthdr;
	const unsigned char *packet= NULL;
	struct sigaction act;
	start_sniff = time(NULL); //start sniff time

	//set sigaction values
	act.sa_sigaction = sighandler;
	act.sa_flags = SA_SIGINFO;

	//options management
	while((c = getopt(argc,argv,"m:hi:p:v:")) != -1){
		switch(c){
			case 'i':
				interface = optarg;
				break;
			case 'm':
				mode = atoi(optarg);
				break;
			case 'p':
				protocol = optarg;
				break;
			case 'v':
				view = optarg;
				break;	
			case 'h':
				help(argv);
				break;
		}
	}

	//start sniffing
	if(protocol != NULL && interface != NULL){
		descr = pcap_open_live(interface, MAXCAPUTERBYTES, mode, 512, errbuf);

		pcap_lookupnet(interface,&netaddr,&mask,errbuf);

		pcap_compile(descr, &filter, protocol,1,mask);

		pcap_setfilter(descr,&filter);
		sigaction(SIGINT, &act, NULL);

		while(1){
			packet = pcap_next(descr,&pkthdr);

			if(packet != NULL){
				printf("Packet #: %d - Packet size: %d KB - %s", ++pktcount, pkthdr.len, ctime(&pkthdr.ts.tv_sec));
				pkt_tot_size += pkthdr.len;

				if(strcmp(protocol,"tcp") == 0)
					strcmp("full", view) == 0 ? print_tcp_full(packet) : print_tcp_simple(packet);
				else if(strcmp(protocol,"udp") == 0)
					print_udp(packet);
				else if(strcmp(protocol,"ip") == 0)
					strcmp("full", view) == 0 ? print_ip_full(packet) : print_ip_simple(packet);
				else if(strcmp(protocol,"icmp") == 0)
					print_icmp(packet);
				else if(strcmp(protocol,"arp") == 0)
					print_arp(packet);
			}
		}
	}
	else{
		fprintf(stderr,"Please choose an interface and a protocol\n");
	}

	return 0;
}
