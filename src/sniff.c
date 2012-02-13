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
#include "header.h"
#include "func.c"
#include "protocols.c"

int main(int argc, char *argv[]){
	int c, mode = 1, err_check; //default promiscous mode with mode = 1
	char *interface = NULL, *protocol = NULL, *view = "simple";
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
				help();
				break;
		}
	}

	//start sniffing
	if(protocol != NULL && interface != NULL){
		descr = pcap_open_live(interface, MAXCAPUTERBYTES, mode, 512, errbuf);

		if(descr == NULL){
			perror(errbuf);
			exit(1);
		}

		err_check = pcap_lookupnet(interface,&netaddr,&mask,errbuf);

		if(err_check == -1){
			perror(errbuf);
			exit(1);
		}

		err_check = pcap_compile(descr, &filter, protocol,1,mask);

		if(err_check == -1){
			perror(pcap_geterr(descr));
			exit(1);
		}

		err_check = pcap_setfilter(descr,&filter);

		if(err_check == -1){
			perror(pcap_geterr(descr));
			exit(1);
		}

		//action to bo taken when SIGINT occurs
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
