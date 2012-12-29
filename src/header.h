#define APPNAME "cocaine"
#define MAXCAPUTERBYTES 2048
#define TRUE 1
#define FALSE !1

int pktcount = 0, pkt_tot_size = 0;
time_t start_sniff;
int view = 0; //simple per default
int compute_sum = 0;
int resolve_name = 0; //name resolution default disabled

/** Header for ARP */
struct arp {
	u_short hw_type;
	u_short proto_type;
	u_char hlen;
	u_char plen;
	u_short operation;
	u_char sha[6]; //sender MAC
	u_char spa[4]; //sender IP
	u_char tha[6]; //target MAC
	u_char tpa[4]; //target IP
};
