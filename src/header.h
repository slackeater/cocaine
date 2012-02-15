#define APPNAME "cocaine"
#define MAXCAPUTERBYTES 2048

int pktcount = 0, pkt_tot_size = 0;
time_t start_sniff;
char *view = "simple";
int compute_sum = 0;

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
