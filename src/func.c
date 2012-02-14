/**
 * Print statistics on CTRL+C
 * @param int signum the number of the signal
 * @param siginfo_t *info the address to the siginfo_t structure
 * @param void *ptr null
 */
void sighandler(int signum, siginfo_t *info, void *ptr){
	printf("\nTime elapsed:\t%.0f seconds\n", difftime(time(NULL), start_sniff));
	printf("Total number of packet sniffed:\t%d\n", pktcount);
	printf("Total size of packet sniffed:\t%d Bytes\n", pkt_tot_size);
	exit(1);
}

/**
 * Print the help
 */
void help(){
	printf("Usage: %s -i <interface> -p <protocol> -m <mode> -v <type>\n",APPNAME);
	printf("-i\tthe network interface used to listen\n");
	printf("-p\tthe protocol to sniff (tcp, udp, ip, icmp, arp)\n");
	printf("-m\tif set to 0 enable promiscous mode (default), 1 to disable\n");
	printf("-v\tview mode, if \"full\" is specified, more information about the packet will print.\n\tWorks only with some protocols. Default \"simple\".\n");
	exit(1);
}

/**
 * Check the user
 */
void check_user(){
	if(getuid() != 0){
		printf("You must be root run in order to run %s.\n", APPNAME);
		exit(1);
	}
}
