/*char *ip_to_string(unsigned int ip){
	double power = 0, num = 0;
	static char ipDotted[15] = "0.0.0.0";
	int i,octet[4],octCount = 3;
	unsigned int tmp_ip = ip;

	for(i = 0 ; i <= 32 ; i++, power++, tmp_ip /= 2){
		if(i != 0 && ((i % 8) == 0)){
			octet[octCount] = (int)num;
			num = power = 0;
			octCount--;
		}

		if((tmp_ip % 2) == 1)
			num += pow(2,power);
	}

	sprintf(ipDotted,"%d.%d.%d.%d",octet[0],octet[1],octet[2],octet[3]);
	return ipDotted;
}*/

void help(char *argv[]){
	printf("Usage: %s -i <interface> -p <protocol> -m <mode>\n",argv[0]);
	printf("-i the network interface used to listen\n");
	printf("-p the protocol to sniff\n");
	printf("-m if set to 0 enable promiscous mode (default), 1 to disable\n");
}
