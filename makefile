CC=gcc

cocaine: 
	$(CC) -lm -lpcap -Wall -g src/sniff.c -o bin/cocaine
tests: cocaine 
	./bin/cocaine -i wlan0 -e "tcp && ip dst 188.165.216.142" -v -n > test/mytest &
	nc www.osgate.org 80 < test/cmd
	sleep 5
	pkill cocaine
	cat test/mytest
