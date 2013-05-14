#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>  
#include <netinet/udp.h> 
#include <string.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <errno.h>

#include "socket.h"

int socket_init()
{
	int fd = socket(AF_PACKET, SOCK_DGRAM, htons(ETH_P_ALL));
	if (fd < 0) {
		fprintf(stderr, "socket_init: Error Creating socket: %m\n", errno);
	}
	/*
	while (1) {
		char buf[2000] = {0};
		int len = recv(fd, buf, 2000, 0);
		printf("%d: ", len);
		for (int i = 0; i < 30; ++i) printf("%x ", buf[i] & 0xFF);
		printf("\n");
	}
	*/
	return fd;
}
