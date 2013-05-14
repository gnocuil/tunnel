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
#include "tun.h"

static int raw_fd;
static int send6_fd;
static char buf[2000];

int socket_init()
{
	raw_fd = socket(AF_PACKET, SOCK_DGRAM, htons(ETH_P_ALL));
	//raw_fd = socket(AF_PACKET, SOCK_DGRAM, IPPROTO_IPIP);
	
	if (raw_fd < 0) {
		fprintf(stderr, "socket_init: Error Creating socket: %m\n", errno);
		return -1;
	}
	
	send6_fd = socket(PF_INET6, SOCK_RAW, IPPROTO_RAW);
	if (send6_fd < 0) {
		fprintf(stderr, "socket_init: Error Creating send socket: %m\n", errno);
		return -1;
	}

	return raw_fd;
}

int handle_socket()
{
	int len = recv(raw_fd, buf, 2000, 0);
	if (buf[0] != 0x60)
		return 0;
	struct ip6_hdr *ip6hdr = (struct ip6_hdr *)buf;
	if (ip6hdr->ip6_nxt != IPPROTO_IPIP)
		return 0;
	
	printf("tun_send!!!\n");
	tun_send(buf + 40, len - 40);
}

int socket_send(char *buf, int len)
{
	struct sockaddr_in6 dest;
	dest.sin6_family = AF_INET6;
	memcpy(&dest.sin6_addr, buf + 24, 16);
	if (sendto(send6_fd, buf, len, 0, (struct sockaddr *)&dest, sizeof(dest)) < 0) {
		fprintf(stderr, "socket_send: Failed to send ipv6 packet: %m\n", errno);
		exit(1);
	}
}
