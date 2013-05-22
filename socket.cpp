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
#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>

#include "socket.h"
#include "tun.h"

static int raw_fd;
static int send6_fd;
static int send4_fd;
static char buf[2000];

int socket_init()
{
	//raw_fd = socket(AF_PACKET, SOCK_DGRAM, htons(ETH_P_ALL));
	raw_fd = socket(AF_INET6, SOCK_RAW, IPPROTO_IPIP);
	
	if (raw_fd < 0) {
		fprintf(stderr, "socket_init: Error Creating socket: %m\n", errno);
		return -1;
	}
	
//	if (fcntl(raw_fd, F_SETFL, O_NONBLOCK) < 0) {i
//		fprintf(stderr, "socket_init: Error Setting nonblock: %m\n", errno);
//		return -1;
//	}
/*	
	send4_fd = socket(PF_INET, SOCK_RAW, IPPROTO_RAW);
	if (send4_fd < 0) {
		fprintf(stderr, "socket_init : Error Creating send4 socket: %m\n", errno);
		return -1;
	}
*/
	return raw_fd;
}

int socket_init_tun()
{
	send6_fd = socket(PF_INET6, SOCK_RAW, IPPROTO_RAW);
	if (send6_fd < 0) {
		fprintf(stderr, "socket_init: Error Creating send socket: %m\n", errno);
		return -1;
	}
}

int handle_socket()
{
	struct sockaddr_in6 sin6addr;
	socklen_t addr_len = sizeof (sin6addr);
	int len = recvfrom(raw_fd, buf, 2000, 0, (struct sockaddr*)&sin6addr, &addr_len);
	if (len < 0)
		return 0;
/*
puts("handle_socket!");
	static long long sum = 0;
	static int count = 0;
	sum += len;
	++count;
//	if (count % 1000 == 0) printf("socket: read %d packets %lld bytes\n", count, sum);
*/
//	printf("socket: read %d bytes\n", len);
	//sin6addr.sin6_addr is the IPv6 addr of TI (struct in6_addr)
	//socket_send4(buf, len);
	tun_send(buf, len);
}
/*
int socket_send4(char *buf, int len)
{
	struct sockaddr_in dest;
	memset(&dest, 0, sizeof(dest));
	dest.sin_family = AF_INET;
	memcpy(&dest.sin_addr, buf + 16, 4);
	if (sendto(send4_fd, buf, len, 0, (struct sockaddr *)&dest, sizeof(dest)) < 0) {
		fprintf(stderr, "socket_send4: Failed to send ipv4 packet len=%d: %m\n", len, errno);
		return -1;
	}
	return 0;
}
*/

int socket_send(char *buf, int len)
{
	struct sockaddr_in6 dest;
	memset(&dest, 0, sizeof(dest));
	dest.sin6_family = AF_INET6;
	memcpy(&dest.sin6_addr, buf + 24, 16);
	
	if (sendto(send6_fd, buf, len, 0, (struct sockaddr *)&dest, sizeof(dest)) != len) {
		fprintf(stderr, "socket_send: Failed to send ipv6 packet len=%d: %m\n", len, errno);
		//for (int i = 0; i < len; ++i) printf("%d:%x ", i + 1, buf[i] & 0xFF);printf("\n");
		return -1;
	}
	return 0;
}
