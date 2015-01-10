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
#include "network.h"
#include "binding.h"

//static int raw_fd;
static int send6_fd;
static int send4_fd;
static char buf[2000];

int socket_init()
{
	int raw_fd = encap->init_socket();
	if (raw_fd < 0)
		return -1;
	
	return raw_fd;
}

int socket_init_tun()
{
	send6_fd = socket(PF_INET6, SOCK_RAW, IPPROTO_RAW);
	if (send6_fd < 0) {
		fprintf(stderr, "socket_init: Error Creating send socket: %m\n");
		return -1;
	}
}

static void count() {
    char *buf = encap->send4buf();
    int len = encap->send4len();
	uint32_t ip = *(uint32_t*)(buf + 12);
	Binding* binding = find(ip, getport_src(buf));
	if (!binding) {
		return;
	}
    binding->count_6to4(len);
}

int handle_socket()
{
	if (encap->handle_socket() < 0)
		return -1;
	count();	
	tun_send(encap->send4buf(), encap->send4len());
}

int socket_send(char *buf, int len)
{
	struct sockaddr_in6 dest;
	memset(&dest, 0, sizeof(dest));
	dest.sin6_family = AF_INET6;
	memcpy(&dest.sin6_addr, buf + 24, 16);
	
	if (sendto(send6_fd, buf, len, 0, (struct sockaddr *)&dest, sizeof(dest)) != len) {
		fprintf(stderr, "socket_send: Failed to send ipv6 packet len=%d: %m\n", len);
		//for (int i = 0; i < len; ++i) printf("%d:%x ", i + 1, buf[i] & 0xFF);printf("\n");
		return -1;
	}
	return 0;
}
