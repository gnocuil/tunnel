#include <linux/if_tun.h>
#include <net/if.h>
#include <errno.h>
#include <cstdio>
#include <fcntl.h>
#include <cstring>
#include <sys/ioctl.h>
#include <iostream>
#include <netinet/ip6.h>  
#include <fcntl.h>

#include "tun.h"
#include "binding.h"
#include "socket.h"

static int tun_fd;
static char buf[2000];

int tun_create(char *dev, int flags)
{
	struct ifreq ifr;
	int err;

	if ((tun_fd = open("/dev/net/tun", O_RDWR)) < 0) {
		fprintf(stderr, "tun_create: Error Creating TUN/TAP: %m\n", errno);
		return -1;
	}

	memset(&ifr, 0, sizeof(ifr));
	ifr.ifr_flags |= flags;

	if (*dev != '\0') {
		strncpy(ifr.ifr_name, dev, IFNAMSIZ);
	}

	if ((err = ioctl(tun_fd, TUNSETIFF, (void *)&ifr)) < 0) {
		fprintf(stderr, "tun_create: Error Setting tunnel name %s: %m\n", dev, errno);
		close(tun_fd);
		return -1;
	}
	if (fcntl(tun_fd, F_SETFL, O_NONBLOCK) < 0) {
		fprintf(stderr, "tun_create: Error Setting nonblock: %m\n", dev, errno);
		return -1;
	}
	strcpy(dev, ifr.ifr_name);

	return tun_fd;
}

int tun_send(char *packet, int len)
{
	int count = write(tun_fd, packet, len);
	return 0;
}

int handle_tun()
{
	printf("tun_fd=%d\n", tun_fd);
	uint16_t len = read(tun_fd, buf + 40, 2000);
	uint32_t ip = *(uint32_t*)(buf + 40 + 16);
	Binding* binding = find(ip, 0);
	if (!binding) {
		return 0;
	}
	printf("found!!!\n");
	struct ip6_hdr *ip6hdr = (struct ip6_hdr *)buf;
	ip6hdr->ip6_flow = htonl((6 << 28) | (0 << 20) | 0);		
	ip6hdr->ip6_plen = htons(len);
	ip6hdr->ip6_nxt = IPPROTO_IPIP;
	ip6hdr->ip6_hops = 128;
	memcpy(&(ip6hdr->ip6_src), &(binding->addr6_TC), sizeof(struct in6_addr));
	memcpy(&(ip6hdr->ip6_dst), &(binding->addr6_TI), sizeof(struct in6_addr));
	
	printf("tun_send!!!\n");
	socket_send(buf, len + 40);
}
