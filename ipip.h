#pragma once

#include <netinet/ip6.h> 

#include "encap.h"

class Encap_IPIP : public Encap {
public:
	const char* name() { return "IPIP"; }
	char* readbuf() {
		return buf + 40;
	}
	int readbuflen() {
		return BUF_LEN - 40;
	}
	char* sendbuf() {
		return buf;
	}
	int makepacket(int len) {
		uint32_t ip = *(uint32_t*)(buf + 40 + 16);
		Binding* binding = find(ip, getport_dest(buf + 40));
		if (!binding) {
			return -1;
		}
		struct ip6_hdr *ip6hdr = (struct ip6_hdr *)buf;
		ip6hdr->ip6_flow = htonl((6 << 28) | (0 << 20) | 0);		
		ip6hdr->ip6_plen = htons(len & 0xFFFF);
		ip6hdr->ip6_nxt = IPPROTO_IPIP;
		ip6hdr->ip6_hops = 128;
		memcpy(&(ip6hdr->ip6_src), &(binding->addr6_TC), sizeof(struct in6_addr));
		memcpy(&(ip6hdr->ip6_dst), &(binding->addr6_TI), sizeof(struct in6_addr));
		send_len = len + 40;
		return 0;
	}
	int init_socket() {
		raw_fd = socket(AF_INET6, SOCK_RAW, IPPROTO_IPIP);
		if (raw_fd < 0) {
			fprintf(stderr, "socket_init: Error Creating socket: %m\n", errno);
			return -1;
		}
		return raw_fd;
	}
	int handle_socket() {
		struct sockaddr_in6 sin6addr;
		socklen_t addr_len = sizeof (sin6addr);
		int len = recvfrom(raw_fd, buf4, BUF_LEN, 0, (struct sockaddr*)&sin6addr, &addr_len);
		send4_len = len;
		if (len < 0)
			return -1;
		return 0;
	}
	char* send4buf() {
		return buf4;
	}
private:
	char buf[BUF_LEN];
	char buf4[BUF_LEN];
	int raw_fd;
};
