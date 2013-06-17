#pragma once

#include <netinet/icmp6.h>  

#include "encap.h"

struct IPv6_psedoheader {
    uint8_t srcaddr[16];
    uint8_t dstaddr[16];
    uint32_t length;
    uint16_t zero1;
    uint8_t zero2;
    uint8_t next_header;
};

class Encap_ICMP : public Encap {
public:
	const char* name() { return "ICMP"; }
	char* readbuf() {
		return buf + 40 + 8;
	}
	int readbuflen() {
		return BUF_LEN - 40 - 8;
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
		
		struct icmp6_hdr *icmp6hdr = (struct icmp6_hdr*)(buf + 40);
		icmp6hdr->icmp6_type = ICMP6_ECHO_REQUEST;
		icmp6hdr->icmp6_code = 0;
		icmp6hdr->icmp6_cksum = 0;
		icmp6hdr->icmp6_id = htons(0xFFFF);
		icmp6hdr->icmp6_seq = htons(0xFFFF);
	
		struct ip6_hdr *ip6hdr = (struct ip6_hdr *)buf;
		ip6hdr->ip6_flow = htonl((6 << 28) | (0 << 20) | 0);		
		ip6hdr->ip6_plen = htons((len + 8) & 0xFFFF);
		ip6hdr->ip6_nxt = IPPROTO_ICMPV6;
		ip6hdr->ip6_hops = 128;
		memcpy(&(ip6hdr->ip6_src), &(binding->addr6_TC), sizeof(struct in6_addr));
		memcpy(&(ip6hdr->ip6_dst), &(binding->addr6_TI), sizeof(struct in6_addr));
		send_len = len + 40 + 8;

		checksum(len + 8);
		
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
		return -1;
	}
	char* send4buf() {
		return buf4;
	}
private:
	void checksum(int len) {//icmp len
		uint32_t checksum = 0;
		struct IPv6_psedoheader header;
		memcpy(header.srcaddr, buf + 24, 16);
		memcpy(header.dstaddr, buf + 8, 16);
		header.length = ntohs(len);
		header.zero1 = header.zero2 = 0;
		header.next_header = IPPROTO_ICMPV6;
		uint16_t *hptr = (uint16_t*)&header;
		int hlen = sizeof(header);
		while (hlen > 0) {
			checksum += *(hptr++);
			hlen -= 2;
		}

		uint16_t *uptr = (uint16_t*)(buf + 40);
		while (len > 1) {
			checksum += *(uptr++);
			len -= 2;
		}
		if (len) {
			checksum += (*((uint8_t*)uptr)) ;
		}
		do {
			checksum = (checksum >> 16) + (checksum & 0xFFFF);
		} while (checksum != (checksum & 0xFFFF));
		uint16_t ans = checksum;
		struct icmp6_hdr *icmp6hdr = (struct icmp6_hdr*)(buf + 40);
		icmp6hdr->icmp6_cksum = (~ans);
	}


	char buf[BUF_LEN];//receive IPv4 packet, send out IPv6 packet
	char buf4[BUF_LEN];//receive IPv6 packet, send out IPv4 packet
	int raw_fd;
};