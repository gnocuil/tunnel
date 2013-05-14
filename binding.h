#pragma once
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <net/if.h>

#define SERVER_NAME "lightweight4over6"

struct Binding {
   struct in_addr remote;
   struct in6_addr remote6,local6;
   uint16_t pset_index, pset_mask; //port set
   uint32_t seconds;//lease time remaining
   uint64_t in_pkts, inbound_bytes;
   uint64_t out_pkts, outbound_bytes;
};

void insert(const Binding& record);
Binding* find(uint32_t ip, uint16_t port);

int binding_init();
