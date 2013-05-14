#pragma once
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <net/if.h>

#define SERVER_NAME "lightweight4over6"

#define TUNNEL_SET_MAPPING    0x48
#define TUNNEL_DEL_MAPPING    0x49
#define TUNNEL_GET_MAPPING    0x50
#define TUNNEL_FLUSH_MAPPING  0x51
#define TUNNEL_MAPPING_NUM    0x52

struct Binding {
   struct in_addr addr_TI;
   struct in6_addr addr6_TI, addr6_TC;
   uint16_t pset_index, pset_mask; //port set
   uint32_t seconds;//lease time remaining
   uint64_t in_pkts, in_bytes;
   uint64_t out_pkts, out_bytes;
};

void insert(const Binding& record);
void remove(const Binding& record);
Binding* find(uint32_t ip, uint16_t port);

int binding_init();
int handle_binding();
