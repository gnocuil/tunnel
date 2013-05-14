#ifndef __MANAGE_H__
#define __MANAGE_H__

#include <sys/types.h>
#include <arpa/inet.h>

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

int set_mapping(struct in_addr addr_TI, struct in6_addr addr6_TI, uint16_t pset_index, uint16_t pset_mask, struct in6_addr addr6_TC, uint32_t seconds);
int del_mapping(struct in_addr addr_TI, uint16_t pset_index, uint16_t pset_mask);
int display_tc_mapping_table();
int del_all_mapping();


#endif /* __MANAGE_H__ */
