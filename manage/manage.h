#ifndef __MANAGE_H__
#define __MANAGE_H__

#include <sys/types.h>
#include <arpa/inet.h>
#include "../binding.h"

int set_mapping(struct in_addr addr_TI, struct in6_addr addr6_TI, uint16_t pset_index, uint16_t pset_mask, struct in6_addr addr6_TC, uint32_t seconds);
int del_mapping(struct in_addr addr_TI, uint16_t pset_index, uint16_t pset_mask);
int display_tc_mapping_table();
int del_all_mapping();


#endif /* __MANAGE_H__ */
