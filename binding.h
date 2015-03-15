#pragma once
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <string>
#include <boost/shared_ptr.hpp>

#define TUNNEL_SET_MAPPING	 0x18
#define TUNNEL_DEL_MAPPING	 0x19
#define TUNNEL_GET_MAPPING	 0x1a
#define TUNNEL_FLUSH_MAPPING  0x1b
#define TUNNEL_MAPPING_NUM	 0x1c

#define BPS_SECONDS 5

struct Binding {
	struct in_addr addr_TI;
	struct in6_addr addr6_TI, addr6_TC;
	uint16_t pset_index, pset_mask; //port set
	uint32_t seconds;//lease time remaining
	uint64_t in_pkts, in_bytes;//in:upstream, 4o6 in, v4 out
	uint64_t out_pkts, out_bytes;//out:downstream, v4 in, 4o6 out
    
    uint64_t in_bytes_cur[BPS_SECONDS];
    uint64_t out_bytes_cur[BPS_SECONDS];
    uint64_t in_bps, out_bps;
    
    //uint16_t bigpacket_6to4[65536];
    //uint16_t bigpacket_4to6[65536];
	
	Binding() {
        memset(&addr_TI, 0, sizeof(addr_TI));
        memset(&addr6_TI, 0, sizeof(addr6_TI));
        memset(&addr6_TC, 0, sizeof(addr6_TC));
        pset_index = pset_mask = 0;
        seconds = 0;
        in_pkts = in_bytes = 0;
        out_pkts = out_bytes = 0;
        
        memset(in_bytes_cur, 0, sizeof(in_bytes_cur));
        memset(out_bytes_cur, 0, sizeof(out_bytes_cur));
        in_bps = out_bps = 0;
        //memset(bigpacket_6to4, 0, sizeof(bigpacket_6to4));
        //memset(bigpacket_4to6, 0, sizeof(bigpacket_4to6));
	}
    
    void count_4to6(int pkt4len) {
        ++out_pkts;
        out_bytes += pkt4len;
        out_bytes_cur[0] += pkt4len;
    }
    
    void count_6to4(int pkt6len) {
        ++in_pkts;
        in_bytes += pkt6len;
        in_bytes_cur[0] += pkt6len;
    }
	
};
typedef boost::shared_ptr<Binding> BindingPtr;

void insert(BindingPtr record);
void remove(const Binding& record);
BindingPtr find(uint32_t ip, uint16_t port);

int binding_init();
int handle_binding();

void binding_restore(std::string file);
void* timer(void* arg);
extern double current_time;//seconds