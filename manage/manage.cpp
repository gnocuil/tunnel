#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <stddef.h>
#include <unistd.h>
#include <string>
#include <sstream>
#include <fstream>
#include <iostream>

#include "manage.h"

using namespace std;

static int init_fd()
{
	int fd;
	if ((fd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {  
		fprintf(stderr, "init_fd: failed to create socket: %m\n");
		return -1;
	}
    struct sockaddr_in serv_addr;
    memset((char *) &serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(8080);
    inet_aton("127.0.0.1", &serv_addr.sin_addr);
    if (connect(fd, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0) {
        perror("ERROR connecting");
        exit(0);
    }
    return fd;
}

int set_mapping(struct in_addr addr_TI, struct in6_addr addr6_TI, uint16_t pset_index, uint16_t pset_mask, struct in6_addr addr6_TC, uint32_t seconds)
{
	int fd = init_fd();
	if (fd < 0)
		return -1;
	struct Binding binding;
	memset(&binding, 0, sizeof(struct Binding));
	binding.addr_TI = addr_TI;
	binding.addr6_TI = addr6_TI;
	binding.addr6_TC = addr6_TC;
	binding.pset_index = pset_index;
	binding.pset_mask = pset_mask;
	binding.seconds = seconds;
	uint8_t command = TUNNEL_SET_MAPPING;
	write(fd, &command, 1);  
	write(fd, &binding, sizeof(struct Binding));
	close(fd);
	return 0;
}

int del_mapping(struct in_addr addr_TI, uint16_t pset_index, uint16_t pset_mask)
{
	int fd = init_fd();
	if (fd < 0)
		return -1;
	struct Binding binding;
	memset(&binding, 0, sizeof(struct Binding));
	binding.addr_TI = addr_TI;
	binding.pset_index = pset_index;
	binding.pset_mask = pset_mask;
	uint8_t command = TUNNEL_DEL_MAPPING;
	write(fd, &command, 1);  
	write(fd, &binding, sizeof(struct Binding));
	close(fd);
	return 0;
}

int display_tc_mapping_table()
{
	ostringstream sout;
	sout << "{\n";
	
	int fd = init_fd();
	if (fd < 0)
		return -1;
	uint8_t command = TUNNEL_GET_MAPPING;
	write(fd, &command, 1);
	uint32_t size;
	read(fd, &size, 4);
	printf("Number of records: %d\n", size);
	sout << "\"records\": " << size << ",\n";
	int i;
	char addr_TI[100] = {0};
	char addr6_TI[100] = {0};
	char addr6_TC[100] = {0};
	printf("%-16s%-40s%-40s%-15s%-15s%-15s\n", "TI IPv4 Addr", "TI IPv6 Addr", "TC IPv6 Addr", "Port Index", "Port Mask", "Time Remaining"); 
	sout << "\"table\": [\n";
	for (i = 0; i < size; ++i) {
		struct Binding binding;
		read(fd, &binding, sizeof(struct Binding));
		inet_ntop(AF_INET, (void*)&binding.addr_TI, addr_TI, 16);
		inet_ntop(AF_INET6, (void*)&binding.addr6_TI, addr6_TI, 48);
		inet_ntop(AF_INET6, (void*)&binding.addr6_TC, addr6_TC, 48);
		printf("%-16s%-40s%-40s0x%-15x0x%-15x%-15d\n", addr_TI, addr6_TI, addr6_TC, binding.pset_index, binding.pset_mask, binding.seconds); 
		
		sout << "  {\n";
		sout << "    \"ipv6-addr\": \"" << addr6_TI << "\",\n";
		sout << "    \"ipv4-addr\": \"" << addr_TI << "\",\n";
		sout << "    \"aftr-addr\": \"" << addr6_TC << "\",\n";
		sout << "    \"portset-index\": " << binding.pset_index << ",\n";
		sout << "    \"portset-mask\": " << binding.pset_mask << ",\n";
		sout << "    \"upstream-pkts\": " << binding.in_pkts << ",\n";
		sout << "    \"downstream-pkts\": " << binding.out_pkts << ",\n";
		sout << "    \"upstream-bytes\": " << binding.in_bytes << ",\n";
		sout << "    \"downstream-bytes\": " << binding.out_bytes << "\n";
		if (i+1==size)
            sout << "  }\n";
        else
            sout << "  },\n";
	}
	sout << "]\n";
	close(fd);
	sout << "}\n";
	
	//cout << sout.str();
	ofstream fout("binding.txt");
	fout << sout.str();
	
	return 0;
}

int del_all_mapping()
{
	int fd = init_fd();
	if (fd < 0)
		return -1;
	uint8_t command = TUNNEL_FLUSH_MAPPING;
	write(fd, &command, 1);
	close(fd);
	return 0;
}
