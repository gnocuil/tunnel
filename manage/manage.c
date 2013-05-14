#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <stddef.h>

#include "manage.h"

static int init_fd()
{
	int fd;
	struct sockaddr_un addr;
	size_t len;
	if ((fd = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {  
		fprintf(stderr, "init_fd: failed to create socket: %m\n", errno);
		return -1;
	}
	//name the socket
	addr.sun_family = AF_UNIX;
	strcpy(addr.sun_path, SERVER_NAME);
	addr.sun_path[0]=0;
	len = strlen(SERVER_NAME)  + offsetof(struct sockaddr_un, sun_path);
	int result = connect(fd, (struct sockaddr*)&addr, len);
	if (result < 0) {
		fprintf(stderr, "init_fd: failed to connect: %m\n", errno);
		return -1;
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
	int fd = init_fd();
	if (fd < 0)
		return -1;
	uint8_t command = TUNNEL_GET_MAPPING;
	write(fd, &command, 1);
	uint32_t size;
	read(fd, &size, 4);
	printf("Number of records: %d\n", size);
	int i;
	char addr_TI[100] = {0};
	char addr6_TI[100] = {0};
	char addr6_TC[100] = {0};
	printf("%-16s%-40s%-40s%-15s%-15s%-15s\n", "TI IPv4 Addr", "TI IPv6 Addr", "TC IPv6 Addr", "Port Index", "Port Mask", "Time Remaining"); 
	for (i = 0; i < size; ++i) {
		struct Binding binding;
		read(fd, &binding, sizeof(struct Binding));
		inet_ntop(AF_INET, (void*)&binding.addr_TI, addr_TI, 16);
		inet_ntop(AF_INET6, (void*)&binding.addr6_TI, addr6_TI, 48);
		inet_ntop(AF_INET6, (void*)&binding.addr6_TC, addr6_TC, 48);
		printf("%-16s%-40s%-40s0x%-15x0x%-15x%-15d\n", addr_TI, addr6_TI, addr6_TC, binding.pset_index, binding.pset_mask, binding.seconds); 
	}
	close(fd);
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
