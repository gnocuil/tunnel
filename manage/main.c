#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <errno.h>
#include <time.h>
#include <memory.h>

void usage()
{
	printf("Usage: manage -a,--add <TI_IPv6> <TI_IPv4> <PortSet_index_hex> <PortSet_mask_hex> <TC_IPv6> <time_remaining_sec>\n");
	printf("              -d,--del <TI_IPv4> <PortSet_index> <PortSet_mask>\n");
	printf("              -s,--show\n");
	printf("              -f,--flush\n");
	printf("Example: manage -a 2001::2 192.168.1.2 0x0800 0xf800 2001::1 3600\n");
	printf("         manage --del 192.168.1.2 0x0800 0xf800\n");
	exit(1);
}

int main(int argc,char *argv[])
{
	struct in_addr addr_TI;
	struct in6_addr addr6_TI, addr6_TC;
	unsigned index, seconds;
	unsigned short pset_index, pset_mask;

	if (argc <= 1)
		usage();
	for (index = 1; index < argc; ++index) {
		if (strcmp(argv[index],"-a") == 0 || strcmp(argv[index],"--add") == 0) {//set mapping 
			if (index + 6 >= argc) {
				usage();
				break;
			}
			seconds = atoi(argv[index + 6]);
			pset_index = (unsigned short)strtoul(argv[index + 3], 0, 0);
			pset_mask = (unsigned short)strtoul(argv[index + 4], 0, 0);
			inet_pton(AF_INET, argv[index + 2], &addr_TI);
			inet_pton(AF_INET6, argv[index + 1], &addr6_TI);
			inet_pton(AF_INET6, argv[index + 5], &addr6_TC);
			set_mapping(addr_TI, addr6_TI, pset_index, pset_mask, addr6_TC, seconds);
			index += 6;
		} else if (strcmp(argv[index],"-d") == 0 || strcmp(argv[index-1],"--del") == 0) {//del mapping 
			if (index + 3 >= argc) {
				usage();
				break;
			}
			inet_pton(AF_INET, argv[index + 1], &addr_TI);
			pset_index = (unsigned short)strtoul(argv[index + 2], 0, 0);
			pset_mask = (unsigned short)strtoul(argv[index + 3], 0, 0);
			del_mapping(addr_TI, pset_index, pset_mask);
			index += 3;
		} else if (strcmp(argv[index],"-s") == 0 || strcmp(argv[index],"--show") == 0) {//display mapping table
			display_tc_mapping_table();
		} else if (strcmp(argv[index],"-f") == 0 || strcmp(argv[index],"--flush") == 0) {//del all mapping
			del_all_mapping();
		} else
			usage();
	}
	return 0;		
}
