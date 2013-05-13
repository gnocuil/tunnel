#include <fcntl.h>
#include <cstdio>
#include <cstdlib>
#include <ctime>
#include <cstring>
#include <sys/ioctl.h>
#include <net/if.h>
#include <errno.h>
#include <linux/if_tun.h>
#include <iostream>

#include "tun.h"
#include "network.h"

using namespace std;

static void usage()
{
	fprintf(stderr, "Usage: tunnel [options]\n");
	fprintf(stderr, "  options: --name <TUNNEL_NAME>       default: 4over6\n");
	fprintf(stderr, "           --mtu <MTU_VALUE>          default: 1460\n");
	
	exit(1);
}

int main(int argc, char *argv[])
{
	srand(time(NULL));
	char tun_name[IFNAMSIZ] = {0};
	strncpy(tun_name, TUNNEL_NAME, IFNAMSIZ);
	mtu = 1460;
	
	for (int i = 1; i < argc; ++i) {
		if (i + 1 < argc && strcmp(argv[i], "--help") == 0) {
			usage();
		}
		if (i + 1 < argc && strcmp(argv[i], "--name") == 0) {
			strncpy(tun_name, argv[++i], IFNAMSIZ);
		}
		if (i + 1 < argc && strcmp(argv[i], "--mtu") == 0) {
			++i;
			sscanf(argv[i], "%d", &mtu);
		}
	}
	
	//Create TUN/TAP interface
	int tun = tun_create(tun_name, IFF_TUN | IFF_NO_PI);
	if (tun < 0) 
	{
		return 1;
	}
	fprintf(stderr, "interface name: %s\n", tun_name);

	set_mtu(tun_name, mtu);//set mtu
	interface_up(tun_name);//interface up

//	int len;
	while (1) {//printf("loop!\n");
/*
		len = read(tun, buf, sizeof(buf));
		
		printf("read %d bytes\n", len);
		int i;
		for(i=0;i<len;i++)
		{
		  printf("%02x ",buf[i]);
		}
		printf("\n");
		
		if (len < 0)
			break;
#define ETH_LEN 0
		memcpy(ip, &buf[ETH_LEN + 12], 4);
		memcpy(&buf[ETH_LEN + 12], &buf[ETH_LEN + 16], 4);
		memcpy(&buf[ETH_LEN + 16], ip, 4);
		buf[ETH_LEN + 20] = 0;
		*((unsigned short*)&buf[ETH_LEN + 22]) += 8;
		
		len = write(tun, buf, len);
		//printf("write %d bytes\n", ret);
*/
	}

	return 0;
}
