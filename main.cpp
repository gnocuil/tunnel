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
#include "socket.h"
#include "binding.h"
#include "encap.h"
#include "ipip.h"
#include "icmp.h"

using namespace std;

#define DEFAULT_MTU 1460

string conffile = "/etc/lw4over6.conf";

static void usage()
{
	fprintf(stderr, "Usage: tunnel [options]\n");
	fprintf(stderr, "  options: --name <TUNNEL_NAME>       default: 4over6\n");
	fprintf(stderr, "           --encap { IPIP | ICMP }    default: IPIP\n");
	fprintf(stderr, "           --mtu <MTU_VALUE>          default: %d\n", DEFAULT_MTU);
    fprintf(stderr, "           --config <CONFIG_FILE>     default: %s\n", conffile.c_str());
    
	exit(1);
}

void* thread_6to4(void* arg)
{
	int raw_fd = socket_init();
	if (raw_fd < 0) {
		exit(1);
	}
	while (1)
		handle_socket();
}

void* thread_binding(void* arg)
{

	while (1)
		handle_binding();
}

extern char tun_name[IFNAMSIZ];

int main(int argc, char *argv[])
{
	srand(time(NULL));
	strncpy(tun_name, TUNNEL_NAME, IFNAMSIZ);
	mtu = DEFAULT_MTU;
	
	for (int i = 1; i < argc; ++i) {
		if (strcmp(argv[i], "--help") == 0) {
			usage();
		}
		if (i + 1 < argc && strcmp(argv[i], "--name") == 0) {
			strncpy(tun_name, argv[++i], IFNAMSIZ);
		} else if (i + 1 < argc && strcmp(argv[i], "--mtu") == 0) {
			++i;
			sscanf(argv[i], "%d", &mtu);
		} else if (i + 1 < argc && strcmp(argv[i], "--encap") == 0) {
			++i;
			if (strcmp(argv[i], "IPIP") == 0) {
				encap = new Encap_IPIP();
			} else if (strcmp(argv[i], "ICMP") == 0) {
				encap = new Encap_ICMP();
			} else {
				usage();
			}
        } else if (i + 1 < argc && strcmp(argv[i], "--config") == 0) {
            ++i;
            conffile = argv[i];
		}
	}

	if (encap == NULL)
		encap = new Encap_IPIP();
	fprintf(stderr, "Encap Mode: %s\n", encap->name());

	//Create TUN/TAP interface
	int tun_fd = tun_create(tun_name);
	if (tun_fd < 0) {
		exit(1);
	}
	fprintf(stderr, "interface name: %s\n", tun_name);
    fprintf(stderr, "Reload configuration file: %s\n", conffile.c_str());

	set_mtu(tun_name, mtu);//set mtu
	interface_up(tun_name);//interface up
	
	int binding_fd = binding_init();
	if (binding_fd < 0) {
		exit(1);
	}
	
	binding_restore(conffile);

	pthread_t tid;
	pthread_create(&tid, NULL, timer, NULL);
	pthread_create(&tid, NULL, thread_6to4, NULL);
	
	//father
	socket_init_tun();

	fd_set set;
	int maxsock = tun_fd;
//	if (raw_fd > maxsock)
//		maxsock = raw_fd;
	if (binding_fd > maxsock)
		maxsock = binding_fd;
    pthread_create(&tid, NULL, thread_binding, NULL);
	while (1) {
		FD_ZERO(&set);
		FD_SET(tun_fd, &set);
//		FD_SET(raw_fd, &set);
//		FD_SET(binding_fd, &set);
		
		int ret = select(maxsock + 1, &set, NULL, NULL, NULL);
		
		if (ret < 0) {
			fprintf(stderr, "main: Error in select: %m\n");
			break;
		}
		if (FD_ISSET(binding_fd, &set)) {
//			printf("select: Binding!!!\n");
			handle_binding();
		} 
		if (FD_ISSET(tun_fd, &set)) {
//			printf("select: TUN!!!\n");
			handle_tun();
		}
/*
		if (FD_ISSET(raw_fd, &set)) {
//			printf("select: RAW!!!\n");
			handle_socket();
		} 
*/
	}

	return 0;
}
