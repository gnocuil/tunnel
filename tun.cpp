#include <linux/if_tun.h>
#include <net/if.h>
#include <errno.h>
#include <cstdio>
#include <fcntl.h>
#include <cstring>
#include <sys/ioctl.h>
#include <iostream>
#include "tun.h"

int tun_create(char *dev, int flags)
{
	struct ifreq ifr;
	int fd, err;

	if ((fd = open("/dev/net/tun", O_RDWR)) < 0)
	{
		fprintf(stderr, "Error Creating TUN/TAP: %m\n", errno);
		return -1;
	}

	memset(&ifr, 0, sizeof(ifr));
	ifr.ifr_flags |= flags;

	if (*dev != '\0') {
		strncpy(ifr.ifr_name, dev, IFNAMSIZ);
	}

	if ((err = ioctl(fd, TUNSETIFF, (void *)&ifr)) < 0) 
	{
		fprintf(stderr, "Error Setting tunnel name %s: %m\n", dev, errno);
		close(fd);
		return -1;
	}

	strcpy(dev, ifr.ifr_name);

	return fd;
}

