#pragma once

#define TUNNEL_NAME "4over6"

int tun_create(char *dev);
int tun_send(char *packet, int len);
int handle_tun();

extern uint16_t getport_dest(char *ippacket);
extern uint16_t getport_src(char *ippacket);