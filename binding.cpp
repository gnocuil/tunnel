#include <unordered_map>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <cstdio>
#include <cstdlib>
#include <iostream>
#include <errno.h>

#include "binding.h"

using namespace std;

static uint16_t mask[] = {
	0x0,
	0x8000,
	0xC000,
	0xE000,
	0xF000,
	0xF800,
	0xFC00,
	0xFE00,
	0xFF00,
	0xFF80,
	0xFFC0,
	0xFFE0,
	0xFFF0,
	0xFFF8,
	0xFFFC,
	0xFFFE,
	0xFFFF
};

static unordered_map<uint64_t, Binding*> table;

static inline uint64_t getkey(const Binding& record)
{
	return ((uint64_t)record.remote.s_addr << 32) | (record.pset_mask <<16) | record.pset_index;
}

static inline uint64_t getkey(uint32_t ip, uint16_t pset_mask, uint16_t pset_index)
{
	return ((uint64_t)ip << 32) | (pset_mask <<16) | pset_index;
}

void insert(const Binding& record)
{
	uint64_t key = getkey(record);
	unordered_map<uint64_t, Binding*>::iterator it = table.find(key);
	if (it == table.end()) {//Insert
		Binding *newrecord = new Binding(record);
		table[key] = newrecord;
	} else {//Modify
		*(it->second) = record;
	}
}

Binding* find(uint32_t ip, uint16_t port)
{
	for (int len = 16; len >= 0; --len) {
		uint64_t key = getkey(ip, mask[len], mask[len] & port);
		unordered_map<uint64_t, Binding*>::iterator it = table.find(key);
		if (it != table.end()) {//Found
			return it->second;
		}
	}
	return NULL;
}

int binding_init()
{
	int server_fd;
	int client_fd;
	struct sockaddr_un server_addr; 
	struct sockaddr_un client_addr;
	size_t server_len,client_len;

	if ((server_fd = socket(AF_UNIX, SOCK_STREAM,  0)) == -1) {
		fprintf(stderr, "binding_init: Failed to create socket: %m\n", errno);
		exit(1);
	}
	
	//name the socket
	server_addr.sun_family = AF_UNIX;
	strcpy(server_addr.sun_path, SERVER_NAME);
	server_addr.sun_path[0]=0;
	//server_len = sizeof(server_addr);
	server_len = strlen(SERVER_NAME)  + offsetof(struct sockaddr_un, sun_path);
	

	bind(server_fd, (struct sockaddr *)&server_addr, server_len);
	//listen the server
	listen(server_fd, 5);
	printf("after listen\n");
	char ch;
	while(1){
		printf("server waiting...\n");
		
		//accept client connect
		client_len = sizeof(client_addr);
		client_fd = accept(server_fd,(struct sockaddr*)&client_addr, &client_len);
		printf("after accept\n");
		//read  data from client socket
		read(client_fd, &ch, 1);
		printf("read from client %d: %c",client_fd,ch);
		ch ++;
		write(client_fd, &ch, 1);
		close(client_fd);
		usleep(100);//1000 miliseconds = 1 second
	}
	
	return server_fd;
}
