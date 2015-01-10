#include <unordered_map>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <cstdio>
#include <cstdlib>
#include <iostream>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <stddef.h>
#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/json_parser.hpp>
#include <boost/foreach.hpp>

#include "binding.h"

using namespace std;

static int server_fd;

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
	return ((uint64_t)record.addr_TI.s_addr << 32) | (record.pset_mask <<16) | record.pset_index;
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

void remove(const Binding& record)
{
	uint64_t key = getkey(record);
	unordered_map<uint64_t, Binding*>::iterator it = table.find(key);
	if (it != table.end()) {//Insert
		if (it->second != NULL) {
			delete it->second;
			it->second = NULL;
		}
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

int handle_binding()
{
	int client_fd = accept(server_fd, NULL, NULL);
	uint8_t command;
	int count;
	uint32_t size;
	
	count = read(client_fd, &command, 1);
	if (count != 1) {
		fprintf(stderr, "handle_socket: Error reading command: %m\n");
		return -1;
	}
	Binding binding;
	switch (command) {
		case TUNNEL_SET_MAPPING:
			count = read(client_fd, &binding, sizeof(Binding));
			if (count != sizeof(Binding)) {
				fprintf(stderr, "handle_socket: Error reading: %m\n");
				return -1;
			}
			insert(binding);
			break;
		case TUNNEL_DEL_MAPPING:
			count = read(client_fd, &binding, sizeof(Binding));
			if (count != sizeof(Binding)) {
				fprintf(stderr, "handle_socket: Error reading: %m\n");
				return -1;
			}
			remove(binding);
			break;
		case TUNNEL_GET_MAPPING:
			size = table.size();
			count = write(client_fd, &size, 4);
			for (unordered_map<uint64_t, Binding*>::iterator it = table.begin(); it != table.end(); ++it) {
				if (it->second != NULL) {
					count = write(client_fd, it->second, sizeof(Binding));
				}
			}
			break;
		case TUNNEL_FLUSH_MAPPING:
			for (unordered_map<uint64_t, Binding*>::iterator it = table.begin(); it != table.end(); ++it) {
				if (it->second != NULL) {
					delete it->second;
					it->second = NULL;
				}
			}
			table.clear();
			break;
		case TUNNEL_MAPPING_NUM:
			size = table.size();
			count = write(client_fd, &size, 4);			
			break;
		default:
			break;
	};
	close(client_fd);
	return 0;
}

int binding_init()
{
	struct sockaddr_un server_addr; 
	size_t server_len;

	if ((server_fd = socket(AF_UNIX, SOCK_STREAM,  0)) == -1) {
		fprintf(stderr, "binding_init: Failed to create socket: %m\n");
		exit(1);
	}
	
	if (fcntl(server_fd, F_SETFL, O_NONBLOCK) < 0) {
		fprintf(stderr, "binding_init: Error Setting nonblock: %m\n");
		return -1;
	}
	
	//name the socket
	server_addr.sun_family = AF_UNIX;
	strcpy(server_addr.sun_path, SERVER_NAME);
	server_addr.sun_path[0]=0;
	//server_len = sizeof(server_addr);
	server_len = strlen(SERVER_NAME)  + offsetof(struct sockaddr_un, sun_path);
	
	bind(server_fd, (struct sockaddr *)&server_addr, server_len);
	listen(server_fd, 5);
	return server_fd;
}

void binding_restore(std::string file)
{
	using boost::property_tree::ptree;
	ptree pt;
	read_json(file, pt);

	try {
		int records = pt.get<int>("records");
		cout << "records="<<records<<endl;
		BOOST_FOREACH(boost::property_tree::ptree::value_type &v, pt.get_child("table")) {
			struct Binding binding;
			memset(&binding, 0, sizeof(struct Binding));

			string addr6_TI = v.second.get<string>("ipv6-addr");
			string addr_TI = v.second.get<string>("ipv4-addr");
			string addr6_TC = v.second.get<string>("aftr-addr");
			inet_pton(AF_INET, addr_TI.c_str(), &binding.addr_TI);
			inet_pton(AF_INET6, addr6_TI.c_str(), &binding.addr6_TI);
			inet_pton(AF_INET6, addr6_TC.c_str(), &binding.addr6_TC);
			
			binding.pset_index = v.second.get<uint16_t>("portset-index");
			binding.pset_mask = v.second.get<uint16_t>("portset-mask");
			binding.in_pkts = v.second.get<uint64_t>("upstream-pkts");
			binding.out_pkts = v.second.get<uint64_t>("downstream-pkts");
			binding.in_bytes = v.second.get<uint64_t>("upstream-bytes");
			binding.out_bytes = v.second.get<uint64_t>("downstream-bytes");
			
			cout << "addr6=" << addr6_TI << " ";
			cout << "addr4=" << addr_TI << " ";
			cout << "AFdr6=" << addr6_TC << " ";
			cout << "pset=" << binding.pset_index << " " << binding.pset_mask << "  ";
			cout << endl;
			insert(binding);
		}
	} catch (const std::exception& ex) {
		fprintf(stderr, "Failed to restore bindings from file %s!\n", file.c_str());
	}
}
