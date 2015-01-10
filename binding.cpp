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
#include <sstream>
#include <fstream>
#include <string>
#include <sys/time.h>

#include "binding.h"

//using namespace std;
using std::unordered_map;
using std::cout;
using std::string;
using std::endl;
using std::ostringstream;
using std::ofstream;

static int server_fd;

static string ip;

char tun_name[IFNAMSIZ] = {0};

static pthread_rwlock_t  rwlock = PTHREAD_RWLOCK_INITIALIZER;

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

static unordered_map<uint64_t, BindingPtr> table;

static inline uint64_t getkey(const Binding& record)
{
	return ((uint64_t)record.addr_TI.s_addr << 32) | (record.pset_mask <<16) | record.pset_index;
}

static inline uint64_t getkey(uint32_t ip, uint16_t pset_mask, uint16_t pset_index)
{
	return ((uint64_t)ip << 32) | (pset_mask <<16) | pset_index;
}

void insert(BindingPtr record)
{
	uint64_t key = getkey(*record);
    pthread_rwlock_wrlock(&rwlock);
	auto it = table.find(key);
	if (it == table.end()) {//Insert
		table[key] = record;
	} else {//Modify
		it->second = record;
	}
    pthread_rwlock_unlock(&rwlock);
}

void remove(const Binding& record)
{
	uint64_t key = getkey(record);
    pthread_rwlock_wrlock(&rwlock);
	auto it = table.find(key);
	if (it != table.end()) {//Insert
        table.erase(it);
	}
    pthread_rwlock_unlock(&rwlock);
}

BindingPtr find(uint32_t ip, uint16_t port)
{
    pthread_rwlock_rdlock(&rwlock);
    BindingPtr ret = BindingPtr();
	for (int len = 16; len >= 0; --len) {
		uint64_t key = getkey(ip, mask[len], mask[len] & port);
		auto it = table.find(key);
		if (it != table.end()) {//Found
			ret = it->second;
            break;
		}
	}
    pthread_rwlock_unlock(&rwlock);
	return ret;
}

string getJson()
{
	ostringstream sout;
	sout << "{\n";
    pthread_rwlock_rdlock(&rwlock);
	sout << "\"records\": " << table.size() << ",\n";
    if (ip.size() > 0) {
        sout << "\"ipv4-address\": \"" << ip << "\",\n";
    }
	int i;
	char addr_TI[100] = {0};
	char addr6_TI[100] = {0};
	char addr6_TC[100] = {0};
	sout << "\"table\": [\n";
    bool first = true;
    for (auto it = table.begin(); it != table.end(); ++it) {
		if (it->second) {
            if (!first) {
                sout << "  },\n";
            } else {
                first = false;
            }
            BindingPtr binding = it->second;
            inet_ntop(AF_INET, (void*)&binding->addr_TI, addr_TI, 16);
            inet_ntop(AF_INET6, (void*)&binding->addr6_TI, addr6_TI, 48);
            inet_ntop(AF_INET6, (void*)&binding->addr6_TC, addr6_TC, 48);
            sout << "  {\n";
            sout << "    \"key\": " << getkey(*binding) << ",\n";
            sout << "    \"ipv6-addr\": \"" << addr6_TI << "\",\n";
            sout << "    \"ipv4-addr\": \"" << addr_TI << "\",\n";
            sout << "    \"aftr-addr\": \"" << addr6_TC << "\",\n";
            sout << "    \"portset-index\": " << binding->pset_index << ",\n";
            sout << "    \"portset-mask\": " << binding->pset_mask << ",\n";
            sout << "    \"upstream-pkts\": " << binding->in_pkts << ",\n";
            sout << "    \"downstream-pkts\": " << binding->out_pkts << ",\n";
            sout << "    \"upstream-bytes\": " << binding->in_bytes << ",\n";
            sout << "    \"downstream-bytes\": " << binding->out_bytes << ",\n";
            sout << "    \"upstream-bps\": " << binding->in_bps << ",\n";
            sout << "    \"downstream-bps\": " << binding->out_bps << "\n";
        }
	}
    pthread_rwlock_unlock(&rwlock);
    if (!first)
        sout << "  }\n";
	sout << "]\n";
	sout << "}\n";
	return sout.str();
}

static void http_server(int fd, char *buf, int len)
{
	cout << "httpsrv:" << buf << endl;
	int i = 0;
	string cmd;
	for (; i < len; ++i) {
		if (buf[i] == ' ') break;
		cmd += buf[i];
	}
	if (i++ >= len) return;
	string path;
	for (; i < len; ++i) {
		if (buf[i] == ' ') break;
		path += buf[i];
	}
	if (i >= len) return;
	int pos;
	if ((pos = path.find('?')) != string::npos) {
		string att = path.substr(pos + 1);
		path = path.substr(0, pos);
//		cout << "att="<<att<<endl;
	}
//	cout<<"cmd="<<cmd<<" path="<<path<<endl;
	if (cmd == "GET") {
		if (path == "/query") {
			string json = getJson();
			string header = "HTTP/1.1 200 OK\r\n";
			header += "Content-Type: application/json; charset=UTF-8\r\n";
			char size[100] = {0};
			sprintf(size, "%d", (int)json.size());
			header += "Content-Length: " + string(size) + "\r\n";
			header += "\r\n";
			header += json;
			int count = write(fd, header.c_str(), header.size());
		}
	}
}

int handle_binding()
{
	int client_fd = accept(server_fd, NULL, NULL);
	uint8_t command;
	int count;
	uint32_t size;
	cout <<getJson();
	count = read(client_fd, &command, 1);
	if (count != 1) {
		fprintf(stderr, "handle_socket: Error reading command: count=%d %m\n", count);
        close(client_fd);
		return -1;
	}
	Binding binding;
	char buf[65536] = {0};
	switch (command) {
		case TUNNEL_SET_MAPPING:
			count = read(client_fd, &binding, sizeof(Binding));
			if (count != sizeof(Binding)) {
				fprintf(stderr, "handle_socket: Error reading: %m\n");
				return -1;
			}
			insert(BindingPtr(new Binding(binding)));
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
            pthread_rwlock_rdlock(&rwlock);
			size = table.size();
			count = write(client_fd, &size, 4);
			for (auto it = table.begin(); it != table.end(); ++it) {
				if (it->second) {
					count = write(client_fd, it->second.get(), sizeof(Binding));
				}
			}
            pthread_rwlock_unlock(&rwlock);
			break;
		case TUNNEL_FLUSH_MAPPING:
            pthread_rwlock_wrlock(&rwlock);
			table.clear();
            pthread_rwlock_unlock(&rwlock);
			break;
		case TUNNEL_MAPPING_NUM:
			size = table.size();
			count = write(client_fd, &size, 4);			
			break;
		default:
			buf[0] = command;
			count = read(client_fd, buf + 1, sizeof(buf) - 1);
			if (count > 0) {
				http_server(client_fd, buf, count + 1);
			}
			break;
	};
	close(client_fd);
	return 0;
}

int binding_init()
{
	struct sockaddr_un server_addr; 
	size_t server_len;

	if ((server_fd = socket(AF_INET6, SOCK_STREAM, 0)) < 0) {
		fprintf(stderr, "binding_init: Failed to create socket: %m\n");
		exit(1);
	}
	int no = 0;
    int yes = 1;
	setsockopt(server_fd, IPPROTO_IPV6, IPV6_V6ONLY, &no, sizeof(no));
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
    
    struct sockaddr_in6 serv_addr;
    bzero((char *) &serv_addr, sizeof(serv_addr));
    serv_addr.sin6_family = AF_INET6;
    serv_addr.sin6_addr = in6addr_any;
    serv_addr.sin6_port = htons(8080);
    if (bind(server_fd, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) == -1)  {
        perror("error in bind()");
        exit(0);
    }

    if (listen(server_fd, 10) != 0)  {
        perror("error in listen()");
        exit(0);
    }

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
			
			insert(BindingPtr(new Binding(binding)));
		}
	} catch (const std::exception& ex) {
		fprintf(stderr, "Failed to restore bindings from file %s!\n", file.c_str());
	}
	try {
		ip = pt.get<std::string>("ipv4-address");
		cout << "iface ip=" << ip << endl;
        string cmd = "ip addr add " + ip + " dev " + tun_name;
        int t = system(cmd.c_str());
	} catch (const std::exception& ex) {
	}
}
double current_time;
extern string conffile;
void* timer(void* arg)
{
    struct timeval t0;
    gettimeofday(&t0, NULL);
    double last_bps_update = 0;
    double last_conf_update = 0;
    while (true) {
        struct timeval t1;
        gettimeofday(&t1, NULL);
        current_time = (t1.tv_sec - t0.tv_sec) + (t1.tv_usec - t0.tv_usec) / 1000000.0;
        if (current_time > last_bps_update + 3) {
            double cur = current_time - last_bps_update;
            last_bps_update = current_time;
            pthread_rwlock_wrlock(&rwlock);
            for (auto it = table.begin(); it != table.end(); ++it) {
                if (it->second != NULL) {
                    BindingPtr binding = it->second;
                    binding->in_bps = binding->in_bytes_cur * 8 / cur;
                    binding->out_bps = binding->out_bytes_cur * 8 / cur;
                    binding->in_bytes_cur = binding->out_bytes_cur = 0;
                }
            }
            pthread_rwlock_unlock(&rwlock);
        }
        if (current_time > last_conf_update + 10) {
            last_conf_update = current_time;
            //puts("update conf file");
            string cmd = "cp " + conffile + " " + conffile + ".bak";
            int t = system(cmd.c_str());
            string json = getJson();
            ofstream fout(conffile);
            fout << json;
        }
        sleep(1);
    }
}
