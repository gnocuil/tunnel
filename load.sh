sysctl net.ipv4.ip_forward=1
iptables -t mangle -A FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1280

screen sudo ./tunnel
ip route add 58.205.200.0/24 dev 4over6 table 1
