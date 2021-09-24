# Raw socket sniffer Linux

Raw socket based sniffer being able to sniff all TCP, IP, ICMP and IGMP packets.

It binds an interface, after set up it in promiscuous mode.

Also being able to sniff some layer 3 packet like ARP, HOMEPLUG and some other one.

Build :

just do

make


Use :

./raw_sniffer -i [interface name]

or

./raw_sniffer

if no interface name is provided, it sniff by default on eno1.

You can see an example of output in example file.

Works on Debian Bullseye and Ubuntu.
