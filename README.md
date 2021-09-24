# Raw socket sniffer Linux

Raw socket based Linux sniffer being able to sniff all TCP, IP, ICMP and IGMP packets.

It binds to an network interface with her name, after set up it in promiscuous mode.

Among others, it uses the functions select(), FD_ISSET() to make it as low level as possible.

Also being able to sniff some layer 3 packet like ARP, HOMEPLUG and some other one.

**Need to be root to run the program**

Some functions are defined but non implemented but it's easy to do it (exemple : fake malloc)

<ins>Build :</ins>

just do **make**

<ins>Use :</ins>

`./raw_sniffer -i [interface name]`

or

`./raw_sniffer`

if no interface name is provided, it sniff by default on eno1. Easy to change

You can see an example of output log in file named "example".

It works on Debian Bullseye and Ubuntu 20.04.

I haven't checked yet for other versions or distros.
