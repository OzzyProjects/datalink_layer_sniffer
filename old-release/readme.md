# Raw socket sniffer Linux

**WORK IN PROGRESS**

**Raw socket Linux sniffer being able to sniff all TCP, IP, ICMP, ARP, IGMP and some frames from OSI Layer 3.**

**It works also as a string extractor, displaying in output file revelant strings**

It grabs all revelant strings from packets : url, domain names, json requests etc...

You can see an example in file named string_log in the results repository

It binds to an network interface with her name, after set up it in promiscuous mode.

Among others, it uses the functions select(), FD_ISSET() to make it as low level as possible.

**Also being able to sniff some layer 2 packets like ARP, HOMEPLUG, HOMEPLUG POWERLINE, ETHERTYPE IEEE 1905 1a and other ones.**

**Need to be root to run the program**

Some functions are defined but non implemented but it's easy to do it (example : fake malloc)

+ <ins>Build commands :</ins>

`sudo git clone https://github.com/OzzyProjects/raw_socket_sniffer.git`

`cd /raw_socket_sniffer`

`sudo make`

+ <ins>Use (in root only) :</ins>

`./raw_sock -i [interface name] [output_string_file]`

or

`./raw_sock [output_string_file]`

The *output_string_file* is optional. Without it, the file created will be named trace.log

**if no interface name is provided, it sniff by default on eno1**. Easy to change

You can see an example of output log in file named "example".

You can have the list of network interface names typing in your terminal

`ip link show`

It works on Debian Buster/Bullseye and Ubuntu 20.04+.

I haven't checked yet for other versions or distros.

You can also check the complete valgrind memcheck report. No memory leaks or other memory problems.

![](valgrind/valgrind.png)


**TODO : code a kernel module with buffer sockets or/and take a serious interest at libpcap to reach data link layer level**
