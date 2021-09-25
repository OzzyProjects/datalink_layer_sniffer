# Raw socket sniffer Linux

**Raw socket Linux sniffer being able to sniff all TCP, IP, ICMP and IGMP packets.**

It binds to an network interface with her name, after set up it in promiscuous mode.

Among others, it uses the functions select(), FD_ISSET() to make it as low level as possible.

**Also being able to sniff some layer 3 packets like ARP, HOMEPLUG, ETHERTYPE_IEEE1905_1 and other ones.**

**Need to be root to run the program**

Some functions are defined but non implemented but it's easy to do it (example : fake malloc)

+ <ins>Build commands :</ins>

`sudo git clone https://github.com/OzzyProjects/raw_socket_sniffer.git`

`cd /raw_socket_sniffer`

`sudo make`

+ <ins>Use (in root only) :</ins>

`./raw_sock -i [interface name]`

or

`./raw_sock`

Some Markdown text with <span style="color:blue">some *blue* text</span>.

**if no interface name is provided, it sniff by default on eno1**. Easy to change

You can see an example of output log in file named "example".

You can have the list of network interface names typing in your terminal

`ip link show`

It works on Debian Buster/Bullseye and Ubuntu 20.04+.

I haven't checked yet for other versions or distros.

You can also check the complete valgrind memcheck report. No memory leaks or other memory problems.

![](valgrind/valgrind.png)


**TODO : code a kernel module with buffer sockets or/and take a serious interest at libpcap to reach data link layer level**
