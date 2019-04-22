# Packet Sniffer 
This program does the following:
* Utilize the pcap library to process raw network packets
* Categorize and print information about packets in a trace file or from a live capture
## About
This is a program to categorize and print select information about packets. The program reads packets from a pcap trace file or from a live capture and produces the following output:
* The Ethernet source and destination address and the decoded Ethernet type. • The source and destination IP (version 4 and 6) addresses, if appropriate.
* The source and destination ports for UDP and TCP.
* If the packet is TCP, then indicate when SYN or FIN flags are set.
If you receive a packet with a protocol not specified above, then the multiplexing key (type or protocol value) is printed. If you receive an IP packet where TCP or UDP is not the encapsulated protocol, then just the protocol value is printed.
  * When printing addresses, the OS does the work for you. It uses the functions inet_ntop(3) and ether_ntoa(3).
The program uses the pcap(3) library, which collects packets and provides them to you as an array of bytes. You have two sources for your packets: a saved capture file or a live capture of traffic off the network.
## How to use
If you provide a filename as a command line argument, then the capture file is used. If you do not use a command line argument, then a live capture is used. You will need to run the program with root privileges to capture live packets. You may use Wireshark to capture traces (save the packets in pcap format) to use as test input to your program or you may download example traces from http://wiki.wireshark.org/SampleCaptures. When working with traces, ensure they include the full Ethernet header (no not capture on the any interface).
It links against the libpcap library (-lpcap) to build the executable.
There are many sources for the packet formats used in this program, but the authoritative sources are: IEEE 802.3 standard for Ethernet, RFC 791 for IPv4, RFC 2460 for IPv6, RFC 793 for TCP, and RFC 768 for UDP.
Additional files for this program include:
* Includes a Makefile that compiles the program upon the command make.
* It takes one optional argument, the filename for the packet trace.
* The program compiles cleanly using the gcc/g++ argument -Wall.
## Permissions
You normally do not have permissions to perform a live capture, so you need to take extra steps to enable your program to run in a live capture. These steps are not required to read from a capture file.
## Run as root
One option is to run your program as root, if your machine is setup to allow this. For most machines, this can happen by running the command sudo ./packets.
## Enable permissions for your program
Another option is to enable your program to perform a live capture by giving it special permissions.
To perform a live capture, follow these steps:
    1. Compile your program
    2. Run the command sudo setcap cap_net_raw=+ep packets
    3. Run your program
    4. You’ll need to run setcap again every time you recompile your program.

## The program follows this order of implementation
* Print Ethernet information (source and destination address and decoded type)
* Print IPv4 information (source and destination address)
* Print IPv6 information (source and destination address)
* Print UDP information (source and destination port)
* Print TCP information (source and destination port and flags)


## Input/Output
Below are input and output examples the program, where each line consists of source -> destination. The program has the formatting of the examples below:

    $packets trace.cap
    Processing file ’trace.pcap’
    0:1f:33:cf:2d:c4 -> 8c:a9:82:62:63:6c
        [IPv4] 10.0.0.2 -> 71.139.247.68
        [TCP] 8334 -> 80 SYN
    8c:a9:82:62:63:6c -> 0:1f:33:cf:2d:c4
        [IPv4] 71.139.247.68 -> 10.0.0.2
        [TCP] 80 -> 8334 FIN
    8c:a9:82:62:63:6c -> 0:1f:33:cf:2d:c4
        [38]
    0:1f:33:cf:2d:c4 -> 8c:a9:82:62:63:6c
        [IPv4] 10.0.0.2 -> 71.139.247.68
        [101]
    70:1a:4:ac:ef:b2 -> 33:33:0:0:0:c
        [IPv6] fe80::e171:e8c6:cbe4:ac15 -> ff02::c
        [UDP] 3455 -> 10456
    33:33:0:0:0:c -> 70:1a:4:ac:ef:b2
        [IPv6] ff02::c -> fe80::e171:e8c6:cbe4:ac15
        [123]
    #packets
    Capturing on interface ’eth0’
    0:1f:33:cf:2d:c4 -> 8c:a9:82:62:63:6c
        [IPv4] 10.0.0.2 -> 71.139.247.68
        [TCP] 8334 -> 80

## Extras
* The functions ntohl(3), ntohs(3), and memcpy(3) are used.
