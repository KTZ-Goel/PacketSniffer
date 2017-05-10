# PacketSniffer
A simple packet sniffer written in fall 2015 using Qt for the gui and Pcap to sniff ethernet packets.
Originally written in pure C as a command line application, then adapted into a GUI application.
Can save, pause, resume, open, and delete captures.

Demonstrates knowledge of networking layers and protocols.

Has support for following Protocols:
+ Layer 2 - Data Link Layer:
	+ Ethernet
	+ ARP

+ Layer 3 - Network Layer:
	+ ICMP
	+ IPv4 and IPv6

+ Layer 4 - Transport Layer:
	+ TCP
	+ UDP

+ Layer 7 - Application Layer:
	+ DNS
	+ HTTP
	+ HTTPS
