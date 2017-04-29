#include <stdio.h>
#include <colors.h>
#include <arpa/inet.h>

#include "ipv6.h"
#include "tcp.h"
#include "udp.h"
#include "ipprotocols.h"

void handle_ipv6(QList<QStandardItem *> *row, const struct sniff_ipv6 *ip6){
	char buffer[INET6_ADDRSTRLEN];
	
	printf(CYAN "	IPv6 Header:\n" RESET);
    
    //Append the source address
	printf("		Source ------- %s\n", inet_ntop(AF_INET6, ip6->ip6_src, buffer, sizeof(buffer)));
    row->append(new QStandardItem(QString(buffer)));
    
    //Append the destination address
	printf("		Destination -- %s\n", inet_ntop(AF_INET6, ip6->ip6_dst, buffer, sizeof(buffer)));
    row->append(new QStandardItem(QString(buffer)));
    
	printf("		Protocol ----- %X\n", ip6->ip6_p);
	
	switch(ip6->ip6_p){
		case IP_TCP: {
			handle_tcp(row, (struct sniff_tcp*)((char *)ip6 + IPV6_HEADER_LENGTH), ntohs(ip6->ip6_len) - IPV6_HEADER_LENGTH);
			break;
		}
		case IP_UDP: {
			handle_udp(row, (struct sniff_udp*)((char *)ip6 + IPV6_HEADER_LENGTH));
			break;
		}
		default: {
			printf(YELLOW "	Transport layer protocol [0x%02X] not implemented yet." RESET "\n", ip6->ip6_p);
			break;
		}
	}
}