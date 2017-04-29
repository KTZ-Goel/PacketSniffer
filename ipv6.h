#ifndef IPV6_H
#define IPV6_H

#include <stdint.h>

#include <QList>
#include <QStandardItem>

//IPv6 header and macros
struct sniff_ipv6 {
	uint32_t  ip6_vtcfl;		//version, traffic class, flow label
	uint16_t  ip6_len;			//The length of the payload
	uint8_t   ip6_p;			//The next header
	uint8_t   ip6_hop;			//The hop limit
	char  	  ip6_src[16];		//The 128 bit source address
	char  	  ip6_dst[16];		//The 128 bit destination address
};
#define IPV6_HEADER_LENGTH 	40
#define IPV6_VERSION(ip6) 	((ip6)->ip6_vtcfl & 0xF0000000)

void handle_ipv6(QList<QStandardItem *> *row, const struct sniff_ipv6 *ip6);

#endif // IPV6_H