#ifndef IPV4_H
#define IPV4_H

#include <stdint.h>
#include <netinet/in.h>

#include <QList>
#include <QStandardItem>

//IPv4 header and macros
struct sniff_ipv4 {
	uint8_t ip_vhl;             //version << 4 | header length >> 2
	uint8_t ip_tos;             //type of service
	uint16_t ip_len;            //total length in bytes
	uint16_t ip_id;             //identification
	uint16_t ip_off;            //fragment offset field
	uint8_t ip_ttl;             //time to live
	uint8_t ip_p;               //protocol
	uint16_t ip_sum;            //checksum
	struct in_addr ip_src;      //source  address
	struct in_addr ip_dst;      //dest address
};

//Macros for the ip_vhl field
#define IP_HL(ip)     (((ip)->ip_vhl) & 0x0f)   //Calculate the header length
#define IP_V(ip)      (((ip)->ip_vhl) >> 4)     //Calculate the IP version


//Macros for the ip_off field
#define IP_RF        0x8000    // reserved fragment flag
#define IP_DF        0x4000    // dont fragment flag
#define IP_MF        0x2000    // more fragments flag

#define IP_OFFMASK   0x1fff    // mask for fragmenting bits
#define IP_OFFSET(ip) ((ntohs((ip)->ip_off)) & IP_OFFMASK)     //Calculate the fragment offset

void handle_ipv4(QList<QStandardItem *> *row, const struct sniff_ipv4 *ip);
void handle_ipv4_fill(QString *infoStr, const struct sniff_ipv4 *ip);

#endif // IPV4_H

