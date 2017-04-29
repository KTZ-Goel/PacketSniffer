#ifndef ARP_H
#define ARP_H

#include <stdint.h>

#include <QList>
#include <QStandardItem>

//ARP Header

struct sniff_arp {
	uint16_t ah_hardware;      //The type of hardware this packet was transmitted on.
	uint16_t ah_protocol;      //The type of layer 3 addressing used
	uint8_t  ah_hlen;          //The length of the hardware address (6 in the case of a MAC address)
	uint8_t  ah_plen;          //The length of the network address (4 in the case of IPv4)
	uint16_t ah_opcode;        //The type of operation this packet is intended for (1 for arp request, 2 for arp reply)
};

#define ARP_HARDWARE_TYPE_ETHERNET    1
#define ARP_PROTOCOL_TYPE_IPV4        0x0800

#define ARP_MAC_LENGTH				  6
#define ARP_IPv4_LENGTH				  4

#define ARP_OPCODE_REQUEST            1
#define ARP_OPCODE_REPLY              2

void handle_arp(QList<QStandardItem *> *row, const struct sniff_arp *arp);
void handle_arp_fill(QString *infoStr, const struct sniff_arp *arp);

#endif // ARP_H

