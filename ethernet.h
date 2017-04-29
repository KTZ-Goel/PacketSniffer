#ifndef ETHERNET_H
#define ETHERNET_H

#include <stdint.h>
#include <pcap.h>

#include <vector>

#include <QStandardItemModel>
#include <QPlainTextEdit>

//Ethernet header and macros
#define SIZE_ETHERNET 14
struct sniff_ethernet {
	uint8_t ether_dhost[6]; 	/* Destination host address, mac address, ex: 00:00:00:00:00:00 */
	uint8_t ether_shost[6]; 	/* Source host address, mac address, ex: 00:00:00:00:00:00 */
	uint16_t ether_type; 	/* Next layer protocol. IP? ARP? RARP? etc */
};
#define ETHERTYPE_IPV4 	0x0800
#define ETHERTYPE_ARP 	0x0806
#define ETHERTYPE_IPV6 	0x86DD

void handle_ethernet(QList<QStandardItem *> *row, const uint8_t *packet);  //Handles an incoming packet, fills in the columns of a table row
void handle_ethernet_fill(QString *infoStr, const char *data);     //Fills in the textEdit with a full summary of the packet

#endif // ETHERNET_H