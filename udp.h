#ifndef UDP_H
#define UDP_H

#include <stdint.h>

#include <QList>
#include <QStandardItem>

//UDP header
struct sniff_udp {
	uint16_t uh_sport;		// Source port
	uint16_t uh_dport;		// Destination port
	uint16_t uh_len;		// length of the packet
	uint16_t uh_sum;		// checksum
};

void handle_udp(QList<QStandardItem *> *row, const struct sniff_udp *udp);
void handle_udp_fill(QString *infoStr, const struct sniff_udp *udp);

#endif // UDP_H

