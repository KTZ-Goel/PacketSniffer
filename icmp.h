#ifndef ICMP_H
#define ICMP_H

#include <stdint.h>

#include <QList>
#include <QStandardItem>

//ICMP types and codes
#define ICMP_TYPE_ECHO_REPLY                 0

#define ICMP_TYPE_ECHO_REQUEST               8

#define ICMP_TYPE_DEST_UNREACH               3
	#define ICMP_CODE_DEST_UNREACH_NET        0
	#define ICMP_CODE_DEST_UNREACH_HOST       1
	#define ICMP_CODE_DEST_UNREACH_PRO        2
	#define ICMP_CODE_DEST_UNREACH_PORT       3

#define ICMP_TYPE_TRACEROUTE                 30



void handle_icmp(QList<QStandardItem *> *row, const uint8_t *data, uint16_t length);
void handle_icmp_fill(QString *infoStr, const uint8_t *data, uint16_t length);

void printTimestamp(QString *infoStr, time_t seconds, time_t ms);
QString getTimeStamp(time_t seconds, time_t ms);

#endif // ICMP_H

