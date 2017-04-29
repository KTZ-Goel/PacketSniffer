#ifndef TCP_H
#define TCP_H

#include <QList>
#include <QStandardItem>

//TCP header
struct sniff_tcp {
	uint16_t th_sport;		// (16 bits) - source port 
	uint16_t th_dport;		// (16 bits) - destination port 
	uint32_t th_seq;		// (32 bits) - sequence number
	uint32_t th_ack;		// (32 bits) - acknowledgement number
	
	uint8_t th_offx2;		// First 4 bits are the header length (offset) in bytes, next 4 bits are reserved
	#define TH_OFF(th)	(((th)->th_offx2 & 0xf0) >> 4)	//Get the header length
	uint8_t th_flags;		// First 2 bits are reserved, next 6 bits are flags
	#define TH_CWR 0x80		// 1000 0000 Congestion window reduced
	#define TH_ECE 0x40		// 0100 0000 ECN-Echo flag
	#define TH_URG 0x20		// 0010 0000 URGENT flag (is urgent pointer set)
	#define TH_ACK 0x10		// 0001 0000 ACK flag
	#define TH_PSH 0x08		// 0000 1000 PUSH flag
	#define TH_RST 0x04		// 0000 0100 RESET flag
	#define TH_SYN 0x02		// 0000 0010 SYN flag
	#define TH_FIN 0x01		// 0000 0001 FIN flag
	#define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
	uint16_t th_win;		// window
	uint16_t th_sum;		// checksum
	uint16_t th_urp;		// urgent pointer
};

#define IS_SET(a, b) ((a) & (b)) ? 1 : 0
void handle_tcp(QList<QStandardItem *> *row, const struct sniff_tcp *tcp, uint16_t size);
void handle_tcp_fill(QString *infoStr, const struct sniff_tcp *tcp, uint16_t size);


#endif // TCP_H

