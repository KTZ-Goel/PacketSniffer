#include <stdio.h>
#include <stdint.h>
#include <arpa/inet.h>

#include "ipv4.h"
#include "ipprotocols.h"
#include "tcp.h"
#include "udp.h"
#include "icmp.h"

#include "colors.h"
#include "shared.h"
#include "tags.h"

void handle_ipv4(QList<QStandardItem *> *row, const struct sniff_ipv4 *ip){
	//const struct sniff_tcp *tcp;				//The TCP header
	uint32_t size_ip;
	
	size_ip = IP_HL(ip)*4;	//Calculate the size of this header
	
	printf(CYAN "	IPv4 Header:\n" RESET);

	if (size_ip < 20) {	//If the size is less than 20 bytes, discard it
		printf(RED "		Invalid IP header length: %u bytes\n" NORMAL, size_ip);
		return;
	}
	
	//IP header information
	char addressBuffer[INET_ADDRSTRLEN];
	printf("		IP version --- IPv%d\n", IP_V(ip));
	printf("		Header Len --- %d bytes\n", IP_HL(ip)*4);
	//printf("		TOS + ECN ---- 0x%04X\n", ip->ip_tos);
	printf("		TOS + ECN ---- "); printBinaryuint8_t(ip->ip_tos);
	printf("\n		Total Length - %d bytes\n", ntohs(ip->ip_len));
	printf("		Offset ------- %d bytes\n", IP_OFFSET(ip) * 8);
	printf("		Flags+Offset - 0x%04X\n", ip->ip_off);
	printf("		TTL ---------- %d\n", ip->ip_ttl);
	printf("		Checksum ----- 0x%04X\n", ntohs(ip->ip_sum));
	printf("		Source ------- %s\n", inet_ntop(AF_INET, &ip->ip_src, addressBuffer, INET_ADDRSTRLEN));
    row->append(new QStandardItem(QString(addressBuffer)));
	printf("		Destination -- %s\n", inet_ntop(AF_INET, &ip->ip_dst, addressBuffer, INET_ADDRSTRLEN));
    row->append(new QStandardItem(QString(addressBuffer)));
	printf("		Protocol ----- %u ", ip->ip_p);

	//Determine the transport layer protocol
	switch(ip->ip_p){
		case IP_TCP: {
			printf("(TCP)\n");
			handle_tcp(row, (struct sniff_tcp*)(((char*)ip) + size_ip), ntohs(ip->ip_len)-size_ip);
			break;
		}
		case IP_UDP: {
			printf("(UDP)\n");
			handle_udp(row, (struct sniff_udp *)(((char *)ip) + size_ip));
			break;
		}
		case IPV4_ICMP:{
			printf("(ICMP)\n");
			handle_icmp(row, (uint8_t *)ip + size_ip, ntohs(ip->ip_len)-size_ip);
			break;
		}
		default: {
			printf(YELLOW "(Not implemented yet)" RESET "\n");
			break;
		}
	}
}

void handle_ipv4_fill(QString *infoStr, const struct sniff_ipv4 *ip){
	uint32_t size_ip = IP_HL(ip)*4;  //The size of this header
	
	//printf(CYAN "	IPv4 Header:\n" RESET);
    infoStr->append(HEADER_TAG_START "IPv4 Header:" HEADER_TAG_END NEWLINE);

	if (size_ip < 20) {	//If the size is less than 20 bytes, discard it
		//printf(RED "		Invalid IP header length: %u bytes\n" NORMAL, size_ip);
        infoStr->append(TAB ERROR_TAG_START + QString("Invalid IP header length: %1 bytes").arg(size_ip) + ERROR_TAG_END NEWLINE);
		return;
	}
	
	//IP header information
	char addressBuffer[INET_ADDRSTRLEN];
    
	//printf("		IP version --- IPv%d\n", IP_V(ip));
    infoStr->append(TAB + QString(BOLD_TAG_START "IP version" BOLD_TAG_END " --- IPv%1").arg(IP_V(ip)) + NEWLINE);
    
	//printf("		Header Len --- %d bytes\n", IP_HL(ip)*4);
    infoStr->append(TAB + QString(BOLD_TAG_START "Header Len" BOLD_TAG_END " --- %1 bytes").arg(size_ip) + NEWLINE);
    
	//printf("		TOS + ECN ---- "); printBinaryuint16_t(ip->ip_tos);
    infoStr->append(TAB + QString(BOLD_TAG_START "TOS + ECN" BOLD_TAG_END " ---- %1").arg(strBinaryuint8_t(ip->ip_tos)) + NEWLINE);
    
    //printf("\n		Total Len ---- %d bytes\n", ntohs(ip->ip_len));
    infoStr->append(TAB + QString(BOLD_TAG_START "Total Len" BOLD_TAG_END " ---- %1 bytes").arg(ntohs(ip->ip_len)) + NEWLINE);
	
    //printf("		Offset ------- %d bytes\n", IP_OFFSET(ip) * 8);
	infoStr->append(TAB + QString(BOLD_TAG_START "Offset" BOLD_TAG_END " ------- %1 bytes").arg(IP_OFFSET(ip) * 8) + NEWLINE);
    
    //printf("		Flags+Offset - 0x%04X\n", ip->ip_off);
    char flagsOffsetBuffer[5];
    snprintf(flagsOffsetBuffer, sizeof(flagsOffsetBuffer), "%04X", ip->ip_off);
    infoStr->append(TAB + QString(BOLD_TAG_START "Flags+Offset" BOLD_TAG_END " - 0x%1").arg(flagsOffsetBuffer) + NEWLINE);
    
    //printf("		TTL ---------- %d\n", ip->ip_ttl);
    infoStr->append(TAB + QString(BOLD_TAG_START "TTL" BOLD_TAG_END " ---------- %1").arg(ip->ip_ttl) + NEWLINE);
    
	
	//printf("		Checksum ----- 0x%04X\n", ntohs(ip->ip_sum));
	char checksumBuffer[5];
    snprintf(checksumBuffer, sizeof(checksumBuffer), "%04X", ntohs(ip->ip_sum));
    infoStr->append(TAB + QString(BOLD_TAG_START "Checksum" BOLD_TAG_END " ----- 0x%1").arg(checksumBuffer) + NEWLINE);
    
    //printf("		Source ------- %s\n", inet_ntop(2, &ip->ip_src, addressBuffer, INET_ADDRSTRLEN));
    infoStr->append(TAB + QString(BOLD_TAG_START "Source" BOLD_TAG_END " ------- %1").arg(inet_ntop(AF_INET, &ip->ip_src, addressBuffer, INET_ADDRSTRLEN)) + NEWLINE);
    
	//printf("		Destination -- %s\n", inet_ntop(2, &ip->ip_dst, addressBuffer, INET_ADDRSTRLEN));
    infoStr->append(TAB + QString(BOLD_TAG_START "Destination" BOLD_TAG_END " -- %1").arg(inet_ntop(AF_INET, &ip->ip_dst, addressBuffer, INET_ADDRSTRLEN)) + NEWLINE);
    
	//printf("		Protocol ----- %u ", ip->ip_p);
    infoStr->append(TAB + QString(BOLD_TAG_START "Protocol" BOLD_TAG_END " ----- %1").arg(ip->ip_p));
    
	//Determine the transport layer protocol
	switch(ip->ip_p){
		case IP_TCP: {
			//printf("(TCP)\n");
            infoStr->append("(TCP)" NEWLINE);
			handle_tcp_fill(infoStr, (struct sniff_tcp*)(((char*)ip) + size_ip), ntohs(ip->ip_len)-size_ip);
			break;
		}
		case IP_UDP: {
			//printf("(UDP)\n");
            infoStr->append("(UDP)" NEWLINE);
			handle_udp_fill(infoStr, (struct sniff_udp *)(((char *)ip) + size_ip));
			break;
		}
		case IPV4_ICMP:{
			//printf("(ICMP)\n");
            infoStr->append("(ICMP)" NEWLINE);
			handle_icmp_fill(infoStr, (uint8_t *)ip + size_ip, ntohs(ip->ip_len)-size_ip);
			break;
		}
		default: {
			//printf(YELLOW "(Not implemented yet)" RESET "\n");
            infoStr->append(YELLOW_FONT_START "(Not implemented yet)" YELLOW_FONT_END NEWLINE);
			break;
		}
	}
}
