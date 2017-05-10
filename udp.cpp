#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <arpa/inet.h>

#include "udp.h"
#include "ports.h"
#include "dns.h"

#include "colors.h"
#include "shared.h"
#include "tags.h"

void handle_udp(QList<QStandardItem *> *row, const struct sniff_udp *udp){
	uint16_t sourcePort = ntohs(udp->uh_sport);
	uint16_t destinationPort = ntohs(udp->uh_dport);
	uint16_t length = ntohs(udp->uh_len);
	uint16_t checksum = ntohs(udp->uh_sum);
	
	printf(CYAN "	UDP Header:\n" RESET);
    
	if(length < 8){
		printf(RED "		Invalid UDP header length: %u bytes\n" NORMAL, length);
		return;
	}
	
	printf("		Src. port ---- %u\n", sourcePort);
	printf("		Dest. Port --- %u\n", destinationPort);
	printf("		Length ------- %u bytes\n", length);
	printf("		Checksum ----- 0x%X\n", checksum);
	
	bool portFound = false;
	
	switch(destinationPort){
		case PORT_DNS: {
			handle_dns(row, (struct sniff_dns *)(((char *)udp) + 8));
			portFound = true;
			break;
		}
	}
	if(portFound == false){
		switch(sourcePort){
			case PORT_DNS: {
				handle_dns(row, (struct sniff_dns *)(((char *)udp) + 8));
				break;
			}
			default: {
				printf(YELLOW "	Application layer protocol [%d] not implemented yet." RESET "\n", destinationPort);
			}
		}
	}
}

void handle_udp_fill(QString *infoStr, const struct sniff_udp *udp){
    uint16_t sourcePort      = ntohs(udp->uh_sport);
	uint16_t destinationPort = ntohs(udp->uh_dport);
	uint16_t length          = ntohs(udp->uh_len);
	uint16_t checksum        = ntohs(udp->uh_sum);
	
	//printf(CYAN "	UDP Header:\n" RESET);
    infoStr->append(HEADER_TAG_START "UDP Header:" HEADER_TAG_END NEWLINE);
    
	if(length < 8){
		//printf(RED "		Invalid UDP header length: %u bytes\n" NORMAL, length);
        infoStr->append(TAB ERROR_TAG_START + QString("Invalid UDP header length: %1 bytes").arg(length) + ERROR_TAG_END);
		return;
	}
	
	//printf("		Src. port ---- %u\n", sourcePort);
	infoStr->append(TAB + QString(BOLD_TAG_START "Src. port" BOLD_TAG_END " ---- %1").arg(sourcePort) + NEWLINE);
    
    //printf("		Dest. Port --- %u\n", destinationPort);
	infoStr->append(TAB + QString(BOLD_TAG_START "Dest. Port" BOLD_TAG_END " --- %1").arg(destinationPort) + NEWLINE);
    
    //printf("		Length ------- %u bytes\n", length);
	infoStr->append(TAB + QString(BOLD_TAG_START "Length" BOLD_TAG_END " ------- %1 bytes").arg(length) + NEWLINE);
    
    //printf("		Checksum ----- 0x%X\n", checksum);
    infoStr->append(TAB + QString(BOLD_TAG_START "Checksum" BOLD_TAG_END " ----- 0x%1").arg(checksum) + NEWLINE);
    
	bool portFound = false;
	
	switch(destinationPort){
		case PORT_DNS: {
			handle_dns_fill(infoStr, (struct sniff_dns *)(((char *)udp) + 8));
			portFound = true;
			break;
		}
	}
	if(portFound == false){
		switch(sourcePort){
			case PORT_DNS: {
				handle_dns_fill(infoStr, (struct sniff_dns *)(((char *)udp) + 8));
				break;
			}
			default: {
				//printf(YELLOW "	Application layer protocol [%d] not implemented yet." RESET "\n", destinationPort);
                infoStr->append(QString(TAB "Neither port is implemented yet." NEWLINE));
			}
		}
	}
    
}
