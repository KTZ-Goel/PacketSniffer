#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <time.h>
#include <arpa/inet.h>
#include <colors.h>

#include <QList>
#include <QVariant>
#include <QStandardItem>

#include "ethernet.h"
#include "modelcolumnindexes.h"

/* Ethertypes */
#include "arp.h"
#include "ipv4.h"
#include "ipv6.h"

#include "shared.h"
#include "tags.h"

void handle_ethernet(QList<QStandardItem *> *row, const uint8_t *packet){
    
	//time_t currentTime = time(NULL);
	
	const struct sniff_ethernet *ethernet;		//The ethernet header
	
	ethernet = (struct sniff_ethernet*)packet;
	
	// Time printed in this format: YYYY/MM/DD HH:MM:SS
    /*
	struct tm *tmptr = localtime(&currentTime);
    printf(CYAN "	Time:\n" RESET);
    printf("		Y/M/D h:m:s -- %d/%02d/%02d %02d:%02d:%02d\n", tmptr->tm_year+1900, tmptr->tm_mon+1, tmptr->tm_mday, tmptr->tm_hour, tmptr->tm_min, tmptr->tm_sec);
    printf("		epoch time --- %ld seconds\n", (long)currentTime);
        
    //Append the time recieved column
    char date[20];
    snprintf(date, sizeof(date), "%d/%02d/%02d %02d:%02d:%02d", tmptr->tm_year+1900, 
                                                                tmptr->tm_mon+1, 
                                                                tmptr->tm_mday, 
                                                                tmptr->tm_hour, 
                                                                tmptr->tm_min, 
                                                                tmptr->tm_sec);
    date[sizeof(date)-1] = '\0';
    row->append(new QStandardItem(QString(date)));
    */
	
	//Ethernet header information
	printf(CYAN "	Ethernet Header:\n" RESET);
	printf("		Destination -- %02X:%02X:%02X:%02X:%02X:%02X\n", ethernet->ether_dhost[0], ethernet->ether_dhost[1], ethernet->ether_dhost[2], ethernet->ether_dhost[3], ethernet->ether_dhost[4], ethernet->ether_dhost[5]);
	printf("		Source ------- %02X:%02X:%02X:%02X:%02X:%02X\n", ethernet->ether_dhost[0], ethernet->ether_shost[1], ethernet->ether_shost[2], ethernet->ether_shost[3], ethernet->ether_shost[4], ethernet->ether_shost[5]);
	printf("		Ethertype ---- 0x%04X ", ntohs(ethernet->ether_type));

	//Determine the Network/Internet layer protocol
	switch(ntohs(ethernet->ether_type)){
		case ETHERTYPE_IPV4:{
			printf("(IPv4)\n");
			handle_ipv4(row, (struct sniff_ipv4*)(packet + SIZE_ETHERNET));
			break;
		}
		case ETHERTYPE_IPV6: {
			printf("(IPv6)\n");
			handle_ipv6(row, (struct sniff_ipv6*)(packet + SIZE_ETHERNET));
			break;
		}
		case ETHERTYPE_ARP: {
			printf("(ARP)\n");
			handle_arp(row, (struct sniff_arp*)(packet + SIZE_ETHERNET));
			break;
		}
		default: {
			printf(YELLOW "(Not implemented yet )" RESET "\n");
			break;
		}
	}
}

void handle_ethernet_fill(QString *infoStr, const char *data){
	const struct sniff_ethernet *ethernet = (struct sniff_ethernet*)data;    //The ethernet header

    //Ethernet header
    infoStr->append(HEADER_TAG_START "Ethernet Header" HEADER_TAG_END NEWLINE);
    
    char buffer[18];
    //Append the destination mac address
    snprintf(buffer, sizeof(buffer), "%02X:%02X:%02X:%02X:%02X:%02X", ethernet->ether_dhost[0], 
                                                                      ethernet->ether_dhost[1], 
                                                                      ethernet->ether_dhost[2], 
                                                                      ethernet->ether_dhost[3], 
                                                                      ethernet->ether_dhost[4], 
                                                                      ethernet->ether_dhost[5]);
    infoStr->append(TAB + QString(BOLD_TAG_START "Destination" BOLD_TAG_END " --- %1").arg(buffer) + NEWLINE);
    
    //Append the source mac address
    snprintf(buffer, sizeof(buffer), "%02X:%02X:%02X:%02X:%02X:%02X", ethernet->ether_shost[0], 
                                                                      ethernet->ether_shost[1], 
                                                                      ethernet->ether_shost[2], 
                                                                      ethernet->ether_shost[3], 
                                                                      ethernet->ether_shost[4], 
                                                                      ethernet->ether_shost[5]);
    infoStr->append(TAB + QString(BOLD_TAG_START "Source" BOLD_TAG_END " -------- %1").arg(buffer) + NEWLINE);
    
    infoStr->append(TAB + QString(BOLD_TAG_START "Ethertype" BOLD_TAG_END " ----- %1").arg(ntohs(ethernet->ether_type)));
    
	//Determine the Network/Internet layer protocol
	switch(ntohs(ethernet->ether_type)){
		case ETHERTYPE_IPV4:{
            infoStr->append("(IPv4)" NEWLINE);
			handle_ipv4_fill(infoStr, (struct sniff_ipv4*)(data + SIZE_ETHERNET));
			break;
		}
		case ETHERTYPE_IPV6: {
            infoStr->append("(IPv6)" NEWLINE);
			//handle_ipv6(row, (struct sniff_ipv6*)(data + SIZE_ETHERNET));
			break;
		}
		case ETHERTYPE_ARP: {
            infoStr->append("(ARP)" NEWLINE);
			handle_arp_fill(infoStr, (struct sniff_arp*)(data + SIZE_ETHERNET));
			break;
		}
		default: {
            infoStr->append(YELLOW_FONT_START "(Not implemented yet)" YELLOW_FONT_END NEWLINE);
			break;
		}
	}
}
