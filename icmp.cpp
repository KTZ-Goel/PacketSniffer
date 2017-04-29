#include <stdio.h>
#include <colors.h>
#include <arpa/inet.h>
#include <time.h>
#include <string.h>

#include "icmp.h"

#include "shared.h"
#include "tags.h"

/*
	The timestamp for the icmp echo (ping) request/reply is an integer
	representing the number of milliseconds since epoch time
*/

void handle_icmp(QList<QStandardItem *> *row, const uint8_t *data, uint16_t length){	
	uint8_t type = data[0];
	uint8_t code = data[1];
	uint16_t checksum = ntohs(((uint16_t *)(data+2))[0]);

	uint16_t offset = 4;
    
	printf(CYAN "	ICMP:\n" RESET);
	row->append(new QStandardItem("ICMP"));
    
    QString infoStr;
    
	printf("		Type --------- [%u] ", type);
	switch(type){
		case ICMP_TYPE_ECHO_REPLY: {
			printf("Echo reply\n");
            infoStr += "Echo Reply, ";
			time_t seconds = *((time_t *)(data) + 2);
			time_t ms = *((time_t *)(data) + 3);
			printTimestamp(&infoStr, seconds, ms);
			break;
		}
		case ICMP_TYPE_ECHO_REQUEST: {
			printf("Echo request\n");
            infoStr += "Echo Request, ";
			time_t seconds = *((time_t *)(data) + 2);
			time_t ms = *((time_t *)(data) + 3);
			printTimestamp(&infoStr, seconds, ms);
			break;
		}
		case ICMP_TYPE_DEST_UNREACH: {
			printf("Destination unreachable\n");
            infoStr += "Destination unreachable";
			break;
		}
		/*
		case ICMP_TYPE_TRACEROUTE: {
			printf("Traceroute\n");
			break;
		}
		*/
		default: {
			printf( YELLOW "Unknown type\n" RESET);
			break;
		}
	}
    
    row->append(new QStandardItem(infoStr));
    
	printf("		Code --------- [%u]\n", code);
	printf("		Checksum ----- 0x%04X\n", checksum);
	printf("		Data:\n\t\t\t");

	data += offset;
	uint16_t n = 0;   //Used for newlines
	while(offset < length){
		if(n == 4){
			printf("\n\t\t\t");
			n = 0;
		}
		printBinaryuint8_t(*data);
		putchar(' ');
		data++;
		n++;
		offset++;
	}

	putchar('\n');
}

void handle_icmp_fill(QString *infoStr, const uint8_t *data, uint16_t length){
    uint8_t  type     = data[0];
	uint8_t  code     = data[1];
	uint16_t checksum = ntohs(((uint16_t *)(data+2))[0]);
	uint16_t offset   = 4;
    
	//printf(CYAN "	ICMP:\n" RESET);
    infoStr->append(QString(HEADER_TAG_START "ICMP:" HEADER_TAG_END NEWLINE));
    
	//printf("		Type --------- [%u] ", type);
    infoStr->append(QString(TAB BOLD_TAG_START "Type" BOLD_TAG_END " --------- [%1] ").arg(type));
	switch(type){
		case ICMP_TYPE_ECHO_REPLY: {
			//printf("Echo reply\n");
            infoStr->append("Echo reply" NEWLINE);
			time_t seconds = *((time_t *)(data) + 2);
			time_t ms = *((time_t *)(data) + 3);
			//printTimestamp(&infoStr, seconds, ms);
            infoStr->append(TAB BOLD_TAG_START "Timestamp ---- " BOLD_TAG_END);
            infoStr->append(getTimeStamp(seconds, ms));
            infoStr->append(NEWLINE);
			break;
		}
		case ICMP_TYPE_ECHO_REQUEST: {
			//printf("Echo request\n");
            infoStr->append("Echo request" NEWLINE);
			time_t seconds = *((time_t *)(data) + 2);
			time_t ms = *((time_t *)(data) + 3);
			break;
		}
		case ICMP_TYPE_DEST_UNREACH: {
			//printf("Destination unreachable\n");
            infoStr->append("Destination unreachable" NEWLINE);
			break;
		}
		/*
		case ICMP_TYPE_TRACEROUTE: {
			printf("Traceroute\n");
			break;
		}
		*/
		default: {
			//printf( YELLOW "Unknown type\n" RESET);
            infoStr->append(YELLOW_FONT_START "Unknown type" YELLOW_FONT_END NEWLINE);
			break;
		}
	}
    
	//printf("		Code --------- [%u]\n", code);
    infoStr->append(QString(TAB BOLD_TAG_START "Code" BOLD_TAG_END " --------- [%1]" NEWLINE).arg(code));
	//printf("		Checksum ----- 0x%04X\n", checksum);
    char checksumBuffer[5];
    snprintf(checksumBuffer, sizeof(checksumBuffer), "%04X", checksum);
    infoStr->append(QString(TAB BOLD_TAG_START "Checksum" BOLD_TAG_END " ----- 0x%1" NEWLINE).arg(checksumBuffer));
	//printf("		Data:\n\t\t\t");
    infoStr->append(TAB BOLD_TAG_START "Data:" BOLD_TAG_END NEWLINE TAB TAB);

	data += offset;
	uint16_t n = 0;   //Used for newlines
	while(offset < length){
		if(n == 4){
			//printf("\n\t\t\t");
            infoStr->append(NEWLINE TAB TAB);
			n = 0;
		}
		//printBinaryuint8_t(*data);
        infoStr->append(strBinaryuint8_t(*data));
		//putchar(' ');
        infoStr->append(' ');
		data++;
		n++;
		offset++;
	}

	//putchar('\n');
}

void printTimestamp(QString *infoStr, time_t seconds, time_t ms){
	char *datetime = ctime(&seconds);
	datetime[strlen(datetime)-1] = '\0';

	int i = strlen(datetime);
	while(datetime[i] != ' '){	//Find the index of the last space (the space right before the year)
		i--;
	}
	printf("		Timestamp ---- ");
	int j = 0;
	while(j < i){
		putchar(datetime[j]);
        infoStr->append(datetime[j]);
		j++;
	}

	printf(".%u%s\n", (uint32_t)ms, datetime+i);
    
    infoStr->append(QString(".%1%2").arg(ms).arg(QString(datetime+i)));
}

QString getTimeStamp(time_t seconds, time_t ms){
    char *datetime = ctime(&seconds);
	datetime[strlen(datetime)-1] = '\0';
    
    QString timeString;
    
	int i = strlen(datetime);
	while(datetime[i] != ' '){	//Find the index of the last space (the space right before the year)
		i--;
	}
    
	int j = 0;
	while(j < i){
        timeString.append(datetime[j]);
		j++;
	}
    
    timeString.append(QString(".%1%2").arg(ms).arg(QString(datetime+i)));
    
    return timeString;
}