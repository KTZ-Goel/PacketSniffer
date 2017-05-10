#include <stdio.h>
#include <stdint.h>
#include <arpa/inet.h>

#include "dns.h"

#include "colors.h"
#include "shared.h"
#include "tags.h"

void handle_dns(QList<QStandardItem *> *row, const struct sniff_dns *dns){
	uint16_t id = ntohs(dns->dh_id);
	uint16_t flags = ntohs(dns->dh_flags);
	uint16_t questionCount = ntohs(dns->dh_question_count);
	uint16_t answerCount = ntohs(dns->dh_answer_count);
	uint16_t nameServerCount = ntohs(dns->dh_name_server_count);
	uint16_t additionalRecordCount = ntohs(dns->dh_additional_record_count);
	
	printf(CYAN "	DNS:\n" RESET);
    row->append(new QStandardItem("DNS"));
	printf("		ID ----------- 0x%X\n", id);
	printf("		Flags:");
    
    QString infoString;
    
    infoString += "id: " + QString::number(id) + ", ";
    
	//Response or Query?
	printf("\n\t\t\t"); printBinaryuint16_tdots(flags, 0, 0);
	if(DH_IS_RESPONSE(flags)){
		printf("Response");
        infoString += "Response, ";
	}
	else{
		printf("Query");
        //infoString += "Query";
	}

	//OPCODE
	uint16_t opcode = DH_OPCODE(flags);
	printf("\n\t\t\t");printBinaryuint16_tdots(flags, 1, 4);
	switch(opcode){
		case DH_OPCODE_QUERY: {
            if(DH_IS_RESPONSE(flags) == false){
                infoString += "Standard Query, ";
            }
			printf(" Standard Query");
			break;
		}
		case DH_OPCODE_IQUERY: {
			printf(" Inverse Query");
			break;
		}
		case DH_OPCODE_STATUS: {
			printf(" Status Query");
			break;
		}
		case DH_OPCODE_RESERVED: {
			printf(" Unnasigned operation code");
			break;
		}
		case DH_OPCODE_NOTIFY: {
			printf(" Notify Query");
			break;
		}
		case DH_OPCODE_UPDATE: {
			printf(" Update Query");
			break;
		}
		default: {
			printf( YELLOW " Operation code %u unknown" RESET, opcode);
			break;
		}
	}

	//Authoritative flag
	printf("\n\t\t\t"); printBinaryuint16_tdots(flags, 5, 5);
	if(DH_IS_AUTHORITATIVE(flags)){
		printf(" Authoritative");
	}
	else{
		printf(" Not authoritative");
	}

	//Truncation flag
	printf("\n\t\t\t"); printBinaryuint16_tdots(flags, 6, 6);
	if(DH_IS_TRUNC(flags)){
		printf(" Truncated");
	}
	else{
		printf(" Not truncated");
	}

	//Recursion desired flag
	printf("\n\t\t\t"); printBinaryuint16_tdots(flags, 7, 7);
	if(DH_REC_DESIRED(flags)){
		printf(" Recursion desired");
	}
	else{
		printf(" Recursion not desired");
	}

	//Recursion available flag
	printf("\n\t\t\t"); printBinaryuint16_tdots(flags, 8, 8);
	if(DH_REC_AVAILABLE(flags)){
		printf(" Recursion available");
	}
	else{
		printf(" Recursion not available");
	}

	//Zero bits
	printf("\n\t\t\t"); printBinaryuint16_tdots(flags, 9, 11);
	if(DH_RESERVED(flags)){
		printf(RED " Reserved bits not zeroed" RESET);
	}
	else{
		printf(" Reserved bits zeroed (as they should be)");
	}

	//Response code
	uint16_t rcode = DH_RCODE(flags);
	printf("\n\t\t\t"); printBinaryuint16_tdots(flags, 12, 15);
	switch(rcode){
		case DH_RCODE_NO_ERR: {
			printf(" No error occured");
			break;
		}
		case DH_RCODE_FMT_ERR: {
			printf(" Format error");
			break;
		}
		case DH_RCODE_SERV_ERR: {
			printf(" Server Failure");
			break;
		}
		case DH_RCODE_NAME_ERR: {
			printf(" Non-existant domain");
			break;
		}
		case DH_RCODE_NOT_IMPL: {
			printf(" Not implemented");
			break;
		}
		case DH_RCODE_REFUSED: {
			printf(" Query refused");
			break;
		}
		default: {
			printf( YELLOW " Response code %u not implemented yet" RESET, rcode);
		}
	}

	//Print out the questions
	printf("\n		Questions ---- %u\n", questionCount);
	int i;
	char *payload = ((char *)dns) + 12;	
	for(i=0; i<questionCount; i++){
		printf("			#%d. ", i+1);		//Print out the question number
		while(*payload <= 31){					//Skip every byte until you get a valid ascii character
			payload++;
		}
		//Print out a dot if the character is not an ascii character
		while(*payload != 0){
			if(*payload >= 32){
				putchar(*payload);
                infoString.append(*payload);
			}
			else{
				putchar('.');
                infoString.append('.');
			}
			payload++;
		}
		payload++;
		putchar('\n');
        infoString += ", ";
		payload += 4;	//Skip the 2 byte type field and the 2 byte class field
	}

	//Print out the answers
	printf("		Answers ------ %u\n", answerCount);
	if(answerCount > 0){
		for(i=0; i<answerCount; i++){
			uint16_t name = ntohs(*((uint16_t *)payload));
			payload += 2;

			uint16_t type = ntohs(*((uint16_t *)payload));
			payload += 2;

			uint16_t dnsClass = ntohs(*((uint16_t *)payload));
			payload += 2;

			uint32_t ttl = ntohl(*((uint32_t *)payload));
			payload += 4;

			uint16_t length = ntohs(*((uint16_t *)payload));
			payload += 2;

			printf("			#%d:\n", i+1);
			printf("				Name -- ");
			char *nameptr = (char *)dns;
			if(DH_IS_POINTER(name)){
				nameptr += DH_NAME_OFFSET(name);
			}
			while((*nameptr) != 0){
				// First Check if the next 2 characters are actually a pointer
				name = *((uint16_t *)nameptr);
				name = ntohs(name);
				if(DH_IS_POINTER(name)){
					nameptr = ((char *)dns) + DH_NAME_OFFSET(name);
				}
				
				char c = *nameptr;
				putchar(IS_PRINTABLE(c) ? c : '.');
                infoString.append(IS_PRINTABLE(c) ? c : '.');
				nameptr++;
			}
			putchar('\n');
            infoString.append('.');
			printf("				Type -- ");
			switch(type){
				case DH_RECORD_A: {
					if(length == 4){
						char address[INET_ADDRSTRLEN];
						printf("A: %s\n", inet_ntop(AF_INET, payload, address, sizeof(address)));
                        infoString += QString(address);
					}
					break;
				}
				case DH_RECORD_CNAME: {
					//printf("			#%d. CNAME, offset: 0x%X bytes.\n", i+1, ntohs(name & 0x3FFF));
					printf("CNAME: ");
                    infoString.append("CNAME: ");
					int i = 0;
					while(i < length-2){
						char c = payload[i];
						putchar(IS_PRINTABLE(c) ? c : '.');
                        infoString.append(IS_PRINTABLE(c) ? c : '.');
						i++;
					}
					name = *((uint16_t *)(payload + i));
					name = ntohs(name);
					if(DH_IS_POINTER(name)){
						char *cnameptr = (char *)dns + DH_NAME_OFFSET(name);
						while((*cnameptr) != 0){
							// First Check if the next 2 characters are actually a pointer
							name = *((uint16_t *)cnameptr);
							name = ntohs(name);
							if(DH_IS_POINTER(name)){
								cnameptr = ((char *)dns) + DH_NAME_OFFSET(name);
							}
							
							char c = *cnameptr;
							putchar(IS_PRINTABLE(c) ? c : '.');
                            infoString.append(IS_PRINTABLE(c) ? c : '.');
							cnameptr++;
						}
					}
					putchar('\n');
					break;
				}
			}
			printf("				Class - [%u] ", dnsClass);
			switch(dnsClass){
				case DNS_CLASS_IN:{
					printf("(Internet)");
					break;
				}
				default: {
					printf(YELLOW " (Unknown)" RESET);
					break;
				}
			}
			putchar('\n');

			printf("				TTL --- %u seconds\n", ttl);

			printf("				Len --- %u bytes\n", length);
			payload += length;
		}
	}
    row->append(new QStandardItem(infoString));
    
	printf("		NS Count ----- %u\n", nameServerCount);
	printf("		AR Count ----- %u\n", additionalRecordCount);
}

void handle_dns_fill(QString *infoStr, const struct sniff_dns *dns){
    uint16_t id = ntohs(dns->dh_id);
	uint16_t flags = ntohs(dns->dh_flags);
	uint16_t questionCount = ntohs(dns->dh_question_count);
	uint16_t answerCount = ntohs(dns->dh_answer_count);
	uint16_t nameServerCount = ntohs(dns->dh_name_server_count);
	uint16_t additionalRecordCount = ntohs(dns->dh_additional_record_count);
	
	//printf(CYAN "	DNS:\n" RESET);
    infoStr->append(HEADER_TAG_START "DNS:" HEADER_TAG_END NEWLINE);
    
	//printf("		ID ----------- 0x%X\n", id);
	char idBuffer[5];
    snprintf(idBuffer, sizeof(idBuffer), "%X", id);
    infoStr->append(TAB + QString(BOLD_TAG_START "ID" BOLD_TAG_END " ----------- 0x%1").arg(idBuffer) + NEWLINE);
    
    //printf("		Flags:");
    infoStr->append(TAB BOLD_TAG_START "Flags: " BOLD_TAG_END);
    
    
	//Response or Query?
	//printf("\n\t\t\t"); printBinaryuint16_tdots(flags, 0, 0);
    infoStr->append(NEWLINE TAB TAB);
    infoStr->append(strBinaryuint16_tdots(flags, 0, 0));
	if(DH_IS_RESPONSE(flags)){
		//printf(" Response");
        infoStr->append(" Response");
	}
	else{
		//printf(" Query");
        infoStr->append(" Query");
	}
    
    
	//OPCODE
	uint16_t opcode = DH_OPCODE(flags);
	//printf("\n\t\t\t");printBinaryuint16_tdots(flags, 1, 4);
    infoStr->append(NEWLINE TAB TAB);
    infoStr->append(strBinaryuint16_tdots(flags, 1, 4));
    
	switch(opcode){
		case DH_OPCODE_QUERY: {
			//printf(" Standard Query");
            infoStr->append(" Standard Query");
			break;
		}
		case DH_OPCODE_IQUERY: {
			//printf(" Inverse Query");
            infoStr->append(" Inverse Query");
			break;
		}
		case DH_OPCODE_STATUS: {
			//printf(" Status Query");
            infoStr->append(" Status Query");
			break;
		}
		case DH_OPCODE_RESERVED: {
			//printf(" Unnasigned operation code");
            infoStr->append(" Unnasigned operation code");
			break;
		}
		case DH_OPCODE_NOTIFY: {
			printf(" Notify Query");
			break;
		}
		case DH_OPCODE_UPDATE: {
			//printf(" Update Query");
            infoStr->append(" Update Query");
			break;
		}
		default: {
			//printf( YELLOW " Operation code %u unknown" RESET, opcode);
            infoStr->append(QString(YELLOW_FONT_START " Operation code %1 unknown" YELLOW_FONT_END).arg(opcode));
			break;
		}
	}
    
	//Authoritative flag
	//printf("\n\t\t\t"); printBinaryuint16_tdots(flags, 5, 5);
    infoStr->append(NEWLINE TAB TAB);
    infoStr->append(strBinaryuint16_tdots(flags, 5, 5));
	if(DH_IS_AUTHORITATIVE(flags)){
		//printf(" Authoritative");
        infoStr->append(" Authoritative");
	}
	else{
		//printf(" Not authoritative");
        infoStr->append(" Not authoritative");
	}
    
    
	//Truncation flag
	//printf("\n\t\t\t"); printBinaryuint16_tdots(flags, 6, 6);
    infoStr->append(NEWLINE TAB TAB);
    infoStr->append(strBinaryuint16_tdots(flags, 6, 6));
	if(DH_IS_TRUNC(flags)){
		//printf(" Truncated");
        infoStr->append(" Truncated");
	}
	else{
		//printf(" Not truncated");
        infoStr->append(" Not truncated");
	}
    
    
	//Recursion desired flag
	//printf("\n\t\t\t"); printBinaryuint16_tdots(flags, 7, 7);
    infoStr->append(NEWLINE TAB TAB);
    infoStr->append(strBinaryuint16_tdots(flags, 7, 7));
	if(DH_REC_DESIRED(flags)){
		//printf(" Recursion desired");
        infoStr->append(" Recursion desired");
	}
	else{
		//printf(" Recursion not desired");
        infoStr->append(" Recursion not desired");
	}
    
	//Recursion available flag
	//printf("\n\t\t\t"); printBinaryuint16_tdots(flags, 8, 8);
    infoStr->append(NEWLINE TAB TAB);
    infoStr->append(strBinaryuint16_tdots(flags, 8, 8));
	if(DH_REC_AVAILABLE(flags)){
		//printf(" Recursion available");
        infoStr->append(" Recursion available");
	}
	else{
		//printf(" Recursion unavailable");
        infoStr->append(" Recursion unavailable");
	}

	//Zero bits
	//printf("\n\t\t\t"); printBinaryuint16_tdots(flags, 9, 11);
    infoStr->append(NEWLINE TAB TAB);
    infoStr->append(strBinaryuint16_tdots(flags, 9, 11));
	if(DH_RESERVED(flags)){
		//printf(RED " Reserved bits not zeroed" RESET);
        infoStr->append(" Reserved bits not zeroed");
	}
	else{
		//printf(" Reserved bits zeroed");
        infoStr->append(" Reserved bits zeroed");
	}
    
    
	//Response code
	uint16_t rcode = DH_RCODE(flags);
	//printf("\n\t\t\t"); printBinaryuint16_tdots(flags, 12, 15);
    infoStr->append(NEWLINE TAB TAB);
    infoStr->append(strBinaryuint16_tdots(flags, 12, 15));
	switch(rcode){
		case DH_RCODE_NO_ERR: {
			//printf(" No error occured");
            infoStr->append(" No error occured");
			break;
		}
		case DH_RCODE_FMT_ERR: {
			//printf(" Format error");
            infoStr->append(" Format error");
			break;
		}
		case DH_RCODE_SERV_ERR: {
			//printf(" Server Failure");
            infoStr->append(" Server Failure");
			break;
		}
		case DH_RCODE_NAME_ERR: {
			//printf(" Non-existant domain");
            infoStr->append(" Non-existant domain");
			break;
		}
		case DH_RCODE_NOT_IMPL: {
			//printf(" Not implemented");
            infoStr->append(" Not implemented");
			break;
		}
		case DH_RCODE_REFUSED: {
			//printf(" Query refused");
            infoStr->append(" Query refused");
			break;
		}
		default: {
			//printf( YELLOW " Response code %u not implemented yet" RESET, rcode);
            infoStr->append(QString(YELLOW_FONT_START " Response code %1 not implemented yet" YELLOW_FONT_END).arg(rcode));
		}
	}
    
	//Print out the questions
	//printf("\n		Questions ---- %u\n", questionCount);
    infoStr->append(QString(NEWLINE TAB BOLD_TAG_START "Questions" BOLD_TAG_END " ---- %1" NEWLINE).arg(questionCount));
	int i;
	char *payload = ((char *)dns) + 12;
	for(i=0; i<questionCount; i++){
		//printf("			#%d. ", i+1);		//Print out the question number
        infoStr->append(TAB TAB + QString("#%1. ").arg(i+1));
		while(*payload <= 31){					//Skip every byte until you get a valid ascii character
			payload++;
		}
		//Print out a dot if the character is not an ascii character
		while(*payload != 0){
			if(*payload >= 32){
				//putchar(*payload);
                infoStr->append(*payload);
			}
			else{
				//putchar('.');
                infoStr->append('.');
			}
			payload++;
		}
		payload++;
		//putchar('\n');
        infoStr->append(NEWLINE);
		payload += 4;	//Skip the 2 byte type field and the 2 byte class field
	}
    
    
	//Print out the answers
	//printf("		Answers ------ %u\n", answerCount);
    infoStr->append(QString(TAB BOLD_TAG_START "Answers" BOLD_TAG_END " ------ %1" NEWLINE).arg(answerCount));
	if(answerCount > 0){
		for(i=0; i<answerCount; i++){
			uint16_t name = ntohs(*((uint16_t *)payload));
			payload += 2;

			uint16_t type = ntohs(*((uint16_t *)payload));
			payload += 2;

			uint16_t dnsClass = ntohs(*((uint16_t *)payload));
			payload += 2;

			uint32_t ttl = ntohl(*((uint32_t *)payload));
			payload += 4;

			uint16_t length = ntohs(*((uint16_t *)payload));
			payload += 2;

			//printf("			#%d:\n", i+1);
            infoStr->append(QString(TAB TAB BOLD_TAG_START "#%1:" BOLD_TAG_END NEWLINE).arg(i+1));
            
			//printf("				Name -- ");
            infoStr->append(TAB TAB TAB BOLD_TAG_START "Name" BOLD_TAG_END " -- ");
            
			char *nameptr = (char *)dns;
			if(DH_IS_POINTER(name)){
				nameptr += DH_NAME_OFFSET(name);
			}
			while((*nameptr) != 0){
				// First Check if the next 2 characters are actually a pointer
				name = *((uint16_t *)nameptr);
				name = ntohs(name);
				if(DH_IS_POINTER(name)){
					nameptr = ((char *)dns) + DH_NAME_OFFSET(name);
				}
				
				char c = *nameptr;
				//putchar(IS_PRINTABLE(c) ? c : '.');
                infoStr->append(IS_PRINTABLE(c) ? c : '.');
				nameptr++;
			}
			//putchar('\n');
            infoStr->append(NEWLINE);
            
			//printf("				Type -- ");
            infoStr->append(TAB TAB TAB BOLD_TAG_START "Type" BOLD_TAG_END " -- ");
            
			switch(type){
				case DH_RECORD_A: {
					if(length == 4){
						char address[INET_ADDRSTRLEN];
						//printf("A: %s\n", inet_ntop(AF_INET, payload, address, sizeof(address)));
                        infoStr->append(QString("A: %1" NEWLINE).arg(inet_ntop(AF_INET, payload, address, sizeof(address))));
					}
					break;
				}
				case DH_RECORD_CNAME: {
					//printf("			#%d. CNAME, offset: 0x%X bytes.\n", i+1, ntohs(name & 0x3FFF));
					//printf("CNAME: ");
                    infoStr->append("CNAME: ");
					int i = 0;
					while(i < length-2){
						char c = payload[i];
						//putchar(IS_PRINTABLE(c) ? c : '.');
                        infoStr->append(IS_PRINTABLE(c) ? c : '.');
						i++;
					}
					name = *((uint16_t *)(payload + i));
					name = ntohs(name);
					if(DH_IS_POINTER(name)){
						char *cnameptr = (char *)dns + DH_NAME_OFFSET(name);
						while((*cnameptr) != 0){
							// First Check if the next 2 characters are actually a pointer
							name = *((uint16_t *)cnameptr);
							name = ntohs(name);
							if(DH_IS_POINTER(name)){
								cnameptr = ((char *)dns) + DH_NAME_OFFSET(name);
							}
							
							char c = *cnameptr;
							//putchar(IS_PRINTABLE(c) ? c : '.');
                            infoStr->append(IS_PRINTABLE(c) ? c : '.');
							cnameptr++;
						}
					}
					//putchar('\n');
                    infoStr->append(NEWLINE);
					break;
				}
			}
			//printf("				Class - [%u] ", dnsClass);
            infoStr->append(QString(TAB TAB TAB BOLD_TAG_START "Class" BOLD_TAG_END " - [%1] ").arg(dnsClass));
			switch(dnsClass){
				case DNS_CLASS_IN:{
					//printf("(Internet)");
                    infoStr->append("(Internet)");
					break;
				}
				default: {
					//printf(YELLOW " (Unknown)" RESET);
                    infoStr->append(YELLOW_FONT_START " (Unknown)" YELLOW_FONT_END);
					break;
				}
			}
			//putchar('\n');
            infoStr->append(NEWLINE);

			//printf("				TTL --- %u seconds\n", ttl);
            infoStr->append(QString(TAB TAB TAB BOLD_TAG_START "TTL" BOLD_TAG_END " --- %1 seconds" NEWLINE).arg(ttl));
            
			//printf("				Len --- %u bytes\n", length);
            infoStr->append(QString(TAB TAB TAB BOLD_TAG_START "Len" BOLD_TAG_END " --- %1 bytes" NEWLINE).arg(length));
			payload += length;
		}
	}
    
	//printf("		NS Count ----- %u\n", nameServerCount);
    infoStr->append(QString(TAB BOLD_TAG_START "NS Count" BOLD_TAG_END " ----- %1" NEWLINE).arg(nameServerCount));
	//printf("		AR Count ----- %u\n", additionalRecordCount);
    infoStr->append(QString(TAB BOLD_TAG_START "AR Count" BOLD_TAG_END " ----- %1" NEWLINE).arg(additionalRecordCount));
    
}
