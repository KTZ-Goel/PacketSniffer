#include <stdio.h>
#include <stdint.h>
#include <colors.h>

#include "http.h"

#include "tags.h"
#include "shared.h"

void handle_http(QList<QStandardItem *> *row, const char *data, uint16_t size){
	int n;			//number of characters read
	int i = 0;		//index into data
    
	printf(CYAN "	HTTP:\n" RESET);
    row->append(new QStandardItem("HTTP"));
	
    if(size == 0){
		printf("		This packet contains no more data\n");
        row->append(new QStandardItem("Acknowledgement, No more data"));
		return;
	}
	if(strncmp(data, "GET", 3) == 0 || strncmp(data, "HTTP", 4) == 0){
        bool firstLineRead = false;
		do{
			n = 0;
			printf("\t\t");
            if(firstLineRead == false){
                QString infoString;
                while(data[i] != '\r'){
                    putchar(data[i]);
                    infoString.append(data[i]);
                    i++;
                    n++;
                }
                row->append(new QStandardItem(infoString));
                firstLineRead = true;
            }
            else{
                while(data[i] != '\r'){
                    putchar(data[i]);
                    i++;
                    n++;
                }
            }
			printf("\n");
			i += 2;
		}while(n > 0);
	}
	else{
        row->append(new QStandardItem("HTTP Data"));
		i = 0;
		n = 1;
		printf("\t\t");
		while(i < size){
			if(data[i] >= 32 && data[i] <= 126){
				putchar(data[i]);
			}
			else{
				putchar('.');
			}
			
			//printbyte(data[i]);
			if((n & 0x3F) == 0){
				printf("\n\t\t");
			}
			n++;
			i++;
		}
		putchar('\n');
	}
}

void handle_http_fill(QString *infoStr, const char *data, uint16_t size){
    int n;			//number of characters read
	int i = 0;		//index into data
    
	//printf(CYAN "	HTTP:\n" RESET);
    infoStr->append(HEADER_TAG_START "HTTP:" HEADER_TAG_END NEWLINE);
	
    if(size == 0){
		//printf("		This packet contains no more data\n");
        infoStr->append(TAB "This packet contains no more data" NEWLINE);
		return;
	}
	if(strncmp(data, "GET", 3) == 0 || strncmp(data, "HTTP", 4) == 0){
		do{
			n = 0;
			//printf("\t\t");
            infoStr->append(TAB);
            while(data[i] != '\r'){
                //putchar(data[i]);
                infoStr->append(IS_PRINTABLE(data[i]) ? data[i] : '.');
                i++;
                n++;
            }
            
			//printf("\n");
            infoStr->append(NEWLINE);
			i += 2;
		}while(n > 0);
	}
	else{
        QHash<char, QString> htmlEntities;
        htmlEntities.insert('<', "&lt;");
        htmlEntities.insert('>', "&gt;");
        
		i = 0;
		n = 1;
		//printf("\t\t");
        infoStr->append(TAB);
		while(i < size){
            char c = data[i];
            if(IS_PRINTABLE(c)){
                if(htmlEntities.contains(c)){
                    infoStr->append(htmlEntities.value(c));
                }
                else{
                    infoStr->append(c);
                }
            }
            else{
                infoStr->append('.');
            }
            /*
			if(data[i] >= 32 && data[i] <= 126){
				putchar(data[i]);
			}
			else{
				putchar('.');
			}
			*/
            
			//printbyte(data[i]);
			if(n == 32){
				//printf("\n\t\t");
                infoStr->append(NEWLINE TAB);
                n = 0;
			}
			n++;
			i++;
		}
		//putchar('\n');
	}
}

/*
void printbyte(char byte){
	uint8_t mask = 128;
	while(mask > 0){
		printf("%d", ((byte & mask) ? 1 : 0));
		mask >>= 1;
	}
}
*/