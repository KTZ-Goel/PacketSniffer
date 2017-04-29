#include <stdint.h>
#include <stdio.h>

#include "shared.h"


void printBinaryuint8_t(uint8_t byte){
	uint8_t mask = 0x80;	// 1000 0000
	//Print out the binary representation of 'byte', no newlines
	while(mask > 0){
		putchar((byte & mask) ? '1': '0');
		mask >>= 1;
	}
}

//Print out the binary representation of 'byte2', no newlines
void printBinaryuint16_t(uint16_t byte2){
	uint16_t mask = 0x8000;        // 1000 0000 0000 0000

	uint8_t n = 1;                 //counter to put a space between every 4 bits
	while(mask > 0){
		putchar((byte2 & mask) ? '1': '0');
		mask >>= 1;
		if((n & 0x03) == 0){         // (n & 0x03) is equivelant to (n % 4)
			putchar(' ');
		}
		n++;
	}
}

// Prints out the binary representation of the short, 
// but prints dots for values < start, and values > end
// Used to show the current flags in a uint16_t
// For example:
//      byte2 ----- 10010001 00001101
//      start ----- 3
//      end ------- 6;
//      printed --- "...1000.........", without the quotes and without newline
void printBinaryuint16_tdots(uint16_t byte2, int start, int end){
	int i = 0;

	while(i < start){
		putchar('.');
		i++;
	}

	uint16_t mask = 0x8000;
	mask >>= start;
	while(i <= end){
		putchar((byte2 & mask) ? '1': '0');
		mask >>= 1;
		i++;
	}

	while(i <= 15){
		putchar('.');
		i++;
	}
}

const char *strBinaryuint16_tdots(uint16_t byte2, int start, int end){
    static char buffer[17];
    int i = 0;

	while(i < start){
		//putchar('.');
        buffer[i] = '.';
		i++;
	}

	uint16_t mask = 0x8000;
	mask >>= start;
	while(i <= end){
		//putchar((byte2 & mask) ? '1': '0');
        buffer[i] = (byte2 & mask) ? '1' : '0';
		mask >>= 1;
		i++;
	}

	while(i <= 15){
		//putchar('.');
        buffer[i] = '.';
		i++;
	}
    
    buffer[16] = '\0';
    return buffer;
}

const char * strBinaryuint8_t(uint8_t byte){
    static char buffer[9];
    uint8_t mask = 0x80;	// 1000 0000
	//Turn the binary representation of 'byte' into a string
    int i = 0;
	while(mask > 0){
        buffer[i] = (byte & mask) ? '1' : '0';
        i++;
		mask >>= 1;
	}
    buffer[8] = '\0';
    return buffer;
}

void setBackgroundColor(QList<QStandardItem *> *row, QColor color){
    for (int i = 0; i < row->length(); ++i) {
        row->at(i)->setData(color, Qt::BackgroundColorRole);
    }
}

QString getHTMLentity(char c){
    QHash<char, QString> htmlEntities;
    htmlEntities.insert('<', "&lt;");
    htmlEntities.insert('>', "&gt;");
    
    if(htmlEntities.contains(c)){
        return htmlEntities.value(c);
    }
    else{
        return QString(c);
    }
}
