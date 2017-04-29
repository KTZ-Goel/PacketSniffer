#ifndef HTTPS_H
#define HTTPS_H

#include <stdint.h>

#include <QList>
#include <QStandardItem>

//SSL content types
#define SSL_CTYPE_HANDSHAKE 	22	//CTYPE = content type
#define SSL_CTYPE_APP_DATA  	23	

//SSL versions
#define SSL_VERSION_SSLV3		0x0300
#define SSL_VERSION_TLSV1		0x0301
#define SSL_VERSION_TLSV12		0x0303

struct sniff_https{
	uint8_t  hh_type;
	uint16_t hh_version;
	uint16_t hh_len;
};

void handle_https(QList<QStandardItem *> *row, const uint8_t *https, uint16_t size);
void handle_https_fill(QString *infoStr, const uint8_t *https, uint16_t size);

#endif // HTTPS_H