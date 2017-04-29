#ifndef HTTP_H
#define HTTP_H

#include <QList>
#include <QStandardItem>

void handle_http(QList<QStandardItem *> *row, const char *data, uint16_t size);
void handle_http_fill(QString *infoStr, const char *data, uint16_t size);

//void printbyte(char byte);

#endif // HTTP_H

