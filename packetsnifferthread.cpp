#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <pcap.h>
#include <arpa/inet.h>
#include <time.h>

#include <QDebug>
#include <QHash>

#include <QFile>
#include <QDataStream>
#include <QFileDialog>
#include <QStandardPaths>

#include "packetsnifferthread.h"
#include "modelcolumnindexes.h"
#include "ethernet.h"

#include "colors.h"
#include "shared.h"
#include "tags.h"


PacketSnifferThread::PacketSnifferThread(QStandardItemModel *packetModel, QStatusBar *statusBar){
    this->packetModel = packetModel;
    this->statusBar = statusBar;
    stopCapture = false;
    packetNumber = 0;
    rawDataView = Binary;
    captureSaved = false;
}

PacketSnifferThread::PacketSnifferThread(QStandardItemModel *packetModel, QString filePath, QStatusBar *statusBar){
    this->packetModel = packetModel;
    this->statusBar = statusBar;
    stopCapture = false;
    packetNumber = 0;
    rawDataView = Binary;
    captureSaved = false;
    
    QHash<QString, QColor> protocolColors;
    protocolColors.insert("ARP", QColor(255, 125, 125));      //Light Red
    protocolColors.insert("DNS", QColor(183, 247, 119));      //Light Green
    protocolColors.insert("HTTP", QColor(150, 255, 255));     //Light Cyan
    protocolColors.insert("HTTPS", QColor(121, 201, 201));    //Dark Cyan
    protocolColors.insert("ICMP", QColor(232, 209, 255));     //Light Purple
    protocolColors.insert("Unknown", QColor(255, 253, 140));  //Light Yellow
    
    const u_char *data;
    
    QFile file(filePath);
    file.open(QIODevice::ReadOnly);
    
    char sizeandtimestamp[8]; // Size and timestamp buffer
    while(file.read(sizeandtimestamp, 8) > 0){
        QList<QStandardItem *> row;                                          //The new row to be inserted
        
        //Append the number of the packet
        QStandardItem *packetNumberItem = new QStandardItem();
        packetNumberItem->setData(QVariant(packetNumber), Qt::DisplayRole);
        row.append(packetNumberItem);
        printf(GREEN "Packet #%d\n" NORMAL, packetNumber);
        
        packetNumber++;
        
        uint *size        = (uint *)&(sizeandtimestamp[0]);
        time_t *timestamp = (time_t *)&(sizeandtimestamp[4]);
        
        //Append the timestamp
        timeStamps.push_back(*timestamp);
        struct tm *tmptr = localtime(timestamp);
        printf(CYAN "	Time:\n" RESET);
        printf("		Y/M/D h:m:s -- %d/%02d/%02d %02d:%02d:%02d\n", tmptr->tm_year+1900, tmptr->tm_mon+1, tmptr->tm_mday, tmptr->tm_hour, tmptr->tm_min, tmptr->tm_sec);
        printf("		epoch time --- %ld seconds\n", (long)(*timestamp));
        
        char date[20];
        snprintf(date, sizeof(date), "%d/%02d/%02d %02d:%02d:%02d", tmptr->tm_year+1900, 
                                                                    tmptr->tm_mon+1, 
                                                                    tmptr->tm_mday, 
                                                                    tmptr->tm_hour, 
                                                                    tmptr->tm_min, 
                                                                    tmptr->tm_sec);
        date[sizeof(date)-1] = '\0';
        row.append(new QStandardItem(QString(date)));
        
        char packetData[*size];
        
        file.read(packetData, *size);
        
        //This has to be done first so that the source, destination, protocol, and info fields can be filled in
        handle_ethernet(&row, (uint8_t *) packetData);
        
        //Some protocols are not implemented yet, so sometimes this function will return and the row will have
        //less than 6 columns filled in, if this is the case, keep appending 'Unknown' to row until every 
        //column is filled in
        while(row.size() < 6){
            row.append(new QStandardItem("Unknown"));
        }
        
        //Copy the full packet into newData
        char *newData = (char *)malloc(*size);
        if(newData == NULL){
            printf("ERROR: Malloc failed\n");
            exit(1);
        }
        memcpy(newData, (void*)packetData, *size);
        
        //Inset the full size column
        QStandardItem *binaryDataSizeItem = new QStandardItem();
        binaryDataSizeItem->setData(QVariant(*size), Qt::DisplayRole);
        row.insert(BINARY_DATA_SIZE_COLUMN_INDEX, binaryDataSizeItem);
        rawData.push_back(newData);
        
        //Set the color of the packet to distinguish it from other packets
        if(protocolColors.contains(row.at(HIGHEST_LEVEL_PROTOCOL_COLUMN_INDEX)->text())){
            setBackgroundColor(&row, protocolColors.value(row.at(HIGHEST_LEVEL_PROTOCOL_COLUMN_INDEX)->text()));
        }
        
        //Add the row to the model
        packetModel->appendRow(row);
    }
}

PacketSnifferThread::~PacketSnifferThread(){
    for(size_t i=0; i<rawData.size(); i++){
        free(rawData.at(i));
    }
    
    rawData.clear();
}

void PacketSnifferThread::stopCapturing(void){
    stopCapture = true;
}

void PacketSnifferThread::run(){
    QHash<QString, QColor> protocolColors;
    protocolColors.insert("ARP", QColor(255, 125, 125));      //Light Red
    protocolColors.insert("DNS", QColor(183, 247, 119));      //Light Green
    protocolColors.insert("HTTP", QColor(150, 255, 255));     //Light Cyan
    protocolColors.insert("HTTPS", QColor(121, 201, 201));    //Dark Cyan
    protocolColors.insert("ICMP", QColor(232, 209, 255));     //Light Purple
    protocolColors.insert("Unknown", QColor(255, 253, 140));  //Light Yellow
    
    const char *device = ETHERNET_DEVICE;   //The device to sniff on
    pcap_t *handle;                         //The session handle
    char errorBuffer[PCAP_ERRBUF_SIZE];     //The buffer to store error messages in
    bpf_u_int32 networkNumber;              //32 bit network address
    bpf_u_int32 networkMask;                //32 bit network mask
    pcap_pkthdr *header;
    const u_char *data;
    captureSaved = false;
    
    //Obtain the network address and the network mask for the device
    if(pcap_lookupnet(device, &networkNumber, &networkMask, errorBuffer) == -1){
        statusBar->showMessage(QString("Can't get netmask for device %1, %2").arg(QString(device)).arg(QString(errorBuffer)));
        networkNumber = 0;
        networkMask = 0;
    }
    
    //Obtain a handle to the device, open the session in promiscuous mode
    handle = pcap_open_live(device, BUFSIZ, 1, 1000, errorBuffer);
    if(handle == NULL){
        statusBar->showMessage(QString("Couldn't open device %1, %2").arg(QString(device)).arg(QString(errorBuffer)));
        return;
    }
    
    int returnValue;
    while((returnValue = pcap_next_ex(handle, &header, &data)) >= 0 && stopCapture == false){
        if(returnValue == 1){
            //Get the time recieved for this packet.
            time_t currentTime = time(NULL);
            timeStamps.push_back(currentTime);
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
            
            QList<QStandardItem *> row;                                          //The new row to be inserted
            
            
            //Append the number of the packet
            QStandardItem *packetNumberItem = new QStandardItem();
            packetNumberItem->setData(QVariant(packetNumber), Qt::DisplayRole);
            row.append(packetNumberItem);
            
            //Append the time column
            row.append(new QStandardItem(QString(date)));
            
            printf(GREEN "Recieved packet #%d\n" NORMAL, packetNumber);
            
            packetNumber++;
            
            //This has to be done first so that the source, destination, protocol, and info fields can be filled in
            handle_ethernet(&row, data);
            
            //Some protocols are not implemented yet, so sometimes this function will return and the row will have
            //less than 6 columns filled in, if this is the case, keep appending 'Unknown' to row until every 
            //column is filled in
            while(row.size() < 6){
                row.append(new QStandardItem("Unknown"));
            }
            
            //Copy the full packet into newData
            char *newData = (char *)malloc(header->len);
            if(newData == NULL){
                printf("ERROR: Malloc failed\n");
                exit(1);
            }
            memcpy(newData, (void*)data, header->len);
            
            //Inset the full size column
            QStandardItem *binaryDataSizeItem = new QStandardItem();
            binaryDataSizeItem->setData(QVariant(header->len), Qt::DisplayRole);
            row.insert(BINARY_DATA_SIZE_COLUMN_INDEX, binaryDataSizeItem);
            rawData.push_back(newData);
            
            //Set the color of the packet to distinguish it from other packets
            if(protocolColors.contains(row.at(HIGHEST_LEVEL_PROTOCOL_COLUMN_INDEX)->text())){
                setBackgroundColor(&row, protocolColors.value(row.at(HIGHEST_LEVEL_PROTOCOL_COLUMN_INDEX)->text()));
            }
            
            //Add the row to the model
            packetModel->appendRow(row);
        }
    }
    if(returnValue == -1){
        printf(RED "An error occured while capturing.\n" RESET);
    }
    
    stopCapture = false;
    
    pcap_close(handle);
}

void PacketSnifferThread::fillInfoAndRawDataWidgets(QPlainTextEdit *infoTextEdit, QPlainTextEdit *rawDataTextEdit, int index, int size){
    //Append the packet info to the infoTextEdit
    QString infoStr;
    
    //infoStr += QString("Packet #%1").arg(pack) + NEWLINE;
    
    handle_ethernet_fill(&infoStr, rawData.at(index));
    infoTextEdit->clear();
    infoTextEdit->appendHtml(infoStr);
    
    //Append the raw binary data to the rawDataTextEdit
    rawDataTextEdit->clear();
    QString rawDataText;
    if(rawDataView == Binary){
        for(int i=0; i<size; i++){
            uint8_t byte = rawData.at(index)[i];
            uint8_t mask = 0x80;  //1000 0000
            while(mask > 0){
                rawDataText.append((byte & mask) ? '1' : '0');
                mask >>= 1;
            }
            rawDataText.append(' ');
        }
    }
    else if(rawDataView == Hexadecimal){
        char hexBuffer[3];
        for(int i=0; i<size; i++){
            snprintf(hexBuffer, sizeof(hexBuffer), "%02X", ((uint8_t *)rawData.at(index))[i]);
            rawDataText.append(hexBuffer);
            rawDataText.append(' ');
        }
    }
    
    rawDataTextEdit->appendHtml(rawDataText);
}

void PacketSnifferThread::setRawDataView(RawDataView rawDataView){
    this->rawDataView = rawDataView;
}

bool PacketSnifferThread::saveCapture(QString filePath){
    if(captureSaved == true){
        return false;
    }
    
    QFile saveFile(filePath);
    if(saveFile.open(QFile::WriteOnly) == false){ //Cant open the file
        return false;
    }
    if(saveFile.exists() && saveFile.isWritable()){
        QDataStream byteStream(&saveFile);
        //File opened, proceed to write the data to it
        for(uint32_t i=0; i<rawData.size(); i++){  //For every packet
            //Write the size of the packet, and the date recieved to the file
            uint size = packetModel->data(packetModel->index(i, BINARY_DATA_SIZE_COLUMN_INDEX)).toUInt();
            
            byteStream.writeRawData((const char *)&size, sizeof(size));               //The packet size
            byteStream.writeRawData((const char *)&timeStamps.at(i), sizeof(time_t)); //The timestamp
            
            //Write the data
            if(byteStream.writeRawData(rawData.at(i), size) == -1){
                saveFile.close();
                return false;
            }
        }
        captureSaved = true;
    }
    else{
        return false;
    }
    
    return true;
}
