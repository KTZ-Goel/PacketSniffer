#ifndef PACKETSNIFFERTHREAD_H
#define PACKETSNIFFERTHREAD_H

#include <vector>
#include <string>
#include <QThread>
#include <QStandardItemModel>
#include <QStatusBar>
#include <QPlainTextEdit>

enum RawDataView {
    Hexadecimal,
    Binary
};

class PacketSnifferThread : public QThread{
public:
    PacketSnifferThread(QStandardItemModel *packetModel, QStatusBar *statusBar,std::string device);
    PacketSnifferThread(QStandardItemModel *packetModel, QString filePath, QStatusBar *statusBar,std::string device);
    ~PacketSnifferThread();
    
private:
    std::vector<char *>    rawData;      //Holds the raw binary data of the packet
    std::vector<time_t>    timeStamps;   //The timestamp of each packet
    QStandardItemModel     *packetModel;
    QStatusBar             *statusBar;
    bool                   stopCapture;
    int                    packetNumber;
    RawDataView            rawDataView;
    bool                   captureSaved;
    
    void run();

public:
    void stopCapturing();
    void fillInfoAndRawDataWidgets(QPlainTextEdit *infoTextEdit, QPlainTextEdit *rawDataTextEdit, int index, int size);
    void setRawDataView(RawDataView rawDataView);
    
    bool saveCapture(QString filePath);
    void saveCaptureAs(void);
    void openCapture(void);
    std::string devicea= "wlo1";
};

#endif // PACKETSNIFFERTHREAD_H
