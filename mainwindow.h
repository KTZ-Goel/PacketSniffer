#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QStandardItemModel>
#include <QSortFilterProxyModel>

#include <vector>

#include "modelcolumnindexes.h"
#include "packetsnifferthread.h"


/*
 * Table format:
 * 
 * +----------------------------+-----------------------------+----------------------------------+-------------------------------------+--------------------------+---------------------------+
 * | TIME_RECIEVED_COLUMN_INDEX | SOURCE_ADDRESS_COLUMN_INDEX | DESTINATION_ADDRESS_COLUMN_INDEX | HIGHEST_LEVEL_PROTOCOL_COLUMN_INDEX | INFORMATION_COLUMN_INDEX | BINARY_INDEX_COLUMN_INDEX |
 * +----------------------------+-----------------------------+----------------------------------+-------------------------------------+--------------------------+---------------------------+
 * |    YYYY/MM/DD hh:mm:ss     |    IPv4/IPv6/MAC address    |     IPv4/IPv6/MAC address        |        ARP/DNS/HTTP/ICMP/etc.       | Short summary of packet  |             0             |
 * +----------------------------+-----------------------------+----------------------------------+-------------------------------------+--------------------------+---------------- ----------+
 * |    2015/12/01 12:23:54     |         192.168.0.1         |           192.168.0.0            |                  ARP                |                          |             1             |
 * +----------------------------+-----------------------------+----------------------------------+-------------------------------------+--------------------------+---------------- ----------+
 * 
 */


namespace Ui {
class MainWindow;
}

class MainWindow : public QMainWindow
{
    Q_OBJECT
    
public:
    explicit MainWindow(QWidget *parent = 0);
    ~MainWindow();
    std::string device = "wlo1";
    
private slots:
    void on_startCaptureButton_clicked();                      //Start the packet capture
    void on_stopCaptureButton_clicked();                       //Stop the packet capture
    void on_actionResize_Columns_triggered();                  //Resize the columns to the contents
    void on_packetTableView_clicked(const QModelIndex &index); //A packet is clicked on
    void on_filterLineEdit_returnPressed();                    //The user has pressed enter on the filter QLineEdit, apply the filter
    
    void on_hexViewRawButton_clicked();   //The user wants to switch the raw packet view to hexadecimal
    void on_binViewRawButton_clicked();   //The user wants to switch the raw packet view to binary
    
    void on_clearFilterButton_clicked();  //The user wants to clear the filter text in the filter QLineEdit
    
    void on_actionSave_triggered();       //Save the current capture, only if it is not running
    
    void on_pauseCaptureButton_clicked();
    
    void on_actionNew_Capture_triggered();
    
    void on_actionOpen_triggered();
    
    void on_deleteCaptureButton_clicked();
    
    void on_actionStart_triggered();
    
    void on_actionPause_triggered();
    
    void on_actionClear_triggered();
    
private:
    Ui::MainWindow *ui;
    int numPackets;
    QStandardItemModel *packetModel;
    QSortFilterProxyModel *packetModelProxy;
    PacketSnifferThread *packetSnifferThread;
    
    bool isCapturing;
    bool isSaved;
};

#endif // MAINWINDOW_H
