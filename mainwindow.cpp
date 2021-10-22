#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <QMessageBox>
#include <QFileDialog>
#include <QStandardPaths>
#include <QDialogButtonBox>

#include<QNetworkInterface>

#include <QStandardItem>
#include <QDebug>
#include <QRegExp>

#include "mainwindow.h"
#include "ui_mainwindow.h"
extern
MainWindow::MainWindow(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::MainWindow)
{
    ui->setupUi(this);
    packetModel = new QStandardItemModel(0, 7, this);
    packetModel->setHorizontalHeaderItem(PACKET_NUMBER_COLUMN_INDEX, new QStandardItem("#"));
    packetModel->setHorizontalHeaderItem(TIME_RECIEVED_COLUMN_INDEX, new QStandardItem("Time"));
    packetModel->setHorizontalHeaderItem(SOURCE_ADDRESS_COLUMN_INDEX, new QStandardItem("Src"));
    packetModel->setHorizontalHeaderItem(DESTINATION_ADDRESS_COLUMN_INDEX, new QStandardItem("Dest"));
    packetModel->setHorizontalHeaderItem(BINARY_DATA_SIZE_COLUMN_INDEX, new QStandardItem("Size"));
    packetModel->setHorizontalHeaderItem(HIGHEST_LEVEL_PROTOCOL_COLUMN_INDEX, new QStandardItem("Pro"));
    packetModel->setHorizontalHeaderItem(INFORMATION_COLUMN_INDEX, new QStandardItem("Info"));
    
    packetModelProxy = new QSortFilterProxyModel(this);
    packetModelProxy->setSourceModel(packetModel);
    
    ui->packetTableView->setModel(packetModelProxy);
    
    //Hide the size column
    //ui->packetTableView->setColumnHidden(6, true);
    //ui->packetTableView->setColumnHidden(7, true);
    
    ui->packetInfoTextArea->setWordWrapMode(QTextOption::NoWrap);
    
    ui->packetTableView->resizeColumnsToContents();
    
    ui->packetTableView->verticalHeader()->setMaximumSectionSize(ui->packetTableView->verticalHeader()->fontMetrics().height() + 4);
    ui->packetTableView->verticalHeader()->setDefaultSectionSize(ui->packetTableView->verticalHeader()->fontMetrics().height() + 4);
    ui->packetTableView->verticalHeader()->hide();
    
    ui->packetTableView->setSelectionBehavior(QAbstractItemView::SelectRows);
    ui->packetTableView->setEditTriggers(QAbstractItemView::NoEditTriggers);
    
    isCapturing = false;
    ui->startCaptureButton->setEnabled(true);
    ui->stopCaptureButton->setEnabled(false);
    ui->pauseCaptureButton->setEnabled(false);
    ui->deleteCaptureButton->setEnabled(false);
    
    QNetworkInterface interface;
    QList<QNetworkInterface> IpList = interface.allInterfaces();
    for (int i = 0; i < IpList.size(); i++){

        qDebug() << "Interface " << i << ":" << IpList.at(i).humanReadableName();
        ui->deviceBox->addItem(IpList.at(i).humanReadableName());
    }
    packetSnifferThread = NULL;
    isSaved = false;
}

MainWindow::~MainWindow(){
    if(packetSnifferThread != NULL){
        packetSnifferThread->stopCapturing();
        while(packetSnifferThread->isRunning()){
        }
        delete packetSnifferThread;
    }
    delete ui;
    delete packetModel;
}

void MainWindow::on_startCaptureButton_clicked(){
    device = ui->deviceBox->currentText().toStdString();
    //If this is the first capture, or if the previous capture was deleted, create a new PacketSnifferThread
    if(packetSnifferThread == NULL){
        packetSnifferThread = new PacketSnifferThread(packetModel, ui->statusBar,device);
    }
    
    //Disable and enable various buttons
    ui->startCaptureButton->setEnabled(false);
    ui->stopCaptureButton->setEnabled(true);
    ui->pauseCaptureButton->setEnabled(true);
    ui->deleteCaptureButton->setEnabled(false);

    //Start the thread
    packetSnifferThread->start();
    ui->statusBar->showMessage(QString("Packet capture started."));
    
    //This capture is no longer saved
    isSaved = false;
    
    /*
    if(isCapturing == false){
        packetModel->removeRows(0, packetModel->rowCount());
        
        if (packetSnifferThread != NULL){
            delete packetSnifferThread;
        }
        
        packetSnifferThread = new PacketSnifferThread(packetModel, ui->statusBar);
        ui->startCaptureButton->setEnabled(false);
        ui->stopCaptureButton->setEnabled(true);
        ui->pauseCaptureButton->setEnabled(true);
        ui->deleteCaptureButton->setEnabled(false);
        packetSnifferThread->start();
        isCapturing = true;
        isSaved = false;
        ui->statusBar->showMessage(QString("Packet capture started."));
    }
    */
}

void MainWindow::on_stopCaptureButton_clicked(){
    ui->statusBar->showMessage("This button does nothing, it should be removed");
}

void MainWindow::on_pauseCaptureButton_clicked(){
    //Stop the thread
    packetSnifferThread->stopCapturing();
    ui->statusBar->showMessage(QString("Packet capture paused."));
    
    //Disable and enable various buttons
    ui->startCaptureButton->setEnabled(true);
    ui->stopCaptureButton->setEnabled(false);
    ui->pauseCaptureButton->setEnabled(false);
    if(packetModel->rowCount() > 0){
        ui->deleteCaptureButton->setEnabled(true);
    }
    else{
        ui->deleteCaptureButton->setEnabled(false);
    }
    /*
    if(isCapturing == true){
        packetSnifferThread->stopCapturing();
        ui->startCaptureButton->setEnabled(true);
        ui->stopCaptureButton->setEnabled(false);
        ui->pauseCaptureButton->setEnabled(false);
        ui->deleteCaptureButton->setEnabled(true);
        isCapturing = false;
        ui->statusBar->showMessage(QString("Packet capture paused."));
    }
    */
}

void MainWindow::on_actionResize_Columns_triggered(){
    for(int i=0; i<packetModel->columnCount()-1; i++){
        ui->packetTableView->resizeColumnToContents(i);
        ui->statusBar->showMessage(QString("Rows resized to fit data."));
    }
}

void MainWindow::on_packetTableView_clicked(const QModelIndex &index){
    QModelIndex mappedIndex = packetModelProxy->mapToSource(index);
    int rawDataIndex = packetModel->data(packetModel->index(mappedIndex.row(), PACKET_NUMBER_COLUMN_INDEX)).toInt();
    int size = packetModel->data(packetModel->index(mappedIndex.row(), BINARY_DATA_SIZE_COLUMN_INDEX)).toInt();
    packetSnifferThread->fillInfoAndRawDataWidgets(ui->packetInfoTextArea, ui->packetRawTextEdit, rawDataIndex, size);
    ui->packetInfoTextArea->moveCursor(QTextCursor::Start);
}

void MainWindow::on_filterLineEdit_returnPressed(){
    QString filter = ui->filterLineEdit->text();
    packetModelProxy->setFilterKeyColumn(-1);
    packetModelProxy->setFilterRegExp(QRegExp(".*" + filter + ".*", Qt::CaseInsensitive));
    if(ui->filterLineEdit->text().length() != 0){
        ui->statusBar->showMessage(
                    QString("%1 packet(s) containing the text '%2'").arg(packetModelProxy->rowCount())
                                                                  .arg(ui->filterLineEdit->text())
        );
    }
}

void MainWindow::on_hexViewRawButton_clicked(){
    if(packetSnifferThread != NULL){
        packetSnifferThread->setRawDataView(Hexadecimal);
    }
    if(ui->packetTableView->currentIndex().isValid()){
        ui->packetTableView->clicked(ui->packetTableView->currentIndex());
    }
}

void MainWindow::on_binViewRawButton_clicked(){
    if(packetSnifferThread != NULL){
        packetSnifferThread->setRawDataView(Binary);
    }
    if(ui->packetTableView->currentIndex().isValid()){
        ui->packetTableView->clicked(ui->packetTableView->currentIndex());
    }
}

void MainWindow::on_clearFilterButton_clicked(){
    ui->filterLineEdit->clear();
    packetModelProxy->setFilterRegExp(".*");
}

void MainWindow::on_actionSave_triggered(){
    //Return if there is nothing to save
    if(packetSnifferThread == NULL){
        ui->statusBar->showMessage("There is nothing to save.");
        return;
    }
    
    //Return if the capture is still running
    if(packetSnifferThread->isRunning()){
        ui->statusBar->showMessage("Please pause the capture first to save.");
        return;
    }
    
    //Return if the current capture is already saved
    if(isSaved == true){
        ui->statusBar->showMessage("This capture is already saved.");
        return;
    }
    
    //Get the filePath
    ui->statusBar->showMessage(QString("Saving capture..."));
    QString filePath = QFileDialog::getSaveFileName(this,
                                                    "Save File",
                                                    QStandardPaths::displayName(QStandardPaths::DesktopLocation),
                                                    "Packet Sniffer Save (*.psnf)");
    
    //Return if the user clicked 'cancel' on the file dialog
    if(filePath.length() == 0){
        ui->statusBar->showMessage(QString("No File Chosen."));
        return;
    }
    
    //Attempt to save the capture
    if(packetSnifferThread->saveCapture(filePath) == true){
        ui->statusBar->showMessage(QString("File succesfully saved to %1").arg(filePath));
        isSaved = true;
    }
    else{
        ui->statusBar->showMessage(QString("Error saving file to %1").arg(filePath));
        isSaved = false;
    }
    /*
    if(packetSnifferThread != NULL){  //No capture is running, nothing to save
        if(packetSnifferThread->isRunning()){  //Cant save the capture when the thread is still running
            ui->statusBar->showMessage(QString("Cannot save while the capture is still running."));
        }
        else{  //Thread has been stopped, show a save file dialog and attempt to save the file
            ui->statusBar->showMessage(QString("Saving capture..."));
            QString fileName = QFileDialog::getSaveFileName(this,
                                                            "Save File",
                                                            QStandardPaths::displayName(QStandardPaths::DesktopLocation),
                                                            "Packet Sniffer Save (*.psnf)");
            if(fileName.length() == 0){ //The user clicked cancel on the fileDialog
                ui->statusBar->showMessage(QString("No File Chosen."));
            }
            else{ //Valid fileName, attempt to save the file
                if(packetSnifferThread->saveCapture(fileName) == true){
                     ui->statusBar->showMessage(QString("File succesfully saved to %1").arg(fileName));
                     isSaved = true;
                }
                else{
                    ui->statusBar->showMessage(QString("Error saving file to %1").arg(fileName));
                }
            }
        }
    }
    else{
        ui->statusBar->showMessage(QString("There is nothing to save."));
    }
    */
}

void MainWindow::on_actionNew_Capture_triggered(){
    if(packetSnifferThread == NULL){   //No capture is running, and nothing to save
        packetSnifferThread = new PacketSnifferThread(packetModel, ui->statusBar,device);
    }
    else if(packetSnifferThread->isRunning()){  //A capture is still running
        ui->statusBar->showMessage("Please stop the capture.");
    }
    else if(isSaved == false){  //The capture is not running, but isnt saved
        ui->deleteCaptureButton->click();
        if(packetSnifferThread == NULL){
            packetSnifferThread = new PacketSnifferThread(packetModel, ui->statusBar,device);
        }
    }
    else{
        ui->deleteCaptureButton->setEnabled(true);
        ui->deleteCaptureButton->click();
    }
}

void MainWindow::on_actionOpen_triggered(){
    if(packetSnifferThread != NULL && isSaved == false){
        if(packetSnifferThread->isRunning()){
            ui->statusBar->showMessage("Please stop the current capture.");
            return;
        }
        ui->deleteCaptureButton->click();
    }
    QString fileName = QFileDialog::getOpenFileName(this,
                                                    "Open File",
                                                    QStandardPaths::displayName(QStandardPaths::DesktopLocation),
                                                    "Packet Sniffer Save File(*.psnf);; All files(*.*)");
    //If the user clicked cancel, return
    if(fileName.length() == 0){
        ui->statusBar->showMessage("No file selected.");
        return;
    }
    packetSnifferThread = new PacketSnifferThread(packetModel, fileName, ui->statusBar,device);
    isSaved = true;
    
    /*
    if(packetSnifferThread == NULL){
        //Get the file name
        QString fileName = QFileDialog::getOpenFileName(this,
                                                        "Open File",
                                                        QStandardPaths::displayName(QStandardPaths::DesktopLocation),
                                                        "Packet Sniffer Save File(*.psnf);; All files(*.*)");
        //If the user clicked cancel, return
        if(fileName.length() == 0){
            ui->statusBar->showMessage("No file selected.");
            return;
        }
        packetSnifferThread = new PacketSnifferThread(packetModel, fileName, ui->statusBar);
        isSaved = true;
    }
    else if(packetSnifferThread->isRunning()){
        ui->statusBar->showMessage("Please stop the current capture.");
    }
    else if(isSaved == false){
        ui->deleteCaptureButton->click();
        //Get the file name
        QString fileName = QFileDialog::getOpenFileName(this,
                                                        "Open File",
                                                        QStandardPaths::displayName(QStandardPaths::DesktopLocation),
                                                        "Packet Sniffer Save File(*.psnf);; All files(*.*)");
        //If the user clicked cancel, return
        if(fileName.length() == 0){
            ui->statusBar->showMessage("No file selected.");
            return;
        }
        packetSnifferThread = new PacketSnifferThread(packetModel, fileName, ui->statusBar);
        isSaved = true;
    }
    */
}

//This option is only available if the packet capture has stopped.
//When this method is called, all the data associated with the current capture is deleted
//    1. The packetSnifferThread is deleted.
//    2. Every row in the packetModel is deleted, except for the headers of course.
//    3. The deleteCaptureButton is disabled
void MainWindow::on_deleteCaptureButton_clicked(){
    //If the current capture is unsaved, show a dialog and ask the user if he wants to save or discard it
    if(isSaved == false){
        QMessageBox yesnobox(QMessageBox::Warning,
                             "Unsaved Capture",
                             "Do you want to save the current capture?",
                             QMessageBox::Save | QMessageBox::Discard | QMessageBox::Cancel,
                             this);
        yesnobox.setDefaultButton(QMessageBox::Cancel);
        
        int action = yesnobox.exec();
        if(action == QMessageBox::Save){ //The user wants to save the current capture
            ui->actionSave->trigger();
        }
        else if (action == QMessageBox::Discard){  //The user wants to discard the current capture
            delete packetSnifferThread;
            packetSnifferThread = NULL;
            packetModel->removeRows(0, packetModel->rowCount());
            ui->deleteCaptureButton->setEnabled(false);
            ui->statusBar->showMessage("Capture discarded.");
        }
    }
    else{
        delete packetSnifferThread;
        packetSnifferThread = NULL;
        packetModel->removeRows(0, packetModel->rowCount());
        ui->deleteCaptureButton->setEnabled(false);
        ui->statusBar->showMessage("Capture discarded.");
    }
}

void MainWindow::on_actionStart_triggered(){
    ui->startCaptureButton->click();
}

void MainWindow::on_actionPause_triggered(){
    ui->pauseCaptureButton->click();
}

void MainWindow::on_actionClear_triggered(){
    ui->deleteCaptureButton->click();
}

/*
void MainWindow::none(){


}
*/
