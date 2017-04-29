#include "mainwindow.h"
#include <QApplication>
#include <QDesktopWidget>
#include <QStyle>

int main(int argc, char *argv[])
{
    QApplication a(argc, argv);
    MainWindow w;
    
    w.setWindowTitle("Packet Sniffer");
    
    //w.setStyleSheet(QString("QTableView{gridline-color:black;}"));
    
    w.setGeometry(
        QStyle::alignedRect(
            Qt::LeftToRight,
            Qt::AlignCenter,
            w.size(),
            a.desktop()->availableGeometry()
        )
    );
    
    w.show();
    
    return a.exec();
}
