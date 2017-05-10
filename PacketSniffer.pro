#-------------------------------------------------
#
# Project created by QtCreator 2015-08-02T16:46:10
#
#-------------------------------------------------

QT       += core gui

greaterThan(QT_MAJOR_VERSION, 4): QT += widgets

TARGET = PacketSniffer
TEMPLATE = app

LIBS += -lpcap

SOURCES += main.cpp\
        mainwindow.cpp \
    packetsnifferthread.cpp \
    ethernet.cpp \
    arp.cpp \
    ipv4.cpp \
    shared.cpp \
    dns.cpp \
    udp.cpp \
    tcp.cpp \
    http.cpp \
    icmp.cpp \
    https.cpp \
    ipv6.cpp

HEADERS  += mainwindow.h \
    packetsnifferthread.h \
    ethernet.h \
    modelcolumnindexes.h \
    arp.h \
    ipv4.h \
    shared.h \
    ipprotocols.h \
    dns.h \
    udp.h \
    ports.h \
    tcp.h \
    http.h \
    icmp.h \
    https.h \
    ipv6.h \
    tags.h \
    colors.h

FORMS    += mainwindow.ui

RESOURCES += \
    resources.qrc

DISTFILES += \
    tempcode
