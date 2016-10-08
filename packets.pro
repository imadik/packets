#-------------------------------------------------
#
# Project created by QtCreator 2016-09-29T01:51:30
#
#-------------------------------------------------

QT       += core gui

QMAKE_LFLAGS_RELEASE    += -static
greaterThan(QT_MAJOR_VERSION, 4): QT += widgets

TARGET = packets
TEMPLATE = app


SOURCES += main.cpp\
        mainwindow.cpp \
    packetsparser.cpp

HEADERS  += mainwindow.h \
    packetsparser.h

FORMS    += mainwindow.ui
