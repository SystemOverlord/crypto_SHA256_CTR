#-------------------------------------------------
#
# Project created by QtCreator 2014-07-28T14:17:20
#
#-------------------------------------------------

QT       += core

QT       -= gui

TARGET = crypt_sha256_ctr
CONFIG   += console
CONFIG   -= app_bundle

TEMPLATE = app


SOURCES += main.cpp \
    sha256.cpp \
    crypt_sha256_ctr.cpp

HEADERS += \
    sha256.h \
    crypt_sha256_ctr.h \
    utils.h
