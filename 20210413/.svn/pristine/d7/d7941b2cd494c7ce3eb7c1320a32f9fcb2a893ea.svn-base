#!/bin/bash

#移植wireshark到系统时的路径必须和编辑路径相同

PATH_WIRESHARK=`pwd`

if [ ! -d "./lib" ] ; then
    mkdir -p lib
    cd ../3rd-party/opensource/wireshark-2.0.2 && ./autogen.sh && \
    ./configure -q --prefix=/usr --enable-wireshark=no --with-gnutls=no && \
    make -j6 -s --no-print-directory && make -j6 -s --no-print-directory install
    sleep 1
    cp -rf /usr/lib/libwireshark.so* ${PATH_WIRESHARK}/lib
    cp -rf /usr/lib/libwsutil.so* ${PATH_WIRESHARK}/lib
    cp -rf /usr/lib/libwiretap.so* ${PATH_WIRESHARK}/lib
    cp -rf /usr/lib/wireshark ${PATH_WIRESHARK}/lib
else 
    rm -rf ./lib
    mkdir -p lib
    cd ../3rd-party/opensource/wireshark-2.0.2 && make distclean && ./autogen.sh && \
    ./configure -q --prefix=/usr --enable-wireshark=no --with-gnutls=no && \
    make -j6 -s --no-print-directory && make -j6 -s --no-print-directory install
    sleep 1
    cp -rf /usr/lib/libwireshark.so* ${PATH_WIRESHARK}/lib
    cp -rf /usr/lib/libwsutil.so* ${PATH_WIRESHARK}/lib
    cp -rf /usr/lib/libwiretap.so* ${PATH_WIRESHARK}/lib
    cp -rf /usr/lib/wireshark ${PATH_WIRESHARK}/lib
fi

cd ${PATH_WIRESHARK} && make clean && make
