#!/bin/sh
set -e

SDKROOT=~/build/idasdk66
IDAROOT=~/ida-6.6

g++ template.cpp -m32 -fPIC -D__IDP__ -D__PLUGIN__ -c -D__LINUX__ -I$SDKROOT/include
g++ -m32 --shared template.o -L$IDAROOT -lida -o qira.plx libwebsockets.a -lcrypto -lz -lssl -lpthread
cp qira.plx $IDAROOT/plugins

