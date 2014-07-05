#!/bin/sh
set -e

unamestr=$(uname)
if [[ "$unamestr" == 'Linux' ]]; then
  SDKROOT=~/build/idasdk66
  IDAROOT=~/ida-6.6
  ln -sf linux_libwebsockets.a libwebsockets.a
elif [[ "$unamestr" == 'Darwin' ]]; then
  SDKROOT=~/idasrc
  IDAROOT="/Applications/IDA Pro 6.6/idaq.app/Contents/MacOS/"
  ln -sf mac_libwebsockets.a libwebsockets.a
fi

g++ template.cpp -m32 -fPIC -D__IDP__ -D__PLUGIN__ -c -D__LINUX__ -I . -I$SDKROOT/include
g++ -m32 --shared template.o "-L$IDAROOT" -lida -o qira.plx libwebsockets.a -lcrypto -lz -lssl -lpthread
sha1sum qira.plx
if [ "$(diff qira.plx "$IDAROOT/plugins/qira.plx")" != "" ]; then
  echo "copying plugin"
  cp qira.plx $IDAROOT/plugins
fi

