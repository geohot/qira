#!/bin/bash
set -e

unamestr=$(uname)
if [[ "$unamestr" == 'Linux' ]]; then
  SDKROOT=~/build/idasdk66
  IDAROOT=~/ida-6.6
  OUTPUT="qira.plx"
  ln -sf linux_libwebsockets.a libwebsockets.a
elif [[ "$unamestr" == 'Darwin' ]]; then
  SDKROOT=~/idasrc
  IDAROOT="/Applications/IDA Pro 6.6/idaq.app/Contents/MacOS/"
  OUTPUT="qira.pmc"
  ln -sf mac_libwebsockets.a libwebsockets.a
fi

g++ template.cpp -m32 -fPIC -D__IDP__ -D__PLUGIN__ -c -D__LINUX__ -I . -I$SDKROOT/include
g++ -m32 --shared template.o "-L$IDAROOT" -lida -o $OUTPUT libwebsockets.a -lcrypto -lz -lssl -lpthread

sha1sum $OUTPUT
if [ "$(diff $OUTPUT "$IDAROOT/plugins/$OUTPUT")" != "" ]; then
  echo "copying plugin"
  cp $OUTPUT "$IDAROOT/plugins"
fi

