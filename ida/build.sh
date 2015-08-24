#!/bin/bash -e

SDKROOT=~/idasdk68
unamestr=$(uname)
if [[ "$unamestr" == 'Linux' ]]; then
  IDAROOT=~/ida-6.8
  OUTPUT="qira.plx"
  OUTPUT64="qira.plx64"
  ln -sf libs/linux_libwebsockets.a libwebsockets.a
elif [[ "$unamestr" == 'Darwin' ]]; then
  IDAROOT="/Applications/IDA Pro 6.6/idaq.app/Contents/MacOS/"
  OUTPUT="qira.pmc"
  OUTPUT64="qira.pmc64"
  ln -sf libs/mac_libwebsockets.a libwebsockets.a
fi

# build 32
g++ template.cpp -m32 -fPIC -D__IDP__ -D__PLUGIN__ -c -D__LINUX__ -I . -I$SDKROOT/include
g++ -m32 --shared template.o "-L$IDAROOT" -lida -o $OUTPUT libwebsockets.a -lcrypto -lz -lssl -lpthread
echo "built 32"

# build 64
g++ template.cpp -D__EA64__=1 -m32 -fPIC -D__IDP__ -D__PLUGIN__ -c -D__LINUX__ -I . -I$SDKROOT/include
g++ -m32 --shared template.o "-L$IDAROOT" -lida64 -o $OUTPUT64 libwebsockets.a -lcrypto -lz -lssl -lpthread
echo "built 64"

if [[ "$unamestr" == 'Linux' ]]; then
  strip $OUTPUT
  strip $OUTPUT64
fi

sha1sum $OUTPUT $OUTPUT64
echo "installing plugin"
cp $OUTPUT "$IDAROOT/plugins"
cp $OUTPUT64 "$IDAROOT/plugins"

if [[ "$unamestr" == 'Linux' ]]; then
  cp $OUTPUT bin/qira_ida68_linux.plx
  cp $OUTPUT64 bin/qira_ida68_linux.plx64
elif [[ "$unamestr" == 'Darwin' ]]; then
  cp $OUTPUT bin/qira_ida68_mac.pmc
  cp $OUTPUT64 bin/qira_ida68_mac.pmc64
fi

