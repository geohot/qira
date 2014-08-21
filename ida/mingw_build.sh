#!/bin/bash -e

SDKROOT=~/build/idasdk66
OUTPUT="qira.plw"
OUTPUT64="qira.p64"
OPENSSL=~/.wine/drive_c/OpenSSL-Win32

i586-mingw32msvc-g++ template.cpp -fPIC -D__IDP__ -D__PLUGIN__ -c -D__NT__ -I . -I$SDKROOT/include

i586-mingw32msvc-g++ --shared template.o $SDKROOT/lib/x86_win_gcc_32/ida.a -o $OUTPUT \
  -lws2_32 \
  $OPENSSL/lib/libeay32.lib \
  $OPENSSL/lib/ssleay32.lib \
  libs/websockets_static.lib \
  libs/ZLIB.lib


