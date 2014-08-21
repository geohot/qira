#!/bin/bash -e

# build websockets with
# cmake .. -DCMAKE_TOOLCHAIN_FILE=../cross-ming.cmake -DLWS_WITH_SSL=0

SDKROOT=~/build/idasdk66
OUTPUT="qira.plw"
OUTPUT64="qira.p64"
OPENSSL=~/.wine/drive_c/OpenSSL-Win32
MINGW_PREFIX="i686-w64-mingw32"

# build 32
$MINGW_PREFIX-g++ template.cpp -fPIC -D__IDP__ -D__PLUGIN__ -c -D__NT__ -I . -I$SDKROOT/include
$MINGW_PREFIX-g++ --shared template.o $SDKROOT/lib/x86_win_gcc_32/ida.a \
  -static-libgcc -static-libstdc++ \
  libs/libwebsockets_static.a \
  libs/libZLIB.a \
  -o $OUTPUT -lws2_32
$MINGW_PREFIX-strip $OUTPUT
echo "built 32"

# build 64
$MINGW_PREFIX-g++ template.cpp -D__EA64__=1 -fPIC -D__IDP__ -D__PLUGIN__ -c -D__NT__ -I . -I$SDKROOT/include
$MINGW_PREFIX-g++ --shared template.o $SDKROOT/lib/x86_win_gcc_64/ida.a \
  -static-libgcc -static-libstdc++ \
  libs/libwebsockets_static.a \
  libs/libZLIB.a \
  -o $OUTPUT64 -lws2_32
$MINGW_PREFIX-strip $OUTPUT64
echo "built 64"

sha1sum $OUTPUT $OUTPUT64

cp $OUTPUT bin/qira_ida66_windows.plw
cp $OUTPUT64 bin/qira_ida66_windows.p64

