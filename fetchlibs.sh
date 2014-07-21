#!/bin/bash -e

mkdir -p libs
cd libs

LIBS="libc-bin libstdc++6"
ARCH="armhf"
#ARCH="i386"

# mini debootstrap 

exec 4>&1
SHA_SIZE=256
DEBOOTSTRAP_CHECKSUM_FIELD="SHA$SHA_SIZE"
SUITE="saucy"
TARGET="$ARCH"
TARGET="$(echo "`pwd`/$TARGET")"
HOST_ARCH=`/usr/bin/dpkg --print-architecture`
HOST_OS=linux
USE_COMPONENTS=main
RESOLVE_DEPS=true
export DEBOOTSTRAP_CHECKSUM_FIELD

mkdir -p "$TARGET" "$TARGET/debootstrap"

DEBOOTSTRAP_DIR=/usr/share/debootstrap
. $DEBOOTSTRAP_DIR/functions
. $DEBOOTSTRAP_DIR/scripts/saucy

MIRRORS="$DEF_MIRROR"

download_indices
work_out_debs

all_debs=$(resolve_deps $LIBS)
echo "$all_debs"
download $all_debs

choose_extractor
extract $all_debs


