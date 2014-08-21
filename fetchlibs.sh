#!/bin/bash -e

DEBOOTSTRAP_DIR=/usr/share/debootstrap

if [ ! -d "$DEBOOTSTRAP_DIR" ]; then
  echo "this script requires debootstrap to be installed"
  exit 1
fi

# this is ubuntu specific i think
fetcharch() {
  ARCH="$1"
  SUITE="$2" 
  exec 4>&1
  SHA_SIZE=256
  DEBOOTSTRAP_CHECKSUM_FIELD="SHA$SHA_SIZE"
  TARGET="$ARCH"
  TARGET="$(echo "`pwd`/$TARGET")"
  HOST_ARCH=`/usr/bin/dpkg --print-architecture`
  HOST_OS=linux
  USE_COMPONENTS=main
  RESOLVE_DEPS=true
  export DEBOOTSTRAP_CHECKSUM_FIELD

  mkdir -p "$TARGET" "$TARGET/debootstrap"

  . $DEBOOTSTRAP_DIR/functions
  . $DEBOOTSTRAP_DIR/scripts/$SUITE

  MIRRORS="$DEF_MIRROR"

  download_indices
  work_out_debs

  all_debs=$(resolve_deps $LIBS)
  echo "$all_debs"
  download $all_debs

  choose_extractor
  extract $all_debs
}

#rm -rf libs
mkdir -p libs
cd libs

LIBS="libc-bin libstdc++6"
fetcharch armhf precise
fetcharch armel precise
fetcharch powerpc precise
fetcharch arm64 saucy

# mini debootstrap 

