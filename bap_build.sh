#!/bin/bash -e

BAP_URL="https://github.com/ivg/bap"
BAP_TAG="bap+qira"

git clone --depth=1 --branch $BAP_TAG $BAP_URL

pushd bap

SYS_DEPENDS=`cat apt.deps`
OPAM_DEPENDS=`cat opam.deps`
ppa=avsm/ocaml42+opam12
export OPAMYES=1
export OPAMVERBOSE=1
export OPAMJOBS=4

echo 'yes' | sudo add-apt-repository ppa:$ppa
sudo apt-get update -qq
sudo apt-get install -qq ocaml ocaml-native-compilers camlp4-extra opam $SYS_DEPENDS

opam init
opam install $OPAM_DEPENDS
eval `opam config env`
oasis setup
./configure --prefix=`opam config var prefix` --with-cxx=`which clang++`
make
make install
popd
