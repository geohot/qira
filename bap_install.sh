#!/bin/bash -e

echo "fetching BAP deps"
sudo apt-get install -qq -y software-properties-common libgmp-dev llvm-3.4-dev time clang-3.4

echo "installing ocaml and opam"
echo 'yes' | sudo add-apt-repository ppa:avsm/ocaml42+opam12
sudo apt-get update -qq
sudo apt-get install -qq -y ocaml ocaml-native-compilers camlp4-extra opam

echo "preparing opam"
export OPAMYES=1
export OPAMJOBS=$(grep processor < /proc/cpuinfo | wc -l)
opam init
opam update

echo "installing BAP"
#export OPAMVERBOSE=1

# needed so travis doesn't give up on us after 10 minutes of no output
function kill_python {
  echo "BAP installed"
  kill %%
}
/usr/bin/env python2.7 -mtimeit "import time; start=time.time()" \
  "while 1: time.sleep(30); print 'still building BAP: %5.2fm elapsed' % ((time.time()-start)/60)" &
trap kill_python EXIT
llvm_version=3.4 opam install bap

