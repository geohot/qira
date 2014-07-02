#!/bin/sh
set -e

BIN=../tests/ctf/ezhp
#BIN=../tests/ctf/hudak
#BIN=../tests/ctf/simple
#SRC=../tests/hello.c
#SRC=../tests/algo.c

if [ $SRC != "" ]; then
  cd tests
  #gcc -m32 -nostdlib -static -g $src
  gcc -m32 -static -g $SRC
  BIN=../tests/a.out
  cd ../
fi

cd scripts
#echo "hello" | ./run_qemu.sh $BIN
#echo "4t_l34st_it_was_1mperat1v3..." | ./run_qemu.sh $BIN
#echo "i wish i were a valid key bob" | ./run_qemu.sh $BIN
./run_qemu.sh $BIN
./commit.sh

#python db_commit_blocks.py
#python memory_server.py
#python build_multigraph.py

