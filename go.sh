#!/bin/sh
set -e

#BIN=../tests/ctf/simple
SRC=../tests/hello.c
#SRC=../tests/algo.c

if [ $SRC != "" ]; then
  cd tests
  #gcc -m32 -nostdlib -static -g algo.c
  gcc -m32 -static -g $SRC
  BIN=../tests/a.out
  cd ../
fi

cd scripts
echo "hello" | ./run_qemu.sh $BIN
python db_commit_asm.py $BIN $SRC
python db_commit_log.py
python db_commit_blocks.py
python memory_server.py

