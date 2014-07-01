#!/bin/sh
set -e

#BIN=../tests/ctf/hudak
#BIN=../tests/ctf/simple
SRC=../tests/hello.c
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
echo "i wish i were a valid key bob" | ./run_qemu.sh $BIN

# build the Program database
python db_commit_asm.py $BIN $SRC
# build the Change database
python db_commit_log.py
# build the memory json
python mem_json_extract.py
# build the pmaps database
python segment_extract.py

#python db_commit_blocks.py
#python memory_server.py
#python build_multigraph.py

