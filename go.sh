#!/bin/sh
set -e
cd tests
gcc -m32 -nostdlib -static -g algo.c
cd ../
cd scripts
./run_qemu.sh
python db_commit_asm.py ../tests/a.out ../tests/algo.c
python db_commit_log.py
python db_commit_blocks.py
python memory_server.py

