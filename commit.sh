#!/bin/sh
set -e

echo "*** build the Program database"
time python db_commit_asm.py $BIN $SRC
#echo "*** filter the Change database"
#time python db_filter_log.py
echo "*** build the Change database"
time python db_commit_log.py
echo "*** build the memory json"
time python mem_json_extract.py
echo "*** build the pmaps database"
time python segment_extract.py

