#!/bin/sh
ltrace -n2 --library=libida.so ~/idademo66/idaq ~/qira/tests/idb/a.out 2>&1 | grep -v "qstrncpy" | grep -v "lxget" | grep -v "qfree" | grep -v "qmutex" | grep -v "invoke_callbacks" | grep -v "netnode_inited" | grep -v "qalloc" | grep -v "qvector_reserve" | grep -v "qvsnprintf"
