#!/bin/sh
ltrace --library=libida.so ~/idademo66/idaq 2>&1 | grep -v "qstrncpy" | grep -v "lxget" | grep -v "qfree" | grep -v "qmutex" | grep -v "invoke_callbacks" | grep -v "netnode_inited"
