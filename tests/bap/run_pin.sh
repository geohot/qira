#!/bin/sh
~/bap/pin/pin -t ~/bap/pintraces/obj-ia32/gentrace.so -logall_after -taint_args -- ~/qira/tests/changetest 23
~/bap/utils/toil -serializedtrace out.bpt > out.useful

