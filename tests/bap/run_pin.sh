#!/bin/bash -e

# using https://github.com/vrtadmin/moflow/tree/master/BAP-0.7-moflow
rm out.*

# -logall_after
~/bap/pin/pin -t ~/bap/pintraces/obj-ia32/gentrace.so -taint_args -- ~/qira/tests/changetest 23
~/bap/utils/toil -serializedtrace out.bpt -o out.il
~/bap/utils/ileval -eval -il out.il
exit

#~/bap/custom_utils/prep-slice.sh out.bpt out.il
~/bap/utils/iltrans -serializedtrace out.bpt -trace-concrete-subst -trace-dsa -pp-ast out.ssail

#~/bap/custom_utils/slicer -il out.il -var dsa_R_DFLAG_1_37201 -b -o out.slice
~/bap/custom_utils/slicer -il out.ssail -var dsa_R_EAX_1_9044 -f -o out.slice

