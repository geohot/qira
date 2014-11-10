#get information from IDA so we can compare against it

#for test in tests/*.idb; do IDAPYTHON='auto' idal -A -OIDAPython:example5.py $test; done

import glob
tests = glob.glob('')

#def get_entry(fn):
#    with open(path,'r') as f:
#        print ELFFile(f)['e_entry']

for fn in tests:
    print "idaq -A -OIDAPython:get_ida_info.py {}".format(fn)
