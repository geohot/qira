#get information from IDA so we can compare against it

#for test in tests/*.idb; do IDAPYTHON='auto' idal -A -OIDAPython:example5.py $test; done

tests = ['../tests/argtest', '../tests/argtest_static', '../tests/arm-hello', '../tests/arm-loop', '../tests/aslrtest', '../tests/changetest', '../tests/coreutils_O0_echo', '../tests/echo', '../tests/echo64', '../tests/forktest', '../tests/heapfunn', '../tests/hello', '../tests/helloc', '../tests/printesp', '../tests/slicingtest', '../tests/test64', '../tests/thread_test', '../tests/ctf/csaw/exploit2', '../tests/ctf/dc2014/eliza-arm', '../tests/ctf/dc2014/eliza_orig', '../tests/ctf/gits2014/fuzzy-29074b5fa6ed6aebb16390ef122ad61f7b9200ed', '../tests/ctf/hitcon/ty-b83f0d0edeb8cfad76d30eddc58da139', '../tests/ctf/secu/numbers', '../tests/haskell/hello', '../tests/haskell/hello.o', '../tests/realworld/zpipe', '../tests/suite/echo64', '../tests/suite/exploit2', '../tests/suite/ty-b83f0d0edeb8cfad76d30eddc58da139', '../tests/vimplugin/a.out', '../tests/vortex/vortex4']

#def get_entry(fn):
#    with open(path,'r') as f:
#        print ELFFile(f)['e_entry']

for fn in tests:
    print "idaq -A -OIDAPython:get_ida_info.py {}".format(fn)
