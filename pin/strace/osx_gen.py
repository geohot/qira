#!/usr/bin/env python2

from urllib import urlopen
syscalls_master = urlopen("http://www.opensource.apple.com/source/xnu/xnu-2422.110.17/bsd/kern/syscalls.master?txt").read()
x = (i.strip().split(None, 3) for i in syscalls_master.splitlines() if i.strip() and i[0] not in '#;')
x = ((i[0],i[3][i[3].index('{')+1:i[3].index('}')].strip()) for i in x if len(i) == 4)
x = {int(k):v for k,v in x if v != 'int nosys(void);'}

# Yay assumptions

def name(v):
  end = v.index('(')
  start = 1+v.rindex(' ', 0, end)
  return v[start:end]

def args(v):
  return v[v.index('(')+1:v.index(')')].split(',')

def typename(arg):
  t = max(arg.rfind(' '), arg.rfind('*'))
  return arg[:t+1].strip(), arg[t+1:].strip()

def isstring((typ, nam)):
  return typ.startswith('user_addr_t') or typ.endswith('char *') or typ.endswith('void *')

def showdecimal((typ, nam)):
  return 'flag' not in nam and '*' not in typ and 'addr' not in typ and ('int' in typ or 'size' in typ)

def showtype((typ, nam)):
  return 'struct' in typ or '_t *' in typ


print '''#ifdef __cplusplus
extern "C" {
#endif

#define SYSCALL_MAXARGS 8
enum argtype {
\tARG_INT,
\tARG_PTR,
\tARG_STR,
\tARG_UNKNOWN
};

const int MAX_SYSCALL_NUM = '''+str(max(x.iterkeys())+1)+''';

struct syscall_entry {
\tconst char *name;
\tint nargs;
\tenum argtype args[SYSCALL_MAXARGS];
} syscalls[] = {
\t{.name = "syscall", .nargs = 1, .args = { ARG_INT, }},'''

def argenumconsts(v):
  def gen(typnam):
    if isstring(typnam):
      return 'ARG_STR'
    if showdecimal(typnam):
      return 'ARG_INT'
    return 'ARG_UNKNOWN'
  return map(gen, map(typename, args(v)))

for i in range(1, max(x.iterkeys())+1):
  if i in x:
    print '\t{.name = "%s", .nargs = %d, .args = { %s}},' % (name(x[i]), len(args(x[i])), ', '.join(argenumconsts(x[i]))+', ')
  else:
    print '\t{.name = "#'+str(i)+'", .nargs = 6, .args = { '+'ARG_UNKNOWN, '*6+'}},'

print '''};

#ifdef __cplusplus
}
#endif'''
