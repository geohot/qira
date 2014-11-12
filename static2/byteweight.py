import sys
sys.path.insert(0, '../../middleware') #needed for testing

import qira_config

# returns list of addresses with respect to the qira memory model
# use no dependencies other than bap toil
# make < 100 FFI calls

class Signature_Err(Exception):
  def __init__(self, value):
    self.value = value

threshold = 0.5
sig_len = 20


# get signature along with its score
def parse(l):
  # l = l.strip()
  words = l.split("->")
  if len(words) != 2:
    raise Signature_Err(0)
  else:
    counts = words[1].split(",")
    sig = words[0]
    if len(counts) != 2:
      raise Signature_Err(1)
    else:
      score = float(counts[0]) / (float(counts[0]) + float(counts[1]))
      return sig, score


# match signature with trie
def score(s, trie):
  if s == "":
    return trie[0]
  else:
    if s[0] in trie[1]:
      return score(s[1:], trie[1][s[0]])
    else:
      return trie[0]


# load : read signature file and convert to trie
def load(sig_file):
  f = open(sig_file, "rb")
  root = [0.0, {}]
  while 1:
    line = f.readline()
    if line == "":
      break
    while line.find("->") == -1:
      line += f.readline()
    sig, score = parse(line)
    # print repr(sig), score
    tree = root
    for i in sig:
      if not i in tree[1]:
        tree[1][i] = [0.0, {}]
      tree = tree[1][i]
    tree[0] = score
  f.close()
  return root


# main function start identification function
def fsi(static):
  trie = load(qira_config.BASEDIR+"/static2/bw_x86")
  functions = set()
  (addr, lenn) = static['sections'][-3]
  for (addr, lenn) in static['sections']:
    strr = static.memory(addr, lenn)
    for i in range(lenn):
      s = score(strr[i:i+sig_len], trie)
      # print hex(addr+i), repr(strr[i:i+sig_len]), s
      if s > threshold:
        functions.add(addr + i)
    # print repr(strr)
  return list(functions)
