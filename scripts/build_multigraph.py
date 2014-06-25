from qira_log import *
from block_analysis import *
import pydot

dat = read_log("/tmp/qira_log")

blocks = do_block_analysis(dat)

graph = pydot.Dot(graph_type='digraph')

arr = []
bb = []
cls = []
for i in range(len(blocks)):
  h = hex(blocks[i]['start']) + "-" + hex(blocks[i]['end'])
  if h not in arr:
    arr.append(h)
  bb.append(arr.index(h))
  cls.append(blocks[i]['clstart'])


# this is the whole graph with an edge between each pair
print bb
print cls

nodes = []
for a in arr:
  n = pydot.Node(a)
  graph.add_node(n)
  nodes.append(n)

for i in range(0, len(bb)-1):
  #graph.add_edge(pydot.Edge(nodes[bb[i]], nodes[bb[i+1]], label=str(cls[i+1])))
  graph.add_edge(pydot.Edge(nodes[bb[i]], nodes[bb[i+1]]))

graph.write_png('/tmp/graph.png')
  

