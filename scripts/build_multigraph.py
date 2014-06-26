from qira_log import *
from block_analysis import *
import pydot

dat = read_log("/tmp/qira_log")

print "extracting blocks"
blocks = do_block_analysis(dat)

print "generating traces"

arr = []
trace = []
cls = []
for i in range(len(blocks)):
  h = hex(blocks[i]['start']) + "-" + hex(blocks[i]['end'])
  if h not in arr:
    arr.append(h)
  trace.append(arr.index(h))
  cls.append(blocks[i]['clstart'])


# this is the whole graph with an edge between each pair
#print trace
#print cls

graph = pydot.Dot(graph_type='digraph')

print "adding nodes"
nodes = []
for a in arr:
  n = pydot.Node(a, shape="box")
  graph.add_node(n)
  nodes.append(n)

edges = []
cnts = []

print "trace size",len(trace)
print "realblock count",len(arr)

print "counting edges"
for i in range(0, len(trace)-1):
  #e = pydot.Edge(nodes[trace[i]], nodes[trace[i+1]], label=str(cls[i+1]), headport="n", tailport="s")
  te = [nodes[trace[i]], nodes[trace[i+1]]]
  if te not in edges:
    edges.append(te)
    cnts.append(1)
  else:
    a = edges.index(te)
    cnts[a] += 1

print "edge count",len(edges)

print "adding edges"
for i in range(len(edges)):
  te = edges[i]
  #print cnts[i]
  if cnts[i] > 1:
    e = pydot.Edge(te[0], te[1], headport="n", tailport="s", color="blue", label=str(cnts[i]))
  else:
    e = pydot.Edge(te[0], te[1], headport="n", tailport="s")
  graph.add_edge(e)

print "drawing png"
graph.write_png('/tmp/graph.png')
  

