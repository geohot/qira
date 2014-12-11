// imported from EDA-3

// vertices are the first address in the basic block
// edges are the two addresses + direction + color
// size doesn't matter for the graph layout algo...i think
Graph = function() {
  this.vertices = {};
  this.edges = [];
}

Graph.prototype.addVertex = function(addr, vlen, dom) {
  if (this.vertices[addr] === undefined) {
    this.vertices[addr] = {};
    this.vertices[addr]['parents'] = [];
    this.vertices[addr]['children'] = [];
    this.vertices[addr]['level'] = undefined;  // useless?
  }
  if (vlen !== undefined) {
    //p('add vertex '+shex(addr)+' - '+shex(addr+vlen));
    this.vertices[addr]['len'] = vlen;
    this.vertices[addr]['rendered'] = dom;
  }
};

Graph.prototype.assignLevels = function() {
  this.levels = [[]];
  for (addr in this.vertices) {
    if (this.vertices[addr]['children'].length === 0) {
      this.levels[0].push(addr);
      this.vertices[addr]['level'] = 0;
    }
  }
  // got all sinks on level 0
  // fix these not to move?
  var onlevel = 0;
  while (this.levels[onlevel].length > 0) {
    if (onlevel > 100) {
      p("MAX LEVELS EXCEEDED");
      break;
    }
    this.levels.push([]); // add new level
    var remove = [];
    for (var i=0; i<this.levels[onlevel].length; i++) {
      // loop over all in the current level
      var addr = this.levels[onlevel][i];
      var vertex = this.vertices[addr];

      // loop over their parents
      for (var j=0; j< vertex['parents'].length; j++) {
        var paddr = vertex.parents[j];
        var pvertex = this.vertices[paddr];
        if (paddr != addr) {
          if (pvertex['level'] !== undefined) {
            // if paddr > addr, continue
            if (bn_cmp(paddr, addr) > 0) {
              //p(paddr+ " > "+addr+", not replacing");
              continue;
            }
            remove.push([paddr,pvertex['level']]);
          }
          pvertex['level'] = onlevel+1;
          this.levels[onlevel+1].push(paddr);
        }
      }
    }
    for (var i=0; i<remove.length;i++) {
      var paddr = remove[i][0];
      var lvl = remove[i][1];
      this.levels[lvl].splice(this.levels[lvl].indexOf(paddr), 1);
    }
    onlevel++;
  }
  this.levels.pop(); // last level should be empty
};

Graph.prototype.inLineage = function(addr, qaddr, seen) {
  seen = seen || [];
  for (var i = 0; i < this.vertices[addr]['parents'].length; i++) {
    var taddr = this.vertices[addr]['parents'][i];
    if (taddr === addr) return true;
    if (seen.indexOf(taddr) !== -1) return false;

    if (inLineage(taddr, qaddr, seen) === true) {
      return true;
    }
  }
  return false;
};

var gPos = {};

Graph.prototype.render = function() {
  var name = Object.keys(this.vertices).toString();
  var send = "digraph graphname {\n";

  document.getElementById("staticpanel").innerHTML = "<svg id='staticgraph' ><g/></svg>";
  document.getElementById("staticgraph").style.width = ($(window).width() - document.getElementById("staticpanel").offsetLeft);

  for (addr in this.vertices) {
    var r = this.vertices[addr].rendered;
    if (r !== undefined) {
      send += 'N' + addr + ' [labelType="html", shape="rect", label="'+r.replace(/"/g,"'")+'"];'+"\n";
    }
  }
  for (var i = 0; i < this.edges.length; i++) {
    send += 'N' + this.edges[i]['from'] + ' -> N' + this.edges[i]['to'] + ' [color='+this.edges[i]['color']+', headport=n, tailport=s]'+";\n";
  }
  send += "}\n";


  var svg = d3.select("svg"),
    inner = d3.select("svg g"),
    zoom = d3.behavior.zoom().on("zoom", function() {
      inner.attr("transform", "translate(" + d3.event.translate + ")" +
                                  "scale(" + d3.event.scale + ")");
    });
  svg.call(zoom);

  // Create and configure the renderer
  var render = dagreD3.render();

  function tryDraw() {
    var g;
  
    g = graphlibDot.read(send);

      // Set margins, if not present
      if (!g.graph().hasOwnProperty("marginx") &&
          !g.graph().hasOwnProperty("marginy")) {
        g.graph().marginx = 20;
        g.graph().marginy = 20;
      }

      d3.select("svg g").call(render, g);
  }

  tryDraw();

  return;
};

Graph.prototype.reverseEdge = function(edgenum) {
  var v1 = this.edges[edgenum]['from'];
  var v2 = this.edges[edgenum]['to'];
  this.vertices[v1]['children'].splice(this.vertices[v1]['children'].indexOf(v2), 1);
  this.vertices[v2]['parents'].splice(this.vertices[v2]['parents'].indexOf(v1), 1);

  this.edges[edgenum]['from'] = v2;
  this.edges[edgenum]['to'] = v1;
  this.edges[edgenum]['reversed'] = true;
  this.vertices[v2]['children'].push(v1);
  this.vertices[v1]['parents'].push(v2);
};

// v1 -> v2
Graph.prototype.addEdge = function(v1, v2, color) {
  //p('add edge '+shex(v1)+' -> '+shex(v2));
  var reversed = false;
  /*if (v1 > v2) {
    var t = v2;
    v2 = v1;
    v1 = t;
    reversed = true;
  }*/
  this.addVertex(v1);
  this.addVertex(v2);
  this.edges.push({'from': v1, 'to': v2, 'color': color, 'reversed': reversed});
  this.vertices[v1]['children'].push(v2);
  this.vertices[v2]['parents'].push(v1);
};

Graph.prototype.debugPrint = function() {
  p('vertices: ');
  for (addr in this.vertices) {
    var vertex = this.vertices[addr];
    p('  '+addr+': '+vertex['len'] + ' ' + vertex['level'] + ' p:' + vertex['parents'] + ' c:' + vertex['children']);
  }
  p('edges: ');
  for (var i = 0; i < this.edges.length; i++) {
    p('  '+this.edges[i]['from']+' -'+this.edges[i]['color']+'> '+this.edges[i]['to']);
  }
};

