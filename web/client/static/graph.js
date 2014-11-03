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

// this runs sugiyama...
Graph.prototype.render = function() {
  var name = Object.keys(this.vertices).toString();
  var send = "digraph graphname {\n";

  // record the old gbox position
  var oldgbox = $("#gbox");
  if (oldgbox.length > 0) {
    gPos[oldgbox[0].className] = [fdec(oldgbox.css("margin-left")), fdec(oldgbox.css("margin-top"))];
  }

  var outergbox = $('<div id="outergbox"></div>');
  $("#staticpanel").html("");
  gbox = document.createElement('div');
  outergbox[0].appendChild(gbox);
  document.getElementById("staticpanel").appendChild(outergbox[0]);
  gbox.id = 'gbox';
  gbox.className = name;
  if (name in gPos) {
    $("#gbox").css("margin-left", gPos[name][0]);
    $("#gbox").css("margin-top", gPos[name][1]);
  }

  for (addr in this.vertices) {
    var r = this.vertices[addr].rendered;
    if (r !== undefined) {
      gbox.appendChild(r);
      var width = (r.offsetWidth * 1.0) / 72.;
      var height = (r.offsetHeight * 1.0) / 72.;
      send += 'N' + addr + ' [width="'+width+'", height="'+height+'", shape="box"];'+"\n";
    }
  }
  for (var i = 0; i < this.edges.length; i++) {
    send += 'N' + this.edges[i]['from'] + ' -> N' + this.edges[i]['to'] + ' [color='+this.edges[i]['color']+', headport=n, tailport=s]'+";\n";
  }
  send += "}\n";

  var req = new XMLHttpRequest();
  req.open('POST', '/dot', false);
  req.send(send);

  //p(send);

  var i;
  var resp = req.response.split('\n').join("").split(";");

  var gdata = resp[0].split('"')[1].split(',');
  //p(gdata);

  gbox.style.width = fnum(gdata[2])+10;
  gbox.style.height = fnum(gdata[3])+10;

  var canvas = document.createElement("canvas");
  canvas.width = fnum(gdata[2])+10;
  canvas.height = fnum(gdata[3])+10;
  canvas.id = "gcanvas";
  gbox.appendChild(canvas);
  var ctx = canvas.getContext("2d");

  for (i = 2; true; i++) {
    if (resp[i].indexOf('}') != -1) break;
    else if (resp[i].indexOf('->') != -1) {
      // this is an edge
      var color = resp[i].substr(resp[i].indexOf('color=')+6).split(',')[0];
      var posstr = resp[i].substr(resp[i].indexOf('pos="')+7).split('"')[0].split(' ');
      var pos = [];
      for (var j=0; j<(posstr.length); j++) {
        var to = posstr[j].split(',');
        pos.push({x:parseFloat(to[0]), y:fnum(gdata[3]) - parseFloat(to[1])});
      }

      // draw spline
      ctx.beginPath();
      // pos[0] is end
      // pos[1] is start
      ctx.moveTo(pos[1].x, pos[1].y);
      for (var j=2; j<pos.length; j+=3) {
        ctx.bezierCurveTo(pos[j].x, pos[j].y, pos[j+1].x, pos[j+1].y, pos[j+2].x, pos[j+2].y);
      }
      ctx.lineTo(pos[0].x, pos[0].y);

      if (pos[1].y < pos[0].y) {
        ctx.lineWidth = 1;
      } else {
        ctx.lineWidth = 2;
      }

      ctx.strokeStyle = color;
      ctx.stroke();

      // draw arrow
      ctx.beginPath();
      ctx.moveTo(pos[0].x, pos[0].y);
      ctx.lineTo(pos[0].x-5, pos[0].y-10);
      ctx.lineTo(pos[0].x+5, pos[0].y-10);
      ctx.lineWidth = 1;
      ctx.fillStyle = color;
      ctx.fill();

    } else {
      // this is a vertex
      var addr = resp[i].split(' ')[0].split('N')[1].trim();
      var pos = resp[i].slice(resp[i].indexOf('pos=')).split('"')[1].split(',');

      //p(addr);
      var r = this.vertices[addr].rendered;

      if (r !== undefined) {
        var left = fnum(pos[0]) - (r.offsetWidth/2);
        var top = fnum(gdata[3]) - (fnum(pos[1]) + (r.offsetHeight/2));

        //r.style.position = "absolute";
        r.style.left = left + "px";
        r.style.top = top + "px";

        //r.style.opacity = ".3";
        //r.style.visibility = "hidden";
      }
    }
  }

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

