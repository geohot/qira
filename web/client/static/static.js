// static stuff

stream = io.connect(STREAM_URL);

Deps.autorun(function() { DA("update static view");
  var iaddr = Session.get('iaddr');
  if (iaddr === undefined) return;
  stream.emit('getfunc', iaddr);
});

/*$(function() {
  $("#staticpanel").css("display", "none");
});*/

function on_tags(addrs) { DS("tags"); 
  var graph = new Graph();

  //p(addrs);

  // this renders all the graph vertices
  var idump = "";
  var in_basic_block = false;
  var last_basic_block = false;
  var cnt = 0;

  function pushBlock() {
    if (last_basic_block != false) {
      var dom = $('<div class="basicblock" id="bb_'+ins.address+'">');
      dom.html(idump);
      idump = "";
      cnt = 0;
      graph.addVertex(last_basic_block, cnt, dom[0]);
    }
  }

  for (var i=0;i<addrs.length;i++) {
    var ins = addrs[i];
    if (in_basic_block == false) {
      // accepts control from previous instruction
      if (ins.flags & 0x10000 && last_basic_block != false) {
        graph.addEdge(last_basic_block, ins.address, "blue");
      }
      in_basic_block = ins.address;
    }
    cnt += 1;
    idump += '<div class="instruction">';
    idump += '<span class="hexdumpdatainstruction iaddr iaddr_'+ins.address+'">'+ins.address+'</span> '+
    //'<div class="instructiondesc">'+hex(ins.flags)+'</div> '+
    '<div class="instructiondesc">'+ins.instruction+'</div>';
    idump += '</div>';
    if (ins.semantics !== undefined && ins.semantics.indexOf("endbb") != -1) {
      last_basic_block = in_basic_block;
      pushBlock();
      in_basic_block = false;
    }
  }

  if (in_basic_block) pushBlock();

  graph.assignLevels();
  graph.debugPrint();
  graph.render();

  rehighlight();
} stream.on('tags', on_tags);

