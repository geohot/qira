// static stuff

stream = io.connect(STREAM_URL);

Deps.autorun(function() { DA("update static view");
  var iview = Session.get('iview');
  var flat = Session.get('flat');
  if (iview === undefined) return;
  stream.emit('getstaticview', iview, flat, [-15,40]);
});

/*$(function() {
  $("#staticpanel").css("display", "none");
});*/


// TODO: this code is replicated in idump.js
function instruction_html_from_tags(ins) {
  var idump = '<div class="instruction">';
  idump += '<span class="insaddr datainstruction addr addr_'+ins.address+'">'+ins.address+'</span> ';
  if (ins.instruction !== undefined) {
    idump += '<div class="instructiondesc">'+highlight_instruction(ins.instruction)+'</div> ';
  } else {
    if (ins.type == "string") {
      idump += '<div class="stringdesc">';
      idump += "'";
      // TODO: escaping?
      ins.bytes.forEach(function(x) {
        idump += String.fromCharCode(x);
      });
      idump += "'";
      idump += '</div>';
    } else {
      if (ins.type == "data") {
        idump += '<div class="datadesc">';
      } else {
        idump += '<div class="bytesdesc">';
      }
      ins.bytes.forEach(function(x) {
        idump += hex2(x)+" ";
      });
      idump += '</div>';
    }
  }

  idump += '<span class="comment comment_'+ins.address+'">'+(ins.comment != undefined ? "; "+ins.comment : "")+'</span>';
  idump += '</div>';
  return idump;
}

function display_flat(addrs) {
  //p(addrs);
  var idump = '<div class="flat">';
  for (var i=0;i<addrs.length;i++) {
    idump += instruction_html_from_tags(addrs[i]);
  }
  idump += '</div>';
  $("#staticpanel").html(idump);
}

function on_flat(addrs) { DS("flat"); 
  display_flat(addrs);
  rehighlight();
  replace_names();
} stream.on('flat', on_flat);

function on_function(fxn) { DS("function"); 
  var graph = new Graph();
  p(fxn);

  for (var bn = 0; bn < fxn.blocks.length; bn++) {
    var bb = fxn.blocks[bn];
    if (bb.length == 0) continue;
    var addr = bb[0].address;
    var cnt = bb.length;
    
    var idump = "";
    for (var i = 0; i < cnt; i++) {
      idump += instruction_html_from_tags(bb[i]);
    }
    var dom = $('<div class="basicblock" id="bb_'+addr+'">');

    dom.html(idump);
    graph.addVertex(addr, cnt, dom[0]);

    // add edges
    for (var i = 0; i < bb[cnt-1].dests.length; i++) {
      var dd = bb[cnt-1].dests[i];
      if (dd[1] == 3) continue;

      var col = "blue";  // base off dd[1]
      if (bb[cnt-1].dests.length > 1 && dd[1] == 4) {
        col = "red";
      } else if (dd[1] == 1) {
        col = "green";
      }
      graph.addEdge(addr, dd[0], col);
    }

  }

  graph.assignLevels();
  graph.render();

  rehighlight();
  replace_names();
} stream.on('function', on_function);

