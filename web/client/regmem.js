stream = io.connect(STREAM_URL);


var current_regs = undefined;

function on_maxclnum(msg) { DS("maxclnum");
  update_maxclnum(msg);
} stream.on('maxclnum', on_maxclnum);

function on_pmaps(msg) { DS("pmaps");
  Session.set('pmaps', msg)
} stream.on('pmaps', on_pmaps);

function redraw_reg_flags() {
  $(".rflag").remove();
  if (current_regs !== undefined) {
    for (r in current_regs) {
      var th = current_regs[r];
      var t = $('#data_'+th.value);
      if (t.length == 1 && !t.hasClass("register")) {
        var rr = $('<div class="rflag"></div>');
        rr.css("background-color", regcolors[th.num]);
        var pos = (t.children().length-1)*3;  // rflag width
        rr.css("margin-left", pos+"px");
        t.prepend(rr);
      }
    }
  }
}

$(document).ready(function() {
  $("#hexdump")[0].addEventListener("mousewheel", function(e) {
    if (e.wheelDelta < 0) {
      Session.set('dview', bn_add(Session.get('dview'), 0x10));
    } else if (e.wheelDelta > 0) {
      Session.set('dview', bn_add(Session.get('dview'), -0x10));
    }
  });
});

function on_memory(msg) { DS("memory");
  // render the hex editor
  // this isn't updated for numberless
  var addr = msg['address'];
  var daddr = Session.get('daddr');
  var PTRSIZE = msg['ptrsize'];
  html = "<table><tr>";
  for (var i = 0; i < msg['len']; i += PTRSIZE) {
    if ((i&0xF) == 0) html += "</tr><tr><td>"+bn_add(addr, i)+":</td>";
    html += "<td></td>";

    // check if it's an address
    var v = "0x";

    if (msg['is_big_endian']) {
      for (var j = 0; j < PTRSIZE; j++) {
        v += hex2(msg['dat'][i+j]);
      }
    } else {
      for (var j = PTRSIZE-1; j >= 0; j--) {
        v += hex2(msg['dat'][i+j]);
      }
    }
    v = bn_canonicalize(v)
    var a = get_data_type(v);
    if (a !== "") {
      // this has a datatype, and therefore is clickable, so add addr
      var exclass = "data_"+bn_add(addr, i);
      var exclassmore = exclass + " addr addr_"+v;
      var minwidth = 84;
      if (PTRSIZE == 8) minwidth = 172;
      html += '<td colspan="'+PTRSIZE+'"><div style="overflow: hidden; width:'+minwidth+'px" id="'+exclass+'"><div class="data hexdump'+a+' '+exclassmore+'">'+v+"</div></div></td>";
    } else {
      for (var j = 0; j < PTRSIZE; j++) {
        var ii = msg['dat'][i+j];
        var me = hex2(ii);
        var exclass = "data_"+bn_add(addr, i+j);
        html += '<td class="data '+exclass+'" id="'+exclass+'">'+me+"</td>";
      }
    }

    // this must run on the last one too
    if ((i&0xF) == (0x10-PTRSIZE)) { 
      str = "";
      for (var j = 0; j < 0x10; j++) {
        // ewww
        var ii = msg['dat'][i-(0x10-PTRSIZE)+j];
        if (ii == 0x20) str += "&nbsp;";
        else if (ii == 0x26) str += "&amp;";
        else if (ii == 0x3C) str += "&lt;";
        else if (ii == 0x3E) str += "&gt;";
        else if (ii >= 0x21 && ii <= 0x7e) str += String.fromCharCode(ii);
        else if (ii == undefined) str += "&nbsp;";
        else str += ".";
      }
      html += "<td>" + str + "</td>"; str = "";
    }
  }
  html += "</tr></table>";
  $("#hexdump")[0].innerHTML = html;
  redraw_reg_flags();
  rehighlight();
  replace_names();
} stream.on('memory', on_memory);


// keep these updated
Deps.autorun(function() { DA("emit getmemory");
  var forknum = Session.get("forknum");
  var daddr = Session.get('daddr');
  var dview = Session.get('dview');
  var clnum = Session.get('clnum');
  if (dview == undefined) {
    $('#hexdump').empty();
  } else {
    stream.emit('getmemory', forknum, clnum-1, dview, 0x100);
  }
});

Deps.autorun(function() { DA("emit getregisters");
  var forknum = Session.get("forknum");
  var clnum = Session.get('clnum');
  stream.emit('getregisters', forknum, clnum-1);
});

function on_registers(msg) { DS("registers");
  current_regs = msg;
  redraw_reg_flags();
  var tsize = msg[0]['size'];
  if (tsize > 0) PTRSIZE = tsize;

  var regviewer = "";
  for (i in msg) {
    var r = msg[i];
    draw_hflag(r.value, r.name, regcolors[r.num]);
    var exclass = get_data_type(r.value);
    if (exclass !== "") {
      exclass += " addr addr_"+r.value;
    }
    regviewer += '<div class="reg '+r.regactions+'">'+
        '<div class="register data data_'+hex(r.address)+'" id="data_'+hex(r.address)+'" style="color:'+regcolors[r.num]+'">'+r.name+': </div>'+
        '<span class="'+exclass+'">'+r.value+'</span>'+
      '</div>';
  }
  $('#regviewer').html(regviewer);
  rehighlight();
  replace_names();
} stream.on('registers', on_registers);

// *** datachanges ***

Deps.autorun(function() { DA("emit getclnum for datachanges");
  var forknum = Session.get("forknum");
  stream.emit('getclnum', forknum, Session.get('clnum'), ['L', 'S'], 2)  // justification for more than 2?
});

// TODO: misleading name
function on_clnum(msg) { DS("clnum");
  var datachanges = "";
  for (i in msg) {
    var dc = msg[i];
    //p(dc);
    var typeclass = ""
    if (dc.type == "L") typeclass = "regread";
    else if (dc.type == "S") typeclass = "regwrite";
    datachanges += '<div class="datachanges '+typeclass+'"> '+
        '<span class="'+get_data_type(dc.address, true)+'">'+dc.address+'</span> '+
        ((dc.type == "S")?'&lt;--':'--')+' '+
        '<span class="'+get_data_type(dc.data, true)+'">'+dc.data+'</span> '+
      '</div> ';
  }
  $('#datachanges').html(datachanges);
} stream.on('clnum', on_clnum);

