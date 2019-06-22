stream = io.connect(STREAM_URL);

function on_setiaddr(iaddr) { DS("setiaddr");
  update_iaddr(iaddr);
} stream.on('setiaddr', on_setiaddr);

function on_setclnum(msg) { DS("setclnum");
  var forknum = msg['forknum'];
  var clnum = msg['clnum'];
  Session.set('forknum', forknum);
  Session.set('clnum', clnum);
  push_history("remote setclnum");
} stream.on('setclnum', on_setclnum);

Deps.autorun(function() { DA("set backend know iaddr changed");
  var iaddr = Session.get('iaddr');
  stream.emit('navigateiaddr', iaddr);
});

Deps.autorun(function() { DA("select first fork if current fork isn't valid");
  var maxclnum = Session.get("max_clnum");
  if (maxclnum === undefined) return;
  var forknum = Session.get('forknum', true)
  if (maxclnum[forknum] === undefined) {
    // i don't know javascript
    for (i in maxclnum) {
      Session.set('forknum', fdec(i));
      Session.set('clnum', maxclnum[i][1]);
      break;
    }
  }
});

Deps.autorun(function() { DA("update controls");
  $("#control_clnum").val(Session.get("clnum"));
  $("#control_forknum").val(Session.get("forknum"));
  $("#control_iaddr").val(Session.get("iaddr"));
  $("#control_daddr").val(Session.get("daddr"));
});

$(document).ready(function() {
  $('#control_clnum').on('change', function(e) {
    Session.set("clnum", fdec(e.target.value));
  });
  $('#control_forknum').on('change', function(e) {
    Session.set("forknum", fdec(e.target.value));
  });
  $('#control_iaddr').on('change', function(e) {
    if (e.target.value == "") {
      Session.set("iaddr", undefined);
    } else {
      update_iaddr(e.target.value, true);
    }
  });
  $('#control_daddr').on('change', function(e) {
    if (e.target.value == "") {
      Session.set("daddr", undefined);
      Session.set("dview", undefined);
    } else {
      update_dview(e.target.value);
    }
  });
});

$(document).ready(function() {
  var drag_x, drag_y, is_dragging;
  function startDrag(x, y) {
    //p("startDrag "+x+" "+y);
    drag_x = fdec($("#gbox").css("margin-left")) - x;
    drag_y = fdec($("#gbox").css("margin-top")) - y;
    is_dragging = true;
  }
  function endDrag(x, y, isend) {
    //p("endDrag "+x+" "+y);
    if (is_dragging) {
      $("#gbox").css("margin-left", (drag_x+x));
      $("#gbox").css("margin-top", (drag_y+y));
    }
    if (isend) is_dragging = false;
  }
  $('#cfg-static').on('wheel', '#outergbox', function(e) {
    var wdx = e.originalEvent.deltaX;
    var wdy = e.originalEvent.deltaY;
    $("#gbox").css("margin-left", fdec($("#gbox").css("margin-left")) + wdx);
    $("#gbox").css("margin-top", fdec($("#gbox").css("margin-top")) + wdy);
  });
  $('#cfg-static').on('mousedown', '#outergbox', function(e) {
    //p("mousedown");
    startDrag(e.screenX, e.screenY);
    return false;
  });
  $('#cfg-static').on('mousemove', '#outergbox', function(e) {
    endDrag(e.screenX, e.screenY, false);
  });
  $('#cfg-static').on('mouseup', '#outergbox', function(e) {
    endDrag(e.screenX, e.screenY, true);
  });
  $('#cfg-static').on('mouseout', '#outergbox', function(e) {
    // TODO: FIX THIS!
    /*p(e.target);
    p(e.target.id);*/
    /*if (e.target.id === "outergbox" || e.target.id === "gcanvas") {
      endDrag(e.screenX, e.screenY, true);
    }*/
  });
  $('body').on('wheel', '.flat', function(e) {
    var cdr = $(".flat").children();
    p(e.originalEvent.deltaY);
    if (e.originalEvent.deltaY > 0) {
      Session.set('iview', bn_add(Session.get('iview'), -1));
    } else if (e.originalEvent.deltaY < 0) {
      Session.set('iview', bn_add(Session.get('iview'), 1));
    }
  });
  $("#idump")[0].addEventListener("wheel", function(e) {
    //p("idump mousewheel");
    if (e.deltaY > 0) {
      Session.set('clnum', Session.get('clnum')+1);
    } else if (e.deltaY < 0) {
      Session.set('clnum', Session.get('clnum')-1);
    }
  });
});

Session.setDefault("flat", false);

// keyboard shortcuts
window.onkeydown = function(e) {
  if (!$(e.target).is("input") && !((e.ctrlKey || e.metaKey) && e.keyCode === 67)) e.preventDefault();
  //p(e.keyCode);
  //p(e);
  if (e.ctrlKey == true) return;
  if (e.keyCode == 32) {
    // space bar
    Session.set("flat", !Session.get("flat"));
  } else if (e.keyCode == 37 || e.keyCode == 39) {
    var fn = Session.get("forknum");
    var maxclnum = Session.get("max_clnum");
    var arr = Object.keys(maxclnum).map(fdec);
    var idx = arr.indexOf(fn);
    if (e.keyCode == 37) {
      if (idx > 0) {
        Session.set("forknum", arr[idx-1]);
      }
    } else {
      if (idx < (arr.length-1)) {
        Session.set("forknum", arr[idx+1]);
      }
    }
  } else if (e.keyCode == 89) {
    var addr = Session.get("iaddr");
    var func = sync_tags_request([addr])[0]['function'];
    if (func !== undefined) {
      var args = prompt("#args for function",sync_tags_request([addr])[0]['nargs']);
      stream.emit('setfunctionargswrap',addr,args);
    }
  } else if (e.keyCode == 67 && e.shiftKey == true) {
    // shift-C = clear all forks
    delete_all_forks();
  } else if (e.keyCode == 'P'.charCodeAt(0)) {  // p, make function
    stream.emit('make', 'function', Session.get("iaddr"));
    Session.set("flat", Session.get("flat"));
  } else if (e.keyCode == 'C'.charCodeAt(0)) {  // c, make code
    stream.emit('make', 'code', Session.get("iaddr"));
    Session.set("flat", Session.get("flat"));
  } else if (e.keyCode == 'A'.charCodeAt(0)) {  // a, make string
    stream.emit('make', 'string', Session.get("iaddr"));
    Session.set("flat", Session.get("flat"));
  } else if (e.keyCode == 'D'.charCodeAt(0)) {  // d, make data
    stream.emit('make', 'data', Session.get("iaddr"));
    Session.set("flat", Session.get("flat"));
  } else if (e.keyCode == 'U'.charCodeAt(0)) {  // u, make undefined
    stream.emit('make', 'undefined', Session.get("iaddr"));
    Session.set("flat", Session.get("flat"));
  } else if (e.keyCode == 38) {
    Session.set("clnum", Session.get("clnum")-1);
  } else if (e.keyCode == 40) {
    Session.set("clnum", Session.get("clnum")+1);
  } else if (e.keyCode == 77) {  // m -- end of function
    stream.emit('navigatefunction', Session.get("forknum"), Session.get("clnum"), false);
  } else if (e.keyCode == 188) {  // , -- start of function
    stream.emit('navigatefunction', Session.get("forknum"), Session.get("clnum"), true);
  } else if (e.keyCode == 90) {  // z
    zoom_out_max();
  } else if (e.keyCode == 74) {  // vim down, j
    go_to_flag(true, e.shiftKey);
  } else if (e.keyCode == 75) {  // vim up, k
    go_to_flag(false, e.shiftKey);
  } else if (e.keyCode == 27) {  // esc
    history.back();
  } else if (e.keyCode == 78 || e.keyCode == 186) {
    // 186 is comment
    if (e.shiftKey) {
      // shift-n = rename data
      var addr = Session.get("daddr");
    } else {
      // n = rename instruction
      var addr = Session.get("iaddr");
    }
    var tagname = 'name';
    if (e.keyCode == 186) {
      tagname = 'comment';
    }

    if (addr == undefined) return;
    var old = sync_tags_request([addr])[0][tagname];
    if (old == undefined) old = "";

    if (tagname == 'name') {
      var dat = prompt("Rename address "+addr, old);
      //having no comment makes sense. having no name does not.
      //or we should default to the autogen name like IDA
      if (dat == "") return;
    } else {
      var dat = prompt("Enter comment for "+addr, old);
    }

    if (dat == undefined) return;
    var send = {};
    send[addr] = {}
    send[addr][tagname] = dat;
    stream.emit("settags", send);

    if (tagname == 'name') {
      replace_names();
    } else if (tagname == 'comment') {
      // do this explictly?
      if (dat != "")
        $(".comment_"+addr).html("; "+dat);
      else
        $(".comment_"+addr).html("");
    }
    Session.set("ida_sync_addr", addr);
    Session.set("ida_sync_tagname", tagname);
    Session.set("ida_sync_dat", dat);
  } else if (e.keyCode == 71) {
    var dat = prompt("Enter change or address");
    if (dat == undefined) return;
    if (dat.substr(0, 2) == "0x") { update_iaddr(dat); }
    else if (fdec(dat) == dat) { Session.set("clnum", fdec(dat)); }
    else {
      stream.emit("gotoname", dat);
    }
  }
};



$(document).ready(function() {

  // control the highlighting of things
  $('body').on('click', '.clnum', function(e) {
    Session.set('clnum', fdec(e.target.textContent));
    push_history("click clnum");
  });
  /*$('body').on('click', '.iaddr', function(e) {
    Session.set('iaddr', e.target.textContent);
    push_history("click iaddr");
  });*/
  $('body').on('click', '.data', function(e) {
    //var daddr = e.target.getAttribute('id').split("_")[1].split(" ")[0];
    var daddr = get_address_from_class(e.target, "data");

    Session.set('daddr', daddr);
    push_history("click data");
  });


  // registers and other places
  $('body').on('click', '.dataromemory', function(e) {
    update_dview(get_address_from_class(e.target));
  });
  $('body').on('click', '.datamemory', function(e) {
    update_dview(get_address_from_class(e.target));
  });
  $('body').on('click', '.datainstruction', function(e) {
    /*var d = get_address_from_class(e.target)
    p(d);
    update_dview(d);*/
    update_iaddr(get_address_from_class(e.target), false);
  });

  $('body').on('dblclick', '.datainstruction', function(e) {
    update_iaddr(get_address_from_class(e.target));
  });

  $('body').on('contextmenu', '.datainstruction', function(e) {
    update_dview(get_address_from_class(e.target));
    return false;
  });

  // hexdump
  $('body').on('dblclick', '.hexdumpdatamemory', function(e) {
    update_dview(get_address_from_class(e.target));
  });
  $('body').on('dblclick', '.hexdumpdataromemory', function(e) {
    update_dview(get_address_from_class(e.target));
  });
  $('body').on('contextmenu', '.hexdumpdatainstruction', function(e) {
    update_iaddr(get_address_from_class(e.target));
    //update_dview(get_address_from_class(e.target));
    return false;
  });
  /*$('body').on('click', '.hexdumpdatainstruction', function(e) {
    update_iaddr(get_address_from_class(e.target), false);
    return false;
  });*/
  $('body').on('dblclick', '.hexdumpdatainstruction', function(e) {
    update_dview(get_address_from_class(e.target));
    return false;
  });
  $('body').on('mousedown', '.hexdumpdataromemory', function(e) { return false; });
  $('body').on('mousedown', '.hexdumpdatamemory', function(e) { return false; });
  $('body').on('mousedown', '.hexdumpdatainstruction', function(e) { return false; });
  $('body').on('mousedown', '.datainstruction', function(e) { return false; });

  // vtimeline flags
  $('body').on('click', '.flag', function(e) {
    var forknum = fdec(e.target.parentNode.id.substr(9));
    var clnum = fdec(e.target.textContent);
    Session.set("forknum", forknum);
    Session.set("clnum", clnum);
    push_history("click flag");
  });
});
