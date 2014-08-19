stream = io.connect(STREAM_URL);

function on_setiaddr(iaddr) { DS("setiaddr");
  Session.set("dirtyiaddr", true);
  Session.set('iaddr', iaddr);
} stream.on('setiaddr', on_setiaddr);

function on_setclnum(forknum, clnum) { DS("setclnum");
  Session.set('forknum', forknum);
  Session.set('clnum', clnum);
} stream.on('setclnum', on_setclnum);

Deps.autorun(function() { DA("set backend know iaddr changed");
  var iaddr = Session.get('iaddr');
  stream.emit('navigateiaddr', iaddr);
});

Deps.autorun(function() { DA("update controls");
  $("#control_clnum").val(Session.get("clnum"));
  $("#control_forknum").val(Session.get("forknum"));
  $("#control_iaddr").val(Session.get("iaddr"));
  $("#control_daddr").val(Session.get("daddr"));
});
  
$(document).ready(function() {
  $('#control_clnum').on('change', function(e) {
    Session.set("clnum", parseInt(e.target.value));
  });
  $('#control_forknum').on('change', function(e) {
    Session.set("forknum", parseInt(e.target.value));
  });
  $('#control_iaddr').on('change', function(e) {
    if (e.target.value == "") {
      Session.set("iaddr", undefined);
    } else {
      Session.set("iaddr", e.target.value);
      Session.set("dirtyiaddr", true);
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

// keyboard shortcuts
window.onkeydown = function(e) {
  //p(e.keyCode);
  //p(e);
  if (e.keyCode == 37) {
    Session.set("forknum", Session.get("forknum")-1);
  } else if (e.keyCode == 39) {
    Session.set("forknum", Session.get("forknum")+1);
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
    go_to_flag(true, false);
  } else if (e.keyCode == 75) {  // vim up, k
    go_to_flag(false, false);
  } else if (e.keyCode == 85) {  // vim down, row up, data, u
    go_to_flag(true, true);
  } else if (e.keyCode == 73) {  // vim up, row up, data, i
    go_to_flag(false, true);
  } else if (e.keyCode == 27) {  // esc
    history.back();
  } else if (e.keyCode == 67 && e.shiftKey == true) {
    // shift-C = clear all forks
    delete_all_forks();
  }
};

$(document).ready(function() {
  $('body').on('click', '.clnum', function(e) {
    Session.set('clnum', parseInt(e.target.textContent));
  });
  $('body').on('click', '.iaddr', function(e) {
    Session.set('iaddr', e.target.textContent);
  });
  $('body').on('click', '.daddr', function(e) {
    var daddr = e.target.getAttribute('id').split("_")[1];
    Session.set('daddr', daddr);
  });
  $('body').on('click', '.hdatamemory', function(e) {
    update_dview(e.target.textContent);
  });
  $('body').on('click', '.hdatainstruction', function(e) {
    update_dview(e.target.textContent);
  });
  $('body').on('dblclick', '.datamemory', function(e) {
    update_dview(e.target.textContent);
  });
  $('body').on('dblclick', '.datainstruction', function(e) {
    update_dview(e.target.textContent);
  });
  $('body').on('contextmenu', '.datainstruction', function(e) {
    Session.set("iaddr", e.target.textContent);
    Session.set("dirtyiaddr", true);
    return false;
  });
  $('body').on('click', '.flag', function(e) {
    var forknum = parseInt(e.target.parentNode.id.substr(9));
    var clnum = parseInt(e.target.textContent);
    Session.set("forknum", forknum);
    Session.set("clnum", clnum);
  });
  $('body').on('contextmenu', '.hdatainstruction', function(e) {
    Session.set("iaddr", e.target.textContent);
    Session.set("dirtyiaddr", true);
    return false;
  });
  $('body').on('mousedown', '.datamemory', function(e) { return false; });
  $('body').on('mousedown', '.datainstruction', function(e) { return false; });
});

