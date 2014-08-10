stream = io.connect(STREAM_URL);

stream.on('setiaddr', function(iaddr) {
  Session.set("dirtyiaddr", true);
  Session.set('iaddr', iaddr);
});

Deps.autorun(function() {
  var iaddr = Session.get('iaddr');
  stream.emit('navigateiaddr', iaddr);
});

Template.controls.clnum = function() {
  return Session.get("clnum");
};

Template.controls.forknum = function() {
  return Session.get("forknum");
};

Template.controls.iaddr = function() {
  return Session.get("iaddr");
};

Template.controls.daddr = function() {
  return Session.get("daddr");
};

Template.controls.events = {
  'change #control_clnum': function(e) {
    Session.set("clnum", parseInt(e.target.value));
  },
  'change #control_forknum': function(e) {
    Session.set("forknum", parseInt(e.target.value));
  },
  'change #control_iaddr': function(e) {
    if (e.target.value == "") {
      Session.set("iaddr", undefined);
    } else {
      Session.set("iaddr", e.target.value);
    }
  },
  'change #control_daddr': function(e) {
    if (e.target.value == "") {
      Session.set("daddr", undefined);
    } else {
      update_dview(e.target.value);
    }
  },
  'click #control_fork': function(e) {
    var clnum = Session.get("clnum");
    var forknum = Session.get("forknum");
    var pending = Session.get('pending');
    stream.emit('forkat', forknum, clnum, pending);
  }
};

// keyboard shortcuts
window.onkeydown = function(e) {
  //p(e.keyCode);
  if (e.keyCode == 37) {
    Session.set("forknum", Session.get("forknum")-1);
  } else if (e.keyCode == 39) {
    Session.set("forknum", Session.get("forknum")+1);
  } else if (e.keyCode == 38) {
    Session.set("clnum", Session.get("clnum")-1);
  } else if (e.keyCode == 40) {
    Session.set("clnum", Session.get("clnum")+1);
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
  } /* else if (e.keyCode == 76) {  // l
    Session.set("iaddr", Session.get("ciaddr"));
  }*/
};

$(document).ready(function() {
  $('body').on('click', '.hdatamemory', function(e) {
    update_dview(e.target.innerHTML);
  });
  $('body').on('click', '.hdatainstruction', function(e) {
    update_dview(e.target.innerHTML);
  });
  $('body').on('contextmenu', '.hdatainstruction', function(e) {
    Session.set("iaddr", e.target.innerHTML);
    Session.set("dirtyiaddr", true);
    return false;
  });
});

// don't pull the window
window.onmousewheel = function(e) {
  if (e.target.id.substr(0,9) == "vtimeline")
    return true;
  else
    return false;
}


