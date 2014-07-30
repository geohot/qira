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
  return hex(Session.get("iaddr"));
};

Template.controls.daddr = function() {
  return hex(Session.get("daddr"));
};

Template.controls.events = {
  'change #control_clnum': function(e) {
    Session.set("clnum", parseInt(e.target.value));
  },
  'change #control_forknum': function(e) {
    Session.set("forknum", parseInt(e.target.value));
  },
  'change #control_iaddr': function(e) {
    Session.set("iaddr", fhex(e.target.value));
  },
  'change #control_daddr': function(e) {
    update_dview(fhex(e.target.value));
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
  } else if (e.keyCode == 27) {  // esc
    history.back();
  }
};

$(document).ready(function() {
  $('body').on('click', '.hdatamemory', function(e) {
    update_dview(fhex(e.target.innerHTML));
  });
  $('body').on('click', '.hdatainstruction', function(e) {
    update_dview(fhex(e.target.innerHTML));
  });
  $('body').on('contextmenu', '.hdatainstruction', function(e) {
    Session.set("iaddr", fhex(e.target.innerHTML));
    return false;
  });
});

// don't pull the window
//window.onmousewheel = function() { return false; }

