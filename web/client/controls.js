Template.controls.clnum = function() {
  return Session.get("clnum");
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
  'change #control_iaddr': function(e) {
    Session.set("iaddr", parseInt(e.target.value, 16));
  },
  'change #control_daddr': function(e) {
    update_dview(parseInt(e.target.value, 16));
  }
};

// keyboard shortcuts
window.onkeydown = function(e) {
  p(e.keyCode);
  if (e.keyCode == 38) {
    Session.set("clnum", Session.get("clnum")-1);
  } else if (e.keyCode == 40) {
    Session.set("clnum", Session.get("clnum")+1);
  } else if (e.keyCode == 90) {
    zoom_out_max();
  } else if (e.keyCode == 27) {
    history.back();
  }
};

