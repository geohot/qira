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
    Session.set("daddr", parseInt(e.target.value, 16));
  }
};


