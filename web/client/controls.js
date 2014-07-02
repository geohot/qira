// belongs in library
function update_dview(addr) {
  Session.set('daddr', addr);
  Session.set('dview', (addr-0x20)-(addr-0x20)%0x10);
}

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


