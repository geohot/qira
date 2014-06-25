var X86REGS = ['EAX', 'ECX', 'EDX', 'EBX', 'ESP', 'EBP', 'ESI', 'EDI', 'EIP'];

Template.changelist.currentchanges = function() {
  var clnum = Session.get('clnum');
  return Change.find({clnum: clnum}, {sort: {address: 1}, limit:20});
};

Template.changelist.iaddr = function() { return hex(Session.get('iaddr')); };
Template.changelist.daddr = function() { return hex(Session.get('daddr')); };
Template.changelist.clnum = function() { return Session.get('clnum'); };

Template.changelist.icllist = function() {
  var iaddr = Session.get('iaddr');
  return Change.find({address: iaddr, type: "I"}, {sort: {clnum: 1},limit:10})
};

Template.changelist.dcllist = function() {
  var daddr = Session.get('daddr');
  if (daddr >= 0x1000) {
    return Change.find({address:daddr}, {sort: {clnum: 1},limit:10});
  } else {
    return false;
  }
};

Template.changelist.events({
  'change #daddr_input': function() {
    if ($("#daddr_input")[0].value == "") {
      Session.set('daddr', undefined);
      return;
    }
    var daddr = parseInt($("#daddr_input")[0].value, 16);
    p("new daddr is "+daddr);
    Session.set('daddr', daddr);
  },
});

Template.change.is_mem = function() {
  return this.type == "L" || this.type == "S";
};

Template.change.events({
  'click .address': function() {
    p("new daddr is "+hex(this.address));
    Session.set('daddr', this.address);
  },
});

Template.change.handleaddress = function () {
  if (this.type == "R" || this.type == "W") {
    if (this.address < (X86REGS.length*4)) {
      return X86REGS[this.address/4];
    } else {
      return hex(this.address);
    }
  } else {
    return hex(this.address);
  }
};

Template.change.handledata = function () {
  return hex(this.data);
};

Template.cl.events({
  'click .change': function() {
    Session.set('clnum', this.clnum);
  }
});

// these three draw the changelist viewer
Deps.autorun(function(){ Meteor.subscribe('dat_clnum', Session.get("clnum")); });
Deps.autorun(function(){ Meteor.subscribe('dat_iaddr', Session.get("iaddr")); });
Deps.autorun(function(){ Meteor.subscribe('dat_daddr', Session.get("daddr")); });

