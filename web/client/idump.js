Meteor.startup(function() {
  $("#idump")[0].addEventListener("mousewheel", function(e) {
    if (e.wheelDelta < 0) {
      Session.set('clnum', Session.get('clnum')+1);
    } else if (e.wheelDelta > 0) {
      Session.set('clnum', Session.get('clnum')-1);
    }
  });
});

Template.idump.ischange = function() {
  var clnum = Session.get("clnum");
  if (this.clnum == clnum) return "highlight";
  else return "";
};

Template.idump.isiaddr = function() {
  var iaddr = Session.get("iaddr");
  if (this.address == iaddr) return "highlight";
  else return "";
}

Template.idump.instructions = function() {
  var clnum = Session.get("clnum");
  var changes = Change.find({clnum: {$gt: clnum-4, $lt: clnum+8}, type: "I"}, {sort: {clnum:1}});
  return changes;
};

Template.idump.program_instruction = function() {
  var progdat = Program.findOne({address: this.address});
  return progdat;
};

Template.idump.hexaddress = function() {
  return hex(this.address);
};

Template.idump.events({
  'click .change': function() {
    Session.set('clnum', this.clnum);
  }
});

Deps.autorun(function(){ Meteor.subscribe('instructions', Session.get("clnum")); });

