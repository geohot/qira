stream = io.connect(STREAM_URL);

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
  if (this.clnum == clnum) {
    // keep the iaddr in sync with the change
    //Session.set('ciaddr', this.address);
    Session.set('iaddr', this.address);
    // let's try turning this off, might be more usable
    // yea, i think it is, file a bug if you hate it
    return "highlight";
  }
  else if (this.slice == true) return "halfhighlight";
  else return "";
};

Template.idump.isiaddr = function() {
  var iaddr = Session.get("iaddr");
  if (this.address == iaddr) return "highlight";
  else return "";
}

// can remove in template
Template.idump.hexaddress = function() {
  return this.address;
};

Template.idump.depth = function() {
  return this.depth * 10;
};

Template.idump.events({
  'click .change': function() {
    Session.set('clnum', this.clnum);
  },
  'mousedown .datainstruction': function(e) { return false; },
  'click .datainstruction': function() {
    Session.set('iaddr', this.address);
  },
  'dblclick .datainstruction': function() {
    update_dview(this.address);
  }
});

Template.idump.instruction = function() { return highlight_addresses(this.instruction); }

// ** should move these to idump.js **

stream.on('instructions', function(msg) {
  $('#idump')[0].innerHTML = "";
  UI.insert(UI.renderWithData(Template.idump, {instructions: msg}), $('#idump')[0]);
});

Deps.autorun(function() { DA("emit getinstructions");
  var forknum = Session.get("forknum");
  var clnum = Session.get("clnum");
  stream.emit('getinstructions', forknum, clnum, clnum-8, clnum+10);
});

