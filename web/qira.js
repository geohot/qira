Change = new Meteor.Collection("change");
Program = new Meteor.Collection("program");

var PC = 0x20;

function p(a) {
  console.log(a);
}

function hex(a) {
  if (a == undefined) {
    return "";
  } else {
    return "0x"+a.toString(16);
  }
}

if (Meteor.isClient) {
  function update_current_clnum(clnum) {
    var cl_selector = $('#cl_selector');
    cl_selector[0].value = clnum;
    cl_selector.slider('refresh');
  }

  Template.cfg.isiaddr = function() {
    var iaddr = Session.get('iaddr');
    if (this.address == iaddr) return "highlight";
    else return "";
  }

  Template.cfg.hexaddress = function() { return hex(this.address)+": "; };

  Template.cfg.lineardump = function() {
    var iaddr = Session.get('iaddr');
    if (iaddr !== undefined) {
      return Program.find({address: {$gt: iaddr-0x30, $lt: iaddr+0x80}}, {sort: {address:1}});
    }
  };

  Template.timeline.max_clnum = function() {
    var post = Change.findOne({}, {sort: {clnum: -1}});
    if (post != undefined) {
      if ($('#cl_selector').length > 0) {
        $('#cl_selector')[0].max = post.clnum;
        var clnum = Session.get("clnum");
        if (clnum == undefined) {
          update_current_clnum(post.clnum);
        } else {
          update_current_clnum(clnum);
        }
      }
    }
  };

  Template.timeline.rendered = function() {
    $('#cl_selector').on("change", function(e) {
      var val = parseInt($('#cl_selector')[0].value);
      Session.set("clnum", val);
    });
  };

  Template.changelist.currentchanges = function() {
    var clnum = Session.get('clnum');
    return Change.find({clnum: clnum}, {sort: {address: 1}, limit:10});
  };

  Template.changelist.iaddr = function() { return hex(Session.get('iaddr')); };
  Template.changelist.daddr = function() { return hex(Session.get('daddr')); };
  Template.changelist.clnum = function() { return Session.get('clnum'); };

  Template.changelist.icllist = function() {
    var iaddr = Session.get('iaddr');
    return Change.find({data: iaddr, address: PC, type: "W"}, {sort: {clnum: 1},limit:10})
  };

  Template.changelist.dcllist = function() {
    var daddr = Session.get('daddr');
    if (daddr >= 0x1000) {
      return Change.find({address:daddr}, {sort: {clnum: 1},limit:10});
    } else {
      return false;
    }
  };

  Template.change.is_mem = function() {
    return this.type == "L" || this.type == "S";
  };

  Template.cl.events({
    'click .change': function() {
      update_current_clnum(this.clnum);
    }
  });
  Template.change.events({
    'click .address': function() {
      p("new daddr is "+hex(this.address));
      Session.set("daddr", this.address);
    }
  });

  Template.cfg.events({
    'click .address': function() {
      p("new iaddr is "+hex(this.address));
      Session.set("iaddr", this.address);
    }
  });

  Template.change.handleaddress = function () {
    if (this.address == PC && this.type == "W") {
      p("new iaddr is "+hex(this.data));
      Session.set("iaddr", this.data);
    }
    return hex(this.address);
  };

  Template.change.handledata = function () {
    return hex(this.data);
  };  

  var subs = new Meteor.autosubscribe(function(){
    Meteor.subscribe('dat_iaddr', Session.get("iaddr"));
    Meteor.subscribe('dat_daddr', Session.get("daddr"));
    Meteor.subscribe('dat_clnum', Session.get("clnum"));

    Meteor.subscribe('instruction_iaddr', Session.get("iaddr"));
  });
  Meteor.subscribe('max_clnum');
}

if (Meteor.isServer) {
  Meteor.startup(function () {
  });

  Meteor.publish('max_clnum', function() {
    // extract 'clnum' from this to get the max clnum
    return Change.find({}, {sort: {clnum: -1}, limit: 1});
  });

  Meteor.publish('dat_clnum', function(clnum){
    // can only return as many as in the changelist
    return Change.find({clnum: clnum}, {sort: {address: 1}, limit:10});
  });

  Meteor.publish('instruction_iaddr', function(iaddr){
    return Program.find({address: {$gt: iaddr-0x50, $lt: iaddr+0x100}}, {sort: {address:1}});
  });

  Meteor.publish('dat_iaddr', function(iaddr){
    // fetch the static info about the range
    return Change.find({data: iaddr, address: PC, type: "W"}, {sort: {clnum: 1}, limit:10})
    //return Program.find({address: PC, type: "W", clnum
  });

  Meteor.publish('dat_daddr', function(daddr){
    // fetch the dynamic info about the instruction range
    //return Change.find({address : {$gt: daddr-0x100, $lt: daddr+0x300}});
    if (daddr >= 0x1000) {
      return Change.find({address:daddr}, {sort: {clnum: 1}, limit:10});
    } else {
      return false;
    }
  });
}


