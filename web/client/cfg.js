function collapsedIndexOf(a, b) {
  var i;
  for (i=0;i<b.length;i++) if (b[i][0] == a[0] && b[i][1] == a[1]) break;
  if (i == b.length) return -1;
  return i;
}

Template.cfg.fxncollapse = function() {
  //p(this.clend);
  var tmp = Fxns.findOne({"clstart": this.clend+1});
  if (tmp) {
    var collapsed = Session.get("collapsed");

    if(collapsedIndexOf([tmp.clstart, tmp.clend], collapsed) != -1) {
      var tmp2 = Change.findOne({"clnum":tmp.clstart});
      var tmp3 = undefined;
      if (tmp2 !== undefined) {
        var tmp3 = Program.findOne({address: tmp2.address});
      }
      
      if (tmp3 !== undefined) {
        return "expand "+tmp3.name+" to "+(tmp.clend+1);
      } else {
        return "expand to "+(tmp.clend+1);
      }
    } else {
      return "collapse to "+(tmp.clend+1);
    }
  }
  return "";
}

Template.cfg.isloop = function() {
  var tmp = Loops.findOne({"blockstart": {$lte: this.blockidx}, "blockend": {$gte: this.blockidx}});
  if (tmp) {
    return "blockloop";
  }
  return "";
};

Template.cfg.loopcnt = function() {
  var tmp = Loops.findOne({"blockstart": {$lte: this.blockidx}, "blockend": {$gte: this.blockidx}});
  if (tmp) {
    return "run "+tmp.count+" times";
  }
  return "";
}

Template.cfg.isiaddr = function() {
  var iaddr = Session.get('iaddr');
  if (this.address == iaddr) return "highlight";
  else return "";
};

Template.cfg.ischange = function() {
  var clnum = Session.get('clnum');
  if (this.clnum == clnum) return "highlight";
  else return "";
};

Template.cfg.hexaddress = function() { return hex(this.address)+": "; };
Template.cfg.hexstart = function() { return hex(this.start); };
Template.cfg.hexend = function() { return hex(this.end); };

Template.cfg.program_instruction = function() {
  return Program.findOne({address: this.address});
};

Template.cfg.comment = function() {
  if (this.comment != undefined) {
    return " // "+this.comment;
  }
};

Template.cfg.instructions = function() {
  var changes = Change.find({clnum: {$gte: this.clstart, $lte: this.clend}, type: "I"}, {sort: {clnum: 1}});
  var query = [];
  return changes;
}

Template.cfg.ddepth = function() {
  return this.depth * 60;
};

Template.cfg.blocks = function() {
  var clnum = Session.get('clnum');
  var BEFORE = clnum-0x10;
  //var cblocks = Blocks.find({clend: {$gt: BEFORE}}, {sort: {clstart: 1}, limit: 20});
  var cblocks = Blocks.find({}, {sort: {clstart: 1}});
  return cblocks;
};

Template.cfg.lineardump = function() {
  //var iaddr = Session.get('iaddr');
  var clnum = Session.get('clnum');
  if (clnum !== undefined) {
    return Change.find({clnum: {$gt: clnum-0x10, $lt: clnum+0x18}, type: "I"}, {sort: {clnum:1}});
  }
};

Template.cfg.events({
  'click .address': function() {
    p("new iaddr from click is "+hex(this.address));
    Session.set('iaddr', this.address);
  },
  'click .change': function() {
    Session.set('clnum', this.clnum);
  },
  'click .collapse': function() {
    var tmp = Fxns.findOne({"clstart": this.clend+1});
    var newc = Session.get("collapsed");
    var nc = [tmp.clstart, tmp.clend];
    var i = collapsedIndexOf(nc, newc);
    if (i == -1) {
      newc.push(nc);
    } else {
      newc.splice(i, 1);
    }
    Session.set("collapsed", newc);
  }
});

Deps.autorun(function(){ Meteor.subscribe('instructions', Session.get("clnum"), Session.get("collapsed")); });
Meteor.subscribe('loops');
var fxn_sub = Meteor.subscribe('fxns', {onReady: function() {
  p("function ready");
  var tmp = Fxns.find();
  var newc = [];
  tmp.forEach(function(post) {
    newc.push([post.clstart, post.clend]);
  });
  Session.set("collapsed", newc);
}});


