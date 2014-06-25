Change = new Meteor.Collection("change");
Blocks = new Meteor.Collection("blocks");
Loops = new Meteor.Collection("loops");
Fxns = new Meteor.Collection("fxns");
Program = new Meteor.Collection("program");

Meteor.startup(function () {
});

Meteor.publish('max_clnum', function() {
  // extract 'clnum' from this to get the max clnum
  return Change.find({}, {sort: {clnum: -1}, limit: 1});
});

Meteor.publish('dat_clnum', function(clnum){
  // can only return as many as in the changelist
  return Change.find({clnum: clnum}, {sort: {address: 1}, limit:20});
});

Meteor.publish('instruction_iaddr', function(iaddr){
  // this doesn't work...
  //return Program.find({address: {$gt: iaddr-0x100, $lt: iaddr+0x100}}, {sort: {address:1}});
});

Meteor.publish('instructions', function(clnum, collapsed) {
  var BEFORE = clnum-0x10;
  var and = [{clend: {$gt: BEFORE}}];
  for (var i = 0; i < collapsed.length; i++) {
    and.push({$or: [{clstart: {$lt: collapsed[i][0]}}, {clend: {$gt: collapsed[i][1]}}]});
  }

  //return Change.find({clnum: {$gt: clnum-0x10, $lt: clnum+0x18}, type: "I"}, {sort: {clnum:1}});
  var cblocks = Blocks.find({$and: and}, {limit: 20});
  //cblocks.forEach(function(post) { console.log(post); });

  // build the changelist fetching query from the blocks
  var query = [];
  var lquery = [];
  var fquery = [];
  cblocks.forEach(function(post) { 
    lquery.push({blockstart: post.blockidx});
    query.push({clnum: {$gte: post.clstart, $lte: post.clend}})
    fquery.push({clstart: {$gte: post.clstart}, clend: {$lte: post.clend}})
  });
  if (query.length == 0) { console.log("cl query failed"); return; }

  // limit here should be the onscreen blocks
  var changes = Change.find({$or: query, type: "I"}, {sort: {clnum: 1}, limit: 0x50});
  var loops = Loops.find({$or: lquery});
  //var fxns = Fxns.find({$or: fquery});
  var fxns = Fxns.find(); // bad

  // build the address fetching query from the changelists
  var query = [];
  changes.forEach(function(post) { query.push({address: post.address}); });
  if (query.length == 0) { console.log("ins query failed"); return; }
  var progdat = Program.find({$or: query});
  // we need to send the program data back here as well...
  return [changes, cblocks, progdat, loops, fxns];
});

Meteor.publish('dat_iaddr', function(iaddr){
  // fetch the static info about the range
  return Change.find({address: iaddr, type: "I"}, {sort: {clnum: 1}, limit:10})
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

Meteor.publish('hexedit_daddr', function(daddr, clnum) {
  return Change.find({address:daddr, clnum:{$lte: clnum}}, {sort: {clnum: -1}, limit:1});
});

