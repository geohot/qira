
Meteor.startup(function () {
});

Meteor.publish('max_clnum', function() {
  // extract 'clnum' from this to get the max clnum
  return Change.find({type: "I"}, {sort: {clnum: -1}, limit: 1});
});

Meteor.publish('pmaps', function() {
  return Pmaps.find();
});

Meteor.publish('dat_clnum', function(clnum) {
  // can only return as many as in the changelist
  return Change.find({clnum: clnum}, {sort: {address: 1}, limit:30});
});

Meteor.publish('instructions', function(clnum) {
  var changes = Change.find({clnum: {$gt: clnum-4, $lt: clnum+8}, type: "I"}, {sort: {clnum:1}});
  var query = [];
  changes.forEach(function(post) { query.push({address: post.address}); });
  if (query.length == 0) { console.log("ins query failed"); return; }
  var progdat = Program.find({$or: query});
  // we need to send the program data back here as well...
  return [changes, progdat];
});

Meteor.publish('dat_iaddr', function(iaddr) {
  // fetch the static info about the range
  return Change.find({address: iaddr, type: "I"}, {sort: {clnum: 1}, limit:30})
});

Meteor.publish('dat_daddr', function(daddr) {
  // fetch the dynamic info about the instruction range
  //return Change.find({address : {$gt: daddr-0x100, $lt: daddr+0x300}});
  if (daddr >= 0x1000) {
    return Change.find({address:daddr, $or: [{type: "L"}, {type: "S"}]}, {sort: {clnum: 1}, limit:30});
  } else {
    return false;
  }
});

