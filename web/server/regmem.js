stream = new Meteor.Stream('regmem');

// these must be kept sorted
var regs = [];
var mem = [];

var fs = Npm.require('fs');

// eww javascript classes

function map_create(dic) {
  var map = [];
  for (i in dic) {
    map.push([i, dic[i]]);
  }
  map.sort(function(a, b) { return a[0]-b[0]; })
}

function map_getbelow(map, a) {
  // hacks
  if (map.length == 0) return 0;

  // real binary search from real algorithm class
  var b = 0;
  var e = map.length;
  while (b != e) {
    var mid = (b+e)>>1;
    if (a <= map[mid][0]) {
      e = mid;
    } else {
      b = mid+1;
    }
  }
  return map[b][1];
}

Meteor.startup(function () {
  fs.readFile("/tmp/qira_memdb", function(err, data) {
    if (err) throw err;
    console.log("read memdb");
    var dat = JSON.parse(data);
    regs = map_create(dat['regs']);
    mem = map_create(dat['mem']);
    console.log("parsed memdb");
  });
});

// shouldn't be here
var X86REGS = ['EAX', 'ECX', 'EDX', 'EBX', 'ESP', 'EBP', 'ESI', 'EDI', 'EIP'];
stream.on('getregisters', function(clnum) {
  /*ret = [];
  for (var i = 0; i < X86REGS.length; i++) {
    ret.push({"name": X86REGS, "value": map_getbelow(regs, i)});
  }
  stream.emit("registers", ret);*/
  stream.emit("registers", {});
});

