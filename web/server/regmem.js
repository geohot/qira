stream = new Meteor.Stream('regmem');

// these must be kept sorted
var regs = [];
var mem = [];

var fs = Npm.require('fs');

// eww javascript classes

function map_create(dic) {
  var ret = {};
  for (j in dic) {
    var map = [];
    for (i in dic[j]) {
      map.push([i, dic[j][i]]);
    }
    map.sort(function(a, b) { return a[0]-b[0]; })
    ret[j] = map;
  }
  return ret;
}

function map_getbelow(map, a) {
  if (map == undefined) return undefined;
  // real binary search from real algorithm class
  var b = 0;
  var e = map.length-1;
  var best = undefined;
  while (b <= e) {
    var mid = (b+e)>>1;
    // do we include the current change?
    if (map[mid][0] <= a) {
      b = mid+1;
      best = mid;
    } else {
      e = mid-1;
    }
  }
  if (best == undefined) {
    return undefined;
  } else {
    //console.log("search for "+a+" found "+map[best][0]);
    return map[best][1];
  }
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
  var ret = [];
  for (var i = 0; i < X86REGS.length; i++) {
    var val = map_getbelow(regs[i*4], clnum)
    if (val !== undefined) {
      ret.push({"name": X86REGS[i], "value": val});
    }
  }
  stream.emit("registers", ret);
});

stream.on('getmemory', function(msg) {
  var ret = {}
  for (var i = msg['address']; i < msg['address'] + msg['len']; i++) {
    var val = map_getbelow(mem[i], msg['clnum']);
    if (val !== undefined) {
      ret[i] = val;
    }
  }
  var rret = {'address': msg['address'], 'len': msg['len'], 'dat': ret};
  stream.emit("memory", rret);
});

