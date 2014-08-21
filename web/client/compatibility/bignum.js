function fhex(a) {
  throw ("DANGER, fhex is a bad function");
  return parseInt(a, 16);
}

function hex2(a) {
  if (a == undefined) return "__";
  var ret = a.toString(16);
  if (ret.length == 1) return "0" + ret;
  return ret;
}

function _fhex(a) {
  //p("DANGER, fhex is a bad function");
  return parseInt(a, 16);
}

// this is safe to use on forknums and clnums
function fdec(a) {
  return parseInt(a, 10);
}

function hex(a) {
  if (a == undefined) {
    return "";
  } else {
    if (a < 0) a += 0x100000000;
    return "0x"+a.toString(16);
  }
}


// s is a hex number
// num is the number of digits to round off
function bn_round(s, num) {
  if ((s.length-2) <= num) {
    ret = "0x0";
  } else {
    var ret = s.substring(0, s.length-num);
    for (var i = 0; i < num; i++) {
      ret += "0";
    }
  }
  return ret;
}

function bn_mod(s, cnt) {
  s = s.substr(2);
  return _fhex("0x"+s.substr(Math.max(0, s.length-cnt)));
}

// who the hell knows if this works?
function bn_add(s, num) {
  s = s.substr(2);
  if (s.length <= 8) { return hex(_fhex(s)+num); }
  else { 
    var ts = _fhex("0x"+s.substr(0,s.length-8));
    var ls = _fhex("0x"+s.substr(s.length-8));
    ls += num;
    ts += (ls/0x100000000) >> 0;
    ls &= 0xFFFFFFFF;
    ret = hex(ls).substr(2);
    while (ret.length != 8) ret = "0" + ret;
    return hex(ts)+ret;
  }
}

function bn_cmp(a, b) {
  if (a.length != b.length) return a.length-b.length;
  var aa = _fhex(a.substring(0,8));
  var bb = _fhex(b.substring(0,8));
  if (aa != bb) return aa-bb;
  aa = _fhex("0x"+a.substring(8));
  bb = _fhex("0x"+b.substring(8));
  return aa-bb;
}

// should also make lowercase
function bn_canonicalize(s) {
  s = s.substr(2);
  while (s.substr(0,1) == '0') s = s.substr(1);
  return "0x"+s;
}

