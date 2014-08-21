function fhex(a) {
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

function bn_add(s, num) {
  // still wrong for big numbers
  return hex(fhex(s)+num);
}

