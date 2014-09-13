var escapeHTML = (function () {
  'use strict';
  var chr = { '"': '&quot;', '&': '&amp;', '<': '&lt;', '>': '&gt;' };
  return function (text) {
    return text.replace(/[\"&<>]/g, function (a) { return chr[a]; });
  };
}());

function highlight_addresses(a) {
  return highlight_instruction(a, false);
}

function highlight_instruction(a, instruction) {
  if (a == undefined) return "undefined";
  if (instruction === undefined) instruction = true;
  var ret = escapeHTML(a);

  // dim colors
  function fc(a) {
    var df = 1.4;
    // heard of loops?
    var r = a.substr(1,2);
    var g = a.substr(3,2);
    var b = a.substr(5,2);
    r = Math.floor(parseInt(r, 16)/df);
    g = Math.floor(parseInt(g, 16)/df);
    b = Math.floor(parseInt(b, 16)/df);
    return "#"+hex2(r)+hex2(g)+hex2(b);
  }

  // highlight registers and addresses
  if (arch !== undefined) {
    var re = "(0x[0123456789abcdef]+)";
    var reps = {};
    if (instruction) {
      for (var i = 0; i < arch[0].length; i++) {
        var rep = '<span style="color: '+fc(regcolors[i])+'" class="data_'+hex(i*arch[1])+'">'+arch[0][i]+'</span>';
        reps[arch[0][i]] = rep;

        var rep = '<span style="color: '+fc(regcolors[i])+'" class="data_'+hex(i*arch[1])+'">'+arch[0][i].toLowerCase()+'</span>';
        reps[arch[0][i].toLowerCase()] = rep;
      }
      for (i in reps) {
        re += "|(" + i + ")";
      }
    }
    function dorep(a) {
      if (a.substr(0, 2) == "0x") {
        var cl = get_data_type(a);
        if (cl == "") {
          return "<span class='hexnumber'>"+a+"</span>";
        } else {
          cl += " addr addr_"+a;
          return "<span class='"+cl+"'>"+a+"</span>";
        }
      } else {
        return reps[a];
      }
    }
    ret = ret.replace(new RegExp(re, "g"), dorep);
  }

  // highlight opcode
  if (instruction) {
    var i = 0;
    for (i = 0; i < ret.length; i++) {
      if (ret[i] == ' ' || ret[i] == '\t') {
        break;
      }
    }
    ret = '<span class="op">' + ret.substr(0, i) + '</span>' + ret.substr(i)
  }
  return ret;
}

function rehighlight() {
  var clnum = Session.get("clnum");
  var iaddr = Session.get("iaddr");
  var daddr = Session.get("daddr");
  $(".autohighlight").removeClass("autohighlight");
  $(".autohighlighti").removeClass("autohighlighti");
  $(".clnum_"+clnum).addClass("autohighlight");
  $(".addr_"+iaddr).addClass("autohighlighti");
  $(".daddr_"+daddr).addClass("autohighlight");
  $(".data_"+daddr).addClass("autohighlight");
}

Deps.autorun(function() { DA("rehighlight");
  rehighlight();
});

stream = io.connect(STREAM_URL);

function get_address_from_class(t, type) {
  if (type === undefined) type = "addr";
  var l = t.className.split(" ").filter(function(x) { return x.substr(0,5) == type+"_"; });
  if (l.length != 1) return undefined;
  return l[0].split("_")[1].split(" ")[0];
}

var names_cache = {};

// sync for no blink!
function replace_names() {
  //return;
  var addrs = [];
  $(".addr").each(function() {
    var ret = get_address_from_class(this);
    if (names_cache[ret] !== undefined) {
      $(this).addClass("name");
      $(this).html(names_cache[ret]);
    }
    if (ret !== undefined) addrs.push(ret);
  });
  //stream.emit('gettagsa', addrs);

  function cb(tags) {
    //p(tags);
    for (var i=0;i<tags.length;i++) {
      names_cache[tags[i]['address']] = tags[i]['name'];
      $(".addr_"+tags[i]['address']).each(function() {
        if (tags[i]['name'] !== undefined) {
          $(this).addClass("name");
          $(this).html(tags[i]['name']);
        }
      });
    }
  }

  async_tags_request(addrs, cb);
}

