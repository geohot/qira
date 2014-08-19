var PAGE_SIZE = 0x1000;

Deps.autorun(function() { DA("pmaps changed, updating haddrline");
  var pmaps = Session.get('pmaps');
  if (pmaps === undefined) return;
  //p(pmaps);
  // eww, numbers. broken for 64-bit
  var addrs = Object.keys(pmaps).map(fhex).sort(function(a, b){return a-b});
  //p(addrs);
  // fill in the holes up to 16 pages
  var pchunks = [];
  for (var i = 0; i < addrs.length;) {
    var pchunk = [];
    var caddr = addrs[i];
    pchunk.push(caddr);
    i++;
    while ((addrs[i]-caddr) < PAGE_SIZE*8) {
      for (var j = caddr+PAGE_SIZE; j <= addrs[i]; j += PAGE_SIZE) {
        pchunk.push(j);
      }
      caddr = addrs[i];
      i++;
    }
    pchunks.push(pchunk);
  }
  //p(pchunks);
  $('#haddrline').empty();
  for (var i = 0; i < pchunks.length; i++) {
    var pcs = $('<div class="pchunks"></div>')
    for (var j = 0; j < pchunks[i].length; j++) {
      var addr = pchunks[i][j];
      pcs.append($('<div class="pchunk pchunk'+pmaps[hex(addr)]+'" id="pchunk_'+hex(addr)+'"></div>'));
    }
    $('#haddrline').append(pcs);
  }
});

draw_hflag = function(addr, name, color, alwaysontop) {
  $("#hflag_"+name).remove();
  var t = $("#pchunk_"+string_round(addr, 3));
  if (t.length == 1) {
    //p("drawing hflag");
    var hflag = $('<div class="hflag" id="hflag_'+name+'"></div>');
    if (alwaysontop) {
      hflag.css("z-index", 2);
      hflag.css("opacity", "0.8");
    } else {
      hflag.css("opacity", "0.4");
    }
    hflag.css("background-color", color);
    // pchunk.width = 15
    // hflag.width = 1
    var off = ((((fhex(addr)%PAGE_SIZE)*1.0)/PAGE_SIZE) * 15) - (1/2.0);
    hflag.css("left", off+"px");
    t.append(hflag);
  }
};

Deps.autorun(function() { DA("draw haddrline iaddr flag");
  var addr = Session.get('iaddr');
  if (addr === undefined) return;
  draw_hflag(addr, 'iaddr', '#AA0000', true);
});

Deps.autorun(function() { DA("draw haddrline daddr flag");
  var addr = Session.get('daddr');
  if (addr === undefined) return;
  draw_hflag(addr, 'daddr', 'yellow', true);
});

$(document).ready(function() {
  var ee = $("#haddrline")[0];
  ee.addEventListener("mousewheel", function(e) {
    ee.scrollLeft += e.wheelDelta;
  });
  function get_addr(e) {
    var tt = [$(e.target), $(e.target).parent()];
    for (i in tt) {
      var t = tt[i];
      if (t.hasClass("pchunk")) {
        var addr = fhex(t.attr('id').split("_")[1]);
        var relX = ((e.pageX - t.offset().left)*1.0)/(t.width());
        addr += Math.floor(relX*PAGE_SIZE);
        return addr
      }
    }
    return undefined;
  }

  ee.addEventListener("click", function(e) {
    var addr = get_addr(e);
    if (addr !== undefined) {
      update_dview(hex(addr));
    }
    return false;
  });
  ee.addEventListener("contextmenu", function(e) {
    var addr = get_addr(e);
    if (addr !== undefined) {
      Session.set("dirtyiaddr", true);
      Session.set('iaddr', hex(addr));
    }
    e.preventDefault();
    return false;
  });
});


