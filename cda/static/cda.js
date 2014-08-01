// connect to the QIRA stream
stream = io.connect("http://localhost:3002/cda");

stream.on('setline', function(filename, line) {
  //p('setline');
  var b64xref = location.hash.split(",")[1];
  if (b64xref === undefined) b64xref = "";
  else b64xref = ","+b64xref;

  //location.replace("/f?"+filename+"#"+line+b64xref);
  session[0] = filename;
  session[1] = line;
});

function p(s) {
  console.log(s);
}

var highlighted = $();

// ugh hacks
var sline = undefined;
var sfile = undefined;
var sb64xref = undefined;

function refresh() {
  if (location.hash == "") {
    $.ajax("/list").done(function(a) {
      $('#program')[0].innerHTML = a;
    });
    sfile = undefined;
    sline = undefined;
    return;
  }

  //p(location.hash);

  var file = location.hash.substr(1).split(",")[0];
  var ln = location.hash.split(",")[1];
  var b64xref = location.hash.split(",")[2];

  if (sfile !== file) {
    $.ajax("/f?"+file).done(function(a) {
      $('#program')[0].innerHTML = a;
      sfile = file;
      sline = undefined;
      refresh();
    });
  }
  if (sline != parseInt(ln)) {
    highlighted.removeClass("line_highlighted")
    highlighted = $("#l" + ln)
    if (highlighted.length > 0) {
      highlighted.addClass("line_highlighted");
      $('#program').scrollTo(highlighted, {offset: -150})
      stream.emit('navigateline', sfile, parseInt(ln))
      sline = parseInt(ln);
    }
  }
  if (b64xref !== undefined && b64xref !== "" && b64xref != sb64xref) {
    selected.removeClass('highlighted');
    selected = $(document.getElementsByName(atob(b64xref)));
    selected.addClass('highlighted');
    $.ajax("/x/"+b64xref).done(function(a) {
      //p(a);
      $('#xrefs')[0].innerHTML = a;
      sb64xref = b64xref;
    });
  }
}

// all of the session is stored in the hash

var session = [];
var selected = $();

// 0 = filename
// 1 = linenumber
// 2 = xref
for (var i = 0; i < 3; i++) {
  session.__defineSetter__(i, function(val) {
    var tmp = location.hash.substr(1).split(",");
    if (this == 0 && val.indexOf("#") != -1) {
      tmp[0] = val.split("#")[0];
      tmp[1] = val.split("#")[1];
    } else {
      tmp[this] = val;
    }
    if (this == 2) {
      location.replace("#"+tmp.join(","));
    } else {
      // for back and forward
      location = "#"+tmp.join(",");
    }
  }.bind(i));
}

function link_click_handler(e) {
  var usr = e.target.getAttribute('name');
  session[2] = btoa(usr);
}

function link_dblclick_handler(e) {
  var targets = e.target.getAttribute('targets').split(" ");
  var usr = e.target.getAttribute('name');
  session[0] = targets[0];
}

function go_to_line(line) {
  session[1] = line;
}

window.onmousedown = function() { return false; };

// when the page loads we need to check the hash
window.onload = function() {
  $('#program').on('click', '.link', link_click_handler);
  $('#program').on('dblclick', '.link', link_dblclick_handler);
  $(window).on('hashchange', refresh);
  refresh();
};

