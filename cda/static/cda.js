// connect to the QIRA stream
stream = io.connect("http://localhost:3002/cda");

stream.on('setline', function(filename, line) {
  //p('setline');
  var b64xref = location.hash.split(",")[1];
  if (b64xref === undefined) b64xref = "";
  else b64xref = ","+b64xref;

  location.replace("/f?"+filename+"#"+line+b64xref);
});

function p(s) {
  console.log(s);
}

var highlighted = $();
var sline = undefined;

// all of the session is stored in the hash
$(window).on('hashchange', function() {
  if (location.hash == "") return;

  p(location.hash);

  var file = location.hash.substr(1).split(",")[0];
  var ln = location.hash.split(",")[1];
  var b64xref = location.hash.split(",")[2];

  if (sline != parseInt(ln)) {
    highlighted.removeClass("line_highlighted")
    highlighted = $("#l" + ln)
    highlighted.addClass("line_highlighted");
    $('#program').scrollTo(highlighted, {offset: -150})
    stream.emit('navigateline', $('#filename')[0].innerHTML, parseInt(ln))
    sline = parseInt(ln);
  }
  if (b64xref !== undefined) {
    selected.removeClass('highlighted');
    selected = $(document.getElementsByName(atob(b64xref)));
    selected.addClass('highlighted');
    if (frames[0].location.pathname != '/x/'+b64xref) {
      frames[0].location.replace('/x/'+b64xref);
    }
  }
});

var session = [];
var selected = $();

// 0 = filename
// 1 = linenumber
// 2 = xref
for (var i = 0; i < 3; i++) {
  session.__defineSetter__(i, function(val) {
    var tmp = location.hash.split(",");
    tmp[this] = val;
    location.replace(tmp.join(","));
  }.bind(i));
}

function link_click_handler(e) {
  var usr = e.target.getAttribute('name');
  session[2] = btoa(usr);
}

function link_dblclick_handler(e) {
  var targets = e.target.getAttribute('targets').split(" ");
  p(targets);
  var usr = e.target.getAttribute('name');
  // wrong
  session[0] = targets[0];
}

function go_to_line(line) {
  session[1] = line;
}

window.onmousedown = function() { return false; };

// when the page loads we need to check the hash
window.onload = function() {
  window.dispatchEvent(new HashChangeEvent("hashchange"))

  $('.link').bind('click', link_click_handler); 
  $('.link').bind('dblclick', link_dblclick_handler); 
};


