// connect to the QIRA stream
stream = io.connect("http://localhost:3002/qira");

function p(s) {
  console.log(s);
}

var highlighted = $();

$(window).on('hashchange', function() {
  if (location.hash == "") location.replace("#0");
  var ln = location.hash.substr(1).split(",")[0];
  var b64xref = location.hash.split(",")[1];
  highlighted.removeClass("line_highlighted")
  highlighted = $("#l" + ln)
  if (highlighted.length > 0) {
    highlighted.addClass("line_highlighted");
    $(window).scrollTo(highlighted, {offset: -150})
    stream.emit('navigateline', $('#filename')[0].innerHTML, parseInt(ln))
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

var selected = $();

function link_click_handler(e) {
  var usr = e.target.getAttribute('name');
  location.replace(location.hash.split(",")[0]+","+btoa(usr));
}

function link_dblclick_handler(e) {
  var targets = e.target.getAttribute('targets').split(" ");
  p(targets);
  var usr = e.target.getAttribute('name');
  location = "/f?"+targets[0]+","+btoa(usr);
}

function go_to_line(line) {
  var b64xref = location.hash.split(",")[1];
  var newl = "#"+line;
  if (b64xref !== undefined) {
    newl += ","+b64xref;
  }
  location.replace(newl);
}

window.onmousedown = function() { return false; };

// when the page loads we need to check the hash
window.onload = function() {
  window.dispatchEvent(new HashChangeEvent("hashchange"))

  $('.link').bind('click', link_click_handler); 
  $('.link').bind('dblclick', link_dblclick_handler); 
};


