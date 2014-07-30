// connect to the QIRA stream
stream = io.connect("http://localhost:3002/qira");

function p(s) {
  console.log(s);
}

var highlighted = $();

$(window).on('hashchange', function() {
  if (window.location.hash == "") return;
  var ln = window.location.hash.substr(1);
  highlighted.removeClass("line_highlighted")
  highlighted = $("#l" + ln)
  highlighted.addClass("line_highlighted");
  $(window).scrollTo(highlighted, {offset: -150})
  stream.emit('navigateline', $('#filename')[0].innerHTML, parseInt(ln))
});

var selected = $();

function link_click_handler(e) {
  //p(e.target.getAttribute('name'));
  selected.removeClass('highlighted');
  selected = $(document.getElementsByName(e.target.getAttribute('name')));
  selected.addClass('highlighted');
}

function link_dblclick_handler(e) {
  var targets = e.target.getAttribute('targets').split(" ");
  p(targets);
  parent.frames[0].location = "/f?"+targets[0];
}

function xref_handler(e) {
  var usr = e.target.getAttribute('name');
  p("xref "+usr);
  parent.frames[1].location = '/x/'+btoa(usr)
  return false;
}

// no selection
window.onmousedown = function() { return false; };

// when the page loads we need to check the hash
window.onload = function() {
  window.dispatchEvent(new HashChangeEvent("hashchange"))

  $('.link').bind('click', link_click_handler); 
  $('.link').bind('dblclick', link_dblclick_handler); 
  $('.link').bind('contextmenu', xref_handler); 
};



