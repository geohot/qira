function p(s) {
  console.log(s);
}

var highlighted = $();

$(window).on('hashchange', function() {
  if (window.location.hash == "") return;
  highlighted.removeClass("line_highlighted")
  highlighted = $("#l" + window.location.hash.substr(1))
  highlighted.addClass("line_highlighted");
  $(window).scrollTo(highlighted, {offset: -150})
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
  window.location = "/f?"+targets[0];
}

function xref_key_handler(e) {
  var usr = selected[0].getAttribute('name');
  window.open('/x/'+btoa(usr), "xrefs", "resizable=no,scrollbars=no,menubar=no,width=300,height=500,left=1000,top=50");
}

// no selection
window.onmousedown = function() { return false; };

// when the page loads we need to check the hash
window.onload = function() {
  window.dispatchEvent(new HashChangeEvent("hashchange"))

  $('.link').bind('click', link_click_handler); 
  $('.link').bind('dblclick', link_dblclick_handler); 

  xdiv = $('<div id="xref"></div>');
  $(document.body).prepend(xdiv);
  
  var keys = {88: xref_key_handler};
  document.onkeydown = function(e) {
    //p(e.which);
    if (keys[e.which] !== undefined) {
      keys[e.which](e);
    }
  };
};



