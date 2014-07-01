var current_hash = "";

// there should be a library for this
Deps.autorun(function() {
  var json = {};
  // for dep tracking, can't use keys
  json['max_clnum'] = Session.get('max_clnum');
  json['clnum'] = Session.get('clnum');
  json['iaddr'] = Session.get('iaddr');
  json['daddr'] = Session.get('daddr');
  json['dview'] = Session.get('dview');
  json['cview'] = Session.get('cview');
  var hash = JSON.stringify(json);
  current_hash = hash;
  //p("updating hash to "+hash);
  window.location.hash = hash;
});

function check_hash() {
  // this runs way too much
  var hash = window.location.hash.substring(1);
  if (hash == current_hash) return;
  if (hash.length == 0) return;
  p("onhashchange");
  var json = JSON.parse(hash);
  //p(json);
  for (k in json) {
    if (Session.get(k) != json[k]) { 
      Session.set(k, json[k]);
    }
  }
}

window.onload = check_hash;
window.onhashchange = check_hash;

Meteor.subscribe('max_clnum', {onReady: function() {
  post = Change.findOne({}, {sort: {clnum: -1}});

  Session.setDefault("clnum", post.clnum);
  Session.set("max_clnum", post.clnum);
}});

