var current_hash = "";

// there should be a library for this
Deps.autorun(function() {
  var json = {};
  // for dep tracking, can't use keys
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

Meteor.subscribe('max_clnum');

Deps.autorun(function() {
  var post = Change.findOne({type: "I"}, {sort: {clnum: -1}, limit: 1});

  if (post !== undefined) {
    if (Session.get("max_clnum") == Session.get("clnum")) {
      // track the max changelist if you have it selected
      Session.set("clnum", post.clnum);
    } else {
      Session.setDefault("clnum", post.clnum);
    }
    Session.set("max_clnum", post.clnum);
  }
});

