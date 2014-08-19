var current_hash = "";

// put the defaults here
Session.setDefault('pending', []);

// there should be a library for this
Deps.autorun(function() { DA("update window.location.hash for history");
  var json = {};
  // only those should be tracked in the history
  // TODO: use the proper history API
  // this is bad, scrolling will pwn the history
  // refactor required
  json['cview'] = Session.get('cview');
  json['dview'] = Session.get('dview');
  json['clnum'] = Session.get('clnum');
  json['daddr'] = Session.get('daddr');
  /*json['forknum'] = Session.get('forknum');
  json['iaddr'] = Session.get('iaddr');
  json['max_clnum'] = Session.get('max_clnum');*/
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

