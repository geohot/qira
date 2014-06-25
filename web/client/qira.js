Change = new Meteor.Collection("change");
Blocks = new Meteor.Collection("blocks");
Loops = new Meteor.Collection("loops");
Fxns = new Meteor.Collection("fxns");
Program = new Meteor.Collection("program");

// bitops make numbers negative

Meteor.startup(function () {
  Session.setDefault("collapsed", []);
});

window.onmousewheel = function(e) {
  if (e.target.id == "cfg" || $(e.target).parents("#cfg").length > 0) {
    if (e.wheelDelta < 0) {
      Session.set('clnum', Session.get('clnum')+1);
    } else if (e.wheelDelta > 0) {
      Session.set('clnum', Session.get('clnum')-1);
    }
  } else if (e.target.id == "hexdump" || $(e.target).parents("#hexdump").length > 0) {
    if (e.wheelDelta < 0) {
      Session.set('daddr', Session.get('daddr')+0x10);
    } else if (e.wheelDelta > 0) {
      Session.set('daddr', Session.get('daddr')-0x10);
    }
  }
};

// there should be a library for this
Deps.autorun(function() {
  var json = {};
  // for dep tracking, can't use keys
  json['max_clnum'] = Session.get('max_clnum');
  json['clnum'] = Session.get('clnum');
  json['iaddr'] = Session.get('iaddr');
  json['daddr'] = Session.get('daddr');
  json['collapsed'] = Session.get('collapsed');
  var hash = JSON.stringify(json);
  //p("updating hash to "+hash);
  window.location.hash = hash;
});

function check_hash() {
  p("onhashchange");
  var hash = window.location.hash.substring(1);
  if (hash.length == 0) return;
  var json = JSON.parse(hash);
  //p(json);
  for (k in json) {
    if (Session.get(k) != json[k]) { 
      Session.set(k, json[k]);
    }
  }
}

window.onload = check_hash;

// TODO: fix this to not snapback
//window.onhashchange = check_hash;

Deps.autorun(function() {
  var cl_selector = $('#cl_selector');
  var clnum = Session.get("clnum");
  var max_clnum = Session.get("max_clnum");
  if (cl_selector.length > 0) {
    cl_selector[0].value = clnum;
    cl_selector.slider('refresh');
  }
});

Meteor.subscribe('max_clnum', {onReady: function() {
  post = Change.findOne({}, {sort: {clnum: -1}});

  Session.setDefault("clnum", post.clnum);
  Session.set("max_clnum", post.clnum);

  var cl_selector = $('#cl_selector');
  cl_selector[0].max = post.clnum;
  cl_selector.on("change", function(e) {
    var val = parseInt($('#cl_selector')[0].value);
    Session.set('clnum', val);
  });
  cl_selector.slider('refresh');
}});

