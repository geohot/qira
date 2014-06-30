
Meteor.startup(function() {
  Deps.autorun(function() {
    var max = Session.get("max_clnum");
    if (max === undefined) return;
    var working_height = $("#vtimeline").height();
    var scale = Math.ceil(max/working_height);
    Session.set("cview", [0, max, scale]);
  });
  $("#vtimeline").click(function(e) {
    if (e.target !== $("#vtimeline")[0]) return;
    var cview = Session.get("cview");
    Session.set("clnum", e.offsetY * cview[2]);
  });
});

function draw_flag(type, clnum) {
  var cview = Session.get("cview");
  if (cview == undefined) return;
  if (cview[0] > clnum || cview[1] < clnum) return;
  var already = $("#flag"+clnum);
  if (already.length > 0) {
    already.addClass("flag"+type);
  }
  var flag = $('<div id="flag'+clnum+'" class="flag flag'+type+'">'+clnum+'</div>');
  flag[0].style.marginTop = (clnum/cview[2]) + "px";
  flag.click(function() { Session.set("clnum", clnum); });
  $('#vtimeline').append(flag);
}

function remove_flags(type) {
  $(".flag"+type).remove();
}

Deps.autorun(function() {
  var clnum = Session.get("clnum");
  remove_flags("change");
  draw_flag("change", clnum);
});

Deps.autorun(function() {
  var clnum = Session.get("clnum");
  var iaddr = Session.get('iaddr');
  remove_flags("iaddr");
  Change.find({address: iaddr, type: "I"}).forEach(function(x) {
    if (x.clnum == clnum) return;
    draw_flag("iaddr", x.clnum);
  });
});

Deps.autorun(function() {
  var clnum = Session.get("clnum");
  var daddr = Session.get('daddr');
  remove_flags("daddrr");
  remove_flags("daddrw");
  //Change.find({address: daddr, $or: [{type: "L"}, {type: "S"}] }).forEach(function(x) {
  Change.find({address: daddr}).forEach(function(x) {
    if (x.clnum == clnum) return;
    if (x.type == "L") draw_flag("daddrr", x.clnum);
    if (x.type == "S") draw_flag("daddrw", x.clnum);
  });
});

