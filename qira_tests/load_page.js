var page = require('webpage').create();
page.settings.javascriptEnabled = true;

page.onConsoleMessage = function(msg) {
  console.log(msg);
};

page.open('http://localhost:3002/', function() {
  var title = page.evaluate(function() { return document.title; });
  if (title !== "qira") {
    console.log("BAD TITLE");
    phantom.exit(-1);
  }
  else
    console.log("Sorry");
  phantom.exit();
});


