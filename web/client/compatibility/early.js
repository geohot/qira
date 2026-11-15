function p(a) { console.log(a); }
//function DA(a) { p("DA: "+a); }
//function DS(a) { p("DS: "+a); }
//function DH(a) { p("DH: "+a); }
function DA(a) {}
function DS(a) {}
function DH(a) {}

STREAM_URL = window.location.origin+"/qira";

// One socket for all client modules. socket.io 1.x returned the same (multiplexed) socket for
// every io.connect(STREAM_URL); socket.io 4 opens a new connection per call, so the replies to
// one module's requests would arrive on another module's socket. The modules use this global.
stream = io.connect(STREAM_URL);

