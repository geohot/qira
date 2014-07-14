//////////////////////////////////////////////////////////////////////////
//                                                                      //
// This is a generated file. You can view the original                  //
// source in your browser if your browser supports source maps.         //
//                                                                      //
// If you are using Chrome, open the Developer Tools and click the gear //
// icon in its lower right corner. In the General Settings panel, turn  //
// on 'Enable source maps'.                                             //
//                                                                      //
// If you are using Firefox 23, go to `about:config` and set the        //
// `devtools.debugger.source-maps-enabled` preference to true.          //
// (The preference should be on by default in Firefox 24; versions      //
// older than 23 do not support source maps.)                           //
//                                                                      //
//////////////////////////////////////////////////////////////////////////


(function () {

/* Imports */
var _ = Package.underscore._;

/* Package-scope variables */
var Meteor;

(function () {

//////////////////////////////////////////////////////////////////////////////////////////////////////
//                                                                                                  //
// packages/meteor/client_environment.js                                                            //
//                                                                                                  //
//////////////////////////////////////////////////////////////////////////////////////////////////////
                                                                                                    //
Meteor = {                                                                                          // 1
  isClient: true,                                                                                   // 2
  isServer: false                                                                                   // 3
};                                                                                                  // 4
                                                                                                    // 5
if (typeof __meteor_runtime_config__ === 'object' &&                                                // 6
    __meteor_runtime_config__.PUBLIC_SETTINGS) {                                                    // 7
  Meteor.settings = { 'public': __meteor_runtime_config__.PUBLIC_SETTINGS };                        // 8
}                                                                                                   // 9
                                                                                                    // 10
//////////////////////////////////////////////////////////////////////////////////////////////////////

}).call(this);






(function () {

//////////////////////////////////////////////////////////////////////////////////////////////////////
//                                                                                                  //
// packages/meteor/helpers.js                                                                       //
//                                                                                                  //
//////////////////////////////////////////////////////////////////////////////////////////////////////
                                                                                                    //
if (Meteor.isServer)                                                                                // 1
  var Future = Npm.require('fibers/future');                                                        // 2
                                                                                                    // 3
if (typeof __meteor_runtime_config__ === 'object' &&                                                // 4
    __meteor_runtime_config__.meteorRelease)                                                        // 5
  Meteor.release = __meteor_runtime_config__.meteorRelease;                                         // 6
                                                                                                    // 7
// XXX find a better home for these? Ideally they would be _.get,                                   // 8
// _.ensure, _.delete..                                                                             // 9
                                                                                                    // 10
_.extend(Meteor, {                                                                                  // 11
  // _get(a,b,c,d) returns a[b][c][d], or else undefined if a[b] or                                 // 12
  // a[b][c] doesn't exist.                                                                         // 13
  //                                                                                                // 14
  _get: function (obj /*, arguments */) {                                                           // 15
    for (var i = 1; i < arguments.length; i++) {                                                    // 16
      if (!(arguments[i] in obj))                                                                   // 17
        return undefined;                                                                           // 18
      obj = obj[arguments[i]];                                                                      // 19
    }                                                                                               // 20
    return obj;                                                                                     // 21
  },                                                                                                // 22
                                                                                                    // 23
  // _ensure(a,b,c,d) ensures that a[b][c][d] exists. If it does not,                               // 24
  // it is created and set to {}. Either way, it is returned.                                       // 25
  //                                                                                                // 26
  _ensure: function (obj /*, arguments */) {                                                        // 27
    for (var i = 1; i < arguments.length; i++) {                                                    // 28
      var key = arguments[i];                                                                       // 29
      if (!(key in obj))                                                                            // 30
        obj[key] = {};                                                                              // 31
      obj = obj[key];                                                                               // 32
    }                                                                                               // 33
                                                                                                    // 34
    return obj;                                                                                     // 35
  },                                                                                                // 36
                                                                                                    // 37
  // _delete(a, b, c, d) deletes a[b][c][d], then a[b][c] unless it                                 // 38
  // isn't empty, then a[b] unless it isn't empty.                                                  // 39
  //                                                                                                // 40
  _delete: function (obj /*, arguments */) {                                                        // 41
    var stack = [obj];                                                                              // 42
    var leaf = true;                                                                                // 43
    for (var i = 1; i < arguments.length - 1; i++) {                                                // 44
      var key = arguments[i];                                                                       // 45
      if (!(key in obj)) {                                                                          // 46
        leaf = false;                                                                               // 47
        break;                                                                                      // 48
      }                                                                                             // 49
      obj = obj[key];                                                                               // 50
      if (typeof obj !== "object")                                                                  // 51
        break;                                                                                      // 52
      stack.push(obj);                                                                              // 53
    }                                                                                               // 54
                                                                                                    // 55
    for (var i = stack.length - 1; i >= 0; i--) {                                                   // 56
      var key = arguments[i+1];                                                                     // 57
                                                                                                    // 58
      if (leaf)                                                                                     // 59
        leaf = false;                                                                               // 60
      else                                                                                          // 61
        for (var other in stack[i][key])                                                            // 62
          return; // not empty -- we're done                                                        // 63
                                                                                                    // 64
      delete stack[i][key];                                                                         // 65
    }                                                                                               // 66
  },                                                                                                // 67
                                                                                                    // 68
  // _wrapAsync can wrap any function that takes some number of arguments that                      // 69
  // can't be undefined, followed by some optional arguments, where the callback                    // 70
  // is the last optional argument.                                                                 // 71
  // e.g. fs.readFile(pathname, [callback]),                                                        // 72
  // fs.open(pathname, flags, [mode], [callback])                                                   // 73
  // For maximum effectiveness and least confusion, wrapAsync should be used on                     // 74
  // functions where the callback is the only argument of type Function.                            // 75
  //                                                                                                // 76
  _wrapAsync: function (fn) {                                                                       // 77
    return function (/* arguments */) {                                                             // 78
      var self = this;                                                                              // 79
      var callback;                                                                                 // 80
      var fut;                                                                                      // 81
      var newArgs = _.toArray(arguments);                                                           // 82
                                                                                                    // 83
      var logErr = function (err) {                                                                 // 84
        if (err)                                                                                    // 85
          return Meteor._debug("Exception in callback of async function",                           // 86
                               err.stack ? err.stack : err);                                        // 87
      };                                                                                            // 88
                                                                                                    // 89
      // Pop off optional args that are undefined                                                   // 90
      while (newArgs.length > 0 &&                                                                  // 91
             typeof(newArgs[newArgs.length - 1]) === "undefined") {                                 // 92
        newArgs.pop();                                                                              // 93
      }                                                                                             // 94
      // If we have any left and the last one is a function, then that's our                        // 95
      // callback; otherwise, we don't have one.                                                    // 96
      if (newArgs.length > 0 &&                                                                     // 97
          newArgs[newArgs.length - 1] instanceof Function) {                                        // 98
        callback = newArgs.pop();                                                                   // 99
      } else {                                                                                      // 100
        if (Meteor.isClient) {                                                                      // 101
          callback = logErr;                                                                        // 102
        } else {                                                                                    // 103
          fut = new Future();                                                                       // 104
          callback = fut.resolver();                                                                // 105
        }                                                                                           // 106
      }                                                                                             // 107
      newArgs.push(Meteor.bindEnvironment(callback));                                               // 108
      var result = fn.apply(self, newArgs);                                                         // 109
      if (fut)                                                                                      // 110
        return fut.wait();                                                                          // 111
      return result;                                                                                // 112
    };                                                                                              // 113
  },                                                                                                // 114
                                                                                                    // 115
  // Sets child's prototype to a new object whose prototype is parent's                             // 116
  // prototype. Used as:                                                                            // 117
  //   Meteor._inherits(ClassB, ClassA).                                                            // 118
  //   _.extend(ClassB.prototype, { ... })                                                          // 119
  // Inspired by CoffeeScript's `extend` and Google Closure's `goog.inherits`.                      // 120
  _inherits: function (Child, Parent) {                                                             // 121
    // copy static fields                                                                           // 122
    _.each(Parent, function (prop, field) {                                                         // 123
      Child[field] = prop;                                                                          // 124
    });                                                                                             // 125
                                                                                                    // 126
    // a middle member of prototype chain: takes the prototype from the Parent                      // 127
    var Middle = function () {                                                                      // 128
      this.constructor = Child;                                                                     // 129
    };                                                                                              // 130
    Middle.prototype = Parent.prototype;                                                            // 131
    Child.prototype = new Middle();                                                                 // 132
    Child.__super__ = Parent.prototype;                                                             // 133
    return Child;                                                                                   // 134
  }                                                                                                 // 135
});                                                                                                 // 136
                                                                                                    // 137
//////////////////////////////////////////////////////////////////////////////////////////////////////

}).call(this);






(function () {

//////////////////////////////////////////////////////////////////////////////////////////////////////
//                                                                                                  //
// packages/meteor/setimmediate.js                                                                  //
//                                                                                                  //
//////////////////////////////////////////////////////////////////////////////////////////////////////
                                                                                                    //
// Chooses one of three setImmediate implementations:                                               // 1
//                                                                                                  // 2
// * Native setImmediate (IE 10, Node 0.9+)                                                         // 3
//                                                                                                  // 4
// * postMessage (many browsers)                                                                    // 5
//                                                                                                  // 6
// * setTimeout  (fallback)                                                                         // 7
//                                                                                                  // 8
// The postMessage implementation is based on                                                       // 9
// https://github.com/NobleJS/setImmediate/tree/1.0.1                                               // 10
//                                                                                                  // 11
// Don't use `nextTick` for Node since it runs its callbacks before                                 // 12
// I/O, which is stricter than we're looking for.                                                   // 13
//                                                                                                  // 14
// Not installed as a polyfill, as our public API is `Meteor.defer`.                                // 15
// Since we're not trying to be a polyfill, we have some                                            // 16
// simplifications:                                                                                 // 17
//                                                                                                  // 18
// If one invocation of a setImmediate callback pauses itself by a                                  // 19
// call to alert/prompt/showModelDialog, the NobleJS polyfill                                       // 20
// implementation ensured that no setImmedate callback would run until                              // 21
// the first invocation completed.  While correct per the spec, what it                             // 22
// would mean for us in practice is that any reactive updates relying                               // 23
// on Meteor.defer would be hung in the main window until the modal                                 // 24
// dialog was dismissed.  Thus we only ensure that a setImmediate                                   // 25
// function is called in a later event loop.                                                        // 26
//                                                                                                  // 27
// We don't need to support using a string to be eval'ed for the                                    // 28
// callback, arguments to the function, or clearImmediate.                                          // 29
                                                                                                    // 30
"use strict";                                                                                       // 31
                                                                                                    // 32
var global = this;                                                                                  // 33
                                                                                                    // 34
                                                                                                    // 35
// IE 10, Node >= 9.1                                                                               // 36
                                                                                                    // 37
function useSetImmediate() {                                                                        // 38
  if (! global.setImmediate)                                                                        // 39
    return null;                                                                                    // 40
  else {                                                                                            // 41
    var setImmediate = function (fn) {                                                              // 42
      global.setImmediate(fn);                                                                      // 43
    };                                                                                              // 44
    setImmediate.implementation = 'setImmediate';                                                   // 45
    return setImmediate;                                                                            // 46
  }                                                                                                 // 47
}                                                                                                   // 48
                                                                                                    // 49
                                                                                                    // 50
// Android 2.3.6, Chrome 26, Firefox 20, IE 8-9, iOS 5.1.1 Safari                                   // 51
                                                                                                    // 52
function usePostMessage() {                                                                         // 53
  // The test against `importScripts` prevents this implementation                                  // 54
  // from being installed inside a web worker, where                                                // 55
  // `global.postMessage` means something completely different and                                  // 56
  // can't be used for this purpose.                                                                // 57
                                                                                                    // 58
  if (!global.postMessage || global.importScripts) {                                                // 59
    return null;                                                                                    // 60
  }                                                                                                 // 61
                                                                                                    // 62
  // Avoid synchronous post message implementations.                                                // 63
                                                                                                    // 64
  var postMessageIsAsynchronous = true;                                                             // 65
  var oldOnMessage = global.onmessage;                                                              // 66
  global.onmessage = function () {                                                                  // 67
      postMessageIsAsynchronous = false;                                                            // 68
  };                                                                                                // 69
  global.postMessage("", "*");                                                                      // 70
  global.onmessage = oldOnMessage;                                                                  // 71
                                                                                                    // 72
  if (! postMessageIsAsynchronous)                                                                  // 73
    return null;                                                                                    // 74
                                                                                                    // 75
  var funcIndex = 0;                                                                                // 76
  var funcs = {};                                                                                   // 77
                                                                                                    // 78
  // Installs an event handler on `global` for the `message` event: see                             // 79
  // * https://developer.mozilla.org/en/DOM/window.postMessage                                      // 80
  // * http://www.whatwg.org/specs/web-apps/current-work/multipage/comms.html#crossDocumentMessages // 81
                                                                                                    // 82
  // XXX use Random.id() here?                                                                      // 83
  var MESSAGE_PREFIX = "Meteor._setImmediate." + Math.random() + '.';                               // 84
                                                                                                    // 85
  function isStringAndStartsWith(string, putativeStart) {                                           // 86
    return (typeof string === "string" &&                                                           // 87
            string.substring(0, putativeStart.length) === putativeStart);                           // 88
  }                                                                                                 // 89
                                                                                                    // 90
  function onGlobalMessage(event) {                                                                 // 91
    // This will catch all incoming messages (even from other                                       // 92
    // windows!), so we need to try reasonably hard to avoid letting                                // 93
    // anyone else trick us into firing off. We test the origin is                                  // 94
    // still this window, and that a (randomly generated)                                           // 95
    // unpredictable identifying prefix is present.                                                 // 96
    if (event.source === global &&                                                                  // 97
        isStringAndStartsWith(event.data, MESSAGE_PREFIX)) {                                        // 98
      var index = event.data.substring(MESSAGE_PREFIX.length);                                      // 99
      try {                                                                                         // 100
        if (funcs[index])                                                                           // 101
          funcs[index]();                                                                           // 102
      }                                                                                             // 103
      finally {                                                                                     // 104
        delete funcs[index];                                                                        // 105
      }                                                                                             // 106
    }                                                                                               // 107
  }                                                                                                 // 108
                                                                                                    // 109
  if (global.addEventListener) {                                                                    // 110
    global.addEventListener("message", onGlobalMessage, false);                                     // 111
  } else {                                                                                          // 112
    global.attachEvent("onmessage", onGlobalMessage);                                               // 113
  }                                                                                                 // 114
                                                                                                    // 115
  var setImmediate = function (fn) {                                                                // 116
    // Make `global` post a message to itself with the handle and                                   // 117
    // identifying prefix, thus asynchronously invoking our                                         // 118
    // onGlobalMessage listener above.                                                              // 119
    ++funcIndex;                                                                                    // 120
    funcs[funcIndex] = fn;                                                                          // 121
    global.postMessage(MESSAGE_PREFIX + funcIndex, "*");                                            // 122
  };                                                                                                // 123
  setImmediate.implementation = 'postMessage';                                                      // 124
  return setImmediate;                                                                              // 125
}                                                                                                   // 126
                                                                                                    // 127
                                                                                                    // 128
function useTimeout() {                                                                             // 129
  var setImmediate = function (fn) {                                                                // 130
    global.setTimeout(fn, 0);                                                                       // 131
  };                                                                                                // 132
  setImmediate.implementation = 'setTimeout';                                                       // 133
  return setImmediate;                                                                              // 134
}                                                                                                   // 135
                                                                                                    // 136
                                                                                                    // 137
Meteor._setImmediate =                                                                              // 138
  useSetImmediate() ||                                                                              // 139
  usePostMessage() ||                                                                               // 140
  useTimeout();                                                                                     // 141
                                                                                                    // 142
//////////////////////////////////////////////////////////////////////////////////////////////////////

}).call(this);






(function () {

//////////////////////////////////////////////////////////////////////////////////////////////////////
//                                                                                                  //
// packages/meteor/timers.js                                                                        //
//                                                                                                  //
//////////////////////////////////////////////////////////////////////////////////////////////////////
                                                                                                    //
var withoutInvocation = function (f) {                                                              // 1
  if (Package.livedata) {                                                                           // 2
    var _CurrentInvocation = Package.livedata.DDP._CurrentInvocation;                               // 3
    if (_CurrentInvocation.get() && _CurrentInvocation.get().isSimulation)                          // 4
      throw new Error("Can't set timers inside simulations");                                       // 5
    return function () { _CurrentInvocation.withValue(null, f); };                                  // 6
  }                                                                                                 // 7
  else                                                                                              // 8
    return f;                                                                                       // 9
};                                                                                                  // 10
                                                                                                    // 11
var bindAndCatch = function (context, f) {                                                          // 12
  return Meteor.bindEnvironment(withoutInvocation(f), context);                                     // 13
};                                                                                                  // 14
                                                                                                    // 15
_.extend(Meteor, {                                                                                  // 16
  // Meteor.setTimeout and Meteor.setInterval callbacks scheduled                                   // 17
  // inside a server method are not part of the method invocation and                               // 18
  // should clear out the CurrentInvocation environment variable.                                   // 19
                                                                                                    // 20
  setTimeout: function (f, duration) {                                                              // 21
    return setTimeout(bindAndCatch("setTimeout callback", f), duration);                            // 22
  },                                                                                                // 23
                                                                                                    // 24
  setInterval: function (f, duration) {                                                             // 25
    return setInterval(bindAndCatch("setInterval callback", f), duration);                          // 26
  },                                                                                                // 27
                                                                                                    // 28
  clearInterval: function(x) {                                                                      // 29
    return clearInterval(x);                                                                        // 30
  },                                                                                                // 31
                                                                                                    // 32
  clearTimeout: function(x) {                                                                       // 33
    return clearTimeout(x);                                                                         // 34
  },                                                                                                // 35
                                                                                                    // 36
  // XXX consider making this guarantee ordering of defer'd callbacks, like                         // 37
  // Deps.afterFlush or Node's nextTick (in practice). Then tests can do:                           // 38
  //    callSomethingThatDefersSomeWork();                                                          // 39
  //    Meteor.defer(expect(somethingThatValidatesThatTheWorkHappened));                            // 40
  defer: function (f) {                                                                             // 41
    Meteor._setImmediate(bindAndCatch("defer callback", f));                                        // 42
  }                                                                                                 // 43
});                                                                                                 // 44
                                                                                                    // 45
//////////////////////////////////////////////////////////////////////////////////////////////////////

}).call(this);






(function () {

//////////////////////////////////////////////////////////////////////////////////////////////////////
//                                                                                                  //
// packages/meteor/errors.js                                                                        //
//                                                                                                  //
//////////////////////////////////////////////////////////////////////////////////////////////////////
                                                                                                    //
// Makes an error subclass which properly contains a stack trace in most                            // 1
// environments. constructor can set fields on `this` (and should probably set                      // 2
// `message`, which is what gets displayed at the top of a stack trace).                            // 3
//                                                                                                  // 4
Meteor.makeErrorType = function (name, constructor) {                                               // 5
  var errorClass = function (/*arguments*/) {                                                       // 6
    var self = this;                                                                                // 7
                                                                                                    // 8
    // Ensure we get a proper stack trace in most Javascript environments                           // 9
    if (Error.captureStackTrace) {                                                                  // 10
      // V8 environments (Chrome and Node.js)                                                       // 11
      Error.captureStackTrace(self, errorClass);                                                    // 12
    } else {                                                                                        // 13
      // Firefox                                                                                    // 14
      var e = new Error;                                                                            // 15
      e.__proto__ = errorClass.prototype;                                                           // 16
      if (e instanceof errorClass)                                                                  // 17
        self = e;                                                                                   // 18
    }                                                                                               // 19
    // Safari magically works.                                                                      // 20
                                                                                                    // 21
    constructor.apply(self, arguments);                                                             // 22
                                                                                                    // 23
    self.errorType = name;                                                                          // 24
                                                                                                    // 25
    return self;                                                                                    // 26
  };                                                                                                // 27
                                                                                                    // 28
  Meteor._inherits(errorClass, Error);                                                              // 29
                                                                                                    // 30
  return errorClass;                                                                                // 31
};                                                                                                  // 32
                                                                                                    // 33
// This should probably be in the livedata package, but we don't want                               // 34
// to require you to use the livedata package to get it. Eventually we                              // 35
// should probably rename it to DDP.Error and put it back in the                                    // 36
// 'livedata' package (which we should rename to 'ddp' also.)                                       // 37
//                                                                                                  // 38
// Note: The DDP server assumes that Meteor.Error EJSON-serializes as an object                     // 39
// containing 'error' and optionally 'reason' and 'details'.                                        // 40
// The DDP client manually puts these into Meteor.Error objects. (We don't use                      // 41
// EJSON.addType here because the type is determined by location in the                             // 42
// protocol, not text on the wire.)                                                                 // 43
//                                                                                                  // 44
Meteor.Error = Meteor.makeErrorType(                                                                // 45
  "Meteor.Error",                                                                                   // 46
  function (error, reason, details) {                                                               // 47
    var self = this;                                                                                // 48
                                                                                                    // 49
    // Currently, a numeric code, likely similar to a HTTP code (eg,                                // 50
    // 404, 500). That is likely to change though.                                                  // 51
    self.error = error;                                                                             // 52
                                                                                                    // 53
    // Optional: A short human-readable summary of the error. Not                                   // 54
    // intended to be shown to end users, just developers. ("Not Found",                            // 55
    // "Internal Server Error")                                                                     // 56
    self.reason = reason;                                                                           // 57
                                                                                                    // 58
    // Optional: Additional information about the error, say for                                    // 59
    // debugging. It might be a (textual) stack trace if the server is                              // 60
    // willing to provide one. The corresponding thing in HTTP would be                             // 61
    // the body of a 404 or 500 response. (The difference is that we                                // 62
    // never expect this to be shown to end users, only developers, so                              // 63
    // it doesn't need to be pretty.)                                                               // 64
    self.details = details;                                                                         // 65
                                                                                                    // 66
    // This is what gets displayed at the top of a stack trace. Current                             // 67
    // format is "[404]" (if no reason is set) or "File not found [404]"                            // 68
    if (self.reason)                                                                                // 69
      self.message = self.reason + ' [' + self.error + ']';                                         // 70
    else                                                                                            // 71
      self.message = '[' + self.error + ']';                                                        // 72
  });                                                                                               // 73
                                                                                                    // 74
// Meteor.Error is basically data and is sent over DDP, so you should be able to                    // 75
// properly EJSON-clone it. This is especially important because if a                               // 76
// Meteor.Error is thrown through a Future, the error, reason, and details                          // 77
// properties become non-enumerable so a standard Object clone won't preserve                       // 78
// them and they will be lost from DDP.                                                             // 79
Meteor.Error.prototype.clone = function () {                                                        // 80
  var self = this;                                                                                  // 81
  return new Meteor.Error(self.error, self.reason, self.details);                                   // 82
};                                                                                                  // 83
                                                                                                    // 84
//////////////////////////////////////////////////////////////////////////////////////////////////////

}).call(this);






(function () {

//////////////////////////////////////////////////////////////////////////////////////////////////////
//                                                                                                  //
// packages/meteor/fiber_stubs_client.js                                                            //
//                                                                                                  //
//////////////////////////////////////////////////////////////////////////////////////////////////////
                                                                                                    //
// This file is a partial analogue to fiber_helpers.js, which allows the client                     // 1
// to use a queue too, and also to call noYieldsAllowed.                                            // 2
                                                                                                    // 3
// The client has no ability to yield, so noYieldsAllowed is a noop.                                // 4
//                                                                                                  // 5
Meteor._noYieldsAllowed = function (f) {                                                            // 6
  return f();                                                                                       // 7
};                                                                                                  // 8
                                                                                                    // 9
// An even simpler queue of tasks than the fiber-enabled one.  This one just                        // 10
// runs all the tasks when you call runTask or flush, synchronously.                                // 11
//                                                                                                  // 12
Meteor._SynchronousQueue = function () {                                                            // 13
  var self = this;                                                                                  // 14
  self._tasks = [];                                                                                 // 15
  self._running = false;                                                                            // 16
};                                                                                                  // 17
                                                                                                    // 18
_.extend(Meteor._SynchronousQueue.prototype, {                                                      // 19
  runTask: function (task) {                                                                        // 20
    var self = this;                                                                                // 21
    if (!self.safeToRunTask())                                                                      // 22
      throw new Error("Could not synchronously run a task from a running task");                    // 23
    self._tasks.push(task);                                                                         // 24
    var tasks = self._tasks;                                                                        // 25
    self._tasks = [];                                                                               // 26
    self._running = true;                                                                           // 27
    try {                                                                                           // 28
      while (!_.isEmpty(tasks)) {                                                                   // 29
        var t = tasks.shift();                                                                      // 30
        try {                                                                                       // 31
          t();                                                                                      // 32
        } catch (e) {                                                                               // 33
          if (_.isEmpty(tasks)) {                                                                   // 34
            // this was the last task, that is, the one we're calling runTask                       // 35
            // for.                                                                                 // 36
            throw e;                                                                                // 37
          } else {                                                                                  // 38
            Meteor._debug("Exception in queued task: " + e.stack);                                  // 39
          }                                                                                         // 40
        }                                                                                           // 41
      }                                                                                             // 42
    } finally {                                                                                     // 43
      self._running = false;                                                                        // 44
    }                                                                                               // 45
  },                                                                                                // 46
                                                                                                    // 47
  queueTask: function (task) {                                                                      // 48
    var self = this;                                                                                // 49
    var wasEmpty = _.isEmpty(self._tasks);                                                          // 50
    self._tasks.push(task);                                                                         // 51
    // Intentionally not using Meteor.setTimeout, because it doesn't like runing                    // 52
    // in stubs for now.                                                                            // 53
    if (wasEmpty)                                                                                   // 54
      setTimeout(_.bind(self.flush, self), 0);                                                      // 55
  },                                                                                                // 56
                                                                                                    // 57
  flush: function () {                                                                              // 58
    var self = this;                                                                                // 59
    self.runTask(function () {});                                                                   // 60
  },                                                                                                // 61
                                                                                                    // 62
  drain: function () {                                                                              // 63
    var self = this;                                                                                // 64
    if (!self.safeToRunTask())                                                                      // 65
      return;                                                                                       // 66
    while (!_.isEmpty(self._tasks)) {                                                               // 67
      self.flush();                                                                                 // 68
    }                                                                                               // 69
  },                                                                                                // 70
                                                                                                    // 71
  safeToRunTask: function () {                                                                      // 72
    var self = this;                                                                                // 73
    return !self._running;                                                                          // 74
  }                                                                                                 // 75
});                                                                                                 // 76
                                                                                                    // 77
//////////////////////////////////////////////////////////////////////////////////////////////////////

}).call(this);






(function () {

//////////////////////////////////////////////////////////////////////////////////////////////////////
//                                                                                                  //
// packages/meteor/startup_client.js                                                                //
//                                                                                                  //
//////////////////////////////////////////////////////////////////////////////////////////////////////
                                                                                                    //
var queue = [];                                                                                     // 1
var loaded = document.readyState === "loaded" ||                                                    // 2
  document.readyState == "complete";                                                                // 3
                                                                                                    // 4
var ready = function() {                                                                            // 5
  loaded = true;                                                                                    // 6
  while (queue.length)                                                                              // 7
    (queue.shift())();                                                                              // 8
};                                                                                                  // 9
                                                                                                    // 10
if (document.addEventListener) {                                                                    // 11
  document.addEventListener('DOMContentLoaded', ready, false);                                      // 12
  window.addEventListener('load', ready, false);                                                    // 13
} else {                                                                                            // 14
  document.attachEvent('onreadystatechange', function () {                                          // 15
    if (document.readyState === "complete")                                                         // 16
      ready();                                                                                      // 17
  });                                                                                               // 18
  window.attachEvent('load', ready);                                                                // 19
}                                                                                                   // 20
                                                                                                    // 21
Meteor.startup = function (cb) {                                                                    // 22
  var doScroll = !document.addEventListener &&                                                      // 23
    document.documentElement.doScroll;                                                              // 24
                                                                                                    // 25
  if (!doScroll || window !== top) {                                                                // 26
    if (loaded)                                                                                     // 27
      cb();                                                                                         // 28
    else                                                                                            // 29
      queue.push(cb);                                                                               // 30
  } else {                                                                                          // 31
    try { doScroll('left'); }                                                                       // 32
    catch (e) {                                                                                     // 33
      setTimeout(function() { Meteor.startup(cb); }, 50);                                           // 34
      return;                                                                                       // 35
    };                                                                                              // 36
    cb();                                                                                           // 37
  }                                                                                                 // 38
};                                                                                                  // 39
                                                                                                    // 40
//////////////////////////////////////////////////////////////////////////////////////////////////////

}).call(this);






(function () {

//////////////////////////////////////////////////////////////////////////////////////////////////////
//                                                                                                  //
// packages/meteor/debug.js                                                                         //
//                                                                                                  //
//////////////////////////////////////////////////////////////////////////////////////////////////////
                                                                                                    //
var suppress = 0;                                                                                   // 1
                                                                                                    // 2
// replacement for console.log. This is a temporary API. We should                                  // 3
// provide a real logging API soon (possibly just a polyfill for                                    // 4
// console?)                                                                                        // 5
//                                                                                                  // 6
// NOTE: this is used on the server to print the warning about                                      // 7
// having autopublish enabled when you probably meant to turn it                                    // 8
// off. it's not really the proper use of something called                                          // 9
// _debug. the intent is for this message to go to the terminal and                                 // 10
// be very visible. if you change _debug to go someplace else, etc,                                 // 11
// please fix the autopublish code to do something reasonable.                                      // 12
//                                                                                                  // 13
Meteor._debug = function (/* arguments */) {                                                        // 14
  if (suppress) {                                                                                   // 15
    suppress--;                                                                                     // 16
    return;                                                                                         // 17
  }                                                                                                 // 18
  if (typeof console !== 'undefined' &&                                                             // 19
      typeof console.log !== 'undefined') {                                                         // 20
    if (arguments.length == 0) { // IE Companion breaks otherwise                                   // 21
      // IE10 PP4 requires at least one argument                                                    // 22
      console.log('');                                                                              // 23
    } else {                                                                                        // 24
      // IE doesn't have console.log.apply, it's not a real Object.                                 // 25
      // http://stackoverflow.com/questions/5538972/console-log-apply-not-working-in-ie9            // 26
      // http://patik.com/blog/complete-cross-browser-console-log/                                  // 27
      if (typeof console.log.apply === "function") {                                                // 28
        // Most browsers                                                                            // 29
                                                                                                    // 30
        // Chrome and Safari only hyperlink URLs to source files in first argument of               // 31
        // console.log, so try to call it with one argument if possible.                            // 32
        // Approach taken here: If all arguments are strings, join them on space.                   // 33
        // See https://github.com/meteor/meteor/pull/732#issuecomment-13975991                      // 34
        var allArgumentsOfTypeString = true;                                                        // 35
        for (var i = 0; i < arguments.length; i++)                                                  // 36
          if (typeof arguments[i] !== "string")                                                     // 37
            allArgumentsOfTypeString = false;                                                       // 38
                                                                                                    // 39
        if (allArgumentsOfTypeString)                                                               // 40
          console.log.apply(console, [Array.prototype.join.call(arguments, " ")]);                  // 41
        else                                                                                        // 42
          console.log.apply(console, arguments);                                                    // 43
                                                                                                    // 44
      } else if (typeof Function.prototype.bind === "function") {                                   // 45
        // IE9                                                                                      // 46
        var log = Function.prototype.bind.call(console.log, console);                               // 47
        log.apply(console, arguments);                                                              // 48
      } else {                                                                                      // 49
        // IE8                                                                                      // 50
        Function.prototype.call.call(console.log, console, Array.prototype.slice.call(arguments));  // 51
      }                                                                                             // 52
    }                                                                                               // 53
  }                                                                                                 // 54
};                                                                                                  // 55
                                                                                                    // 56
// Suppress the next 'count' Meteor._debug messsages. Use this to                                   // 57
// stop tests from spamming the console.                                                            // 58
//                                                                                                  // 59
Meteor._suppress_log = function (count) {                                                           // 60
  suppress += count;                                                                                // 61
};                                                                                                  // 62
                                                                                                    // 63
//////////////////////////////////////////////////////////////////////////////////////////////////////

}).call(this);






(function () {

//////////////////////////////////////////////////////////////////////////////////////////////////////
//                                                                                                  //
// packages/meteor/dynamics_browser.js                                                              //
//                                                                                                  //
//////////////////////////////////////////////////////////////////////////////////////////////////////
                                                                                                    //
// Simple implementation of dynamic scoping, for use in browsers                                    // 1
                                                                                                    // 2
var nextSlot = 0;                                                                                   // 3
var currentValues = [];                                                                             // 4
                                                                                                    // 5
Meteor.EnvironmentVariable = function () {                                                          // 6
  this.slot = nextSlot++;                                                                           // 7
};                                                                                                  // 8
                                                                                                    // 9
_.extend(Meteor.EnvironmentVariable.prototype, {                                                    // 10
  get: function () {                                                                                // 11
    return currentValues[this.slot];                                                                // 12
  },                                                                                                // 13
                                                                                                    // 14
  getOrNullIfOutsideFiber: function () {                                                            // 15
    return this.get();                                                                              // 16
  },                                                                                                // 17
                                                                                                    // 18
  withValue: function (value, func) {                                                               // 19
    var saved = currentValues[this.slot];                                                           // 20
    try {                                                                                           // 21
      currentValues[this.slot] = value;                                                             // 22
      var ret = func();                                                                             // 23
    } finally {                                                                                     // 24
      currentValues[this.slot] = saved;                                                             // 25
    }                                                                                               // 26
    return ret;                                                                                     // 27
  }                                                                                                 // 28
});                                                                                                 // 29
                                                                                                    // 30
Meteor.bindEnvironment = function (func, onException, _this) {                                      // 31
  // needed in order to be able to create closures inside func and                                  // 32
  // have the closed variables not change back to their original                                    // 33
  // values                                                                                         // 34
  var boundValues = _.clone(currentValues);                                                         // 35
                                                                                                    // 36
  if (!onException || typeof(onException) === 'string') {                                           // 37
    var description = onException || "callback of async function";                                  // 38
    onException = function (error) {                                                                // 39
      Meteor._debug(                                                                                // 40
        "Exception in " + description + ":",                                                        // 41
        error && error.stack || error                                                               // 42
      );                                                                                            // 43
    };                                                                                              // 44
  }                                                                                                 // 45
                                                                                                    // 46
  return function (/* arguments */) {                                                               // 47
    var savedValues = currentValues;                                                                // 48
    try {                                                                                           // 49
      currentValues = boundValues;                                                                  // 50
      var ret = func.apply(_this, _.toArray(arguments));                                            // 51
    } catch (e) {                                                                                   // 52
      // note: callback-hook currently relies on the fact that if onException                       // 53
      // throws in the browser, the wrapped call throws.                                            // 54
      onException(e);                                                                               // 55
    } finally {                                                                                     // 56
      currentValues = savedValues;                                                                  // 57
    }                                                                                               // 58
    return ret;                                                                                     // 59
  };                                                                                                // 60
};                                                                                                  // 61
                                                                                                    // 62
Meteor._nodeCodeMustBeInFiber = function () {                                                       // 63
  // no-op on browser                                                                               // 64
};                                                                                                  // 65
                                                                                                    // 66
//////////////////////////////////////////////////////////////////////////////////////////////////////

}).call(this);






(function () {

//////////////////////////////////////////////////////////////////////////////////////////////////////
//                                                                                                  //
// packages/meteor/url_common.js                                                                    //
//                                                                                                  //
//////////////////////////////////////////////////////////////////////////////////////////////////////
                                                                                                    //
Meteor.absoluteUrl = function (path, options) {                                                     // 1
  // path is optional                                                                               // 2
  if (!options && typeof path === 'object') {                                                       // 3
    options = path;                                                                                 // 4
    path = undefined;                                                                               // 5
  }                                                                                                 // 6
  // merge options with defaults                                                                    // 7
  options = _.extend({}, Meteor.absoluteUrl.defaultOptions, options || {});                         // 8
                                                                                                    // 9
  var url = options.rootUrl;                                                                        // 10
  if (!url)                                                                                         // 11
    throw new Error("Must pass options.rootUrl or set ROOT_URL in the server environment");         // 12
                                                                                                    // 13
  if (!/^http[s]?:\/\//i.test(url)) // url starts with 'http://' or 'https://'                      // 14
    url = 'http://' + url; // we will later fix to https if options.secure is set                   // 15
                                                                                                    // 16
  if (!/\/$/.test(url)) // url ends with '/'                                                        // 17
    url += '/';                                                                                     // 18
                                                                                                    // 19
  if (path)                                                                                         // 20
    url += path;                                                                                    // 21
                                                                                                    // 22
  // turn http to https if secure option is set, and we're not talking                              // 23
  // to localhost.                                                                                  // 24
  if (options.secure &&                                                                             // 25
      /^http:/.test(url) && // url starts with 'http:'                                              // 26
      !/http:\/\/localhost[:\/]/.test(url) && // doesn't match localhost                            // 27
      !/http:\/\/127\.0\.0\.1[:\/]/.test(url)) // or 127.0.0.1                                      // 28
    url = url.replace(/^http:/, 'https:');                                                          // 29
                                                                                                    // 30
  if (options.replaceLocalhost)                                                                     // 31
    url = url.replace(/^http:\/\/localhost([:\/].*)/, 'http://127.0.0.1$1');                        // 32
                                                                                                    // 33
  return url;                                                                                       // 34
};                                                                                                  // 35
                                                                                                    // 36
// allow later packages to override default options                                                 // 37
Meteor.absoluteUrl.defaultOptions = { };                                                            // 38
if (typeof __meteor_runtime_config__ === "object" &&                                                // 39
    __meteor_runtime_config__.ROOT_URL)                                                             // 40
  Meteor.absoluteUrl.defaultOptions.rootUrl = __meteor_runtime_config__.ROOT_URL;                   // 41
                                                                                                    // 42
                                                                                                    // 43
Meteor._relativeToSiteRootUrl = function (link) {                                                   // 44
  if (typeof __meteor_runtime_config__ === "object" &&                                              // 45
      link.substr(0, 1) === "/")                                                                    // 46
    link = (__meteor_runtime_config__.ROOT_URL_PATH_PREFIX || "") + link;                           // 47
  return link;                                                                                      // 48
};                                                                                                  // 49
                                                                                                    // 50
//////////////////////////////////////////////////////////////////////////////////////////////////////

}).call(this);


/* Exports */
if (typeof Package === 'undefined') Package = {};
Package.meteor = {
  Meteor: Meteor
};

})();

//# sourceMappingURL=439f867e12888606900664d4463e1b3ee3644e44.map
