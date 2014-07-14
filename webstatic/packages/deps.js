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
var Meteor = Package.meteor.Meteor;

/* Package-scope variables */
var Deps;

(function () {

//////////////////////////////////////////////////////////////////////////////////
//                                                                              //
// packages/deps/deps.js                                                        //
//                                                                              //
//////////////////////////////////////////////////////////////////////////////////
                                                                                //
//////////////////////////////////////////////////                              // 1
// Package docs at http://docs.meteor.com/#deps //                              // 2
//////////////////////////////////////////////////                              // 3
                                                                                // 4
Deps = {};                                                                      // 5
                                                                                // 6
// http://docs.meteor.com/#deps_active                                          // 7
Deps.active = false;                                                            // 8
                                                                                // 9
// http://docs.meteor.com/#deps_currentcomputation                              // 10
Deps.currentComputation = null;                                                 // 11
                                                                                // 12
var setCurrentComputation = function (c) {                                      // 13
  Deps.currentComputation = c;                                                  // 14
  Deps.active = !! c;                                                           // 15
};                                                                              // 16
                                                                                // 17
// _assign is like _.extend or the upcoming Object.assign.                      // 18
// Copy src's own, enumerable properties onto tgt and return                    // 19
// tgt.                                                                         // 20
var _hasOwnProperty = Object.prototype.hasOwnProperty;                          // 21
var _assign = function (tgt, src) {                                             // 22
  for (var k in src) {                                                          // 23
    if (_hasOwnProperty.call(src, k))                                           // 24
      tgt[k] = src[k];                                                          // 25
  }                                                                             // 26
  return tgt;                                                                   // 27
};                                                                              // 28
                                                                                // 29
var _debugFunc = function () {                                                  // 30
  // lazy evaluation because `Meteor` does not exist right away                 // 31
  return (typeof Meteor !== "undefined" ? Meteor._debug :                       // 32
          ((typeof console !== "undefined") && console.log ?                    // 33
           function () { console.log.apply(console, arguments); } :             // 34
           function () {}));                                                    // 35
};                                                                              // 36
                                                                                // 37
var _throwOrLog = function (from, e) {                                          // 38
  if (throwFirstError) {                                                        // 39
    throw e;                                                                    // 40
  } else {                                                                      // 41
    _debugFunc()("Exception from Deps " + from + " function:",                  // 42
                 e.stack || e.message);                                         // 43
  }                                                                             // 44
};                                                                              // 45
                                                                                // 46
// Takes a function `f`, and wraps it in a `Meteor._noYieldsAllowed`            // 47
// block if we are running on the server. On the client, returns the            // 48
// original function (since `Meteor._noYieldsAllowed` is a                      // 49
// no-op). This has the benefit of not adding an unnecessary stack              // 50
// frame on the client.                                                         // 51
var withNoYieldsAllowed = function (f) {                                        // 52
  if ((typeof Meteor === 'undefined') || Meteor.isClient) {                     // 53
    return f;                                                                   // 54
  } else {                                                                      // 55
    return function () {                                                        // 56
      var args = arguments;                                                     // 57
      Meteor._noYieldsAllowed(function () {                                     // 58
        f.apply(null, args);                                                    // 59
      });                                                                       // 60
    };                                                                          // 61
  }                                                                             // 62
};                                                                              // 63
                                                                                // 64
var nextId = 1;                                                                 // 65
// computations whose callbacks we should call at flush time                    // 66
var pendingComputations = [];                                                   // 67
// `true` if a Deps.flush is scheduled, or if we are in Deps.flush now          // 68
var willFlush = false;                                                          // 69
// `true` if we are in Deps.flush now                                           // 70
var inFlush = false;                                                            // 71
// `true` if we are computing a computation now, either first time              // 72
// or recompute.  This matches Deps.active unless we are inside                 // 73
// Deps.nonreactive, which nullfies currentComputation even though              // 74
// an enclosing computation may still be running.                               // 75
var inCompute = false;                                                          // 76
// `true` if the `_throwFirstError` option was passed in to the call            // 77
// to Deps.flush that we are in. When set, throw rather than log the            // 78
// first error encountered while flushing. Before throwing the error,           // 79
// finish flushing (from a finally block), logging any subsequent               // 80
// errors.                                                                      // 81
var throwFirstError = false;                                                    // 82
                                                                                // 83
var afterFlushCallbacks = [];                                                   // 84
                                                                                // 85
var requireFlush = function () {                                                // 86
  if (! willFlush) {                                                            // 87
    setTimeout(Deps.flush, 0);                                                  // 88
    willFlush = true;                                                           // 89
  }                                                                             // 90
};                                                                              // 91
                                                                                // 92
// Deps.Computation constructor is visible but private                          // 93
// (throws an error if you try to call it)                                      // 94
var constructingComputation = false;                                            // 95
                                                                                // 96
//                                                                              // 97
// http://docs.meteor.com/#deps_computation                                     // 98
//                                                                              // 99
Deps.Computation = function (f, parent) {                                       // 100
  if (! constructingComputation)                                                // 101
    throw new Error(                                                            // 102
      "Deps.Computation constructor is private; use Deps.autorun");             // 103
  constructingComputation = false;                                              // 104
                                                                                // 105
  var self = this;                                                              // 106
                                                                                // 107
  // http://docs.meteor.com/#computation_stopped                                // 108
  self.stopped = false;                                                         // 109
                                                                                // 110
  // http://docs.meteor.com/#computation_invalidated                            // 111
  self.invalidated = false;                                                     // 112
                                                                                // 113
  // http://docs.meteor.com/#computation_firstrun                               // 114
  self.firstRun = true;                                                         // 115
                                                                                // 116
  self._id = nextId++;                                                          // 117
  self._onInvalidateCallbacks = [];                                             // 118
  // the plan is at some point to use the parent relation                       // 119
  // to constrain the order that computations are processed                     // 120
  self._parent = parent;                                                        // 121
  self._func = f;                                                               // 122
  self._recomputing = false;                                                    // 123
                                                                                // 124
  var errored = true;                                                           // 125
  try {                                                                         // 126
    self._compute();                                                            // 127
    errored = false;                                                            // 128
  } finally {                                                                   // 129
    self.firstRun = false;                                                      // 130
    if (errored)                                                                // 131
      self.stop();                                                              // 132
  }                                                                             // 133
};                                                                              // 134
                                                                                // 135
_assign(Deps.Computation.prototype, {                                           // 136
                                                                                // 137
  // http://docs.meteor.com/#computation_oninvalidate                           // 138
  onInvalidate: function (f) {                                                  // 139
    var self = this;                                                            // 140
                                                                                // 141
    if (typeof f !== 'function')                                                // 142
      throw new Error("onInvalidate requires a function");                      // 143
                                                                                // 144
    if (self.invalidated) {                                                     // 145
      Deps.nonreactive(function () {                                            // 146
        withNoYieldsAllowed(f)(self);                                           // 147
      });                                                                       // 148
    } else {                                                                    // 149
      self._onInvalidateCallbacks.push(f);                                      // 150
    }                                                                           // 151
  },                                                                            // 152
                                                                                // 153
  // http://docs.meteor.com/#computation_invalidate                             // 154
  invalidate: function () {                                                     // 155
    var self = this;                                                            // 156
    if (! self.invalidated) {                                                   // 157
      // if we're currently in _recompute(), don't enqueue                      // 158
      // ourselves, since we'll rerun immediately anyway.                       // 159
      if (! self._recomputing && ! self.stopped) {                              // 160
        requireFlush();                                                         // 161
        pendingComputations.push(this);                                         // 162
      }                                                                         // 163
                                                                                // 164
      self.invalidated = true;                                                  // 165
                                                                                // 166
      // callbacks can't add callbacks, because                                 // 167
      // self.invalidated === true.                                             // 168
      for(var i = 0, f; f = self._onInvalidateCallbacks[i]; i++) {              // 169
        Deps.nonreactive(function () {                                          // 170
          withNoYieldsAllowed(f)(self);                                         // 171
        });                                                                     // 172
      }                                                                         // 173
      self._onInvalidateCallbacks = [];                                         // 174
    }                                                                           // 175
  },                                                                            // 176
                                                                                // 177
  // http://docs.meteor.com/#computation_stop                                   // 178
  stop: function () {                                                           // 179
    if (! this.stopped) {                                                       // 180
      this.stopped = true;                                                      // 181
      this.invalidate();                                                        // 182
    }                                                                           // 183
  },                                                                            // 184
                                                                                // 185
  _compute: function () {                                                       // 186
    var self = this;                                                            // 187
    self.invalidated = false;                                                   // 188
                                                                                // 189
    var previous = Deps.currentComputation;                                     // 190
    setCurrentComputation(self);                                                // 191
    var previousInCompute = inCompute;                                          // 192
    inCompute = true;                                                           // 193
    try {                                                                       // 194
      withNoYieldsAllowed(self._func)(self);                                    // 195
    } finally {                                                                 // 196
      setCurrentComputation(previous);                                          // 197
      inCompute = false;                                                        // 198
    }                                                                           // 199
  },                                                                            // 200
                                                                                // 201
  _recompute: function () {                                                     // 202
    var self = this;                                                            // 203
                                                                                // 204
    self._recomputing = true;                                                   // 205
    try {                                                                       // 206
      while (self.invalidated && ! self.stopped) {                              // 207
        try {                                                                   // 208
          self._compute();                                                      // 209
        } catch (e) {                                                           // 210
          _throwOrLog("recompute", e);                                          // 211
        }                                                                       // 212
        // If _compute() invalidated us, we run again immediately.              // 213
        // A computation that invalidates itself indefinitely is an             // 214
        // infinite loop, of course.                                            // 215
        //                                                                      // 216
        // We could put an iteration counter here and catch run-away            // 217
        // loops.                                                               // 218
      }                                                                         // 219
    } finally {                                                                 // 220
      self._recomputing = false;                                                // 221
    }                                                                           // 222
  }                                                                             // 223
});                                                                             // 224
                                                                                // 225
//                                                                              // 226
// http://docs.meteor.com/#deps_dependency                                      // 227
//                                                                              // 228
Deps.Dependency = function () {                                                 // 229
  this._dependentsById = {};                                                    // 230
};                                                                              // 231
                                                                                // 232
_assign(Deps.Dependency.prototype, {                                            // 233
  // http://docs.meteor.com/#dependency_depend                                  // 234
  //                                                                            // 235
  // Adds `computation` to this set if it is not already                        // 236
  // present.  Returns true if `computation` is a new member of the set.        // 237
  // If no argument, defaults to currentComputation, or does nothing            // 238
  // if there is no currentComputation.                                         // 239
  depend: function (computation) {                                              // 240
    if (! computation) {                                                        // 241
      if (! Deps.active)                                                        // 242
        return false;                                                           // 243
                                                                                // 244
      computation = Deps.currentComputation;                                    // 245
    }                                                                           // 246
    var self = this;                                                            // 247
    var id = computation._id;                                                   // 248
    if (! (id in self._dependentsById)) {                                       // 249
      self._dependentsById[id] = computation;                                   // 250
      computation.onInvalidate(function () {                                    // 251
        delete self._dependentsById[id];                                        // 252
      });                                                                       // 253
      return true;                                                              // 254
    }                                                                           // 255
    return false;                                                               // 256
  },                                                                            // 257
                                                                                // 258
  // http://docs.meteor.com/#dependency_changed                                 // 259
  changed: function () {                                                        // 260
    var self = this;                                                            // 261
    for (var id in self._dependentsById)                                        // 262
      self._dependentsById[id].invalidate();                                    // 263
  },                                                                            // 264
                                                                                // 265
  // http://docs.meteor.com/#dependency_hasdependents                           // 266
  hasDependents: function () {                                                  // 267
    var self = this;                                                            // 268
    for(var id in self._dependentsById)                                         // 269
      return true;                                                              // 270
    return false;                                                               // 271
  }                                                                             // 272
});                                                                             // 273
                                                                                // 274
_assign(Deps, {                                                                 // 275
  // http://docs.meteor.com/#deps_flush                                         // 276
  flush: function (_opts) {                                                     // 277
    // XXX What part of the comment below is still true? (We no longer          // 278
    // have Spark)                                                              // 279
    //                                                                          // 280
    // Nested flush could plausibly happen if, say, a flush causes              // 281
    // DOM mutation, which causes a "blur" event, which runs an                 // 282
    // app event handler that calls Deps.flush.  At the moment                  // 283
    // Spark blocks event handlers during DOM mutation anyway,                  // 284
    // because the LiveRange tree isn't valid.  And we don't have               // 285
    // any useful notion of a nested flush.                                     // 286
    //                                                                          // 287
    // https://app.asana.com/0/159908330244/385138233856                        // 288
    if (inFlush)                                                                // 289
      throw new Error("Can't call Deps.flush while flushing");                  // 290
                                                                                // 291
    if (inCompute)                                                              // 292
      throw new Error("Can't flush inside Deps.autorun");                       // 293
                                                                                // 294
    inFlush = true;                                                             // 295
    willFlush = true;                                                           // 296
    throwFirstError = !! (_opts && _opts._throwFirstError);                     // 297
                                                                                // 298
    var finishedTry = false;                                                    // 299
    try {                                                                       // 300
      while (pendingComputations.length ||                                      // 301
             afterFlushCallbacks.length) {                                      // 302
                                                                                // 303
        // recompute all pending computations                                   // 304
        while (pendingComputations.length) {                                    // 305
          var comp = pendingComputations.shift();                               // 306
          comp._recompute();                                                    // 307
        }                                                                       // 308
                                                                                // 309
        if (afterFlushCallbacks.length) {                                       // 310
          // call one afterFlush callback, which may                            // 311
          // invalidate more computations                                       // 312
          var func = afterFlushCallbacks.shift();                               // 313
          try {                                                                 // 314
            func();                                                             // 315
          } catch (e) {                                                         // 316
            _throwOrLog("afterFlush function", e);                              // 317
          }                                                                     // 318
        }                                                                       // 319
      }                                                                         // 320
      finishedTry = true;                                                       // 321
    } finally {                                                                 // 322
      if (! finishedTry) {                                                      // 323
        // we're erroring                                                       // 324
        inFlush = false; // needed before calling `Deps.flush()` again          // 325
        Deps.flush({_throwFirstError: false}); // finish flushing               // 326
      }                                                                         // 327
      willFlush = false;                                                        // 328
      inFlush = false;                                                          // 329
    }                                                                           // 330
  },                                                                            // 331
                                                                                // 332
  // http://docs.meteor.com/#deps_autorun                                       // 333
  //                                                                            // 334
  // Run f(). Record its dependencies. Rerun it whenever the                    // 335
  // dependencies change.                                                       // 336
  //                                                                            // 337
  // Returns a new Computation, which is also passed to f.                      // 338
  //                                                                            // 339
  // Links the computation to the current computation                           // 340
  // so that it is stopped if the current computation is invalidated.           // 341
  autorun: function (f) {                                                       // 342
    if (typeof f !== 'function')                                                // 343
      throw new Error('Deps.autorun requires a function argument');             // 344
                                                                                // 345
    constructingComputation = true;                                             // 346
    var c = new Deps.Computation(f, Deps.currentComputation);                   // 347
                                                                                // 348
    if (Deps.active)                                                            // 349
      Deps.onInvalidate(function () {                                           // 350
        c.stop();                                                               // 351
      });                                                                       // 352
                                                                                // 353
    return c;                                                                   // 354
  },                                                                            // 355
                                                                                // 356
  // http://docs.meteor.com/#deps_nonreactive                                   // 357
  //                                                                            // 358
  // Run `f` with no current computation, returning the return value            // 359
  // of `f`.  Used to turn off reactivity for the duration of `f`,              // 360
  // so that reactive data sources accessed by `f` will not result in any       // 361
  // computations being invalidated.                                            // 362
  nonreactive: function (f) {                                                   // 363
    var previous = Deps.currentComputation;                                     // 364
    setCurrentComputation(null);                                                // 365
    try {                                                                       // 366
      return f();                                                               // 367
    } finally {                                                                 // 368
      setCurrentComputation(previous);                                          // 369
    }                                                                           // 370
  },                                                                            // 371
                                                                                // 372
  // http://docs.meteor.com/#deps_oninvalidate                                  // 373
  onInvalidate: function (f) {                                                  // 374
    if (! Deps.active)                                                          // 375
      throw new Error("Deps.onInvalidate requires a currentComputation");       // 376
                                                                                // 377
    Deps.currentComputation.onInvalidate(f);                                    // 378
  },                                                                            // 379
                                                                                // 380
  // http://docs.meteor.com/#deps_afterflush                                    // 381
  afterFlush: function (f) {                                                    // 382
    afterFlushCallbacks.push(f);                                                // 383
    requireFlush();                                                             // 384
  }                                                                             // 385
});                                                                             // 386
                                                                                // 387
//////////////////////////////////////////////////////////////////////////////////

}).call(this);






(function () {

//////////////////////////////////////////////////////////////////////////////////
//                                                                              //
// packages/deps/deprecated.js                                                  //
//                                                                              //
//////////////////////////////////////////////////////////////////////////////////
                                                                                //
// Deprecated (Deps-recated?) functions.                                        // 1
                                                                                // 2
// These functions used to be on the Meteor object (and worked slightly         // 3
// differently).                                                                // 4
// XXX COMPAT WITH 0.5.7                                                        // 5
Meteor.flush = Deps.flush;                                                      // 6
Meteor.autorun = Deps.autorun;                                                  // 7
                                                                                // 8
// We used to require a special "autosubscribe" call to reactively subscribe to // 9
// things. Now, it works with autorun.                                          // 10
// XXX COMPAT WITH 0.5.4                                                        // 11
Meteor.autosubscribe = Deps.autorun;                                            // 12
                                                                                // 13
// This Deps API briefly existed in 0.5.8 and 0.5.9                             // 14
// XXX COMPAT WITH 0.5.9                                                        // 15
Deps.depend = function (d) {                                                    // 16
  return d.depend();                                                            // 17
};                                                                              // 18
                                                                                // 19
//////////////////////////////////////////////////////////////////////////////////

}).call(this);


/* Exports */
if (typeof Package === 'undefined') Package = {};
Package.deps = {
  Deps: Deps
};

})();

//# sourceMappingURL=4a82362ae66e863a1c1a8b0a5fec6f665e2038d1.map
