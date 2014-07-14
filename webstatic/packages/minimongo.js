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
var _ = Package.underscore._;
var JSON = Package.json.JSON;
var EJSON = Package.ejson.EJSON;
var IdMap = Package['id-map'].IdMap;
var OrderedDict = Package['ordered-dict'].OrderedDict;
var Deps = Package.deps.Deps;
var Random = Package.random.Random;
var GeoJSON = Package['geojson-utils'].GeoJSON;

/* Package-scope variables */
var LocalCollection, Minimongo, MinimongoTest, MinimongoError, isArray, isPlainObject, isIndexable, isOperatorObject, isNumericKey, regexpElementMatcher, equalityElementMatcher, ELEMENT_OPERATORS, makeLookupFunction, expandArraysInBranches, projectionDetails, pathsToTree;

(function () {

////////////////////////////////////////////////////////////////////////////////////////////////////////
//                                                                                                    //
// packages/minimongo/minimongo.js                                                                    //
//                                                                                                    //
////////////////////////////////////////////////////////////////////////////////////////////////////////
                                                                                                      //
// XXX type checking on selectors (graceful error if malformed)                                       // 1
                                                                                                      // 2
// LocalCollection: a set of documents that supports queries and modifiers.                           // 3
                                                                                                      // 4
// Cursor: a specification for a particular subset of documents, w/                                   // 5
// a defined order, limit, and offset.  creating a Cursor with LocalCollection.find(),                // 6
                                                                                                      // 7
// ObserveHandle: the return value of a live query.                                                   // 8
                                                                                                      // 9
LocalCollection = function (name) {                                                                   // 10
  var self = this;                                                                                    // 11
  self.name = name;                                                                                   // 12
  // _id -> document (also containing id)                                                             // 13
  self._docs = new LocalCollection._IdMap;                                                            // 14
                                                                                                      // 15
  self._observeQueue = new Meteor._SynchronousQueue();                                                // 16
                                                                                                      // 17
  self.next_qid = 1; // live query id generator                                                       // 18
                                                                                                      // 19
  // qid -> live query object. keys:                                                                  // 20
  //  ordered: bool. ordered queries have addedBefore/movedBefore callbacks.                          // 21
  //  results: array (ordered) or object (unordered) of current results                               // 22
  //    (aliased with self._docs!)                                                                    // 23
  //  resultsSnapshot: snapshot of results. null if not paused.                                       // 24
  //  cursor: Cursor object for the query.                                                            // 25
  //  selector, sorter, (callbacks): functions                                                        // 26
  self.queries = {};                                                                                  // 27
                                                                                                      // 28
  // null if not saving originals; an IdMap from id to original document value if                     // 29
  // saving originals. See comments before saveOriginals().                                           // 30
  self._savedOriginals = null;                                                                        // 31
                                                                                                      // 32
  // True when observers are paused and we should not send callbacks.                                 // 33
  self.paused = false;                                                                                // 34
};                                                                                                    // 35
                                                                                                      // 36
Minimongo = {};                                                                                       // 37
                                                                                                      // 38
// Object exported only for unit testing.                                                             // 39
// Use it to export private functions to test in Tinytest.                                            // 40
MinimongoTest = {};                                                                                   // 41
                                                                                                      // 42
LocalCollection._applyChanges = function (doc, changeFields) {                                        // 43
  _.each(changeFields, function (value, key) {                                                        // 44
    if (value === undefined)                                                                          // 45
      delete doc[key];                                                                                // 46
    else                                                                                              // 47
      doc[key] = value;                                                                               // 48
  });                                                                                                 // 49
};                                                                                                    // 50
                                                                                                      // 51
MinimongoError = function (message) {                                                                 // 52
  var e = new Error(message);                                                                         // 53
  e.name = "MinimongoError";                                                                          // 54
  return e;                                                                                           // 55
};                                                                                                    // 56
                                                                                                      // 57
                                                                                                      // 58
// options may include sort, skip, limit, reactive                                                    // 59
// sort may be any of these forms:                                                                    // 60
//     {a: 1, b: -1}                                                                                  // 61
//     [["a", "asc"], ["b", "desc"]]                                                                  // 62
//     ["a", ["b", "desc"]]                                                                           // 63
//   (in the first form you're beholden to key enumeration order in                                   // 64
//   your javascript VM)                                                                              // 65
//                                                                                                    // 66
// reactive: if given, and false, don't register with Deps (default                                   // 67
// is true)                                                                                           // 68
//                                                                                                    // 69
// XXX possibly should support retrieving a subset of fields? and                                     // 70
// have it be a hint (ignored on the client, when not copying the                                     // 71
// doc?)                                                                                              // 72
//                                                                                                    // 73
// XXX sort does not yet support subkeys ('a.b') .. fix that!                                         // 74
// XXX add one more sort form: "key"                                                                  // 75
// XXX tests                                                                                          // 76
LocalCollection.prototype.find = function (selector, options) {                                       // 77
  // default syntax for everything is to omit the selector argument.                                  // 78
  // but if selector is explicitly passed in as false or undefined, we                                // 79
  // want a selector that matches nothing.                                                            // 80
  if (arguments.length === 0)                                                                         // 81
    selector = {};                                                                                    // 82
                                                                                                      // 83
  return new LocalCollection.Cursor(this, selector, options);                                         // 84
};                                                                                                    // 85
                                                                                                      // 86
// don't call this ctor directly.  use LocalCollection.find().                                        // 87
LocalCollection.Cursor = function (collection, selector, options) {                                   // 88
  var self = this;                                                                                    // 89
  if (!options) options = {};                                                                         // 90
                                                                                                      // 91
  self.collection = collection;                                                                       // 92
  self.sorter = null;                                                                                 // 93
                                                                                                      // 94
  if (LocalCollection._selectorIsId(selector)) {                                                      // 95
    // stash for fast path                                                                            // 96
    self._selectorId = selector;                                                                      // 97
    self.matcher = new Minimongo.Matcher(selector, self);                                             // 98
  } else {                                                                                            // 99
    self._selectorId = undefined;                                                                     // 100
    self.matcher = new Minimongo.Matcher(selector, self);                                             // 101
    if (self.matcher.hasGeoQuery() || options.sort) {                                                 // 102
      self.sorter = new Minimongo.Sorter(options.sort || [],                                          // 103
                                         { matcher: self.matcher });                                  // 104
    }                                                                                                 // 105
  }                                                                                                   // 106
  self.skip = options.skip;                                                                           // 107
  self.limit = options.limit;                                                                         // 108
  self.fields = options.fields;                                                                       // 109
                                                                                                      // 110
  if (self.fields)                                                                                    // 111
    self.projectionFn = LocalCollection._compileProjection(self.fields);                              // 112
                                                                                                      // 113
  self._transform = LocalCollection.wrapTransform(options.transform);                                 // 114
                                                                                                      // 115
  // by default, queries register w/ Deps when it is available.                                       // 116
  if (typeof Deps !== "undefined")                                                                    // 117
    self.reactive = (options.reactive === undefined) ? true : options.reactive;                       // 118
};                                                                                                    // 119
                                                                                                      // 120
// Since we don't actually have a "nextObject" interface, there's really no                           // 121
// reason to have a "rewind" interface.  All it did was make multiple calls                           // 122
// to fetch/map/forEach return nothing the second time.                                               // 123
// XXX COMPAT WITH 0.8.1                                                                              // 124
LocalCollection.Cursor.prototype.rewind = function () {                                               // 125
};                                                                                                    // 126
                                                                                                      // 127
LocalCollection.prototype.findOne = function (selector, options) {                                    // 128
  if (arguments.length === 0)                                                                         // 129
    selector = {};                                                                                    // 130
                                                                                                      // 131
  // NOTE: by setting limit 1 here, we end up using very inefficient                                  // 132
  // code that recomputes the whole query on each update. The upside is                               // 133
  // that when you reactively depend on a findOne you only get                                        // 134
  // invalidated when the found object changes, not any object in the                                 // 135
  // collection. Most findOne will be by id, which has a fast path, so                                // 136
  // this might not be a big deal. In most cases, invalidation causes                                 // 137
  // the called to re-query anyway, so this should be a net performance                               // 138
  // improvement.                                                                                     // 139
  options = options || {};                                                                            // 140
  options.limit = 1;                                                                                  // 141
                                                                                                      // 142
  return this.find(selector, options).fetch()[0];                                                     // 143
};                                                                                                    // 144
                                                                                                      // 145
LocalCollection.Cursor.prototype.forEach = function (callback, thisArg) {                             // 146
  var self = this;                                                                                    // 147
                                                                                                      // 148
  var docs;                                                                                           // 149
  var needsClone = true;                                                                              // 150
  if (self.reactive && Deps.active) {                                                                 // 151
    // Ensure that we invalidate the current computation if the result of this                        // 152
    // query changes. We also piggy-back on top of the query done by                                  // 153
    // observeChanges so we don't need to do another query.                                           // 154
    var computation = Deps.currentComputation;                                                        // 155
    var invalidate = function () {                                                                    // 156
      computation.invalidate();                                                                       // 157
    };                                                                                                // 158
    var initial = true;                                                                               // 159
    docs = [];                                                                                        // 160
    // observeChanges will stop() when this computation is invalidated                                // 161
    self.observeChanges({                                                                             // 162
      added: function (id, fields) {                                                                  // 163
        if (initial) {                                                                                // 164
          fields._id = id;                                                                            // 165
          docs.push(fields);                                                                          // 166
        } else {                                                                                      // 167
          invalidate();                                                                               // 168
        }                                                                                             // 169
      },                                                                                              // 170
      changed: invalidate,                                                                            // 171
      removed: invalidate,                                                                            // 172
      movedBefore: invalidate                                                                         // 173
    });                                                                                               // 174
    initial = false;                                                                                  // 175
    needsClone = false;  // observeChanges gives us cloned docs                                       // 176
  } else {                                                                                            // 177
    docs = self._getRawObjects({ordered: true});                                                      // 178
  }                                                                                                   // 179
                                                                                                      // 180
  _.each(docs, function (elt, i) {                                                                    // 181
    if (self.projectionFn) {                                                                          // 182
      elt = self.projectionFn(elt);                                                                   // 183
    } else if (needsClone) {                                                                          // 184
      // projection functions always clone the pieces they use, and                                   // 185
      // observeChanges callbacks got a cloned document, but otherwise we have                        // 186
      // to do it here.                                                                               // 187
      elt = EJSON.clone(elt);                                                                         // 188
    }                                                                                                 // 189
                                                                                                      // 190
    if (self._transform)                                                                              // 191
      elt = self._transform(elt);                                                                     // 192
    callback.call(thisArg, elt, i, self);                                                             // 193
  });                                                                                                 // 194
};                                                                                                    // 195
                                                                                                      // 196
LocalCollection.Cursor.prototype.getTransform = function () {                                         // 197
  return this._transform;                                                                             // 198
};                                                                                                    // 199
                                                                                                      // 200
LocalCollection.Cursor.prototype.map = function (callback, thisArg) {                                 // 201
  var self = this;                                                                                    // 202
  var res = [];                                                                                       // 203
  self.forEach(function (doc, index) {                                                                // 204
    res.push(callback.call(thisArg, doc, index, self));                                               // 205
  });                                                                                                 // 206
  return res;                                                                                         // 207
};                                                                                                    // 208
                                                                                                      // 209
LocalCollection.Cursor.prototype.fetch = function () {                                                // 210
  var self = this;                                                                                    // 211
  var res = [];                                                                                       // 212
  self.forEach(function (doc) {                                                                       // 213
    res.push(doc);                                                                                    // 214
  });                                                                                                 // 215
  return res;                                                                                         // 216
};                                                                                                    // 217
                                                                                                      // 218
LocalCollection.Cursor.prototype.count = function () {                                                // 219
  var self = this;                                                                                    // 220
                                                                                                      // 221
  if (self.reactive && Deps.active) {                                                                 // 222
    // Ensure that we invalidate the current computation if the result of this                        // 223
    // query changes. We also piggy-back on top of the query done by                                  // 224
    // observeChanges so we don't need to do another query.                                           // 225
    var computation = Deps.currentComputation;                                                        // 226
    var invalidate = function () {                                                                    // 227
      computation.invalidate();                                                                       // 228
    };                                                                                                // 229
    var initial = true;                                                                               // 230
    var count = 0;                                                                                    // 231
    // observeChanges will stop() when this computation is invalidated                                // 232
    self.observeChanges({                                                                             // 233
      // we have to use addedBefore rather than added, because observeChanges in                      // 234
      // unordered (added) mode doesn't support skip/limit                                            // 235
      addedBefore: function () {                                                                      // 236
        if (initial) {                                                                                // 237
          count++;                                                                                    // 238
        } else {                                                                                      // 239
          invalidate();                                                                               // 240
        }                                                                                             // 241
      },                                                                                              // 242
      removed: invalidate                                                                             // 243
    });                                                                                               // 244
    initial = false;                                                                                  // 245
    return count;                                                                                     // 246
  }                                                                                                   // 247
                                                                                                      // 248
  return self._getRawObjects({ordered: true}).length;                                                 // 249
};                                                                                                    // 250
                                                                                                      // 251
LocalCollection.Cursor.prototype._publishCursor = function (sub) {                                    // 252
  var self = this;                                                                                    // 253
  if (! self.collection.name)                                                                         // 254
    throw new Error("Can't publish a cursor from a collection without a name.");                      // 255
  var collection = self.collection.name;                                                              // 256
                                                                                                      // 257
  // XXX minimongo should not depend on mongo-livedata!                                               // 258
  return Meteor.Collection._publishCursor(self, sub, collection);                                     // 259
};                                                                                                    // 260
                                                                                                      // 261
LocalCollection.Cursor.prototype._getCollectionName = function () {                                   // 262
  var self = this;                                                                                    // 263
  return self.collection.name;                                                                        // 264
};                                                                                                    // 265
                                                                                                      // 266
LocalCollection._observeChangesCallbacksAreOrdered = function (callbacks) {                           // 267
  if (callbacks.added && callbacks.addedBefore)                                                       // 268
    throw new Error("Please specify only one of added() and addedBefore()");                          // 269
  return !!(callbacks.addedBefore || callbacks.movedBefore);                                          // 270
};                                                                                                    // 271
                                                                                                      // 272
LocalCollection._observeCallbacksAreOrdered = function (callbacks) {                                  // 273
  if (callbacks.addedAt && callbacks.added)                                                           // 274
    throw new Error("Please specify only one of added() and addedAt()");                              // 275
  if (callbacks.changedAt && callbacks.changed)                                                       // 276
    throw new Error("Please specify only one of changed() and changedAt()");                          // 277
  if (callbacks.removed && callbacks.removedAt)                                                       // 278
    throw new Error("Please specify only one of removed() and removedAt()");                          // 279
                                                                                                      // 280
  return !!(callbacks.addedAt || callbacks.movedTo || callbacks.changedAt                             // 281
            || callbacks.removedAt);                                                                  // 282
};                                                                                                    // 283
                                                                                                      // 284
// the handle that comes back from observe.                                                           // 285
LocalCollection.ObserveHandle = function () {};                                                       // 286
                                                                                                      // 287
// options to contain:                                                                                // 288
//  * callbacks for observe():                                                                        // 289
//    - addedAt (document, atIndex)                                                                   // 290
//    - added (document)                                                                              // 291
//    - changedAt (newDocument, oldDocument, atIndex)                                                 // 292
//    - changed (newDocument, oldDocument)                                                            // 293
//    - removedAt (document, atIndex)                                                                 // 294
//    - removed (document)                                                                            // 295
//    - movedTo (document, oldIndex, newIndex)                                                        // 296
//                                                                                                    // 297
// attributes available on returned query handle:                                                     // 298
//  * stop(): end updates                                                                             // 299
//  * collection: the collection this query is querying                                               // 300
//                                                                                                    // 301
// iff x is a returned query handle, (x instanceof                                                    // 302
// LocalCollection.ObserveHandle) is true                                                             // 303
//                                                                                                    // 304
// initial results delivered through added callback                                                   // 305
// XXX maybe callbacks should take a list of objects, to expose transactions?                         // 306
// XXX maybe support field limiting (to limit what you're notified on)                                // 307
                                                                                                      // 308
_.extend(LocalCollection.Cursor.prototype, {                                                          // 309
  observe: function (options) {                                                                       // 310
    var self = this;                                                                                  // 311
    return LocalCollection._observeFromObserveChanges(self, options);                                 // 312
  },                                                                                                  // 313
  observeChanges: function (options) {                                                                // 314
    var self = this;                                                                                  // 315
                                                                                                      // 316
    var ordered = LocalCollection._observeChangesCallbacksAreOrdered(options);                        // 317
                                                                                                      // 318
    // there are several places that assume you aren't combining skip/limit with                      // 319
    // unordered observe.  eg, update's EJSON.clone, and the "there are several"                      // 320
    // comment in _modifyAndNotify                                                                    // 321
    // XXX allow skip/limit with unordered observe                                                    // 322
    if (!ordered && (self.skip || self.limit))                                                        // 323
      throw new Error("must use ordered observe with skip or limit");                                 // 324
                                                                                                      // 325
    if (self.fields && (self.fields._id === 0 || self.fields._id === false))                          // 326
      throw Error("You may not observe a cursor with {fields: {_id: 0}}");                            // 327
                                                                                                      // 328
    var query = {                                                                                     // 329
      matcher: self.matcher, // not fast pathed                                                       // 330
      sorter: ordered && self.sorter,                                                                 // 331
      distances: (                                                                                    // 332
        self.matcher.hasGeoQuery() && ordered && new LocalCollection._IdMap),                         // 333
      resultsSnapshot: null,                                                                          // 334
      ordered: ordered,                                                                               // 335
      cursor: self,                                                                                   // 336
      projectionFn: self.projectionFn                                                                 // 337
    };                                                                                                // 338
    var qid;                                                                                          // 339
                                                                                                      // 340
    // Non-reactive queries call added[Before] and then never call anything                           // 341
    // else.                                                                                          // 342
    if (self.reactive) {                                                                              // 343
      qid = self.collection.next_qid++;                                                               // 344
      self.collection.queries[qid] = query;                                                           // 345
    }                                                                                                 // 346
    query.results = self._getRawObjects({                                                             // 347
      ordered: ordered, distances: query.distances});                                                 // 348
    if (self.collection.paused)                                                                       // 349
      query.resultsSnapshot = (ordered ? [] : new LocalCollection._IdMap);                            // 350
                                                                                                      // 351
    // wrap callbacks we were passed. callbacks only fire when not paused and                         // 352
    // are never undefined                                                                            // 353
    // Filters out blacklisted fields according to cursor's projection.                               // 354
    // XXX wrong place for this?                                                                      // 355
                                                                                                      // 356
    // furthermore, callbacks enqueue until the operation we're working on is                         // 357
    // done.                                                                                          // 358
    var wrapCallback = function (f, fieldsIndex, ignoreEmptyFields) {                                 // 359
      if (!f)                                                                                         // 360
        return function () {};                                                                        // 361
      return function (/*args*/) {                                                                    // 362
        var context = this;                                                                           // 363
        var args = arguments;                                                                         // 364
                                                                                                      // 365
        if (self.collection.paused)                                                                   // 366
          return;                                                                                     // 367
                                                                                                      // 368
        if (fieldsIndex !== undefined && self.projectionFn) {                                         // 369
          args[fieldsIndex] = self.projectionFn(args[fieldsIndex]);                                   // 370
          if (ignoreEmptyFields && _.isEmpty(args[fieldsIndex]))                                      // 371
            return;                                                                                   // 372
        }                                                                                             // 373
                                                                                                      // 374
        self.collection._observeQueue.queueTask(function () {                                         // 375
          f.apply(context, args);                                                                     // 376
        });                                                                                           // 377
      };                                                                                              // 378
    };                                                                                                // 379
    query.added = wrapCallback(options.added, 1);                                                     // 380
    query.changed = wrapCallback(options.changed, 1, true);                                           // 381
    query.removed = wrapCallback(options.removed);                                                    // 382
    if (ordered) {                                                                                    // 383
      query.addedBefore = wrapCallback(options.addedBefore, 1);                                       // 384
      query.movedBefore = wrapCallback(options.movedBefore);                                          // 385
    }                                                                                                 // 386
                                                                                                      // 387
    if (!options._suppress_initial && !self.collection.paused) {                                      // 388
      // XXX unify ordered and unordered interface                                                    // 389
      var each = ordered                                                                              // 390
            ? _.bind(_.each, null, query.results)                                                     // 391
            : _.bind(query.results.forEach, query.results);                                           // 392
      each(function (doc) {                                                                           // 393
        var fields = EJSON.clone(doc);                                                                // 394
                                                                                                      // 395
        delete fields._id;                                                                            // 396
        if (ordered)                                                                                  // 397
          query.addedBefore(doc._id, fields, null);                                                   // 398
        query.added(doc._id, fields);                                                                 // 399
      });                                                                                             // 400
    }                                                                                                 // 401
                                                                                                      // 402
    var handle = new LocalCollection.ObserveHandle;                                                   // 403
    _.extend(handle, {                                                                                // 404
      collection: self.collection,                                                                    // 405
      stop: function () {                                                                             // 406
        if (self.reactive)                                                                            // 407
          delete self.collection.queries[qid];                                                        // 408
      }                                                                                               // 409
    });                                                                                               // 410
                                                                                                      // 411
    if (self.reactive && Deps.active) {                                                               // 412
      // XXX in many cases, the same observe will be recreated when                                   // 413
      // the current autorun is rerun.  we could save work by                                         // 414
      // letting it linger across rerun and potentially get                                           // 415
      // repurposed if the same observe is performed, using logic                                     // 416
      // similar to that of Meteor.subscribe.                                                         // 417
      Deps.onInvalidate(function () {                                                                 // 418
        handle.stop();                                                                                // 419
      });                                                                                             // 420
    }                                                                                                 // 421
    // run the observe callbacks resulting from the initial contents                                  // 422
    // before we leave the observe.                                                                   // 423
    self.collection._observeQueue.drain();                                                            // 424
                                                                                                      // 425
    return handle;                                                                                    // 426
  }                                                                                                   // 427
});                                                                                                   // 428
                                                                                                      // 429
// Returns a collection of matching objects, but doesn't deep copy them.                              // 430
//                                                                                                    // 431
// If ordered is set, returns a sorted array, respecting sorter, skip, and limit                      // 432
// properties of the query.  if sorter is falsey, no sort -- you get the natural                      // 433
// order.                                                                                             // 434
//                                                                                                    // 435
// If ordered is not set, returns an object mapping from ID to doc (sorter, skip                      // 436
// and limit should not be set).                                                                      // 437
//                                                                                                    // 438
// If ordered is set and this cursor is a $near geoquery, then this function                          // 439
// will use an _IdMap to track each distance from the $near argument point in                         // 440
// order to use it as a sort key. If an _IdMap is passed in the 'distances'                           // 441
// argument, this function will clear it and use it for this purpose (otherwise                       // 442
// it will just create its own _IdMap). The observeChanges implementation uses                        // 443
// this to remember the distances after this function returns.                                        // 444
LocalCollection.Cursor.prototype._getRawObjects = function (options) {                                // 445
  var self = this;                                                                                    // 446
  options = options || {};                                                                            // 447
                                                                                                      // 448
  // XXX use OrderedDict instead of array, and make IdMap and OrderedDict                             // 449
  // compatible                                                                                       // 450
  var results = options.ordered ? [] : new LocalCollection._IdMap;                                    // 451
                                                                                                      // 452
  // fast path for single ID value                                                                    // 453
  if (self._selectorId !== undefined) {                                                               // 454
    // If you have non-zero skip and ask for a single id, you get                                     // 455
    // nothing. This is so it matches the behavior of the '{_id: foo}'                                // 456
    // path.                                                                                          // 457
    if (self.skip)                                                                                    // 458
      return results;                                                                                 // 459
                                                                                                      // 460
    var selectedDoc = self.collection._docs.get(self._selectorId);                                    // 461
    if (selectedDoc) {                                                                                // 462
      if (options.ordered)                                                                            // 463
        results.push(selectedDoc);                                                                    // 464
      else                                                                                            // 465
        results.set(self._selectorId, selectedDoc);                                                   // 466
    }                                                                                                 // 467
    return results;                                                                                   // 468
  }                                                                                                   // 469
                                                                                                      // 470
  // slow path for arbitrary selector, sort, skip, limit                                              // 471
                                                                                                      // 472
  // in the observeChanges case, distances is actually part of the "query" (ie,                       // 473
  // live results set) object.  in other cases, distances is only used inside                         // 474
  // this function.                                                                                   // 475
  var distances;                                                                                      // 476
  if (self.matcher.hasGeoQuery() && options.ordered) {                                                // 477
    if (options.distances) {                                                                          // 478
      distances = options.distances;                                                                  // 479
      distances.clear();                                                                              // 480
    } else {                                                                                          // 481
      distances = new LocalCollection._IdMap();                                                       // 482
    }                                                                                                 // 483
  }                                                                                                   // 484
                                                                                                      // 485
  self.collection._docs.forEach(function (doc, id) {                                                  // 486
    var matchResult = self.matcher.documentMatches(doc);                                              // 487
    if (matchResult.result) {                                                                         // 488
      if (options.ordered) {                                                                          // 489
        results.push(doc);                                                                            // 490
        if (distances && matchResult.distance !== undefined)                                          // 491
          distances.set(id, matchResult.distance);                                                    // 492
      } else {                                                                                        // 493
        results.set(id, doc);                                                                         // 494
      }                                                                                               // 495
    }                                                                                                 // 496
    // Fast path for limited unsorted queries.                                                        // 497
    // XXX 'length' check here seems wrong for ordered                                                // 498
    if (self.limit && !self.skip && !self.sorter &&                                                   // 499
        results.length === self.limit)                                                                // 500
      return false;  // break                                                                         // 501
    return true;  // continue                                                                         // 502
  });                                                                                                 // 503
                                                                                                      // 504
  if (!options.ordered)                                                                               // 505
    return results;                                                                                   // 506
                                                                                                      // 507
  if (self.sorter) {                                                                                  // 508
    var comparator = self.sorter.getComparator({distances: distances});                               // 509
    results.sort(comparator);                                                                         // 510
  }                                                                                                   // 511
                                                                                                      // 512
  var idx_start = self.skip || 0;                                                                     // 513
  var idx_end = self.limit ? (self.limit + idx_start) : results.length;                               // 514
  return results.slice(idx_start, idx_end);                                                           // 515
};                                                                                                    // 516
                                                                                                      // 517
// XXX enforce rule that field names can't start with '$' or contain '.'                              // 518
// (real mongodb does in fact enforce this)                                                           // 519
// XXX possibly enforce that 'undefined' does not appear (we assume                                   // 520
// this in our handling of null and $exists)                                                          // 521
LocalCollection.prototype.insert = function (doc, callback) {                                         // 522
  var self = this;                                                                                    // 523
  doc = EJSON.clone(doc);                                                                             // 524
                                                                                                      // 525
  if (!_.has(doc, '_id')) {                                                                           // 526
    // if you really want to use ObjectIDs, set this global.                                          // 527
    // Meteor.Collection specifies its own ids and does not use this code.                            // 528
    doc._id = LocalCollection._useOID ? new LocalCollection._ObjectID()                               // 529
                                      : Random.id();                                                  // 530
  }                                                                                                   // 531
  var id = doc._id;                                                                                   // 532
                                                                                                      // 533
  if (self._docs.has(id))                                                                             // 534
    throw MinimongoError("Duplicate _id '" + id + "'");                                               // 535
                                                                                                      // 536
  self._saveOriginal(id, undefined);                                                                  // 537
  self._docs.set(id, doc);                                                                            // 538
                                                                                                      // 539
  var queriesToRecompute = [];                                                                        // 540
  // trigger live queries that match                                                                  // 541
  for (var qid in self.queries) {                                                                     // 542
    var query = self.queries[qid];                                                                    // 543
    var matchResult = query.matcher.documentMatches(doc);                                             // 544
    if (matchResult.result) {                                                                         // 545
      if (query.distances && matchResult.distance !== undefined)                                      // 546
        query.distances.set(id, matchResult.distance);                                                // 547
      if (query.cursor.skip || query.cursor.limit)                                                    // 548
        queriesToRecompute.push(qid);                                                                 // 549
      else                                                                                            // 550
        LocalCollection._insertInResults(query, doc);                                                 // 551
    }                                                                                                 // 552
  }                                                                                                   // 553
                                                                                                      // 554
  _.each(queriesToRecompute, function (qid) {                                                         // 555
    if (self.queries[qid])                                                                            // 556
      LocalCollection._recomputeResults(self.queries[qid]);                                           // 557
  });                                                                                                 // 558
  self._observeQueue.drain();                                                                         // 559
                                                                                                      // 560
  // Defer because the caller likely doesn't expect the callback to be run                            // 561
  // immediately.                                                                                     // 562
  if (callback)                                                                                       // 563
    Meteor.defer(function () {                                                                        // 564
      callback(null, id);                                                                             // 565
    });                                                                                               // 566
  return id;                                                                                          // 567
};                                                                                                    // 568
                                                                                                      // 569
// Iterates over a subset of documents that could match selector; calls                               // 570
// f(doc, id) on each of them.  Specifically, if selector specifies                                   // 571
// specific _id's, it only looks at those.  doc is *not* cloned: it is the                            // 572
// same object that is in _docs.                                                                      // 573
LocalCollection.prototype._eachPossiblyMatchingDoc = function (selector, f) {                         // 574
  var self = this;                                                                                    // 575
  var specificIds = LocalCollection._idsMatchedBySelector(selector);                                  // 576
  if (specificIds) {                                                                                  // 577
    for (var i = 0; i < specificIds.length; ++i) {                                                    // 578
      var id = specificIds[i];                                                                        // 579
      var doc = self._docs.get(id);                                                                   // 580
      if (doc) {                                                                                      // 581
        var breakIfFalse = f(doc, id);                                                                // 582
        if (breakIfFalse === false)                                                                   // 583
          break;                                                                                      // 584
      }                                                                                               // 585
    }                                                                                                 // 586
  } else {                                                                                            // 587
    self._docs.forEach(f);                                                                            // 588
  }                                                                                                   // 589
};                                                                                                    // 590
                                                                                                      // 591
LocalCollection.prototype.remove = function (selector, callback) {                                    // 592
  var self = this;                                                                                    // 593
                                                                                                      // 594
  // Easy special case: if we're not calling observeChanges callbacks and we're                       // 595
  // not saving originals and we got asked to remove everything, then just empty                      // 596
  // everything directly.                                                                             // 597
  if (self.paused && !self._savedOriginals && EJSON.equals(selector, {})) {                           // 598
    var result = self._docs.size();                                                                   // 599
    self._docs.clear();                                                                               // 600
    _.each(self.queries, function (query) {                                                           // 601
      if (query.ordered) {                                                                            // 602
        query.results = [];                                                                           // 603
      } else {                                                                                        // 604
        query.results.clear();                                                                        // 605
      }                                                                                               // 606
    });                                                                                               // 607
    if (callback) {                                                                                   // 608
      Meteor.defer(function () {                                                                      // 609
        callback(null, result);                                                                       // 610
      });                                                                                             // 611
    }                                                                                                 // 612
    return result;                                                                                    // 613
  }                                                                                                   // 614
                                                                                                      // 615
  var matcher = new Minimongo.Matcher(selector, self);                                                // 616
  var remove = [];                                                                                    // 617
  self._eachPossiblyMatchingDoc(selector, function (doc, id) {                                        // 618
    if (matcher.documentMatches(doc).result)                                                          // 619
      remove.push(id);                                                                                // 620
  });                                                                                                 // 621
                                                                                                      // 622
  var queriesToRecompute = [];                                                                        // 623
  var queryRemove = [];                                                                               // 624
  for (var i = 0; i < remove.length; i++) {                                                           // 625
    var removeId = remove[i];                                                                         // 626
    var removeDoc = self._docs.get(removeId);                                                         // 627
    _.each(self.queries, function (query, qid) {                                                      // 628
      if (query.matcher.documentMatches(removeDoc).result) {                                          // 629
        if (query.cursor.skip || query.cursor.limit)                                                  // 630
          queriesToRecompute.push(qid);                                                               // 631
        else                                                                                          // 632
          queryRemove.push({qid: qid, doc: removeDoc});                                               // 633
      }                                                                                               // 634
    });                                                                                               // 635
    self._saveOriginal(removeId, removeDoc);                                                          // 636
    self._docs.remove(removeId);                                                                      // 637
  }                                                                                                   // 638
                                                                                                      // 639
  // run live query callbacks _after_ we've removed the documents.                                    // 640
  _.each(queryRemove, function (remove) {                                                             // 641
    var query = self.queries[remove.qid];                                                             // 642
    if (query) {                                                                                      // 643
      query.distances && query.distances.remove(remove.doc._id);                                      // 644
      LocalCollection._removeFromResults(query, remove.doc);                                          // 645
    }                                                                                                 // 646
  });                                                                                                 // 647
  _.each(queriesToRecompute, function (qid) {                                                         // 648
    var query = self.queries[qid];                                                                    // 649
    if (query)                                                                                        // 650
      LocalCollection._recomputeResults(query);                                                       // 651
  });                                                                                                 // 652
  self._observeQueue.drain();                                                                         // 653
  result = remove.length;                                                                             // 654
  if (callback)                                                                                       // 655
    Meteor.defer(function () {                                                                        // 656
      callback(null, result);                                                                         // 657
    });                                                                                               // 658
  return result;                                                                                      // 659
};                                                                                                    // 660
                                                                                                      // 661
// XXX atomicity: if multi is true, and one modification fails, do                                    // 662
// we rollback the whole operation, or what?                                                          // 663
LocalCollection.prototype.update = function (selector, mod, options, callback) {                      // 664
  var self = this;                                                                                    // 665
  if (! callback && options instanceof Function) {                                                    // 666
    callback = options;                                                                               // 667
    options = null;                                                                                   // 668
  }                                                                                                   // 669
  if (!options) options = {};                                                                         // 670
                                                                                                      // 671
  var matcher = new Minimongo.Matcher(selector, self);                                                // 672
                                                                                                      // 673
  // Save the original results of any query that we might need to                                     // 674
  // _recomputeResults on, because _modifyAndNotify will mutate the objects in                        // 675
  // it. (We don't need to save the original results of paused queries because                        // 676
  // they already have a resultsSnapshot and we won't be diffing in                                   // 677
  // _recomputeResults.)                                                                              // 678
  var qidToOriginalResults = {};                                                                      // 679
  _.each(self.queries, function (query, qid) {                                                        // 680
    // XXX for now, skip/limit implies ordered observe, so query.results is                           // 681
    // always an array                                                                                // 682
    if ((query.cursor.skip || query.cursor.limit) && !query.paused)                                   // 683
      qidToOriginalResults[qid] = EJSON.clone(query.results);                                         // 684
  });                                                                                                 // 685
  var recomputeQids = {};                                                                             // 686
                                                                                                      // 687
  var updateCount = 0;                                                                                // 688
                                                                                                      // 689
  self._eachPossiblyMatchingDoc(selector, function (doc, id) {                                        // 690
    var queryResult = matcher.documentMatches(doc);                                                   // 691
    if (queryResult.result) {                                                                         // 692
      // XXX Should we save the original even if mod ends up being a no-op?                           // 693
      self._saveOriginal(id, doc);                                                                    // 694
      self._modifyAndNotify(doc, mod, recomputeQids, queryResult.arrayIndices);                       // 695
      ++updateCount;                                                                                  // 696
      if (!options.multi)                                                                             // 697
        return false;  // break                                                                       // 698
    }                                                                                                 // 699
    return true;                                                                                      // 700
  });                                                                                                 // 701
                                                                                                      // 702
  _.each(recomputeQids, function (dummy, qid) {                                                       // 703
    var query = self.queries[qid];                                                                    // 704
    if (query)                                                                                        // 705
      LocalCollection._recomputeResults(query,                                                        // 706
                                        qidToOriginalResults[qid]);                                   // 707
  });                                                                                                 // 708
  self._observeQueue.drain();                                                                         // 709
                                                                                                      // 710
  // If we are doing an upsert, and we didn't modify any documents yet, then                          // 711
  // it's time to do an insert. Figure out what document we are inserting, and                        // 712
  // generate an id for it.                                                                           // 713
  var insertedId;                                                                                     // 714
  if (updateCount === 0 && options.upsert) {                                                          // 715
    var newDoc = LocalCollection._removeDollarOperators(selector);                                    // 716
    LocalCollection._modify(newDoc, mod, {isInsert: true});                                           // 717
    if (! newDoc._id && options.insertedId)                                                           // 718
      newDoc._id = options.insertedId;                                                                // 719
    insertedId = self.insert(newDoc);                                                                 // 720
    updateCount = 1;                                                                                  // 721
  }                                                                                                   // 722
                                                                                                      // 723
  // Return the number of affected documents, or in the upsert case, an object                        // 724
  // containing the number of affected docs and the id of the doc that was                            // 725
  // inserted, if any.                                                                                // 726
  var result;                                                                                         // 727
  if (options._returnObject) {                                                                        // 728
    result = {                                                                                        // 729
      numberAffected: updateCount                                                                     // 730
    };                                                                                                // 731
    if (insertedId !== undefined)                                                                     // 732
      result.insertedId = insertedId;                                                                 // 733
  } else {                                                                                            // 734
    result = updateCount;                                                                             // 735
  }                                                                                                   // 736
                                                                                                      // 737
  if (callback)                                                                                       // 738
    Meteor.defer(function () {                                                                        // 739
      callback(null, result);                                                                         // 740
    });                                                                                               // 741
  return result;                                                                                      // 742
};                                                                                                    // 743
                                                                                                      // 744
// A convenience wrapper on update. LocalCollection.upsert(sel, mod) is                               // 745
// equivalent to LocalCollection.update(sel, mod, { upsert: true, _returnObject:                      // 746
// true }).                                                                                           // 747
LocalCollection.prototype.upsert = function (selector, mod, options, callback) {                      // 748
  var self = this;                                                                                    // 749
  if (! callback && typeof options === "function") {                                                  // 750
    callback = options;                                                                               // 751
    options = {};                                                                                     // 752
  }                                                                                                   // 753
  return self.update(selector, mod, _.extend({}, options, {                                           // 754
    upsert: true,                                                                                     // 755
    _returnObject: true                                                                               // 756
  }), callback);                                                                                      // 757
};                                                                                                    // 758
                                                                                                      // 759
LocalCollection.prototype._modifyAndNotify = function (                                               // 760
    doc, mod, recomputeQids, arrayIndices) {                                                          // 761
  var self = this;                                                                                    // 762
                                                                                                      // 763
  var matched_before = {};                                                                            // 764
  for (var qid in self.queries) {                                                                     // 765
    var query = self.queries[qid];                                                                    // 766
    if (query.ordered) {                                                                              // 767
      matched_before[qid] = query.matcher.documentMatches(doc).result;                                // 768
    } else {                                                                                          // 769
      // Because we don't support skip or limit (yet) in unordered queries, we                        // 770
      // can just do a direct lookup.                                                                 // 771
      matched_before[qid] = query.results.has(doc._id);                                               // 772
    }                                                                                                 // 773
  }                                                                                                   // 774
                                                                                                      // 775
  var old_doc = EJSON.clone(doc);                                                                     // 776
                                                                                                      // 777
  LocalCollection._modify(doc, mod, {arrayIndices: arrayIndices});                                    // 778
                                                                                                      // 779
  for (qid in self.queries) {                                                                         // 780
    query = self.queries[qid];                                                                        // 781
    var before = matched_before[qid];                                                                 // 782
    var afterMatch = query.matcher.documentMatches(doc);                                              // 783
    var after = afterMatch.result;                                                                    // 784
    if (after && query.distances && afterMatch.distance !== undefined)                                // 785
      query.distances.set(doc._id, afterMatch.distance);                                              // 786
                                                                                                      // 787
    if (query.cursor.skip || query.cursor.limit) {                                                    // 788
      // We need to recompute any query where the doc may have been in the                            // 789
      // cursor's window either before or after the update. (Note that if skip                        // 790
      // or limit is set, "before" and "after" being true do not necessarily                          // 791
      // mean that the document is in the cursor's output after skip/limit is                         // 792
      // applied... but if they are false, then the document definitely is NOT                        // 793
      // in the output. So it's safe to skip recompute if neither before or                           // 794
      // after are true.)                                                                             // 795
      if (before || after)                                                                            // 796
        recomputeQids[qid] = true;                                                                    // 797
    } else if (before && !after) {                                                                    // 798
      LocalCollection._removeFromResults(query, doc);                                                 // 799
    } else if (!before && after) {                                                                    // 800
      LocalCollection._insertInResults(query, doc);                                                   // 801
    } else if (before && after) {                                                                     // 802
      LocalCollection._updateInResults(query, doc, old_doc);                                          // 803
    }                                                                                                 // 804
  }                                                                                                   // 805
};                                                                                                    // 806
                                                                                                      // 807
// XXX the sorted-query logic below is laughably inefficient. we'll                                   // 808
// need to come up with a better datastructure for this.                                              // 809
//                                                                                                    // 810
// XXX the logic for observing with a skip or a limit is even more                                    // 811
// laughably inefficient. we recompute the whole results every time!                                  // 812
                                                                                                      // 813
LocalCollection._insertInResults = function (query, doc) {                                            // 814
  var fields = EJSON.clone(doc);                                                                      // 815
  delete fields._id;                                                                                  // 816
  if (query.ordered) {                                                                                // 817
    if (!query.sorter) {                                                                              // 818
      query.addedBefore(doc._id, fields, null);                                                       // 819
      query.results.push(doc);                                                                        // 820
    } else {                                                                                          // 821
      var i = LocalCollection._insertInSortedList(                                                    // 822
        query.sorter.getComparator({distances: query.distances}),                                     // 823
        query.results, doc);                                                                          // 824
      var next = query.results[i+1];                                                                  // 825
      if (next)                                                                                       // 826
        next = next._id;                                                                              // 827
      else                                                                                            // 828
        next = null;                                                                                  // 829
      query.addedBefore(doc._id, fields, next);                                                       // 830
    }                                                                                                 // 831
    query.added(doc._id, fields);                                                                     // 832
  } else {                                                                                            // 833
    query.added(doc._id, fields);                                                                     // 834
    query.results.set(doc._id, doc);                                                                  // 835
  }                                                                                                   // 836
};                                                                                                    // 837
                                                                                                      // 838
LocalCollection._removeFromResults = function (query, doc) {                                          // 839
  if (query.ordered) {                                                                                // 840
    var i = LocalCollection._findInOrderedResults(query, doc);                                        // 841
    query.removed(doc._id);                                                                           // 842
    query.results.splice(i, 1);                                                                       // 843
  } else {                                                                                            // 844
    var id = doc._id;  // in case callback mutates doc                                                // 845
    query.removed(doc._id);                                                                           // 846
    query.results.remove(id);                                                                         // 847
  }                                                                                                   // 848
};                                                                                                    // 849
                                                                                                      // 850
LocalCollection._updateInResults = function (query, doc, old_doc) {                                   // 851
  if (!EJSON.equals(doc._id, old_doc._id))                                                            // 852
    throw new Error("Can't change a doc's _id while updating");                                       // 853
  var changedFields = LocalCollection._makeChangedFields(doc, old_doc);                               // 854
  if (!query.ordered) {                                                                               // 855
    if (!_.isEmpty(changedFields)) {                                                                  // 856
      query.changed(doc._id, changedFields);                                                          // 857
      query.results.set(doc._id, doc);                                                                // 858
    }                                                                                                 // 859
    return;                                                                                           // 860
  }                                                                                                   // 861
                                                                                                      // 862
  var orig_idx = LocalCollection._findInOrderedResults(query, doc);                                   // 863
                                                                                                      // 864
  if (!_.isEmpty(changedFields))                                                                      // 865
    query.changed(doc._id, changedFields);                                                            // 866
  if (!query.sorter)                                                                                  // 867
    return;                                                                                           // 868
                                                                                                      // 869
  // just take it out and put it back in again, and see if the index                                  // 870
  // changes                                                                                          // 871
  query.results.splice(orig_idx, 1);                                                                  // 872
  var new_idx = LocalCollection._insertInSortedList(                                                  // 873
    query.sorter.getComparator({distances: query.distances}),                                         // 874
    query.results, doc);                                                                              // 875
  if (orig_idx !== new_idx) {                                                                         // 876
    var next = query.results[new_idx+1];                                                              // 877
    if (next)                                                                                         // 878
      next = next._id;                                                                                // 879
    else                                                                                              // 880
      next = null;                                                                                    // 881
    query.movedBefore && query.movedBefore(doc._id, next);                                            // 882
  }                                                                                                   // 883
};                                                                                                    // 884
                                                                                                      // 885
// Recomputes the results of a query and runs observe callbacks for the                               // 886
// difference between the previous results and the current results (unless                            // 887
// paused). Used for skip/limit queries.                                                              // 888
//                                                                                                    // 889
// When this is used by insert or remove, it can just use query.results for the                       // 890
// old results (and there's no need to pass in oldResults), because these                             // 891
// operations don't mutate the documents in the collection. Update needs to pass                      // 892
// in an oldResults which was deep-copied before the modifier was applied.                            // 893
LocalCollection._recomputeResults = function (query, oldResults) {                                    // 894
  if (!oldResults)                                                                                    // 895
    oldResults = query.results;                                                                       // 896
  if (query.distances)                                                                                // 897
    query.distances.clear();                                                                          // 898
  query.results = query.cursor._getRawObjects({                                                       // 899
    ordered: query.ordered, distances: query.distances});                                             // 900
                                                                                                      // 901
  if (!query.paused) {                                                                                // 902
    LocalCollection._diffQueryChanges(                                                                // 903
      query.ordered, oldResults, query.results, query);                                               // 904
  }                                                                                                   // 905
};                                                                                                    // 906
                                                                                                      // 907
                                                                                                      // 908
LocalCollection._findInOrderedResults = function (query, doc) {                                       // 909
  if (!query.ordered)                                                                                 // 910
    throw new Error("Can't call _findInOrderedResults on unordered query");                           // 911
  for (var i = 0; i < query.results.length; i++)                                                      // 912
    if (query.results[i] === doc)                                                                     // 913
      return i;                                                                                       // 914
  throw Error("object missing from query");                                                           // 915
};                                                                                                    // 916
                                                                                                      // 917
// This binary search puts a value between any equal values, and the first                            // 918
// lesser value.                                                                                      // 919
LocalCollection._binarySearch = function (cmp, array, value) {                                        // 920
  var first = 0, rangeLength = array.length;                                                          // 921
                                                                                                      // 922
  while (rangeLength > 0) {                                                                           // 923
    var halfRange = Math.floor(rangeLength/2);                                                        // 924
    if (cmp(value, array[first + halfRange]) >= 0) {                                                  // 925
      first += halfRange + 1;                                                                         // 926
      rangeLength -= halfRange + 1;                                                                   // 927
    } else {                                                                                          // 928
      rangeLength = halfRange;                                                                        // 929
    }                                                                                                 // 930
  }                                                                                                   // 931
  return first;                                                                                       // 932
};                                                                                                    // 933
                                                                                                      // 934
LocalCollection._insertInSortedList = function (cmp, array, value) {                                  // 935
  if (array.length === 0) {                                                                           // 936
    array.push(value);                                                                                // 937
    return 0;                                                                                         // 938
  }                                                                                                   // 939
                                                                                                      // 940
  var idx = LocalCollection._binarySearch(cmp, array, value);                                         // 941
  array.splice(idx, 0, value);                                                                        // 942
  return idx;                                                                                         // 943
};                                                                                                    // 944
                                                                                                      // 945
// To track what documents are affected by a piece of code, call saveOriginals()                      // 946
// before it and retrieveOriginals() after it. retrieveOriginals returns an                           // 947
// object whose keys are the ids of the documents that were affected since the                        // 948
// call to saveOriginals(), and the values are equal to the document's contents                       // 949
// at the time of saveOriginals. (In the case of an inserted document, undefined                      // 950
// is the value.) You must alternate between calls to saveOriginals() and                             // 951
// retrieveOriginals().                                                                               // 952
LocalCollection.prototype.saveOriginals = function () {                                               // 953
  var self = this;                                                                                    // 954
  if (self._savedOriginals)                                                                           // 955
    throw new Error("Called saveOriginals twice without retrieveOriginals");                          // 956
  self._savedOriginals = new LocalCollection._IdMap;                                                  // 957
};                                                                                                    // 958
LocalCollection.prototype.retrieveOriginals = function () {                                           // 959
  var self = this;                                                                                    // 960
  if (!self._savedOriginals)                                                                          // 961
    throw new Error("Called retrieveOriginals without saveOriginals");                                // 962
                                                                                                      // 963
  var originals = self._savedOriginals;                                                               // 964
  self._savedOriginals = null;                                                                        // 965
  return originals;                                                                                   // 966
};                                                                                                    // 967
                                                                                                      // 968
LocalCollection.prototype._saveOriginal = function (id, doc) {                                        // 969
  var self = this;                                                                                    // 970
  // Are we even trying to save originals?                                                            // 971
  if (!self._savedOriginals)                                                                          // 972
    return;                                                                                           // 973
  // Have we previously mutated the original (and so 'doc' is not actually                            // 974
  // original)?  (Note the 'has' check rather than truth: we store undefined                          // 975
  // here for inserted docs!)                                                                         // 976
  if (self._savedOriginals.has(id))                                                                   // 977
    return;                                                                                           // 978
  self._savedOriginals.set(id, EJSON.clone(doc));                                                     // 979
};                                                                                                    // 980
                                                                                                      // 981
// Pause the observers. No callbacks from observers will fire until                                   // 982
// 'resumeObservers' is called.                                                                       // 983
LocalCollection.prototype.pauseObservers = function () {                                              // 984
  // No-op if already paused.                                                                         // 985
  if (this.paused)                                                                                    // 986
    return;                                                                                           // 987
                                                                                                      // 988
  // Set the 'paused' flag such that new observer messages don't fire.                                // 989
  this.paused = true;                                                                                 // 990
                                                                                                      // 991
  // Take a snapshot of the query results for each query.                                             // 992
  for (var qid in this.queries) {                                                                     // 993
    var query = this.queries[qid];                                                                    // 994
                                                                                                      // 995
    query.resultsSnapshot = EJSON.clone(query.results);                                               // 996
  }                                                                                                   // 997
};                                                                                                    // 998
                                                                                                      // 999
// Resume the observers. Observers immediately receive change                                         // 1000
// notifications to bring them to the current state of the                                            // 1001
// database. Note that this is not just replaying all the changes that                                // 1002
// happened during the pause, it is a smarter 'coalesced' diff.                                       // 1003
LocalCollection.prototype.resumeObservers = function () {                                             // 1004
  var self = this;                                                                                    // 1005
  // No-op if not paused.                                                                             // 1006
  if (!this.paused)                                                                                   // 1007
    return;                                                                                           // 1008
                                                                                                      // 1009
  // Unset the 'paused' flag. Make sure to do this first, otherwise                                   // 1010
  // observer methods won't actually fire when we trigger them.                                       // 1011
  this.paused = false;                                                                                // 1012
                                                                                                      // 1013
  for (var qid in this.queries) {                                                                     // 1014
    var query = self.queries[qid];                                                                    // 1015
    // Diff the current results against the snapshot and send to observers.                           // 1016
    // pass the query object for its observer callbacks.                                              // 1017
    LocalCollection._diffQueryChanges(                                                                // 1018
      query.ordered, query.resultsSnapshot, query.results, query);                                    // 1019
    query.resultsSnapshot = null;                                                                     // 1020
  }                                                                                                   // 1021
  self._observeQueue.drain();                                                                         // 1022
};                                                                                                    // 1023
                                                                                                      // 1024
                                                                                                      // 1025
// NB: used by livedata                                                                               // 1026
LocalCollection._idStringify = function (id) {                                                        // 1027
  if (id instanceof LocalCollection._ObjectID) {                                                      // 1028
    return id.valueOf();                                                                              // 1029
  } else if (typeof id === 'string') {                                                                // 1030
    if (id === "") {                                                                                  // 1031
      return id;                                                                                      // 1032
    } else if (id.substr(0, 1) === "-" || // escape previously dashed strings                         // 1033
               id.substr(0, 1) === "~" || // escape escaped numbers, true, false                      // 1034
               LocalCollection._looksLikeObjectID(id) || // escape object-id-form strings             // 1035
               id.substr(0, 1) === '{') { // escape object-form strings, for maybe implementing later // 1036
      return "-" + id;                                                                                // 1037
    } else {                                                                                          // 1038
      return id; // other strings go through unchanged.                                               // 1039
    }                                                                                                 // 1040
  } else if (id === undefined) {                                                                      // 1041
    return '-';                                                                                       // 1042
  } else if (typeof id === 'object' && id !== null) {                                                 // 1043
    throw new Error("Meteor does not currently support objects other than ObjectID as ids");          // 1044
  } else { // Numbers, true, false, null                                                              // 1045
    return "~" + JSON.stringify(id);                                                                  // 1046
  }                                                                                                   // 1047
};                                                                                                    // 1048
                                                                                                      // 1049
                                                                                                      // 1050
// NB: used by livedata                                                                               // 1051
LocalCollection._idParse = function (id) {                                                            // 1052
  if (id === "") {                                                                                    // 1053
    return id;                                                                                        // 1054
  } else if (id === '-') {                                                                            // 1055
    return undefined;                                                                                 // 1056
  } else if (id.substr(0, 1) === '-') {                                                               // 1057
    return id.substr(1);                                                                              // 1058
  } else if (id.substr(0, 1) === '~') {                                                               // 1059
    return JSON.parse(id.substr(1));                                                                  // 1060
  } else if (LocalCollection._looksLikeObjectID(id)) {                                                // 1061
    return new LocalCollection._ObjectID(id);                                                         // 1062
  } else {                                                                                            // 1063
    return id;                                                                                        // 1064
  }                                                                                                   // 1065
};                                                                                                    // 1066
                                                                                                      // 1067
LocalCollection._makeChangedFields = function (newDoc, oldDoc) {                                      // 1068
  var fields = {};                                                                                    // 1069
  LocalCollection._diffObjects(oldDoc, newDoc, {                                                      // 1070
    leftOnly: function (key, value) {                                                                 // 1071
      fields[key] = undefined;                                                                        // 1072
    },                                                                                                // 1073
    rightOnly: function (key, value) {                                                                // 1074
      fields[key] = value;                                                                            // 1075
    },                                                                                                // 1076
    both: function (key, leftValue, rightValue) {                                                     // 1077
      if (!EJSON.equals(leftValue, rightValue))                                                       // 1078
        fields[key] = rightValue;                                                                     // 1079
    }                                                                                                 // 1080
  });                                                                                                 // 1081
  return fields;                                                                                      // 1082
};                                                                                                    // 1083
                                                                                                      // 1084
////////////////////////////////////////////////////////////////////////////////////////////////////////

}).call(this);






(function () {

////////////////////////////////////////////////////////////////////////////////////////////////////////
//                                                                                                    //
// packages/minimongo/wrap_transform.js                                                               //
//                                                                                                    //
////////////////////////////////////////////////////////////////////////////////////////////////////////
                                                                                                      //
// Wrap a transform function to return objects that have the _id field                                // 1
// of the untransformed document. This ensures that subsystems such as                                // 2
// the observe-sequence package that call `observe` can keep track of                                 // 3
// the documents identities.                                                                          // 4
//                                                                                                    // 5
// - Require that it returns objects                                                                  // 6
// - If the return value has an _id field, verify that it matches the                                 // 7
//   original _id field                                                                               // 8
// - If the return value doesn't have an _id field, add it back.                                      // 9
LocalCollection.wrapTransform = function (transform) {                                                // 10
  if (!transform)                                                                                     // 11
    return null;                                                                                      // 12
                                                                                                      // 13
  return function (doc) {                                                                             // 14
    if (!_.has(doc, '_id')) {                                                                         // 15
      // XXX do we ever have a transform on the oplog's collection? because that                      // 16
      // collection has no _id.                                                                       // 17
      throw new Error("can only transform documents with _id");                                       // 18
    }                                                                                                 // 19
                                                                                                      // 20
    var id = doc._id;                                                                                 // 21
    // XXX consider making deps a weak dependency and checking Package.deps here                      // 22
    var transformed = Deps.nonreactive(function () {                                                  // 23
      return transform(doc);                                                                          // 24
    });                                                                                               // 25
                                                                                                      // 26
    if (!isPlainObject(transformed)) {                                                                // 27
      throw new Error("transform must return object");                                                // 28
    }                                                                                                 // 29
                                                                                                      // 30
    if (_.has(transformed, '_id')) {                                                                  // 31
      if (!EJSON.equals(transformed._id, id)) {                                                       // 32
        throw new Error("transformed document can't have different _id");                             // 33
      }                                                                                               // 34
    } else {                                                                                          // 35
      transformed._id = id;                                                                           // 36
    }                                                                                                 // 37
    return transformed;                                                                               // 38
  };                                                                                                  // 39
};                                                                                                    // 40
                                                                                                      // 41
                                                                                                      // 42
////////////////////////////////////////////////////////////////////////////////////////////////////////

}).call(this);






(function () {

////////////////////////////////////////////////////////////////////////////////////////////////////////
//                                                                                                    //
// packages/minimongo/helpers.js                                                                      //
//                                                                                                    //
////////////////////////////////////////////////////////////////////////////////////////////////////////
                                                                                                      //
// Like _.isArray, but doesn't regard polyfilled Uint8Arrays on old browsers as                       // 1
// arrays.                                                                                            // 2
// XXX maybe this should be EJSON.isArray                                                             // 3
isArray = function (x) {                                                                              // 4
  return _.isArray(x) && !EJSON.isBinary(x);                                                          // 5
};                                                                                                    // 6
                                                                                                      // 7
// XXX maybe this should be EJSON.isObject, though EJSON doesn't know about                           // 8
// RegExp                                                                                             // 9
// XXX note that _type(undefined) === 3!!!!                                                           // 10
isPlainObject = LocalCollection._isPlainObject = function (x) {                                       // 11
  return x && LocalCollection._f._type(x) === 3;                                                      // 12
};                                                                                                    // 13
                                                                                                      // 14
isIndexable = function (x) {                                                                          // 15
  return isArray(x) || isPlainObject(x);                                                              // 16
};                                                                                                    // 17
                                                                                                      // 18
// Returns true if this is an object with at least one key and all keys begin                         // 19
// with $.  Unless inconsistentOK is set, throws if some keys begin with $ and                        // 20
// others don't.                                                                                      // 21
isOperatorObject = function (valueSelector, inconsistentOK) {                                         // 22
  if (!isPlainObject(valueSelector))                                                                  // 23
    return false;                                                                                     // 24
                                                                                                      // 25
  var theseAreOperators = undefined;                                                                  // 26
  _.each(valueSelector, function (value, selKey) {                                                    // 27
    var thisIsOperator = selKey.substr(0, 1) === '$';                                                 // 28
    if (theseAreOperators === undefined) {                                                            // 29
      theseAreOperators = thisIsOperator;                                                             // 30
    } else if (theseAreOperators !== thisIsOperator) {                                                // 31
      if (!inconsistentOK)                                                                            // 32
        throw new Error("Inconsistent operator: " +                                                   // 33
                        JSON.stringify(valueSelector));                                               // 34
      theseAreOperators = false;                                                                      // 35
    }                                                                                                 // 36
  });                                                                                                 // 37
  return !!theseAreOperators;  // {} has no operators                                                 // 38
};                                                                                                    // 39
                                                                                                      // 40
                                                                                                      // 41
// string can be converted to integer                                                                 // 42
isNumericKey = function (s) {                                                                         // 43
  return /^[0-9]+$/.test(s);                                                                          // 44
};                                                                                                    // 45
                                                                                                      // 46
////////////////////////////////////////////////////////////////////////////////////////////////////////

}).call(this);






(function () {

////////////////////////////////////////////////////////////////////////////////////////////////////////
//                                                                                                    //
// packages/minimongo/selector.js                                                                     //
//                                                                                                    //
////////////////////////////////////////////////////////////////////////////////////////////////////////
                                                                                                      //
// The minimongo selector compiler!                                                                   // 1
                                                                                                      // 2
// Terminology:                                                                                       // 3
//  - a "selector" is the EJSON object representing a selector                                        // 4
//  - a "matcher" is its compiled form (whether a full Minimongo.Matcher                              // 5
//    object or one of the component lambdas that matches parts of it)                                // 6
//  - a "result object" is an object with a "result" field and maybe                                  // 7
//    distance and arrayIndices.                                                                      // 8
//  - a "branched value" is an object with a "value" field and maybe                                  // 9
//    "dontIterate" and "arrayIndices".                                                               // 10
//  - a "document" is a top-level object that can be stored in a collection.                          // 11
//  - a "lookup function" is a function that takes in a document and returns                          // 12
//    an array of "branched values".                                                                  // 13
//  - a "branched matcher" maps from an array of branched values to a result                          // 14
//    object.                                                                                         // 15
//  - an "element matcher" maps from a single value to a bool.                                        // 16
                                                                                                      // 17
// Main entry point.                                                                                  // 18
//   var matcher = new Minimongo.Matcher({a: {$gt: 5}});                                              // 19
//   if (matcher.documentMatches({a: 7})) ...                                                         // 20
Minimongo.Matcher = function (selector) {                                                             // 21
  var self = this;                                                                                    // 22
  // A set (object mapping string -> *) of all of the document paths looked                           // 23
  // at by the selector. Also includes the empty string if it may look at any                         // 24
  // path (eg, $where).                                                                               // 25
  self._paths = {};                                                                                   // 26
  // Set to true if compilation finds a $near.                                                        // 27
  self._hasGeoQuery = false;                                                                          // 28
  // Set to true if compilation finds a $where.                                                       // 29
  self._hasWhere = false;                                                                             // 30
  // Set to false if compilation finds anything other than a simple equality or                       // 31
  // one or more of '$gt', '$gte', '$lt', '$lte', '$ne', '$in', '$nin' used with                      // 32
  // scalars as operands.                                                                             // 33
  self._isSimple = true;                                                                              // 34
  // Set to a dummy document which always matches this Matcher. Or set to null                        // 35
  // if such document is too hard to find.                                                            // 36
  self._matchingDocument = undefined;                                                                 // 37
  // A clone of the original selector. It may just be a function if the user                          // 38
  // passed in a function; otherwise is definitely an object (eg, IDs are                             // 39
  // translated into {_id: ID} first. Used by canBecomeTrueByModifier and                             // 40
  // Sorter._useWithMatcher.                                                                          // 41
  self._selector = null;                                                                              // 42
  self._docMatcher = self._compileSelector(selector);                                                 // 43
};                                                                                                    // 44
                                                                                                      // 45
_.extend(Minimongo.Matcher.prototype, {                                                               // 46
  documentMatches: function (doc) {                                                                   // 47
    if (!doc || typeof doc !== "object") {                                                            // 48
      throw Error("documentMatches needs a document");                                                // 49
    }                                                                                                 // 50
    return this._docMatcher(doc);                                                                     // 51
  },                                                                                                  // 52
  hasGeoQuery: function () {                                                                          // 53
    return this._hasGeoQuery;                                                                         // 54
  },                                                                                                  // 55
  hasWhere: function () {                                                                             // 56
    return this._hasWhere;                                                                            // 57
  },                                                                                                  // 58
  isSimple: function () {                                                                             // 59
    return this._isSimple;                                                                            // 60
  },                                                                                                  // 61
                                                                                                      // 62
  // Given a selector, return a function that takes one argument, a                                   // 63
  // document. It returns a result object.                                                            // 64
  _compileSelector: function (selector) {                                                             // 65
    var self = this;                                                                                  // 66
    // you can pass a literal function instead of a selector                                          // 67
    if (selector instanceof Function) {                                                               // 68
      self._isSimple = false;                                                                         // 69
      self._selector = selector;                                                                      // 70
      self._recordPathUsed('');                                                                       // 71
      return function (doc) {                                                                         // 72
        return {result: !!selector.call(doc)};                                                        // 73
      };                                                                                              // 74
    }                                                                                                 // 75
                                                                                                      // 76
    // shorthand -- scalars match _id                                                                 // 77
    if (LocalCollection._selectorIsId(selector)) {                                                    // 78
      self._selector = {_id: selector};                                                               // 79
      self._recordPathUsed('_id');                                                                    // 80
      return function (doc) {                                                                         // 81
        return {result: EJSON.equals(doc._id, selector)};                                             // 82
      };                                                                                              // 83
    }                                                                                                 // 84
                                                                                                      // 85
    // protect against dangerous selectors.  falsey and {_id: falsey} are both                        // 86
    // likely programmer error, and not what you want, particularly for                               // 87
    // destructive operations.                                                                        // 88
    if (!selector || (('_id' in selector) && !selector._id)) {                                        // 89
      self._isSimple = false;                                                                         // 90
      return nothingMatcher;                                                                          // 91
    }                                                                                                 // 92
                                                                                                      // 93
    // Top level can't be an array or true or binary.                                                 // 94
    if (typeof(selector) === 'boolean' || isArray(selector) ||                                        // 95
        EJSON.isBinary(selector))                                                                     // 96
      throw new Error("Invalid selector: " + selector);                                               // 97
                                                                                                      // 98
    self._selector = EJSON.clone(selector);                                                           // 99
    return compileDocumentSelector(selector, self, {isRoot: true});                                   // 100
  },                                                                                                  // 101
  _recordPathUsed: function (path) {                                                                  // 102
    this._paths[path] = true;                                                                         // 103
  },                                                                                                  // 104
  // Returns a list of key paths the given selector is looking for. It includes                       // 105
  // the empty string if there is a $where.                                                           // 106
  _getPaths: function () {                                                                            // 107
    return _.keys(this._paths);                                                                       // 108
  }                                                                                                   // 109
});                                                                                                   // 110
                                                                                                      // 111
                                                                                                      // 112
// Takes in a selector that could match a full document (eg, the original                             // 113
// selector). Returns a function mapping document->result object.                                     // 114
//                                                                                                    // 115
// matcher is the Matcher object we are compiling.                                                    // 116
//                                                                                                    // 117
// If this is the root document selector (ie, not wrapped in $and or the like),                       // 118
// then isRoot is true. (This is used by $near.)                                                      // 119
var compileDocumentSelector = function (docSelector, matcher, options) {                              // 120
  options = options || {};                                                                            // 121
  var docMatchers = [];                                                                               // 122
  _.each(docSelector, function (subSelector, key) {                                                   // 123
    if (key.substr(0, 1) === '$') {                                                                   // 124
      // Outer operators are either logical operators (they recurse back into                         // 125
      // this function), or $where.                                                                   // 126
      if (!_.has(LOGICAL_OPERATORS, key))                                                             // 127
        throw new Error("Unrecognized logical operator: " + key);                                     // 128
      matcher._isSimple = false;                                                                      // 129
      docMatchers.push(LOGICAL_OPERATORS[key](subSelector, matcher,                                   // 130
                                              options.inElemMatch));                                  // 131
    } else {                                                                                          // 132
      // Record this path, but only if we aren't in an elemMatcher, since in an                       // 133
      // elemMatch this is a path inside an object in an array, not in the doc                        // 134
      // root.                                                                                        // 135
      if (!options.inElemMatch)                                                                       // 136
        matcher._recordPathUsed(key);                                                                 // 137
      var lookUpByIndex = makeLookupFunction(key);                                                    // 138
      var valueMatcher =                                                                              // 139
        compileValueSelector(subSelector, matcher, options.isRoot);                                   // 140
      docMatchers.push(function (doc) {                                                               // 141
        var branchValues = lookUpByIndex(doc);                                                        // 142
        return valueMatcher(branchValues);                                                            // 143
      });                                                                                             // 144
    }                                                                                                 // 145
  });                                                                                                 // 146
                                                                                                      // 147
  return andDocumentMatchers(docMatchers);                                                            // 148
};                                                                                                    // 149
                                                                                                      // 150
// Takes in a selector that could match a key-indexed value in a document; eg,                        // 151
// {$gt: 5, $lt: 9}, or a regular expression, or any non-expression object (to                        // 152
// indicate equality).  Returns a branched matcher: a function mapping                                // 153
// [branched value]->result object.                                                                   // 154
var compileValueSelector = function (valueSelector, matcher, isRoot) {                                // 155
  if (valueSelector instanceof RegExp) {                                                              // 156
    matcher._isSimple = false;                                                                        // 157
    return convertElementMatcherToBranchedMatcher(                                                    // 158
      regexpElementMatcher(valueSelector));                                                           // 159
  } else if (isOperatorObject(valueSelector)) {                                                       // 160
    return operatorBranchedMatcher(valueSelector, matcher, isRoot);                                   // 161
  } else {                                                                                            // 162
    return convertElementMatcherToBranchedMatcher(                                                    // 163
      equalityElementMatcher(valueSelector));                                                         // 164
  }                                                                                                   // 165
};                                                                                                    // 166
                                                                                                      // 167
// Given an element matcher (which evaluates a single value), returns a branched                      // 168
// value (which evaluates the element matcher on all the branches and returns a                       // 169
// more structured return value possibly including arrayIndices).                                     // 170
var convertElementMatcherToBranchedMatcher = function (                                               // 171
    elementMatcher, options) {                                                                        // 172
  options = options || {};                                                                            // 173
  return function (branches) {                                                                        // 174
    var expanded = branches;                                                                          // 175
    if (!options.dontExpandLeafArrays) {                                                              // 176
      expanded = expandArraysInBranches(                                                              // 177
        branches, options.dontIncludeLeafArrays);                                                     // 178
    }                                                                                                 // 179
    var ret = {};                                                                                     // 180
    ret.result = _.any(expanded, function (element) {                                                 // 181
      var matched = elementMatcher(element.value);                                                    // 182
                                                                                                      // 183
      // Special case for $elemMatch: it means "true, and use this as an array                        // 184
      // index if I didn't already have one".                                                         // 185
      if (typeof matched === 'number') {                                                              // 186
        // XXX This code dates from when we only stored a single array index                          // 187
        // (for the outermost array). Should we be also including deeper array                        // 188
        // indices from the $elemMatch match?                                                         // 189
        if (!element.arrayIndices)                                                                    // 190
          element.arrayIndices = [matched];                                                           // 191
        matched = true;                                                                               // 192
      }                                                                                               // 193
                                                                                                      // 194
      // If some element matched, and it's tagged with array indices, include                         // 195
      // those indices in our result object.                                                          // 196
      if (matched && element.arrayIndices)                                                            // 197
        ret.arrayIndices = element.arrayIndices;                                                      // 198
                                                                                                      // 199
      return matched;                                                                                 // 200
    });                                                                                               // 201
    return ret;                                                                                       // 202
  };                                                                                                  // 203
};                                                                                                    // 204
                                                                                                      // 205
// Takes a RegExp object and returns an element matcher.                                              // 206
regexpElementMatcher = function (regexp) {                                                            // 207
  return function (value) {                                                                           // 208
    if (value instanceof RegExp) {                                                                    // 209
      // Comparing two regexps means seeing if the regexps are identical                              // 210
      // (really!). Underscore knows how.                                                             // 211
      return _.isEqual(value, regexp);                                                                // 212
    }                                                                                                 // 213
    // Regexps only work against strings.                                                             // 214
    if (typeof value !== 'string')                                                                    // 215
      return false;                                                                                   // 216
    return regexp.test(value);                                                                        // 217
  };                                                                                                  // 218
};                                                                                                    // 219
                                                                                                      // 220
// Takes something that is not an operator object and returns an element matcher                      // 221
// for equality with that thing.                                                                      // 222
equalityElementMatcher = function (elementSelector) {                                                 // 223
  if (isOperatorObject(elementSelector))                                                              // 224
    throw Error("Can't create equalityValueSelector for operator object");                            // 225
                                                                                                      // 226
  // Special-case: null and undefined are equal (if you got undefined in there                        // 227
  // somewhere, or if you got it due to some branch being non-existent in the                         // 228
  // weird special case), even though they aren't with EJSON.equals.                                  // 229
  if (elementSelector == null) {  // undefined or null                                                // 230
    return function (value) {                                                                         // 231
      return value == null;  // undefined or null                                                     // 232
    };                                                                                                // 233
  }                                                                                                   // 234
                                                                                                      // 235
  return function (value) {                                                                           // 236
    return LocalCollection._f._equal(elementSelector, value);                                         // 237
  };                                                                                                  // 238
};                                                                                                    // 239
                                                                                                      // 240
// Takes an operator object (an object with $ keys) and returns a branched                            // 241
// matcher for it.                                                                                    // 242
var operatorBranchedMatcher = function (valueSelector, matcher, isRoot) {                             // 243
  // Each valueSelector works separately on the various branches.  So one                             // 244
  // operator can match one branch and another can match another branch.  This                        // 245
  // is OK.                                                                                           // 246
                                                                                                      // 247
  var operatorMatchers = [];                                                                          // 248
  _.each(valueSelector, function (operand, operator) {                                                // 249
    // XXX we should actually implement $eq, which is new in 2.6                                      // 250
    var simpleRange = _.contains(['$lt', '$lte', '$gt', '$gte'], operator) &&                         // 251
      _.isNumber(operand);                                                                            // 252
    var simpleInequality = operator === '$ne' && !_.isObject(operand);                                // 253
    var simpleInclusion = _.contains(['$in', '$nin'], operator) &&                                    // 254
      _.isArray(operand) && !_.any(operand, _.isObject);                                              // 255
                                                                                                      // 256
    if (! (operator === '$eq' || simpleRange ||                                                       // 257
           simpleInclusion || simpleInequality)) {                                                    // 258
      matcher._isSimple = false;                                                                      // 259
    }                                                                                                 // 260
                                                                                                      // 261
    if (_.has(VALUE_OPERATORS, operator)) {                                                           // 262
      operatorMatchers.push(                                                                          // 263
        VALUE_OPERATORS[operator](operand, valueSelector, matcher, isRoot));                          // 264
    } else if (_.has(ELEMENT_OPERATORS, operator)) {                                                  // 265
      var options = ELEMENT_OPERATORS[operator];                                                      // 266
      operatorMatchers.push(                                                                          // 267
        convertElementMatcherToBranchedMatcher(                                                       // 268
          options.compileElementSelector(                                                             // 269
            operand, valueSelector, matcher),                                                         // 270
          options));                                                                                  // 271
    } else {                                                                                          // 272
      throw new Error("Unrecognized operator: " + operator);                                          // 273
    }                                                                                                 // 274
  });                                                                                                 // 275
                                                                                                      // 276
  return andBranchedMatchers(operatorMatchers);                                                       // 277
};                                                                                                    // 278
                                                                                                      // 279
var compileArrayOfDocumentSelectors = function (                                                      // 280
    selectors, matcher, inElemMatch) {                                                                // 281
  if (!isArray(selectors) || _.isEmpty(selectors))                                                    // 282
    throw Error("$and/$or/$nor must be nonempty array");                                              // 283
  return _.map(selectors, function (subSelector) {                                                    // 284
    if (!isPlainObject(subSelector))                                                                  // 285
      throw Error("$or/$and/$nor entries need to be full objects");                                   // 286
    return compileDocumentSelector(                                                                   // 287
      subSelector, matcher, {inElemMatch: inElemMatch});                                              // 288
  });                                                                                                 // 289
};                                                                                                    // 290
                                                                                                      // 291
// Operators that appear at the top level of a document selector.                                     // 292
var LOGICAL_OPERATORS = {                                                                             // 293
  $and: function (subSelector, matcher, inElemMatch) {                                                // 294
    var matchers = compileArrayOfDocumentSelectors(                                                   // 295
      subSelector, matcher, inElemMatch);                                                             // 296
    return andDocumentMatchers(matchers);                                                             // 297
  },                                                                                                  // 298
                                                                                                      // 299
  $or: function (subSelector, matcher, inElemMatch) {                                                 // 300
    var matchers = compileArrayOfDocumentSelectors(                                                   // 301
      subSelector, matcher, inElemMatch);                                                             // 302
                                                                                                      // 303
    // Special case: if there is only one matcher, use it directly, *preserving*                      // 304
    // any arrayIndices it returns.                                                                   // 305
    if (matchers.length === 1)                                                                        // 306
      return matchers[0];                                                                             // 307
                                                                                                      // 308
    return function (doc) {                                                                           // 309
      var result = _.any(matchers, function (f) {                                                     // 310
        return f(doc).result;                                                                         // 311
      });                                                                                             // 312
      // $or does NOT set arrayIndices when it has multiple                                           // 313
      // sub-expressions. (Tested against MongoDB.)                                                   // 314
      return {result: result};                                                                        // 315
    };                                                                                                // 316
  },                                                                                                  // 317
                                                                                                      // 318
  $nor: function (subSelector, matcher, inElemMatch) {                                                // 319
    var matchers = compileArrayOfDocumentSelectors(                                                   // 320
      subSelector, matcher, inElemMatch);                                                             // 321
    return function (doc) {                                                                           // 322
      var result = _.all(matchers, function (f) {                                                     // 323
        return !f(doc).result;                                                                        // 324
      });                                                                                             // 325
      // Never set arrayIndices, because we only match if nothing in particular                       // 326
      // "matched" (and because this is consistent with MongoDB).                                     // 327
      return {result: result};                                                                        // 328
    };                                                                                                // 329
  },                                                                                                  // 330
                                                                                                      // 331
  $where: function (selectorValue, matcher) {                                                         // 332
    // Record that *any* path may be used.                                                            // 333
    matcher._recordPathUsed('');                                                                      // 334
    matcher._hasWhere = true;                                                                         // 335
    if (!(selectorValue instanceof Function)) {                                                       // 336
      // XXX MongoDB seems to have more complex logic to decide where or or not                       // 337
      // to add "return"; not sure exactly what it is.                                                // 338
      selectorValue = Function("obj", "return " + selectorValue);                                     // 339
    }                                                                                                 // 340
    return function (doc) {                                                                           // 341
      // We make the document available as both `this` and `obj`.                                     // 342
      // XXX not sure what we should do if this throws                                                // 343
      return {result: selectorValue.call(doc, doc)};                                                  // 344
    };                                                                                                // 345
  },                                                                                                  // 346
                                                                                                      // 347
  // This is just used as a comment in the query (in MongoDB, it also ends up in                      // 348
  // query logs); it has no effect on the actual selection.                                           // 349
  $comment: function () {                                                                             // 350
    return function () {                                                                              // 351
      return {result: true};                                                                          // 352
    };                                                                                                // 353
  }                                                                                                   // 354
};                                                                                                    // 355
                                                                                                      // 356
// Returns a branched matcher that matches iff the given matcher does not.                            // 357
// Note that this implicitly "deMorganizes" the wrapped function.  ie, it                             // 358
// means that ALL branch values need to fail to match innerBranchedMatcher.                           // 359
var invertBranchedMatcher = function (branchedMatcher) {                                              // 360
  return function (branchValues) {                                                                    // 361
    var invertMe = branchedMatcher(branchValues);                                                     // 362
    // We explicitly choose to strip arrayIndices here: it doesn't make sense to                      // 363
    // say "update the array element that does not match something", at least                         // 364
    // in mongo-land.                                                                                 // 365
    return {result: !invertMe.result};                                                                // 366
  };                                                                                                  // 367
};                                                                                                    // 368
                                                                                                      // 369
// Operators that (unlike LOGICAL_OPERATORS) pertain to individual paths in a                         // 370
// document, but (unlike ELEMENT_OPERATORS) do not have a simple definition as                        // 371
// "match each branched value independently and combine with                                          // 372
// convertElementMatcherToBranchedMatcher".                                                           // 373
var VALUE_OPERATORS = {                                                                               // 374
  $not: function (operand, valueSelector, matcher) {                                                  // 375
    return invertBranchedMatcher(compileValueSelector(operand, matcher));                             // 376
  },                                                                                                  // 377
  $ne: function (operand) {                                                                           // 378
    return invertBranchedMatcher(convertElementMatcherToBranchedMatcher(                              // 379
      equalityElementMatcher(operand)));                                                              // 380
  },                                                                                                  // 381
  $nin: function (operand) {                                                                          // 382
    return invertBranchedMatcher(convertElementMatcherToBranchedMatcher(                              // 383
      ELEMENT_OPERATORS.$in.compileElementSelector(operand)));                                        // 384
  },                                                                                                  // 385
  $exists: function (operand) {                                                                       // 386
    var exists = convertElementMatcherToBranchedMatcher(function (value) {                            // 387
      return value !== undefined;                                                                     // 388
    });                                                                                               // 389
    return operand ? exists : invertBranchedMatcher(exists);                                          // 390
  },                                                                                                  // 391
  // $options just provides options for $regex; its logic is inside $regex                            // 392
  $options: function (operand, valueSelector) {                                                       // 393
    if (!_.has(valueSelector, '$regex'))                                                              // 394
      throw Error("$options needs a $regex");                                                         // 395
    return everythingMatcher;                                                                         // 396
  },                                                                                                  // 397
  // $maxDistance is basically an argument to $near                                                   // 398
  $maxDistance: function (operand, valueSelector) {                                                   // 399
    if (!valueSelector.$near)                                                                         // 400
      throw Error("$maxDistance needs a $near");                                                      // 401
    return everythingMatcher;                                                                         // 402
  },                                                                                                  // 403
  $all: function (operand, valueSelector, matcher) {                                                  // 404
    if (!isArray(operand))                                                                            // 405
      throw Error("$all requires array");                                                             // 406
    // Not sure why, but this seems to be what MongoDB does.                                          // 407
    if (_.isEmpty(operand))                                                                           // 408
      return nothingMatcher;                                                                          // 409
                                                                                                      // 410
    var branchedMatchers = [];                                                                        // 411
    _.each(operand, function (criterion) {                                                            // 412
      // XXX handle $all/$elemMatch combination                                                       // 413
      if (isOperatorObject(criterion))                                                                // 414
        throw Error("no $ expressions in $all");                                                      // 415
      // This is always a regexp or equality selector.                                                // 416
      branchedMatchers.push(compileValueSelector(criterion, matcher));                                // 417
    });                                                                                               // 418
    // andBranchedMatchers does NOT require all selectors to return true on the                       // 419
    // SAME branch.                                                                                   // 420
    return andBranchedMatchers(branchedMatchers);                                                     // 421
  },                                                                                                  // 422
  $near: function (operand, valueSelector, matcher, isRoot) {                                         // 423
    if (!isRoot)                                                                                      // 424
      throw Error("$near can't be inside another $ operator");                                        // 425
    matcher._hasGeoQuery = true;                                                                      // 426
                                                                                                      // 427
    // There are two kinds of geodata in MongoDB: coordinate pairs and                                // 428
    // GeoJSON. They use different distance metrics, too. GeoJSON queries are                         // 429
    // marked with a $geometry property.                                                              // 430
                                                                                                      // 431
    var maxDistance, point, distance;                                                                 // 432
    if (isPlainObject(operand) && _.has(operand, '$geometry')) {                                      // 433
      // GeoJSON "2dsphere" mode.                                                                     // 434
      maxDistance = operand.$maxDistance;                                                             // 435
      point = operand.$geometry;                                                                      // 436
      distance = function (value) {                                                                   // 437
        // XXX: for now, we don't calculate the actual distance between, say,                         // 438
        // polygon and circle. If people care about this use-case it will get                         // 439
        // a priority.                                                                                // 440
        if (!value || !value.type)                                                                    // 441
          return null;                                                                                // 442
        if (value.type === "Point") {                                                                 // 443
          return GeoJSON.pointDistance(point, value);                                                 // 444
        } else {                                                                                      // 445
          return GeoJSON.geometryWithinRadius(value, point, maxDistance)                              // 446
            ? 0 : maxDistance + 1;                                                                    // 447
        }                                                                                             // 448
      };                                                                                              // 449
    } else {                                                                                          // 450
      maxDistance = valueSelector.$maxDistance;                                                       // 451
      if (!isArray(operand) && !isPlainObject(operand))                                               // 452
        throw Error("$near argument must be coordinate pair or GeoJSON");                             // 453
      point = pointToArray(operand);                                                                  // 454
      distance = function (value) {                                                                   // 455
        if (!isArray(value) && !isPlainObject(value))                                                 // 456
          return null;                                                                                // 457
        return distanceCoordinatePairs(point, value);                                                 // 458
      };                                                                                              // 459
    }                                                                                                 // 460
                                                                                                      // 461
    return function (branchedValues) {                                                                // 462
      // There might be multiple points in the document that match the given                          // 463
      // field. Only one of them needs to be within $maxDistance, but we need to                      // 464
      // evaluate all of them and use the nearest one for the implicit sort                           // 465
      // specifier. (That's why we can't just use ELEMENT_OPERATORS here.)                            // 466
      //                                                                                              // 467
      // Note: This differs from MongoDB's implementation, where a document will                      // 468
      // actually show up *multiple times* in the result set, with one entry for                      // 469
      // each within-$maxDistance branching point.                                                    // 470
      branchedValues = expandArraysInBranches(branchedValues);                                        // 471
      var result = {result: false};                                                                   // 472
      _.each(branchedValues, function (branch) {                                                      // 473
        var curDistance = distance(branch.value);                                                     // 474
        // Skip branches that aren't real points or are too far away.                                 // 475
        if (curDistance === null || curDistance > maxDistance)                                        // 476
          return;                                                                                     // 477
        // Skip anything that's a tie.                                                                // 478
        if (result.distance !== undefined && result.distance <= curDistance)                          // 479
          return;                                                                                     // 480
        result.result = true;                                                                         // 481
        result.distance = curDistance;                                                                // 482
        if (!branch.arrayIndices)                                                                     // 483
          delete result.arrayIndices;                                                                 // 484
        else                                                                                          // 485
          result.arrayIndices = branch.arrayIndices;                                                  // 486
      });                                                                                             // 487
      return result;                                                                                  // 488
    };                                                                                                // 489
  }                                                                                                   // 490
};                                                                                                    // 491
                                                                                                      // 492
// Helpers for $near.                                                                                 // 493
var distanceCoordinatePairs = function (a, b) {                                                       // 494
  a = pointToArray(a);                                                                                // 495
  b = pointToArray(b);                                                                                // 496
  var x = a[0] - b[0];                                                                                // 497
  var y = a[1] - b[1];                                                                                // 498
  if (_.isNaN(x) || _.isNaN(y))                                                                       // 499
    return null;                                                                                      // 500
  return Math.sqrt(x * x + y * y);                                                                    // 501
};                                                                                                    // 502
// Makes sure we get 2 elements array and assume the first one to be x and                            // 503
// the second one to y no matter what user passes.                                                    // 504
// In case user passes { lon: x, lat: y } returns [x, y]                                              // 505
var pointToArray = function (point) {                                                                 // 506
  return _.map(point, _.identity);                                                                    // 507
};                                                                                                    // 508
                                                                                                      // 509
// Helper for $lt/$gt/$lte/$gte.                                                                      // 510
var makeInequality = function (cmpValueComparator) {                                                  // 511
  return {                                                                                            // 512
    compileElementSelector: function (operand) {                                                      // 513
      // Arrays never compare false with non-arrays for any inequality.                               // 514
      // XXX This was behavior we observed in pre-release MongoDB 2.5, but                            // 515
      //     it seems to have been reverted.                                                          // 516
      //     See https://jira.mongodb.org/browse/SERVER-11444                                         // 517
      if (isArray(operand)) {                                                                         // 518
        return function () {                                                                          // 519
          return false;                                                                               // 520
        };                                                                                            // 521
      }                                                                                               // 522
                                                                                                      // 523
      // Special case: consider undefined and null the same (so true with                             // 524
      // $gte/$lte).                                                                                  // 525
      if (operand === undefined)                                                                      // 526
        operand = null;                                                                               // 527
                                                                                                      // 528
      var operandType = LocalCollection._f._type(operand);                                            // 529
                                                                                                      // 530
      return function (value) {                                                                       // 531
        if (value === undefined)                                                                      // 532
          value = null;                                                                               // 533
        // Comparisons are never true among things of different type (except                          // 534
        // null vs undefined).                                                                        // 535
        if (LocalCollection._f._type(value) !== operandType)                                          // 536
          return false;                                                                               // 537
        return cmpValueComparator(LocalCollection._f._cmp(value, operand));                           // 538
      };                                                                                              // 539
    }                                                                                                 // 540
  };                                                                                                  // 541
};                                                                                                    // 542
                                                                                                      // 543
// Each element selector contains:                                                                    // 544
//  - compileElementSelector, a function with args:                                                   // 545
//    - operand - the "right hand side" of the operator                                               // 546
//    - valueSelector - the "context" for the operator (so that $regex can find                       // 547
//      $options)                                                                                     // 548
//    - matcher - the Matcher this is going into (so that $elemMatch can compile                      // 549
//      more things)                                                                                  // 550
//    returning a function mapping a single value to bool.                                            // 551
//  - dontExpandLeafArrays, a bool which prevents expandArraysInBranches from                         // 552
//    being called                                                                                    // 553
//  - dontIncludeLeafArrays, a bool which causes an argument to be passed to                          // 554
//    expandArraysInBranches if it is called                                                          // 555
ELEMENT_OPERATORS = {                                                                                 // 556
  $lt: makeInequality(function (cmpValue) {                                                           // 557
    return cmpValue < 0;                                                                              // 558
  }),                                                                                                 // 559
  $gt: makeInequality(function (cmpValue) {                                                           // 560
    return cmpValue > 0;                                                                              // 561
  }),                                                                                                 // 562
  $lte: makeInequality(function (cmpValue) {                                                          // 563
    return cmpValue <= 0;                                                                             // 564
  }),                                                                                                 // 565
  $gte: makeInequality(function (cmpValue) {                                                          // 566
    return cmpValue >= 0;                                                                             // 567
  }),                                                                                                 // 568
  $mod: {                                                                                             // 569
    compileElementSelector: function (operand) {                                                      // 570
      if (!(isArray(operand) && operand.length === 2                                                  // 571
            && typeof(operand[0]) === 'number'                                                        // 572
            && typeof(operand[1]) === 'number')) {                                                    // 573
        throw Error("argument to $mod must be an array of two numbers");                              // 574
      }                                                                                               // 575
      // XXX could require to be ints or round or something                                           // 576
      var divisor = operand[0];                                                                       // 577
      var remainder = operand[1];                                                                     // 578
      return function (value) {                                                                       // 579
        return typeof value === 'number' && value % divisor === remainder;                            // 580
      };                                                                                              // 581
    }                                                                                                 // 582
  },                                                                                                  // 583
  $in: {                                                                                              // 584
    compileElementSelector: function (operand) {                                                      // 585
      if (!isArray(operand))                                                                          // 586
        throw Error("$in needs an array");                                                            // 587
                                                                                                      // 588
      var elementMatchers = [];                                                                       // 589
      _.each(operand, function (option) {                                                             // 590
        if (option instanceof RegExp)                                                                 // 591
          elementMatchers.push(regexpElementMatcher(option));                                         // 592
        else if (isOperatorObject(option))                                                            // 593
          throw Error("cannot nest $ under $in");                                                     // 594
        else                                                                                          // 595
          elementMatchers.push(equalityElementMatcher(option));                                       // 596
      });                                                                                             // 597
                                                                                                      // 598
      return function (value) {                                                                       // 599
        // Allow {a: {$in: [null]}} to match when 'a' does not exist.                                 // 600
        if (value === undefined)                                                                      // 601
          value = null;                                                                               // 602
        return _.any(elementMatchers, function (e) {                                                  // 603
          return e(value);                                                                            // 604
        });                                                                                           // 605
      };                                                                                              // 606
    }                                                                                                 // 607
  },                                                                                                  // 608
  $size: {                                                                                            // 609
    // {a: [[5, 5]]} must match {a: {$size: 1}} but not {a: {$size: 2}}, so we                        // 610
    // don't want to consider the element [5,5] in the leaf array [[5,5]] as a                        // 611
    // possible value.                                                                                // 612
    dontExpandLeafArrays: true,                                                                       // 613
    compileElementSelector: function (operand) {                                                      // 614
      if (typeof operand === 'string') {                                                              // 615
        // Don't ask me why, but by experimentation, this seems to be what Mongo                      // 616
        // does.                                                                                      // 617
        operand = 0;                                                                                  // 618
      } else if (typeof operand !== 'number') {                                                       // 619
        throw Error("$size needs a number");                                                          // 620
      }                                                                                               // 621
      return function (value) {                                                                       // 622
        return isArray(value) && value.length === operand;                                            // 623
      };                                                                                              // 624
    }                                                                                                 // 625
  },                                                                                                  // 626
  $type: {                                                                                            // 627
    // {a: [5]} must not match {a: {$type: 4}} (4 means array), but it should                         // 628
    // match {a: {$type: 1}} (1 means number), and {a: [[5]]} must match {$a:                         // 629
    // {$type: 4}}. Thus, when we see a leaf array, we *should* expand it but                         // 630
    // should *not* include it itself.                                                                // 631
    dontIncludeLeafArrays: true,                                                                      // 632
    compileElementSelector: function (operand) {                                                      // 633
      if (typeof operand !== 'number')                                                                // 634
        throw Error("$type needs a number");                                                          // 635
      return function (value) {                                                                       // 636
        return value !== undefined                                                                    // 637
          && LocalCollection._f._type(value) === operand;                                             // 638
      };                                                                                              // 639
    }                                                                                                 // 640
  },                                                                                                  // 641
  $regex: {                                                                                           // 642
    compileElementSelector: function (operand, valueSelector) {                                       // 643
      if (!(typeof operand === 'string' || operand instanceof RegExp))                                // 644
        throw Error("$regex has to be a string or RegExp");                                           // 645
                                                                                                      // 646
      var regexp;                                                                                     // 647
      if (valueSelector.$options !== undefined) {                                                     // 648
        // Options passed in $options (even the empty string) always overrides                        // 649
        // options in the RegExp object itself. (See also                                             // 650
        // Meteor.Collection._rewriteSelector.)                                                       // 651
                                                                                                      // 652
        // Be clear that we only support the JS-supported options, not extended                       // 653
        // ones (eg, Mongo supports x and s). Ideally we would implement x and s                      // 654
        // by transforming the regexp, but not today...                                               // 655
        if (/[^gim]/.test(valueSelector.$options))                                                    // 656
          throw new Error("Only the i, m, and g regexp options are supported");                       // 657
                                                                                                      // 658
        var regexSource = operand instanceof RegExp ? operand.source : operand;                       // 659
        regexp = new RegExp(regexSource, valueSelector.$options);                                     // 660
      } else if (operand instanceof RegExp) {                                                         // 661
        regexp = operand;                                                                             // 662
      } else {                                                                                        // 663
        regexp = new RegExp(operand);                                                                 // 664
      }                                                                                               // 665
      return regexpElementMatcher(regexp);                                                            // 666
    }                                                                                                 // 667
  },                                                                                                  // 668
  $elemMatch: {                                                                                       // 669
    dontExpandLeafArrays: true,                                                                       // 670
    compileElementSelector: function (operand, valueSelector, matcher) {                              // 671
      if (!isPlainObject(operand))                                                                    // 672
        throw Error("$elemMatch need an object");                                                     // 673
                                                                                                      // 674
      var subMatcher, isDocMatcher;                                                                   // 675
      if (isOperatorObject(operand, true)) {                                                          // 676
        subMatcher = compileValueSelector(operand, matcher);                                          // 677
        isDocMatcher = false;                                                                         // 678
      } else {                                                                                        // 679
        // This is NOT the same as compileValueSelector(operand), and not just                        // 680
        // because of the slightly different calling convention.                                      // 681
        // {$elemMatch: {x: 3}} means "an element has a field x:3", not                               // 682
        // "consists only of a field x:3". Also, regexps and sub-$ are allowed.                       // 683
        subMatcher = compileDocumentSelector(operand, matcher,                                        // 684
                                             {inElemMatch: true});                                    // 685
        isDocMatcher = true;                                                                          // 686
      }                                                                                               // 687
                                                                                                      // 688
      return function (value) {                                                                       // 689
        if (!isArray(value))                                                                          // 690
          return false;                                                                               // 691
        for (var i = 0; i < value.length; ++i) {                                                      // 692
          var arrayElement = value[i];                                                                // 693
          var arg;                                                                                    // 694
          if (isDocMatcher) {                                                                         // 695
            // We can only match {$elemMatch: {b: 3}} against objects.                                // 696
            // (We can also match against arrays, if there's numeric indices,                         // 697
            // eg {$elemMatch: {'0.b': 3}} or {$elemMatch: {0: 3}}.)                                  // 698
            if (!isPlainObject(arrayElement) && !isArray(arrayElement))                               // 699
              return false;                                                                           // 700
            arg = arrayElement;                                                                       // 701
          } else {                                                                                    // 702
            // dontIterate ensures that {a: {$elemMatch: {$gt: 5}}} matches                           // 703
            // {a: [8]} but not {a: [[8]]}                                                            // 704
            arg = [{value: arrayElement, dontIterate: true}];                                         // 705
          }                                                                                           // 706
          // XXX support $near in $elemMatch by propagating $distance?                                // 707
          if (subMatcher(arg).result)                                                                 // 708
            return i;   // specially understood to mean "use as arrayIndices"                         // 709
        }                                                                                             // 710
        return false;                                                                                 // 711
      };                                                                                              // 712
    }                                                                                                 // 713
  }                                                                                                   // 714
};                                                                                                    // 715
                                                                                                      // 716
// makeLookupFunction(key) returns a lookup function.                                                 // 717
//                                                                                                    // 718
// A lookup function takes in a document and returns an array of matching                             // 719
// branches.  If no arrays are found while looking up the key, this array will                        // 720
// have exactly one branches (possibly 'undefined', if some segment of the key                        // 721
// was not found).                                                                                    // 722
//                                                                                                    // 723
// If arrays are found in the middle, this can have more than one element, since                      // 724
// we "branch". When we "branch", if there are more key segments to look up,                          // 725
// then we only pursue branches that are plain objects (not arrays or scalars).                       // 726
// This means we can actually end up with no branches!                                                // 727
//                                                                                                    // 728
// We do *NOT* branch on arrays that are found at the end (ie, at the last                            // 729
// dotted member of the key). We just return that array; if you want to                               // 730
// effectively "branch" over the array's values, post-process the lookup                              // 731
// function with expandArraysInBranches.                                                              // 732
//                                                                                                    // 733
// Each branch is an object with keys:                                                                // 734
//  - value: the value at the branch                                                                  // 735
//  - dontIterate: an optional bool; if true, it means that 'value' is an array                       // 736
//    that expandArraysInBranches should NOT expand. This specifically happens                        // 737
//    when there is a numeric index in the key, and ensures the                                       // 738
//    perhaps-surprising MongoDB behavior where {'a.0': 5} does NOT                                   // 739
//    match {a: [[5]]}.                                                                               // 740
//  - arrayIndices: if any array indexing was done during lookup (either due to                       // 741
//    explicit numeric indices or implicit branching), this will be an array of                       // 742
//    the array indices used, from outermost to innermost; it is falsey or                            // 743
//    absent if no array index is used. If an explicit numeric index is used,                         // 744
//    the index will be followed in arrayIndices by the string 'x'.                                   // 745
//                                                                                                    // 746
//    Note: arrayIndices is used for two purposes. First, it is used to                               // 747
//    implement the '$' modifier feature, which only ever looks at its first                          // 748
//    element.                                                                                        // 749
//                                                                                                    // 750
//    Second, it is used for sort key generation, which needs to be able to tell                      // 751
//    the difference between different paths. Moreover, it needs to                                   // 752
//    differentiate between explicit and implicit branching, which is why                             // 753
//    there's the somewhat hacky 'x' entry: this means that explicit and                              // 754
//    implicit array lookups will have different full arrayIndices paths. (That                       // 755
//    code only requires that different paths have different arrayIndices; it                         // 756
//    doesn't actually "parse" arrayIndices. As an alternative, arrayIndices                          // 757
//    could contain objects with flags like "implicit", but I think that only                         // 758
//    makes the code surrounding them more complex.)                                                  // 759
//                                                                                                    // 760
//    (By the way, this field ends up getting passed around a lot without                             // 761
//    cloning, so never mutate any arrayIndices field/var in this package!)                           // 762
//                                                                                                    // 763
//                                                                                                    // 764
// At the top level, you may only pass in a plain object or array.                                    // 765
//                                                                                                    // 766
// See the test 'minimongo - lookup' for some examples of what lookup functions                       // 767
// return.                                                                                            // 768
makeLookupFunction = function (key) {                                                                 // 769
  var parts = key.split('.');                                                                         // 770
  var firstPart = parts.length ? parts[0] : '';                                                       // 771
  var firstPartIsNumeric = isNumericKey(firstPart);                                                   // 772
  var lookupRest;                                                                                     // 773
  if (parts.length > 1) {                                                                             // 774
    lookupRest = makeLookupFunction(parts.slice(1).join('.'));                                        // 775
  }                                                                                                   // 776
                                                                                                      // 777
  var elideUnnecessaryFields = function (retVal) {                                                    // 778
    if (!retVal.dontIterate)                                                                          // 779
      delete retVal.dontIterate;                                                                      // 780
    if (retVal.arrayIndices && !retVal.arrayIndices.length)                                           // 781
      delete retVal.arrayIndices;                                                                     // 782
    return retVal;                                                                                    // 783
  };                                                                                                  // 784
                                                                                                      // 785
  // Doc will always be a plain object or an array.                                                   // 786
  // apply an explicit numeric index, an array.                                                       // 787
  return function (doc, arrayIndices) {                                                               // 788
    if (!arrayIndices)                                                                                // 789
      arrayIndices = [];                                                                              // 790
                                                                                                      // 791
    if (isArray(doc)) {                                                                               // 792
      // If we're being asked to do an invalid lookup into an array (non-integer                      // 793
      // or out-of-bounds), return no results (which is different from returning                      // 794
      // a single undefined result, in that `null` equality checks won't match).                      // 795
      if (!(firstPartIsNumeric && firstPart < doc.length))                                            // 796
        return [];                                                                                    // 797
                                                                                                      // 798
      // Remember that we used this array index. Include an 'x' to indicate that                      // 799
      // the previous index came from being considered as an explicit array                           // 800
      // index (not branching).                                                                       // 801
      arrayIndices = arrayIndices.concat(+firstPart, 'x');                                            // 802
    }                                                                                                 // 803
                                                                                                      // 804
    // Do our first lookup.                                                                           // 805
    var firstLevel = doc[firstPart];                                                                  // 806
                                                                                                      // 807
    // If there is no deeper to dig, return what we found.                                            // 808
    //                                                                                                // 809
    // If what we found is an array, most value selectors will choose to treat                        // 810
    // the elements of the array as matchable values in their own right, but                          // 811
    // that's done outside of the lookup function. (Exceptions to this are $size                      // 812
    // and stuff relating to $elemMatch.  eg, {a: {$size: 2}} does not match {a:                      // 813
    // [[1, 2]]}.)                                                                                    // 814
    //                                                                                                // 815
    // That said, if we just did an *explicit* array lookup (on doc) to find                          // 816
    // firstLevel, and firstLevel is an array too, we do NOT want value                               // 817
    // selectors to iterate over it.  eg, {'a.0': 5} does not match {a: [[5]]}.                       // 818
    // So in that case, we mark the return value as "don't iterate".                                  // 819
    if (!lookupRest) {                                                                                // 820
      return [elideUnnecessaryFields({                                                                // 821
        value: firstLevel,                                                                            // 822
        dontIterate: isArray(doc) && isArray(firstLevel),                                             // 823
        arrayIndices: arrayIndices})];                                                                // 824
    }                                                                                                 // 825
                                                                                                      // 826
    // We need to dig deeper.  But if we can't, because what we've found is not                       // 827
    // an array or plain object, we're done. If we just did a numeric index into                      // 828
    // an array, we return nothing here (this is a change in Mongo 2.5 from                           // 829
    // Mongo 2.4, where {'a.0.b': null} stopped matching {a: [5]}). Otherwise,                        // 830
    // return a single `undefined` (which can, for example, match via equality                        // 831
    // with `null`).                                                                                  // 832
    if (!isIndexable(firstLevel)) {                                                                   // 833
      if (isArray(doc))                                                                               // 834
        return [];                                                                                    // 835
      return [elideUnnecessaryFields({value: undefined,                                               // 836
                                      arrayIndices: arrayIndices})];                                  // 837
    }                                                                                                 // 838
                                                                                                      // 839
    var result = [];                                                                                  // 840
    var appendToResult = function (more) {                                                            // 841
      Array.prototype.push.apply(result, more);                                                       // 842
    };                                                                                                // 843
                                                                                                      // 844
    // Dig deeper: look up the rest of the parts on whatever we've found.                             // 845
    // (lookupRest is smart enough to not try to do invalid lookups into                              // 846
    // firstLevel if it's an array.)                                                                  // 847
    appendToResult(lookupRest(firstLevel, arrayIndices));                                             // 848
                                                                                                      // 849
    // If we found an array, then in *addition* to potentially treating the next                      // 850
    // part as a literal integer lookup, we should also "branch": try to look up                      // 851
    // the rest of the parts on each array element in parallel.                                       // 852
    //                                                                                                // 853
    // In this case, we *only* dig deeper into array elements that are plain                          // 854
    // objects. (Recall that we only got this far if we have further to dig.)                         // 855
    // This makes sense: we certainly don't dig deeper into non-indexable                             // 856
    // objects. And it would be weird to dig into an array: it's simpler to have                      // 857
    // a rule that explicit integer indexes only apply to an outer array, not to                      // 858
    // an array you find after a branching search.                                                    // 859
    if (isArray(firstLevel)) {                                                                        // 860
      _.each(firstLevel, function (branch, arrayIndex) {                                              // 861
        if (isPlainObject(branch)) {                                                                  // 862
          appendToResult(lookupRest(                                                                  // 863
            branch,                                                                                   // 864
            arrayIndices.concat(arrayIndex)));                                                        // 865
        }                                                                                             // 866
      });                                                                                             // 867
    }                                                                                                 // 868
                                                                                                      // 869
    return result;                                                                                    // 870
  };                                                                                                  // 871
};                                                                                                    // 872
MinimongoTest.makeLookupFunction = makeLookupFunction;                                                // 873
                                                                                                      // 874
expandArraysInBranches = function (branches, skipTheArrays) {                                         // 875
  var branchesOut = [];                                                                               // 876
  _.each(branches, function (branch) {                                                                // 877
    var thisIsArray = isArray(branch.value);                                                          // 878
    // We include the branch itself, *UNLESS* we it's an array that we're going                       // 879
    // to iterate and we're told to skip arrays.  (That's right, we include some                      // 880
    // arrays even skipTheArrays is true: these are arrays that were found via                        // 881
    // explicit numerical indices.)                                                                   // 882
    if (!(skipTheArrays && thisIsArray && !branch.dontIterate)) {                                     // 883
      branchesOut.push({                                                                              // 884
        value: branch.value,                                                                          // 885
        arrayIndices: branch.arrayIndices                                                             // 886
      });                                                                                             // 887
    }                                                                                                 // 888
    if (thisIsArray && !branch.dontIterate) {                                                         // 889
      _.each(branch.value, function (leaf, i) {                                                       // 890
        branchesOut.push({                                                                            // 891
          value: leaf,                                                                                // 892
          arrayIndices: (branch.arrayIndices || []).concat(i)                                         // 893
        });                                                                                           // 894
      });                                                                                             // 895
    }                                                                                                 // 896
  });                                                                                                 // 897
  return branchesOut;                                                                                 // 898
};                                                                                                    // 899
                                                                                                      // 900
var nothingMatcher = function (docOrBranchedValues) {                                                 // 901
  return {result: false};                                                                             // 902
};                                                                                                    // 903
                                                                                                      // 904
var everythingMatcher = function (docOrBranchedValues) {                                              // 905
  return {result: true};                                                                              // 906
};                                                                                                    // 907
                                                                                                      // 908
                                                                                                      // 909
// NB: We are cheating and using this function to implement "AND" for both                            // 910
// "document matchers" and "branched matchers". They both return result objects                       // 911
// but the argument is different: for the former it's a whole doc, whereas for                        // 912
// the latter it's an array of "branched values".                                                     // 913
var andSomeMatchers = function (subMatchers) {                                                        // 914
  if (subMatchers.length === 0)                                                                       // 915
    return everythingMatcher;                                                                         // 916
  if (subMatchers.length === 1)                                                                       // 917
    return subMatchers[0];                                                                            // 918
                                                                                                      // 919
  return function (docOrBranches) {                                                                   // 920
    var ret = {};                                                                                     // 921
    ret.result = _.all(subMatchers, function (f) {                                                    // 922
      var subResult = f(docOrBranches);                                                               // 923
      // Copy a 'distance' number out of the first sub-matcher that has                               // 924
      // one. Yes, this means that if there are multiple $near fields in a                            // 925
      // query, something arbitrary happens; this appears to be consistent with                       // 926
      // Mongo.                                                                                       // 927
      if (subResult.result && subResult.distance !== undefined                                        // 928
          && ret.distance === undefined) {                                                            // 929
        ret.distance = subResult.distance;                                                            // 930
      }                                                                                               // 931
      // Similarly, propagate arrayIndices from sub-matchers... but to match                          // 932
      // MongoDB behavior, this time the *last* sub-matcher with arrayIndices                         // 933
      // wins.                                                                                        // 934
      if (subResult.result && subResult.arrayIndices) {                                               // 935
        ret.arrayIndices = subResult.arrayIndices;                                                    // 936
      }                                                                                               // 937
      return subResult.result;                                                                        // 938
    });                                                                                               // 939
                                                                                                      // 940
    // If we didn't actually match, forget any extra metadata we came up with.                        // 941
    if (!ret.result) {                                                                                // 942
      delete ret.distance;                                                                            // 943
      delete ret.arrayIndices;                                                                        // 944
    }                                                                                                 // 945
    return ret;                                                                                       // 946
  };                                                                                                  // 947
};                                                                                                    // 948
                                                                                                      // 949
var andDocumentMatchers = andSomeMatchers;                                                            // 950
var andBranchedMatchers = andSomeMatchers;                                                            // 951
                                                                                                      // 952
                                                                                                      // 953
// helpers used by compiled selector code                                                             // 954
LocalCollection._f = {                                                                                // 955
  // XXX for _all and _in, consider building 'inquery' at compile time..                              // 956
                                                                                                      // 957
  _type: function (v) {                                                                               // 958
    if (typeof v === "number")                                                                        // 959
      return 1;                                                                                       // 960
    if (typeof v === "string")                                                                        // 961
      return 2;                                                                                       // 962
    if (typeof v === "boolean")                                                                       // 963
      return 8;                                                                                       // 964
    if (isArray(v))                                                                                   // 965
      return 4;                                                                                       // 966
    if (v === null)                                                                                   // 967
      return 10;                                                                                      // 968
    if (v instanceof RegExp)                                                                          // 969
      // note that typeof(/x/) === "object"                                                           // 970
      return 11;                                                                                      // 971
    if (typeof v === "function")                                                                      // 972
      return 13;                                                                                      // 973
    if (v instanceof Date)                                                                            // 974
      return 9;                                                                                       // 975
    if (EJSON.isBinary(v))                                                                            // 976
      return 5;                                                                                       // 977
    if (v instanceof LocalCollection._ObjectID)                                                       // 978
      return 7;                                                                                       // 979
    return 3; // object                                                                               // 980
                                                                                                      // 981
    // XXX support some/all of these:                                                                 // 982
    // 14, symbol                                                                                     // 983
    // 15, javascript code with scope                                                                 // 984
    // 16, 18: 32-bit/64-bit integer                                                                  // 985
    // 17, timestamp                                                                                  // 986
    // 255, minkey                                                                                    // 987
    // 127, maxkey                                                                                    // 988
  },                                                                                                  // 989
                                                                                                      // 990
  // deep equality test: use for literal document and array matches                                   // 991
  _equal: function (a, b) {                                                                           // 992
    return EJSON.equals(a, b, {keyOrderSensitive: true});                                             // 993
  },                                                                                                  // 994
                                                                                                      // 995
  // maps a type code to a value that can be used to sort values of                                   // 996
  // different types                                                                                  // 997
  _typeorder: function (t) {                                                                          // 998
    // http://www.mongodb.org/display/DOCS/What+is+the+Compare+Order+for+BSON+Types                   // 999
    // XXX what is the correct sort position for Javascript code?                                     // 1000
    // ('100' in the matrix below)                                                                    // 1001
    // XXX minkey/maxkey                                                                              // 1002
    return [-1,  // (not a type)                                                                      // 1003
            1,   // number                                                                            // 1004
            2,   // string                                                                            // 1005
            3,   // object                                                                            // 1006
            4,   // array                                                                             // 1007
            5,   // binary                                                                            // 1008
            -1,  // deprecated                                                                        // 1009
            6,   // ObjectID                                                                          // 1010
            7,   // bool                                                                              // 1011
            8,   // Date                                                                              // 1012
            0,   // null                                                                              // 1013
            9,   // RegExp                                                                            // 1014
            -1,  // deprecated                                                                        // 1015
            100, // JS code                                                                           // 1016
            2,   // deprecated (symbol)                                                               // 1017
            100, // JS code                                                                           // 1018
            1,   // 32-bit int                                                                        // 1019
            8,   // Mongo timestamp                                                                   // 1020
            1    // 64-bit int                                                                        // 1021
           ][t];                                                                                      // 1022
  },                                                                                                  // 1023
                                                                                                      // 1024
  // compare two values of unknown type according to BSON ordering                                    // 1025
  // semantics. (as an extension, consider 'undefined' to be less than                                // 1026
  // any other value.) return negative if a is less, positive if b is                                 // 1027
  // less, or 0 if equal                                                                              // 1028
  _cmp: function (a, b) {                                                                             // 1029
    if (a === undefined)                                                                              // 1030
      return b === undefined ? 0 : -1;                                                                // 1031
    if (b === undefined)                                                                              // 1032
      return 1;                                                                                       // 1033
    var ta = LocalCollection._f._type(a);                                                             // 1034
    var tb = LocalCollection._f._type(b);                                                             // 1035
    var oa = LocalCollection._f._typeorder(ta);                                                       // 1036
    var ob = LocalCollection._f._typeorder(tb);                                                       // 1037
    if (oa !== ob)                                                                                    // 1038
      return oa < ob ? -1 : 1;                                                                        // 1039
    if (ta !== tb)                                                                                    // 1040
      // XXX need to implement this if we implement Symbol or integers, or                            // 1041
      // Timestamp                                                                                    // 1042
      throw Error("Missing type coercion logic in _cmp");                                             // 1043
    if (ta === 7) { // ObjectID                                                                       // 1044
      // Convert to string.                                                                           // 1045
      ta = tb = 2;                                                                                    // 1046
      a = a.toHexString();                                                                            // 1047
      b = b.toHexString();                                                                            // 1048
    }                                                                                                 // 1049
    if (ta === 9) { // Date                                                                           // 1050
      // Convert to millis.                                                                           // 1051
      ta = tb = 1;                                                                                    // 1052
      a = a.getTime();                                                                                // 1053
      b = b.getTime();                                                                                // 1054
    }                                                                                                 // 1055
                                                                                                      // 1056
    if (ta === 1) // double                                                                           // 1057
      return a - b;                                                                                   // 1058
    if (tb === 2) // string                                                                           // 1059
      return a < b ? -1 : (a === b ? 0 : 1);                                                          // 1060
    if (ta === 3) { // Object                                                                         // 1061
      // this could be much more efficient in the expected case ...                                   // 1062
      var to_array = function (obj) {                                                                 // 1063
        var ret = [];                                                                                 // 1064
        for (var key in obj) {                                                                        // 1065
          ret.push(key);                                                                              // 1066
          ret.push(obj[key]);                                                                         // 1067
        }                                                                                             // 1068
        return ret;                                                                                   // 1069
      };                                                                                              // 1070
      return LocalCollection._f._cmp(to_array(a), to_array(b));                                       // 1071
    }                                                                                                 // 1072
    if (ta === 4) { // Array                                                                          // 1073
      for (var i = 0; ; i++) {                                                                        // 1074
        if (i === a.length)                                                                           // 1075
          return (i === b.length) ? 0 : -1;                                                           // 1076
        if (i === b.length)                                                                           // 1077
          return 1;                                                                                   // 1078
        var s = LocalCollection._f._cmp(a[i], b[i]);                                                  // 1079
        if (s !== 0)                                                                                  // 1080
          return s;                                                                                   // 1081
      }                                                                                               // 1082
    }                                                                                                 // 1083
    if (ta === 5) { // binary                                                                         // 1084
      // Surprisingly, a small binary blob is always less than a large one in                         // 1085
      // Mongo.                                                                                       // 1086
      if (a.length !== b.length)                                                                      // 1087
        return a.length - b.length;                                                                   // 1088
      for (i = 0; i < a.length; i++) {                                                                // 1089
        if (a[i] < b[i])                                                                              // 1090
          return -1;                                                                                  // 1091
        if (a[i] > b[i])                                                                              // 1092
          return 1;                                                                                   // 1093
      }                                                                                               // 1094
      return 0;                                                                                       // 1095
    }                                                                                                 // 1096
    if (ta === 8) { // boolean                                                                        // 1097
      if (a) return b ? 0 : 1;                                                                        // 1098
      return b ? -1 : 0;                                                                              // 1099
    }                                                                                                 // 1100
    if (ta === 10) // null                                                                            // 1101
      return 0;                                                                                       // 1102
    if (ta === 11) // regexp                                                                          // 1103
      throw Error("Sorting not supported on regular expression"); // XXX                              // 1104
    // 13: javascript code                                                                            // 1105
    // 14: symbol                                                                                     // 1106
    // 15: javascript code with scope                                                                 // 1107
    // 16: 32-bit integer                                                                             // 1108
    // 17: timestamp                                                                                  // 1109
    // 18: 64-bit integer                                                                             // 1110
    // 255: minkey                                                                                    // 1111
    // 127: maxkey                                                                                    // 1112
    if (ta === 13) // javascript code                                                                 // 1113
      throw Error("Sorting not supported on Javascript code"); // XXX                                 // 1114
    throw Error("Unknown type to sort");                                                              // 1115
  }                                                                                                   // 1116
};                                                                                                    // 1117
                                                                                                      // 1118
// Oddball function used by upsert.                                                                   // 1119
LocalCollection._removeDollarOperators = function (selector) {                                        // 1120
  var selectorDoc = {};                                                                               // 1121
  for (var k in selector)                                                                             // 1122
    if (k.substr(0, 1) !== '$')                                                                       // 1123
      selectorDoc[k] = selector[k];                                                                   // 1124
  return selectorDoc;                                                                                 // 1125
};                                                                                                    // 1126
                                                                                                      // 1127
////////////////////////////////////////////////////////////////////////////////////////////////////////

}).call(this);






(function () {

////////////////////////////////////////////////////////////////////////////////////////////////////////
//                                                                                                    //
// packages/minimongo/sort.js                                                                         //
//                                                                                                    //
////////////////////////////////////////////////////////////////////////////////////////////////////////
                                                                                                      //
// Give a sort spec, which can be in any of these forms:                                              // 1
//   {"key1": 1, "key2": -1}                                                                          // 2
//   [["key1", "asc"], ["key2", "desc"]]                                                              // 3
//   ["key1", ["key2", "desc"]]                                                                       // 4
//                                                                                                    // 5
// (.. with the first form being dependent on the key enumeration                                     // 6
// behavior of your javascript VM, which usually does what you mean in                                // 7
// this case if the key names don't look like integers ..)                                            // 8
//                                                                                                    // 9
// return a function that takes two objects, and returns -1 if the                                    // 10
// first object comes first in order, 1 if the second object comes                                    // 11
// first, or 0 if neither object comes before the other.                                              // 12
                                                                                                      // 13
Minimongo.Sorter = function (spec, options) {                                                         // 14
  var self = this;                                                                                    // 15
  options = options || {};                                                                            // 16
                                                                                                      // 17
  self._sortSpecParts = [];                                                                           // 18
                                                                                                      // 19
  var addSpecPart = function (path, ascending) {                                                      // 20
    if (!path)                                                                                        // 21
      throw Error("sort keys must be non-empty");                                                     // 22
    if (path.charAt(0) === '$')                                                                       // 23
      throw Error("unsupported sort key: " + path);                                                   // 24
    self._sortSpecParts.push({                                                                        // 25
      path: path,                                                                                     // 26
      lookup: makeLookupFunction(path),                                                               // 27
      ascending: ascending                                                                            // 28
    });                                                                                               // 29
  };                                                                                                  // 30
                                                                                                      // 31
  if (spec instanceof Array) {                                                                        // 32
    for (var i = 0; i < spec.length; i++) {                                                           // 33
      if (typeof spec[i] === "string") {                                                              // 34
        addSpecPart(spec[i], true);                                                                   // 35
      } else {                                                                                        // 36
        addSpecPart(spec[i][0], spec[i][1] !== "desc");                                               // 37
      }                                                                                               // 38
    }                                                                                                 // 39
  } else if (typeof spec === "object") {                                                              // 40
    _.each(spec, function (value, key) {                                                              // 41
      addSpecPart(key, value >= 0);                                                                   // 42
    });                                                                                               // 43
  } else {                                                                                            // 44
    throw Error("Bad sort specification: " + JSON.stringify(spec));                                   // 45
  }                                                                                                   // 46
                                                                                                      // 47
  // To implement affectedByModifier, we piggy-back on top of Matcher's                               // 48
  // affectedByModifier code; we create a selector that is affected by the same                       // 49
  // modifiers as this sort order. This is only implemented on the server.                            // 50
  if (self.affectedByModifier) {                                                                      // 51
    var selector = {};                                                                                // 52
    _.each(self._sortSpecParts, function (spec) {                                                     // 53
      selector[spec.path] = 1;                                                                        // 54
    });                                                                                               // 55
    self._selectorForAffectedByModifier = new Minimongo.Matcher(selector);                            // 56
  }                                                                                                   // 57
                                                                                                      // 58
  self._keyComparator = composeComparators(                                                           // 59
    _.map(self._sortSpecParts, function (spec, i) {                                                   // 60
      return self._keyFieldComparator(i);                                                             // 61
    }));                                                                                              // 62
                                                                                                      // 63
  // If you specify a matcher for this Sorter, _keyFilter may be set to a                             // 64
  // function which selects whether or not a given "sort key" (tuple of values                        // 65
  // for the different sort spec fields) is compatible with the selector.                             // 66
  self._keyFilter = null;                                                                             // 67
  options.matcher && self._useWithMatcher(options.matcher);                                           // 68
};                                                                                                    // 69
                                                                                                      // 70
// In addition to these methods, sorter_project.js defines combineIntoProjection                      // 71
// on the server only.                                                                                // 72
_.extend(Minimongo.Sorter.prototype, {                                                                // 73
  getComparator: function (options) {                                                                 // 74
    var self = this;                                                                                  // 75
                                                                                                      // 76
    // If we have no distances, just use the comparator from the source                               // 77
    // specification (which defaults to "everything is equal".                                        // 78
    if (!options || !options.distances) {                                                             // 79
      return self._getBaseComparator();                                                               // 80
    }                                                                                                 // 81
                                                                                                      // 82
    var distances = options.distances;                                                                // 83
                                                                                                      // 84
    // Return a comparator which first tries the sort specification, and if that                      // 85
    // says "it's equal", breaks ties using $near distances.                                          // 86
    return composeComparators([self._getBaseComparator(), function (a, b) {                           // 87
      if (!distances.has(a._id))                                                                      // 88
        throw Error("Missing distance for " + a._id);                                                 // 89
      if (!distances.has(b._id))                                                                      // 90
        throw Error("Missing distance for " + b._id);                                                 // 91
      return distances.get(a._id) - distances.get(b._id);                                             // 92
    }]);                                                                                              // 93
  },                                                                                                  // 94
                                                                                                      // 95
  _getPaths: function () {                                                                            // 96
    var self = this;                                                                                  // 97
    return _.pluck(self._sortSpecParts, 'path');                                                      // 98
  },                                                                                                  // 99
                                                                                                      // 100
  // Finds the minimum key from the doc, according to the sort specs.  (We say                        // 101
  // "minimum" here but this is with respect to the sort spec, so "descending"                        // 102
  // sort fields mean we're finding the max for that field.)                                          // 103
  //                                                                                                  // 104
  // Note that this is NOT "find the minimum value of the first field, the                            // 105
  // minimum value of the second field, etc"... it's "choose the                                      // 106
  // lexicographically minimum value of the key vector, allowing only keys which                      // 107
  // you can find along the same paths".  ie, for a doc {a: [{x: 0, y: 5}, {x:                        // 108
  // 1, y: 3}]} with sort spec {'a.x': 1, 'a.y': 1}, the only keys are [0,5] and                      // 109
  // [1,3], and the minimum key is [0,5]; notably, [0,3] is NOT a key.                                // 110
  _getMinKeyFromDoc: function (doc) {                                                                 // 111
    var self = this;                                                                                  // 112
    var minKey = null;                                                                                // 113
                                                                                                      // 114
    self._generateKeysFromDoc(doc, function (key) {                                                   // 115
      if (!self._keyCompatibleWithSelector(key))                                                      // 116
        return;                                                                                       // 117
                                                                                                      // 118
      if (minKey === null) {                                                                          // 119
        minKey = key;                                                                                 // 120
        return;                                                                                       // 121
      }                                                                                               // 122
      if (self._compareKeys(key, minKey) < 0) {                                                       // 123
        minKey = key;                                                                                 // 124
      }                                                                                               // 125
    });                                                                                               // 126
                                                                                                      // 127
    // This could happen if our key filter somehow filters out all the keys even                      // 128
    // though somehow the selector matches.                                                           // 129
    if (minKey === null)                                                                              // 130
      throw Error("sort selector found no keys in doc?");                                             // 131
    return minKey;                                                                                    // 132
  },                                                                                                  // 133
                                                                                                      // 134
  _keyCompatibleWithSelector: function (key) {                                                        // 135
    var self = this;                                                                                  // 136
    return !self._keyFilter || self._keyFilter(key);                                                  // 137
  },                                                                                                  // 138
                                                                                                      // 139
  // Iterates over each possible "key" from doc (ie, over each branch), calling                       // 140
  // 'cb' with the key.                                                                               // 141
  _generateKeysFromDoc: function (doc, cb) {                                                          // 142
    var self = this;                                                                                  // 143
                                                                                                      // 144
    if (self._sortSpecParts.length === 0)                                                             // 145
      throw new Error("can't generate keys without a spec");                                          // 146
                                                                                                      // 147
    // maps index -> ({'' -> value} or {path -> value})                                               // 148
    var valuesByIndexAndPath = [];                                                                    // 149
                                                                                                      // 150
    var pathFromIndices = function (indices) {                                                        // 151
      return indices.join(',') + ',';                                                                 // 152
    };                                                                                                // 153
                                                                                                      // 154
    var knownPaths = null;                                                                            // 155
                                                                                                      // 156
    _.each(self._sortSpecParts, function (spec, whichField) {                                         // 157
      // Expand any leaf arrays that we find, and ignore those arrays                                 // 158
      // themselves.  (We never sort based on an array itself.)                                       // 159
      var branches = expandArraysInBranches(spec.lookup(doc), true);                                  // 160
                                                                                                      // 161
      // If there are no values for a key (eg, key goes to an empty array),                           // 162
      // pretend we found one null value.                                                             // 163
      if (!branches.length)                                                                           // 164
        branches = [{value: null}];                                                                   // 165
                                                                                                      // 166
      var usedPaths = false;                                                                          // 167
      valuesByIndexAndPath[whichField] = {};                                                          // 168
      _.each(branches, function (branch) {                                                            // 169
        if (!branch.arrayIndices) {                                                                   // 170
          // If there are no array indices for a branch, then it must be the                          // 171
          // only branch, because the only thing that produces multiple branches                      // 172
          // is the use of arrays.                                                                    // 173
          if (branches.length > 1)                                                                    // 174
            throw Error("multiple branches but no array used?");                                      // 175
          valuesByIndexAndPath[whichField][''] = branch.value;                                        // 176
          return;                                                                                     // 177
        }                                                                                             // 178
                                                                                                      // 179
        usedPaths = true;                                                                             // 180
        var path = pathFromIndices(branch.arrayIndices);                                              // 181
        if (_.has(valuesByIndexAndPath[whichField], path))                                            // 182
          throw Error("duplicate path: " + path);                                                     // 183
        valuesByIndexAndPath[whichField][path] = branch.value;                                        // 184
                                                                                                      // 185
        // If two sort fields both go into arrays, they have to go into the                           // 186
        // exact same arrays and we have to find the same paths.  This is                             // 187
        // roughly the same condition that makes MongoDB throw this strange                           // 188
        // error message.  eg, the main thing is that if sort spec is {a: 1,                          // 189
        // b:1} then a and b cannot both be arrays.                                                   // 190
        //                                                                                            // 191
        // (In MongoDB it seems to be OK to have {a: 1, 'a.x.y': 1} where 'a'                         // 192
        // and 'a.x.y' are both arrays, but we don't allow this for now.                              // 193
        // #NestedArraySort                                                                           // 194
        // XXX achieve full compatibility here                                                        // 195
        if (knownPaths && !_.has(knownPaths, path)) {                                                 // 196
          throw Error("cannot index parallel arrays");                                                // 197
        }                                                                                             // 198
      });                                                                                             // 199
                                                                                                      // 200
      if (knownPaths) {                                                                               // 201
        // Similarly to above, paths must match everywhere, unless this is a                          // 202
        // non-array field.                                                                           // 203
        if (!_.has(valuesByIndexAndPath[whichField], '') &&                                           // 204
            _.size(knownPaths) !== _.size(valuesByIndexAndPath[whichField])) {                        // 205
          throw Error("cannot index parallel arrays!");                                               // 206
        }                                                                                             // 207
      } else if (usedPaths) {                                                                         // 208
        knownPaths = {};                                                                              // 209
        _.each(valuesByIndexAndPath[whichField], function (x, path) {                                 // 210
          knownPaths[path] = true;                                                                    // 211
        });                                                                                           // 212
      }                                                                                               // 213
    });                                                                                               // 214
                                                                                                      // 215
    if (!knownPaths) {                                                                                // 216
      // Easy case: no use of arrays.                                                                 // 217
      var soleKey = _.map(valuesByIndexAndPath, function (values) {                                   // 218
        if (!_.has(values, ''))                                                                       // 219
          throw Error("no value in sole key case?");                                                  // 220
        return values[''];                                                                            // 221
      });                                                                                             // 222
      cb(soleKey);                                                                                    // 223
      return;                                                                                         // 224
    }                                                                                                 // 225
                                                                                                      // 226
    _.each(knownPaths, function (x, path) {                                                           // 227
      var key = _.map(valuesByIndexAndPath, function (values) {                                       // 228
        if (_.has(values, ''))                                                                        // 229
          return values[''];                                                                          // 230
        if (!_.has(values, path))                                                                     // 231
          throw Error("missing path?");                                                               // 232
        return values[path];                                                                          // 233
      });                                                                                             // 234
      cb(key);                                                                                        // 235
    });                                                                                               // 236
  },                                                                                                  // 237
                                                                                                      // 238
  // Takes in two keys: arrays whose lengths match the number of spec                                 // 239
  // parts. Returns negative, 0, or positive based on using the sort spec to                          // 240
  // compare fields.                                                                                  // 241
  _compareKeys: function (key1, key2) {                                                               // 242
    var self = this;                                                                                  // 243
    if (key1.length !== self._sortSpecParts.length ||                                                 // 244
        key2.length !== self._sortSpecParts.length) {                                                 // 245
      throw Error("Key has wrong length");                                                            // 246
    }                                                                                                 // 247
                                                                                                      // 248
    return self._keyComparator(key1, key2);                                                           // 249
  },                                                                                                  // 250
                                                                                                      // 251
  // Given an index 'i', returns a comparator that compares two key arrays based                      // 252
  // on field 'i'.                                                                                    // 253
  _keyFieldComparator: function (i) {                                                                 // 254
    var self = this;                                                                                  // 255
    var invert = !self._sortSpecParts[i].ascending;                                                   // 256
    return function (key1, key2) {                                                                    // 257
      var compare = LocalCollection._f._cmp(key1[i], key2[i]);                                        // 258
      if (invert)                                                                                     // 259
        compare = -compare;                                                                           // 260
      return compare;                                                                                 // 261
    };                                                                                                // 262
  },                                                                                                  // 263
                                                                                                      // 264
  // Returns a comparator that represents the sort specification (but not                             // 265
  // including a possible geoquery distance tie-breaker).                                             // 266
  _getBaseComparator: function () {                                                                   // 267
    var self = this;                                                                                  // 268
                                                                                                      // 269
    // If we're only sorting on geoquery distance and no specs, just say                              // 270
    // everything is equal.                                                                           // 271
    if (!self._sortSpecParts.length) {                                                                // 272
      return function (doc1, doc2) {                                                                  // 273
        return 0;                                                                                     // 274
      };                                                                                              // 275
    }                                                                                                 // 276
                                                                                                      // 277
    return function (doc1, doc2) {                                                                    // 278
      var key1 = self._getMinKeyFromDoc(doc1);                                                        // 279
      var key2 = self._getMinKeyFromDoc(doc2);                                                        // 280
      return self._compareKeys(key1, key2);                                                           // 281
    };                                                                                                // 282
  },                                                                                                  // 283
                                                                                                      // 284
  // In MongoDB, if you have documents                                                                // 285
  //    {_id: 'x', a: [1, 10]} and                                                                    // 286
  //    {_id: 'y', a: [5, 15]},                                                                       // 287
  // then C.find({}, {sort: {a: 1}}) puts x before y (1 comes before 5).                              // 288
  // But  C.find({a: {$gt: 3}}, {sort: {a: 1}}) puts y before x (1 does not                           // 289
  // match the selector, and 5 comes before 10).                                                      // 290
  //                                                                                                  // 291
  // The way this works is pretty subtle!  For example, if the documents                              // 292
  // are instead {_id: 'x', a: [{x: 1}, {x: 10}]}) and                                                // 293
  //             {_id: 'y', a: [{x: 5}, {x: 15}]}),                                                   // 294
  // then C.find({'a.x': {$gt: 3}}, {sort: {'a.x': 1}}) and                                           // 295
  //      C.find({a: {$elemMatch: {x: {$gt: 3}}}}, {sort: {'a.x': 1}})                                // 296
  // both follow this rule (y before x).  (ie, you do have to apply this                              // 297
  // through $elemMatch.)                                                                             // 298
  //                                                                                                  // 299
  // So if you pass a matcher to this sorter's constructor, we will attempt to                        // 300
  // skip sort keys that don't match the selector. The logic here is pretty                           // 301
  // subtle and undocumented; we've gotten as close as we can figure out based                        // 302
  // on our understanding of Mongo's behavior.                                                        // 303
  _useWithMatcher: function (matcher) {                                                               // 304
    var self = this;                                                                                  // 305
                                                                                                      // 306
    if (self._keyFilter)                                                                              // 307
      throw Error("called _useWithMatcher twice?");                                                   // 308
                                                                                                      // 309
    // If we are only sorting by distance, then we're not going to bother to                          // 310
    // build a key filter.                                                                            // 311
    // XXX figure out how geoqueries interact with this stuff                                         // 312
    if (_.isEmpty(self._sortSpecParts))                                                               // 313
      return;                                                                                         // 314
                                                                                                      // 315
    var selector = matcher._selector;                                                                 // 316
                                                                                                      // 317
    // If the user just passed a literal function to find(), then we can't get a                      // 318
    // key filter from it.                                                                            // 319
    if (selector instanceof Function)                                                                 // 320
      return;                                                                                         // 321
                                                                                                      // 322
    var constraintsByPath = {};                                                                       // 323
    _.each(self._sortSpecParts, function (spec, i) {                                                  // 324
      constraintsByPath[spec.path] = [];                                                              // 325
    });                                                                                               // 326
                                                                                                      // 327
    _.each(selector, function (subSelector, key) {                                                    // 328
      // XXX support $and and $or                                                                     // 329
                                                                                                      // 330
      var constraints = constraintsByPath[key];                                                       // 331
      if (!constraints)                                                                               // 332
        return;                                                                                       // 333
                                                                                                      // 334
      // XXX it looks like the real MongoDB implementation isn't "does the                            // 335
      // regexp match" but "does the value fall into a range named by the                             // 336
      // literal prefix of the regexp", ie "foo" in /^foo(bar|baz)+/  But                             // 337
      // "does the regexp match" is a good approximation.                                             // 338
      if (subSelector instanceof RegExp) {                                                            // 339
        // As far as we can tell, using either of the options that both we and                        // 340
        // MongoDB support ('i' and 'm') disables use of the key filter. This                         // 341
        // makes sense: MongoDB mostly appears to be calculating ranges of an                         // 342
        // index to use, which means it only cares about regexps that match                           // 343
        // one range (with a literal prefix), and both 'i' and 'm' prevent the                        // 344
        // literal prefix of the regexp from actually meaning one range.                              // 345
        if (subSelector.ignoreCase || subSelector.multiline)                                          // 346
          return;                                                                                     // 347
        constraints.push(regexpElementMatcher(subSelector));                                          // 348
        return;                                                                                       // 349
      }                                                                                               // 350
                                                                                                      // 351
      if (isOperatorObject(subSelector)) {                                                            // 352
        _.each(subSelector, function (operand, operator) {                                            // 353
          if (_.contains(['$lt', '$lte', '$gt', '$gte'], operator)) {                                 // 354
            // XXX this depends on us knowing that these operators don't use any                      // 355
            // of the arguments to compileElementSelector other than operand.                         // 356
            constraints.push(                                                                         // 357
              ELEMENT_OPERATORS[operator].compileElementSelector(operand));                           // 358
          }                                                                                           // 359
                                                                                                      // 360
          // See comments in the RegExp block above.                                                  // 361
          if (operator === '$regex' && !subSelector.$options) {                                       // 362
            constraints.push(                                                                         // 363
              ELEMENT_OPERATORS.$regex.compileElementSelector(                                        // 364
                operand, subSelector));                                                               // 365
          }                                                                                           // 366
                                                                                                      // 367
          // XXX support {$exists: true}, $mod, $type, $in, $elemMatch                                // 368
        });                                                                                           // 369
        return;                                                                                       // 370
      }                                                                                               // 371
                                                                                                      // 372
      // OK, it's an equality thing.                                                                  // 373
      constraints.push(equalityElementMatcher(subSelector));                                          // 374
    });                                                                                               // 375
                                                                                                      // 376
    // It appears that the first sort field is treated differently from the                           // 377
    // others; we shouldn't create a key filter unless the first sort field is                        // 378
    // restricted, though after that point we can restrict the other sort fields                      // 379
    // or not as we wish.                                                                             // 380
    if (_.isEmpty(constraintsByPath[self._sortSpecParts[0].path]))                                    // 381
      return;                                                                                         // 382
                                                                                                      // 383
    self._keyFilter = function (key) {                                                                // 384
      return _.all(self._sortSpecParts, function (specPart, index) {                                  // 385
        return _.all(constraintsByPath[specPart.path], function (f) {                                 // 386
          return f(key[index]);                                                                       // 387
        });                                                                                           // 388
      });                                                                                             // 389
    };                                                                                                // 390
  }                                                                                                   // 391
});                                                                                                   // 392
                                                                                                      // 393
// Given an array of comparators                                                                      // 394
// (functions (a,b)->(negative or positive or zero)), returns a single                                // 395
// comparator which uses each comparator in order and returns the first                               // 396
// non-zero value.                                                                                    // 397
var composeComparators = function (comparatorArray) {                                                 // 398
  return function (a, b) {                                                                            // 399
    for (var i = 0; i < comparatorArray.length; ++i) {                                                // 400
      var compare = comparatorArray[i](a, b);                                                         // 401
      if (compare !== 0)                                                                              // 402
        return compare;                                                                               // 403
    }                                                                                                 // 404
    return 0;                                                                                         // 405
  };                                                                                                  // 406
};                                                                                                    // 407
                                                                                                      // 408
////////////////////////////////////////////////////////////////////////////////////////////////////////

}).call(this);






(function () {

////////////////////////////////////////////////////////////////////////////////////////////////////////
//                                                                                                    //
// packages/minimongo/projection.js                                                                   //
//                                                                                                    //
////////////////////////////////////////////////////////////////////////////////////////////////////////
                                                                                                      //
// Knows how to compile a fields projection to a predicate function.                                  // 1
// @returns - Function: a closure that filters out an object according to the                         // 2
//            fields projection rules:                                                                // 3
//            @param obj - Object: MongoDB-styled document                                            // 4
//            @returns - Object: a document with the fields filtered out                              // 5
//                       according to projection rules. Doesn't retain subfields                      // 6
//                       of passed argument.                                                          // 7
LocalCollection._compileProjection = function (fields) {                                              // 8
  LocalCollection._checkSupportedProjection(fields);                                                  // 9
                                                                                                      // 10
  var _idProjection = _.isUndefined(fields._id) ? true : fields._id;                                  // 11
  var details = projectionDetails(fields);                                                            // 12
                                                                                                      // 13
  // returns transformed doc according to ruleTree                                                    // 14
  var transform = function (doc, ruleTree) {                                                          // 15
    // Special case for "sets"                                                                        // 16
    if (_.isArray(doc))                                                                               // 17
      return _.map(doc, function (subdoc) { return transform(subdoc, ruleTree); });                   // 18
                                                                                                      // 19
    var res = details.including ? {} : EJSON.clone(doc);                                              // 20
    _.each(ruleTree, function (rule, key) {                                                           // 21
      if (!_.has(doc, key))                                                                           // 22
        return;                                                                                       // 23
      if (_.isObject(rule)) {                                                                         // 24
        // For sub-objects/subsets we branch                                                          // 25
        if (_.isObject(doc[key]))                                                                     // 26
          res[key] = transform(doc[key], rule);                                                       // 27
        // Otherwise we don't even touch this subfield                                                // 28
      } else if (details.including)                                                                   // 29
        res[key] = EJSON.clone(doc[key]);                                                             // 30
      else                                                                                            // 31
        delete res[key];                                                                              // 32
    });                                                                                               // 33
                                                                                                      // 34
    return res;                                                                                       // 35
  };                                                                                                  // 36
                                                                                                      // 37
  return function (obj) {                                                                             // 38
    var res = transform(obj, details.tree);                                                           // 39
                                                                                                      // 40
    if (_idProjection && _.has(obj, '_id'))                                                           // 41
      res._id = obj._id;                                                                              // 42
    if (!_idProjection && _.has(res, '_id'))                                                          // 43
      delete res._id;                                                                                 // 44
    return res;                                                                                       // 45
  };                                                                                                  // 46
};                                                                                                    // 47
                                                                                                      // 48
// Traverses the keys of passed projection and constructs a tree where all                            // 49
// leaves are either all True or all False                                                            // 50
// @returns Object:                                                                                   // 51
//  - tree - Object - tree representation of keys involved in projection                              // 52
//  (exception for '_id' as it is a special case handled separately)                                  // 53
//  - including - Boolean - "take only certain fields" type of projection                             // 54
projectionDetails = function (fields) {                                                               // 55
  // Find the non-_id keys (_id is handled specially because it is included unless                    // 56
  // explicitly excluded). Sort the keys, so that our code to detect overlaps                         // 57
  // like 'foo' and 'foo.bar' can assume that 'foo' comes first.                                      // 58
  var fieldsKeys = _.keys(fields).sort();                                                             // 59
                                                                                                      // 60
  // If there are other rules other than '_id', treat '_id' differently in a                          // 61
  // separate case. If '_id' is the only rule, use it to understand if it is                          // 62
  // including/excluding projection.                                                                  // 63
  if (fieldsKeys.length > 0 && !(fieldsKeys.length === 1 && fieldsKeys[0] === '_id'))                 // 64
    fieldsKeys = _.reject(fieldsKeys, function (key) { return key === '_id'; });                      // 65
                                                                                                      // 66
  var including = null; // Unknown                                                                    // 67
                                                                                                      // 68
  _.each(fieldsKeys, function (keyPath) {                                                             // 69
    var rule = !!fields[keyPath];                                                                     // 70
    if (including === null)                                                                           // 71
      including = rule;                                                                               // 72
    if (including !== rule)                                                                           // 73
      // This error message is copies from MongoDB shell                                              // 74
      throw MinimongoError("You cannot currently mix including and excluding fields.");               // 75
  });                                                                                                 // 76
                                                                                                      // 77
                                                                                                      // 78
  var projectionRulesTree = pathsToTree(                                                              // 79
    fieldsKeys,                                                                                       // 80
    function (path) { return including; },                                                            // 81
    function (node, path, fullPath) {                                                                 // 82
      // Check passed projection fields' keys: If you have two rules such as                          // 83
      // 'foo.bar' and 'foo.bar.baz', then the result becomes ambiguous. If                           // 84
      // that happens, there is a probability you are doing something wrong,                          // 85
      // framework should notify you about such mistake earlier on cursor                             // 86
      // compilation step than later during runtime.  Note, that real mongo                           // 87
      // doesn't do anything about it and the later rule appears in projection                        // 88
      // project, more priority it takes.                                                             // 89
      //                                                                                              // 90
      // Example, assume following in mongo shell:                                                    // 91
      // > db.coll.insert({ a: { b: 23, c: 44 } })                                                    // 92
      // > db.coll.find({}, { 'a': 1, 'a.b': 1 })                                                     // 93
      // { "_id" : ObjectId("520bfe456024608e8ef24af3"), "a" : { "b" : 23 } }                         // 94
      // > db.coll.find({}, { 'a.b': 1, 'a': 1 })                                                     // 95
      // { "_id" : ObjectId("520bfe456024608e8ef24af3"), "a" : { "b" : 23, "c" : 44 } }               // 96
      //                                                                                              // 97
      // Note, how second time the return set of keys is different.                                   // 98
                                                                                                      // 99
      var currentPath = fullPath;                                                                     // 100
      var anotherPath = path;                                                                         // 101
      throw MinimongoError("both " + currentPath + " and " + anotherPath +                            // 102
                           " found in fields option, using both of them may trigger " +               // 103
                           "unexpected behavior. Did you mean to use only one of them?");             // 104
    });                                                                                               // 105
                                                                                                      // 106
  return {                                                                                            // 107
    tree: projectionRulesTree,                                                                        // 108
    including: including                                                                              // 109
  };                                                                                                  // 110
};                                                                                                    // 111
                                                                                                      // 112
// paths - Array: list of mongo style paths                                                           // 113
// newLeafFn - Function: of form function(path) should return a scalar value to                       // 114
//                       put into list created for that path                                          // 115
// conflictFn - Function: of form function(node, path, fullPath) is called                            // 116
//                        when building a tree path for 'fullPath' node on                            // 117
//                        'path' was already a leaf with a value. Must return a                       // 118
//                        conflict resolution.                                                        // 119
// initial tree - Optional Object: starting tree.                                                     // 120
// @returns - Object: tree represented as a set of nested objects                                     // 121
pathsToTree = function (paths, newLeafFn, conflictFn, tree) {                                         // 122
  tree = tree || {};                                                                                  // 123
  _.each(paths, function (keyPath) {                                                                  // 124
    var treePos = tree;                                                                               // 125
    var pathArr = keyPath.split('.');                                                                 // 126
                                                                                                      // 127
    // use _.all just for iteration with break                                                        // 128
    var success = _.all(pathArr.slice(0, -1), function (key, idx) {                                   // 129
      if (!_.has(treePos, key))                                                                       // 130
        treePos[key] = {};                                                                            // 131
      else if (!_.isObject(treePos[key])) {                                                           // 132
        treePos[key] = conflictFn(treePos[key],                                                       // 133
                                  pathArr.slice(0, idx + 1).join('.'),                                // 134
                                  keyPath);                                                           // 135
        // break out of loop if we are failing for this path                                          // 136
        if (!_.isObject(treePos[key]))                                                                // 137
          return false;                                                                               // 138
      }                                                                                               // 139
                                                                                                      // 140
      treePos = treePos[key];                                                                         // 141
      return true;                                                                                    // 142
    });                                                                                               // 143
                                                                                                      // 144
    if (success) {                                                                                    // 145
      var lastKey = _.last(pathArr);                                                                  // 146
      if (!_.has(treePos, lastKey))                                                                   // 147
        treePos[lastKey] = newLeafFn(keyPath);                                                        // 148
      else                                                                                            // 149
        treePos[lastKey] = conflictFn(treePos[lastKey], keyPath, keyPath);                            // 150
    }                                                                                                 // 151
  });                                                                                                 // 152
                                                                                                      // 153
  return tree;                                                                                        // 154
};                                                                                                    // 155
                                                                                                      // 156
LocalCollection._checkSupportedProjection = function (fields) {                                       // 157
  if (!_.isObject(fields) || _.isArray(fields))                                                       // 158
    throw MinimongoError("fields option must be an object");                                          // 159
                                                                                                      // 160
  _.each(fields, function (val, keyPath) {                                                            // 161
    if (_.contains(keyPath.split('.'), '$'))                                                          // 162
      throw MinimongoError("Minimongo doesn't support $ operator in projections yet.");               // 163
    if (_.indexOf([1, 0, true, false], val) === -1)                                                   // 164
      throw MinimongoError("Projection values should be one of 1, 0, true, or false");                // 165
  });                                                                                                 // 166
};                                                                                                    // 167
                                                                                                      // 168
                                                                                                      // 169
////////////////////////////////////////////////////////////////////////////////////////////////////////

}).call(this);






(function () {

////////////////////////////////////////////////////////////////////////////////////////////////////////
//                                                                                                    //
// packages/minimongo/modify.js                                                                       //
//                                                                                                    //
////////////////////////////////////////////////////////////////////////////////////////////////////////
                                                                                                      //
// XXX need a strategy for passing the binding of $ into this                                         // 1
// function, from the compiled selector                                                               // 2
//                                                                                                    // 3
// maybe just {key.up.to.just.before.dollarsign: array_index}                                         // 4
//                                                                                                    // 5
// XXX atomicity: if one modification fails, do we roll back the whole                                // 6
// change?                                                                                            // 7
//                                                                                                    // 8
// options:                                                                                           // 9
//   - isInsert is set when _modify is being called to compute the document to                        // 10
//     insert as part of an upsert operation. We use this primarily to figure                         // 11
//     out when to set the fields in $setOnInsert, if present.                                        // 12
LocalCollection._modify = function (doc, mod, options) {                                              // 13
  options = options || {};                                                                            // 14
  if (!isPlainObject(mod))                                                                            // 15
    throw MinimongoError("Modifier must be an object");                                               // 16
  var isModifier = isOperatorObject(mod);                                                             // 17
                                                                                                      // 18
  var newDoc;                                                                                         // 19
                                                                                                      // 20
  if (!isModifier) {                                                                                  // 21
    if (mod._id && !EJSON.equals(doc._id, mod._id))                                                   // 22
      throw MinimongoError("Cannot change the _id of a document");                                    // 23
                                                                                                      // 24
    // replace the whole document                                                                     // 25
    for (var k in mod) {                                                                              // 26
      if (/\./.test(k))                                                                               // 27
        throw MinimongoError(                                                                         // 28
          "When replacing document, field name may not contain '.'");                                 // 29
    }                                                                                                 // 30
    newDoc = mod;                                                                                     // 31
  } else {                                                                                            // 32
    // apply modifiers to the doc.                                                                    // 33
    newDoc = EJSON.clone(doc);                                                                        // 34
                                                                                                      // 35
    _.each(mod, function (operand, op) {                                                              // 36
      var modFunc = MODIFIERS[op];                                                                    // 37
      // Treat $setOnInsert as $set if this is an insert.                                             // 38
      if (options.isInsert && op === '$setOnInsert')                                                  // 39
        modFunc = MODIFIERS['$set'];                                                                  // 40
      if (!modFunc)                                                                                   // 41
        throw MinimongoError("Invalid modifier specified " + op);                                     // 42
      _.each(operand, function (arg, keypath) {                                                       // 43
        // XXX mongo doesn't allow mod field names to end in a period,                                // 44
        // but I don't see why.. it allows '' as a key, as does JS                                    // 45
        if (keypath.length && keypath[keypath.length-1] === '.')                                      // 46
          throw MinimongoError(                                                                       // 47
            "Invalid mod field name, may not end in a period");                                       // 48
                                                                                                      // 49
        if (keypath === '_id')                                                                        // 50
          throw MinimongoError("Mod on _id not allowed");                                             // 51
                                                                                                      // 52
        var keyparts = keypath.split('.');                                                            // 53
        var noCreate = _.has(NO_CREATE_MODIFIERS, op);                                                // 54
        var forbidArray = (op === "$rename");                                                         // 55
        var target = findModTarget(newDoc, keyparts, {                                                // 56
          noCreate: NO_CREATE_MODIFIERS[op],                                                          // 57
          forbidArray: (op === "$rename"),                                                            // 58
          arrayIndices: options.arrayIndices                                                          // 59
        });                                                                                           // 60
        var field = keyparts.pop();                                                                   // 61
        modFunc(target, field, arg, keypath, newDoc);                                                 // 62
      });                                                                                             // 63
    });                                                                                               // 64
  }                                                                                                   // 65
                                                                                                      // 66
  // move new document into place.                                                                    // 67
  _.each(_.keys(doc), function (k) {                                                                  // 68
    // Note: this used to be for (var k in doc) however, this does not                                // 69
    // work right in Opera. Deleting from a doc while iterating over it                               // 70
    // would sometimes cause opera to skip some keys.                                                 // 71
                                                                                                      // 72
    // isInsert: if we're constructing a document to insert (via upsert)                              // 73
    // and we're in replacement mode, not modify mode, DON'T take the                                 // 74
    // _id from the query.  This matches mongo's behavior.                                            // 75
    if (k !== '_id' || options.isInsert)                                                              // 76
      delete doc[k];                                                                                  // 77
  });                                                                                                 // 78
  _.each(newDoc, function (v, k) {                                                                    // 79
    doc[k] = v;                                                                                       // 80
  });                                                                                                 // 81
};                                                                                                    // 82
                                                                                                      // 83
// for a.b.c.2.d.e, keyparts should be ['a', 'b', 'c', '2', 'd', 'e'],                                // 84
// and then you would operate on the 'e' property of the returned                                     // 85
// object.                                                                                            // 86
//                                                                                                    // 87
// if options.noCreate is falsey, creates intermediate levels of                                      // 88
// structure as necessary, like mkdir -p (and raises an exception if                                  // 89
// that would mean giving a non-numeric property to an array.) if                                     // 90
// options.noCreate is true, return undefined instead.                                                // 91
//                                                                                                    // 92
// may modify the last element of keyparts to signal to the caller that it needs                      // 93
// to use a different value to index into the returned object (for example,                           // 94
// ['a', '01'] -> ['a', 1]).                                                                          // 95
//                                                                                                    // 96
// if forbidArray is true, return null if the keypath goes through an array.                          // 97
//                                                                                                    // 98
// if options.arrayIndices is set, use its first element for the (first) '$' in                       // 99
// the path.                                                                                          // 100
var findModTarget = function (doc, keyparts, options) {                                               // 101
  options = options || {};                                                                            // 102
  var usedArrayIndex = false;                                                                         // 103
  for (var i = 0; i < keyparts.length; i++) {                                                         // 104
    var last = (i === keyparts.length - 1);                                                           // 105
    var keypart = keyparts[i];                                                                        // 106
    var indexable = isIndexable(doc);                                                                 // 107
    if (!indexable) {                                                                                 // 108
      if (options.noCreate)                                                                           // 109
        return undefined;                                                                             // 110
      var e = MinimongoError(                                                                         // 111
        "cannot use the part '" + keypart + "' to traverse " + doc);                                  // 112
      e.setPropertyError = true;                                                                      // 113
      throw e;                                                                                        // 114
    }                                                                                                 // 115
    if (doc instanceof Array) {                                                                       // 116
      if (options.forbidArray)                                                                        // 117
        return null;                                                                                  // 118
      if (keypart === '$') {                                                                          // 119
        if (usedArrayIndex)                                                                           // 120
          throw MinimongoError("Too many positional (i.e. '$') elements");                            // 121
        if (!options.arrayIndices || !options.arrayIndices.length) {                                  // 122
          throw MinimongoError("The positional operator did not find the " +                          // 123
                               "match needed from the query");                                        // 124
        }                                                                                             // 125
        keypart = options.arrayIndices[0];                                                            // 126
        usedArrayIndex = true;                                                                        // 127
      } else if (isNumericKey(keypart)) {                                                             // 128
        keypart = parseInt(keypart);                                                                  // 129
      } else {                                                                                        // 130
        if (options.noCreate)                                                                         // 131
          return undefined;                                                                           // 132
        throw MinimongoError(                                                                         // 133
          "can't append to array using string field name ["                                           // 134
                    + keypart + "]");                                                                 // 135
      }                                                                                               // 136
      if (last)                                                                                       // 137
        // handle 'a.01'                                                                              // 138
        keyparts[i] = keypart;                                                                        // 139
      if (options.noCreate && keypart >= doc.length)                                                  // 140
        return undefined;                                                                             // 141
      while (doc.length < keypart)                                                                    // 142
        doc.push(null);                                                                               // 143
      if (!last) {                                                                                    // 144
        if (doc.length === keypart)                                                                   // 145
          doc.push({});                                                                               // 146
        else if (typeof doc[keypart] !== "object")                                                    // 147
          throw MinimongoError("can't modify field '" + keyparts[i + 1] +                             // 148
                      "' of list value " + JSON.stringify(doc[keypart]));                             // 149
      }                                                                                               // 150
    } else {                                                                                          // 151
      if (keypart.length && keypart.substr(0, 1) === '$')                                             // 152
        throw MinimongoError("can't set field named " + keypart);                                     // 153
      if (!(keypart in doc)) {                                                                        // 154
        if (options.noCreate)                                                                         // 155
          return undefined;                                                                           // 156
        if (!last)                                                                                    // 157
          doc[keypart] = {};                                                                          // 158
      }                                                                                               // 159
    }                                                                                                 // 160
                                                                                                      // 161
    if (last)                                                                                         // 162
      return doc;                                                                                     // 163
    doc = doc[keypart];                                                                               // 164
  }                                                                                                   // 165
                                                                                                      // 166
  // notreached                                                                                       // 167
};                                                                                                    // 168
                                                                                                      // 169
var NO_CREATE_MODIFIERS = {                                                                           // 170
  $unset: true,                                                                                       // 171
  $pop: true,                                                                                         // 172
  $rename: true,                                                                                      // 173
  $pull: true,                                                                                        // 174
  $pullAll: true                                                                                      // 175
};                                                                                                    // 176
                                                                                                      // 177
var MODIFIERS = {                                                                                     // 178
  $inc: function (target, field, arg) {                                                               // 179
    if (typeof arg !== "number")                                                                      // 180
      throw MinimongoError("Modifier $inc allowed for numbers only");                                 // 181
    if (field in target) {                                                                            // 182
      if (typeof target[field] !== "number")                                                          // 183
        throw MinimongoError("Cannot apply $inc modifier to non-number");                             // 184
      target[field] += arg;                                                                           // 185
    } else {                                                                                          // 186
      target[field] = arg;                                                                            // 187
    }                                                                                                 // 188
  },                                                                                                  // 189
  $set: function (target, field, arg) {                                                               // 190
    if (!_.isObject(target)) { // not an array or an object                                           // 191
      var e = MinimongoError("Cannot set property on non-object field");                              // 192
      e.setPropertyError = true;                                                                      // 193
      throw e;                                                                                        // 194
    }                                                                                                 // 195
    if (target === null) {                                                                            // 196
      var e = MinimongoError("Cannot set property on null");                                          // 197
      e.setPropertyError = true;                                                                      // 198
      throw e;                                                                                        // 199
    }                                                                                                 // 200
    target[field] = EJSON.clone(arg);                                                                 // 201
  },                                                                                                  // 202
  $setOnInsert: function (target, field, arg) {                                                       // 203
    // converted to `$set` in `_modify`                                                               // 204
  },                                                                                                  // 205
  $unset: function (target, field, arg) {                                                             // 206
    if (target !== undefined) {                                                                       // 207
      if (target instanceof Array) {                                                                  // 208
        if (field in target)                                                                          // 209
          target[field] = null;                                                                       // 210
      } else                                                                                          // 211
        delete target[field];                                                                         // 212
    }                                                                                                 // 213
  },                                                                                                  // 214
  $push: function (target, field, arg) {                                                              // 215
    if (target[field] === undefined)                                                                  // 216
      target[field] = [];                                                                             // 217
    if (!(target[field] instanceof Array))                                                            // 218
      throw MinimongoError("Cannot apply $push modifier to non-array");                               // 219
                                                                                                      // 220
    if (!(arg && arg.$each)) {                                                                        // 221
      // Simple mode: not $each                                                                       // 222
      target[field].push(EJSON.clone(arg));                                                           // 223
      return;                                                                                         // 224
    }                                                                                                 // 225
                                                                                                      // 226
    // Fancy mode: $each (and maybe $slice and $sort)                                                 // 227
    var toPush = arg.$each;                                                                           // 228
    if (!(toPush instanceof Array))                                                                   // 229
      throw MinimongoError("$each must be an array");                                                 // 230
                                                                                                      // 231
    // Parse $slice.                                                                                  // 232
    var slice = undefined;                                                                            // 233
    if ('$slice' in arg) {                                                                            // 234
      if (typeof arg.$slice !== "number")                                                             // 235
        throw MinimongoError("$slice must be a numeric value");                                       // 236
      // XXX should check to make sure integer                                                        // 237
      if (arg.$slice > 0)                                                                             // 238
        throw MinimongoError("$slice in $push must be zero or negative");                             // 239
      slice = arg.$slice;                                                                             // 240
    }                                                                                                 // 241
                                                                                                      // 242
    // Parse $sort.                                                                                   // 243
    var sortFunction = undefined;                                                                     // 244
    if (arg.$sort) {                                                                                  // 245
      if (slice === undefined)                                                                        // 246
        throw MinimongoError("$sort requires $slice to be present");                                  // 247
      // XXX this allows us to use a $sort whose value is an array, but that's                        // 248
      // actually an extension of the Node driver, so it won't work                                   // 249
      // server-side. Could be confusing!                                                             // 250
      // XXX is it correct that we don't do geo-stuff here?                                           // 251
      sortFunction = new Minimongo.Sorter(arg.$sort).getComparator();                                 // 252
      for (var i = 0; i < toPush.length; i++) {                                                       // 253
        if (LocalCollection._f._type(toPush[i]) !== 3) {                                              // 254
          throw MinimongoError("$push like modifiers using $sort " +                                  // 255
                      "require all elements to be objects");                                          // 256
        }                                                                                             // 257
      }                                                                                               // 258
    }                                                                                                 // 259
                                                                                                      // 260
    // Actually push.                                                                                 // 261
    for (var j = 0; j < toPush.length; j++)                                                           // 262
      target[field].push(EJSON.clone(toPush[j]));                                                     // 263
                                                                                                      // 264
    // Actually sort.                                                                                 // 265
    if (sortFunction)                                                                                 // 266
      target[field].sort(sortFunction);                                                               // 267
                                                                                                      // 268
    // Actually slice.                                                                                // 269
    if (slice !== undefined) {                                                                        // 270
      if (slice === 0)                                                                                // 271
        target[field] = [];  // differs from Array.slice!                                             // 272
      else                                                                                            // 273
        target[field] = target[field].slice(slice);                                                   // 274
    }                                                                                                 // 275
  },                                                                                                  // 276
  $pushAll: function (target, field, arg) {                                                           // 277
    if (!(typeof arg === "object" && arg instanceof Array))                                           // 278
      throw MinimongoError("Modifier $pushAll/pullAll allowed for arrays only");                      // 279
    var x = target[field];                                                                            // 280
    if (x === undefined)                                                                              // 281
      target[field] = arg;                                                                            // 282
    else if (!(x instanceof Array))                                                                   // 283
      throw MinimongoError("Cannot apply $pushAll modifier to non-array");                            // 284
    else {                                                                                            // 285
      for (var i = 0; i < arg.length; i++)                                                            // 286
        x.push(arg[i]);                                                                               // 287
    }                                                                                                 // 288
  },                                                                                                  // 289
  $addToSet: function (target, field, arg) {                                                          // 290
    var x = target[field];                                                                            // 291
    if (x === undefined)                                                                              // 292
      target[field] = [arg];                                                                          // 293
    else if (!(x instanceof Array))                                                                   // 294
      throw MinimongoError("Cannot apply $addToSet modifier to non-array");                           // 295
    else {                                                                                            // 296
      var isEach = false;                                                                             // 297
      if (typeof arg === "object") {                                                                  // 298
        for (var k in arg) {                                                                          // 299
          if (k === "$each")                                                                          // 300
            isEach = true;                                                                            // 301
          break;                                                                                      // 302
        }                                                                                             // 303
      }                                                                                               // 304
      var values = isEach ? arg["$each"] : [arg];                                                     // 305
      _.each(values, function (value) {                                                               // 306
        for (var i = 0; i < x.length; i++)                                                            // 307
          if (LocalCollection._f._equal(value, x[i]))                                                 // 308
            return;                                                                                   // 309
        x.push(EJSON.clone(value));                                                                   // 310
      });                                                                                             // 311
    }                                                                                                 // 312
  },                                                                                                  // 313
  $pop: function (target, field, arg) {                                                               // 314
    if (target === undefined)                                                                         // 315
      return;                                                                                         // 316
    var x = target[field];                                                                            // 317
    if (x === undefined)                                                                              // 318
      return;                                                                                         // 319
    else if (!(x instanceof Array))                                                                   // 320
      throw MinimongoError("Cannot apply $pop modifier to non-array");                                // 321
    else {                                                                                            // 322
      if (typeof arg === 'number' && arg < 0)                                                         // 323
        x.splice(0, 1);                                                                               // 324
      else                                                                                            // 325
        x.pop();                                                                                      // 326
    }                                                                                                 // 327
  },                                                                                                  // 328
  $pull: function (target, field, arg) {                                                              // 329
    if (target === undefined)                                                                         // 330
      return;                                                                                         // 331
    var x = target[field];                                                                            // 332
    if (x === undefined)                                                                              // 333
      return;                                                                                         // 334
    else if (!(x instanceof Array))                                                                   // 335
      throw MinimongoError("Cannot apply $pull/pullAll modifier to non-array");                       // 336
    else {                                                                                            // 337
      var out = [];                                                                                   // 338
      if (typeof arg === "object" && !(arg instanceof Array)) {                                       // 339
        // XXX would be much nicer to compile this once, rather than                                  // 340
        // for each document we modify.. but usually we're not                                        // 341
        // modifying that many documents, so we'll let it slide for                                   // 342
        // now                                                                                        // 343
                                                                                                      // 344
        // XXX Minimongo.Matcher isn't up for the job, because we need                                // 345
        // to permit stuff like {$pull: {a: {$gt: 4}}}.. something                                    // 346
        // like {$gt: 4} is not normally a complete selector.                                         // 347
        // same issue as $elemMatch possibly?                                                         // 348
        var matcher = new Minimongo.Matcher(arg);                                                     // 349
        for (var i = 0; i < x.length; i++)                                                            // 350
          if (!matcher.documentMatches(x[i]).result)                                                  // 351
            out.push(x[i]);                                                                           // 352
      } else {                                                                                        // 353
        for (var i = 0; i < x.length; i++)                                                            // 354
          if (!LocalCollection._f._equal(x[i], arg))                                                  // 355
            out.push(x[i]);                                                                           // 356
      }                                                                                               // 357
      target[field] = out;                                                                            // 358
    }                                                                                                 // 359
  },                                                                                                  // 360
  $pullAll: function (target, field, arg) {                                                           // 361
    if (!(typeof arg === "object" && arg instanceof Array))                                           // 362
      throw MinimongoError("Modifier $pushAll/pullAll allowed for arrays only");                      // 363
    if (target === undefined)                                                                         // 364
      return;                                                                                         // 365
    var x = target[field];                                                                            // 366
    if (x === undefined)                                                                              // 367
      return;                                                                                         // 368
    else if (!(x instanceof Array))                                                                   // 369
      throw MinimongoError("Cannot apply $pull/pullAll modifier to non-array");                       // 370
    else {                                                                                            // 371
      var out = [];                                                                                   // 372
      for (var i = 0; i < x.length; i++) {                                                            // 373
        var exclude = false;                                                                          // 374
        for (var j = 0; j < arg.length; j++) {                                                        // 375
          if (LocalCollection._f._equal(x[i], arg[j])) {                                              // 376
            exclude = true;                                                                           // 377
            break;                                                                                    // 378
          }                                                                                           // 379
        }                                                                                             // 380
        if (!exclude)                                                                                 // 381
          out.push(x[i]);                                                                             // 382
      }                                                                                               // 383
      target[field] = out;                                                                            // 384
    }                                                                                                 // 385
  },                                                                                                  // 386
  $rename: function (target, field, arg, keypath, doc) {                                              // 387
    if (keypath === arg)                                                                              // 388
      // no idea why mongo has this restriction..                                                     // 389
      throw MinimongoError("$rename source must differ from target");                                 // 390
    if (target === null)                                                                              // 391
      throw MinimongoError("$rename source field invalid");                                           // 392
    if (typeof arg !== "string")                                                                      // 393
      throw MinimongoError("$rename target must be a string");                                        // 394
    if (target === undefined)                                                                         // 395
      return;                                                                                         // 396
    var v = target[field];                                                                            // 397
    delete target[field];                                                                             // 398
                                                                                                      // 399
    var keyparts = arg.split('.');                                                                    // 400
    var target2 = findModTarget(doc, keyparts, {forbidArray: true});                                  // 401
    if (target2 === null)                                                                             // 402
      throw MinimongoError("$rename target field invalid");                                           // 403
    var field2 = keyparts.pop();                                                                      // 404
    target2[field2] = v;                                                                              // 405
  },                                                                                                  // 406
  $bit: function (target, field, arg) {                                                               // 407
    // XXX mongo only supports $bit on integers, and we only support                                  // 408
    // native javascript numbers (doubles) so far, so we can't support $bit                           // 409
    throw MinimongoError("$bit is not supported");                                                    // 410
  }                                                                                                   // 411
};                                                                                                    // 412
                                                                                                      // 413
////////////////////////////////////////////////////////////////////////////////////////////////////////

}).call(this);






(function () {

////////////////////////////////////////////////////////////////////////////////////////////////////////
//                                                                                                    //
// packages/minimongo/diff.js                                                                         //
//                                                                                                    //
////////////////////////////////////////////////////////////////////////////////////////////////////////
                                                                                                      //
                                                                                                      // 1
// ordered: bool.                                                                                     // 2
// old_results and new_results: collections of documents.                                             // 3
//    if ordered, they are arrays.                                                                    // 4
//    if unordered, they are IdMaps                                                                   // 5
LocalCollection._diffQueryChanges = function (ordered, oldResults, newResults,                        // 6
                                       observer) {                                                    // 7
  if (ordered)                                                                                        // 8
    LocalCollection._diffQueryOrderedChanges(                                                         // 9
      oldResults, newResults, observer);                                                              // 10
  else                                                                                                // 11
    LocalCollection._diffQueryUnorderedChanges(                                                       // 12
      oldResults, newResults, observer);                                                              // 13
};                                                                                                    // 14
                                                                                                      // 15
LocalCollection._diffQueryUnorderedChanges = function (oldResults, newResults,                        // 16
                                                       observer) {                                    // 17
  if (observer.movedBefore) {                                                                         // 18
    throw new Error("_diffQueryUnordered called with a movedBefore observer!");                       // 19
  }                                                                                                   // 20
                                                                                                      // 21
  newResults.forEach(function (newDoc, id) {                                                          // 22
    var oldDoc = oldResults.get(id);                                                                  // 23
    if (oldDoc) {                                                                                     // 24
      if (observer.changed && !EJSON.equals(oldDoc, newDoc)) {                                        // 25
        observer.changed(                                                                             // 26
          id, LocalCollection._makeChangedFields(newDoc, oldDoc));                                    // 27
      }                                                                                               // 28
    } else if (observer.added) {                                                                      // 29
      var fields = EJSON.clone(newDoc);                                                               // 30
      delete fields._id;                                                                              // 31
      observer.added(newDoc._id, fields);                                                             // 32
    }                                                                                                 // 33
  });                                                                                                 // 34
                                                                                                      // 35
  if (observer.removed) {                                                                             // 36
    oldResults.forEach(function (oldDoc, id) {                                                        // 37
      if (!newResults.has(id))                                                                        // 38
        observer.removed(id);                                                                         // 39
    });                                                                                               // 40
  }                                                                                                   // 41
};                                                                                                    // 42
                                                                                                      // 43
                                                                                                      // 44
LocalCollection._diffQueryOrderedChanges = function (old_results, new_results, observer) {            // 45
                                                                                                      // 46
  var new_presence_of_id = {};                                                                        // 47
  _.each(new_results, function (doc) {                                                                // 48
    if (new_presence_of_id[doc._id])                                                                  // 49
      Meteor._debug("Duplicate _id in new_results");                                                  // 50
    new_presence_of_id[doc._id] = true;                                                               // 51
  });                                                                                                 // 52
                                                                                                      // 53
  var old_index_of_id = {};                                                                           // 54
  _.each(old_results, function (doc, i) {                                                             // 55
    if (doc._id in old_index_of_id)                                                                   // 56
      Meteor._debug("Duplicate _id in old_results");                                                  // 57
    old_index_of_id[doc._id] = i;                                                                     // 58
  });                                                                                                 // 59
                                                                                                      // 60
  // ALGORITHM:                                                                                       // 61
  //                                                                                                  // 62
  // To determine which docs should be considered "moved" (and which                                  // 63
  // merely change position because of other docs moving) we run                                      // 64
  // a "longest common subsequence" (LCS) algorithm.  The LCS of the                                  // 65
  // old doc IDs and the new doc IDs gives the docs that should NOT be                                // 66
  // considered moved.                                                                                // 67
                                                                                                      // 68
  // To actually call the appropriate callbacks to get from the old state to the                      // 69
  // new state:                                                                                       // 70
                                                                                                      // 71
  // First, we call removed() on all the items that only appear in the old                            // 72
  // state.                                                                                           // 73
                                                                                                      // 74
  // Then, once we have the items that should not move, we walk through the new                       // 75
  // results array group-by-group, where a "group" is a set of items that have                        // 76
  // moved, anchored on the end by an item that should not move.  One by one, we                      // 77
  // move each of those elements into place "before" the anchoring end-of-group                       // 78
  // item, and fire changed events on them if necessary.  Then we fire a changed                      // 79
  // event on the anchor, and move on to the next group.  There is always at                          // 80
  // least one group; the last group is anchored by a virtual "null" id at the                        // 81
  // end.                                                                                             // 82
                                                                                                      // 83
  // Asymptotically: O(N k) where k is number of ops, or potentially                                  // 84
  // O(N log N) if inner loop of LCS were made to be binary search.                                   // 85
                                                                                                      // 86
                                                                                                      // 87
  //////// LCS (longest common sequence, with respect to _id)                                         // 88
  // (see Wikipedia article on Longest Increasing Subsequence,                                        // 89
  // where the LIS is taken of the sequence of old indices of the                                     // 90
  // docs in new_results)                                                                             // 91
  //                                                                                                  // 92
  // unmoved: the output of the algorithm; members of the LCS,                                        // 93
  // in the form of indices into new_results                                                          // 94
  var unmoved = [];                                                                                   // 95
  // max_seq_len: length of LCS found so far                                                          // 96
  var max_seq_len = 0;                                                                                // 97
  // seq_ends[i]: the index into new_results of the last doc in a                                     // 98
  // common subsequence of length of i+1 <= max_seq_len                                               // 99
  var N = new_results.length;                                                                         // 100
  var seq_ends = new Array(N);                                                                        // 101
  // ptrs:  the common subsequence ending with new_results[n] extends                                 // 102
  // a common subsequence ending with new_results[ptr[n]], unless                                     // 103
  // ptr[n] is -1.                                                                                    // 104
  var ptrs = new Array(N);                                                                            // 105
  // virtual sequence of old indices of new results                                                   // 106
  var old_idx_seq = function(i_new) {                                                                 // 107
    return old_index_of_id[new_results[i_new]._id];                                                   // 108
  };                                                                                                  // 109
  // for each item in new_results, use it to extend a common subsequence                              // 110
  // of length j <= max_seq_len                                                                       // 111
  for(var i=0; i<N; i++) {                                                                            // 112
    if (old_index_of_id[new_results[i]._id] !== undefined) {                                          // 113
      var j = max_seq_len;                                                                            // 114
      // this inner loop would traditionally be a binary search,                                      // 115
      // but scanning backwards we will likely find a subseq to extend                                // 116
      // pretty soon, bounded for example by the total number of ops.                                 // 117
      // If this were to be changed to a binary search, we'd still want                               // 118
      // to scan backwards a bit as an optimization.                                                  // 119
      while (j > 0) {                                                                                 // 120
        if (old_idx_seq(seq_ends[j-1]) < old_idx_seq(i))                                              // 121
          break;                                                                                      // 122
        j--;                                                                                          // 123
      }                                                                                               // 124
                                                                                                      // 125
      ptrs[i] = (j === 0 ? -1 : seq_ends[j-1]);                                                       // 126
      seq_ends[j] = i;                                                                                // 127
      if (j+1 > max_seq_len)                                                                          // 128
        max_seq_len = j+1;                                                                            // 129
    }                                                                                                 // 130
  }                                                                                                   // 131
                                                                                                      // 132
  // pull out the LCS/LIS into unmoved                                                                // 133
  var idx = (max_seq_len === 0 ? -1 : seq_ends[max_seq_len-1]);                                       // 134
  while (idx >= 0) {                                                                                  // 135
    unmoved.push(idx);                                                                                // 136
    idx = ptrs[idx];                                                                                  // 137
  }                                                                                                   // 138
  // the unmoved item list is built backwards, so fix that                                            // 139
  unmoved.reverse();                                                                                  // 140
                                                                                                      // 141
  // the last group is always anchored by the end of the result list, which is                        // 142
  // an id of "null"                                                                                  // 143
  unmoved.push(new_results.length);                                                                   // 144
                                                                                                      // 145
  _.each(old_results, function (doc) {                                                                // 146
    if (!new_presence_of_id[doc._id])                                                                 // 147
      observer.removed && observer.removed(doc._id);                                                  // 148
  });                                                                                                 // 149
  // for each group of things in the new_results that is anchored by an unmoved                       // 150
  // element, iterate through the things before it.                                                   // 151
  var startOfGroup = 0;                                                                               // 152
  _.each(unmoved, function (endOfGroup) {                                                             // 153
    var groupId = new_results[endOfGroup] ? new_results[endOfGroup]._id : null;                       // 154
    var oldDoc;                                                                                       // 155
    var newDoc;                                                                                       // 156
    var fields;                                                                                       // 157
    for (var i = startOfGroup; i < endOfGroup; i++) {                                                 // 158
      newDoc = new_results[i];                                                                        // 159
      if (!_.has(old_index_of_id, newDoc._id)) {                                                      // 160
        fields = EJSON.clone(newDoc);                                                                 // 161
        delete fields._id;                                                                            // 162
        observer.addedBefore && observer.addedBefore(newDoc._id, fields, groupId);                    // 163
        observer.added && observer.added(newDoc._id, fields);                                         // 164
      } else {                                                                                        // 165
        // moved                                                                                      // 166
        oldDoc = old_results[old_index_of_id[newDoc._id]];                                            // 167
        fields = LocalCollection._makeChangedFields(newDoc, oldDoc);                                  // 168
        if (!_.isEmpty(fields)) {                                                                     // 169
          observer.changed && observer.changed(newDoc._id, fields);                                   // 170
        }                                                                                             // 171
        observer.movedBefore && observer.movedBefore(newDoc._id, groupId);                            // 172
      }                                                                                               // 173
    }                                                                                                 // 174
    if (groupId) {                                                                                    // 175
      newDoc = new_results[endOfGroup];                                                               // 176
      oldDoc = old_results[old_index_of_id[newDoc._id]];                                              // 177
      fields = LocalCollection._makeChangedFields(newDoc, oldDoc);                                    // 178
      if (!_.isEmpty(fields)) {                                                                       // 179
        observer.changed && observer.changed(newDoc._id, fields);                                     // 180
      }                                                                                               // 181
    }                                                                                                 // 182
    startOfGroup = endOfGroup+1;                                                                      // 183
  });                                                                                                 // 184
                                                                                                      // 185
                                                                                                      // 186
};                                                                                                    // 187
                                                                                                      // 188
                                                                                                      // 189
// General helper for diff-ing two objects.                                                           // 190
// callbacks is an object like so:                                                                    // 191
// { leftOnly: function (key, leftValue) {...},                                                       // 192
//   rightOnly: function (key, rightValue) {...},                                                     // 193
//   both: function (key, leftValue, rightValue) {...},                                               // 194
// }                                                                                                  // 195
LocalCollection._diffObjects = function (left, right, callbacks) {                                    // 196
  _.each(left, function (leftValue, key) {                                                            // 197
    if (_.has(right, key))                                                                            // 198
      callbacks.both && callbacks.both(key, leftValue, right[key]);                                   // 199
    else                                                                                              // 200
      callbacks.leftOnly && callbacks.leftOnly(key, leftValue);                                       // 201
  });                                                                                                 // 202
  if (callbacks.rightOnly) {                                                                          // 203
    _.each(right, function(rightValue, key) {                                                         // 204
      if (!_.has(left, key))                                                                          // 205
        callbacks.rightOnly(key, rightValue);                                                         // 206
    });                                                                                               // 207
  }                                                                                                   // 208
};                                                                                                    // 209
                                                                                                      // 210
////////////////////////////////////////////////////////////////////////////////////////////////////////

}).call(this);






(function () {

////////////////////////////////////////////////////////////////////////////////////////////////////////
//                                                                                                    //
// packages/minimongo/id_map.js                                                                       //
//                                                                                                    //
////////////////////////////////////////////////////////////////////////////////////////////////////////
                                                                                                      //
LocalCollection._IdMap = function () {                                                                // 1
  var self = this;                                                                                    // 2
  IdMap.call(self, LocalCollection._idStringify, LocalCollection._idParse);                           // 3
};                                                                                                    // 4
                                                                                                      // 5
Meteor._inherits(LocalCollection._IdMap, IdMap);                                                      // 6
                                                                                                      // 7
                                                                                                      // 8
////////////////////////////////////////////////////////////////////////////////////////////////////////

}).call(this);






(function () {

////////////////////////////////////////////////////////////////////////////////////////////////////////
//                                                                                                    //
// packages/minimongo/observe.js                                                                      //
//                                                                                                    //
////////////////////////////////////////////////////////////////////////////////////////////////////////
                                                                                                      //
// XXX maybe move these into another ObserveHelpers package or something                              // 1
                                                                                                      // 2
// _CachingChangeObserver is an object which receives observeChanges callbacks                        // 3
// and keeps a cache of the current cursor state up to date in self.docs. Users                       // 4
// of this class should read the docs field but not modify it. You should pass                        // 5
// the "applyChange" field as the callbacks to the underlying observeChanges                          // 6
// call. Optionally, you can specify your own observeChanges callbacks which are                      // 7
// invoked immediately before the docs field is updated; this object is made                          // 8
// available as `this` to those callbacks.                                                            // 9
LocalCollection._CachingChangeObserver = function (options) {                                         // 10
  var self = this;                                                                                    // 11
  options = options || {};                                                                            // 12
                                                                                                      // 13
  var orderedFromCallbacks = options.callbacks &&                                                     // 14
        LocalCollection._observeChangesCallbacksAreOrdered(options.callbacks);                        // 15
  if (_.has(options, 'ordered')) {                                                                    // 16
    self.ordered = options.ordered;                                                                   // 17
    if (options.callbacks && options.ordered !== orderedFromCallbacks)                                // 18
      throw Error("ordered option doesn't match callbacks");                                          // 19
  } else if (options.callbacks) {                                                                     // 20
    self.ordered = orderedFromCallbacks;                                                              // 21
  } else {                                                                                            // 22
    throw Error("must provide ordered or callbacks");                                                 // 23
  }                                                                                                   // 24
  var callbacks = options.callbacks || {};                                                            // 25
                                                                                                      // 26
  if (self.ordered) {                                                                                 // 27
    self.docs = new OrderedDict(LocalCollection._idStringify);                                        // 28
    self.applyChange = {                                                                              // 29
      addedBefore: function (id, fields, before) {                                                    // 30
        var doc = EJSON.clone(fields);                                                                // 31
        doc._id = id;                                                                                 // 32
        callbacks.addedBefore && callbacks.addedBefore.call(                                          // 33
          self, id, fields, before);                                                                  // 34
        // This line triggers if we provide added with movedBefore.                                   // 35
        callbacks.added && callbacks.added.call(self, id, fields);                                    // 36
        // XXX could `before` be a falsy ID?  Technically                                             // 37
        // idStringify seems to allow for them -- though                                              // 38
        // OrderedDict won't call stringify on a falsy arg.                                           // 39
        self.docs.putBefore(id, doc, before || null);                                                 // 40
      },                                                                                              // 41
      movedBefore: function (id, before) {                                                            // 42
        var doc = self.docs.get(id);                                                                  // 43
        callbacks.movedBefore && callbacks.movedBefore.call(self, id, before);                        // 44
        self.docs.moveBefore(id, before || null);                                                     // 45
      }                                                                                               // 46
    };                                                                                                // 47
  } else {                                                                                            // 48
    self.docs = new LocalCollection._IdMap;                                                           // 49
    self.applyChange = {                                                                              // 50
      added: function (id, fields) {                                                                  // 51
        var doc = EJSON.clone(fields);                                                                // 52
        callbacks.added && callbacks.added.call(self, id, fields);                                    // 53
        doc._id = id;                                                                                 // 54
        self.docs.set(id,  doc);                                                                      // 55
      }                                                                                               // 56
    };                                                                                                // 57
  }                                                                                                   // 58
                                                                                                      // 59
  // The methods in _IdMap and OrderedDict used by these callbacks are                                // 60
  // identical.                                                                                       // 61
  self.applyChange.changed = function (id, fields) {                                                  // 62
    var doc = self.docs.get(id);                                                                      // 63
    if (!doc)                                                                                         // 64
      throw new Error("Unknown id for changed: " + id);                                               // 65
    callbacks.changed && callbacks.changed.call(                                                      // 66
      self, id, EJSON.clone(fields));                                                                 // 67
    LocalCollection._applyChanges(doc, fields);                                                       // 68
  };                                                                                                  // 69
  self.applyChange.removed = function (id) {                                                          // 70
    callbacks.removed && callbacks.removed.call(self, id);                                            // 71
    self.docs.remove(id);                                                                             // 72
  };                                                                                                  // 73
};                                                                                                    // 74
                                                                                                      // 75
LocalCollection._observeFromObserveChanges = function (cursor, observeCallbacks) {                    // 76
  var transform = cursor.getTransform() || function (doc) {return doc;};                              // 77
  var suppressed = !!observeCallbacks._suppress_initial;                                              // 78
                                                                                                      // 79
  var observeChangesCallbacks;                                                                        // 80
  if (LocalCollection._observeCallbacksAreOrdered(observeCallbacks)) {                                // 81
    // The "_no_indices" option sets all index arguments to -1 and skips the                          // 82
    // linear scans required to generate them.  This lets observers that don't                        // 83
    // need absolute indices benefit from the other features of this API --                           // 84
    // relative order, transforms, and applyChanges -- without the speed hit.                         // 85
    var indices = !observeCallbacks._no_indices;                                                      // 86
    observeChangesCallbacks = {                                                                       // 87
      addedBefore: function (id, fields, before) {                                                    // 88
        var self = this;                                                                              // 89
        if (suppressed || !(observeCallbacks.addedAt || observeCallbacks.added))                      // 90
          return;                                                                                     // 91
        var doc = transform(_.extend(fields, {_id: id}));                                             // 92
        if (observeCallbacks.addedAt) {                                                               // 93
          var index = indices                                                                         // 94
                ? (before ? self.docs.indexOf(before) : self.docs.size()) : -1;                       // 95
          observeCallbacks.addedAt(doc, index, before);                                               // 96
        } else {                                                                                      // 97
          observeCallbacks.added(doc);                                                                // 98
        }                                                                                             // 99
      },                                                                                              // 100
      changed: function (id, fields) {                                                                // 101
        var self = this;                                                                              // 102
        if (!(observeCallbacks.changedAt || observeCallbacks.changed))                                // 103
          return;                                                                                     // 104
        var doc = EJSON.clone(self.docs.get(id));                                                     // 105
        if (!doc)                                                                                     // 106
          throw new Error("Unknown id for changed: " + id);                                           // 107
        var oldDoc = transform(EJSON.clone(doc));                                                     // 108
        LocalCollection._applyChanges(doc, fields);                                                   // 109
        doc = transform(doc);                                                                         // 110
        if (observeCallbacks.changedAt) {                                                             // 111
          var index = indices ? self.docs.indexOf(id) : -1;                                           // 112
          observeCallbacks.changedAt(doc, oldDoc, index);                                             // 113
        } else {                                                                                      // 114
          observeCallbacks.changed(doc, oldDoc);                                                      // 115
        }                                                                                             // 116
      },                                                                                              // 117
      movedBefore: function (id, before) {                                                            // 118
        var self = this;                                                                              // 119
        if (!observeCallbacks.movedTo)                                                                // 120
          return;                                                                                     // 121
        var from = indices ? self.docs.indexOf(id) : -1;                                              // 122
                                                                                                      // 123
        var to = indices                                                                              // 124
              ? (before ? self.docs.indexOf(before) : self.docs.size()) : -1;                         // 125
        // When not moving backwards, adjust for the fact that removing the                           // 126
        // document slides everything back one slot.                                                  // 127
        if (to > from)                                                                                // 128
          --to;                                                                                       // 129
        observeCallbacks.movedTo(transform(EJSON.clone(self.docs.get(id))),                           // 130
                                 from, to, before || null);                                           // 131
      },                                                                                              // 132
      removed: function (id) {                                                                        // 133
        var self = this;                                                                              // 134
        if (!(observeCallbacks.removedAt || observeCallbacks.removed))                                // 135
          return;                                                                                     // 136
        // technically maybe there should be an EJSON.clone here, but it's about                      // 137
        // to be removed from self.docs!                                                              // 138
        var doc = transform(self.docs.get(id));                                                       // 139
        if (observeCallbacks.removedAt) {                                                             // 140
          var index = indices ? self.docs.indexOf(id) : -1;                                           // 141
          observeCallbacks.removedAt(doc, index);                                                     // 142
        } else {                                                                                      // 143
          observeCallbacks.removed(doc);                                                              // 144
        }                                                                                             // 145
      }                                                                                               // 146
    };                                                                                                // 147
  } else {                                                                                            // 148
    observeChangesCallbacks = {                                                                       // 149
      added: function (id, fields) {                                                                  // 150
        if (!suppressed && observeCallbacks.added) {                                                  // 151
          var doc = _.extend(fields, {_id:  id});                                                     // 152
          observeCallbacks.added(transform(doc));                                                     // 153
        }                                                                                             // 154
      },                                                                                              // 155
      changed: function (id, fields) {                                                                // 156
        var self = this;                                                                              // 157
        if (observeCallbacks.changed) {                                                               // 158
          var oldDoc = self.docs.get(id);                                                             // 159
          var doc = EJSON.clone(oldDoc);                                                              // 160
          LocalCollection._applyChanges(doc, fields);                                                 // 161
          observeCallbacks.changed(transform(doc), transform(oldDoc));                                // 162
        }                                                                                             // 163
      },                                                                                              // 164
      removed: function (id) {                                                                        // 165
        var self = this;                                                                              // 166
        if (observeCallbacks.removed) {                                                               // 167
          observeCallbacks.removed(transform(self.docs.get(id)));                                     // 168
        }                                                                                             // 169
      }                                                                                               // 170
    };                                                                                                // 171
  }                                                                                                   // 172
                                                                                                      // 173
  var changeObserver = new LocalCollection._CachingChangeObserver(                                    // 174
    {callbacks: observeChangesCallbacks});                                                            // 175
  var handle = cursor.observeChanges(changeObserver.applyChange);                                     // 176
  suppressed = false;                                                                                 // 177
                                                                                                      // 178
  if (changeObserver.ordered) {                                                                       // 179
    // Fetches the current list of documents, in order, as an array.  Can be                          // 180
    // called at any time.  Internal API assumed by the `observe-sequence`                            // 181
    // package (used by Meteor UI for `#each` blocks).  Only defined on ordered                       // 182
    // observes (those that listen on `addedAt` or similar).  Continues to work                       // 183
    // after `stop()` is called on the handle.                                                        // 184
    //                                                                                                // 185
    // Because we already materialize the full OrderedDict of all documents, it                       // 186
    // seems nice to provide access to the view rather than making the data                           // 187
    // consumer reconstitute it.  This gives the consumer a shot at doing                             // 188
    // something smart with the feed like proxying it, since firing callbacks                         // 189
    // like `changed` and `movedTo` basically requires omniscience (knowing old                       // 190
    // and new documents, old and new indices, and the correct value for                              // 191
    // `before`).                                                                                     // 192
    //                                                                                                // 193
    // NOTE: If called from an observe callback for a certain change, the result                      // 194
    // is *not* guaranteed to be a snapshot of the cursor up to that                                  // 195
    // change. This is because the callbacks are invoked before updating docs.                        // 196
    handle._fetch = function () {                                                                     // 197
      var docsArray = [];                                                                             // 198
      changeObserver.docs.forEach(function (doc) {                                                    // 199
        docsArray.push(transform(EJSON.clone(doc)));                                                  // 200
      });                                                                                             // 201
      return docsArray;                                                                               // 202
    };                                                                                                // 203
  }                                                                                                   // 204
                                                                                                      // 205
  return handle;                                                                                      // 206
};                                                                                                    // 207
                                                                                                      // 208
////////////////////////////////////////////////////////////////////////////////////////////////////////

}).call(this);






(function () {

////////////////////////////////////////////////////////////////////////////////////////////////////////
//                                                                                                    //
// packages/minimongo/objectid.js                                                                     //
//                                                                                                    //
////////////////////////////////////////////////////////////////////////////////////////////////////////
                                                                                                      //
LocalCollection._looksLikeObjectID = function (str) {                                                 // 1
  return str.length === 24 && str.match(/^[0-9a-f]*$/);                                               // 2
};                                                                                                    // 3
                                                                                                      // 4
LocalCollection._ObjectID = function (hexString) {                                                    // 5
  //random-based impl of Mongo ObjectID                                                               // 6
  var self = this;                                                                                    // 7
  if (hexString) {                                                                                    // 8
    hexString = hexString.toLowerCase();                                                              // 9
    if (!LocalCollection._looksLikeObjectID(hexString)) {                                             // 10
      throw new Error("Invalid hexadecimal string for creating an ObjectID");                         // 11
    }                                                                                                 // 12
    // meant to work with _.isEqual(), which relies on structural equality                            // 13
    self._str = hexString;                                                                            // 14
  } else {                                                                                            // 15
    self._str = Random.hexString(24);                                                                 // 16
  }                                                                                                   // 17
};                                                                                                    // 18
                                                                                                      // 19
LocalCollection._ObjectID.prototype.toString = function () {                                          // 20
  var self = this;                                                                                    // 21
  return "ObjectID(\"" + self._str + "\")";                                                           // 22
};                                                                                                    // 23
                                                                                                      // 24
LocalCollection._ObjectID.prototype.equals = function (other) {                                       // 25
  var self = this;                                                                                    // 26
  return other instanceof LocalCollection._ObjectID &&                                                // 27
    self.valueOf() === other.valueOf();                                                               // 28
};                                                                                                    // 29
                                                                                                      // 30
LocalCollection._ObjectID.prototype.clone = function () {                                             // 31
  var self = this;                                                                                    // 32
  return new LocalCollection._ObjectID(self._str);                                                    // 33
};                                                                                                    // 34
                                                                                                      // 35
LocalCollection._ObjectID.prototype.typeName = function() {                                           // 36
  return "oid";                                                                                       // 37
};                                                                                                    // 38
                                                                                                      // 39
LocalCollection._ObjectID.prototype.getTimestamp = function() {                                       // 40
  var self = this;                                                                                    // 41
  return parseInt(self._str.substr(0, 8), 16);                                                        // 42
};                                                                                                    // 43
                                                                                                      // 44
LocalCollection._ObjectID.prototype.valueOf =                                                         // 45
    LocalCollection._ObjectID.prototype.toJSONValue =                                                 // 46
    LocalCollection._ObjectID.prototype.toHexString =                                                 // 47
    function () { return this._str; };                                                                // 48
                                                                                                      // 49
// Is this selector just shorthand for lookup by _id?                                                 // 50
LocalCollection._selectorIsId = function (selector) {                                                 // 51
  return (typeof selector === "string") ||                                                            // 52
    (typeof selector === "number") ||                                                                 // 53
    selector instanceof LocalCollection._ObjectID;                                                    // 54
};                                                                                                    // 55
                                                                                                      // 56
// Is the selector just lookup by _id (shorthand or not)?                                             // 57
LocalCollection._selectorIsIdPerhapsAsObject = function (selector) {                                  // 58
  return LocalCollection._selectorIsId(selector) ||                                                   // 59
    (selector && typeof selector === "object" &&                                                      // 60
     selector._id && LocalCollection._selectorIsId(selector._id) &&                                   // 61
     _.size(selector) === 1);                                                                         // 62
};                                                                                                    // 63
                                                                                                      // 64
// If this is a selector which explicitly constrains the match by ID to a finite                      // 65
// number of documents, returns a list of their IDs.  Otherwise returns                               // 66
// null. Note that the selector may have other restrictions so it may not even                        // 67
// match those document!  We care about $in and $and since those are generated                        // 68
// access-controlled update and remove.                                                               // 69
LocalCollection._idsMatchedBySelector = function (selector) {                                         // 70
  // Is the selector just an ID?                                                                      // 71
  if (LocalCollection._selectorIsId(selector))                                                        // 72
    return [selector];                                                                                // 73
  if (!selector)                                                                                      // 74
    return null;                                                                                      // 75
                                                                                                      // 76
  // Do we have an _id clause?                                                                        // 77
  if (_.has(selector, '_id')) {                                                                       // 78
    // Is the _id clause just an ID?                                                                  // 79
    if (LocalCollection._selectorIsId(selector._id))                                                  // 80
      return [selector._id];                                                                          // 81
    // Is the _id clause {_id: {$in: ["x", "y", "z"]}}?                                               // 82
    if (selector._id && selector._id.$in                                                              // 83
        && _.isArray(selector._id.$in)                                                                // 84
        && !_.isEmpty(selector._id.$in)                                                               // 85
        && _.all(selector._id.$in, LocalCollection._selectorIsId)) {                                  // 86
      return selector._id.$in;                                                                        // 87
    }                                                                                                 // 88
    return null;                                                                                      // 89
  }                                                                                                   // 90
                                                                                                      // 91
  // If this is a top-level $and, and any of the clauses constrain their                              // 92
  // documents, then the whole selector is constrained by any one clause's                            // 93
  // constraint. (Well, by their intersection, but that seems unlikely.)                              // 94
  if (selector.$and && _.isArray(selector.$and)) {                                                    // 95
    for (var i = 0; i < selector.$and.length; ++i) {                                                  // 96
      var subIds = LocalCollection._idsMatchedBySelector(selector.$and[i]);                           // 97
      if (subIds)                                                                                     // 98
        return subIds;                                                                                // 99
    }                                                                                                 // 100
  }                                                                                                   // 101
                                                                                                      // 102
  return null;                                                                                        // 103
};                                                                                                    // 104
                                                                                                      // 105
EJSON.addType("oid",  function (str) {                                                                // 106
  return new LocalCollection._ObjectID(str);                                                          // 107
});                                                                                                   // 108
                                                                                                      // 109
////////////////////////////////////////////////////////////////////////////////////////////////////////

}).call(this);


/* Exports */
if (typeof Package === 'undefined') Package = {};
Package.minimongo = {
  LocalCollection: LocalCollection,
  Minimongo: Minimongo,
  MinimongoTest: MinimongoTest
};

})();

//# sourceMappingURL=6aa0e153bfd7e4a28ee447a4cbfaf1fef0870a06.map
