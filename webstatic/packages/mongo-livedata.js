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
var Random = Package.random.Random;
var EJSON = Package.ejson.EJSON;
var JSON = Package.json.JSON;
var _ = Package.underscore._;
var LocalCollection = Package.minimongo.LocalCollection;
var Minimongo = Package.minimongo.Minimongo;
var Log = Package.logging.Log;
var DDP = Package.livedata.DDP;
var Deps = Package.deps.Deps;
var check = Package.check.check;
var Match = Package.check.Match;

/* Package-scope variables */
var LocalCollectionDriver;

(function () {

/////////////////////////////////////////////////////////////////////////////////////////////////////////
//                                                                                                     //
// packages/mongo-livedata/local_collection_driver.js                                                  //
//                                                                                                     //
/////////////////////////////////////////////////////////////////////////////////////////////////////////
                                                                                                       //
LocalCollectionDriver = function () {                                                                  // 1
  var self = this;                                                                                     // 2
  self.noConnCollections = {};                                                                         // 3
};                                                                                                     // 4
                                                                                                       // 5
var ensureCollection = function (name, collections) {                                                  // 6
  if (!(name in collections))                                                                          // 7
    collections[name] = new LocalCollection(name);                                                     // 8
  return collections[name];                                                                            // 9
};                                                                                                     // 10
                                                                                                       // 11
_.extend(LocalCollectionDriver.prototype, {                                                            // 12
  open: function (name, conn) {                                                                        // 13
    var self = this;                                                                                   // 14
    if (!name)                                                                                         // 15
      return new LocalCollection;                                                                      // 16
    if (! conn) {                                                                                      // 17
      return ensureCollection(name, self.noConnCollections);                                           // 18
    }                                                                                                  // 19
    if (! conn._mongo_livedata_collections)                                                            // 20
      conn._mongo_livedata_collections = {};                                                           // 21
    // XXX is there a way to keep track of a connection's collections without                          // 22
    // dangling it off the connection object?                                                          // 23
    return ensureCollection(name, conn._mongo_livedata_collections);                                   // 24
  }                                                                                                    // 25
});                                                                                                    // 26
                                                                                                       // 27
// singleton                                                                                           // 28
LocalCollectionDriver = new LocalCollectionDriver;                                                     // 29
                                                                                                       // 30
/////////////////////////////////////////////////////////////////////////////////////////////////////////

}).call(this);






(function () {

/////////////////////////////////////////////////////////////////////////////////////////////////////////
//                                                                                                     //
// packages/mongo-livedata/collection.js                                                               //
//                                                                                                     //
/////////////////////////////////////////////////////////////////////////////////////////////////////////
                                                                                                       //
// options.connection, if given, is a LivedataClient or LivedataServer                                 // 1
// XXX presently there is no way to destroy/clean up a Collection                                      // 2
                                                                                                       // 3
Meteor.Collection = function (name, options) {                                                         // 4
  var self = this;                                                                                     // 5
  if (! (self instanceof Meteor.Collection))                                                           // 6
    throw new Error('use "new" to construct a Meteor.Collection');                                     // 7
                                                                                                       // 8
  if (!name && (name !== null)) {                                                                      // 9
    Meteor._debug("Warning: creating anonymous collection. It will not be " +                          // 10
                  "saved or synchronized over the network. (Pass null for " +                          // 11
                  "the collection name to turn off this warning.)");                                   // 12
    name = null;                                                                                       // 13
  }                                                                                                    // 14
                                                                                                       // 15
  if (name !== null && typeof name !== "string") {                                                     // 16
    throw new Error(                                                                                   // 17
      "First argument to new Meteor.Collection must be a string or null");                             // 18
  }                                                                                                    // 19
                                                                                                       // 20
  if (options && options.methods) {                                                                    // 21
    // Backwards compatibility hack with original signature (which passed                              // 22
    // "connection" directly instead of in options. (Connections must have a "methods"                 // 23
    // method.)                                                                                        // 24
    // XXX remove before 1.0                                                                           // 25
    options = {connection: options};                                                                   // 26
  }                                                                                                    // 27
  // Backwards compatibility: "connection" used to be called "manager".                                // 28
  if (options && options.manager && !options.connection) {                                             // 29
    options.connection = options.manager;                                                              // 30
  }                                                                                                    // 31
  options = _.extend({                                                                                 // 32
    connection: undefined,                                                                             // 33
    idGeneration: 'STRING',                                                                            // 34
    transform: null,                                                                                   // 35
    _driver: undefined,                                                                                // 36
    _preventAutopublish: false                                                                         // 37
  }, options);                                                                                         // 38
                                                                                                       // 39
  switch (options.idGeneration) {                                                                      // 40
  case 'MONGO':                                                                                        // 41
    self._makeNewID = function () {                                                                    // 42
      var src = name ? DDP.randomStream('/collection/' + name) : Random;                               // 43
      return new Meteor.Collection.ObjectID(src.hexString(24));                                        // 44
    };                                                                                                 // 45
    break;                                                                                             // 46
  case 'STRING':                                                                                       // 47
  default:                                                                                             // 48
    self._makeNewID = function () {                                                                    // 49
      var src = name ? DDP.randomStream('/collection/' + name) : Random;                               // 50
      return src.id();                                                                                 // 51
    };                                                                                                 // 52
    break;                                                                                             // 53
  }                                                                                                    // 54
                                                                                                       // 55
  self._transform = LocalCollection.wrapTransform(options.transform);                                  // 56
                                                                                                       // 57
  if (! name || options.connection === null)                                                           // 58
    // note: nameless collections never have a connection                                              // 59
    self._connection = null;                                                                           // 60
  else if (options.connection)                                                                         // 61
    self._connection = options.connection;                                                             // 62
  else if (Meteor.isClient)                                                                            // 63
    self._connection = Meteor.connection;                                                              // 64
  else                                                                                                 // 65
    self._connection = Meteor.server;                                                                  // 66
                                                                                                       // 67
  if (!options._driver) {                                                                              // 68
    if (name && self._connection === Meteor.server &&                                                  // 69
        typeof MongoInternals !== "undefined" &&                                                       // 70
        MongoInternals.defaultRemoteCollectionDriver) {                                                // 71
      options._driver = MongoInternals.defaultRemoteCollectionDriver();                                // 72
    } else {                                                                                           // 73
      options._driver = LocalCollectionDriver;                                                         // 74
    }                                                                                                  // 75
  }                                                                                                    // 76
                                                                                                       // 77
  self._collection = options._driver.open(name, self._connection);                                     // 78
  self._name = name;                                                                                   // 79
                                                                                                       // 80
  if (self._connection && self._connection.registerStore) {                                            // 81
    // OK, we're going to be a slave, replicating some remote                                          // 82
    // database, except possibly with some temporary divergence while                                  // 83
    // we have unacknowledged RPC's.                                                                   // 84
    var ok = self._connection.registerStore(name, {                                                    // 85
      // Called at the beginning of a batch of updates. batchSize is the number                        // 86
      // of update calls to expect.                                                                    // 87
      //                                                                                               // 88
      // XXX This interface is pretty janky. reset probably ought to go back to                        // 89
      // being its own function, and callers shouldn't have to calculate                               // 90
      // batchSize. The optimization of not calling pause/remove should be                             // 91
      // delayed until later: the first call to update() should buffer its                             // 92
      // message, and then we can either directly apply it at endUpdate time if                        // 93
      // it was the only update, or do pauseObservers/apply/apply at the next                          // 94
      // update() if there's another one.                                                              // 95
      beginUpdate: function (batchSize, reset) {                                                       // 96
        // pause observers so users don't see flicker when updating several                            // 97
        // objects at once (including the post-reconnect reset-and-reapply                             // 98
        // stage), and so that a re-sorting of a query can take advantage of the                       // 99
        // full _diffQuery moved calculation instead of applying change one at a                       // 100
        // time.                                                                                       // 101
        if (batchSize > 1 || reset)                                                                    // 102
          self._collection.pauseObservers();                                                           // 103
                                                                                                       // 104
        if (reset)                                                                                     // 105
          self._collection.remove({});                                                                 // 106
      },                                                                                               // 107
                                                                                                       // 108
      // Apply an update.                                                                              // 109
      // XXX better specify this interface (not in terms of a wire message)?                           // 110
      update: function (msg) {                                                                         // 111
        var mongoId = LocalCollection._idParse(msg.id);                                                // 112
        var doc = self._collection.findOne(mongoId);                                                   // 113
                                                                                                       // 114
        // Is this a "replace the whole doc" message coming from the quiescence                        // 115
        // of method writes to an object? (Note that 'undefined' is a valid                            // 116
        // value meaning "remove it".)                                                                 // 117
        if (msg.msg === 'replace') {                                                                   // 118
          var replace = msg.replace;                                                                   // 119
          if (!replace) {                                                                              // 120
            if (doc)                                                                                   // 121
              self._collection.remove(mongoId);                                                        // 122
          } else if (!doc) {                                                                           // 123
            self._collection.insert(replace);                                                          // 124
          } else {                                                                                     // 125
            // XXX check that replace has no $ ops                                                     // 126
            self._collection.update(mongoId, replace);                                                 // 127
          }                                                                                            // 128
          return;                                                                                      // 129
        } else if (msg.msg === 'added') {                                                              // 130
          if (doc) {                                                                                   // 131
            throw new Error("Expected not to find a document already present for an add");             // 132
          }                                                                                            // 133
          self._collection.insert(_.extend({_id: mongoId}, msg.fields));                               // 134
        } else if (msg.msg === 'removed') {                                                            // 135
          if (!doc)                                                                                    // 136
            throw new Error("Expected to find a document already present for removed");                // 137
          self._collection.remove(mongoId);                                                            // 138
        } else if (msg.msg === 'changed') {                                                            // 139
          if (!doc)                                                                                    // 140
            throw new Error("Expected to find a document to change");                                  // 141
          if (!_.isEmpty(msg.fields)) {                                                                // 142
            var modifier = {};                                                                         // 143
            _.each(msg.fields, function (value, key) {                                                 // 144
              if (value === undefined) {                                                               // 145
                if (!modifier.$unset)                                                                  // 146
                  modifier.$unset = {};                                                                // 147
                modifier.$unset[key] = 1;                                                              // 148
              } else {                                                                                 // 149
                if (!modifier.$set)                                                                    // 150
                  modifier.$set = {};                                                                  // 151
                modifier.$set[key] = value;                                                            // 152
              }                                                                                        // 153
            });                                                                                        // 154
            self._collection.update(mongoId, modifier);                                                // 155
          }                                                                                            // 156
        } else {                                                                                       // 157
          throw new Error("I don't know how to deal with this message");                               // 158
        }                                                                                              // 159
                                                                                                       // 160
      },                                                                                               // 161
                                                                                                       // 162
      // Called at the end of a batch of updates.                                                      // 163
      endUpdate: function () {                                                                         // 164
        self._collection.resumeObservers();                                                            // 165
      },                                                                                               // 166
                                                                                                       // 167
      // Called around method stub invocations to capture the original versions                        // 168
      // of modified documents.                                                                        // 169
      saveOriginals: function () {                                                                     // 170
        self._collection.saveOriginals();                                                              // 171
      },                                                                                               // 172
      retrieveOriginals: function () {                                                                 // 173
        return self._collection.retrieveOriginals();                                                   // 174
      }                                                                                                // 175
    });                                                                                                // 176
                                                                                                       // 177
    if (!ok)                                                                                           // 178
      throw new Error("There is already a collection named '" + name + "'");                           // 179
  }                                                                                                    // 180
                                                                                                       // 181
  self._defineMutationMethods();                                                                       // 182
                                                                                                       // 183
  // autopublish                                                                                       // 184
  if (Package.autopublish && !options._preventAutopublish && self._connection                          // 185
      && self._connection.publish) {                                                                   // 186
    self._connection.publish(null, function () {                                                       // 187
      return self.find();                                                                              // 188
    }, {is_auto: true});                                                                               // 189
  }                                                                                                    // 190
};                                                                                                     // 191
                                                                                                       // 192
///                                                                                                    // 193
/// Main collection API                                                                                // 194
///                                                                                                    // 195
                                                                                                       // 196
                                                                                                       // 197
_.extend(Meteor.Collection.prototype, {                                                                // 198
                                                                                                       // 199
  _getFindSelector: function (args) {                                                                  // 200
    if (args.length == 0)                                                                              // 201
      return {};                                                                                       // 202
    else                                                                                               // 203
      return args[0];                                                                                  // 204
  },                                                                                                   // 205
                                                                                                       // 206
  _getFindOptions: function (args) {                                                                   // 207
    var self = this;                                                                                   // 208
    if (args.length < 2) {                                                                             // 209
      return { transform: self._transform };                                                           // 210
    } else {                                                                                           // 211
      check(args[1], Match.Optional(Match.ObjectIncluding({                                            // 212
        fields: Match.Optional(Match.OneOf(Object, undefined)),                                        // 213
        sort: Match.Optional(Match.OneOf(Object, Array, undefined)),                                   // 214
        limit: Match.Optional(Match.OneOf(Number, undefined)),                                         // 215
        skip: Match.Optional(Match.OneOf(Number, undefined))                                           // 216
     })));                                                                                             // 217
                                                                                                       // 218
      return _.extend({                                                                                // 219
        transform: self._transform                                                                     // 220
      }, args[1]);                                                                                     // 221
    }                                                                                                  // 222
  },                                                                                                   // 223
                                                                                                       // 224
  find: function (/* selector, options */) {                                                           // 225
    // Collection.find() (return all docs) behaves differently                                         // 226
    // from Collection.find(undefined) (return 0 docs).  so be                                         // 227
    // careful about the length of arguments.                                                          // 228
    var self = this;                                                                                   // 229
    var argArray = _.toArray(arguments);                                                               // 230
    return self._collection.find(self._getFindSelector(argArray),                                      // 231
                                 self._getFindOptions(argArray));                                      // 232
  },                                                                                                   // 233
                                                                                                       // 234
  findOne: function (/* selector, options */) {                                                        // 235
    var self = this;                                                                                   // 236
    var argArray = _.toArray(arguments);                                                               // 237
    return self._collection.findOne(self._getFindSelector(argArray),                                   // 238
                                    self._getFindOptions(argArray));                                   // 239
  }                                                                                                    // 240
                                                                                                       // 241
});                                                                                                    // 242
                                                                                                       // 243
Meteor.Collection._publishCursor = function (cursor, sub, collection) {                                // 244
  var observeHandle = cursor.observeChanges({                                                          // 245
    added: function (id, fields) {                                                                     // 246
      sub.added(collection, id, fields);                                                               // 247
    },                                                                                                 // 248
    changed: function (id, fields) {                                                                   // 249
      sub.changed(collection, id, fields);                                                             // 250
    },                                                                                                 // 251
    removed: function (id) {                                                                           // 252
      sub.removed(collection, id);                                                                     // 253
    }                                                                                                  // 254
  });                                                                                                  // 255
                                                                                                       // 256
  // We don't call sub.ready() here: it gets called in livedata_server, after                          // 257
  // possibly calling _publishCursor on multiple returned cursors.                                     // 258
                                                                                                       // 259
  // register stop callback (expects lambda w/ no args).                                               // 260
  sub.onStop(function () {observeHandle.stop();});                                                     // 261
};                                                                                                     // 262
                                                                                                       // 263
// protect against dangerous selectors.  falsey and {_id: falsey} are both                             // 264
// likely programmer error, and not what you want, particularly for destructive                        // 265
// operations.  JS regexps don't serialize over DDP but can be trivially                               // 266
// replaced by $regex.                                                                                 // 267
Meteor.Collection._rewriteSelector = function (selector) {                                             // 268
  // shorthand -- scalars match _id                                                                    // 269
  if (LocalCollection._selectorIsId(selector))                                                         // 270
    selector = {_id: selector};                                                                        // 271
                                                                                                       // 272
  if (!selector || (('_id' in selector) && !selector._id))                                             // 273
    // can't match anything                                                                            // 274
    return {_id: Random.id()};                                                                         // 275
                                                                                                       // 276
  var ret = {};                                                                                        // 277
  _.each(selector, function (value, key) {                                                             // 278
    // Mongo supports both {field: /foo/} and {field: {$regex: /foo/}}                                 // 279
    if (value instanceof RegExp) {                                                                     // 280
      ret[key] = convertRegexpToMongoSelector(value);                                                  // 281
    } else if (value && value.$regex instanceof RegExp) {                                              // 282
      ret[key] = convertRegexpToMongoSelector(value.$regex);                                           // 283
      // if value is {$regex: /foo/, $options: ...} then $options                                      // 284
      // override the ones set on $regex.                                                              // 285
      if (value.$options !== undefined)                                                                // 286
        ret[key].$options = value.$options;                                                            // 287
    }                                                                                                  // 288
    else if (_.contains(['$or','$and','$nor'], key)) {                                                 // 289
      // Translate lower levels of $and/$or/$nor                                                       // 290
      ret[key] = _.map(value, function (v) {                                                           // 291
        return Meteor.Collection._rewriteSelector(v);                                                  // 292
      });                                                                                              // 293
    } else {                                                                                           // 294
      ret[key] = value;                                                                                // 295
    }                                                                                                  // 296
  });                                                                                                  // 297
  return ret;                                                                                          // 298
};                                                                                                     // 299
                                                                                                       // 300
// convert a JS RegExp object to a Mongo {$regex: ..., $options: ...}                                  // 301
// selector                                                                                            // 302
var convertRegexpToMongoSelector = function (regexp) {                                                 // 303
  check(regexp, RegExp); // safety belt                                                                // 304
                                                                                                       // 305
  var selector = {$regex: regexp.source};                                                              // 306
  var regexOptions = '';                                                                               // 307
  // JS RegExp objects support 'i', 'm', and 'g'. Mongo regex $options                                 // 308
  // support 'i', 'm', 'x', and 's'. So we support 'i' and 'm' here.                                   // 309
  if (regexp.ignoreCase)                                                                               // 310
    regexOptions += 'i';                                                                               // 311
  if (regexp.multiline)                                                                                // 312
    regexOptions += 'm';                                                                               // 313
  if (regexOptions)                                                                                    // 314
    selector.$options = regexOptions;                                                                  // 315
                                                                                                       // 316
  return selector;                                                                                     // 317
};                                                                                                     // 318
                                                                                                       // 319
var throwIfSelectorIsNotId = function (selector, methodName) {                                         // 320
  if (!LocalCollection._selectorIsIdPerhapsAsObject(selector)) {                                       // 321
    throw new Meteor.Error(                                                                            // 322
      403, "Not permitted. Untrusted code may only " + methodName +                                    // 323
        " documents by ID.");                                                                          // 324
  }                                                                                                    // 325
};                                                                                                     // 326
                                                                                                       // 327
// 'insert' immediately returns the inserted document's new _id.                                       // 328
// The others return values immediately if you are in a stub, an in-memory                             // 329
// unmanaged collection, or a mongo-backed collection and you don't pass a                             // 330
// callback. 'update' and 'remove' return the number of affected                                       // 331
// documents. 'upsert' returns an object with keys 'numberAffected' and, if an                         // 332
// insert happened, 'insertedId'.                                                                      // 333
//                                                                                                     // 334
// Otherwise, the semantics are exactly like other methods: they take                                  // 335
// a callback as an optional last argument; if no callback is                                          // 336
// provided, they block until the operation is complete, and throw an                                  // 337
// exception if it fails; if a callback is provided, then they don't                                   // 338
// necessarily block, and they call the callback when they finish with error and                       // 339
// result arguments.  (The insert method provides the document ID as its result;                       // 340
// update and remove provide the number of affected docs as the result; upsert                         // 341
// provides an object with numberAffected and maybe insertedId.)                                       // 342
//                                                                                                     // 343
// On the client, blocking is impossible, so if a callback                                             // 344
// isn't provided, they just return immediately and any error                                          // 345
// information is lost.                                                                                // 346
//                                                                                                     // 347
// There's one more tweak. On the client, if you don't provide a                                       // 348
// callback, then if there is an error, a message will be logged with                                  // 349
// Meteor._debug.                                                                                      // 350
//                                                                                                     // 351
// The intent (though this is actually determined by the underlying                                    // 352
// drivers) is that the operations should be done synchronously, not                                   // 353
// generating their result until the database has acknowledged                                         // 354
// them. In the future maybe we should provide a flag to turn this                                     // 355
// off.                                                                                                // 356
_.each(["insert", "update", "remove"], function (name) {                                               // 357
  Meteor.Collection.prototype[name] = function (/* arguments */) {                                     // 358
    var self = this;                                                                                   // 359
    var args = _.toArray(arguments);                                                                   // 360
    var callback;                                                                                      // 361
    var insertId;                                                                                      // 362
    var ret;                                                                                           // 363
                                                                                                       // 364
    if (args.length && args[args.length - 1] instanceof Function)                                      // 365
      callback = args.pop();                                                                           // 366
                                                                                                       // 367
    if (name === "insert") {                                                                           // 368
      if (!args.length)                                                                                // 369
        throw new Error("insert requires an argument");                                                // 370
      // shallow-copy the document and generate an ID                                                  // 371
      args[0] = _.extend({}, args[0]);                                                                 // 372
      if ('_id' in args[0]) {                                                                          // 373
        insertId = args[0]._id;                                                                        // 374
        if (!insertId || !(typeof insertId === 'string'                                                // 375
              || insertId instanceof Meteor.Collection.ObjectID))                                      // 376
          throw new Error("Meteor requires document _id fields to be non-empty strings or ObjectIDs"); // 377
      } else {                                                                                         // 378
        var generateId = true;                                                                         // 379
        // Don't generate the id if we're the client and the 'outermost' call                          // 380
        // This optimization saves us passing both the randomSeed and the id                           // 381
        // Passing both is redundant.                                                                  // 382
        if (self._connection && self._connection !== Meteor.server) {                                  // 383
          var enclosing = DDP._CurrentInvocation.get();                                                // 384
          if (!enclosing) {                                                                            // 385
            generateId = false;                                                                        // 386
          }                                                                                            // 387
        }                                                                                              // 388
        if (generateId) {                                                                              // 389
          insertId = args[0]._id = self._makeNewID();                                                  // 390
        }                                                                                              // 391
      }                                                                                                // 392
    } else {                                                                                           // 393
      args[0] = Meteor.Collection._rewriteSelector(args[0]);                                           // 394
                                                                                                       // 395
      if (name === "update") {                                                                         // 396
        // Mutate args but copy the original options object. We need to add                            // 397
        // insertedId to options, but don't want to mutate the caller's options                        // 398
        // object. We need to mutate `args` because we pass `args` into the                            // 399
        // driver below.                                                                               // 400
        var options = args[2] = _.clone(args[2]) || {};                                                // 401
        if (options && typeof options !== "function" && options.upsert) {                              // 402
          // set `insertedId` if absent.  `insertedId` is a Meteor extension.                          // 403
          if (options.insertedId) {                                                                    // 404
            if (!(typeof options.insertedId === 'string'                                               // 405
                  || options.insertedId instanceof Meteor.Collection.ObjectID))                        // 406
              throw new Error("insertedId must be string or ObjectID");                                // 407
          } else {                                                                                     // 408
            options.insertedId = self._makeNewID();                                                    // 409
          }                                                                                            // 410
        }                                                                                              // 411
      }                                                                                                // 412
    }                                                                                                  // 413
                                                                                                       // 414
    // On inserts, always return the id that we generated; on all other                                // 415
    // operations, just return the result from the collection.                                         // 416
    var chooseReturnValueFromCollectionResult = function (result) {                                    // 417
      if (name === "insert") {                                                                         // 418
        if (!insertId && result) {                                                                     // 419
          insertId = result;                                                                           // 420
        }                                                                                              // 421
        return insertId;                                                                               // 422
      } else {                                                                                         // 423
        return result;                                                                                 // 424
      }                                                                                                // 425
    };                                                                                                 // 426
                                                                                                       // 427
    var wrappedCallback;                                                                               // 428
    if (callback) {                                                                                    // 429
      wrappedCallback = function (error, result) {                                                     // 430
        callback(error, ! error && chooseReturnValueFromCollectionResult(result));                     // 431
      };                                                                                               // 432
    }                                                                                                  // 433
                                                                                                       // 434
    if (self._connection && self._connection !== Meteor.server) {                                      // 435
      // just remote to another endpoint, propagate return value or                                    // 436
      // exception.                                                                                    // 437
                                                                                                       // 438
      var enclosing = DDP._CurrentInvocation.get();                                                    // 439
      var alreadyInSimulation = enclosing && enclosing.isSimulation;                                   // 440
                                                                                                       // 441
      if (Meteor.isClient && !wrappedCallback && ! alreadyInSimulation) {                              // 442
        // Client can't block, so it can't report errors by exception,                                 // 443
        // only by callback. If they forget the callback, give them a                                  // 444
        // default one that logs the error, so they aren't totally                                     // 445
        // baffled if their writes don't work because their database is                                // 446
        // down.                                                                                       // 447
        // Don't give a default callback in simulation, because inside stubs we                        // 448
        // want to return the results from the local collection immediately and                        // 449
        // not force a callback.                                                                       // 450
        wrappedCallback = function (err) {                                                             // 451
          if (err)                                                                                     // 452
            Meteor._debug(name + " failed: " + (err.reason || err.stack));                             // 453
        };                                                                                             // 454
      }                                                                                                // 455
                                                                                                       // 456
      if (!alreadyInSimulation && name !== "insert") {                                                 // 457
        // If we're about to actually send an RPC, we should throw an error if                         // 458
        // this is a non-ID selector, because the mutation methods only allow                          // 459
        // single-ID selectors. (If we don't throw here, we'll see flicker.)                           // 460
        throwIfSelectorIsNotId(args[0], name);                                                         // 461
      }                                                                                                // 462
                                                                                                       // 463
      ret = chooseReturnValueFromCollectionResult(                                                     // 464
        self._connection.apply(self._prefix + name, args, {returnStubValue: true}, wrappedCallback)    // 465
      );                                                                                               // 466
                                                                                                       // 467
    } else {                                                                                           // 468
      // it's my collection.  descend into the collection object                                       // 469
      // and propagate any exception.                                                                  // 470
      args.push(wrappedCallback);                                                                      // 471
      try {                                                                                            // 472
        // If the user provided a callback and the collection implements this                          // 473
        // operation asynchronously, then queryRet will be undefined, and the                          // 474
        // result will be returned through the callback instead.                                       // 475
        var queryRet = self._collection[name].apply(self._collection, args);                           // 476
        ret = chooseReturnValueFromCollectionResult(queryRet);                                         // 477
      } catch (e) {                                                                                    // 478
        if (callback) {                                                                                // 479
          callback(e);                                                                                 // 480
          return null;                                                                                 // 481
        }                                                                                              // 482
        throw e;                                                                                       // 483
      }                                                                                                // 484
    }                                                                                                  // 485
                                                                                                       // 486
    // both sync and async, unless we threw an exception, return ret                                   // 487
    // (new document ID for insert, num affected for update/remove, object with                        // 488
    // numberAffected and maybe insertedId for upsert).                                                // 489
    return ret;                                                                                        // 490
  };                                                                                                   // 491
});                                                                                                    // 492
                                                                                                       // 493
Meteor.Collection.prototype.upsert = function (selector, modifier,                                     // 494
                                               options, callback) {                                    // 495
  var self = this;                                                                                     // 496
  if (! callback && typeof options === "function") {                                                   // 497
    callback = options;                                                                                // 498
    options = {};                                                                                      // 499
  }                                                                                                    // 500
  return self.update(selector, modifier,                                                               // 501
              _.extend({}, options, { _returnObject: true, upsert: true }),                            // 502
              callback);                                                                               // 503
};                                                                                                     // 504
                                                                                                       // 505
// We'll actually design an index API later. For now, we just pass through to                          // 506
// Mongo's, but make it synchronous.                                                                   // 507
Meteor.Collection.prototype._ensureIndex = function (index, options) {                                 // 508
  var self = this;                                                                                     // 509
  if (!self._collection._ensureIndex)                                                                  // 510
    throw new Error("Can only call _ensureIndex on server collections");                               // 511
  self._collection._ensureIndex(index, options);                                                       // 512
};                                                                                                     // 513
Meteor.Collection.prototype._dropIndex = function (index) {                                            // 514
  var self = this;                                                                                     // 515
  if (!self._collection._dropIndex)                                                                    // 516
    throw new Error("Can only call _dropIndex on server collections");                                 // 517
  self._collection._dropIndex(index);                                                                  // 518
};                                                                                                     // 519
Meteor.Collection.prototype._dropCollection = function () {                                            // 520
  var self = this;                                                                                     // 521
  if (!self._collection.dropCollection)                                                                // 522
    throw new Error("Can only call _dropCollection on server collections");                            // 523
  self._collection.dropCollection();                                                                   // 524
};                                                                                                     // 525
Meteor.Collection.prototype._createCappedCollection = function (byteSize) {                            // 526
  var self = this;                                                                                     // 527
  if (!self._collection._createCappedCollection)                                                       // 528
    throw new Error("Can only call _createCappedCollection on server collections");                    // 529
  self._collection._createCappedCollection(byteSize);                                                  // 530
};                                                                                                     // 531
                                                                                                       // 532
Meteor.Collection.ObjectID = LocalCollection._ObjectID;                                                // 533
                                                                                                       // 534
///                                                                                                    // 535
/// Remote methods and access control.                                                                 // 536
///                                                                                                    // 537
                                                                                                       // 538
// Restrict default mutators on collection. allow() and deny() take the                                // 539
// same options:                                                                                       // 540
//                                                                                                     // 541
// options.insert {Function(userId, doc)}                                                              // 542
//   return true to allow/deny adding this document                                                    // 543
//                                                                                                     // 544
// options.update {Function(userId, docs, fields, modifier)}                                           // 545
//   return true to allow/deny updating these documents.                                               // 546
//   `fields` is passed as an array of fields that are to be modified                                  // 547
//                                                                                                     // 548
// options.remove {Function(userId, docs)}                                                             // 549
//   return true to allow/deny removing these documents                                                // 550
//                                                                                                     // 551
// options.fetch {Array}                                                                               // 552
//   Fields to fetch for these validators. If any call to allow or deny                                // 553
//   does not have this option then all fields are loaded.                                             // 554
//                                                                                                     // 555
// allow and deny can be called multiple times. The validators are                                     // 556
// evaluated as follows:                                                                               // 557
// - If neither deny() nor allow() has been called on the collection,                                  // 558
//   then the request is allowed if and only if the "insecure" smart                                   // 559
//   package is in use.                                                                                // 560
// - Otherwise, if any deny() function returns true, the request is denied.                            // 561
// - Otherwise, if any allow() function returns true, the request is allowed.                          // 562
// - Otherwise, the request is denied.                                                                 // 563
//                                                                                                     // 564
// Meteor may call your deny() and allow() functions in any order, and may not                         // 565
// call all of them if it is able to make a decision without calling them all                          // 566
// (so don't include side effects).                                                                    // 567
                                                                                                       // 568
(function () {                                                                                         // 569
  var addValidator = function(allowOrDeny, options) {                                                  // 570
    // validate keys                                                                                   // 571
    var VALID_KEYS = ['insert', 'update', 'remove', 'fetch', 'transform'];                             // 572
    _.each(_.keys(options), function (key) {                                                           // 573
      if (!_.contains(VALID_KEYS, key))                                                                // 574
        throw new Error(allowOrDeny + ": Invalid key: " + key);                                        // 575
    });                                                                                                // 576
                                                                                                       // 577
    var self = this;                                                                                   // 578
    self._restricted = true;                                                                           // 579
                                                                                                       // 580
    _.each(['insert', 'update', 'remove'], function (name) {                                           // 581
      if (options[name]) {                                                                             // 582
        if (!(options[name] instanceof Function)) {                                                    // 583
          throw new Error(allowOrDeny + ": Value for `" + name + "` must be a function");              // 584
        }                                                                                              // 585
                                                                                                       // 586
        // If the transform is specified at all (including as 'null') in this                          // 587
        // call, then take that; otherwise, take the transform from the                                // 588
        // collection.                                                                                 // 589
        if (options.transform === undefined) {                                                         // 590
          options[name].transform = self._transform;  // already wrapped                               // 591
        } else {                                                                                       // 592
          options[name].transform = LocalCollection.wrapTransform(                                     // 593
            options.transform);                                                                        // 594
        }                                                                                              // 595
                                                                                                       // 596
        self._validators[name][allowOrDeny].push(options[name]);                                       // 597
      }                                                                                                // 598
    });                                                                                                // 599
                                                                                                       // 600
    // Only update the fetch fields if we're passed things that affect                                 // 601
    // fetching. This way allow({}) and allow({insert: f}) don't result in                             // 602
    // setting fetchAllFields                                                                          // 603
    if (options.update || options.remove || options.fetch) {                                           // 604
      if (options.fetch && !(options.fetch instanceof Array)) {                                        // 605
        throw new Error(allowOrDeny + ": Value for `fetch` must be an array");                         // 606
      }                                                                                                // 607
      self._updateFetch(options.fetch);                                                                // 608
    }                                                                                                  // 609
  };                                                                                                   // 610
                                                                                                       // 611
  Meteor.Collection.prototype.allow = function(options) {                                              // 612
    addValidator.call(this, 'allow', options);                                                         // 613
  };                                                                                                   // 614
  Meteor.Collection.prototype.deny = function(options) {                                               // 615
    addValidator.call(this, 'deny', options);                                                          // 616
  };                                                                                                   // 617
})();                                                                                                  // 618
                                                                                                       // 619
                                                                                                       // 620
Meteor.Collection.prototype._defineMutationMethods = function() {                                      // 621
  var self = this;                                                                                     // 622
                                                                                                       // 623
  // set to true once we call any allow or deny methods. If true, use                                  // 624
  // allow/deny semantics. If false, use insecure mode semantics.                                      // 625
  self._restricted = false;                                                                            // 626
                                                                                                       // 627
  // Insecure mode (default to allowing writes). Defaults to 'undefined' which                         // 628
  // means insecure iff the insecure package is loaded. This property can be                           // 629
  // overriden by tests or packages wishing to change insecure mode behavior of                        // 630
  // their collections.                                                                                // 631
  self._insecure = undefined;                                                                          // 632
                                                                                                       // 633
  self._validators = {                                                                                 // 634
    insert: {allow: [], deny: []},                                                                     // 635
    update: {allow: [], deny: []},                                                                     // 636
    remove: {allow: [], deny: []},                                                                     // 637
    upsert: {allow: [], deny: []}, // dummy arrays; can't set these!                                   // 638
    fetch: [],                                                                                         // 639
    fetchAllFields: false                                                                              // 640
  };                                                                                                   // 641
                                                                                                       // 642
  if (!self._name)                                                                                     // 643
    return; // anonymous collection                                                                    // 644
                                                                                                       // 645
  // XXX Think about method namespacing. Maybe methods should be                                       // 646
  // "Meteor:Mongo:insert/NAME"?                                                                       // 647
  self._prefix = '/' + self._name + '/';                                                               // 648
                                                                                                       // 649
  // mutation methods                                                                                  // 650
  if (self._connection) {                                                                              // 651
    var m = {};                                                                                        // 652
                                                                                                       // 653
    _.each(['insert', 'update', 'remove'], function (method) {                                         // 654
      m[self._prefix + method] = function (/* ... */) {                                                // 655
        // All the methods do their own validation, instead of using check().                          // 656
        check(arguments, [Match.Any]);                                                                 // 657
        var args = _.toArray(arguments);                                                               // 658
        try {                                                                                          // 659
          // For an insert, if the client didn't specify an _id, generate one                          // 660
          // now; because this uses DDP.randomStream, it will be consistent with                       // 661
          // what the client generated. We generate it now rather than later so                        // 662
          // that if (eg) an allow/deny rule does an insert to the same                                // 663
          // collection (not that it really should), the generated _id will                            // 664
          // still be the first use of the stream and will be consistent.                              // 665
          //                                                                                           // 666
          // However, we don't actually stick the _id onto the document yet,                           // 667
          // because we want allow/deny rules to be able to differentiate                              // 668
          // between arbitrary client-specified _id fields and merely                                  // 669
          // client-controlled-via-randomSeed fields.                                                  // 670
          var generatedId = null;                                                                      // 671
          if (method === "insert" && !_.has(args[0], '_id')) {                                         // 672
            generatedId = self._makeNewID();                                                           // 673
          }                                                                                            // 674
                                                                                                       // 675
          if (this.isSimulation) {                                                                     // 676
            // In a client simulation, you can do any mutation (even with a                            // 677
            // complex selector).                                                                      // 678
            if (generatedId !== null)                                                                  // 679
              args[0]._id = generatedId;                                                               // 680
            return self._collection[method].apply(                                                     // 681
              self._collection, args);                                                                 // 682
          }                                                                                            // 683
                                                                                                       // 684
          // This is the server receiving a method call from the client.                               // 685
                                                                                                       // 686
          // We don't allow arbitrary selectors in mutations from the client: only                     // 687
          // single-ID selectors.                                                                      // 688
          if (method !== 'insert')                                                                     // 689
            throwIfSelectorIsNotId(args[0], method);                                                   // 690
                                                                                                       // 691
          if (self._restricted) {                                                                      // 692
            // short circuit if there is no way it will pass.                                          // 693
            if (self._validators[method].allow.length === 0) {                                         // 694
              throw new Meteor.Error(                                                                  // 695
                403, "Access denied. No allow validators set on restricted " +                         // 696
                  "collection for method '" + method + "'.");                                          // 697
            }                                                                                          // 698
                                                                                                       // 699
            var validatedMethodName =                                                                  // 700
                  '_validated' + method.charAt(0).toUpperCase() + method.slice(1);                     // 701
            args.unshift(this.userId);                                                                 // 702
            method === 'insert' && args.push(generatedId);                                             // 703
            return self[validatedMethodName].apply(self, args);                                        // 704
          } else if (self._isInsecure()) {                                                             // 705
            if (generatedId !== null)                                                                  // 706
              args[0]._id = generatedId;                                                               // 707
            // In insecure mode, allow any mutation (with a simple selector).                          // 708
            return self._collection[method].apply(self._collection, args);                             // 709
          } else {                                                                                     // 710
            // In secure mode, if we haven't called allow or deny, then nothing                        // 711
            // is permitted.                                                                           // 712
            throw new Meteor.Error(403, "Access denied");                                              // 713
          }                                                                                            // 714
        } catch (e) {                                                                                  // 715
          if (e.name === 'MongoError' || e.name === 'MinimongoError') {                                // 716
            throw new Meteor.Error(409, e.toString());                                                 // 717
          } else {                                                                                     // 718
            throw e;                                                                                   // 719
          }                                                                                            // 720
        }                                                                                              // 721
      };                                                                                               // 722
    });                                                                                                // 723
    // Minimongo on the server gets no stubs; instead, by default                                      // 724
    // it wait()s until its result is ready, yielding.                                                 // 725
    // This matches the behavior of macromongo on the server better.                                   // 726
    if (Meteor.isClient || self._connection === Meteor.server)                                         // 727
      self._connection.methods(m);                                                                     // 728
  }                                                                                                    // 729
};                                                                                                     // 730
                                                                                                       // 731
                                                                                                       // 732
Meteor.Collection.prototype._updateFetch = function (fields) {                                         // 733
  var self = this;                                                                                     // 734
                                                                                                       // 735
  if (!self._validators.fetchAllFields) {                                                              // 736
    if (fields) {                                                                                      // 737
      self._validators.fetch = _.union(self._validators.fetch, fields);                                // 738
    } else {                                                                                           // 739
      self._validators.fetchAllFields = true;                                                          // 740
      // clear fetch just to make sure we don't accidentally read it                                   // 741
      self._validators.fetch = null;                                                                   // 742
    }                                                                                                  // 743
  }                                                                                                    // 744
};                                                                                                     // 745
                                                                                                       // 746
Meteor.Collection.prototype._isInsecure = function () {                                                // 747
  var self = this;                                                                                     // 748
  if (self._insecure === undefined)                                                                    // 749
    return !!Package.insecure;                                                                         // 750
  return self._insecure;                                                                               // 751
};                                                                                                     // 752
                                                                                                       // 753
var docToValidate = function (validator, doc, generatedId) {                                           // 754
  var ret = doc;                                                                                       // 755
  if (validator.transform) {                                                                           // 756
    ret = EJSON.clone(doc);                                                                            // 757
    // If you set a server-side transform on your collection, then you don't get                       // 758
    // to tell the difference between "client specified the ID" and "server                            // 759
    // generated the ID", because transforms expect to get _id.  If you want to                        // 760
    // do that check, you can do it with a specific                                                    // 761
    // `C.allow({insert: f, transform: null})` validator.                                              // 762
    if (generatedId !== null) {                                                                        // 763
      ret._id = generatedId;                                                                           // 764
    }                                                                                                  // 765
    ret = validator.transform(ret);                                                                    // 766
  }                                                                                                    // 767
  return ret;                                                                                          // 768
};                                                                                                     // 769
                                                                                                       // 770
Meteor.Collection.prototype._validatedInsert = function (userId, doc,                                  // 771
                                                         generatedId) {                                // 772
  var self = this;                                                                                     // 773
                                                                                                       // 774
  // call user validators.                                                                             // 775
  // Any deny returns true means denied.                                                               // 776
  if (_.any(self._validators.insert.deny, function(validator) {                                        // 777
    return validator(userId, docToValidate(validator, doc, generatedId));                              // 778
  })) {                                                                                                // 779
    throw new Meteor.Error(403, "Access denied");                                                      // 780
  }                                                                                                    // 781
  // Any allow returns true means proceed. Throw error if they all fail.                               // 782
  if (_.all(self._validators.insert.allow, function(validator) {                                       // 783
    return !validator(userId, docToValidate(validator, doc, generatedId));                             // 784
  })) {                                                                                                // 785
    throw new Meteor.Error(403, "Access denied");                                                      // 786
  }                                                                                                    // 787
                                                                                                       // 788
  // If we generated an ID above, insert it now: after the validation, but                             // 789
  // before actually inserting.                                                                        // 790
  if (generatedId !== null)                                                                            // 791
    doc._id = generatedId;                                                                             // 792
                                                                                                       // 793
  self._collection.insert.call(self._collection, doc);                                                 // 794
};                                                                                                     // 795
                                                                                                       // 796
var transformDoc = function (validator, doc) {                                                         // 797
  if (validator.transform)                                                                             // 798
    return validator.transform(doc);                                                                   // 799
  return doc;                                                                                          // 800
};                                                                                                     // 801
                                                                                                       // 802
// Simulate a mongo `update` operation while validating that the access                                // 803
// control rules set by calls to `allow/deny` are satisfied. If all                                    // 804
// pass, rewrite the mongo operation to use $in to set the list of                                     // 805
// document ids to change ##ValidatedChange                                                            // 806
Meteor.Collection.prototype._validatedUpdate = function(                                               // 807
    userId, selector, mutator, options) {                                                              // 808
  var self = this;                                                                                     // 809
                                                                                                       // 810
  options = options || {};                                                                             // 811
                                                                                                       // 812
  if (!LocalCollection._selectorIsIdPerhapsAsObject(selector))                                         // 813
    throw new Error("validated update should be of a single ID");                                      // 814
                                                                                                       // 815
  // We don't support upserts because they don't fit nicely into allow/deny                            // 816
  // rules.                                                                                            // 817
  if (options.upsert)                                                                                  // 818
    throw new Meteor.Error(403, "Access denied. Upserts not " +                                        // 819
                           "allowed in a restricted collection.");                                     // 820
                                                                                                       // 821
  // compute modified fields                                                                           // 822
  var fields = [];                                                                                     // 823
  _.each(mutator, function (params, op) {                                                              // 824
    if (op.charAt(0) !== '$') {                                                                        // 825
      throw new Meteor.Error(                                                                          // 826
        403, "Access denied. In a restricted collection you can only update documents, not replace them. Use a Mongo update operator, such as '$set'.");
    } else if (!_.has(ALLOWED_UPDATE_OPERATIONS, op)) {                                                // 828
      throw new Meteor.Error(                                                                          // 829
        403, "Access denied. Operator " + op + " not allowed in a restricted collection.");            // 830
    } else {                                                                                           // 831
      _.each(_.keys(params), function (field) {                                                        // 832
        // treat dotted fields as if they are replacing their                                          // 833
        // top-level part                                                                              // 834
        if (field.indexOf('.') !== -1)                                                                 // 835
          field = field.substring(0, field.indexOf('.'));                                              // 836
                                                                                                       // 837
        // record the field we are trying to change                                                    // 838
        if (!_.contains(fields, field))                                                                // 839
          fields.push(field);                                                                          // 840
      });                                                                                              // 841
    }                                                                                                  // 842
  });                                                                                                  // 843
                                                                                                       // 844
  var findOptions = {transform: null};                                                                 // 845
  if (!self._validators.fetchAllFields) {                                                              // 846
    findOptions.fields = {};                                                                           // 847
    _.each(self._validators.fetch, function(fieldName) {                                               // 848
      findOptions.fields[fieldName] = 1;                                                               // 849
    });                                                                                                // 850
  }                                                                                                    // 851
                                                                                                       // 852
  var doc = self._collection.findOne(selector, findOptions);                                           // 853
  if (!doc)  // none satisfied!                                                                        // 854
    return 0;                                                                                          // 855
                                                                                                       // 856
  var factoriedDoc;                                                                                    // 857
                                                                                                       // 858
  // call user validators.                                                                             // 859
  // Any deny returns true means denied.                                                               // 860
  if (_.any(self._validators.update.deny, function(validator) {                                        // 861
    if (!factoriedDoc)                                                                                 // 862
      factoriedDoc = transformDoc(validator, doc);                                                     // 863
    return validator(userId,                                                                           // 864
                     factoriedDoc,                                                                     // 865
                     fields,                                                                           // 866
                     mutator);                                                                         // 867
  })) {                                                                                                // 868
    throw new Meteor.Error(403, "Access denied");                                                      // 869
  }                                                                                                    // 870
  // Any allow returns true means proceed. Throw error if they all fail.                               // 871
  if (_.all(self._validators.update.allow, function(validator) {                                       // 872
    if (!factoriedDoc)                                                                                 // 873
      factoriedDoc = transformDoc(validator, doc);                                                     // 874
    return !validator(userId,                                                                          // 875
                      factoriedDoc,                                                                    // 876
                      fields,                                                                          // 877
                      mutator);                                                                        // 878
  })) {                                                                                                // 879
    throw new Meteor.Error(403, "Access denied");                                                      // 880
  }                                                                                                    // 881
                                                                                                       // 882
  // Back when we supported arbitrary client-provided selectors, we actually                           // 883
  // rewrote the selector to include an _id clause before passing to Mongo to                          // 884
  // avoid races, but since selector is guaranteed to already just be an ID, we                        // 885
  // don't have to any more.                                                                           // 886
                                                                                                       // 887
  return self._collection.update.call(                                                                 // 888
    self._collection, selector, mutator, options);                                                     // 889
};                                                                                                     // 890
                                                                                                       // 891
// Only allow these operations in validated updates. Specifically                                      // 892
// whitelist operations, rather than blacklist, so new complex                                         // 893
// operations that are added aren't automatically allowed. A complex                                   // 894
// operation is one that does more than just modify its target                                         // 895
// field. For now this contains all update operations except '$rename'.                                // 896
// http://docs.mongodb.org/manual/reference/operators/#update                                          // 897
var ALLOWED_UPDATE_OPERATIONS = {                                                                      // 898
  $inc:1, $set:1, $unset:1, $addToSet:1, $pop:1, $pullAll:1, $pull:1,                                  // 899
  $pushAll:1, $push:1, $bit:1                                                                          // 900
};                                                                                                     // 901
                                                                                                       // 902
// Simulate a mongo `remove` operation while validating access control                                 // 903
// rules. See #ValidatedChange                                                                         // 904
Meteor.Collection.prototype._validatedRemove = function(userId, selector) {                            // 905
  var self = this;                                                                                     // 906
                                                                                                       // 907
  var findOptions = {transform: null};                                                                 // 908
  if (!self._validators.fetchAllFields) {                                                              // 909
    findOptions.fields = {};                                                                           // 910
    _.each(self._validators.fetch, function(fieldName) {                                               // 911
      findOptions.fields[fieldName] = 1;                                                               // 912
    });                                                                                                // 913
  }                                                                                                    // 914
                                                                                                       // 915
  var doc = self._collection.findOne(selector, findOptions);                                           // 916
  if (!doc)                                                                                            // 917
    return 0;                                                                                          // 918
                                                                                                       // 919
  // call user validators.                                                                             // 920
  // Any deny returns true means denied.                                                               // 921
  if (_.any(self._validators.remove.deny, function(validator) {                                        // 922
    return validator(userId, transformDoc(validator, doc));                                            // 923
  })) {                                                                                                // 924
    throw new Meteor.Error(403, "Access denied");                                                      // 925
  }                                                                                                    // 926
  // Any allow returns true means proceed. Throw error if they all fail.                               // 927
  if (_.all(self._validators.remove.allow, function(validator) {                                       // 928
    return !validator(userId, transformDoc(validator, doc));                                           // 929
  })) {                                                                                                // 930
    throw new Meteor.Error(403, "Access denied");                                                      // 931
  }                                                                                                    // 932
                                                                                                       // 933
  // Back when we supported arbitrary client-provided selectors, we actually                           // 934
  // rewrote the selector to {_id: {$in: [ids that we found]}} before passing to                       // 935
  // Mongo to avoid races, but since selector is guaranteed to already just be                         // 936
  // an ID, we don't have to any more.                                                                 // 937
                                                                                                       // 938
  return self._collection.remove.call(self._collection, selector);                                     // 939
};                                                                                                     // 940
                                                                                                       // 941
/////////////////////////////////////////////////////////////////////////////////////////////////////////

}).call(this);


/* Exports */
if (typeof Package === 'undefined') Package = {};
Package['mongo-livedata'] = {};

})();

//# sourceMappingURL=26f4a1853dbf09c49d7cc49710b6fa14f83b138b.map
