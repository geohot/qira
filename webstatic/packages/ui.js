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
var $ = Package.jquery.$;
var jQuery = Package.jquery.jQuery;
var Deps = Package.deps.Deps;
var Random = Package.random.Random;
var EJSON = Package.ejson.EJSON;
var _ = Package.underscore._;
var OrderedDict = Package['ordered-dict'].OrderedDict;
var LocalCollection = Package.minimongo.LocalCollection;
var Minimongo = Package.minimongo.Minimongo;
var ObserveSequence = Package['observe-sequence'].ObserveSequence;
var HTML = Package.htmljs.HTML;

/* Package-scope variables */
var UI, Handlebars, reportUIException, _extend, Component, findComponentWithProp, findComponentWithHelper, getComponentData, updateTemplateInstance, currentTemplateInstance, AttributeHandler, makeAttributeHandler, ElementAttributesUpdater, currentComponent;

(function () {

////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//                                                                                                            //
// packages/ui/exceptions.js                                                                                  //
//                                                                                                            //
////////////////////////////////////////////////////////////////////////////////////////////////////////////////
                                                                                                              //
                                                                                                              // 1
var debugFunc;                                                                                                // 2
                                                                                                              // 3
// Meteor UI calls into user code in many places, and it's nice to catch exceptions                           // 4
// propagated from user code immediately so that the whole system doesn't just                                // 5
// break.  Catching exceptions is easy; reporting them is hard.  This helper                                  // 6
// reports exceptions.                                                                                        // 7
//                                                                                                            // 8
// Usage:                                                                                                     // 9
//                                                                                                            // 10
// ```                                                                                                        // 11
// try {                                                                                                      // 12
//   // ... someStuff ...                                                                                     // 13
// } catch (e) {                                                                                              // 14
//   reportUIException(e);                                                                                    // 15
// }                                                                                                          // 16
// ```                                                                                                        // 17
//                                                                                                            // 18
// An optional second argument overrides the default message.                                                 // 19
                                                                                                              // 20
reportUIException = function (e, msg) {                                                                       // 21
  if (! debugFunc)                                                                                            // 22
    // adapted from Deps                                                                                      // 23
    debugFunc = function () {                                                                                 // 24
      return (typeof Meteor !== "undefined" ? Meteor._debug :                                                 // 25
              ((typeof console !== "undefined") && console.log ? console.log :                                // 26
               function () {}));                                                                              // 27
    };                                                                                                        // 28
                                                                                                              // 29
  // In Chrome, `e.stack` is a multiline string that starts with the message                                  // 30
  // and contains a stack trace.  Furthermore, `console.log` makes it clickable.                              // 31
  // `console.log` supplies the space between the two arguments.                                              // 32
  debugFunc()(msg || 'Exception in Meteor UI:', e.stack || e.message);                                        // 33
};                                                                                                            // 34
                                                                                                              // 35
////////////////////////////////////////////////////////////////////////////////////////////////////////////////

}).call(this);






(function () {

////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//                                                                                                            //
// packages/ui/base.js                                                                                        //
//                                                                                                            //
////////////////////////////////////////////////////////////////////////////////////////////////////////////////
                                                                                                              //
UI = {};                                                                                                      // 1
                                                                                                              // 2
// A very basic operation like Underscore's `_.extend` that                                                   // 3
// copies `src`'s own, enumerable properties onto `tgt` and                                                   // 4
// returns `tgt`.                                                                                             // 5
_extend = function (tgt, src) {                                                                               // 6
  for (var k in src)                                                                                          // 7
    if (src.hasOwnProperty(k))                                                                                // 8
      tgt[k] = src[k];                                                                                        // 9
  return tgt;                                                                                                 // 10
};                                                                                                            // 11
                                                                                                              // 12
// Defines a single non-enumerable, read-only property                                                        // 13
// on `tgt`.                                                                                                  // 14
// It won't be non-enumerable in IE 8, so its                                                                 // 15
// non-enumerability can't be relied on for logic                                                             // 16
// purposes, it just makes things prettier in                                                                 // 17
// the dev console.                                                                                           // 18
var _defineNonEnum = function (tgt, name, value) {                                                            // 19
  try {                                                                                                       // 20
    Object.defineProperty(tgt, name, {value: value});                                                         // 21
  } catch (e) {                                                                                               // 22
    // IE < 9                                                                                                 // 23
    tgt[name] = value;                                                                                        // 24
  }                                                                                                           // 25
  return tgt;                                                                                                 // 26
};                                                                                                            // 27
                                                                                                              // 28
// Named function (like `function Component() {}` below) make                                                 // 29
// inspection in debuggers more descriptive. In IE, this sets the                                             // 30
// value of the `Component` var in the function scope in which it's                                           // 31
// executed. We already have a top-level `Component` var so we create                                         // 32
// a new function scope to not write it over in IE.                                                           // 33
(function () {                                                                                                // 34
                                                                                                              // 35
  // Components and Component kinds are the same thing, just                                                  // 36
  // objects; there are no constructor functions, no `new`,                                                   // 37
  // and no `instanceof`.  A Component object is like a class,                                                // 38
  // until it is inited, at which point it becomes more like                                                  // 39
  // an instance.                                                                                             // 40
  //                                                                                                          // 41
  // `y = x.extend({ ...new props })` creates a new Component                                                 // 42
  // `y` with `x` as its prototype, plus additional properties                                                // 43
  // on `y` itself.  `extend` is used both to subclass and to                                                 // 44
  // create instances (and the hope is we can gloss over the                                                  // 45
  // difference in the docs).                                                                                 // 46
  UI.Component = (function (constr) {                                                                         // 47
                                                                                                              // 48
    // Make sure the "class name" that Chrome infers for                                                      // 49
    // UI.Component is "Component", and that                                                                  // 50
    // `new UI.Component._constr` (which is what `extend`                                                     // 51
    // does) also produces objects whose inferred class                                                       // 52
    // name is "Component".  Chrome's name inference rules                                                    // 53
    // are a little mysterious, but a function name in                                                        // 54
    // the source code (as in `function Component() {}`)                                                      // 55
    // seems to be reliable and high precedence.                                                              // 56
    var C = new constr;                                                                                       // 57
    _defineNonEnum(C, '_constr', constr);                                                                     // 58
    _defineNonEnum(C, '_super', null);                                                                        // 59
    return C;                                                                                                 // 60
  })(function Component() {});                                                                                // 61
})();                                                                                                         // 62
                                                                                                              // 63
_extend(UI, {                                                                                                 // 64
  nextGuid: 2, // Component is 1!                                                                             // 65
                                                                                                              // 66
  isComponent: function (obj) {                                                                               // 67
    return obj && UI.isKindOf(obj, UI.Component);                                                             // 68
  },                                                                                                          // 69
  // `UI.isKindOf(a, b)` where `a` and `b` are Components                                                     // 70
  // (or kinds) asks if `a` is or descends from                                                               // 71
  // (transitively extends) `b`.                                                                              // 72
  isKindOf: function (a, b) {                                                                                 // 73
    while (a) {                                                                                               // 74
      if (a === b)                                                                                            // 75
        return true;                                                                                          // 76
      a = a._super;                                                                                           // 77
    }                                                                                                         // 78
    return false;                                                                                             // 79
  },                                                                                                          // 80
  // use these to produce error messages for developers                                                       // 81
  // (though throwing a more specific error message is                                                        // 82
  // even better)                                                                                             // 83
  _requireNotDestroyed: function (c) {                                                                        // 84
    if (c.isDestroyed)                                                                                        // 85
      throw new Error("Component has been destroyed; can't perform this operation");                          // 86
  },                                                                                                          // 87
  _requireInited: function (c) {                                                                              // 88
    if (! c.isInited)                                                                                         // 89
      throw new Error("Component must be inited to perform this operation");                                  // 90
  },                                                                                                          // 91
  _requireDom: function (c) {                                                                                 // 92
    if (! c.dom)                                                                                              // 93
      throw new Error("Component must be built into DOM to perform this operation");                          // 94
  }                                                                                                           // 95
});                                                                                                           // 96
                                                                                                              // 97
Component = UI.Component;                                                                                     // 98
                                                                                                              // 99
_extend(UI.Component, {                                                                                       // 100
  kind: "Component",                                                                                          // 101
  guid: "1",                                                                                                  // 102
  dom: null,                                                                                                  // 103
  // Has this Component ever been inited?                                                                     // 104
  isInited: false,                                                                                            // 105
  // Has this Component been destroyed?  Only inited Components                                               // 106
  // can be destroyed.                                                                                        // 107
  isDestroyed: false,                                                                                         // 108
  // Component that created this component (typically also                                                    // 109
  // the DOM containment parent).                                                                             // 110
  // No child pointers (except in `dom`).                                                                     // 111
  parent: null,                                                                                               // 112
                                                                                                              // 113
  // create a new subkind or instance whose proto pointer                                                     // 114
  // points to this, with additional props set.                                                               // 115
  extend: function (props) {                                                                                  // 116
    // this function should never cause `props` to be                                                         // 117
    // mutated in case people want to reuse `props` objects                                                   // 118
    // in a mixin-like way.                                                                                   // 119
                                                                                                              // 120
    if (this.isInited)                                                                                        // 121
      // Disallow extending inited Components so that                                                         // 122
      // inited Components don't inherit instance-specific                                                    // 123
      // properties from other inited Components, just                                                        // 124
      // default values.                                                                                      // 125
      throw new Error("Can't extend an inited Component");                                                    // 126
                                                                                                              // 127
    var constr;                                                                                               // 128
    var constrMade = false;                                                                                   // 129
    if (props && props.kind) {                                                                                // 130
      // If `kind` is different from super, set a constructor.                                                // 131
      // We used to set the function name here so that components                                             // 132
      // printed better in the console, but we took it out because                                            // 133
      // of CSP (and in hopes that Chrome finally adds proper                                                 // 134
      // displayName support).                                                                                // 135
      constr = function () {};                                                                                // 136
      constrMade = true;                                                                                      // 137
    } else {                                                                                                  // 138
      constr = this._constr;                                                                                  // 139
    }                                                                                                         // 140
                                                                                                              // 141
    // We don't know where we're getting `constr` from --                                                     // 142
    // it might be from some supertype -- just that it has                                                    // 143
    // the right function name.  So set the `prototype`                                                       // 144
    // property each time we use it as a constructor.                                                         // 145
    constr.prototype = this;                                                                                  // 146
                                                                                                              // 147
    var c = new constr;                                                                                       // 148
    if (constrMade)                                                                                           // 149
      c._constr = constr;                                                                                     // 150
                                                                                                              // 151
    if (props)                                                                                                // 152
      _extend(c, props);                                                                                      // 153
                                                                                                              // 154
    // for efficient Component instantiations, we assign                                                      // 155
    // as few things as possible here.                                                                        // 156
    _defineNonEnum(c, '_super', this);                                                                        // 157
    c.guid = String(UI.nextGuid++);                                                                           // 158
                                                                                                              // 159
    return c;                                                                                                 // 160
  }                                                                                                           // 161
});                                                                                                           // 162
                                                                                                              // 163
//callChainedCallback = function (comp, propName, orig) {                                                     // 164
  // Call `comp.foo`, `comp._super.foo`,                                                                      // 165
  // `comp._super._super.foo`, and so on, but in reverse                                                      // 166
  // order, and only if `foo` is an "own property" in each                                                    // 167
  // case.  Furthermore, the passed value of `this` should                                                    // 168
  // remain `comp` for all calls (which is achieved by                                                        // 169
  // filling in `orig` when recursing).                                                                       // 170
//  if (comp._super)                                                                                          // 171
//    callChainedCallback(comp._super, propName, orig || comp);                                               // 172
//                                                                                                            // 173
//  if (comp.hasOwnProperty(propName))                                                                        // 174
//    comp[propName].call(orig || comp);                                                                      // 175
//};                                                                                                          // 176
                                                                                                              // 177
                                                                                                              // 178
// Returns 0 if the nodes are the same or either one contains the other;                                      // 179
// otherwise, -1 if a comes before b, or else 1 if b comes before a in                                        // 180
// document order.                                                                                            // 181
// Requires: `a` and `b` are element nodes in the same document tree.                                         // 182
var compareElementIndex = function (a, b) {                                                                   // 183
  // See http://ejohn.org/blog/comparing-document-position/                                                   // 184
  if (a === b)                                                                                                // 185
    return 0;                                                                                                 // 186
  if (a.compareDocumentPosition) {                                                                            // 187
    var n = a.compareDocumentPosition(b);                                                                     // 188
    return ((n & 0x18) ? 0 : ((n & 0x4) ? -1 : 1));                                                           // 189
  } else {                                                                                                    // 190
    // Only old IE is known to not have compareDocumentPosition (though Safari                                // 191
    // originally lacked it).  Thankfully, IE gives us a way of comparing elements                            // 192
    // via the "sourceIndex" property.                                                                        // 193
    if (a.contains(b) || b.contains(a))                                                                       // 194
      return 0;                                                                                               // 195
    return (a.sourceIndex < b.sourceIndex ? -1 : 1);                                                          // 196
  }                                                                                                           // 197
};                                                                                                            // 198
                                                                                                              // 199
findComponentWithProp = function (id, comp) {                                                                 // 200
  while (comp) {                                                                                              // 201
    if (typeof comp[id] !== 'undefined')                                                                      // 202
      return comp;                                                                                            // 203
    comp = comp.parent;                                                                                       // 204
  }                                                                                                           // 205
  return null;                                                                                                // 206
};                                                                                                            // 207
                                                                                                              // 208
// Look up the component's chain of parents until we find one with                                            // 209
// `__helperHost` set (a component that can have helpers defined on it,                                       // 210
// i.e. a template).                                                                                          // 211
var findHelperHostComponent = function (comp) {                                                               // 212
  while (comp) {                                                                                              // 213
    if (comp.__helperHost) {                                                                                  // 214
      return comp;                                                                                            // 215
    }                                                                                                         // 216
    comp = comp.parent;                                                                                       // 217
  }                                                                                                           // 218
  return null;                                                                                                // 219
};                                                                                                            // 220
                                                                                                              // 221
findComponentWithHelper = function (id, comp) {                                                               // 222
  while (comp) {                                                                                              // 223
    if (comp.__helperHost) {                                                                                  // 224
      if (typeof comp[id] !== 'undefined')                                                                    // 225
        return comp;                                                                                          // 226
      else                                                                                                    // 227
        return null;                                                                                          // 228
    }                                                                                                         // 229
    comp = comp.parent;                                                                                       // 230
  }                                                                                                           // 231
  return null;                                                                                                // 232
};                                                                                                            // 233
                                                                                                              // 234
getComponentData = function (comp) {                                                                          // 235
  comp = findComponentWithProp('data', comp);                                                                 // 236
  return (comp ?                                                                                              // 237
          (typeof comp.data === 'function' ?                                                                  // 238
           comp.data() : comp.data) :                                                                         // 239
          null);                                                                                              // 240
};                                                                                                            // 241
                                                                                                              // 242
updateTemplateInstance = function (comp) {                                                                    // 243
  // Populate `comp.templateInstance.{firstNode,lastNode,data}`                                               // 244
  // on demand.                                                                                               // 245
  var tmpl = comp.templateInstance;                                                                           // 246
  tmpl.data = getComponentData(comp);                                                                         // 247
                                                                                                              // 248
  if (comp.dom && !comp.isDestroyed) {                                                                        // 249
    tmpl.firstNode = comp.dom.startNode().nextSibling;                                                        // 250
    tmpl.lastNode = comp.dom.endNode().previousSibling;                                                       // 251
    // Catch the case where the DomRange is empty and we'd                                                    // 252
    // otherwise pass the out-of-order nodes (end, start)                                                     // 253
    // as (firstNode, lastNode).                                                                              // 254
    if (tmpl.lastNode && tmpl.lastNode.nextSibling === tmpl.firstNode)                                        // 255
      tmpl.lastNode = tmpl.firstNode;                                                                         // 256
  } else {                                                                                                    // 257
    // on 'created' or 'destroyed' callbacks we don't have a DomRange                                         // 258
    tmpl.firstNode = null;                                                                                    // 259
    tmpl.lastNode = null;                                                                                     // 260
  }                                                                                                           // 261
};                                                                                                            // 262
                                                                                                              // 263
_extend(UI.Component, {                                                                                       // 264
  // We implement the old APIs here, including how data is passed                                             // 265
  // to helpers in `this`.                                                                                    // 266
  helpers: function (dict) {                                                                                  // 267
    _extend(this, dict);                                                                                      // 268
  },                                                                                                          // 269
  events: function (dict) {                                                                                   // 270
    var events;                                                                                               // 271
    if (this.hasOwnProperty('_events'))                                                                       // 272
      events = this._events;                                                                                  // 273
    else                                                                                                      // 274
      events = (this._events = []);                                                                           // 275
                                                                                                              // 276
    _.each(dict, function (handler, spec) {                                                                   // 277
      var clauses = spec.split(/,\s+/);                                                                       // 278
      // iterate over clauses of spec, e.g. ['click .foo', 'click .bar']                                      // 279
      _.each(clauses, function (clause) {                                                                     // 280
        var parts = clause.split(/\s+/);                                                                      // 281
        if (parts.length === 0)                                                                               // 282
          return;                                                                                             // 283
                                                                                                              // 284
        var newEvents = parts.shift();                                                                        // 285
        var selector = parts.join(' ');                                                                       // 286
        events.push({events: newEvents,                                                                       // 287
                     selector: selector,                                                                      // 288
                     handler: handler});                                                                      // 289
      });                                                                                                     // 290
    });                                                                                                       // 291
  }                                                                                                           // 292
});                                                                                                           // 293
                                                                                                              // 294
// XXX we don't really want this to be a user-visible callback,                                               // 295
// it's just a particular signal we need from DomRange.                                                       // 296
UI.Component.notifyParented = function () {                                                                   // 297
  var self = this;                                                                                            // 298
  for (var comp = self; comp; comp = comp._super) {                                                           // 299
    var events = (comp.hasOwnProperty('_events') && comp._events) || null;                                    // 300
    if ((! events) && comp.hasOwnProperty('events') &&                                                        // 301
        typeof comp.events === 'object') {                                                                    // 302
      // Provide limited back-compat support for `.events = {...}`                                            // 303
      // syntax.  Pass `comp.events` to the original `.events(...)`                                           // 304
      // function.  This code must run only once per component, in                                            // 305
      // order to not bind the handlers more than once, which is                                              // 306
      // ensured by the fact that we only do this when `comp._events`                                         // 307
      // is falsy, and we cause it to be set now.                                                             // 308
      UI.Component.events.call(comp, comp.events);                                                            // 309
      events = comp._events;                                                                                  // 310
    }                                                                                                         // 311
    _.each(events, function (esh) { // {events, selector, handler}                                            // 312
      // wrap the handler here, per instance of the template that                                             // 313
      // declares the event map, so we can pass the instance to                                               // 314
      // the event handler.                                                                                   // 315
      var wrappedHandler = function (event) {                                                                 // 316
        var comp = UI.DomRange.getContainingComponent(event.currentTarget);                                   // 317
        var data = comp && getComponentData(comp);                                                            // 318
        var args = _.toArray(arguments);                                                                      // 319
        updateTemplateInstance(self);                                                                         // 320
        return Deps.nonreactive(function () {                                                                 // 321
          // put self.templateInstance as the second argument                                                 // 322
          args.splice(1, 0, self.templateInstance);                                                           // 323
          // Don't want to be in a deps context, even if we were somehow                                      // 324
          // triggered synchronously in an existing deps context                                              // 325
          // (the `blur` event can do this).                                                                  // 326
          // XXX we should probably do what Spark did and block all                                           // 327
          // event handling during our DOM manip.  Many apps had weird                                        // 328
          // unanticipated bugs until we did that.                                                            // 329
          return esh.handler.apply(data === null ? {} : data, args);                                          // 330
        });                                                                                                   // 331
      };                                                                                                      // 332
                                                                                                              // 333
      self.dom.on(esh.events, esh.selector, wrappedHandler);                                                  // 334
    });                                                                                                       // 335
  }                                                                                                           // 336
                                                                                                              // 337
  if (self.rendered) {                                                                                        // 338
    // Defer rendered callback until flush time.                                                              // 339
    Deps.afterFlush(function () {                                                                             // 340
      if (! self.isDestroyed) {                                                                               // 341
        updateTemplateInstance(self);                                                                         // 342
        self.rendered.call(self.templateInstance);                                                            // 343
      }                                                                                                       // 344
    });                                                                                                       // 345
  }                                                                                                           // 346
};                                                                                                            // 347
                                                                                                              // 348
// past compat                                                                                                // 349
UI.Component.preserve = function () {                                                                         // 350
  Meteor._debug("The 'preserve' method on templates is now unnecessary and deprecated.");                     // 351
};                                                                                                            // 352
                                                                                                              // 353
// Gets the data context of the enclosing component that rendered a                                           // 354
// given element                                                                                              // 355
UI.getElementData = function (el) {                                                                           // 356
  var comp = UI.DomRange.getContainingComponent(el);                                                          // 357
  return comp && getComponentData(comp);                                                                      // 358
};                                                                                                            // 359
                                                                                                              // 360
var jsUrlsAllowed = false;                                                                                    // 361
UI._allowJavascriptUrls = function () {                                                                       // 362
  jsUrlsAllowed = true;                                                                                       // 363
};                                                                                                            // 364
UI._javascriptUrlsAllowed = function () {                                                                     // 365
  return jsUrlsAllowed;                                                                                       // 366
};                                                                                                            // 367
                                                                                                              // 368
UI._templateInstance = function () {                                                                          // 369
  var currentComp = currentComponent.get();                                                                   // 370
  if (! currentComp) {                                                                                        // 371
    throw new Error("You can only call UI._templateInstance() from within" +                                  // 372
                    " a helper function.");                                                                   // 373
  }                                                                                                           // 374
                                                                                                              // 375
  // Find the enclosing component that is a template. (`currentComp`                                          // 376
  // could be, for example, an #if or #with, and we want the component                                        // 377
  // that is the surrounding template.)                                                                       // 378
  var template = findHelperHostComponent(currentComp);                                                        // 379
  if (! template) {                                                                                           // 380
    throw new Error("Current component is not inside a template?");                                           // 381
  }                                                                                                           // 382
                                                                                                              // 383
  // Lazily update the template instance for this helper, and do it only                                      // 384
  // once.                                                                                                    // 385
  if (! currentTemplateInstance) {                                                                            // 386
    updateTemplateInstance(template);                                                                         // 387
    currentTemplateInstance = template.templateInstance;                                                      // 388
  }                                                                                                           // 389
  return currentTemplateInstance;                                                                             // 390
};                                                                                                            // 391
                                                                                                              // 392
// Returns the data context of the parent which is 'numLevels' above the                                      // 393
// component. Same behavior as {{../..}} in a template, with 'numLevels'                                      // 394
// occurrences of '..'.                                                                                       // 395
UI._parentData = function (numLevels) {                                                                       // 396
  var component = currentComponent.get();                                                                     // 397
  while (component && numLevels >= 0) {                                                                       // 398
    // Decrement numLevels every time we find a new data context. Break                                       // 399
    // once we have reached numLevels < 0.                                                                    // 400
    if (component.data !== undefined && --numLevels < 0) {                                                    // 401
      break;                                                                                                  // 402
    }                                                                                                         // 403
    component = component.parent;                                                                             // 404
  }                                                                                                           // 405
                                                                                                              // 406
  if (! component) {                                                                                          // 407
    return null;                                                                                              // 408
  }                                                                                                           // 409
                                                                                                              // 410
  return getComponentData(component);                                                                         // 411
};                                                                                                            // 412
                                                                                                              // 413
////////////////////////////////////////////////////////////////////////////////////////////////////////////////

}).call(this);






(function () {

////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//                                                                                                            //
// packages/ui/dombackend.js                                                                                  //
//                                                                                                            //
////////////////////////////////////////////////////////////////////////////////////////////////////////////////
                                                                                                              //
if (Meteor.isClient) {                                                                                        // 1
                                                                                                              // 2
  // XXX in the future, make the jQuery adapter a separate                                                    // 3
  // package and make the choice of back-end library                                                          // 4
  // configurable.  Adapters all expose the same DomBackend interface.                                        // 5
                                                                                                              // 6
  if (! Package.jquery)                                                                                       // 7
    throw new Error("Meteor UI jQuery adapter: jQuery not found.");                                           // 8
                                                                                                              // 9
  var $jq = Package.jquery.jQuery;                                                                            // 10
                                                                                                              // 11
  var DomBackend = {};                                                                                        // 12
  UI.DomBackend = DomBackend;                                                                                 // 13
                                                                                                              // 14
  ///// Removal detection and interoperability.                                                               // 15
                                                                                                              // 16
  // For an explanation of this technique, see:                                                               // 17
  // http://bugs.jquery.com/ticket/12213#comment:23 .                                                         // 18
  //                                                                                                          // 19
  // In short, an element is considered "removed" when jQuery                                                 // 20
  // cleans up its *private* userdata on the element,                                                         // 21
  // which we can detect using a custom event with a teardown                                                 // 22
  // hook.                                                                                                    // 23
                                                                                                              // 24
  var JQUERY_REMOVAL_WATCHER_EVENT_NAME = 'meteor_ui_removal_watcher';                                        // 25
  var REMOVAL_CALLBACKS_PROPERTY_NAME = '$meteor_ui_removal_callbacks';                                       // 26
  var NOOP = function () {};                                                                                  // 27
                                                                                                              // 28
  // Causes `elem` (a DOM element) to be detached from its parent, if any.                                    // 29
  // Whether or not `elem` was detached, causes any callbacks registered                                      // 30
  // with `onElementTeardown` on `elem` and its descendants to fire.                                          // 31
  // Not for use on non-element nodes.                                                                        // 32
  //                                                                                                          // 33
  // This method is modeled after the behavior of jQuery's `$(elem).remove()`,                                // 34
  // which causes teardown on the subtree being removed.                                                      // 35
  DomBackend.removeElement = function (elem) {                                                                // 36
    $jq(elem).remove();                                                                                       // 37
  };                                                                                                          // 38
                                                                                                              // 39
  DomBackend.tearDownElement = function (elem) {                                                              // 40
    var elems = _.toArray(elem.getElementsByTagName('*'));                                                    // 41
    elems.push(elem);                                                                                         // 42
    $jq.cleanData(elems);                                                                                     // 43
  };                                                                                                          // 44
                                                                                                              // 45
  // Registers a callback function to be called when the given element or                                     // 46
  // one of its ancestors is removed from the DOM via the backend library.                                    // 47
  // The callback function is called at most once, and it receives the element                                // 48
  // in question as an argument.                                                                              // 49
  DomBackend.onElementTeardown = function (elem, func) {                                                      // 50
    if (! elem[REMOVAL_CALLBACKS_PROPERTY_NAME]) {                                                            // 51
      elem[REMOVAL_CALLBACKS_PROPERTY_NAME] = [];                                                             // 52
                                                                                                              // 53
      // Set up the event, only the first time.                                                               // 54
      $jq(elem).on(JQUERY_REMOVAL_WATCHER_EVENT_NAME, NOOP);                                                  // 55
    }                                                                                                         // 56
                                                                                                              // 57
    elem[REMOVAL_CALLBACKS_PROPERTY_NAME].push(func);                                                         // 58
  };                                                                                                          // 59
                                                                                                              // 60
  $jq.event.special[JQUERY_REMOVAL_WATCHER_EVENT_NAME] = {                                                    // 61
    teardown: function() {                                                                                    // 62
      var elem = this;                                                                                        // 63
      var callbacks = elem[REMOVAL_CALLBACKS_PROPERTY_NAME];                                                  // 64
      if (callbacks) {                                                                                        // 65
        for (var i = 0; i < callbacks.length; i++)                                                            // 66
          callbacks[i](elem);                                                                                 // 67
        elem[REMOVAL_CALLBACKS_PROPERTY_NAME] = null;                                                         // 68
      }                                                                                                       // 69
    }                                                                                                         // 70
  };                                                                                                          // 71
                                                                                                              // 72
  DomBackend.parseHTML = function (html) {                                                                    // 73
    // Return an array of nodes.                                                                              // 74
    //                                                                                                        // 75
    // jQuery does fancy stuff like creating an appropriate                                                   // 76
    // container element and setting innerHTML on it, as well                                                 // 77
    // as working around various IE quirks.                                                                   // 78
    return $jq.parseHTML(html) || [];                                                                         // 79
  };                                                                                                          // 80
                                                                                                              // 81
  // Must use jQuery semantics for `context`, not                                                             // 82
  // querySelectorAll's.  In other words, all the parts                                                       // 83
  // of `selector` must be found under `context`.                                                             // 84
  DomBackend.findBySelector = function (selector, context) {                                                  // 85
    return $jq(selector, context);                                                                            // 86
  };                                                                                                          // 87
                                                                                                              // 88
  DomBackend.newFragment = function (nodeArray) {                                                             // 89
    var frag = document.createDocumentFragment();                                                             // 90
    for (var i = 0; i < nodeArray.length; i++)                                                                // 91
      frag.appendChild(nodeArray[i]);                                                                         // 92
    return frag;                                                                                              // 93
  };                                                                                                          // 94
                                                                                                              // 95
  // `selector` is non-null.  `type` is one type (but                                                         // 96
  // may be in backend-specific form, e.g. have namespaces).                                                  // 97
  // Order fired must be order bound.                                                                         // 98
  DomBackend.delegateEvents = function (elem, type, selector, handler) {                                      // 99
    $jq(elem).on(type, selector, handler);                                                                    // 100
  };                                                                                                          // 101
                                                                                                              // 102
  DomBackend.undelegateEvents = function (elem, type, handler) {                                              // 103
    $jq(elem).off(type, handler);                                                                             // 104
  };                                                                                                          // 105
                                                                                                              // 106
  DomBackend.bindEventCapturer = function (elem, type, selector, handler) {                                   // 107
    var $elem = $jq(elem);                                                                                    // 108
                                                                                                              // 109
    var wrapper = function (event) {                                                                          // 110
      event = $jq.event.fix(event);                                                                           // 111
      event.currentTarget = event.target;                                                                     // 112
                                                                                                              // 113
      // Note: It might improve jQuery interop if we called into jQuery                                       // 114
      // here somehow.  Since we don't use jQuery to dispatch the event,                                      // 115
      // we don't fire any of jQuery's event hooks or anything.  However,                                     // 116
      // since jQuery can't bind capturing handlers, it's not clear                                           // 117
      // where we would hook in.  Internal jQuery functions like `dispatch`                                   // 118
      // are too high-level.                                                                                  // 119
      var $target = $jq(event.currentTarget);                                                                 // 120
      if ($target.is($elem.find(selector)))                                                                   // 121
        handler.call(elem, event);                                                                            // 122
    };                                                                                                        // 123
                                                                                                              // 124
    handler._meteorui_wrapper = wrapper;                                                                      // 125
                                                                                                              // 126
    type = this.parseEventType(type);                                                                         // 127
    // add *capturing* event listener                                                                         // 128
    elem.addEventListener(type, wrapper, true);                                                               // 129
  };                                                                                                          // 130
                                                                                                              // 131
  DomBackend.unbindEventCapturer = function (elem, type, handler) {                                           // 132
    type = this.parseEventType(type);                                                                         // 133
    elem.removeEventListener(type, handler._meteorui_wrapper, true);                                          // 134
  };                                                                                                          // 135
                                                                                                              // 136
  DomBackend.parseEventType = function (type) {                                                               // 137
    // strip off namespaces                                                                                   // 138
    var dotLoc = type.indexOf('.');                                                                           // 139
    if (dotLoc >= 0)                                                                                          // 140
      return type.slice(0, dotLoc);                                                                           // 141
    return type;                                                                                              // 142
  };                                                                                                          // 143
                                                                                                              // 144
}                                                                                                             // 145
                                                                                                              // 146
////////////////////////////////////////////////////////////////////////////////////////////////////////////////

}).call(this);






(function () {

////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//                                                                                                            //
// packages/ui/domrange.js                                                                                    //
//                                                                                                            //
////////////////////////////////////////////////////////////////////////////////////////////////////////////////
                                                                                                              //
// TODO                                                                                                       // 1
// - Lazy removal detection                                                                                   // 2
// - UI hooks (expose, test)                                                                                  // 3
// - Quick remove/add (mark "leaving" members; needs UI hooks)                                                // 4
// - Event removal on removal                                                                                 // 5
                                                                                                              // 6
var DomBackend = UI.DomBackend;                                                                               // 7
                                                                                                              // 8
var removeNode = function (n) {                                                                               // 9
  if (n.nodeType === 1 &&                                                                                     // 10
      n.parentNode._uihooks && n.parentNode._uihooks.removeElement) {                                         // 11
    n.parentNode._uihooks.removeElement(n);                                                                   // 12
  } else {                                                                                                    // 13
    n.parentNode.removeChild(n);                                                                              // 14
  }                                                                                                           // 15
};                                                                                                            // 16
                                                                                                              // 17
var insertNode = function (n, parent, next) {                                                                 // 18
  // `|| null` because IE throws an error if 'next' is undefined                                              // 19
  next = next || null;                                                                                        // 20
  if (n.nodeType === 1 &&                                                                                     // 21
      parent._uihooks && parent._uihooks.insertElement) {                                                     // 22
    parent._uihooks.insertElement(n, next);                                                                   // 23
  } else {                                                                                                    // 24
    parent.insertBefore(n, next);                                                                             // 25
  }                                                                                                           // 26
};                                                                                                            // 27
                                                                                                              // 28
var moveNode = function (n, parent, next) {                                                                   // 29
  // `|| null` because IE throws an error if 'next' is undefined                                              // 30
  next = next || null;                                                                                        // 31
  if (n.nodeType === 1 &&                                                                                     // 32
      parent._uihooks && parent._uihooks.moveElement) {                                                       // 33
    parent._uihooks.moveElement(n, next);                                                                     // 34
  } else {                                                                                                    // 35
    parent.insertBefore(n, next);                                                                             // 36
  }                                                                                                           // 37
};                                                                                                            // 38
                                                                                                              // 39
// A very basic operation like Underscore's `_.extend` that                                                   // 40
// copies `src`'s own, enumerable properties onto `tgt` and                                                   // 41
// returns `tgt`.                                                                                             // 42
var _extend = function (tgt, src) {                                                                           // 43
  for (var k in src)                                                                                          // 44
    if (src.hasOwnProperty(k))                                                                                // 45
      tgt[k] = src[k];                                                                                        // 46
  return tgt;                                                                                                 // 47
};                                                                                                            // 48
                                                                                                              // 49
var _contains = function (list, item) {                                                                       // 50
  if (! list)                                                                                                 // 51
    return false;                                                                                             // 52
  for (var i = 0, N = list.length; i < N; i++)                                                                // 53
    if (list[i] === item)                                                                                     // 54
      return true;                                                                                            // 55
  return false;                                                                                               // 56
};                                                                                                            // 57
                                                                                                              // 58
var isArray = function (x) {                                                                                  // 59
  return !!((typeof x.length === 'number') &&                                                                 // 60
            (x.sort || x.splice));                                                                            // 61
};                                                                                                            // 62
                                                                                                              // 63
// Text nodes consisting of only whitespace                                                                   // 64
// are "insignificant" nodes.                                                                                 // 65
var isSignificantNode = function (n) {                                                                        // 66
  return ! (n.nodeType === 3 &&                                                                               // 67
            (! n.nodeValue ||                                                                                 // 68
             /^\s+$/.test(n.nodeValue)));                                                                     // 69
};                                                                                                            // 70
                                                                                                              // 71
var checkId = function (id) {                                                                                 // 72
  if (typeof id !== 'string')                                                                                 // 73
    throw new Error("id must be a string");                                                                   // 74
  if (! id)                                                                                                   // 75
    throw new Error("id may not be empty");                                                                   // 76
};                                                                                                            // 77
                                                                                                              // 78
var textExpandosSupported = (function () {                                                                    // 79
  var tn = document.createTextNode('');                                                                       // 80
  try {                                                                                                       // 81
    tn.blahblah = true;                                                                                       // 82
    return true;                                                                                              // 83
  } catch (e) {                                                                                               // 84
    // IE 8                                                                                                   // 85
    return false;                                                                                             // 86
  }                                                                                                           // 87
})();                                                                                                         // 88
                                                                                                              // 89
var createMarkerNode = (                                                                                      // 90
  textExpandosSupported ?                                                                                     // 91
    function () { return document.createTextNode(""); } :                                                     // 92
  function () { return document.createComment("IE"); });                                                      // 93
                                                                                                              // 94
var rangeParented = function (range) {                                                                        // 95
  if (! range.isParented) {                                                                                   // 96
    range.isParented = true;                                                                                  // 97
                                                                                                              // 98
    if (! range.owner) {                                                                                      // 99
      // top-level (unowned) ranges in an element,                                                            // 100
      // keep a pointer to the range on the parent                                                            // 101
      // element.  This is really just for IE 9+                                                              // 102
      // TextNode GC issues, but we can't do reliable                                                         // 103
      // feature detection (i.e. bug detection).                                                              // 104
      var parentNode = range.parentNode();                                                                    // 105
      var rangeDict = (                                                                                       // 106
        parentNode.$_uiranges ||                                                                              // 107
          (parentNode.$_uiranges = {}));                                                                      // 108
      rangeDict[range._rangeId] = range;                                                                      // 109
      range._rangeDict = rangeDict;                                                                           // 110
                                                                                                              // 111
      // get jQuery to tell us when this node is removed                                                      // 112
      DomBackend.onElementTeardown(parentNode, function () {                                                  // 113
        rangeRemoved(range, true /* alreadyTornDown */);                                                      // 114
      });                                                                                                     // 115
    }                                                                                                         // 116
                                                                                                              // 117
    if (range.component && range.component.notifyParented)                                                    // 118
      range.component.notifyParented();                                                                       // 119
                                                                                                              // 120
    // recurse on member ranges                                                                               // 121
    var members = range.members;                                                                              // 122
    for (var k in members) {                                                                                  // 123
      var mem = members[k];                                                                                   // 124
      if (mem instanceof DomRange)                                                                            // 125
        rangeParented(mem);                                                                                   // 126
    }                                                                                                         // 127
  }                                                                                                           // 128
};                                                                                                            // 129
                                                                                                              // 130
var rangeRemoved = function (range, alreadyTornDown) {                                                        // 131
  if (! range.isRemoved) {                                                                                    // 132
    range.isRemoved = true;                                                                                   // 133
                                                                                                              // 134
    if (range._rangeDict)                                                                                     // 135
      delete range._rangeDict[range._rangeId];                                                                // 136
                                                                                                              // 137
    // clean up events                                                                                        // 138
    if (range.stopHandles) {                                                                                  // 139
      for (var i = 0; i < range.stopHandles.length; i++)                                                      // 140
        range.stopHandles[i].stop();                                                                          // 141
      range.stopHandles = null;                                                                               // 142
    }                                                                                                         // 143
                                                                                                              // 144
    // notify component of removal                                                                            // 145
    if (range.removed)                                                                                        // 146
      range.removed();                                                                                        // 147
                                                                                                              // 148
    membersRemoved(range, alreadyTornDown);                                                                   // 149
  }                                                                                                           // 150
};                                                                                                            // 151
                                                                                                              // 152
var nodeRemoved = function (node, alreadyTornDown) {                                                          // 153
  if (node.nodeType === 1) { // ELEMENT                                                                       // 154
    var comps = DomRange.getComponents(node);                                                                 // 155
    for (var i = 0, N = comps.length; i < N; i++)                                                             // 156
      rangeRemoved(comps[i], true /* alreadyTornDown */);                                                     // 157
                                                                                                              // 158
    // `alreadyTornDown` is an optimization so that we don't                                                  // 159
    // tear down the same elements multiple times when tearing                                                // 160
    // down a tree of DomRanges and elements, leading to asymptotic                                           // 161
    // inefficiency.                                                                                          // 162
    //                                                                                                        // 163
    // When jQuery removes an element or DomBackend.tearDownElement                                           // 164
    // is called, the DOM is "cleaned" recursively, calling all                                               // 165
    // onElementTearDown handlers on the entire DOM subtree.                                                  // 166
    // Since the entire subtree is already walked, we don't want to                                           // 167
    // also walk the subtrees of each DomRange for teardown purposes.                                         // 168
    if (! alreadyTornDown)                                                                                    // 169
      DomBackend.tearDownElement(node);                                                                       // 170
  }                                                                                                           // 171
};                                                                                                            // 172
                                                                                                              // 173
var membersRemoved = function (range, alreadyTornDown) {                                                      // 174
  var members = range.members;                                                                                // 175
  for (var k in members) {                                                                                    // 176
    var mem = members[k];                                                                                     // 177
    if (mem instanceof DomRange)                                                                              // 178
      rangeRemoved(mem, alreadyTornDown);                                                                     // 179
    else                                                                                                      // 180
      nodeRemoved(mem, alreadyTornDown);                                                                      // 181
  }                                                                                                           // 182
};                                                                                                            // 183
                                                                                                              // 184
var nextGuid = 1;                                                                                             // 185
                                                                                                              // 186
var DomRange = function () {                                                                                  // 187
  var start = createMarkerNode();                                                                             // 188
  var end = createMarkerNode();                                                                               // 189
  var fragment = DomBackend.newFragment([start, end]);                                                        // 190
  fragment.$_uiIsOffscreen = true;                                                                            // 191
                                                                                                              // 192
  this.start = start;                                                                                         // 193
  this.end = end;                                                                                             // 194
  start.$ui = this;                                                                                           // 195
  end.$ui = this;                                                                                             // 196
                                                                                                              // 197
  this.members = {};                                                                                          // 198
  this.nextMemberId = 1;                                                                                      // 199
  this.owner = null;                                                                                          // 200
  this._rangeId = nextGuid++;                                                                                 // 201
  this._rangeDict = null;                                                                                     // 202
                                                                                                              // 203
  this.isParented = false;                                                                                    // 204
  this.isRemoved = false;                                                                                     // 205
                                                                                                              // 206
  this.stopHandles = null;                                                                                    // 207
};                                                                                                            // 208
                                                                                                              // 209
_extend(DomRange.prototype, {                                                                                 // 210
  getNodes: function () {                                                                                     // 211
    if (! this.parentNode())                                                                                  // 212
      return [];                                                                                              // 213
                                                                                                              // 214
    this.refresh();                                                                                           // 215
                                                                                                              // 216
    var afterNode = this.end.nextSibling;                                                                     // 217
    var nodes = [];                                                                                           // 218
    for (var n = this.start;                                                                                  // 219
         n && n !== afterNode;                                                                                // 220
         n = n.nextSibling)                                                                                   // 221
      nodes.push(n);                                                                                          // 222
    return nodes;                                                                                             // 223
  },                                                                                                          // 224
  removeAll: function () {                                                                                    // 225
    if (! this.parentNode())                                                                                  // 226
      return;                                                                                                 // 227
                                                                                                              // 228
    this.refresh();                                                                                           // 229
                                                                                                              // 230
    // leave start and end                                                                                    // 231
    var afterNode = this.end;                                                                                 // 232
    var nodes = [];                                                                                           // 233
    for (var n = this.start.nextSibling;                                                                      // 234
         n && n !== afterNode;                                                                                // 235
         n = n.nextSibling) {                                                                                 // 236
      // don't remove yet since then we'd lose nextSibling                                                    // 237
      nodes.push(n);                                                                                          // 238
    }                                                                                                         // 239
    for (var i = 0, N = nodes.length; i < N; i++)                                                             // 240
      removeNode(nodes[i]);                                                                                   // 241
                                                                                                              // 242
    membersRemoved(this);                                                                                     // 243
                                                                                                              // 244
    this.members = {};                                                                                        // 245
  },                                                                                                          // 246
  // (_nextNode is internal)                                                                                  // 247
  add: function (id, newMemberOrArray, beforeId, _nextNode) {                                                 // 248
    if (id != null && typeof id !== 'string') {                                                               // 249
      if (typeof id !== 'object')                                                                             // 250
        // a non-object first argument is probably meant                                                      // 251
        // as an id, NOT a new member, so complain about it                                                   // 252
        // as such.                                                                                           // 253
        throw new Error("id must be a string");                                                               // 254
      beforeId = newMemberOrArray;                                                                            // 255
      newMemberOrArray = id;                                                                                  // 256
      id = null;                                                                                              // 257
    }                                                                                                         // 258
                                                                                                              // 259
    if (! newMemberOrArray || typeof newMemberOrArray !== 'object')                                           // 260
      throw new Error("Expected component, node, or array");                                                  // 261
                                                                                                              // 262
    if (isArray(newMemberOrArray)) {                                                                          // 263
      if (newMemberOrArray.length === 1) {                                                                    // 264
        newMemberOrArray = newMemberOrArray[0];                                                               // 265
      } else {                                                                                                // 266
        if (id != null)                                                                                       // 267
          throw new Error("Can only add one node or one component if id is given");                           // 268
        var array = newMemberOrArray;                                                                         // 269
        // calculate `nextNode` once in case it involves a refresh                                            // 270
        _nextNode = this.getInsertionPoint(beforeId);                                                         // 271
        for (var i = 0; i < array.length; i++)                                                                // 272
          this.add(null, array[i], beforeId, _nextNode);                                                      // 273
        return;                                                                                               // 274
      }                                                                                                       // 275
    }                                                                                                         // 276
                                                                                                              // 277
    var parentNode = this.parentNode();                                                                       // 278
    // Consider ourselves removed (and don't mind) if                                                         // 279
    // start marker has no parent.                                                                            // 280
    if (! parentNode)                                                                                         // 281
      return;                                                                                                 // 282
    // because this may call `refresh`, it must be done                                                       // 283
    // early, before we add the new member.                                                                   // 284
    var nextNode = (_nextNode ||                                                                              // 285
                    this.getInsertionPoint(beforeId));                                                        // 286
                                                                                                              // 287
    var newMember = newMemberOrArray;                                                                         // 288
    if (id == null) {                                                                                         // 289
      id = this.nextMemberId++;                                                                               // 290
    } else {                                                                                                  // 291
      checkId(id);                                                                                            // 292
      id = ' ' + id;                                                                                          // 293
    }                                                                                                         // 294
                                                                                                              // 295
    var members = this.members;                                                                               // 296
    if (members.hasOwnProperty(id)) {                                                                         // 297
      var oldMember = members[id];                                                                            // 298
      if (oldMember instanceof DomRange) {                                                                    // 299
        // range, does it still exist?                                                                        // 300
        var oldRange = oldMember;                                                                             // 301
        if (oldRange.start.parentNode !== parentNode) {                                                       // 302
          delete members[id];                                                                                 // 303
          oldRange.owner = null;                                                                              // 304
          rangeRemoved(oldRange);                                                                             // 305
        } else {                                                                                              // 306
          throw new Error("Member already exists: " + id.slice(1));                                           // 307
        }                                                                                                     // 308
      } else {                                                                                                // 309
        // node, does it still exist?                                                                         // 310
        var oldNode = oldMember;                                                                              // 311
        if (oldNode.parentNode !== parentNode) {                                                              // 312
          nodeRemoved(oldNode);                                                                               // 313
          delete members[id];                                                                                 // 314
        } else {                                                                                              // 315
          throw new Error("Member already exists: " + id.slice(1));                                           // 316
        }                                                                                                     // 317
      }                                                                                                       // 318
    }                                                                                                         // 319
                                                                                                              // 320
    if (newMember instanceof DomRange) {                                                                      // 321
      // Range                                                                                                // 322
      var range = newMember;                                                                                  // 323
      range.owner = this;                                                                                     // 324
      var nodes = range.getNodes();                                                                           // 325
                                                                                                              // 326
      members[id] = newMember;                                                                                // 327
      for (var i = 0; i < nodes.length; i++)                                                                  // 328
        insertNode(nodes[i], parentNode, nextNode);                                                           // 329
                                                                                                              // 330
      if (this.isParented)                                                                                    // 331
        rangeParented(range);                                                                                 // 332
    } else {                                                                                                  // 333
      // Node                                                                                                 // 334
      if (typeof newMember.nodeType !== 'number')                                                             // 335
        throw new Error("Expected Component or Node");                                                        // 336
      var node = newMember;                                                                                   // 337
      // can't attach `$ui` to a TextNode in IE 8, so                                                         // 338
      // don't bother on any browser.                                                                         // 339
      if (node.nodeType !== 3)                                                                                // 340
        node.$ui = this;                                                                                      // 341
                                                                                                              // 342
      members[id] = newMember;                                                                                // 343
      insertNode(node, parentNode, nextNode);                                                                 // 344
    }                                                                                                         // 345
  },                                                                                                          // 346
  remove: function (id) {                                                                                     // 347
    if (id == null) {                                                                                         // 348
      // remove self                                                                                          // 349
      this.removeAll();                                                                                       // 350
      removeNode(this.start);                                                                                 // 351
      removeNode(this.end);                                                                                   // 352
      this.owner = null;                                                                                      // 353
      rangeRemoved(this);                                                                                     // 354
      return;                                                                                                 // 355
    }                                                                                                         // 356
                                                                                                              // 357
    checkId(id);                                                                                              // 358
    id = ' ' + id;                                                                                            // 359
    var members = this.members;                                                                               // 360
    var member = (members.hasOwnProperty(id) &&                                                               // 361
                  members[id]);                                                                               // 362
    delete members[id];                                                                                       // 363
                                                                                                              // 364
    // Don't mind double-remove.                                                                              // 365
    if (! member)                                                                                             // 366
      return;                                                                                                 // 367
                                                                                                              // 368
    var parentNode = this.parentNode();                                                                       // 369
    // Consider ourselves removed (and don't mind) if                                                         // 370
    // start marker has no parent.                                                                            // 371
    if (! parentNode)                                                                                         // 372
      return;                                                                                                 // 373
                                                                                                              // 374
    if (member instanceof DomRange) {                                                                         // 375
      // Range                                                                                                // 376
      var range = member;                                                                                     // 377
      range.owner = null;                                                                                     // 378
      // Don't mind if range (specifically its start                                                          // 379
      // marker) has been removed already.                                                                    // 380
      if (range.start.parentNode === parentNode)                                                              // 381
        member.remove();                                                                                      // 382
    } else {                                                                                                  // 383
      // Node                                                                                                 // 384
      var node = member;                                                                                      // 385
      // Don't mind if node has been removed already.                                                         // 386
      if (node.parentNode === parentNode)                                                                     // 387
        removeNode(node);                                                                                     // 388
    }                                                                                                         // 389
  },                                                                                                          // 390
  moveBefore: function (id, beforeId) {                                                                       // 391
    var nextNode = this.getInsertionPoint(beforeId);                                                          // 392
    checkId(id);                                                                                              // 393
    id = ' ' + id;                                                                                            // 394
    var members = this.members;                                                                               // 395
    var member =                                                                                              // 396
          (members.hasOwnProperty(id) &&                                                                      // 397
           members[id]);                                                                                      // 398
                                                                                                              // 399
    // Don't mind if member doesn't exist.                                                                    // 400
    if (! member)                                                                                             // 401
      return;                                                                                                 // 402
                                                                                                              // 403
    var parentNode = this.parentNode();                                                                       // 404
    // Consider ourselves removed (and don't mind) if                                                         // 405
    // start marker has no parent.                                                                            // 406
    if (! parentNode)                                                                                         // 407
      return;                                                                                                 // 408
                                                                                                              // 409
    if (member instanceof DomRange) {                                                                         // 410
      // Range                                                                                                // 411
      var range = member;                                                                                     // 412
      // Don't mind if range (specifically its start marker)                                                  // 413
      // has been removed already.                                                                            // 414
      if (range.start.parentNode === parentNode) {                                                            // 415
        range.refresh();                                                                                      // 416
        var nodes = range.getNodes();                                                                         // 417
        for (var i = 0; i < nodes.length; i++)                                                                // 418
          moveNode(nodes[i], parentNode, nextNode);                                                           // 419
      }                                                                                                       // 420
    } else {                                                                                                  // 421
      // Node                                                                                                 // 422
      var node = member;                                                                                      // 423
      moveNode(node, parentNode, nextNode);                                                                   // 424
    }                                                                                                         // 425
  },                                                                                                          // 426
  get: function (id) {                                                                                        // 427
    checkId(id);                                                                                              // 428
    id = ' ' + id;                                                                                            // 429
    var members = this.members;                                                                               // 430
    if (members.hasOwnProperty(id))                                                                           // 431
      return members[id];                                                                                     // 432
    return null;                                                                                              // 433
  },                                                                                                          // 434
  parentNode: function () {                                                                                   // 435
    return this.start.parentNode;                                                                             // 436
  },                                                                                                          // 437
  startNode: function () {                                                                                    // 438
    return this.start;                                                                                        // 439
  },                                                                                                          // 440
  endNode: function () {                                                                                      // 441
    return this.end;                                                                                          // 442
  },                                                                                                          // 443
  eachMember: function (nodeFunc, rangeFunc) {                                                                // 444
    var members = this.members;                                                                               // 445
    var parentNode = this.parentNode();                                                                       // 446
    for (var k in members) {                                                                                  // 447
      // mem is a component (hosting a Range) or a Node                                                       // 448
      var mem = members[k];                                                                                   // 449
      if (mem instanceof DomRange) {                                                                          // 450
        // Range                                                                                              // 451
        var range = mem;                                                                                      // 452
        if (range.start.parentNode === parentNode) {                                                          // 453
          rangeFunc && rangeFunc(range); // still there                                                       // 454
        } else {                                                                                              // 455
          range.owner = null;                                                                                 // 456
          delete members[k]; // gone                                                                          // 457
          rangeRemoved(range);                                                                                // 458
        }                                                                                                     // 459
      } else {                                                                                                // 460
        // Node                                                                                               // 461
        var node = mem;                                                                                       // 462
        if (node.parentNode === parentNode) {                                                                 // 463
          nodeFunc && nodeFunc(node); // still there                                                          // 464
        } else {                                                                                              // 465
          delete members[k]; // gone                                                                          // 466
          nodeRemoved(node);                                                                                  // 467
        }                                                                                                     // 468
      }                                                                                                       // 469
    }                                                                                                         // 470
  },                                                                                                          // 471
                                                                                                              // 472
  ///////////// INTERNALS below this point, pretty much                                                       // 473
                                                                                                              // 474
  // The purpose of "refreshing" a DomRange is to                                                             // 475
  // take into account any element removals or moves                                                          // 476
  // that may have occurred, and to "fix" the start                                                           // 477
  // and end markers before the entire range is moved                                                         // 478
  // or removed so that they bracket the appropriate                                                          // 479
  // content.                                                                                                 // 480
  //                                                                                                          // 481
  // For example, if a DomRange contains a single element                                                     // 482
  // node, and this node is moved using jQuery, refreshing                                                    // 483
  // the DomRange will look to the element as ground truth                                                    // 484
  // and move the start/end markers around the element.                                                       // 485
  // A refreshed DomRange's nodes may surround nodes from                                                     // 486
  // sibling DomRanges (including their marker nodes)                                                         // 487
  // until the sibling DomRange is refreshed.                                                                 // 488
  //                                                                                                          // 489
  // Specifically, `refresh` moves the `start`                                                                // 490
  // and `end` nodes to immediate before the first,                                                           // 491
  // and after the last, "significant" node the                                                               // 492
  // DomRange contains, where a significant node                                                              // 493
  // is any node except a whitespace-only text-node.                                                          // 494
  // All member ranges are refreshed first.  Adjacent                                                         // 495
  // insignificant member nodes are included between                                                          // 496
  // `start` and `end` as well, but it's possible that                                                        // 497
  // other insignificant nodes remain as siblings                                                             // 498
  // elsewhere.  Nodes with no DomRange owner that are                                                        // 499
  // found between this DomRange's nodes are adopted.                                                         // 500
  //                                                                                                          // 501
  // Performing add/move/remove operations on an "each"                                                       // 502
  // shouldn't require refreshing the entire each, just                                                       // 503
  // the member in question.  (However, adding to the                                                         // 504
  // end may require refreshing the whole "each";                                                             // 505
  // see `getInsertionPoint`.  Adding multiple members                                                        // 506
  // at once using `add(array)` is faster.                                                                    // 507
  refresh: function () {                                                                                      // 508
                                                                                                              // 509
    var parentNode = this.parentNode();                                                                       // 510
    if (! parentNode)                                                                                         // 511
      return;                                                                                                 // 512
                                                                                                              // 513
    // Using `eachMember`, do several things:                                                                 // 514
    // - Refresh all member ranges                                                                            // 515
    // - Count our members                                                                                    // 516
    // - If there's only one, get that one                                                                    // 517
    // - Make a list of member TextNodes, which we                                                            // 518
    //   can't detect with a `$ui` property because                                                           // 519
    //   IE 8 doesn't allow user-defined properties                                                           // 520
    //   on TextNodes.                                                                                        // 521
    var someNode = null;                                                                                      // 522
    var someRange = null;                                                                                     // 523
    var numMembers = 0;                                                                                       // 524
    var textNodes = null;                                                                                     // 525
    this.eachMember(function (node) {                                                                         // 526
      someNode = node;                                                                                        // 527
      numMembers++;                                                                                           // 528
      if (node.nodeType === 3) {                                                                              // 529
        textNodes = (textNodes || []);                                                                        // 530
        textNodes.push(node);                                                                                 // 531
      }                                                                                                       // 532
    }, function (range) {                                                                                     // 533
      range.refresh();                                                                                        // 534
      someRange = range;                                                                                      // 535
      numMembers++;                                                                                           // 536
    });                                                                                                       // 537
                                                                                                              // 538
    var firstNode = null;                                                                                     // 539
    var lastNode = null;                                                                                      // 540
                                                                                                              // 541
    if (numMembers === 0) {                                                                                   // 542
      // don't scan for members                                                                               // 543
    } else if (numMembers === 1) {                                                                            // 544
      if (someNode) {                                                                                         // 545
        firstNode = someNode;                                                                                 // 546
        lastNode = someNode;                                                                                  // 547
      } else if (someRange) {                                                                                 // 548
        firstNode = someRange.start;                                                                          // 549
        lastNode = someRange.end;                                                                             // 550
      }                                                                                                       // 551
    } else {                                                                                                  // 552
      // This loop is O(childNodes.length), even if our members                                               // 553
      // are already consecutive.  This means refreshing just one                                             // 554
      // item in a list is technically order of the total number                                              // 555
      // of siblings, including in other list items.                                                          // 556
      //                                                                                                      // 557
      // The root cause is we intentionally don't track the                                                   // 558
      // DOM order of our members, so finding the first                                                       // 559
      // and last in sibling order either involves a scan                                                     // 560
      // or a bunch of calls to compareDocumentPosition.                                                      // 561
      //                                                                                                      // 562
      // Fortunately, the common cases of zero and one members                                                // 563
      // are optimized.  Also, the scan is super-fast because                                                 // 564
      // no work is done for unknown nodes.  It could be possible                                             // 565
      // to optimize this code further if it becomes a problem.                                               // 566
      for (var node = parentNode.firstChild;                                                                  // 567
           node; node = node.nextSibling) {                                                                   // 568
                                                                                                              // 569
        var nodeOwner;                                                                                        // 570
        if (node.$ui &&                                                                                       // 571
            (nodeOwner = node.$ui) &&                                                                         // 572
            ((nodeOwner === this &&                                                                           // 573
              node !== this.start &&                                                                          // 574
              node !== this.end &&                                                                            // 575
              isSignificantNode(node)) ||                                                                     // 576
             (nodeOwner !== this &&                                                                           // 577
              nodeOwner.owner === this &&                                                                     // 578
              nodeOwner.start === node))) {                                                                   // 579
          // found a member range or node                                                                     // 580
          // (excluding "insignificant" empty text nodes,                                                     // 581
          // which won't be moved by, say, jQuery)                                                            // 582
          if (firstNode) {                                                                                    // 583
            // if we've already found a member in our                                                         // 584
            // scan, see if there are some easy ownerless                                                     // 585
            // nodes to "adopt" by scanning backwards.                                                        // 586
            for (var n = firstNode.previousSibling;                                                           // 587
                 n && ! n.$ui;                                                                                // 588
                 n = n.previousSibling) {                                                                     // 589
              this.members[this.nextMemberId++] = n;                                                          // 590
              // can't attach `$ui` to a TextNode in IE 8, so                                                 // 591
              // don't bother on any browser.                                                                 // 592
              if (n.nodeType !== 3)                                                                           // 593
                n.$ui = this;                                                                                 // 594
            }                                                                                                 // 595
          }                                                                                                   // 596
          if (node.$ui === this) {                                                                            // 597
            // Node                                                                                           // 598
            firstNode = (firstNode || node);                                                                  // 599
            lastNode = node;                                                                                  // 600
          } else {                                                                                            // 601
            // Range                                                                                          // 602
            // skip it and include its nodes in                                                               // 603
            // firstNode/lastNode.                                                                            // 604
            firstNode = (firstNode || node);                                                                  // 605
            node = node.$ui.end;                                                                              // 606
            lastNode = node;                                                                                  // 607
          }                                                                                                   // 608
        }                                                                                                     // 609
      }                                                                                                       // 610
    }                                                                                                         // 611
    if (firstNode) {                                                                                          // 612
      // some member or significant node was found.                                                           // 613
      // expand to include our insigificant member                                                            // 614
      // nodes as well.                                                                                       // 615
      for (var n;                                                                                             // 616
           (n = firstNode.previousSibling) &&                                                                 // 617
           (n.$ui && n.$ui === this ||                                                                        // 618
            _contains(textNodes, n));)                                                                        // 619
        firstNode = n;                                                                                        // 620
      for (var n;                                                                                             // 621
           (n = lastNode.nextSibling) &&                                                                      // 622
           (n.$ui && n.$ui === this ||                                                                        // 623
            _contains(textNodes, n));)                                                                        // 624
        lastNode = n;                                                                                         // 625
      // adjust our start/end pointers                                                                        // 626
      if (firstNode !== this.start)                                                                           // 627
        insertNode(this.start,                                                                                // 628
                   parentNode, firstNode);                                                                    // 629
      if (lastNode !== this.end)                                                                              // 630
        insertNode(this.end, parentNode,                                                                      // 631
                 lastNode.nextSibling);                                                                       // 632
    }                                                                                                         // 633
  },                                                                                                          // 634
  getInsertionPoint: function (beforeId) {                                                                    // 635
    var members = this.members;                                                                               // 636
    var parentNode = this.parentNode();                                                                       // 637
                                                                                                              // 638
    if (! beforeId) {                                                                                         // 639
      // Refreshing here is necessary if we want to                                                           // 640
      // allow elements to move around arbitrarily.                                                           // 641
      // If jQuery is used to reorder elements, it could                                                      // 642
      // easily make our `end` pointer meaningless,                                                           // 643
      // even though all our members continue to make                                                         // 644
      // good reference points as long as they are refreshed.                                                 // 645
      //                                                                                                      // 646
      // However, a refresh is expensive!  Let's                                                              // 647
      // make the developer manually refresh if                                                               // 648
      // elements are being re-ordered externally.                                                            // 649
      return this.end;                                                                                        // 650
    }                                                                                                         // 651
                                                                                                              // 652
    checkId(beforeId);                                                                                        // 653
    beforeId = ' ' + beforeId;                                                                                // 654
    var mem = members[beforeId];                                                                              // 655
                                                                                                              // 656
    if (mem instanceof DomRange) {                                                                            // 657
      // Range                                                                                                // 658
      var range = mem;                                                                                        // 659
      if (range.start.parentNode === parentNode) {                                                            // 660
        // still there                                                                                        // 661
        range.refresh();                                                                                      // 662
        return range.start;                                                                                   // 663
      } else {                                                                                                // 664
        range.owner = null;                                                                                   // 665
        rangeRemoved(range);                                                                                  // 666
      }                                                                                                       // 667
    } else {                                                                                                  // 668
      // Node                                                                                                 // 669
      var node = mem;                                                                                         // 670
      if (node.parentNode === parentNode)                                                                     // 671
        return node; // still there                                                                           // 672
      else                                                                                                    // 673
        nodeRemoved(node);                                                                                    // 674
    }                                                                                                         // 675
                                                                                                              // 676
    // not there anymore                                                                                      // 677
    delete members[beforeId];                                                                                 // 678
    // no good position                                                                                       // 679
    return this.end;                                                                                          // 680
  }                                                                                                           // 681
});                                                                                                           // 682
                                                                                                              // 683
DomRange.prototype.elements = function (intoArray) {                                                          // 684
  intoArray = (intoArray || []);                                                                              // 685
  this.eachMember(function (node) {                                                                           // 686
    if (node.nodeType === 1)                                                                                  // 687
      intoArray.push(node);                                                                                   // 688
  }, function (range) {                                                                                       // 689
    range.elements(intoArray);                                                                                // 690
  });                                                                                                         // 691
  return intoArray;                                                                                           // 692
};                                                                                                            // 693
                                                                                                              // 694
// XXX alias the below as `UI.refresh` and `UI.insert`                                                        // 695
                                                                                                              // 696
// In a real-life case where you need a refresh,                                                              // 697
// you probably don't have easy                                                                               // 698
// access to the appropriate DomRange or component,                                                           // 699
// just the enclosing element:                                                                                // 700
//                                                                                                            // 701
// ```                                                                                                        // 702
// {{#Sortable}}                                                                                              // 703
//   <div>                                                                                                    // 704
//     {{#each}}                                                                                              // 705
//       ...                                                                                                  // 706
// ```                                                                                                        // 707
//                                                                                                            // 708
// In this case, Sortable wants to call `refresh`                                                             // 709
// on the div, not the each, so it would use this function.                                                   // 710
DomRange.refresh = function (element) {                                                                       // 711
  var comps = DomRange.getComponents(element);                                                                // 712
                                                                                                              // 713
  for (var i = 0, N = comps.length; i < N; i++)                                                               // 714
    comps[i].refresh();                                                                                       // 715
};                                                                                                            // 716
                                                                                                              // 717
DomRange.getComponents = function (element) {                                                                 // 718
  var topLevelComps = [];                                                                                     // 719
  for (var n = element.firstChild;                                                                            // 720
       n; n = n.nextSibling) {                                                                                // 721
    if (n.$ui && n === n.$ui.start &&                                                                         // 722
        ! n.$ui.owner)                                                                                        // 723
      topLevelComps.push(n.$ui);                                                                              // 724
  }                                                                                                           // 725
  return topLevelComps;                                                                                       // 726
};                                                                                                            // 727
                                                                                                              // 728
// `parentNode` must be an ELEMENT, not a fragment                                                            // 729
DomRange.insert = function (range, parentNode, nextNode) {                                                    // 730
  var nodes = range.getNodes();                                                                               // 731
  for (var i = 0; i < nodes.length; i++)                                                                      // 732
    insertNode(nodes[i], parentNode, nextNode);                                                               // 733
  rangeParented(range);                                                                                       // 734
};                                                                                                            // 735
                                                                                                              // 736
DomRange.getContainingComponent = function (element) {                                                        // 737
  while (element && ! element.$ui)                                                                            // 738
    element = element.parentNode;                                                                             // 739
                                                                                                              // 740
  var range = (element && element.$ui);                                                                       // 741
                                                                                                              // 742
  while (range) {                                                                                             // 743
    if (range.component)                                                                                      // 744
      return range.component;                                                                                 // 745
    range = range.owner;                                                                                      // 746
  }                                                                                                           // 747
  return null;                                                                                                // 748
};                                                                                                            // 749
                                                                                                              // 750
///// FIND BY SELECTOR                                                                                        // 751
                                                                                                              // 752
DomRange.prototype.contains = function (compOrNode) {                                                         // 753
  if (! compOrNode)                                                                                           // 754
    throw new Error("Expected Component or Node");                                                            // 755
                                                                                                              // 756
  var parentNode = this.parentNode();                                                                         // 757
  if (! parentNode)                                                                                           // 758
    return false;                                                                                             // 759
                                                                                                              // 760
  var range;                                                                                                  // 761
  if (compOrNode instanceof DomRange) {                                                                       // 762
    // Component                                                                                              // 763
    range = compOrNode;                                                                                       // 764
    var pn = range.parentNode();                                                                              // 765
    if (! pn)                                                                                                 // 766
      return false;                                                                                           // 767
    // If parentNode is different, it must be a node                                                          // 768
    // we contain.                                                                                            // 769
    if (pn !== parentNode)                                                                                    // 770
      return this.contains(pn);                                                                               // 771
    if (range === this)                                                                                       // 772
      return false; // don't contain self                                                                     // 773
    // Ok, `range` is a same-parent range to see if we                                                        // 774
    // contain.                                                                                               // 775
  } else {                                                                                                    // 776
    // Node                                                                                                   // 777
    var node = compOrNode;                                                                                    // 778
    if (! elementContains(parentNode, node))                                                                  // 779
      return false;                                                                                           // 780
                                                                                                              // 781
    while (node.parentNode !== parentNode)                                                                    // 782
      node = node.parentNode;                                                                                 // 783
                                                                                                              // 784
    range = node.$ui;                                                                                         // 785
  }                                                                                                           // 786
                                                                                                              // 787
  // Now see if `range` is truthy and either `this`                                                           // 788
  // or an immediate subrange                                                                                 // 789
                                                                                                              // 790
  while (range && range !== this)                                                                             // 791
    range = range.owner;                                                                                      // 792
                                                                                                              // 793
  return range === this;                                                                                      // 794
};                                                                                                            // 795
                                                                                                              // 796
DomRange.prototype.$ = function (selector) {                                                                  // 797
  var self = this;                                                                                            // 798
                                                                                                              // 799
  var parentNode = this.parentNode();                                                                         // 800
  if (! parentNode)                                                                                           // 801
    throw new Error("Can't select in removed DomRange");                                                      // 802
                                                                                                              // 803
  // Strategy: Find all selector matches under parentNode,                                                    // 804
  // then filter out the ones that aren't in this DomRange                                                    // 805
  // using upwards pointers ($ui, owner, parentNode).  This is                                                // 806
  // asymptotically slow in the presence of O(N) sibling                                                      // 807
  // content that is under parentNode but not in our range,                                                   // 808
  // so if performance is an issue, the selector should be                                                    // 809
  // run on a child element.                                                                                  // 810
                                                                                                              // 811
  // Since jQuery can't run selectors on a DocumentFragment,                                                  // 812
  // we don't expect findBySelector to work.                                                                  // 813
  if (parentNode.nodeType === 11 /* DocumentFragment */ ||                                                    // 814
      parentNode.$_uiIsOffscreen)                                                                             // 815
    throw new Error("Can't use $ on an offscreen component");                                                 // 816
                                                                                                              // 817
  var results = DomBackend.findBySelector(selector, parentNode);                                              // 818
                                                                                                              // 819
  // We don't assume `results` has jQuery API; a plain array                                                  // 820
  // should do just as well.  However, if we do have a jQuery                                                 // 821
  // array, we want to end up with one also, so we use                                                        // 822
  // `.filter`.                                                                                               // 823
                                                                                                              // 824
                                                                                                              // 825
  // Function that selects only elements that are actually                                                    // 826
  // in this DomRange, rather than simply descending from                                                     // 827
  // `parentNode`.                                                                                            // 828
  var filterFunc = function (elem) {                                                                          // 829
    // handle jQuery's arguments to filter, where the node                                                    // 830
    // is in `this` and the index is the first argument.                                                      // 831
    if (typeof elem === 'number')                                                                             // 832
      elem = this;                                                                                            // 833
                                                                                                              // 834
    return self.contains(elem);                                                                               // 835
  };                                                                                                          // 836
                                                                                                              // 837
  if (! results.filter) {                                                                                     // 838
    // not a jQuery array, and not a browser with                                                             // 839
    // Array.prototype.filter (e.g. IE <9)                                                                    // 840
    var newResults = [];                                                                                      // 841
    for (var i = 0; i < results.length; i++) {                                                                // 842
      var x = results[i];                                                                                     // 843
      if (filterFunc(x))                                                                                      // 844
        newResults.push(x);                                                                                   // 845
    }                                                                                                         // 846
    results = newResults;                                                                                     // 847
  } else {                                                                                                    // 848
    // `results.filter` is either jQuery's or ECMAScript's `filter`                                           // 849
    results = results.filter(filterFunc);                                                                     // 850
  }                                                                                                           // 851
                                                                                                              // 852
  return results;                                                                                             // 853
};                                                                                                            // 854
                                                                                                              // 855
                                                                                                              // 856
///// EVENTS                                                                                                  // 857
                                                                                                              // 858
// List of events to always delegate, never capture.                                                          // 859
// Since jQuery fakes bubbling for certain events in                                                          // 860
// certain browsers (like `submit`), we don't want to                                                         // 861
// get in its way.                                                                                            // 862
//                                                                                                            // 863
// We could list all known bubbling                                                                           // 864
// events here to avoid creating speculative capturers                                                        // 865
// for them, but it would only be an optimization.                                                            // 866
var eventsToDelegate = {                                                                                      // 867
  blur: 1, change: 1, click: 1, focus: 1, focusin: 1,                                                         // 868
  focusout: 1, reset: 1, submit: 1                                                                            // 869
};                                                                                                            // 870
                                                                                                              // 871
var EVENT_MODE_TBD = 0;                                                                                       // 872
var EVENT_MODE_BUBBLING = 1;                                                                                  // 873
var EVENT_MODE_CAPTURING = 2;                                                                                 // 874
                                                                                                              // 875
var HandlerRec = function (elem, type, selector, handler, $ui) {                                              // 876
  this.elem = elem;                                                                                           // 877
  this.type = type;                                                                                           // 878
  this.selector = selector;                                                                                   // 879
  this.handler = handler;                                                                                     // 880
  this.$ui = $ui;                                                                                             // 881
                                                                                                              // 882
  this.mode = EVENT_MODE_TBD;                                                                                 // 883
                                                                                                              // 884
  // It's important that delegatedHandler be a different                                                      // 885
  // instance for each handlerRecord, because its identity                                                    // 886
  // is used to remove it.                                                                                    // 887
  //                                                                                                          // 888
  // It's also important that the closure have access to                                                      // 889
  // `this` when it is not called with it set.                                                                // 890
  this.delegatedHandler = (function (h) {                                                                     // 891
    return function (evt) {                                                                                   // 892
      if ((! h.selector) && evt.currentTarget !== evt.target)                                                 // 893
        // no selector means only fire on target                                                              // 894
        return;                                                                                               // 895
      if (! h.$ui.contains(evt.currentTarget))                                                                // 896
        return;                                                                                               // 897
      return h.handler.apply(h.$ui, arguments);                                                               // 898
    };                                                                                                        // 899
  })(this);                                                                                                   // 900
                                                                                                              // 901
  // WHY CAPTURE AND DELEGATE: jQuery can't delegate                                                          // 902
  // non-bubbling events, because                                                                             // 903
  // event capture doesn't work in IE 8.  However, there                                                      // 904
  // are all sorts of new-fangled non-bubbling events                                                         // 905
  // like "play" and "touchenter".  We delegate these                                                         // 906
  // events using capture in all browsers except IE 8.                                                        // 907
  // IE 8 doesn't support these events anyway.                                                                // 908
                                                                                                              // 909
  var tryCapturing = elem.addEventListener &&                                                                 // 910
        (! eventsToDelegate.hasOwnProperty(                                                                   // 911
          DomBackend.parseEventType(type)));                                                                  // 912
                                                                                                              // 913
  if (tryCapturing) {                                                                                         // 914
    this.capturingHandler = (function (h) {                                                                   // 915
      return function (evt) {                                                                                 // 916
        if (h.mode === EVENT_MODE_TBD) {                                                                      // 917
          // must be first time we're called.                                                                 // 918
          if (evt.bubbles) {                                                                                  // 919
            // this type of event bubbles, so don't                                                           // 920
            // get called again.                                                                              // 921
            h.mode = EVENT_MODE_BUBBLING;                                                                     // 922
            DomBackend.unbindEventCapturer(                                                                   // 923
              h.elem, h.type, h.capturingHandler);                                                            // 924
            return;                                                                                           // 925
          } else {                                                                                            // 926
            // this type of event doesn't bubble,                                                             // 927
            // so unbind the delegation, preventing                                                           // 928
            // it from ever firing.                                                                           // 929
            h.mode = EVENT_MODE_CAPTURING;                                                                    // 930
            DomBackend.undelegateEvents(                                                                      // 931
              h.elem, h.type, h.delegatedHandler);                                                            // 932
          }                                                                                                   // 933
        }                                                                                                     // 934
                                                                                                              // 935
        h.delegatedHandler(evt);                                                                              // 936
      };                                                                                                      // 937
    })(this);                                                                                                 // 938
                                                                                                              // 939
  } else {                                                                                                    // 940
    this.mode = EVENT_MODE_BUBBLING;                                                                          // 941
  }                                                                                                           // 942
};                                                                                                            // 943
                                                                                                              // 944
HandlerRec.prototype.bind = function () {                                                                     // 945
  // `this.mode` may be EVENT_MODE_TBD, in which case we bind both. in                                        // 946
  // this case, 'capturingHandler' is in charge of detecting the                                              // 947
  // correct mode and turning off one or the other handlers.                                                  // 948
  if (this.mode !== EVENT_MODE_BUBBLING) {                                                                    // 949
    DomBackend.bindEventCapturer(                                                                             // 950
      this.elem, this.type, this.selector || '*',                                                             // 951
      this.capturingHandler);                                                                                 // 952
  }                                                                                                           // 953
                                                                                                              // 954
  if (this.mode !== EVENT_MODE_CAPTURING)                                                                     // 955
    DomBackend.delegateEvents(                                                                                // 956
      this.elem, this.type,                                                                                   // 957
      this.selector || '*', this.delegatedHandler);                                                           // 958
};                                                                                                            // 959
                                                                                                              // 960
HandlerRec.prototype.unbind = function () {                                                                   // 961
  if (this.mode !== EVENT_MODE_BUBBLING)                                                                      // 962
    DomBackend.unbindEventCapturer(this.elem, this.type,                                                      // 963
                                   this.capturingHandler);                                                    // 964
                                                                                                              // 965
  if (this.mode !== EVENT_MODE_CAPTURING)                                                                     // 966
    DomBackend.undelegateEvents(this.elem, this.type,                                                         // 967
                                this.delegatedHandler);                                                       // 968
};                                                                                                            // 969
                                                                                                              // 970
                                                                                                              // 971
// XXX could write the form of arguments for this function                                                    // 972
// in several different ways, including simply as an event map.                                               // 973
DomRange.prototype.on = function (events, selector, handler) {                                                // 974
  var parentNode = this.parentNode();                                                                         // 975
  if (! parentNode)                                                                                           // 976
    // if we're not in the DOM, silently fail.                                                                // 977
    return;                                                                                                   // 978
  // haven't been added yet; error                                                                            // 979
  if (parentNode.$_uiIsOffscreen)                                                                             // 980
    throw new Error("Can't bind events before DomRange is inserted");                                         // 981
                                                                                                              // 982
  var eventTypes = [];                                                                                        // 983
  events.replace(/[^ /]+/g, function (e) {                                                                    // 984
    eventTypes.push(e);                                                                                       // 985
  });                                                                                                         // 986
                                                                                                              // 987
  if (! handler && (typeof selector === 'function')) {                                                        // 988
    // omitted `selector`                                                                                     // 989
    handler = selector;                                                                                       // 990
    selector = null;                                                                                          // 991
  } else if (! selector) {                                                                                    // 992
    // take `""` to `null`                                                                                    // 993
    selector = null;                                                                                          // 994
  }                                                                                                           // 995
                                                                                                              // 996
  var newHandlerRecs = [];                                                                                    // 997
  for (var i = 0, N = eventTypes.length; i < N; i++) {                                                        // 998
    var type = eventTypes[i];                                                                                 // 999
                                                                                                              // 1000
    var eventDict = parentNode.$_uievents;                                                                    // 1001
    if (! eventDict)                                                                                          // 1002
      eventDict = (parentNode.$_uievents = {});                                                               // 1003
                                                                                                              // 1004
    var info = eventDict[type];                                                                               // 1005
    if (! info) {                                                                                             // 1006
      info = eventDict[type] = {};                                                                            // 1007
      info.handlers = [];                                                                                     // 1008
    }                                                                                                         // 1009
    var handlerList = info.handlers;                                                                          // 1010
    var handlerRec = new HandlerRec(                                                                          // 1011
      parentNode, type, selector, handler, this);                                                             // 1012
    newHandlerRecs.push(handlerRec);                                                                          // 1013
    handlerRec.bind();                                                                                        // 1014
    handlerList.push(handlerRec);                                                                             // 1015
    // move handlers of enclosing ranges to end                                                               // 1016
    for (var r = this.owner; r; r = r.owner) {                                                                // 1017
      // r is an enclosing DomRange                                                                           // 1018
      for (var j = 0, Nj = handlerList.length;                                                                // 1019
           j < Nj; j++) {                                                                                     // 1020
        var h = handlerList[j];                                                                               // 1021
        if (h.$ui === r) {                                                                                    // 1022
          h.unbind();                                                                                         // 1023
          h.bind();                                                                                           // 1024
          handlerList.splice(j, 1); // remove handlerList[j]                                                  // 1025
          handlerList.push(h);                                                                                // 1026
          j--; // account for removed handler                                                                 // 1027
          Nj--; // don't visit appended handlers                                                              // 1028
        }                                                                                                     // 1029
      }                                                                                                       // 1030
    }                                                                                                         // 1031
  }                                                                                                           // 1032
                                                                                                              // 1033
  this.stopHandles = (this.stopHandles || []);                                                                // 1034
  this.stopHandles.push({                                                                                     // 1035
    // closes over just `parentNode` and `newHandlerRecs`                                                     // 1036
    stop: function () {                                                                                       // 1037
      var eventDict = parentNode.$_uievents;                                                                  // 1038
      if (! eventDict)                                                                                        // 1039
        return;                                                                                               // 1040
                                                                                                              // 1041
      for (var i = 0; i < newHandlerRecs.length; i++) {                                                       // 1042
        var handlerToRemove = newHandlerRecs[i];                                                              // 1043
        var info = eventDict[handlerToRemove.type];                                                           // 1044
        if (! info)                                                                                           // 1045
          continue;                                                                                           // 1046
        var handlerList = info.handlers;                                                                      // 1047
        for (var j = handlerList.length - 1; j >= 0; j--) {                                                   // 1048
          if (handlerList[j] === handlerToRemove) {                                                           // 1049
            handlerToRemove.unbind();                                                                         // 1050
            handlerList.splice(j, 1); // remove handlerList[j]                                                // 1051
          }                                                                                                   // 1052
        }                                                                                                     // 1053
      }                                                                                                       // 1054
      newHandlerRecs.length = 0;                                                                              // 1055
    }                                                                                                         // 1056
  });                                                                                                         // 1057
};                                                                                                            // 1058
                                                                                                              // 1059
  // Returns true if element a contains node b and is not node b.                                             // 1060
  var elementContains = function (a, b) {                                                                     // 1061
    if (a.nodeType !== 1) // ELEMENT                                                                          // 1062
      return false;                                                                                           // 1063
    if (a === b)                                                                                              // 1064
      return false;                                                                                           // 1065
                                                                                                              // 1066
    if (a.compareDocumentPosition) {                                                                          // 1067
      return a.compareDocumentPosition(b) & 0x10;                                                             // 1068
    } else {                                                                                                  // 1069
          // Should be only old IE and maybe other old browsers here.                                         // 1070
          // Modern Safari has both functions but seems to get contains() wrong.                              // 1071
          // IE can't handle b being a text node.  We work around this                                        // 1072
          // by doing a direct parent test now.                                                               // 1073
      b = b.parentNode;                                                                                       // 1074
      if (! (b && b.nodeType === 1)) // ELEMENT                                                               // 1075
        return false;                                                                                         // 1076
      if (a === b)                                                                                            // 1077
        return true;                                                                                          // 1078
                                                                                                              // 1079
      return a.contains(b);                                                                                   // 1080
    }                                                                                                         // 1081
  };                                                                                                          // 1082
                                                                                                              // 1083
                                                                                                              // 1084
UI.DomRange = DomRange;                                                                                       // 1085
                                                                                                              // 1086
////////////////////////////////////////////////////////////////////////////////////////////////////////////////

}).call(this);






(function () {

////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//                                                                                                            //
// packages/ui/attrs.js                                                                                       //
//                                                                                                            //
////////////////////////////////////////////////////////////////////////////////////////////////////////////////
                                                                                                              //
                                                                                                              // 1
// An AttributeHandler object is responsible for updating a particular attribute                              // 2
// of a particular element.  AttributeHandler subclasses implement                                            // 3
// browser-specific logic for dealing with particular attributes across                                       // 4
// different browsers.                                                                                        // 5
//                                                                                                            // 6
// To define a new type of AttributeHandler, use                                                              // 7
// `var FooHandler = AttributeHandler.extend({ update: function ... })`                                       // 8
// where the `update` function takes arguments `(element, oldValue, value)`.                                  // 9
// The `element` argument is always the same between calls to `update` on                                     // 10
// the same instance.  `oldValue` and `value` are each either `null` or                                       // 11
// a Unicode string of the type that might be passed to the value argument                                    // 12
// of `setAttribute` (i.e. not an HTML string with character references).                                     // 13
// When an AttributeHandler is installed, an initial call to `update` is                                      // 14
// always made with `oldValue = null`.  The `update` method can access                                        // 15
// `this.name` if the AttributeHandler class is a generic one that applies                                    // 16
// to multiple attribute names.                                                                               // 17
//                                                                                                            // 18
// AttributeHandlers can store custom properties on `this`, as long as they                                   // 19
// don't use the names `element`, `name`, `value`, and `oldValue`.                                            // 20
//                                                                                                            // 21
// AttributeHandlers can't influence how attributes appear in rendered HTML,                                  // 22
// only how they are updated after materialization as DOM.                                                    // 23
                                                                                                              // 24
AttributeHandler = function (name, value) {                                                                   // 25
  this.name = name;                                                                                           // 26
  this.value = value;                                                                                         // 27
};                                                                                                            // 28
                                                                                                              // 29
AttributeHandler.prototype.update = function (element, oldValue, value) {                                     // 30
  if (value === null) {                                                                                       // 31
    if (oldValue !== null)                                                                                    // 32
      element.removeAttribute(this.name);                                                                     // 33
  } else {                                                                                                    // 34
    element.setAttribute(this.name, value);                                                                   // 35
  }                                                                                                           // 36
};                                                                                                            // 37
                                                                                                              // 38
AttributeHandler.extend = function (options) {                                                                // 39
  var curType = this;                                                                                         // 40
  var subType = function AttributeHandlerSubtype(/*arguments*/) {                                             // 41
    AttributeHandler.apply(this, arguments);                                                                  // 42
  };                                                                                                          // 43
  subType.prototype = new curType;                                                                            // 44
  subType.extend = curType.extend;                                                                            // 45
  if (options)                                                                                                // 46
    _.extend(subType.prototype, options);                                                                     // 47
  return subType;                                                                                             // 48
};                                                                                                            // 49
                                                                                                              // 50
/// Apply the diff between the attributes of "oldValue" and "value" to "element."                             // 51
//                                                                                                            // 52
// Each subclass must implement a parseValue method which takes a string                                      // 53
// as an input and returns a dict of attributes. The keys of the dict                                         // 54
// are unique identifiers (ie. css properties in the case of styles), and the                                 // 55
// values are the entire attribute which will be injected into the element.                                   // 56
//                                                                                                            // 57
// Extended below to support classes, SVG elements and styles.                                                // 58
                                                                                                              // 59
var DiffingAttributeHandler = AttributeHandler.extend({                                                       // 60
  update: function (element, oldValue, value) {                                                               // 61
    if (!this.getCurrentValue || !this.setValue || !this.parseValue)                                          // 62
      throw new Error("Missing methods in subclass of 'DiffingAttributeHandler'");                            // 63
                                                                                                              // 64
    var oldAttrsMap = oldValue ? this.parseValue(oldValue) : {};                                              // 65
    var newAttrsMap = value ? this.parseValue(value) : {};                                                    // 66
                                                                                                              // 67
    // the current attributes on the element, which we will mutate.                                           // 68
                                                                                                              // 69
    var attrString = this.getCurrentValue(element);                                                           // 70
    var attrsMap = attrString ? this.parseValue(attrString) : {};                                             // 71
                                                                                                              // 72
    _.each(_.keys(oldAttrsMap), function (t) {                                                                // 73
      if (! (t in newAttrsMap))                                                                               // 74
        delete attrsMap[t];                                                                                   // 75
    });                                                                                                       // 76
                                                                                                              // 77
    _.each(_.keys(newAttrsMap), function (t) {                                                                // 78
      attrsMap[t] = newAttrsMap[t];                                                                           // 79
    });                                                                                                       // 80
                                                                                                              // 81
    this.setValue(element, _.values(attrsMap).join(' '));                                                     // 82
  }                                                                                                           // 83
});                                                                                                           // 84
                                                                                                              // 85
var ClassHandler = DiffingAttributeHandler.extend({                                                           // 86
  // @param rawValue {String}                                                                                 // 87
  getCurrentValue: function (element) {                                                                       // 88
    return element.className;                                                                                 // 89
  },                                                                                                          // 90
  setValue: function (element, className) {                                                                   // 91
    element.className = className;                                                                            // 92
  },                                                                                                          // 93
  parseValue: function (attrString) {                                                                         // 94
    var tokens = {};                                                                                          // 95
                                                                                                              // 96
    _.each(attrString.split(' '), function(token) {                                                           // 97
      if (token)                                                                                              // 98
        tokens[token] = token;                                                                                // 99
    });                                                                                                       // 100
    return tokens;                                                                                            // 101
  }                                                                                                           // 102
});                                                                                                           // 103
                                                                                                              // 104
var SVGClassHandler = ClassHandler.extend({                                                                   // 105
  getCurrentValue: function (element) {                                                                       // 106
    return element.className.baseVal;                                                                         // 107
  },                                                                                                          // 108
  setValue: function (element, className) {                                                                   // 109
    element.setAttribute('class', className);                                                                 // 110
  }                                                                                                           // 111
});                                                                                                           // 112
                                                                                                              // 113
var StyleHandler = DiffingAttributeHandler.extend({                                                           // 114
  getCurrentValue: function (element) {                                                                       // 115
    return element.getAttribute('style');                                                                     // 116
  },                                                                                                          // 117
  setValue: function (element, style) {                                                                       // 118
    if (style === '') {                                                                                       // 119
      element.removeAttribute('style');                                                                       // 120
    } else {                                                                                                  // 121
      element.setAttribute('style', style);                                                                   // 122
    }                                                                                                         // 123
  },                                                                                                          // 124
                                                                                                              // 125
  // Parse a string to produce a map from property to attribute string.                                       // 126
  //                                                                                                          // 127
  // Example:                                                                                                 // 128
  // "color:red; foo:12px" produces a token {color: "color:red", foo:"foo:12px"}                              // 129
  parseValue: function (attrString) {                                                                         // 130
    var tokens = {};                                                                                          // 131
                                                                                                              // 132
    // Regex for parsing a css attribute declaration, taken from css-parse:                                   // 133
    // https://github.com/reworkcss/css-parse/blob/7cef3658d0bba872cde05a85339034b187cb3397/index.js#L219     // 134
    var regex = /(\*?[-#\/\*\\\w]+(?:\[[0-9a-z_-]+\])?)\s*:\s*(?:\'(?:\\\'|.)*?\'|"(?:\\"|.)*?"|\([^\)]*?\)|[^};])+[;\s]*/g;
    var match = regex.exec(attrString);                                                                       // 136
    while (match) {                                                                                           // 137
      // match[0] = entire matching string                                                                    // 138
      // match[1] = css property                                                                              // 139
      // Prefix the token to prevent conflicts with existing properties.                                      // 140
                                                                                                              // 141
      // XXX No `String.trim` on Safari 4. Swap out $.trim if we want to                                      // 142
      // remove strong dep on jquery.                                                                         // 143
      tokens[' ' + match[1]] = match[0].trim ?                                                                // 144
        match[0].trim() : $.trim(match[0]);                                                                   // 145
                                                                                                              // 146
      match = regex.exec(attrString);                                                                         // 147
    }                                                                                                         // 148
                                                                                                              // 149
    return tokens;                                                                                            // 150
  }                                                                                                           // 151
});                                                                                                           // 152
                                                                                                              // 153
var BooleanHandler = AttributeHandler.extend({                                                                // 154
  update: function (element, oldValue, value) {                                                               // 155
    var name = this.name;                                                                                     // 156
    if (value == null) {                                                                                      // 157
      if (oldValue != null)                                                                                   // 158
        element[name] = false;                                                                                // 159
    } else {                                                                                                  // 160
      element[name] = true;                                                                                   // 161
    }                                                                                                         // 162
  }                                                                                                           // 163
});                                                                                                           // 164
                                                                                                              // 165
var ValueHandler = AttributeHandler.extend({                                                                  // 166
  update: function (element, oldValue, value) {                                                               // 167
    element.value = value;                                                                                    // 168
  }                                                                                                           // 169
});                                                                                                           // 170
                                                                                                              // 171
// attributes of the type 'xlink:something' should be set using                                               // 172
// the correct namespace in order to work                                                                     // 173
var XlinkHandler = AttributeHandler.extend({                                                                  // 174
  update: function(element, oldValue, value) {                                                                // 175
    var NS = 'http://www.w3.org/1999/xlink';                                                                  // 176
    if (value === null) {                                                                                     // 177
      if (oldValue !== null)                                                                                  // 178
        element.removeAttributeNS(NS, this.name);                                                             // 179
    } else {                                                                                                  // 180
      element.setAttributeNS(NS, this.name, this.value);                                                      // 181
    }                                                                                                         // 182
  }                                                                                                           // 183
});                                                                                                           // 184
                                                                                                              // 185
// cross-browser version of `instanceof SVGElement`                                                           // 186
var isSVGElement = function (elem) {                                                                          // 187
  return 'ownerSVGElement' in elem;                                                                           // 188
};                                                                                                            // 189
                                                                                                              // 190
var isUrlAttribute = function (tagName, attrName) {                                                           // 191
  // Compiled from http://www.w3.org/TR/REC-html40/index/attributes.html                                      // 192
  // and                                                                                                      // 193
  // http://www.w3.org/html/wg/drafts/html/master/index.html#attributes-1                                     // 194
  var urlAttrs = {                                                                                            // 195
    FORM: ['action'],                                                                                         // 196
    BODY: ['background'],                                                                                     // 197
    BLOCKQUOTE: ['cite'],                                                                                     // 198
    Q: ['cite'],                                                                                              // 199
    DEL: ['cite'],                                                                                            // 200
    INS: ['cite'],                                                                                            // 201
    OBJECT: ['classid', 'codebase', 'data', 'usemap'],                                                        // 202
    APPLET: ['codebase'],                                                                                     // 203
    A: ['href'],                                                                                              // 204
    AREA: ['href'],                                                                                           // 205
    LINK: ['href'],                                                                                           // 206
    BASE: ['href'],                                                                                           // 207
    IMG: ['longdesc', 'src', 'usemap'],                                                                       // 208
    FRAME: ['longdesc', 'src'],                                                                               // 209
    IFRAME: ['longdesc', 'src'],                                                                              // 210
    HEAD: ['profile'],                                                                                        // 211
    SCRIPT: ['src'],                                                                                          // 212
    INPUT: ['src', 'usemap', 'formaction'],                                                                   // 213
    BUTTON: ['formaction'],                                                                                   // 214
    BASE: ['href'],                                                                                           // 215
    MENUITEM: ['icon'],                                                                                       // 216
    HTML: ['manifest'],                                                                                       // 217
    VIDEO: ['poster']                                                                                         // 218
  };                                                                                                          // 219
                                                                                                              // 220
  if (attrName === 'itemid') {                                                                                // 221
    return true;                                                                                              // 222
  }                                                                                                           // 223
                                                                                                              // 224
  var urlAttrNames = urlAttrs[tagName] || [];                                                                 // 225
  return _.contains(urlAttrNames, attrName);                                                                  // 226
};                                                                                                            // 227
                                                                                                              // 228
// To get the protocol for a URL, we let the browser normalize it for                                         // 229
// us, by setting it as the href for an anchor tag and then reading out                                       // 230
// the 'protocol' property.                                                                                   // 231
if (Meteor.isClient) {                                                                                        // 232
  var anchorForNormalization = document.createElement('A');                                                   // 233
}                                                                                                             // 234
                                                                                                              // 235
var getUrlProtocol = function (url) {                                                                         // 236
  if (Meteor.isClient) {                                                                                      // 237
    anchorForNormalization.href = url;                                                                        // 238
    return (anchorForNormalization.protocol || "").toLowerCase();                                             // 239
  } else {                                                                                                    // 240
    throw new Error('getUrlProtocol not implemented on the server');                                          // 241
  }                                                                                                           // 242
};                                                                                                            // 243
                                                                                                              // 244
// UrlHandler is an attribute handler for all HTML attributes that take                                       // 245
// URL values. It disallows javascript: URLs, unless                                                          // 246
// UI._allowJavascriptUrls() has been called. To detect javascript:                                           // 247
// urls, we set the attribute on a dummy anchor element and then read                                         // 248
// out the 'protocol' property of the attribute.                                                              // 249
var origUpdate = AttributeHandler.prototype.update;                                                           // 250
var UrlHandler = AttributeHandler.extend({                                                                    // 251
  update: function (element, oldValue, value) {                                                               // 252
    var self = this;                                                                                          // 253
    var args = arguments;                                                                                     // 254
                                                                                                              // 255
    if (UI._javascriptUrlsAllowed()) {                                                                        // 256
      origUpdate.apply(self, args);                                                                           // 257
    } else {                                                                                                  // 258
      var isJavascriptProtocol = (getUrlProtocol(value) === "javascript:");                                   // 259
      if (isJavascriptProtocol) {                                                                             // 260
        Meteor._debug("URLs that use the 'javascript:' protocol are not " +                                   // 261
                      "allowed in URL attribute values. " +                                                   // 262
                      "Call UI._allowJavascriptUrls() " +                                                     // 263
                      "to enable them.");                                                                     // 264
        origUpdate.apply(self, [element, oldValue, null]);                                                    // 265
      } else {                                                                                                // 266
        origUpdate.apply(self, args);                                                                         // 267
      }                                                                                                       // 268
    }                                                                                                         // 269
  }                                                                                                           // 270
});                                                                                                           // 271
                                                                                                              // 272
// XXX make it possible for users to register attribute handlers!                                             // 273
makeAttributeHandler = function (elem, name, value) {                                                         // 274
  // generally, use setAttribute but certain attributes need to be set                                        // 275
  // by directly setting a JavaScript property on the DOM element.                                            // 276
  if (name === 'class') {                                                                                     // 277
    if (isSVGElement(elem)) {                                                                                 // 278
      return new SVGClassHandler(name, value);                                                                // 279
    } else {                                                                                                  // 280
      return new ClassHandler(name, value);                                                                   // 281
    }                                                                                                         // 282
  } else if (name === 'style') {                                                                              // 283
    return new StyleHandler(name, value);                                                                     // 284
  } else if ((elem.tagName === 'OPTION' && name === 'selected') ||                                            // 285
             (elem.tagName === 'INPUT' && name === 'checked')) {                                              // 286
    return new BooleanHandler(name, value);                                                                   // 287
  } else if ((elem.tagName === 'TEXTAREA' || elem.tagName === 'INPUT')                                        // 288
             && name === 'value') {                                                                           // 289
    // internally, TEXTAREAs tracks their value in the 'value'                                                // 290
    // attribute just like INPUTs.                                                                            // 291
    return new ValueHandler(name, value);                                                                     // 292
  } else if (name.substring(0,6) === 'xlink:') {                                                              // 293
    return new XlinkHandler(name.substring(6), value);                                                        // 294
  } else if (isUrlAttribute(elem.tagName, name)) {                                                            // 295
    return new UrlHandler(name, value);                                                                       // 296
  } else {                                                                                                    // 297
    return new AttributeHandler(name, value);                                                                 // 298
  }                                                                                                           // 299
                                                                                                              // 300
  // XXX will need one for 'style' on IE, though modern browsers                                              // 301
  // seem to handle setAttribute ok.                                                                          // 302
};                                                                                                            // 303
                                                                                                              // 304
                                                                                                              // 305
ElementAttributesUpdater = function (elem) {                                                                  // 306
  this.elem = elem;                                                                                           // 307
  this.handlers = {};                                                                                         // 308
};                                                                                                            // 309
                                                                                                              // 310
// Update attributes on `elem` to the dictionary `attrs`, whose                                               // 311
// values are strings.                                                                                        // 312
ElementAttributesUpdater.prototype.update = function(newAttrs) {                                              // 313
  var elem = this.elem;                                                                                       // 314
  var handlers = this.handlers;                                                                               // 315
                                                                                                              // 316
  for (var k in handlers) {                                                                                   // 317
    if (! newAttrs.hasOwnProperty(k)) {                                                                       // 318
      // remove attributes (and handlers) for attribute names                                                 // 319
      // that don't exist as keys of `newAttrs` and so won't                                                  // 320
      // be visited when traversing it.  (Attributes that                                                     // 321
      // exist in the `newAttrs` object but are `null`                                                        // 322
      // are handled later.)                                                                                  // 323
      var handler = handlers[k];                                                                              // 324
      var oldValue = handler.value;                                                                           // 325
      handler.value = null;                                                                                   // 326
      handler.update(elem, oldValue, null);                                                                   // 327
      delete handlers[k];                                                                                     // 328
    }                                                                                                         // 329
  }                                                                                                           // 330
                                                                                                              // 331
  for (var k in newAttrs) {                                                                                   // 332
    var handler = null;                                                                                       // 333
    var oldValue;                                                                                             // 334
    var value = newAttrs[k];                                                                                  // 335
    if (! handlers.hasOwnProperty(k)) {                                                                       // 336
      if (value !== null) {                                                                                   // 337
        // make new handler                                                                                   // 338
        handler = makeAttributeHandler(elem, k, value);                                                       // 339
        handlers[k] = handler;                                                                                // 340
        oldValue = null;                                                                                      // 341
      }                                                                                                       // 342
    } else {                                                                                                  // 343
      handler = handlers[k];                                                                                  // 344
      oldValue = handler.value;                                                                               // 345
    }                                                                                                         // 346
    if (oldValue !== value) {                                                                                 // 347
      handler.value = value;                                                                                  // 348
      handler.update(elem, oldValue, value);                                                                  // 349
      if (value === null)                                                                                     // 350
        delete handlers[k];                                                                                   // 351
    }                                                                                                         // 352
  }                                                                                                           // 353
};                                                                                                            // 354
                                                                                                              // 355
////////////////////////////////////////////////////////////////////////////////////////////////////////////////

}).call(this);






(function () {

////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//                                                                                                            //
// packages/ui/render.js                                                                                      //
//                                                                                                            //
////////////////////////////////////////////////////////////////////////////////////////////////////////////////
                                                                                                              //
                                                                                                              // 1
UI.Component.instantiate = function (parent) {                                                                // 2
  var kind = this;                                                                                            // 3
                                                                                                              // 4
  // check arguments                                                                                          // 5
  if (UI.isComponent(kind)) {                                                                                 // 6
    if (kind.isInited)                                                                                        // 7
      throw new Error("A component kind is required, not an instance");                                       // 8
  } else {                                                                                                    // 9
    throw new Error("Expected Component kind");                                                               // 10
  }                                                                                                           // 11
                                                                                                              // 12
  var inst = kind.extend(); // XXX args go here                                                               // 13
  inst.isInited = true;                                                                                       // 14
                                                                                                              // 15
  // XXX messy to define this here                                                                            // 16
  inst.templateInstance = {                                                                                   // 17
    $: function(selector) {                                                                                   // 18
      // XXX check that `.dom` exists here?                                                                   // 19
      return inst.dom.$(selector);                                                                            // 20
    },                                                                                                        // 21
    findAll: function (selector) {                                                                            // 22
      return $.makeArray(this.$(selector));                                                                   // 23
    },                                                                                                        // 24
    find: function (selector) {                                                                               // 25
      var result = this.$(selector);                                                                          // 26
      return result[0] || null;                                                                               // 27
    },                                                                                                        // 28
    firstNode: null,                                                                                          // 29
    lastNode: null,                                                                                           // 30
    data: null,                                                                                               // 31
    __component__: inst                                                                                       // 32
  };                                                                                                          // 33
                                                                                                              // 34
  inst.parent = (parent || null);                                                                             // 35
                                                                                                              // 36
  if (inst.init)                                                                                              // 37
    inst.init();                                                                                              // 38
                                                                                                              // 39
  if (inst.created) {                                                                                         // 40
    updateTemplateInstance(inst);                                                                             // 41
    inst.created.call(inst.templateInstance);                                                                 // 42
  }                                                                                                           // 43
                                                                                                              // 44
  return inst;                                                                                                // 45
};                                                                                                            // 46
                                                                                                              // 47
UI.Component.render = function () {                                                                           // 48
  return null;                                                                                                // 49
};                                                                                                            // 50
                                                                                                              // 51
var Box = function (func, equals) {                                                                           // 52
  var self = this;                                                                                            // 53
                                                                                                              // 54
  self.func = func;                                                                                           // 55
  self.equals = equals;                                                                                       // 56
                                                                                                              // 57
  self.curResult = null;                                                                                      // 58
                                                                                                              // 59
  self.dep = new Deps.Dependency;                                                                             // 60
                                                                                                              // 61
  self.resultComputation = Deps.nonreactive(function () {                                                     // 62
    return Deps.autorun(function (c) {                                                                        // 63
      var func = self.func;                                                                                   // 64
                                                                                                              // 65
      var newResult = func();                                                                                 // 66
                                                                                                              // 67
      if (! c.firstRun) {                                                                                     // 68
        var equals = self.equals;                                                                             // 69
        var oldResult = self.curResult;                                                                       // 70
                                                                                                              // 71
        if (equals ? equals(newResult, oldResult) :                                                           // 72
            newResult === oldResult) {                                                                        // 73
          // same as last time                                                                                // 74
          return;                                                                                             // 75
        }                                                                                                     // 76
      }                                                                                                       // 77
                                                                                                              // 78
      self.curResult = newResult;                                                                             // 79
      self.dep.changed();                                                                                     // 80
    });                                                                                                       // 81
  });                                                                                                         // 82
};                                                                                                            // 83
                                                                                                              // 84
Box.prototype.stop = function () {                                                                            // 85
  this.resultComputation.stop();                                                                              // 86
};                                                                                                            // 87
                                                                                                              // 88
Box.prototype.get = function () {                                                                             // 89
  if (Deps.active && ! this.resultComputation.stopped)                                                        // 90
    this.dep.depend();                                                                                        // 91
                                                                                                              // 92
  return this.curResult;                                                                                      // 93
};                                                                                                            // 94
                                                                                                              // 95
// Takes a reactive function (call it `inner`) and returns a reactive function                                // 96
// `outer` which is equivalent except in its reactive behavior.  Specifically,                                // 97
// `outer` has the following two special properties:                                                          // 98
//                                                                                                            // 99
// 1. Isolation:  An invocation of `outer()` only invalidates its context                                     // 100
//    when the value of `inner()` changes.  For example, `inner` may be a                                     // 101
//    function that gets one or more Session variables and calculates a                                       // 102
//    true/false value.  `outer` blocks invalidation signals caused by the                                    // 103
//    Session variables changing and sends a signal out only when the value                                   // 104
//    changes between true and false (in this example).  The value can be                                     // 105
//    of any type, and it is compared with `===` unless an `equals` function                                  // 106
//    is provided.                                                                                            // 107
//                                                                                                            // 108
// 2. Value Sharing:  The `outer` function returned by `emboxValue` can be                                    // 109
//    shared between different contexts, for example by assigning it to an                                    // 110
//    object as a method that can be accessed at any time, such as by                                         // 111
//    different templates or different parts of a template.  No matter                                        // 112
//    how many times `outer` is called, `inner` is only called once until                                     // 113
//    it changes.  The most recent value is stored internally.                                                // 114
//                                                                                                            // 115
// Conceptually, an emboxed value is much like a Session variable which is                                    // 116
// kept up to date by an autorun.  Session variables provide storage                                          // 117
// (value sharing) and they don't notify their listeners unless a value                                       // 118
// actually changes (isolation).  The biggest difference is that such an                                      // 119
// autorun would never be stopped, and the Session variable would never be                                    // 120
// deleted even if it wasn't used any more.  An emboxed value, on the other                                   // 121
// hand, automatically stops computing when it's not being used, and starts                                   // 122
// again when called from a reactive context.  This means that when it stops                                  // 123
// being used, it can be completely garbage-collected.                                                        // 124
//                                                                                                            // 125
// If a non-function value is supplied to `emboxValue` instead of a reactive                                  // 126
// function, then `outer` is still a function but it simply returns the value.                                // 127
//                                                                                                            // 128
UI.emboxValue = function (funcOrValue, equals) {                                                              // 129
  if (typeof funcOrValue === 'function') {                                                                    // 130
                                                                                                              // 131
    var func = funcOrValue;                                                                                   // 132
    var box = new Box(func, equals);                                                                          // 133
                                                                                                              // 134
    var f = function () {                                                                                     // 135
      return box.get();                                                                                       // 136
    };                                                                                                        // 137
                                                                                                              // 138
    f.stop = function () {                                                                                    // 139
      box.stop();                                                                                             // 140
    };                                                                                                        // 141
                                                                                                              // 142
    return f;                                                                                                 // 143
                                                                                                              // 144
  } else {                                                                                                    // 145
    var value = funcOrValue;                                                                                  // 146
    var result = function () {                                                                                // 147
      return value;                                                                                           // 148
    };                                                                                                        // 149
    result._isEmboxedConstant = true;                                                                         // 150
    return result;                                                                                            // 151
  }                                                                                                           // 152
};                                                                                                            // 153
                                                                                                              // 154
                                                                                                              // 155
UI.namedEmboxValue = function (name, funcOrValue, equals) {                                                   // 156
  if (! Deps.active) {                                                                                        // 157
    var f = UI.emboxValue(funcOrValue, equals);                                                               // 158
    f.stop();                                                                                                 // 159
    return f;                                                                                                 // 160
  }                                                                                                           // 161
                                                                                                              // 162
  var c = Deps.currentComputation;                                                                            // 163
  if (! c[name])                                                                                              // 164
    c[name] = UI.emboxValue(funcOrValue, equals);                                                             // 165
                                                                                                              // 166
  return c[name];                                                                                             // 167
};                                                                                                            // 168
                                                                                                              // 169
////////////////////////////////////////                                                                      // 170
                                                                                                              // 171
UI.insert = function (renderedTemplate, parentElement, nextNode) {                                            // 172
  if (! renderedTemplate.dom)                                                                                 // 173
    throw new Error("Expected template rendered with UI.render");                                             // 174
                                                                                                              // 175
  UI.DomRange.insert(renderedTemplate.dom, parentElement, nextNode);                                          // 176
};                                                                                                            // 177
                                                                                                              // 178
// Insert a DOM node or DomRange into a DOM element or DomRange.                                              // 179
//                                                                                                            // 180
// One of three things happens depending on what needs to be inserted into what:                              // 181
// - `range.add` (anything into DomRange)                                                                     // 182
// - `UI.DomRange.insert` (DomRange into element)                                                             // 183
// - `elem.insertBefore` (node into element)                                                                  // 184
//                                                                                                            // 185
// The optional `before` argument is an existing node or id to insert before in                               // 186
// the parent element or DomRange.                                                                            // 187
var insert = function (nodeOrRange, parent, before) {                                                         // 188
  if (! parent)                                                                                               // 189
    throw new Error("Materialization parent required");                                                       // 190
                                                                                                              // 191
  if (parent instanceof UI.DomRange) {                                                                        // 192
    parent.add(nodeOrRange, before);                                                                          // 193
  } else if (nodeOrRange instanceof UI.DomRange) {                                                            // 194
    // parent is an element; inserting a range                                                                // 195
    UI.DomRange.insert(nodeOrRange, parent, before);                                                          // 196
  } else {                                                                                                    // 197
    // parent is an element; inserting an element                                                             // 198
    parent.insertBefore(nodeOrRange, before || null); // `null` for IE                                        // 199
  }                                                                                                           // 200
};                                                                                                            // 201
                                                                                                              // 202
// options include:                                                                                           // 203
//   - _nestInCurrentComputation: defaults to false. If true, then                                            // 204
//     `render`'s autoruns will be nested inside the current                                                  // 205
//     computation, so if the current computation is invalidated, then                                        // 206
//     the autoruns set up inside `render` will be stopped. If false,                                         // 207
//     the autoruns will be set up in a fresh Deps context, so                                                // 208
//     invalidating the current computation will have no effect on them.                                      // 209
UI.render = function (kind, parentComponent, options) {                                                       // 210
  options = options || {};                                                                                    // 211
                                                                                                              // 212
  if (kind.isInited)                                                                                          // 213
    throw new Error("Can't render component instance, only component kind");                                  // 214
                                                                                                              // 215
  var inst, content, range;                                                                                   // 216
                                                                                                              // 217
  Deps.nonreactive(function () {                                                                              // 218
                                                                                                              // 219
    inst = kind.instantiate(parentComponent);                                                                 // 220
                                                                                                              // 221
    content = (inst.render && inst.render());                                                                 // 222
                                                                                                              // 223
    range = new UI.DomRange;                                                                                  // 224
    inst.dom = range;                                                                                         // 225
    range.component = inst;                                                                                   // 226
                                                                                                              // 227
    if (! options._nestInCurrentComputation) {                                                                // 228
      materialize(content, range, null, inst);                                                                // 229
    }                                                                                                         // 230
                                                                                                              // 231
  });                                                                                                         // 232
                                                                                                              // 233
  if (options._nestInCurrentComputation) {                                                                    // 234
    materialize(content, range, null, inst);                                                                  // 235
  }                                                                                                           // 236
                                                                                                              // 237
  range.removed = function () {                                                                               // 238
    inst.isDestroyed = true;                                                                                  // 239
    if (inst.destroyed) {                                                                                     // 240
      Deps.nonreactive(function () {                                                                          // 241
        updateTemplateInstance(inst);                                                                         // 242
        inst.destroyed.call(inst.templateInstance);                                                           // 243
      });                                                                                                     // 244
    }                                                                                                         // 245
  };                                                                                                          // 246
                                                                                                              // 247
  return inst;                                                                                                // 248
};                                                                                                            // 249
                                                                                                              // 250
// options are the same as for UI.render.                                                                     // 251
UI.renderWithData = function (kind, data, parentComponent, options) {                                         // 252
  if (! UI.isComponent(kind))                                                                                 // 253
    throw new Error("Component required here");                                                               // 254
  if (kind.isInited)                                                                                          // 255
    throw new Error("Can't render component instance, only component kind");                                  // 256
  if (typeof data === 'function')                                                                             // 257
    throw new Error("Data argument can't be a function");                                                     // 258
                                                                                                              // 259
  return UI.render(kind.extend({data: function () { return data; }}),                                         // 260
                   parentComponent, options);                                                                 // 261
};                                                                                                            // 262
                                                                                                              // 263
var contentEquals = function (a, b) {                                                                         // 264
  if (a instanceof HTML.Raw) {                                                                                // 265
    return (b instanceof HTML.Raw) && (a.value === b.value);                                                  // 266
  } else if (a == null) {                                                                                     // 267
    return (b == null);                                                                                       // 268
  } else {                                                                                                    // 269
    return (a === b) &&                                                                                       // 270
      ((typeof a === 'number') || (typeof a === 'boolean') ||                                                 // 271
       (typeof a === 'string'));                                                                              // 272
  }                                                                                                           // 273
};                                                                                                            // 274
                                                                                                              // 275
UI.InTemplateScope = function (tmplInstance, content) {                                                       // 276
  if (! (this instanceof UI.InTemplateScope))                                                                 // 277
    // called without `new`                                                                                   // 278
    return new UI.InTemplateScope(tmplInstance, content);                                                     // 279
                                                                                                              // 280
  var parentPtr = tmplInstance.parent;                                                                        // 281
  if (parentPtr.__isTemplateWith)                                                                             // 282
    parentPtr = parentPtr.parent;                                                                             // 283
                                                                                                              // 284
  this.parentPtr = parentPtr;                                                                                 // 285
  this.content = content;                                                                                     // 286
};                                                                                                            // 287
                                                                                                              // 288
UI.InTemplateScope.prototype.toHTML = function (parentComponent) {                                            // 289
  return HTML.toHTML(this.content, this.parentPtr);                                                           // 290
};                                                                                                            // 291
                                                                                                              // 292
UI.InTemplateScope.prototype.toText = function (textMode, parentComponent) {                                  // 293
  return HTML.toText(this.content, textMode, this.parentPtr);                                                 // 294
};                                                                                                            // 295
                                                                                                              // 296
// Convert the pseudoDOM `node` into reactive DOM nodes and insert them                                       // 297
// into the element or DomRange `parent`, before the node or id `before`.                                     // 298
var materialize = function (node, parent, before, parentComponent) {                                          // 299
  // XXX should do more error-checking for the case where user is supplying the tags.                         // 300
  // For example, check that CharRef has `html` and `str` properties and no content.                          // 301
  // Check that Comment has a single string child and no attributes.  Etc.                                    // 302
                                                                                                              // 303
  if (node == null) {                                                                                         // 304
    // null or undefined.                                                                                     // 305
    // do nothinge.                                                                                           // 306
  } else if ((typeof node === 'string') || (typeof node === 'boolean') || (typeof node === 'number')) {       // 307
    node = String(node);                                                                                      // 308
    insert(document.createTextNode(node), parent, before);                                                    // 309
  } else if (node instanceof Array) {                                                                         // 310
    for (var i = 0; i < node.length; i++)                                                                     // 311
      materialize(node[i], parent, before, parentComponent);                                                  // 312
  } else if (typeof node === 'function') {                                                                    // 313
                                                                                                              // 314
    var range = new UI.DomRange;                                                                              // 315
    var lastContent = null;                                                                                   // 316
    var rangeUpdater = Deps.autorun(function (c) {                                                            // 317
      var content = node();                                                                                   // 318
      // normalize content a little, for easier comparison                                                    // 319
      if (HTML.isNully(content))                                                                              // 320
        content = null;                                                                                       // 321
      else if ((content instanceof Array) && content.length === 1)                                            // 322
        content = content[0];                                                                                 // 323
                                                                                                              // 324
      // update if content is different from last time                                                        // 325
      if (! contentEquals(content, lastContent)) {                                                            // 326
        lastContent = content;                                                                                // 327
                                                                                                              // 328
        if (! c.firstRun)                                                                                     // 329
          range.removeAll();                                                                                  // 330
                                                                                                              // 331
        materialize(content, range, null, parentComponent);                                                   // 332
      }                                                                                                       // 333
    });                                                                                                       // 334
    range.removed = function () {                                                                             // 335
      rangeUpdater.stop();                                                                                    // 336
      if (node.stop)                                                                                          // 337
        node.stop();                                                                                          // 338
    };                                                                                                        // 339
    // XXXX HACK                                                                                              // 340
    if (Deps.active && node.stop) {                                                                           // 341
      Deps.onInvalidate(function () {                                                                         // 342
        node.stop();                                                                                          // 343
      });                                                                                                     // 344
    }                                                                                                         // 345
    insert(range, parent, before);                                                                            // 346
  } else if (node instanceof HTML.Tag) {                                                                      // 347
    var tagName = node.tagName;                                                                               // 348
    var elem;                                                                                                 // 349
    if (HTML.isKnownSVGElement(tagName) && document.createElementNS) {                                        // 350
      elem = document.createElementNS('http://www.w3.org/2000/svg', tagName);                                 // 351
    } else {                                                                                                  // 352
      elem = document.createElement(node.tagName);                                                            // 353
    }                                                                                                         // 354
                                                                                                              // 355
    var rawAttrs = node.attrs;                                                                                // 356
    var children = node.children;                                                                             // 357
    if (node.tagName === 'textarea') {                                                                        // 358
      rawAttrs = (rawAttrs || {});                                                                            // 359
      rawAttrs.value = children;                                                                              // 360
      children = [];                                                                                          // 361
    };                                                                                                        // 362
                                                                                                              // 363
    if (rawAttrs) {                                                                                           // 364
      var attrComp = Deps.autorun(function (c) {                                                              // 365
        var attrUpdater = c.updater;                                                                          // 366
        if (! attrUpdater) {                                                                                  // 367
          attrUpdater = c.updater = new ElementAttributesUpdater(elem);                                       // 368
        }                                                                                                     // 369
                                                                                                              // 370
        try {                                                                                                 // 371
          var attrs = HTML.evaluateAttributes(rawAttrs, parentComponent);                                     // 372
          var stringAttrs = {};                                                                               // 373
          if (attrs) {                                                                                        // 374
            for (var k in attrs) {                                                                            // 375
              stringAttrs[k] = HTML.toText(attrs[k], HTML.TEXTMODE.STRING,                                    // 376
                                           parentComponent);                                                  // 377
            }                                                                                                 // 378
            attrUpdater.update(stringAttrs);                                                                  // 379
          }                                                                                                   // 380
        } catch (e) {                                                                                         // 381
          reportUIException(e);                                                                               // 382
        }                                                                                                     // 383
      });                                                                                                     // 384
      UI.DomBackend.onElementTeardown(elem, function () {                                                     // 385
        attrComp.stop();                                                                                      // 386
      });                                                                                                     // 387
    }                                                                                                         // 388
    materialize(children, elem, null, parentComponent);                                                       // 389
                                                                                                              // 390
    insert(elem, parent, before);                                                                             // 391
  } else if (typeof node.instantiate === 'function') {                                                        // 392
    // component                                                                                              // 393
    var instance = UI.render(node, parentComponent, {                                                         // 394
      _nestInCurrentComputation: true                                                                         // 395
    });                                                                                                       // 396
                                                                                                              // 397
    // Call internal callback, which may take advantage of the current                                        // 398
    // Deps computation.                                                                                      // 399
    if (instance.materialized)                                                                                // 400
      instance.materialized(instance.dom);                                                                    // 401
                                                                                                              // 402
    insert(instance.dom, parent, before);                                                                     // 403
  } else if (node instanceof HTML.CharRef) {                                                                  // 404
    insert(document.createTextNode(node.str), parent, before);                                                // 405
  } else if (node instanceof HTML.Comment) {                                                                  // 406
    insert(document.createComment(node.sanitizedValue), parent, before);                                      // 407
  } else if (node instanceof HTML.Raw) {                                                                      // 408
    // Get an array of DOM nodes by using the browser's HTML parser                                           // 409
    // (like innerHTML).                                                                                      // 410
    var htmlNodes = UI.DomBackend.parseHTML(node.value);                                                      // 411
    for (var i = 0; i < htmlNodes.length; i++)                                                                // 412
      insert(htmlNodes[i], parent, before);                                                                   // 413
  } else if (Package['html-tools'] && (node instanceof Package['html-tools'].HTMLTools.Special)) {            // 414
    throw new Error("Can't materialize Special tag, it's just an intermediate rep");                          // 415
  } else if (node instanceof UI.InTemplateScope) {                                                            // 416
    materialize(node.content, parent, before, node.parentPtr);                                                // 417
  } else {                                                                                                    // 418
    // can't get here                                                                                         // 419
    throw new Error("Unexpected node in htmljs: " + node);                                                    // 420
  }                                                                                                           // 421
};                                                                                                            // 422
                                                                                                              // 423
                                                                                                              // 424
                                                                                                              // 425
// XXX figure out the right names, and namespace, for these.                                                  // 426
// for example, maybe some of them go in the HTML package.                                                    // 427
UI.materialize = materialize;                                                                                 // 428
                                                                                                              // 429
UI.body = UI.Component.extend({                                                                               // 430
  kind: 'body',                                                                                               // 431
  contentParts: [],                                                                                           // 432
  render: function () {                                                                                       // 433
    return this.contentParts;                                                                                 // 434
  },                                                                                                          // 435
  // XXX revisit how body works.                                                                              // 436
  INSTANTIATED: false,                                                                                        // 437
  __helperHost: true                                                                                          // 438
});                                                                                                           // 439
                                                                                                              // 440
UI.block = function (renderFunc) {                                                                            // 441
  return UI.Component.extend({ render: renderFunc });                                                         // 442
};                                                                                                            // 443
                                                                                                              // 444
UI.toHTML = function (content, parentComponent) {                                                             // 445
  return HTML.toHTML(content, parentComponent);                                                               // 446
};                                                                                                            // 447
                                                                                                              // 448
UI.toRawText = function (content, parentComponent) {                                                          // 449
  return HTML.toText(content, HTML.TEXTMODE.STRING, parentComponent);                                         // 450
};                                                                                                            // 451
                                                                                                              // 452
////////////////////////////////////////////////////////////////////////////////////////////////////////////////

}).call(this);






(function () {

////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//                                                                                                            //
// packages/ui/builtins.js                                                                                    //
//                                                                                                            //
////////////////////////////////////////////////////////////////////////////////////////////////////////////////
                                                                                                              //
                                                                                                              // 1
UI.If = function (argFunc, contentBlock, elseContentBlock) {                                                  // 2
  checkBlockHelperArguments('If', argFunc, contentBlock, elseContentBlock);                                   // 3
                                                                                                              // 4
  var f = function () {                                                                                       // 5
    var emboxedCondition = emboxCondition(argFunc);                                                           // 6
    f.stop = function () {                                                                                    // 7
      emboxedCondition.stop();                                                                                // 8
    };                                                                                                        // 9
    if (emboxedCondition())                                                                                   // 10
      return contentBlock;                                                                                    // 11
    else                                                                                                      // 12
      return elseContentBlock || null;                                                                        // 13
  };                                                                                                          // 14
                                                                                                              // 15
  return f;                                                                                                   // 16
};                                                                                                            // 17
                                                                                                              // 18
                                                                                                              // 19
UI.Unless = function (argFunc, contentBlock, elseContentBlock) {                                              // 20
  checkBlockHelperArguments('Unless', argFunc, contentBlock, elseContentBlock);                               // 21
                                                                                                              // 22
  var f = function () {                                                                                       // 23
    var emboxedCondition = emboxCondition(argFunc);                                                           // 24
    f.stop = function () {                                                                                    // 25
      emboxedCondition.stop();                                                                                // 26
    };                                                                                                        // 27
    if (! emboxedCondition())                                                                                 // 28
      return contentBlock;                                                                                    // 29
    else                                                                                                      // 30
      return elseContentBlock || null;                                                                        // 31
  };                                                                                                          // 32
                                                                                                              // 33
  return f;                                                                                                   // 34
};                                                                                                            // 35
                                                                                                              // 36
// Returns true if `a` and `b` are `===`, unless they are of a mutable type.                                  // 37
// (Because then, they may be equal references to an object that was mutated,                                 // 38
// and we'll never know.  We save only a reference to the old object; we don't                                // 39
// do any deep-copying or diffing.)                                                                           // 40
UI.safeEquals = function (a, b) {                                                                             // 41
  if (a !== b)                                                                                                // 42
    return false;                                                                                             // 43
  else                                                                                                        // 44
    return ((!a) || (typeof a === 'number') || (typeof a === 'boolean') ||                                    // 45
            (typeof a === 'string'));                                                                         // 46
};                                                                                                            // 47
                                                                                                              // 48
// Unlike Spacebars.With, there's no else case and no conditional logic.                                      // 49
//                                                                                                            // 50
// We don't do any reactive emboxing of `argFunc` here; it should be done                                     // 51
// by the caller if efficiency and/or number of calls to the data source                                      // 52
// is important.                                                                                              // 53
UI.With = function (argFunc, contentBlock) {                                                                  // 54
  checkBlockHelperArguments('With', argFunc, contentBlock);                                                   // 55
                                                                                                              // 56
  var block = contentBlock;                                                                                   // 57
  if ('data' in block) {                                                                                      // 58
    // XXX TODO: get religion about where `data` property goes                                                // 59
    block = UI.block(function () {                                                                            // 60
      return contentBlock;                                                                                    // 61
    });                                                                                                       // 62
  }                                                                                                           // 63
                                                                                                              // 64
  block.data = function () {                                                                                  // 65
    throw new Error("Can't get data for component kind");                                                     // 66
  };                                                                                                          // 67
                                                                                                              // 68
  block.init = function () {                                                                                  // 69
    this.data = UI.emboxValue(argFunc, UI.safeEquals);                                                        // 70
  };                                                                                                          // 71
                                                                                                              // 72
  block.materialized = function () {                                                                          // 73
    var self = this;                                                                                          // 74
    if (Deps.active) {                                                                                        // 75
      Deps.onInvalidate(function () {                                                                         // 76
        self.data.stop();                                                                                     // 77
      });                                                                                                     // 78
    }                                                                                                         // 79
  };                                                                                                          // 80
  block.materialized.isWith = true;                                                                           // 81
                                                                                                              // 82
  return block;                                                                                               // 83
};                                                                                                            // 84
                                                                                                              // 85
UI.Each = function (argFunc, contentBlock, elseContentBlock) {                                                // 86
  checkBlockHelperArguments('Each', argFunc, contentBlock, elseContentBlock);                                 // 87
                                                                                                              // 88
  return UI.EachImpl.extend({                                                                                 // 89
    __sequence: argFunc,                                                                                      // 90
    __content: contentBlock,                                                                                  // 91
    __elseContent: elseContentBlock                                                                           // 92
  });                                                                                                         // 93
};                                                                                                            // 94
                                                                                                              // 95
var checkBlockHelperArguments = function (which, argFunc, contentBlock, elseContentBlock) {                   // 96
  if (typeof argFunc !== 'function')                                                                          // 97
    throw new Error('First argument to ' + which + ' must be a function');                                    // 98
  if (! UI.isComponent(contentBlock))                                                                         // 99
    throw new Error('Second argument to ' + which + ' must be a template or UI.block');                       // 100
  if (elseContentBlock && ! UI.isComponent(elseContentBlock))                                                 // 101
    throw new Error('Third argument to ' + which + ' must be a template or UI.block if present');             // 102
};                                                                                                            // 103
                                                                                                              // 104
// Returns a function that computes `!! conditionFunc()` except:                                              // 105
//                                                                                                            // 106
// - Empty array is considered falsy                                                                          // 107
// - The result is UI.emboxValue'd (doesn't trigger invalidation                                              // 108
//   as long as the condition stays truthy or stays falsy)                                                    // 109
var emboxCondition = function (conditionFunc) {                                                               // 110
  return UI.namedEmboxValue('if/unless', function () {                                                        // 111
    // `condition` is emboxed; it is always a function,                                                       // 112
    // and it only triggers invalidation if its return                                                        // 113
    // value actually changes.  We still need to isolate                                                      // 114
    // the calculation of whether it is truthy or falsy                                                       // 115
    // in order to not re-render if it changes from one                                                       // 116
    // truthy or falsy value to another.                                                                      // 117
    var cond = conditionFunc();                                                                               // 118
                                                                                                              // 119
    // empty arrays are treated as falsey values                                                              // 120
    if (cond instanceof Array && cond.length === 0)                                                           // 121
      return false;                                                                                           // 122
    else                                                                                                      // 123
      return !! cond;                                                                                         // 124
  });                                                                                                         // 125
};                                                                                                            // 126
                                                                                                              // 127
////////////////////////////////////////////////////////////////////////////////////////////////////////////////

}).call(this);






(function () {

////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//                                                                                                            //
// packages/ui/each.js                                                                                        //
//                                                                                                            //
////////////////////////////////////////////////////////////////////////////////////////////////////////////////
                                                                                                              //
UI.EachImpl = Component.extend({                                                                              // 1
  typeName: 'Each',                                                                                           // 2
  render: function (modeHint) {                                                                               // 3
    var self = this;                                                                                          // 4
    var content = self.__content;                                                                             // 5
    var elseContent = self.__elseContent;                                                                     // 6
                                                                                                              // 7
    if (modeHint === 'STATIC') {                                                                              // 8
      // This is a hack.  The caller gives us a hint if the                                                   // 9
      // value we return will be static (in HTML or text)                                                     // 10
      // or dynamic (materialized DOM).  The dynamic path                                                     // 11
      // returns `null` and then we populate the DOM from                                                     // 12
      // the `materialized` callback.                                                                         // 13
      //                                                                                                      // 14
      // It would be much cleaner to always return the same                                                   // 15
      // value here, and to have that value be some special                                                   // 16
      // object that encapsulates the logic for populating                                                    // 17
      // the #each using a mode-agnostic interface that                                                       // 18
      // works for HTML, text, and DOM.  Alternatively, we                                                    // 19
      // could formalize the current pattern, e.g. defining                                                   // 20
      // a method like component.populate(domRange) and one                                                   // 21
      // like renderStatic() or even renderHTML / renderText.                                                 // 22
      var parts = _.map(                                                                                      // 23
        ObserveSequence.fetch(self.__sequence()),                                                             // 24
        function (item) {                                                                                     // 25
          return content.extend({data: function () {                                                          // 26
            return item;                                                                                      // 27
          }});                                                                                                // 28
        });                                                                                                   // 29
                                                                                                              // 30
      if (parts.length) {                                                                                     // 31
        return parts;                                                                                         // 32
      } else {                                                                                                // 33
        return elseContent;                                                                                   // 34
      }                                                                                                       // 35
      return parts;                                                                                           // 36
    } else {                                                                                                  // 37
      return null;                                                                                            // 38
    }                                                                                                         // 39
  },                                                                                                          // 40
  materialized: function () {                                                                                 // 41
    var self = this;                                                                                          // 42
                                                                                                              // 43
    var range = self.dom;                                                                                     // 44
                                                                                                              // 45
    var content = self.__content;                                                                             // 46
    var elseContent = self.__elseContent;                                                                     // 47
                                                                                                              // 48
    // if there is an else clause, keep track of the number of                                                // 49
    // rendered items.  use this to display the else clause when count                                        // 50
    // becomes zero, and remove it when count becomes positive.                                               // 51
    var itemCount = 0;                                                                                        // 52
    var addToCount = function(delta) {                                                                        // 53
      if (!elseContent) // if no else, no need to keep track of count                                         // 54
        return;                                                                                               // 55
                                                                                                              // 56
      if (itemCount + delta < 0)                                                                              // 57
        throw new Error("count should never become negative");                                                // 58
                                                                                                              // 59
      if (itemCount === 0) {                                                                                  // 60
        // remove else clause                                                                                 // 61
        range.removeAll();                                                                                    // 62
      }                                                                                                       // 63
      itemCount += delta;                                                                                     // 64
      if (itemCount === 0) {                                                                                  // 65
        UI.materialize(elseContent, range, null, self);                                                       // 66
      }                                                                                                       // 67
    };                                                                                                        // 68
                                                                                                              // 69
    this.observeHandle = ObserveSequence.observe(function () {                                                // 70
      return self.__sequence();                                                                               // 71
    }, {                                                                                                      // 72
      addedAt: function (id, item, i, beforeId) {                                                             // 73
        addToCount(1);                                                                                        // 74
        id = LocalCollection._idStringify(id);                                                                // 75
                                                                                                              // 76
        var data = item;                                                                                      // 77
        var dep = new Deps.Dependency;                                                                        // 78
                                                                                                              // 79
        // function to become `comp.data`                                                                     // 80
        var dataFunc = function () {                                                                          // 81
          dep.depend();                                                                                       // 82
          return data;                                                                                        // 83
        };                                                                                                    // 84
        // Storing `$set` on `comp.data` lets us                                                              // 85
        // access it from `changed`.                                                                          // 86
        dataFunc.$set = function (v) {                                                                        // 87
          data = v;                                                                                           // 88
          dep.changed();                                                                                      // 89
        };                                                                                                    // 90
                                                                                                              // 91
        if (beforeId)                                                                                         // 92
          beforeId = LocalCollection._idStringify(beforeId);                                                  // 93
                                                                                                              // 94
        var renderedItem = UI.render(content.extend({data: dataFunc}), self);                                 // 95
        range.add(id, renderedItem.dom, beforeId);                                                            // 96
      },                                                                                                      // 97
      removedAt: function (id, item) {                                                                        // 98
        addToCount(-1);                                                                                       // 99
        range.remove(LocalCollection._idStringify(id));                                                       // 100
      },                                                                                                      // 101
      movedTo: function (id, item, i, j, beforeId) {                                                          // 102
        range.moveBefore(                                                                                     // 103
          LocalCollection._idStringify(id),                                                                   // 104
          beforeId && LocalCollection._idStringify(beforeId));                                                // 105
      },                                                                                                      // 106
      changedAt: function (id, newItem, atIndex) {                                                            // 107
        range.get(LocalCollection._idStringify(id)).component.data.$set(newItem);                             // 108
      }                                                                                                       // 109
    });                                                                                                       // 110
                                                                                                              // 111
    // on initial render, display the else clause if no items                                                 // 112
    addToCount(0);                                                                                            // 113
  },                                                                                                          // 114
  destroyed: function () {                                                                                    // 115
    if (this.__component__.observeHandle)                                                                     // 116
      this.__component__.observeHandle.stop();                                                                // 117
  }                                                                                                           // 118
});                                                                                                           // 119
                                                                                                              // 120
////////////////////////////////////////////////////////////////////////////////////////////////////////////////

}).call(this);






(function () {

////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//                                                                                                            //
// packages/ui/fields.js                                                                                      //
//                                                                                                            //
////////////////////////////////////////////////////////////////////////////////////////////////////////////////
                                                                                                              //
                                                                                                              // 1
var global = (function () { return this; })();                                                                // 2
                                                                                                              // 3
currentComponent = new Meteor.EnvironmentVariable();                                                          // 4
                                                                                                              // 5
// Searches for the given property in `comp` or a parent,                                                     // 6
// and returns it as is (without call it if it's a function).                                                 // 7
var lookupComponentProp = function (comp, prop) {                                                             // 8
  comp = findComponentWithProp(prop, comp);                                                                   // 9
  var result = (comp ? comp.data : null);                                                                     // 10
  if (typeof result === 'function')                                                                           // 11
    result = _.bind(result, comp);                                                                            // 12
  return result;                                                                                              // 13
};                                                                                                            // 14
                                                                                                              // 15
// Component that's a no-op when used as a block helper like                                                  // 16
// `{{#foo}}...{{/foo}}`. Prints a warning that it is deprecated.                                             // 17
var noOpComponent = function (name) {                                                                         // 18
  return Component.extend({                                                                                   // 19
    kind: 'NoOp',                                                                                             // 20
    render: function () {                                                                                     // 21
      Meteor._debug("{{#" + name + "}} is now unnecessary and deprecated.");                                  // 22
      return this.__content;                                                                                  // 23
    }                                                                                                         // 24
  });                                                                                                         // 25
};                                                                                                            // 26
                                                                                                              // 27
// This map is searched first when you do something like `{{#foo}}` in                                        // 28
// a template.                                                                                                // 29
var builtInComponents = {                                                                                     // 30
  // for past compat:                                                                                         // 31
  'constant': noOpComponent("constant"),                                                                      // 32
  'isolate': noOpComponent("isolate")                                                                         // 33
};                                                                                                            // 34
                                                                                                              // 35
_extend(UI.Component, {                                                                                       // 36
  // Options:                                                                                                 // 37
  //                                                                                                          // 38
  // - template {Boolean} If true, look at the list of templates after                                        // 39
  //   helpers and before data context.                                                                       // 40
  lookup: function (id, opts) {                                                                               // 41
    var self = this;                                                                                          // 42
    var template = opts && opts.template;                                                                     // 43
    var result;                                                                                               // 44
    var comp;                                                                                                 // 45
                                                                                                              // 46
    if (!id)                                                                                                  // 47
      throw new Error("must pass id to lookup");                                                              // 48
                                                                                                              // 49
    if (/^\./.test(id)) {                                                                                     // 50
      // starts with a dot. must be a series of dots which maps to an                                         // 51
      // ancestor of the appropriate height.                                                                  // 52
      if (!/^(\.)+$/.test(id)) {                                                                              // 53
        throw new Error("id starting with dot must be a series of dots");                                     // 54
      }                                                                                                       // 55
                                                                                                              // 56
      var compWithData = findComponentWithProp('data', self);                                                 // 57
      for (var i = 1; i < id.length; i++) {                                                                   // 58
        compWithData = compWithData ? findComponentWithProp('data', compWithData.parent) : null;              // 59
      }                                                                                                       // 60
                                                                                                              // 61
      return (compWithData ? compWithData.data : null);                                                       // 62
                                                                                                              // 63
    } else if ((comp = findComponentWithHelper(id, self))) {                                                  // 64
      // found a property or method of a component                                                            // 65
      // (`self` or one of its ancestors)                                                                     // 66
      var result = comp[id];                                                                                  // 67
                                                                                                              // 68
    } else if (_.has(builtInComponents, id)) {                                                                // 69
      return builtInComponents[id];                                                                           // 70
                                                                                                              // 71
    // Code to search the global namespace for capitalized names                                              // 72
    // like component classes, `Template`, `StringUtils.foo`,                                                 // 73
    // etc.                                                                                                   // 74
    //                                                                                                        // 75
    // } else if (/^[A-Z]/.test(id) && (id in global)) {                                                      // 76
    //   // Only look for a global identifier if `id` is                                                      // 77
    //   // capitalized.  This avoids having `{{name}}` mean                                                  // 78
    //   // `window.name`.                                                                                    // 79
    //   result = global[id];                                                                                 // 80
    //   return function (/*arguments*/) {                                                                    // 81
    //     var data = getComponentData(self);                                                                 // 82
    //     if (typeof result === 'function')                                                                  // 83
    //       return result.apply(data, arguments);                                                            // 84
    //     return result;                                                                                     // 85
    //   };                                                                                                   // 86
    } else if (template && _.has(Template, id)) {                                                             // 87
      return Template[id];                                                                                    // 88
                                                                                                              // 89
    } else if ((result = UI._globalHelper(id))) {                                                             // 90
                                                                                                              // 91
    } else {                                                                                                  // 92
      // Resolve id `foo` as `data.foo` (with a "soft dot").                                                  // 93
      return function (/* arguments */) {                                                                     // 94
        var data = getComponentData(self);                                                                    // 95
        if (template && !(data && _.has(data, id)))                                                           // 96
          throw new Error("Can't find template, helper or data context " +                                    // 97
                          "key: " + id);                                                                      // 98
        if (! data)                                                                                           // 99
          return data;                                                                                        // 100
        var result = data[id];                                                                                // 101
        if (typeof result === 'function')                                                                     // 102
          return result.apply(data, arguments);                                                               // 103
        return result;                                                                                        // 104
      };                                                                                                      // 105
    }                                                                                                         // 106
                                                                                                              // 107
    if (typeof result === 'function' && ! result._isEmboxedConstant) {                                        // 108
      // Wrap the function `result`, binding `this` to `getComponentData(self)`.                              // 109
      // This creates a dependency when the result function is called.                                        // 110
      // Don't do this if the function is really just an emboxed constant.                                    // 111
      return function (/*arguments*/) {                                                                       // 112
        var args = arguments;                                                                                 // 113
        return currentComponent.withValue(self, function () {                                                 // 114
          currentTemplateInstance = null; // lazily computed, since `updateTemplateInstance` is a little slow // 115
          var data = getComponentData(self);                                                                  // 116
          return result.apply(data === null ? {} : data, args);                                               // 117
        });                                                                                                   // 118
      };                                                                                                      // 119
    } else {                                                                                                  // 120
      return result;                                                                                          // 121
    };                                                                                                        // 122
  },                                                                                                          // 123
  lookupTemplate: function (id) {                                                                             // 124
    return this.lookup(id, {template: true});                                                                 // 125
  },                                                                                                          // 126
  get: function (id) {                                                                                        // 127
    // support `this.get()` to get the data context.                                                          // 128
    if (id === undefined)                                                                                     // 129
      id = ".";                                                                                               // 130
                                                                                                              // 131
    var result = this.lookup(id);                                                                             // 132
    return (typeof result === 'function' ? result() : result);                                                // 133
  },                                                                                                          // 134
  set: function (id, value) {                                                                                 // 135
    var comp = findComponentWithProp(id, this);                                                               // 136
    if (! comp || ! comp[id])                                                                                 // 137
      throw new Error("Can't find field: " + id);                                                             // 138
    if (typeof comp[id] !== 'function')                                                                       // 139
      throw new Error("Not a settable field: " + id);                                                         // 140
    comp[id](value);                                                                                          // 141
  }                                                                                                           // 142
});                                                                                                           // 143
                                                                                                              // 144
////////////////////////////////////////////////////////////////////////////////////////////////////////////////

}).call(this);






(function () {

////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//                                                                                                            //
// packages/ui/handlebars_backcompat.js                                                                       //
//                                                                                                            //
////////////////////////////////////////////////////////////////////////////////////////////////////////////////
                                                                                                              //
// XXX this file no longer makes sense in isolation.  take it apart as                                        // 1
// part file reorg on the 'ui' package                                                                        // 2
var globalHelpers = {};                                                                                       // 3
                                                                                                              // 4
UI.registerHelper = function (name, func) {                                                                   // 5
  globalHelpers[name] = func;                                                                                 // 6
};                                                                                                            // 7
                                                                                                              // 8
UI._globalHelper = function (name) {                                                                          // 9
  return globalHelpers[name];                                                                                 // 10
};                                                                                                            // 11
                                                                                                              // 12
Handlebars = {};                                                                                              // 13
Handlebars.registerHelper = UI.registerHelper;                                                                // 14
                                                                                                              // 15
// Utility to HTML-escape a string.                                                                           // 16
UI._escape = Handlebars._escape = (function() {                                                               // 17
  var escape_map = {                                                                                          // 18
    "<": "&lt;",                                                                                              // 19
    ">": "&gt;",                                                                                              // 20
    '"': "&quot;",                                                                                            // 21
    "'": "&#x27;",                                                                                            // 22
    "`": "&#x60;", /* IE allows backtick-delimited attributes?? */                                            // 23
    "&": "&amp;"                                                                                              // 24
  };                                                                                                          // 25
  var escape_one = function(c) {                                                                              // 26
    return escape_map[c];                                                                                     // 27
  };                                                                                                          // 28
                                                                                                              // 29
  return function (x) {                                                                                       // 30
    return x.replace(/[&<>"'`]/g, escape_one);                                                                // 31
  };                                                                                                          // 32
})();                                                                                                         // 33
                                                                                                              // 34
// Return these from {{...}} helpers to achieve the same as returning                                         // 35
// strings from {{{...}}} helpers                                                                             // 36
Handlebars.SafeString = function(string) {                                                                    // 37
  this.string = string;                                                                                       // 38
};                                                                                                            // 39
Handlebars.SafeString.prototype.toString = function() {                                                       // 40
  return this.string.toString();                                                                              // 41
};                                                                                                            // 42
                                                                                                              // 43
////////////////////////////////////////////////////////////////////////////////////////////////////////////////

}).call(this);


/* Exports */
if (typeof Package === 'undefined') Package = {};
Package.ui = {
  UI: UI,
  Handlebars: Handlebars
};

})();

//# sourceMappingURL=9419ac08328918a04e7a49464a988d45f851e1b0.map
