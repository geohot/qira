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
var Spacebars = Package['spacebars-common'].Spacebars;
var HTML = Package.htmljs.HTML;
var UI = Package.ui.UI;
var Handlebars = Package.ui.Handlebars;
var Template = Package.templating.Template;

(function () {

//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//                                                                                                          //
// packages/spacebars/spacebars-runtime.js                                                                  //
//                                                                                                          //
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
                                                                                                            //
// * `templateOrFunction` - template (component) or function returning a template                           // 1
// or null                                                                                                  // 2
Spacebars.include = function (templateOrFunction, contentBlock, elseContentBlock) {                         // 3
  if (contentBlock && ! UI.isComponent(contentBlock))                                                       // 4
    throw new Error('Second argument to Spacebars.include must be a template or UI.block if present');      // 5
  if (elseContentBlock && ! UI.isComponent(elseContentBlock))                                               // 6
    throw new Error('Third argument to Spacebars.include must be a template or UI.block if present');       // 7
                                                                                                            // 8
  var props = null;                                                                                         // 9
  if (contentBlock) {                                                                                       // 10
    props = (props || {});                                                                                  // 11
    props.__content = contentBlock;                                                                         // 12
  }                                                                                                         // 13
  if (elseContentBlock) {                                                                                   // 14
    props = (props || {});                                                                                  // 15
    props.__elseContent = elseContentBlock;                                                                 // 16
  }                                                                                                         // 17
                                                                                                            // 18
  if (UI.isComponent(templateOrFunction))                                                                   // 19
    return templateOrFunction.extend(props);                                                                // 20
                                                                                                            // 21
  var func = templateOrFunction;                                                                            // 22
                                                                                                            // 23
  var f = function () {                                                                                     // 24
    var emboxedFunc = UI.namedEmboxValue('Spacebars.include', func);                                        // 25
    f.stop = function () {                                                                                  // 26
      emboxedFunc.stop();                                                                                   // 27
    };                                                                                                      // 28
    var tmpl = emboxedFunc();                                                                               // 29
                                                                                                            // 30
    if (tmpl === null)                                                                                      // 31
      return null;                                                                                          // 32
    if (! UI.isComponent(tmpl))                                                                             // 33
      throw new Error("Expected null or template in return value from inclusion function, found: " + tmpl); // 34
                                                                                                            // 35
    return tmpl.extend(props);                                                                              // 36
  };                                                                                                        // 37
                                                                                                            // 38
  return f;                                                                                                 // 39
};                                                                                                          // 40
                                                                                                            // 41
// Executes `{{foo bar baz}}` when called on `(foo, bar, baz)`.                                             // 42
// If `bar` and `baz` are functions, they are called before                                                 // 43
// `foo` is called on them.                                                                                 // 44
//                                                                                                          // 45
// This is the shared part of Spacebars.mustache and                                                        // 46
// Spacebars.attrMustache, which differ in how they post-process the                                        // 47
// result.                                                                                                  // 48
Spacebars.mustacheImpl = function (value/*, args*/) {                                                       // 49
  var args = arguments;                                                                                     // 50
  // if we have any arguments (pos or kw), add an options argument                                          // 51
  // if there isn't one.                                                                                    // 52
  if (args.length > 1) {                                                                                    // 53
    var kw = args[args.length - 1];                                                                         // 54
    if (! (kw instanceof Spacebars.kw)) {                                                                   // 55
      kw = Spacebars.kw();                                                                                  // 56
      // clone arguments into an actual array, then push                                                    // 57
      // the empty kw object.                                                                               // 58
      args = Array.prototype.slice.call(arguments);                                                         // 59
      args.push(kw);                                                                                        // 60
    } else {                                                                                                // 61
      // For each keyword arg, call it if it's a function                                                   // 62
      var newHash = {};                                                                                     // 63
      for (var k in kw.hash) {                                                                              // 64
        var v = kw.hash[k];                                                                                 // 65
        newHash[k] = (typeof v === 'function' ? v() : v);                                                   // 66
      }                                                                                                     // 67
      args[args.length - 1] = Spacebars.kw(newHash);                                                        // 68
    }                                                                                                       // 69
  }                                                                                                         // 70
                                                                                                            // 71
  return Spacebars.call.apply(null, args);                                                                  // 72
};                                                                                                          // 73
                                                                                                            // 74
Spacebars.mustache = function (value/*, args*/) {                                                           // 75
  var result = Spacebars.mustacheImpl.apply(null, arguments);                                               // 76
                                                                                                            // 77
  if (result instanceof Spacebars.SafeString)                                                               // 78
    return HTML.Raw(result.toString());                                                                     // 79
  else                                                                                                      // 80
    // map `null`, `undefined`, and `false` to null, which is important                                     // 81
    // so that attributes with nully values are considered absent.                                          // 82
    // stringify anything else (e.g. strings, booleans, numbers including 0).                               // 83
    return (result == null || result === false) ? null : String(result);                                    // 84
};                                                                                                          // 85
                                                                                                            // 86
Spacebars.attrMustache = function (value/*, args*/) {                                                       // 87
  var result = Spacebars.mustacheImpl.apply(null, arguments);                                               // 88
                                                                                                            // 89
  if (result == null || result === '') {                                                                    // 90
    return null;                                                                                            // 91
  } else if (typeof result === 'object') {                                                                  // 92
    return result;                                                                                          // 93
  } else if (typeof result === 'string' && HTML.isValidAttributeName(result)) {                             // 94
    var obj = {};                                                                                           // 95
    obj[result] = '';                                                                                       // 96
    return obj;                                                                                             // 97
  } else {                                                                                                  // 98
    throw new Error("Expected valid attribute name, '', null, or object");                                  // 99
  }                                                                                                         // 100
};                                                                                                          // 101
                                                                                                            // 102
Spacebars.dataMustache = function (value/*, args*/) {                                                       // 103
  var result = Spacebars.mustacheImpl.apply(null, arguments);                                               // 104
                                                                                                            // 105
  return result;                                                                                            // 106
};                                                                                                          // 107
                                                                                                            // 108
// Idempotently wrap in `HTML.Raw`.                                                                         // 109
//                                                                                                          // 110
// Called on the return value from `Spacebars.mustache` in case the                                         // 111
// template uses triple-stache (`{{{foo bar baz}}}`).                                                       // 112
Spacebars.makeRaw = function (value) {                                                                      // 113
  if (value == null) // null or undefined                                                                   // 114
    return null;                                                                                            // 115
  else if (value instanceof HTML.Raw)                                                                       // 116
    return value;                                                                                           // 117
  else                                                                                                      // 118
    return HTML.Raw(value);                                                                                 // 119
};                                                                                                          // 120
                                                                                                            // 121
// If `value` is a function, called it on the `args`, after                                                 // 122
// evaluating the args themselves (by calling them if they are                                              // 123
// functions).  Otherwise, simply return `value` (and assert that                                           // 124
// there are no args).                                                                                      // 125
Spacebars.call = function (value/*, args*/) {                                                               // 126
  if (typeof value === 'function') {                                                                        // 127
    // evaluate arguments if they are functions (by calling them)                                           // 128
    var newArgs = [];                                                                                       // 129
    for (var i = 1; i < arguments.length; i++) {                                                            // 130
      var arg = arguments[i];                                                                               // 131
      newArgs[i-1] = (typeof arg === 'function' ? arg() : arg);                                             // 132
    }                                                                                                       // 133
                                                                                                            // 134
    return value.apply(null, newArgs);                                                                      // 135
  } else {                                                                                                  // 136
    if (arguments.length > 1)                                                                               // 137
      throw new Error("Can't call non-function: " + value);                                                 // 138
                                                                                                            // 139
    return value;                                                                                           // 140
  }                                                                                                         // 141
};                                                                                                          // 142
                                                                                                            // 143
// Call this as `Spacebars.kw({ ... })`.  The return value                                                  // 144
// is `instanceof Spacebars.kw`.                                                                            // 145
Spacebars.kw = function (hash) {                                                                            // 146
  if (! (this instanceof Spacebars.kw))                                                                     // 147
    // called without new; call with new                                                                    // 148
    return new Spacebars.kw(hash);                                                                          // 149
                                                                                                            // 150
  this.hash = hash || {};                                                                                   // 151
};                                                                                                          // 152
                                                                                                            // 153
// Call this as `Spacebars.SafeString("some HTML")`.  The return value                                      // 154
// is `instanceof Spacebars.SafeString` (and `instanceof Handlebars.SafeString).                            // 155
Spacebars.SafeString = function (html) {                                                                    // 156
  if (! (this instanceof Spacebars.SafeString))                                                             // 157
    // called without new; call with new                                                                    // 158
    return new Spacebars.SafeString(html);                                                                  // 159
                                                                                                            // 160
  return new Handlebars.SafeString(html);                                                                   // 161
};                                                                                                          // 162
Spacebars.SafeString.prototype = Handlebars.SafeString.prototype;                                           // 163
                                                                                                            // 164
// `Spacebars.dot(foo, "bar", "baz")` performs a special kind                                               // 165
// of `foo.bar.baz` that allows safe indexing of `null` and                                                 // 166
// indexing of functions (which calls the function).  If the                                                // 167
// result is a function, it is always a bound function (e.g.                                                // 168
// a wrapped version of `baz` that always uses `foo.bar` as                                                 // 169
// `this`).                                                                                                 // 170
//                                                                                                          // 171
// In `Spacebars.dot(foo, "bar")`, `foo` is assumed to be either                                            // 172
// a non-function value or a "fully-bound" function wrapping a value,                                       // 173
// where fully-bound means it takes no arguments and ignores `this`.                                        // 174
//                                                                                                          // 175
// `Spacebars.dot(foo, "bar")` performs the following steps:                                                // 176
//                                                                                                          // 177
// * If `foo` is falsy, return `foo`.                                                                       // 178
//                                                                                                          // 179
// * If `foo` is a function, call it (set `foo` to `foo()`).                                                // 180
//                                                                                                          // 181
// * If `foo` is falsy now, return `foo`.                                                                   // 182
//                                                                                                          // 183
// * Return `foo.bar`, binding it to `foo` if it's a function.                                              // 184
Spacebars.dot = function (value, id1/*, id2, ...*/) {                                                       // 185
  if (arguments.length > 2) {                                                                               // 186
    // Note: doing this recursively is probably less efficient than                                         // 187
    // doing it in an iterative loop.                                                                       // 188
    var argsForRecurse = [];                                                                                // 189
    argsForRecurse.push(Spacebars.dot(value, id1));                                                         // 190
    argsForRecurse.push.apply(argsForRecurse,                                                               // 191
                              Array.prototype.slice.call(arguments, 2));                                    // 192
    return Spacebars.dot.apply(null, argsForRecurse);                                                       // 193
  }                                                                                                         // 194
                                                                                                            // 195
  if (typeof value === 'function')                                                                          // 196
    value = value();                                                                                        // 197
                                                                                                            // 198
  if (! value)                                                                                              // 199
    return value; // falsy, don't index, pass through                                                       // 200
                                                                                                            // 201
  var result = value[id1];                                                                                  // 202
  if (typeof result !== 'function')                                                                         // 203
    return result;                                                                                          // 204
  // `value[id1]` (or `value()[id1]`) is a function.                                                        // 205
  // Bind it so that when called, `value` will be placed in `this`.                                         // 206
  return function (/*arguments*/) {                                                                         // 207
    return result.apply(value, arguments);                                                                  // 208
  };                                                                                                        // 209
};                                                                                                          // 210
                                                                                                            // 211
// Implement Spacebars's #with, which renders its else case (or nothing)                                    // 212
// if the argument is falsy.                                                                                // 213
Spacebars.With = function (argFunc, contentBlock, elseContentBlock) {                                       // 214
  return UI.Component.extend({                                                                              // 215
    init: function () {                                                                                     // 216
      this.v = UI.emboxValue(argFunc, UI.safeEquals);                                                       // 217
    },                                                                                                      // 218
    render: function () {                                                                                   // 219
      return UI.If(this.v, UI.With(this.v, contentBlock), elseContentBlock);                                // 220
    },                                                                                                      // 221
    materialized: (function () {                                                                            // 222
      var f = function (range) {                                                                            // 223
        var self = this;                                                                                    // 224
        if (Deps.active) {                                                                                  // 225
          Deps.onInvalidate(function () {                                                                   // 226
            self.v.stop();                                                                                  // 227
          });                                                                                               // 228
        }                                                                                                   // 229
        if (range) {                                                                                        // 230
          range.removed = function () {                                                                     // 231
            self.v.stop();                                                                                  // 232
          };                                                                                                // 233
        }                                                                                                   // 234
      };                                                                                                    // 235
      f.isWith = true;                                                                                      // 236
      return f;                                                                                             // 237
    })()                                                                                                    // 238
  });                                                                                                       // 239
};                                                                                                          // 240
                                                                                                            // 241
Spacebars.TemplateWith = function (argFunc, contentBlock) {                                                 // 242
  var w = UI.With(argFunc, contentBlock);                                                                   // 243
  w.__isTemplateWith = true;                                                                                // 244
  return w;                                                                                                 // 245
};                                                                                                          // 246
                                                                                                            // 247
//////////////////////////////////////////////////////////////////////////////////////////////////////////////

}).call(this);






(function () {

//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//                                                                                                          //
// packages/spacebars/template.dynamic.js                                                                   //
//                                                                                                          //
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
                                                                                                            //
                                                                                                            // 1
Template.__define__("__dynamic", (function() {                                                              // 2
  var self = this;                                                                                          // 3
  var template = this;                                                                                      // 4
  return [ function() {                                                                                     // 5
    return Spacebars.mustache(self.lookup("checkContext"));                                                 // 6
  }, "\n  ", UI.If(function() {                                                                             // 7
    return Spacebars.call(self.lookup("dataContextPresent"));                                               // 8
  }, UI.block(function() {                                                                                  // 9
    var self = this;                                                                                        // 10
    return [ "\n    ", Spacebars.include(self.lookupTemplate("__dynamicWithDataContext")), "\n  " ];        // 11
  }), UI.block(function() {                                                                                 // 12
    var self = this;                                                                                        // 13
    return [ "\n    \n    ", Spacebars.TemplateWith(function() {                                            // 14
      return {                                                                                              // 15
        template: Spacebars.call(self.lookup("template")),                                                  // 16
        data: Spacebars.call(self.lookup(".."))                                                             // 17
      };                                                                                                    // 18
    }, UI.block(function() {                                                                                // 19
      var self = this;                                                                                      // 20
      return Spacebars.include(self.lookupTemplate("__dynamicWithDataContext"));                            // 21
    })), "\n  " ];                                                                                          // 22
  })) ];                                                                                                    // 23
}));                                                                                                        // 24
                                                                                                            // 25
Template.__define__("__dynamicWithDataContext", (function() {                                               // 26
  var self = this;                                                                                          // 27
  var template = this;                                                                                      // 28
  return Spacebars.With(function() {                                                                        // 29
    return Spacebars.dataMustache(self.lookup("chooseTemplate"), self.lookup("template"));                  // 30
  }, UI.block(function() {                                                                                  // 31
    var self = this;                                                                                        // 32
    return [ "\n    ", Spacebars.With(function() {                                                          // 33
      return Spacebars.call(Spacebars.dot(self.lookup(".."), "data"));                                      // 34
    }, UI.block(function() {                                                                                // 35
      var self = this;                                                                                      // 36
      return [ "    \n      ", Spacebars.include(self.lookupTemplate("..")), "           \n    " ];         // 37
    }), UI.block(function() {                                                                               // 38
      var self = this;                                                                                      // 39
      return [ "             \n      ", Spacebars.TemplateWith(function() {                                 // 40
        return Spacebars.call(Spacebars.dot(self.lookup(".."), "data"));                                    // 41
      }, UI.block(function() {                                                                              // 42
        var self = this;                                                                                    // 43
        return Spacebars.include(self.lookupTemplate(".."));                                                // 44
      })), "   \n    " ];                                                                                   // 45
    })), "\n  " ];                                                                                          // 46
  }));                                                                                                      // 47
}));                                                                                                        // 48
                                                                                                            // 49
//////////////////////////////////////////////////////////////////////////////////////////////////////////////

}).call(this);






(function () {

//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//                                                                                                          //
// packages/spacebars/dynamic.js                                                                            //
//                                                                                                          //
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
                                                                                                            //
Template.__dynamicWithDataContext.chooseTemplate = function (name) {                                        // 1
  return Template[name] || null;                                                                            // 2
};                                                                                                          // 3
                                                                                                            // 4
Template.__dynamic.dataContextPresent = function () {                                                       // 5
  return _.has(this, "data");                                                                               // 6
};                                                                                                          // 7
                                                                                                            // 8
Template.__dynamic.checkContext = function () {                                                             // 9
  if (! _.has(this, "template")) {                                                                          // 10
    throw new Error("Must specify name in the 'template' argument " +                                       // 11
                    "to {{> UI.dynamic}}.");                                                                // 12
  }                                                                                                         // 13
                                                                                                            // 14
  _.each(this, function (v, k) {                                                                            // 15
    if (k !== "template" && k !== "data") {                                                                 // 16
      throw new Error("Invalid argument to {{> UI.dynamic}}: " +                                            // 17
                      k);                                                                                   // 18
    }                                                                                                       // 19
  });                                                                                                       // 20
};                                                                                                          // 21
                                                                                                            // 22
//////////////////////////////////////////////////////////////////////////////////////////////////////////////

}).call(this);


/* Exports */
if (typeof Package === 'undefined') Package = {};
Package.spacebars = {};

})();

//# sourceMappingURL=8988006be5c29dbe17997e9691a21dce4e537665.map
