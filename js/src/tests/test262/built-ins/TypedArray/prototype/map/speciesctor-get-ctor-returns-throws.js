// |reftest| shell-option(--enable-float16array)
// Copyright (C) 2018 Peter Wong. All rights reserved.
// This code is governed by the BSD license found in the LICENSE file.
/*---
esid: sec-%typedarray%.prototype.map
description: >
  Throws if O.constructor returns a non-Object and non-undefined value
info: |
  22.2.3.19 %TypedArray%.prototype.map ( callbackfn [ , thisArg ] )

  ...
  6. Let A be ? TypedArraySpeciesCreate(O, « len »).
  ...

  22.2.4.7 TypedArraySpeciesCreate ( exemplar, argumentList )

  ...
  3. Let constructor be ? SpeciesConstructor(exemplar, defaultConstructor).
  ...

  7.3.20 SpeciesConstructor ( O, defaultConstructor )

  1. Assert: Type(O) is Object.
  2. Let C be ? Get(O, "constructor").
  3. If C is undefined, return defaultConstructor.
  4. If Type(C) is not Object, throw a TypeError exception.
  ...
includes: [testTypedArray.js]
features: [Symbol, TypedArray]
---*/

var callbackfn = function() { return 0; };

testWithTypedArrayConstructors(function(TA) {
  var sample = new TA([40, 41, 42, 43]);

  sample.constructor = 42;
  assert.throws(TypeError, function() {
    sample.map(callbackfn);
  }, "42");

  sample.constructor = "1";
  assert.throws(TypeError, function() {
    sample.map(callbackfn);
  }, "string");

  sample.constructor = null;
  assert.throws(TypeError, function() {
    sample.map(callbackfn);
  }, "null");

  sample.constructor = NaN;
  assert.throws(TypeError, function() {
    sample.map(callbackfn);
  }, "NaN");

  sample.constructor = false;
  assert.throws(TypeError, function() {
    sample.map(callbackfn);
  }, "false");

  sample.constructor = Symbol("1");
  assert.throws(TypeError, function() {
    sample.map(callbackfn);
  }, "symbol");
});

reportCompare(0, 0);
