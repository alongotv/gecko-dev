// |reftest| shell-option(--enable-float16array)
// Copyright (C) 2016 the V8 project authors. All rights reserved.
// This code is governed by the BSD license found in the LICENSE file.
/*---
esid: sec-%typedarray%.prototype.slice
description: >
  Throws a TypeError exception when `this` is not a TypedArray instance
info: |
  22.2.3.24 %TypedArray%.prototype.slice ( start, end )

  The following steps are taken:

  1. Let O be the this value.
  2. Perform ? ValidateTypedArray(O).
  ...

  22.2.3.5.1 Runtime Semantics: ValidateTypedArray ( O )

  1. If Type(O) is not Object, throw a TypeError exception.
  2. If O does not have a [[TypedArrayName]] internal slot, throw a TypeError
  exception.
  ...
includes: [testTypedArray.js]
features: [TypedArray]
---*/

var slice = TypedArray.prototype.slice;

assert.throws(TypeError, function() {
  slice.call({}, 0, 0);
}, "this is an Object");

assert.throws(TypeError, function() {
  slice.call([], 0, 0);
}, "this is an Array");

var ab = new ArrayBuffer(8);
assert.throws(TypeError, function() {
  slice.call(ab, 0, 0);
}, "this is an ArrayBuffer instance");

var dv = new DataView(new ArrayBuffer(8), 0, 1);
assert.throws(TypeError, function() {
  slice.call(dv, 0, 0);
}, "this is a DataView instance");

reportCompare(0, 0);
