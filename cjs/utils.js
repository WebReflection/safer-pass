'use strict';
const {apply, call} = require('safer-function');

const {freeze} = Object;
const {fromCharCode} = String;
const {charCodeAt} = '';
const {map} = [];
const U8A = Uint8Array;

const arr2str = arr => apply(fromCharCode, null, arr);
exports.arr2str = arr2str;
const str2arr = str => call(map, str, c => call(charCodeAt, c, 0));
exports.str2arr = str2arr;

exports.Uint8Array = U8A;
exports.freeze = freeze;
