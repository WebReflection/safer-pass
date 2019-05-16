'use strict';
const saferClass = (m => m.__esModule ? /* istanbul ignore next */ m.default : /* istanbul ignore next */ m)(require('safer-class'));
const crypto = (m => m.__esModule ? /* istanbul ignore next */ m.default : /* istanbul ignore next */ m)(require('safer-crypto'));
const {Uint8Array, arr2str, freeze, str2arr} = require('./utils.js');

class IV extends Uint8Array {

  static from(value) {
    return super.from(typeof value === 'string' ? str2arr(value) : value);
  }

  constructor(length = 16) {
    super(length);
    const buffer = crypto.getRandomValues(new Uint8Array(length));
    for (let i = 0; i < length; i++)
      this[i] = buffer[i];
  }

  toString() {
    return arr2str(this);
  }
}

saferClass(IV);
freeze(IV);
freeze(IV.prototype);

Object.defineProperty(exports, '__esModule', {value: true}).default = IV;
