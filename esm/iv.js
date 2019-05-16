import saferClass from 'safer-class';
import crypto from 'safer-crypto';
import {Uint8Array, arr2str, freeze, str2arr} from './utils.js';

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

export default IV;
