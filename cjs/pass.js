'use strict';
const saferClass = (m => m.__esModule ? /* istanbul ignore next */ m.default : /* istanbul ignore next */ m)(require('safer-class'));
const crypto = (m => m.__esModule ? /* istanbul ignore next */ m.default : /* istanbul ignore next */ m)(require('safer-crypto'));
const {Promise, reject} = require('safer-promise');
const {bind} = require('safer-function');
const {encode, decode} = require('safer-text');
const {Uint8Array, arr2str, freeze, str2arr} = require('./utils.js');
const IV = (m => m.__esModule ? /* istanbul ignore next */ m.default : /* istanbul ignore next */ m)(require('./iv.js'));

const length = 256;
const method = 'AES-CBC';
const secrets = new WeakMap;
const getSecret = bind(secrets.get, secrets);
const setSecret = bind(secrets.set, secrets);
const {subtle} = crypto;

class Pass {

  static unserialize(serializeed, password, salt) {
    const {data, iv, str} = serializeed;
    const pass = new Pass(password, salt, IV.from(iv));
    return pass.decrypt(data, str);
  }

  constructor(
    password,
    salt = method + length,
    iv = new IV
  ) {
    if (typeof password === 'string')
      password = encode(password);
    if (typeof salt === 'string')
      salt = encode(salt);
    const name = 'PBKDF2';
    setSecret(freeze(this), new Promise($ => {
      subtle.importKey(
        'raw',
        password,
        {name},
        false,
        ['deriveBits', 'deriveKey']
      )
      .then(key => subtle.deriveKey(
        {
          name,
          salt,
          iterations: 8192,
          hash: `SHA-${length}`
        },
        key,
        {name: method, length},
        true,
        ['encrypt', 'decrypt']
      ))
      .then(key => {
        subtle.exportKey('jwk', key).then(jwk => $({iv, key, jwk}));
      });
    }));
  }

  decrypt(input, returnString = false) {
    const output = getSecret(this).then(
      ({iv, key}) => subtle.decrypt(
        {name: method, iv},
        key,
        typeof input === 'string' ?
          new Uint8Array(str2arr(input)) :
          input
      )
    );
    return (
      returnString ?
        output.then(decode) :
        output
    ).catch(
      () => reject(new Error('unable to decrypt'))
    );
  }

  encrypt(input, returnString = false) {
    const output = getSecret(this).then(
      ({iv, key}) => subtle.encrypt(
        {name: method, iv},
        key,
        typeof input === 'string' ?
          encode(input) :
          input
      )
    );
    return (
      returnString ?
        output.then(result => arr2str(new Uint8Array(result))) :
        output
    ).catch(
      () => reject(new Error('unable to encrypt'))
    );
  }

  serialize(input) {
    return getSecret(this).then(({iv}) => {
      return this.encrypt(input, true).then(data => {
        return {
          data,
          iv: iv.toString(),
          str: typeof input === 'string'
        };
      });
    });
  }

}

saferClass(Pass);
freeze(Pass);
freeze(Pass.prototype);

Object.defineProperty(exports, '__esModule', {value: true}).default = Pass;
