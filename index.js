var saferPass = (function (exports) {
  'use strict';

  /*! (c) Andrea Giammarchi - ISC */
  var call = Function.call;
  var bind = call.bind(call.bind);
  var apply = bind(call, call.apply);
  call = bind(call, call);

  /*! (c) Andrea Giammarchi - ISC */

  const {
    defineProperty,
    getPrototypeOf,
    getOwnPropertyDescriptor,
    getOwnPropertyNames,
    getOwnPropertySymbols,
    hasOwnProperty
  } = Object;

  const {concat, forEach, includes, push} = [];

  const falsify = (descriptor, name) => {
    defineProperty(descriptor, name, {
      enumerable: true,
      value: false
    });
  };

  const updated = descriptor => {
    falsify(descriptor, 'configurable');
    if (call(hasOwnProperty, descriptor, 'writable'))
      falsify(descriptor, 'writable');
    return descriptor;
  };

  var saferObject = object => {
    const self = object;
    const names = [];
    const descriptors = [];
    do {
      call(
        forEach,
        call(
          concat,
          getOwnPropertyNames(object),
          getOwnPropertySymbols(object)
        ),
        name => {
          if (!call(includes, names, name)) {
            call(push, names, name);
            call(push, descriptors, getOwnPropertyDescriptor(object, name));
          }
        }
      );
    }
    while (object = getPrototypeOf(object));
    call(forEach, names, (name, i) => {
      defineProperty(self, name, updated(descriptors[i]));
    });
    return self;
  };

  /*! (c) Andrea Giammarchi - ISC */

  var saferClass = Class => (
    saferObject(Class.prototype),
    saferObject(Class)
  );

  const {freeze, setPrototypeOf} = Object;
  const {reject: _reject, resolve: _resolve} = Promise;

  class SaferPromise extends Promise {
    static reject(value) {
      return call(_reject, SaferPromise, convert(value));
    }
    static resolve(value) {
      return call(_resolve, SaferPromise, convert(value));
    }
    constructor(fn) {
      freeze(super(fn));
    }
  }

  const {prototype, reject, resolve} = SaferPromise;
  const convert = value => (
    typeof value === 'object' &&
    value !== null &&
    'then' in value &&
    !(value instanceof SaferPromise) ?
      setPrototypeOf(value, prototype) :
      value
  );

  saferClass(SaferPromise);
  freeze(SaferPromise);
  freeze(prototype);

  /*! (c) Andrea Giammarchi - ISC */

  const {freeze: freeze$1, defineProperty: defineProperty$1, getOwnPropertyNames: getOwnPropertyNames$1, getPrototypeOf: getPrototypeOf$1} = Object;
  const isMethod = (self, key) => (
    !/^(?:caller|callee|arguments)$/.test(key) &&
    typeof self[key] === 'function' &&
    key !== 'constructor'
  );

  const {subtle} = crypto;

  const saferCrypto = {};
  const saferSubtle = {};

  getOwnPropertyNames$1(getPrototypeOf$1(crypto)).forEach(key => {
    if (isMethod(crypto, key)) {
      defineProperty$1(saferCrypto, key, {
        enumerable: true,
        value: bind(crypto[key], crypto)
      });
    }
  });

  getOwnPropertyNames$1(getPrototypeOf$1(subtle)).forEach(key => {
    if (isMethod(subtle, key)) {
      const method = subtle[key];
      defineProperty$1(saferSubtle, key, {
        enumerable: true,
        value() {
          return resolve(apply(method, subtle, arguments));
        }
      });
    }
  });

  var crypto$1 = freeze$1(defineProperty$1(saferCrypto, 'subtle', {
    enumerable: true,
    value: freeze$1(saferSubtle)
  }));

  const {freeze: freeze$2} = Object;
  const {fromCharCode} = String;
  const {charCodeAt} = '';
  const {map} = [];
  const U8A = Uint8Array;

  const arr2str = arr => apply(fromCharCode, null, arr);
  const str2arr = str => call(map, str, c => call(charCodeAt, c, 0));

  class IV extends U8A {

    static from(value) {
      return super.from(typeof value === 'string' ? str2arr(value) : value);
    }

    constructor(length = 16) {
      super(length);
      const buffer = crypto$1.getRandomValues(new U8A(length));
      for (let i = 0; i < length; i++)
        this[i] = buffer[i];
    }

    toString() {
      return arr2str(this);
    }
  }

  saferClass(IV);
  freeze$2(IV);
  freeze$2(IV.prototype);

  /*! (c) Andrea Giammarchi - ISC */

  const {encode, decode} = ((TE, TD) => {
    const {encode} = TE.prototype;
    const {decode} = TD.prototype;
    return {
      encode: value => call(encode, new TE, value),
      decode: (value, label, options) => call(
        decode,
        new TD(label || 'utf-8', options || {}),
        value
      ),
    };
  })(TextEncoder, TextDecoder);

  const length = 256;
  const method = 'AES-CBC';
  const secrets = new WeakMap;
  const getSecret = bind(secrets.get, secrets);
  const setSecret = bind(secrets.set, secrets);
  const {subtle: subtle$1} = crypto$1;

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
      setSecret(freeze$2(this), new SaferPromise($ => {
        subtle$1.importKey(
          'raw',
          password,
          {name},
          false,
          ['deriveBits', 'deriveKey']
        )
        .then(key => subtle$1.deriveKey(
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
          subtle$1.exportKey('jwk', key).then(jwk => $({iv, key, jwk}));
        });
      }));
    }

    decrypt(input, returnString = false) {
      const output = getSecret(this).then(
        ({iv, key}) => subtle$1.decrypt(
          {name: method, iv},
          key,
          typeof input === 'string' ?
            new U8A(str2arr(input)) :
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
        ({iv, key}) => subtle$1.encrypt(
          {name: method, iv},
          key,
          typeof input === 'string' ?
            encode(input) :
            input
        )
      );
      return (
        returnString ?
          output.then(result => arr2str(new U8A(result))) :
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
  freeze$2(Pass);
  freeze$2(Pass.prototype);

  exports.IV = IV;
  exports.Pass = Pass;

  return exports;

}({}));
