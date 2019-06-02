# safer-pass

<sup>**Social Media Photo by [freestocks.org](https://unsplash.com/@freestocks) on [Unsplash](https://unsplash.com/)**</sup>

[![Build Status](https://travis-ci.com/WebReflection/safer-pass.svg?branch=master)](https://travis-ci.com/WebReflection/safer-pass) [![Coverage Status](https://coveralls.io/repos/github/WebReflection/safer-pass/badge.svg?branch=master)](https://coveralls.io/github/WebReflection/safer-promise?branch=master) ![WebReflection status](https://offline.report/status/webreflection.svg)

A safer and easy way to protect with password text or files.

#### v1 breaking change

The `Pass` constructor signature is now `Pass(password[, salt[, iv]])`.


### Background

Cryptography isn't easy, and the current [Web Crypto API](https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API) is not making it any easier for Web developers to simply protect some text, file, or image, with a user defined password.

Not only the [Web Crypto API is easy to crack](https://github.com/WebReflection/safer-crypto#safer-crypto), for any malicious 3rd parts script running in the wild, its usage is also fairly complicated, 'cause complicated is indeed the subject as a whole.

This module uses all [techniques recognized as able to make JS safer](https://github.com/domenic/get-originals), and it tries to simplify the topic without necessarily making it any less safe than it should.


## The Password Protection's ABC

There are 3 terms, or variables, to keep in mind:

  * the **user password**
  * the **salt**
  * the **initialization vector** (IV)

The least important thing is usually, and unfortunately, the _user password_, keep reading to know more.


### The user password

Both 'cause humans aren't too good at remembering long sentences, and mostly because every service online asks you to comply with absurd rules, we have our fingers print and our finances authenticated through a 4 to 6 digits pin. and yet if we chose passwords by ourselves, with our rules, they believe we're doomed.

See [xkcd comic 936](https://xkcd.com/936/) to know more.

Anyway, the first thing to remember is that our favorite password is usually not good enough.


### The salt

A _salt_ is usually `"a very long and unique string"` that a server, or a computer, but not usually a browser, is very good at keeping secret.

A _salt_ is usually mandatory to avoid storing passwords in clear, but it's also not something you want to pass around.

Due to its controversial nature, this module provides a way to define a specific salt, but it's not in the ABC nature of this paragraph that you'll learn more about it.

Please [do investigate mote about salts](https://en.wikipedia.org/wiki/Salt_(cryptography)) to improve security.


### The (IV) Initialization Vector

This is the most important variable of them all: you either know it, or you'll hardly crack the encrypted data.

The _IV_ is a random generated _salt_ like variable, that is used to add some sort of unpredictable encryption, and it's mandatory to be able, password or not, to decrypt such data.

This means that an instance of `Pass` that doesn't use a shared `IV`, will be the only one able to encrypt and decrypt its own data.

```js
import {IV, Pass} from 'safer-pass';

const user1 = new Pass(password);
const user2 = new Pass(password);

// user1 can encrypt and decrypt data
user1
  .encrypt(data)
  .then(buffer => user1.decrypt(data))
  .then(console.log);

// but user2 cannot decrypt user1 data
user1
  .encrypt(data)
  .then(buffer => user2.decrypt(data))
  .catch(error => {
    console.error('Ooooooops, the IV is not the same!');
  });
```


## How to encrypt and decrypt at distance

The 2 things that users need to know, one by heart, and one by their machine, is the password, and the IV.

```js
import {IV, Pass} from 'safer-pass';

const SALT = 'some-very-long-and-unique-secret';

const sharedIV = new IV;
const user1 = new Pass(password, SALT, sharedIV);
const user2 = new Pass(password, SALT, sharedIV);

// user1 can encrypt and user2 can decrypt data
user1
  .encrypt(data)
  .then(buffer => user2.decrypt(data))
  .then(console.log);

```


## How to transfer encrypted data

Assuming both users know the same `password` and optionally, but recommended, the same `salt`, the module offer an instance `serialize` and a static `unserialize` method.

```js
// from user1 side
import {Pass} from 'safer-pass';

const SALT = 'some-very-long-and-unique-secret';

const user1 = new Pass(
  password,
  SALT
);
user1.serialize('secret info').then(transfer);

// from user2 side
import {Pass} from 'safer-pass';
receive()
  .then(
    data => Pass.unserialize(
      data,
      password,
      SALT
    )
  )
  .then(console.log);
```

# API

There are two classes provided with this module, the `IV` one, and the `Pass` one.

## IV

```js
class IV extends Uint8Array {

  static from(value) {
    // return an IV from a buffer or a string
  }

  constructor(length = 16) {
    // creates an IV with length 16 by default
  }

  toString() {
    // return a string representation of the IV
  }
}
```


## Pass

```js
class Pass {

  static unserialize(serializeed, password, salt) {
    // return a promise that resolves as decrypted data
  }

  constructor(
    password,     // either a string or a buffer
    salt = '...', // an optional salt to use
    iv = new IV   // am optional random buffer to use
  ) {
    // creates a frozen instance of Pass
  }

  decrypt(input, returnString = false) {
    // return a promise with decrypted data
    // either as buffer, or string
  }

  encrypt(input, returnString = false) {
    // return a promise with encrypted data
    // either as buffer, or string
  }

  serialize(input) {
    // return a promise with an object
    // usable to transfer data, being saved in a db
    // or being posted via JSON.stringify
  }

}
```
