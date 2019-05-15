const WebCrypto = require('node-webcrypto-ossl');
const {encode, decode} = require('safer-text');

global.crypto = new WebCrypto;

const {IV, Pass} = require('../cjs');


const password = 'my super secret thing';
const salt = encode('this is absolutely secret too');
let pass0encrypt;

const pass0 = new Pass(password);
pass0.encrypt('this is pass0').then(buff => {
  pass0encrypt = buff;
  console.assert(typeof buff === 'object', 'pass0 can encrypt');
  pass0.decrypt(buff).then(buff => {
    console.assert(typeof buff === 'object', 'pass0 can decrypt');
    console.assert('this is pass0' === decode(buff));
    console.log(decode(buff));
  });
});

const pass1 = new Pass(password);
pass1.encrypt('this is pass1', true).then(buff => {
  console.assert(typeof buff === 'string', 'pass1 can encrypt');
  pass1.decrypt(buff, true).then(buff => {
    console.assert(typeof buff === 'string', 'pass1 can decrypt');
    console.assert('this is pass1' === buff);
    console.log(buff);
  });
});

const iv0 = new IV;
const pass3 = new Pass(password, iv0, salt);
const pass4 = new Pass(password, iv0, salt);
pass3.encrypt('this is pass3 for pass4').then(buff => {
  pass4.decrypt(buff).then(buff => {
    console.assert('this is pass3 for pass4' === decode(buff));
    console.log(decode(buff));
  });
});

console.assert(
  iv0.toString() === IV.from(iv0.toString()).toString() &&
  iv0.toString() === IV.from(iv0).toString(),
  'IV is serializable'
);

const iv1 = new IV;
const pass5 = new Pass(encode(password), iv1);
const pass6 = new Pass(encode(password), iv1);
pass5.encrypt(encode('this is pass5 for pass6')).then(buff => {
  pass6.decrypt(buff).then(buff => {
    console.assert('this is pass5 for pass6' === decode(buff));
    console.log(decode(buff));
  });
});

const pass7 = new Pass(password);
pass7.encrypt(void 0).catch(error => {
  console.log(error.message);
});
pass7.decrypt(pass0encrypt).catch(error => {
  console.log(error.message);
});

pass0
  .serialize('this is pass0')
  .then(serialized => Pass.unserialize(serialized, password))
  .then(console.log);

