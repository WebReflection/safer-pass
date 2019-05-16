import {apply, call} from 'safer-function';

const {freeze} = Object;
const {fromCharCode} = String;
const {charCodeAt} = '';
const {map} = [];
const U8A = Uint8Array;

const asChar = (i, len, str) => (i < len ? str[i] : fromCharCode(i));

export const arr2str = arr => apply(fromCharCode, null, arr);
export const str2arr = str => call(map, str, c => call(charCodeAt, c, 0));
export const shuffle = (a, b) => {
  const alen = a.length;
  const blen = b.length;
  const len = alen < blen ? blen : alen;
  let out = "";
  for (let i = 0; i < len; i++)
    out = out + asChar(i, alen, a) + asChar(i, blen, b);
  return out;
};

export {
  U8A as Uint8Array,
  freeze
};
