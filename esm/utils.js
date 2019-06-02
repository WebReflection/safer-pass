import {apply, call} from 'safer-function';

const {freeze} = Object;
const {fromCharCode} = String;
const {charCodeAt} = '';
const {map} = [];
const U8A = Uint8Array;

export const arr2str = arr => apply(fromCharCode, null, arr);
export const str2arr = str => call(map, str, c => call(charCodeAt, c, 0));

export {
  U8A as Uint8Array,
  freeze
};
