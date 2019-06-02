
// The following works, but I think it's not a good idea,
// 'cause it bypasses the password completely.
// TODO: think about a better way to enable import/export
/*
static import({iv, jwk}) {
  const ek = create(this.prototype);
  setSecret(ek, new Promise($ => {
    promise(
      importKey(
        'jwk',
        jwk,
        method,
        jwk.ext,
        jwk.key_ops
      ),
      $then,
      key => $({
        iv: IV.from(iv),
        key,
        jwk
      })
    );
  }));
  return ek;
}

export() {
  return promise(
    getSecret(this),
    $then,
    ({iv, jwk}) => ({iv: arr2str(iv), jwk})
  );
}
//*/


/* from usitl.js not used anymore
const asChar = (i, len, str) => (i < len ? str[i] : fromCharCode(i));
export const shuffle = (a, b) => {
  const alen = a.length;
  const blen = b.length;
  const len = alen < blen ? blen : alen;
  let out = "";
  for (let i = 0; i < len; i++)
    out = out + asChar(i, alen, a) + asChar(i, blen, b);
  return out;
};
// */
