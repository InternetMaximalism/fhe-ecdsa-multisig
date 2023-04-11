import BN from "bn.js";

const zero = new BN(0);
const one = new BN(1);
const two = new BN(2);
const n = new BN(
  "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141",
  "hex"
);

export function getMultiSigAddressPoint(keyPair1, pubKey2) {
  return pubKey2.mul(keyPair1.getPrivate());
}

export function getMultiSigPrivateKey(keyPair1, keyPair2) {
  return keyPair1.getPrivate().mul(keyPair2.getPrivate()).umod(n);
}

export function recoverAliceKeyFromMultiSigKey(privKeyMultiSig, bobKeyPair) {
  let powers = bobKeyPair.getPrivate();
  let tmpExp = n.sub(two);
  let privKeyBobInv = one;
  while (tmpExp.gt(zero)) {
    if (tmpExp.umod(two).eq(one)) {
      privKeyBobInv = privKeyBobInv.mul(powers).umod(n);
    }

    powers = powers.sqr().umod(n);
    tmpExp = tmpExp.shrn(1);
  }

  return privKeyMultiSig.mul(privKeyBobInv).umod(n);
}
