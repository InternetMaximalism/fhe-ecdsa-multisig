import elliptic from "elliptic";
import BN from "bn.js";
var EC = elliptic.ec;

export function getMultiSigAddressPoint(privKey, pubKey) {
  return pubKey.mul(privKey.getPrivate());
}

export function getMultiSigPrivateKey(privKey1, privKey2) {
  const n = new BN("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141", "hex");
  return privKey1.getPrivate().mul(privKey2.getPrivate()).umod(n);
}
