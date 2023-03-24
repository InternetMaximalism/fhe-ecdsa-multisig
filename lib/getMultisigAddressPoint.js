import elliptic from "elliptic";
var EC = elliptic.ec;

export function getMultiSigAddressPoint(privKey, pubKey) {
  return pubKey.mul(privKey.getPrivate());
}

export function getMultiSigPrivateKey(privKey1, privKey2) {
  return privKey1.getPrivate().mul(privKey2.getPrivate());
}
