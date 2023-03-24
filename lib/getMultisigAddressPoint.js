import elliptic from "elliptic";
var EC = elliptic.ec;

export function getMultiSigAddressPoint(privKey, pubKey) {
  return pubKey.getPublic().mul(privKey.getPrivate());
}
