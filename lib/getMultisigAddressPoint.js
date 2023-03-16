import elliptic from 'elliptic';
import BN from 'bn.js';
var EC = elliptic.ec;

export function getMultiSigAddressPoint(privKey,pubKey){

    return pubKey.getPublic().mul(privKey.getPrivate());

}