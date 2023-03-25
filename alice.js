import { hexZeroPad, joinSignature } from "@ethersproject/bytes";
import { recoverAddress } from "@ethersproject/transactions";
import BN from "bn.js";
import { randomBytes } from "crypto";
import { decryptMatrixToBN, LWEencrypt, LWEsetup } from "nodeseal-bn";
import { EC } from "./lib/makek.js";

var ec = new EC("secp256k1");

export async function step1(aliceKey, message) {
  var alicek = ec.makeK(message, ec);
  var setup = await LWEsetup();
  var challengeMsg = _generateRandomBN();

  var alicekInsKey = ec.keyFromPrivate(alicek.k.toJSON(), "hex");
  var aliceKSig = alicekInsKey.sign(challengeMsg, ec);
  var aliceInsPubKey = ec.keyFromPublic(alicekInsKey.getPublic(), "hex");

  var decryptor = setup.decryptor;

  var setupWithoutDecryptor = setup;
  setupWithoutDecryptor.decryptor = false; //erase the decryptor(private key)

  var encPriv = LWEencrypt(
    setup.encryptor,
    aliceKey.getPrivate(),
    setup.encoder
  );
  var aliceKSig = ec.sign(challengeMsg, alicekInsKey);
  var forBob = {
    setup: setupWithoutDecryptor,
    alicekPubKey: aliceInsPubKey,
    aliceKSig: aliceKSig,
    encPriv: encPriv,
    message: message,
    challengeMsg: challengeMsg,
  };

  return { setup: setup, k: alicek, forBob: forBob, decryptor: decryptor };
}

export function step3(fromBob, step1Data) {
  var det = _verifyMultiK(fromBob, step1Data.forBob, step1Data.k);
  if (!det) {
    console.log("here");
    return false;
  }
  var data = _calcSignature(
    step1Data,
    fromBob.cipherTextMatrix,
    step1Data.k,
    fromBob.multiK
  );
  return data;
}

function _generateRandomBN() {
  const value = randomBytes(32);
  const bn = new BN(value.toString("hex"), 16);
  return bn;
}

function _verifyMultiK(fromBob, forBob, alicek) {
  if (ec.verify(forBob.challengeMsg, fromBob.signature, fromBob.bobKPubKey)) {
    if (
      fromBob.multiK.getX().toString() ===
      fromBob.bobKPubKey.getPublic().mul(alicek.k).getX().toString()
    ) {
      return true;
    }
  }
  return false;
}

function _calcSignature(step1Data, cipherTextMatrix, alicek, multiK) {
  let s = decryptMatrixToBN(
    step1Data.decryptor,
    cipherTextMatrix.contents,
    step1Data.setup.encoder
  );
  s = s.mul(new BN(alicek.kinv)).umod(alicek.n);
  // if (
  //   s.gte(
  //     new BN(
  //       "7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0",
  //       "hex"
  //     )
  //   )
  // ) {
  //   s = alicek.n.sub(s);
  // }

  const signature = getSignature(multiK, s);

  return signature;
}

export function recoverEncryptedMultiSig(message, address, signature) {
  const digest = message.toArray();
  const recoveredAddress = recoverAddress(digest, signature);

  return {
    result: address === recoveredAddress,
    signature: joinSignature(signature),
  };
}

function getSignature(multiK, s) {
  const n = multiK.curve.n;
  const nh = multiK.curve.n.ushrn(1);

  var kpX = multiK.getX();
  var r = kpX.umod(n);
  if (r.cmpn(0) === 0) {
    throw new Error("invalid signature");
  }

  var recoveryParam =
    (multiK.getY().isOdd() ? 1 : 0) | (multiK.getX().cmp(r) !== 0 ? 2 : 0);

  //  Use complement of `s`, if it is > `n / 2`
  if (s.cmp(nh) > 0) {
    s = n.sub(s);
    recoveryParam ^= 1;
  }
  const signature = {
    recoveryParam,
    r: multiK.getX(),
    s,
  };

  return {
    recoveryParam: signature.recoveryParam,
    r: hexZeroPad("0x" + signature.r.toString(16), 32),
    s: hexZeroPad("0x" + signature.s.toString(16), 32),
  };
}
