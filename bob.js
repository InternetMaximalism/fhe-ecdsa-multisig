import BN from "bn.js";
import { LWEaddMatrix, LWEencrypt, LWEsmul } from "nodeseal-bn";
import { EC } from "./lib/makek.js";

var ec = new EC("secp256k1");

export function step2(forBob, bobkey) {
  if (!ec.verify(forBob.challengeMsg, forBob.aliceKSig, forBob.alicekPubKey)) {
    return false;
  }

  var bobk = ec.makeK(forBob.message, ec);
  var multiK = forBob.alicekPubKey.getPublic().mul(bobk.k);
  var bobkInsKey = ec.keyFromPrivate(bobk.k.toJSON(), "hex");
  var signature = ec.sign(forBob.challengeMsg, bobkInsKey);
  var bobInsPubKey = ec.keyFromPublic(bobkInsKey.getPublic(), "hex");

  var fromBob = {
    multiK: multiK,
    signature: signature,
    cipherTextMatrix: false,
    bobKPubKey: bobInsPubKey,
  };
  fromBob.cipherTextMatrix = _calculateCipherText(
    bobkey,
    bobk,
    forBob.setup,
    forBob.message,
    multiK,
    forBob.encPriv
  );

  return fromBob;
}

function _calculateCipherText(bobkey, bobk, setup, message, multiK, encPriv) {
  var instantNumber = ec.makeK(message, ec);
  instantNumber = instantNumber.k.umod(
    new BN("1000000000000000000000000000000")
  );

  var input = bobk.kinv
    .mul(message)
    .umod(bobk.n)
    .add(bobk.n.mul(instantNumber));
  var cipherTex0 = LWEencrypt(setup.encryptor, input, setup.encoder);
  var cipherTex00 = LWEsmul(
    setup.evaluator,
    setup.encoder,
    cipherTex0,
    new BN(1),
    setup.seal
  );

  var input2 = bobk.kinv
    .mul(new BN(bobkey.getPrivate()))
    .mul(new BN(multiK.getX()))
    .umod(bobk.n);
  var cipherTex1 = LWEsmul(
    setup.evaluator,
    setup.encoder,
    encPriv,
    input2,
    setup.seal
  );

  var c2 = LWEaddMatrix(
    setup.evaluator,
    cipherTex00.contents,
    cipherTex1.contents,
    setup.seal
  );
  return c2;
}
