import BN from "bn.js";
import { strict as assert } from "node:assert";
import {
  decryptMatrixToBN,
  LWEaddMatrix,
  LWEencrypt,
  LWEsetup,
  LWEsmul,
} from "nodeseal-bn";
import { EC } from "../lib/makek.js";

var ec = new EC("secp256k1");

describe("unit tests", async function () {
  it("simple test", async function () {
    var message = new BN("113235254334098504928004375928");
    //Alice
    var alicek = ec.makeK(message, ec);
    //Bob
    var bobk = ec.makeK(message, ec);
    var instantNumber = ec.makeK(message, ec); //.umod(new BN("1000000000000000000"));
    instantNumber = instantNumber.k.umod(
      new BN("1000000000000000000000000000000")
    );
    // sig here [important]

    var multiK = alicek.kp.mul(bobk.k);
    console.log("diff check", alicek.k.toString() !== bobk.k.toString());

    //Alice
    var key = ec.genKeyPair();
    var setup = await LWEsetup();
    var encPriv = await LWEencrypt(
      setup.encryptor,
      key.getPrivate(),
      setup.encoder
    );

    //Bob
    var bobkey = ec.genKeyPair();
    var multiP = key.getPublic().mul(bobkey.getPrivate());
    var multiP_ = bobkey.getPublic().mul(key.getPrivate());
    assert.equal(multiP.getX().toString(), multiP_.getX().toString());

    var seal = setup.seal;
    //console.log(bobk.k.toString());
    var input = bobk.kinv
      .mul(message)
      .umod(bobk.n)
      .add(bobk.n.mul(instantNumber));
    var cipherTex0 = await LWEencrypt(setup.encryptor, input, setup.encoder);
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
    var cipherTex1 = await LWEsmul(
      setup.evaluator,
      setup.encoder,
      encPriv,
      input2,
      setup.seal
    );

    var c2 = await LWEaddMatrix(
      setup.evaluator,
      cipherTex00.contents,
      cipherTex1.contents,
      seal
    );
    var dec = await decryptMatrixToBN(
      setup.decryptor,
      c2.contents,
      setup.encoder
    );

    var s = dec.mul(new BN(alicek.kinv)).umod(alicek.n);
    var sinv = s.invm(alicek.n);

    var u1 = sinv.mul(message).umod(alicek.n);
    var u2 = sinv.mul(multiK.getX()).umod(alicek.n);
    var p;
    p = ec.g.mul(u1);
    var p2 = multiP.mul(u2);
    p = p.add(p2);
    assert.equal(p.x.toString(), multiK.getX().toString());
  });
});
