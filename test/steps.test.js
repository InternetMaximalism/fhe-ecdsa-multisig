import { keccak256 } from "@ethersproject/keccak256";
import { serialize } from "@ethersproject/transactions";
import BN from "bn.js";
import { ethers } from "ethers";
import { strict as assert } from "node:assert";
import { recoverEncryptedMultiSig, step1, step3 } from "../alice.js";
import { step2 } from "../bob.js";
import {
  getMultiSigAddressPoint,
  getMultiSigPrivateKey,
  recoverAliceKeyFromMultiSigKey,
} from "../lib/getMultiSigAddressPoint.js";
import { EC } from "../lib/makek.js";

var ec = new EC("secp256k1");

const INFURA_URL = process.env.INFURA_URL;

const createTransaction = () => {
  const txParams = {
    nonce: "0x00",
    gasPrice: "0x09184e72a000",
    gasLimit: "0x2710",
    to: "0x0000000000000000000000000000000000000000",
    value: "0x00",
    data: "0x7f7465737432000000000000000000000000000000000000000000000000000000600057",
  };
  const hashedTx = keccak256(serialize(txParams));
  const message = new BN(hashedTx.slice(2), "hex");

  return { txParams, message };
};

export async function sendSignature(txParams, signature) {
  const provider = new ethers.providers.JsonRpcProvider(INFURA_URL);
  const signedTransaction = serialize(txParams, signature);
  const receipt = await provider.sendTransaction(signedTransaction);
  await receipt.wait();
}

describe("test for exported functions", async function () {
  it("checknpx", async function () {
    const { txParams, message } = createTransaction();

    //Alice
    var alicekey = ec.genKeyPair();
    var bobkey = ec.genKeyPair();
    var multiP = getMultiSigAddressPoint(alicekey, bobkey.getPublic());
    const address = ethers.utils.computeAddress(
      "0x" + multiP.encode("hex", false)
    );

    var step1Data = await step1(alicekey, message);

    //Bob
    var fromBob = step2(step1Data.forBob, bobkey);
    assert.notEqual(fromBob, false);

    //Alice
    var signature = step3(fromBob, step1Data);

    var { validity } = recoverEncryptedMultiSig(message, address, signature);
    assert.equal(validity, true);

    // sendSignature(txParams, signature);
  });

  it("recover Alice key from multi-sig key", async function () {
    const aliceKey = ec.genKeyPair();
    const bobKey = ec.genKeyPair();
    const multiSigKey = getMultiSigPrivateKey(aliceKey, bobKey);
    const recoveredAliceKey = recoverAliceKeyFromMultiSigKey(multiSigKey, bobKey);
    assert.ok(recoveredAliceKey.eq(aliceKey.getPrivate()));
  })
});
