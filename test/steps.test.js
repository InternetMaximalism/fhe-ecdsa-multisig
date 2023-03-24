import BN from "bn.js";
import { strict as assert } from "node:assert";
import { step1, step3, recoverEncryptedMultiSig } from "../alice.js";
import { step2 } from "../bob.js";
import { getMultiSigAddressPoint } from "../lib/getMultiSigAddressPoint.js";
import { EC } from "../lib/makek.js";
import { keccak256 } from "@ethersproject/keccak256";
import { serialize } from "@ethersproject/transactions";

var ec = new EC("secp256k1");

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
  const provider = new ethers.providers.JsonRpcProvider(
    `https://goerli.infura.io/v3/xxx`
  );

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
    var multiP = getMultiSigAddressPoint(alicekey, bobkey);
    var step1Data = await step1(alicekey, message);

    //Bob
    var fromBob = step2(step1Data.forBob, bobkey);
    assert.notEqual(fromBob, false);

    //Alice
    var signature = step3(fromBob, step1Data);

    var validity = recoverEncryptedMultiSig(message, multiP, signature);
    assert.equal(validity, true);

    sendSignature(txParams, signature);
  });
});
