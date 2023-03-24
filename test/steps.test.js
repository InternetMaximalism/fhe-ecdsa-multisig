import BN from "bn.js";
import { strict as assert } from "node:assert";
import { step1, step3 } from "../alice.js";
import { step2 } from "../bob.js";
import { getMultiSigAddressPoint } from "../lib/getMultiSigAddressPoint.js";
import { EC } from "../lib/makek.js";

var ec = new EC("secp256k1");

describe("test for exported functions", async function () {
  it("checknpx", async function () {
    var message = new BN("158293048502934850342985029384584350945309458");
    //Alice
    var alicekey = ec.genKeyPair();
    var bobkey = ec.genKeyPair();
    var multiP = getMultiSigAddressPoint(alicekey, bobkey);
    var step1Data = await step1(alicekey, message);

    //Bob
    var fromBob = step2(step1Data.forBob, bobkey);
    assert.notEqual(fromBob, false);

    //Alice
    var signature = step3(fromBob, step1Data, multiP);
    assert.equal(signature.result, true);
  });
});
