//this is a wrapper of EC function here
//https://github.com/indutny/elliptic/blob/master/lib/elliptic/ec/index.js

import BN from "bn.js";
import elliptic from "elliptic";
import HmacDRBG from "hmac-drbg";
var EC = elliptic.ec;

// This function is makeing a ramdom number 'k' (sometimes it's 's') in the ECDSA
EC.prototype.makeK = function makeK(msg, ec) {
  // Zero-extend key to provide enough entropy
  msg = this._truncateToN(new BN(msg, 16));
  var bytes = this.n.byteLength();
  var bkey = ec.genKeyPair().getPrivate().toArray("be", bytes);

  // Zero-extend nonce to have the same byte size as N
  var nonce = msg.toArray("be", bytes);

  // Instantiate Hmac_DRBG
  var drbg = new HmacDRBG({
    hash: this.hash,
    entropy: bkey,
    nonce: nonce,
    pers: ec.pers,
    persEnc: ec.persEnc || "utf8",
  });

  // Number of bytes to generate
  var ns1 = this.n.sub(new BN(1));

  var k = new BN(drbg.generate(this.n.byteLength()));
  k = this._truncateToN(k, true);
  if (k.cmpn(1) <= 0 || k.cmp(ns1) >= 0) return false;

  var kp = this.g.mul(k);
  if (kp.isInfinity()) return false;

  var kpX = kp.getX();
  var r = kpX.umod(this.n);
  if (r.cmpn(0) === 0) return false;
  return { r: r, k: k, kpx: kpX, kinv: k.invm(this.n), kp: kp, n: this.n };
};
export var EC;
