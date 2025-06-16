// this is a wrapper of EC function here
// https://github.com/indutny/elliptic/blob/master/lib/elliptic/ec/index.js
// https://github.com/wevm/viem/blob/a4159d7c9ebda462ee88ce9f0ca3a23c5c820057/src/accounts/utils/sign.ts#L51
// https://github.com/paulmillr/noble-curves/blob/c16d7c0b041cf61ea5a73affad2f38c1423b0dab/src/abstract/weierstrass.ts#L1050

import BN from "bn.js";
import elliptic from "elliptic";
// import HmacDRBG from "hmac-drbg";
import { hmac } from "@noble/hashes/hmac";
import { sha256 } from "@noble/hashes/sha256";
import { concatBytes } from "@noble/hashes/utils";
import * as secp256k1 from "@noble/secp256k1";

var EC = elliptic.ec;

const { CURVE, etc } = secp256k1;
const N = CURVE.n; // Curve order
const fLen = 32; // Field length (32 bytes)

const err = (m = "") => {
  throw new Error(m);
};
const isu8 = (a) =>
  a instanceof Uint8Array ||
  (ArrayBuffer.isView(a) && a.constructor.name === "Uint8Array");
// assert is Uint8Array (of specific length)
const au8 = (a, l) =>
  !isu8(a) || (typeof l === "number" && l > 0 && a.length !== l)
    ? err("Uint8Array expected")
    : a;
const u8fr = (buf) => Uint8Array.from(buf);
const h2b = etc.hexToBytes;
const toU8 = (a, len) =>
  au8(typeof a === "string" ? h2b(a) : u8fr(au8(a)), len); // norm(hex/u8a) to u8a
// mod division
const M = (a, b) => {
  const r = a % b;
  return r >= 0n ? r : b + r;
};

// RFC6979: ensure ECDSA msg is X bytes.
const b2n = etc.bytesToNumberBE;
const bits2int = (bytes) => {
  const delta = bytes.length * 8 - 256; // RFC suggests optional truncating via bits2octets
  if (delta > 1024) err("msg invalid"); // our CUSTOM check, "just-in-case"
  const num = b2n(bytes); // FIPS 186-4 4.6 suggests the leftmost min(nBitLen, outLen) bits, which
  return delta > 0 ? num >> BigInt(delta) : num; // matches bits2int. bits2int can produce res>N.
};
const bits2int_modN = (bytes) => M(bits2int(bytes), N);
const ge = (n) => typeof n === "bigint" && 0n < n && n < N;
// p: Hex | bigint
const toPriv = (p) => {
  // normalize private key to bigint
  if (typeof p !== "bigint") p = b2n(toU8(p, fLen)); // convert to bigint when bytes
  return ge(p) ? p : err("private key invalid 3"); // check if bigint is in range
};

/**
 * Generate a deterministic k value based on RFC6979
 * @param {secp256k1.Bytes} msgHash - Message hash (32 bytes)
 * @param {secp256k1.Bytes | bigint} privateKey - Private key
 * @param options - Options
 * @param {boolean | secp256k1.Bytes} options.extraEntropy - Additional entropy (optional)
 * @returns Deterministically generated k value
 */
export const getDeterministicK = (msgHash, privateKey, options = {}) => {
  // Prepare arguments
  const h1i = bits2int_modN(toU8(msgHash));
  const h1o = etc.numberToBytesBE(h1i);
  const d = toPriv(privateKey);
  const do_ = etc.numberToBytesBE(d);

  // Prepare seed
  const seed = [do_, h1o];

  if (options.extraEntropy) {
    let ent = options.extraEntropy;
    if (ent === true) {
      // If true, generate random bytes
      ent = etc.randomBytes(fLen);
    } else {
      // Otherwise, use the provided entropy
      ent = toU8(ent);
    }
    seed.push(ent);
  }

  // Use HMAC-DRBG from RFC6979 to generate k value
  const v = new Uint8Array(fLen).fill(1);
  const k = new Uint8Array(fLen).fill(0);

  // // HMAC function
  // if (typeof etc.hmacSha256 !== "function") {
  //   throw new Error("etc.hmacSha256 not available");
  // }
  // const h = (...b) => etc.hmacSha256(k, v, ...b);
  const h = (key, ...msgs) => hmac(sha256, key, concatBytes(...msgs));

  // Apply initial seed
  const concatenatedSeed = etc.concatBytes(...seed);

  // Step D - Initialization
  let newK = h(k, v, new Uint8Array([0x00]), concatenatedSeed);
  let newV = h(newK, v);

  // Step E - If additional entropy is provided
  if (concatenatedSeed.length) {
    newK = h(newK, newV, new Uint8Array([0x01]), concatenatedSeed);
    newV = h(newK, newV);
  }

  // Step F, G - Generate k value
  let kVal;
  let counter = 0;

  while (true) {
    if (counter++ > 1000)
      throw new Error("Tried 1000 k values, all were invalid");
    newV = h(newK, newV);

    const T = newV;
    kVal = etc.bytesToNumberBE(T);

    // Check if k value is in valid range
    if (kVal > 0n && kVal < N) {
      break;
    }

    // If k value is invalid, generate a new seed
    newK = h(newK, newV, new Uint8Array([0x00]));
    newV = h(newK, newV);
  }

  return kVal;
};

// This function is makeing a ramdom number 'k' (sometimes it's 's') in the ECDSA
/**
 *
 * Generate a deterministic k value based on RFC6979
 * @param {number | string | number[] | Uint8Array | Buffer | BN} msg - Message hash (32 bytes)
 * @param {bigint} privateKey - Private key
 * @returns
 */
EC.prototype.makeK = function makeK(msg, keyPair) {
  const privateKey = BigInt("0x" + keyPair.getPrivate().toString(16));

  // Zero-extend key to provide enough entropy
  msg = this._truncateToN(new BN(msg, 16));
  var bytes = this.n.byteLength();
  // var bkey = ec.genKeyPair().getPrivate().toArray("be", bytes);

  // Zero-extend nonce to have the same byte size as N
  var nonce = new Uint8Array(msg.toArray("be", bytes));

  // // Instantiate Hmac_DRBG
  // var drbg = new HmacDRBG({
  //   hash: this.hash,
  //   entropy: bkey,
  //   nonce: nonce,
  //   pers: ec.pers,
  //   persEnc: ec.persEnc || "utf8",
  // });

  // Number of bytes to generate
  var ns1 = this.n.sub(new BN(1));

  // var k = new BN(drbg.generate(this.n.byteLength()));
  // k = this._truncateToN(k, true);
  const deterministicK = getDeterministicK(nonce, privateKey);
  const k = new BN(deterministicK.toString(), 10);
  if (k.cmpn(1) <= 0 || k.cmp(ns1) >= 0) return false;

  var kp = this.g.mul(k);
  if (kp.isInfinity()) return false;

  var kpX = kp.getX();
  var r = kpX.umod(this.n);
  if (r.cmpn(0) === 0) return false;
  return { r: r, k: k, kpx: kpX, kinv: k.invm(this.n), kp: kp, n: this.n };
};
export var EC;
