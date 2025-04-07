import { p256 } from "@noble/curves/p256";
import { toByteArray, fromByteArray } from 'base64-js';
import { Ber } from 'asn1';
import { Uint8ArrayToCharArray, toCircomBigIntBytes, sha256Pad } from '@zk-email/helpers';
import { sha256 } from '@noble/hashes/sha256';
export const MAX_JWT_PADDED_BYTES = 1024;
import { strict as assert } from 'assert';

export function uint8ArrayToBigInt(x: Uint8Array): bigint {
  return BigInt('0x' + Buffer.from(x).toString('hex'));
}

export function bigint_to_registers(x: bigint, n: number, k: number): bigint[] {
  let mod: bigint = 1n;
  for (var idx = 0; idx < n; idx++) {
    mod = mod * 2n;
  }

  let ret: bigint[] = [];
  var x_temp: bigint = x;
  for (var idx = 0; idx < k; idx++) {
    ret.push(x_temp % mod);
    x_temp = x_temp / mod;
  }
  return ret;
}

function toByteArrayPad(s) {
  while (s.length % 4 != 0) {
    s = s + "=";
  }
  return toByteArray(s);
}
function get_x_y_from_pk(pk) {
  var pk1 = toByteArray(pk);
  var reader = new Ber.Reader(Buffer.from(pk1));
  reader.readSequence();
  reader.readSequence();
  reader.readOID();
  reader.readOID();

  let buffer = Buffer.alloc(64)
  buffer = reader.readString(3, buffer);

  const xy = buffer.subarray(2)
  const x = xy.subarray(0, 32);
  const y = xy.subarray(32);

  return [x, y]
}

function bufferToBigInt(buffer) {
  // Convert the buffer to a hexadecimal string then to BigInt.
  return BigInt('0x' + buffer.toString('hex'));
}

export function prepareES256Inputs(message, signature, pk) {
  let sig = Buffer.from(signature, "base64url");
  let sig_decoded = p256.Signature.fromCompact(sig.toString('hex'));
  let sig_r = bigint_to_registers(sig_decoded.r, 43, 6);
  let sig_s = bigint_to_registers(sig_decoded.s, 43, 6);

  let pk1 = pk.replace("-----BEGIN PUBLIC KEY-----", "").replace("-----END PUBLIC KEY-----", "").replaceAll("\n", "");
  let [x, y] = get_x_y_from_pk(pk1);
  let pubkey = new p256.ProjectivePoint(
    bufferToBigInt(x),
    bufferToBigInt(y),
    1n
  );

  console.log("Checking the signature with library...")
  let check = p256.verify(sig.toString('hex'), Buffer.from(sha256(message)).toString('hex'), pubkey.toHex());
  assert.ok(check);

  let [pb_x, pb_y] = [bufferToBigInt(x), bufferToBigInt(y)];
  let [messagePadded, messagePaddedLen] = sha256Pad(message, MAX_JWT_PADDED_BYTES);

  return {
    sig_r: sig_r,
    sig_s: sig_s,
    pubkey: [bigint_to_registers(pb_x, 43, 6), bigint_to_registers(pb_y, 43, 6)],
    message: Uint8ArrayToCharArray(messagePadded),
    messageLength: messagePaddedLen.toString(),
  }
}
