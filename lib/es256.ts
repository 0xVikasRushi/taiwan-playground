import { p256 } from "@noble/curves/p256";
import { toByteArray, fromByteArray } from 'base64-js';
import { Ber } from 'asn1';
import { Uint8ArrayToCharArray, toCircomBigIntBytes, sha256Pad } from '@zk-email/helpers';
import { sha256 } from '@noble/hashes/sha256';
export const MAX_JWT_PADDED_BYTES = 1024;
import { strict as assert } from 'assert';

export interface Es256CircuitParams {
  n: number,
  k: number,
  maxMessageLength: number
}

export function generateEs256CircuitParams(params: number[]): Es256CircuitParams {
  return {
    n: params[0],
    k: params[1],
    maxMessageLength: params[2],
  };
}

function bigint_to_registers(x: bigint, n: number, k: number): bigint[] {
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

  return [bufferToBigInt(x), bufferToBigInt(y)]
}

function bufferToBigInt(buffer) {
  // Convert the buffer to a hexadecimal string then to BigInt.
  return BigInt('0x' + buffer.toString('hex'));
}

export interface JwkEcdsaPublicKey {
  kty: string,
  crv: string,
  kid?: string,
  x: string,
  y: string
}

export interface PemPublicKey {
  pem: string,
}

function base64ToBigInt(base64Str) {
  const buffer = Buffer.from(base64Str, 'base64');
  const hex = buffer.toString('hex');
  return BigInt('0x' + hex);
}

export function generateES256Inputs(params: Es256CircuitParams, message: string, b64Signature : string, pk: JwkEcdsaPublicKey | PemPublicKey) {
  assert.ok(message.length <= params.maxMessageLength);

  // decode signature
  let sig = Buffer.from(b64Signature, "base64url");
  let sig_decoded = p256.Signature.fromCompact(sig.toString('hex'));
  let sig_r = bigint_to_registers(sig_decoded.r, 43, 6);
  let sig_s = bigint_to_registers(sig_decoded.s, 43, 6);

  // decode public key  
  let x,y;
  if ('pem' in pk) {
    let pk1 = pk.pem.replace("-----BEGIN PUBLIC KEY-----", "").replace("-----END PUBLIC KEY-----", "").replaceAll("\n", "");
    [x, y] = get_x_y_from_pk(pk1);  
  } else {
    assert.ok(pk.kty == 'EC');
    assert.ok(pk.crv == 'P-256');
    [x,y] = [base64ToBigInt(pk.x), base64ToBigInt(pk.y)]
  }

  // internal check
  let pubkey = new p256.ProjectivePoint(x,y,1n);
  let check = p256.verify(sig.toString('hex'), Buffer.from(sha256(message)).toString('hex'), pubkey.toHex());
  assert.ok(check);

  // generate padded message
  let [messagePadded, messagePaddedLen] = sha256Pad(message, params.maxMessageLength);

  // return inputs
  return {
    sig_r: sig_r,
    sig_s: sig_s,
    pubkey: [bigint_to_registers(x, 43, 6), bigint_to_registers(y, 43, 6)],
    message: Uint8ArrayToCharArray(messagePadded),
    messageLength: messagePaddedLen.toString(),
  }
}
