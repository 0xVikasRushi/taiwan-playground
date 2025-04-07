import fs from 'fs';
import path from 'path';
import { wasm as wasm_tester } from 'circom_tester';
import { p256 } from "@noble/curves/p256";
import { toByteArray, fromByteArray } from 'base64-js';
import { Ber } from 'asn1';
import { Uint8ArrayToCharArray, toCircomBigIntBytes, sha256Pad } from '@zk-email/helpers';
import { sha256 } from '@noble/hashes/sha256';
export const MAX_JWT_PADDED_BYTES = 1024;
import { strict as assert } from 'assert';

export function uint8ArrayToBigInt(x: Uint8Array): bigint {
  return BigInt('0x'+Buffer.from(x).toString('hex'));
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

  const xy = buffer.slice(2)
  const x = xy.slice(0, 32);
  const y = xy.slice(32);

  return [x, y]
}

function bufferToBigInt(buffer) {
  // Convert the buffer to a hexadecimal string then to BigInt.
  return BigInt('0x' + buffer.toString('hex'));
}

function prepareMessage(
  headerString: string,
  payloadString: string,
  maxMessageLength,
): [Uint8Array, number] {
  const message = Buffer.from(`${headerString}.${payloadString}`);
  return sha256Pad(message, maxMessageLength || MAX_JWT_PADDED_BYTES);
}

function verify_jwt(token, pk) {

}

describe('JWT Verifier Circuit', () => {
  jest.setTimeout(10 * 60 * 1000); // 10 minutes
  let circuit : any;
  let es256jwt : string;
  let pk : string;

  beforeAll(async () => {
    let es256jwt = "eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJEaW5vQ2hpZXNhLmdpdGh1Yi5pbyIsInN1YiI6ImFyeWEiLCJhdWQiOiJraW5hIiwiaWF0IjoxNzQzNjgyNzE3LCJleHAiOjE4NDM2ODMzMTcsImFhYSI6eyJwcm9wWCI6eyJhYWEiOiJpcHhhbXAwZWdjY3QweWYyb2t1dGo5In19fQ.2g_jAb5PeW8vErjOKbHbZIsxjcIFN_mD4-XqXZzcNKy8lM9Ef5DYALjOS-6sKW2j9kLWLwJ6g7bOj-erJTT6cg";
    let pk = `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE4zBhqu2TOhVW3BBZ2kYPgk5g2R8B
/cs8T/3PQxSPcsANh7Q9OXjDn+QVizLrWTze7hi0wAQzyl4ACRMV1PBZDg==
-----END PUBLIC KEY-----`;

    let [h,p,s] = es256jwt.split(".");

    let hash = sha256(h+"."+p);
    let sig = Buffer.from(s, "base64url");

    let pk1 = pk.replace("-----BEGIN PUBLIC KEY-----", "").replace("-----END PUBLIC KEY-----", "").replaceAll("\n", "");
    let [x,y] = get_x_y_from_pk(pk1);
    let pubkey = new p256.ProjectivePoint(
      bufferToBigInt(x), 
      bufferToBigInt(y),
      1n
    );
    
    let res = p256.verify(sig.toString('hex'),  Buffer.from(hash).toString('hex'), pubkey.toHex());

    console.log("===>"+res)

    assert.ok(res);

    console.log("begin compiling circuit");
    
    const RECOMPILE = false;
    
    circuit = await wasm_tester(path.join(__dirname, './test-circuits/jwt-es256-verifier-test.circom'), {
      recompile: RECOMPILE,
      include: path.join(__dirname, '../node_modules'),
      output: path.join(__dirname, './compiled-test-circuits'),
    });
    console.log("end compiling circuit");



  });

  it('should verify a basic JWT', async () => {
    let es256jwt = "eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJEaW5vQ2hpZXNhLmdpdGh1Yi5pbyIsInN1YiI6ImFyeWEiLCJhdWQiOiJraW5hIiwiaWF0IjoxNzQzNjgyNzE3LCJleHAiOjE4NDM2ODMzMTcsImFhYSI6eyJwcm9wWCI6eyJhYWEiOiJpcHhhbXAwZWdjY3QweWYyb2t1dGo5In19fQ.2g_jAb5PeW8vErjOKbHbZIsxjcIFN_mD4-XqXZzcNKy8lM9Ef5DYALjOS-6sKW2j9kLWLwJ6g7bOj-erJTT6cg";
    let pk = `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE4zBhqu2TOhVW3BBZ2kYPgk5g2R8B
/cs8T/3PQxSPcsANh7Q9OXjDn+QVizLrWTze7hi0wAQzyl4ACRMV1PBZDg==
-----END PUBLIC KEY-----`;


    let [header,payload,signature] = es256jwt.split(".");

    let sig = Buffer.from(signature, "base64url");
    let sig_decoded = p256.Signature.fromCompact(sig.toString('hex'));
    let sig_r = bigint_to_registers(sig_decoded.r, 43, 6);
    let sig_s = bigint_to_registers(sig_decoded.s, 43, 6);

    let pk1 = pk.replace("-----BEGIN PUBLIC KEY-----", "").replace("-----END PUBLIC KEY-----", "").replaceAll("\n", "");
    let [x,y] = get_x_y_from_pk(pk1);
    let pubkey = new p256.ProjectivePoint(
      bufferToBigInt(x), 
      bufferToBigInt(y),
      1n
    );
    console.log("Checking the signature with library...")
    let check = p256.verify(sig.toString('hex'),  Buffer.from(sha256(header+"."+payload)).toString('hex'), pubkey.toHex());
    assert.ok(check);

    let [pb_x,pb_y] = [ bufferToBigInt(x), bufferToBigInt(y)];
    let [messagePadded, messagePaddedLen] = prepareMessage(header,payload, 1024 ); 

    const verifierInputs =  {
        sig_r : sig_r,
        sig_s : sig_s,
        pubkey : [bigint_to_registers(pb_x, 43, 6), bigint_to_registers(pb_y, 43, 6)],
        message: Uint8ArrayToCharArray(messagePadded),
        messageLength: messagePaddedLen.toString(),
    }
 
    console.log("Computing witness...");
    const witness = await circuit.calculateWitness(verifierInputs);

    console.log("Checking constraints...");
    await circuit.checkConstraints(witness);

  });
});

