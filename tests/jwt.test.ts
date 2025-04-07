import { wasm as wasm_tester } from 'circom_tester';
import path from 'path';

import { prepareES256Inputs } from '../lib/es256.ts';
import { strict as assert } from 'assert';

function string2input(s: string, padLength) {
  let values = Array.from(s).map(char => BigInt(char.charCodeAt(0)));
  while (values.length < padLength) {
    values.push(0n)
  }
  return values;
}

describe('ES256 Verifier Circuit', () => {
  jest.setTimeout(20 * 60 * 1000); // 10 minutes
  let circuit: any;
  let es256jwt: string;
  let pk: string;

  beforeAll(async () => {

    const RECOMPILE = true;

    circuit = await wasm_tester(path.join(__dirname, './test-circuits/jwt-test.circom'), {
      recompile: RECOMPILE,
      include: path.join(__dirname, '../node_modules'),
      output: path.join(__dirname, './compiled-test-circuits'),
    });
    console.log("end compiling circuit");

  });

  it('should verify a basic JWT', async () => {
    let token = "eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJEaW5vQ2hpZXNhLmdpdGh1Yi5pbyIsInN1YiI6ImFyeWEiLCJhdWQiOiJraW5hIiwiaWF0IjoxNzQzNjgyNzE3LCJleHAiOjE4NDM2ODMzMTcsImFhYSI6eyJwcm9wWCI6eyJhYWEiOiJpcHhhbXAwZWdjY3QweWYyb2t1dGo5In19fQ.2g_jAb5PeW8vErjOKbHbZIsxjcIFN_mD4-XqXZzcNKy8lM9Ef5DYALjOS-6sKW2j9kLWLwJ6g7bOj-erJTT6cg";
    let pk = `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE4zBhqu2TOhVW3BBZ2kYPgk5g2R8B
/cs8T/3PQxSPcsANh7Q9OXjDn+QVizLrWTze7hi0wAQzyl4ACRMV1PBZDg==
-----END PUBLIC KEY-----`;

    // payload is
    // {"iss":"DinoChiesa.github.io","sub":"arya","aud":"kina","iat":1743682717,"exp":1843683317,"aaa":{"propX":{"aaa":"ipxamp0egcct0yf2okutj9"}}}s

    const maxSubstringLength = 8;

    let [header, payload, signature] = token.split(".");

    let verifierInputs = prepareES256Inputs(Buffer.from(`${header}.${payload}`), signature, pk)
    verifierInputs["periodIndex"]=token.indexOf('.');

    verifierInputs["matchesCount"]=1n;
    let substr = `ipxa`; 
    verifierInputs["matchSubstring"]=[ string2input(substr, maxSubstringLength) ];
    verifierInputs["matchLength"]= [ substr.length ] ;
    verifierInputs["matchIndex"]= [ atob(payload).indexOf(substr) ];
    assert.ok(verifierInputs["matchIndex"][0] != -1);

    console.log("Computing witness...");
    const witness = await circuit.calculateWitness(verifierInputs);

    console.log("Checking constraints...");
    await circuit.checkConstraints(witness);

  });
});

