import { wasm as wasm_tester } from 'circom_tester';
import path from 'path';

import { generateES256Inputs, generateEs256CircuitParams } from '../lib/es256.ts';

describe('ES256 Verifier Circuit', () => {
  jest.setTimeout(20 * 60 * 1000); // 10 minutes
  let circuit: any;
  let es256jwt: string;
  let pk: string;

  beforeAll(async () => {

    const RECOMPILE = true;

    circuit = await wasm_tester(path.join(__dirname, './test-circuits/es256-test.circom'), {
      recompile: RECOMPILE,
      include: path.join(__dirname, '../node_modules'),
      output: path.join(__dirname, './compiled-test-circuits'),
    });
    console.log("end compiling circuit");

  });

  it('should verify a basic ES256 Signature', async () => {
    let es256jwt = "eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJEaW5vQ2hpZXNhLmdpdGh1Yi5pbyIsInN1YiI6ImFyeWEiLCJhdWQiOiJraW5hIiwiaWF0IjoxNzQzNjgyNzE3LCJleHAiOjE4NDM2ODMzMTcsImFhYSI6eyJwcm9wWCI6eyJhYWEiOiJpcHhhbXAwZWdjY3QweWYyb2t1dGo5In19fQ.2g_jAb5PeW8vErjOKbHbZIsxjcIFN_mD4-XqXZzcNKy8lM9Ef5DYALjOS-6sKW2j9kLWLwJ6g7bOj-erJTT6cg";
    let pk = `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE4zBhqu2TOhVW3BBZ2kYPgk5g2R8B
/cs8T/3PQxSPcsANh7Q9OXjDn+QVizLrWTze7hi0wAQzyl4ACRMV1PBZDg==
-----END PUBLIC KEY-----`;

    let [header, payload, signature] = es256jwt.split(".");

    let params = generateEs256CircuitParams([43,6,1024]); 
    let verifierInputs = generateES256Inputs(params, Buffer.from(`${header}.${payload}`), signature, pk)

    console.log("Computing witness...");
    const witness = await circuit.calculateWitness(verifierInputs);

    console.log("Checking constraints...");
    await circuit.checkConstraints(witness);

  });
});

