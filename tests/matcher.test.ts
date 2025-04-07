import { wasm as wasm_tester } from 'circom_tester';
import path from 'path';
import { strict as assert } from 'assert';

function string2input(s: string, padLength) {
  let values = Array.from(s).map(char => BigInt(char.charCodeAt(0)));
  while (values.length < padLength) {
    values.push(0n)
  }
  return values;
}

describe('Matcher Circuit', () => {
  let circuit: any;

  beforeAll(async () => {

    const RECOMPILE = true;

    circuit = await wasm_tester(path.join(__dirname, './test-circuits/matcher-test.circom'), {
      recompile: RECOMPILE,
      include: path.join(__dirname, '../node_modules'),
      output: path.join(__dirname, './compiled-test-circuits'),
    });
    console.log("end compiling circuit");

  });

  it('Match test', async () => {
 
    const maxTextLength = 256;
    const maxSubstringLength = 8;

    let text = `{"iss":"DinoChiesa.github.io","sub":"arya","aud":"kina","iat":1743682717,"exp":1843683317,"aaa":{"propX":{"aaa":"ipxamp0egcct0yf2okutj9"}}}`;
    let substr = `ipxa`; 
    
    let inputs = [];
    inputs["enabled"] = 1n;
    inputs["text"] = string2input(text, maxTextLength);
    inputs["textLength"] = text.length;
    inputs["substring"]=string2input(substr,maxSubstringLength);
    inputs["substringLength"]=substr.length;
    inputs["substringIndex"]=text.indexOf(substr);

    assert.ok(inputs["substringIndex"] != -1);

    console.log("Computing witness...");
    const witness = await circuit.calculateWitness(inputs);

    console.log("Checking constraints...");
    await circuit.checkConstraints(witness);

  });
});

