import { WitnessTester } from "circomkit";
import { circomkit } from "./common";
import assert from "assert";

function string2input(s: string, padLength: number) {
  let values = Array.from(s).map((char) => BigInt(char.charCodeAt(0)));
  while (values.length < padLength) {
    values.push(0n);
  }
  return values;
}

describe("Matcher Circuit", () => {
  let circuit: WitnessTester<["text", "textLength", "substring", "substringIndex", "substringLength", "enabled"], []>;

  const maxTextLength = 256;
  const maxSubstringLength = 8;

  describe("Match test", () => {
    before(async () => {
      circuit = await circomkit.WitnessTester(`Matcher`, {
        file: "matcher",
        template: "Matcher",
        params: [maxTextLength, maxSubstringLength],
      });
      console.log("#constraints:", await circuit.getConstraintCount());
    });

    it("should match substring", async () => {
      let text = `{"iss":"DinoChiesa.github.io","sub":"arya","aud":"kina","iat":1743682717,"exp":1843683317,"aaa":{"propX":{"aaa":"ipxamp0egcct0yf2okutj9"}}}`;
      let substr = `ipxa`;

      let inputs: any = [];
      inputs["enabled"] = 1n;
      inputs["text"] = string2input(text, maxTextLength);
      inputs["textLength"] = text.length;
      inputs["substring"] = string2input(substr, maxSubstringLength);
      inputs["substringLength"] = substr.length;
      inputs["substringIndex"] = text.indexOf(substr);

      assert(inputs["substringIndex"] != -1);

      const witness = await circuit.calculateWitness(inputs);
      await circuit.expectConstraintPass(witness);
    });
  });
});
