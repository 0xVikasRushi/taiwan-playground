import { WitnessTester } from "circomkit";
import { circomkit } from "./common";
import { generateJwtCircuitParams, generateJwtInputs } from "../src/jwt";
describe("ES256 Verifier Circuit", () => {
  let circuit: WitnessTester<
    [
      "message",
      "messageLength",
      "periodIndex",
      "sig_r",
      "sig_s",
      "pubkey",
      "matchesCount",
      "matchSubstring",
      "matchLength",
      "matchIndex"
    ],
    []
  >;

  describe("JWT Circuit", () => {
    before(async () => {
      const RECOMPILE = true;

      circuit = await circomkit.WitnessTester(`JWT`, {
        file: "jwt",
        template: "JWT",
        params: [43, 6, 1024, 256, 256, 5, 8],
        recompile: RECOMPILE,
      });
      console.log("#constraints:", await circuit.getConstraintCount());
    });

    it("should verify a basic JWT", async () => {
      let token =
        "eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJEaW5vQ2hpZXNhLmdpdGh1Yi5pbyIsInN1YiI6ImFyeWEiLCJhdWQiOiJraW5hIiwiaWF0IjoxNzQzNjgyNzE3LCJleHAiOjE4NDM2ODMzMTcsImFhYSI6eyJwcm9wWCI6eyJhYWEiOiJpcHhhbXAwZWdjY3QweWYyb2t1dGo5In19fQ.2g_jAb5PeW8vErjOKbHbZIsxjcIFN_mD4-XqXZzcNKy8lM9Ef5DYALjOS-6sKW2j9kLWLwJ6g7bOj-erJTT6cg";
      let pk = `-----BEGIN PUBLIC KEY-----
  MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE4zBhqu2TOhVW3BBZ2kYPgk5g2R8B
  /cs8T/3PQxSPcsANh7Q9OXjDn+QVizLrWTze7hi0wAQzyl4ACRMV1PBZDg==
  -----END PUBLIC KEY-----`;

      // payload is
      // {"iss":"DinoChiesa.github.io","sub":"arya","aud":"kina","iat":1743682717,"exp":1843683317,"aaa":{"propX":{"aaa":"ipxamp0egcct0yf2okutj9"}}}s

      const params = generateJwtCircuitParams([43, 6, 1024, 256, 256, 5, 8]);
      const inputs = generateJwtInputs(params, token, { pem: pk }, ["ipxa", `"iat"`]);

      console.log("Computing witness...");
      const witness = await circuit.calculateWitness(inputs);

      await circuit.expectConstraintPass(witness);
      console.log("JWT Circuit verified");
    });
  });
});
