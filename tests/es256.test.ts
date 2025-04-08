import { WitnessTester } from "circomkit";
import { circomkit } from "./common";
import { generateEs256CircuitParams, generateES256Inputs } from "../src/es256";

describe("ES256 Verifier Circuit", () => {
  let circuit: WitnessTester<["message", "messageLength", "sig_r", "sig_s", "pubkey"]>;

  describe("ES256 Circuit", () => {
    before(async () => {
      circuit = await circomkit.WitnessTester(`ES256`, {
        file: "es256",
        template: "ES256",
        params: [43, 6, 1024],
      });
      console.log("#constraints:", await circuit.getConstraintCount());
    });

    it("should verify ecdsa signature", async () => {
      let es256jwt =
        "eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJEaW5vQ2hpZXNhLmdpdGh1Yi5pbyIsInN1YiI6ImFyeWEiLCJhdWQiOiJraW5hIiwiaWF0IjoxNzQzNjgyNzE3LCJleHAiOjE4NDM2ODMzMTcsImFhYSI6eyJwcm9wWCI6eyJhYWEiOiJpcHhhbXAwZWdjY3QweWYyb2t1dGo5In19fQ.2g_jAb5PeW8vErjOKbHbZIsxjcIFN_mD4-XqXZzcNKy8lM9Ef5DYALjOS-6sKW2j9kLWLwJ6g7bOj-erJTT6cg";
      let pk = `-----BEGIN PUBLIC KEY-----
  MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE4zBhqu2TOhVW3BBZ2kYPgk5g2R8B
  /cs8T/3PQxSPcsANh7Q9OXjDn+QVizLrWTze7hi0wAQzyl4ACRMV1PBZDg==
  -----END PUBLIC KEY-----`;

      let [header, payload, signature] = es256jwt.split(".");

      let params = generateEs256CircuitParams([43, 6, 1024]);
      let verifierInputs = generateES256Inputs(params, Buffer.from(`${header}.${payload}`), signature, pk);
      let witness = await circuit.calculateWitness(verifierInputs);

      console.log("Checking constraints...");
      await circuit.expectConstraintPass(witness);

      console.log("ES256 Circuit verified");
    });
  });
});
