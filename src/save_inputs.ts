import { generateEs256CircuitParams, generateES256Inputs } from "./es256";
import fs from "fs";
import { generateJwtCircuitParams, generateJwtInputs } from "./jwt";
import { string2input } from "./utils";

function saveES256Inputs() {
  let es256jwt =
    "eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJEaW5vQ2hpZXNhLmdpdGh1Yi5pbyIsInN1YiI6ImFyeWEiLCJhdWQiOiJraW5hIiwiaWF0IjoxNzQzNjgyNzE3LCJleHAiOjE4NDM2ODMzMTcsImFhYSI6eyJwcm9wWCI6eyJhYWEiOiJpcHhhbXAwZWdjY3QweWYyb2t1dGo5In19fQ.2g_jAb5PeW8vErjOKbHbZIsxjcIFN_mD4-XqXZzcNKy8lM9Ef5DYALjOS-6sKW2j9kLWLwJ6g7bOj-erJTT6cg";
  let pk = `-----BEGIN PUBLIC KEY-----
      MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE4zBhqu2TOhVW3BBZ2kYPgk5g2R8B
      /cs8T/3PQxSPcsANh7Q9OXjDn+QVizLrWTze7hi0wAQzyl4ACRMV1PBZDg==
      -----END PUBLIC KEY-----`;

  let [header, payload, signature] = es256jwt.split(".");

  let params = generateEs256CircuitParams([43, 6, 1024]);
  let verifierInputs = generateES256Inputs(params, Buffer.from(`${header}.${payload}`), signature, { pem: pk });

  fs.writeFileSync(
    "inputs/es256/default.json",
    JSON.stringify(verifierInputs, (_, v) => (typeof v === "bigint" ? v.toString() : v), 2)
  );

  console.log("ES256 inputs saved to ../es256/default.json");
}

function saveJWTInputs() {
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
  fs.writeFileSync(
    "inputs/jwt/default.json",
    JSON.stringify(inputs, (_, v) => (typeof v === "bigint" ? v.toString() : v), 2)
  );
  console.log("JWT inputs saved to ../jwt/default.json");
}

function saveMatcherInputs() {
  let text = `{"iss":"DinoChiesa.github.io","sub":"arya","aud":"kina","iat":1743682717,"exp":1843683317,"aaa":{"propX":{"aaa":"ipxamp0egcct0yf2okutj9"}}}`;
  let substr = `ipxa`;
  const maxTextLength = 256;
  const maxSubstringLength = 8;

  let inputs: any = {};
  inputs["enabled"] = 1n;
  inputs["text"] = string2input(text, maxTextLength);
  inputs["textLength"] = text.length;
  inputs["substring"] = string2input(substr, maxSubstringLength);
  inputs["substringLength"] = substr.length;
  inputs["substringIndex"] = text.indexOf(substr);

  // Convert BigInts to strings so JSON.stringify works
  const replacer = (_key: string, value: any) => (typeof value === "bigint" ? value.toString() : value);

  fs.writeFileSync("inputs/matcher/default.json", JSON.stringify(inputs, replacer, 2));
  console.log("Matcher inputs saved to ../matcher/default.json");
}

function main() {
  saveMatcherInputs();
  saveES256Inputs();
  saveJWTInputs();
}
main();
