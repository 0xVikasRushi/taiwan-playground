import { Sha256 } from '@aws-crypto/sha256-js';
import { toByteArray, fromByteArray } from 'base64-js';
import bs58 from 'bs58';
import jwt from 'jsonwebtoken';
import { importSPKI } from 'jose';
import { strict as assert } from 'assert';
import pkg from 'safer-buffer';
const { Buffer } = pkg;
import { Ber } from 'asn1';
import { subtle, createVerify, KeyObject, createSecretKey, createPrivateKey } from 'crypto';

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

async function verify_jwt(jwt, [x, y]) {

  let [h, p, s] = jwt.split(".")

  const import_pk = await crypto.subtle.importKey(
    "jwk",
    {
      "kty": "EC",
      "crv": "P-256",
      "x": fromByteArray(x),
      "y": fromByteArray(y),
      "kid": "Public key used in JWS spec Appendix A.3 example"
    }
    ,
    {
      name: "ECDSA",
      namedCurve: "P-256"
    },
    true,
    ["verify"]
  );

  let success = await crypto.subtle.verify(
    {
      name: "ECDSA",
      hash: { name: "SHA-256" },
    },
    import_pk,
    toByteArrayPad(s),
    Buffer.from(h + "." + p),
  );

  return success;
}


async function verify_taiwan() {
  let token = "eyJqa3UiOiJodHRwczovL2lzc3Vlci12Yy11YXQud2FsbGV0Lmdvdi50dy9hcGkva2V5cyIsImtpZCI6ImtleS0xIiwidHlwIjoidmMrc2Qtand0IiwiYWxnIjoiRVMyNTYifQ.eyJzdWIiOiJkaWQ6a2V5OnpZcU52VkNrWVhhTXNGVVhEemJvRk1DMXRSV0ZjOHBUTGRONTgzb3FhcG9LNk1veno5dEVWVWpYU2lDN3Y2eXlOR0I4TW5DZUh1SE5hWlpzczFYS1E5dktzY2EyN0VIM0NQTXFSSnN5b2pqdXRyNEtrMzJaWVE0TDRjdHpZaDVHMWhrR1I3VFlhQ0Q3ekczWU1WS0V2dWQxejhZVnR5N2lxZzhBVTZxQ3hvS25ibkVVNnJEQSIsIm5iZiI6MTczOTgxNjY3MiwiaXNzIjoiZGlkOmtleTp6MmRtekQ4MWNnUHg4VmtpN0pidXVNbUZZcldQZ1lveXR5a1VaM2V5cWh0MWo5S2JzWTlEUnFTQ2d6elJ1RmJwcTlxd0pUTGtCbm1tQlhoZFNkcTZCREpSTXg2dENHMWp0a2R3Z0tYTmZOMXFXRVJEdnhhYzVyWTZoY25GUDdIdjYzaU01eTNWeHRNTjRUc3h5WnZibnJhcFcyUnBGb3ZFMURKNG03ZURWTFN1cUd0YzFpIiwiY25mIjp7Imp3ayI6eyJrdHkiOiJFQyIsImNydiI6IlAtMjU2IiwieCI6IlBrcV82ZDJpeUIwZGVvalYyLXlta0ZWeUpNeElfTDlHZVF4aDBORExoNDQ9IiwieSI6IjBOZnFMdmUtSXEwSFZZUE11eEctWHpRNUlmNktaOFhvQ0hkNmZOaDhsZFU9In19LCJleHAiOjY3OTc3NzcxODcyLCJ2YyI6eyJAY29udGV4dCI6WyJodHRwczovL3d3dy53My5vcmcvMjAxOC9jcmVkZW50aWFscy92MSJdLCJ0eXBlIjpbIlZlcmlmaWFibGVDcmVkZW50aWFsIiwiOTM1ODE5MjVfZGQiXSwiY3JlZGVudGlhbFN0YXR1cyI6eyJ0eXBlIjoiU3RhdHVzTGlzdDIwMjFFbnRyeSIsImlkIjoiaHR0cHM6Ly9pc3N1ZXItdmMtdWF0LndhbGxldC5nb3YudHcvYXBpL3N0YXR1cy1saXN0LzkzNTgxOTI1X2RkL3IwIzYiLCJzdGF0dXNMaXN0SW5kZXgiOiI2Iiwic3RhdHVzTGlzdENyZWRlbnRpYWwiOiJodHRwczovL2lzc3Vlci12Yy11YXQud2FsbGV0Lmdvdi50dy9hcGkvc3RhdHVzLWxpc3QvOTM1ODE5MjVfZGQvcjAiLCJzdGF0dXNQdXJwb3NlIjoicmV2b2NhdGlvbiJ9LCJjcmVkZW50aWFsU2NoZW1hIjp7ImlkIjoiaHR0cHM6Ly9mcm9udGVuZC11YXQud2FsbGV0Lmdvdi50dy9hcGkvc2NoZW1hLzkzNTgxOTI1L2RkL1YxL2Q0ZDFhMGY5LTNmMDktNGMyZS1iODk5LTA4YzM0NDkwYzhlYSIsInR5cGUiOiJKc29uU2NoZW1hIn0sImNyZWRlbnRpYWxTdWJqZWN0Ijp7Il9zZCI6WyJKY2lHYzViS2lkT0dteGp1dkM4TGRVeWthVlhCWEJQaEJYMWtYcERlLUxvIiwicFZPdzJOajU3RzJOa2VWSEJDV3doRUJqdWZTSmhwOWxwM201VzltQWg5QSJdLCJfc2RfYWxnIjoic2hhLTI1NiJ9fSwibm9uY2UiOiJCSElDVTI2TiIsImp0aSI6Imh0dHBzOi8vaXNzdWVyLXZjLXVhdC53YWxsZXQuZ292LnR3L2FwaS9jcmVkZW50aWFsLzRmYzNiYTY1LTY1ZGQtNDEyNC05ZTczLWNhOWY0OWNkNzc2NyJ9.h0wBjwjBDb48wZ_XVWnnrRrWh2Sgd4Lq7sc72N54svJFklnFuHebxvn-Ui6jftnQbPnLTKEyJbE75DatCkfkdQ~WyJ1cWJ5Y0VSZlN4RXF1a0dtWGwyXzl3IiwibmFtZSIsImRlbmtlbmkiXQ~WyJYMXllNDloV0s1bTJneWFBLXROQXRnIiwicm9jX2JpcnRoZGF5IiwiMDc1MDEwMSJd~\\";
  let keys = {
    "keys": [
      {
        "kty": "EC",
        "crv": "P-256",
        "kid": "key-1",
        "x": "rJUIrWnliWn5brtxVJPlGNZl2hKTosVMlWDc-G-gScM",
        "y": "mm3p9quG010NysYgK-CAQz2E-wTVSNeIHl_HvWaaM6I"
      },
      {
        "kty": "EC",
        "crv": "P-256",
        "kid": "key-2",
        "x": "9CNEmxkQimYxZtsoLuHyu2w_dHrVWrXapZzpYE0qm78",
        "y": "1FNwzxeSbIAcMlsvtx3iGzyUwoAyldffbvshNooWy2Q"
      }
    ]
  }
  let [h, p, s] = token.split(".") 
  const import_pk = await crypto.subtle.importKey(
    "jwk",
    keys['keys'][0],
    {
      name: "ECDSA",
      namedCurve: "P-256"
    },
    true,
    ["verify"]
  );

  let success = await crypto.subtle.verify(
    {
      name: "ECDSA",
      hash: { name: "SHA-256" },
    },
    import_pk,
    toByteArrayPad(s),
    Buffer.from(h + "." + p),
  );

  return success;
}

let es256jwt = "eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJEaW5vQ2hpZXNhLmdpdGh1Yi5pbyIsInN1YiI6ImFyeWEiLCJhdWQiOiJraW5hIiwiaWF0IjoxNzQzNjgyNzE3LCJleHAiOjE4NDM2ODMzMTcsImFhYSI6eyJwcm9wWCI6eyJhYWEiOiJpcHhhbXAwZWdjY3QweWYyb2t1dGo5In19fQ.2g_jAb5PeW8vErjOKbHbZIsxjcIFN_mD4-XqXZzcNKy8lM9Ef5DYALjOS-6sKW2j9kLWLwJ6g7bOj-erJTT6cg";
let pk = `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE4zBhqu2TOhVW3BBZ2kYPgk5g2R8B
/cs8T/3PQxSPcsANh7Q9OXjDn+QVizLrWTze7hi0wAQzyl4ACRMV1PBZDg==
-----END PUBLIC KEY-----`;

// verify with jsonwebtoken 
let _ = jwt.verify(es256jwt, pk)

let pk1 = pk.replace("-----BEGIN PUBLIC KEY-----", "").replace("-----END PUBLIC KEY-----", "").replaceAll("\n", "");

let [x, y] = get_x_y_from_pk(pk1);
assert.ok(await verify_jwt(es256jwt, [x, y]));

let modified_es256jwt = es256jwt.replace("eyJhbGciOiJFUzI1NiJ9", "eyJhbGciOiJFUzI1NiJ0");
assert.ok(!await verify_jwt(modified_es256jwt, [x, y]));


console.log(await verify_taiwan());