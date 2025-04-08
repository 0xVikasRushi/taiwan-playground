import { Sha256 } from "@aws-crypto/sha256-js";
import { toByteArray, fromByteArray } from "base64-js";
import bs58 from "bs58";
import jwt from "jsonwebtoken";
import { importSPKI } from "jose";

const token =
  "eyJqa3UiOiJodHRwczovL2lzc3Vlci12Yy11YXQud2FsbGV0Lmdvdi50dy9hcGkva2V5cyIsImtpZCI6ImtleS0xIiwidHlwIjoidmMrc2Qtand0IiwiYWxnIjoiRVMyNTYifQ.eyJzdWIiOiJkaWQ6a2V5OnpZcU52VkNrWVhhTXNGVVhEemJvRk1DMXRSV0ZjOHBUTGRONTgzb3FhcG9LNk1veno5dEVWVWpYU2lDN3Y2eXlOR0I4TW5DZUh1SE5hWlpzczFYS1E5dktzY2EyN0VIM0NQTXFSSnN5b2pqdXRyNEtrMzJaWVE0TDRjdHpZaDVHMWhrR1I3VFlhQ0Q3ekczWU1WS0V2dWQxejhZVnR5N2lxZzhBVTZxQ3hvS25ibkVVNnJEQSIsIm5iZiI6MTczOTgxNjY3MiwiaXNzIjoiZGlkOmtleTp6MmRtekQ4MWNnUHg4VmtpN0pidXVNbUZZcldQZ1lveXR5a1VaM2V5cWh0MWo5S2JzWTlEUnFTQ2d6elJ1RmJwcTlxd0pUTGtCbm1tQlhoZFNkcTZCREpSTXg2dENHMWp0a2R3Z0tYTmZOMXFXRVJEdnhhYzVyWTZoY25GUDdIdjYzaU01eTNWeHRNTjRUc3h5WnZibnJhcFcyUnBGb3ZFMURKNG03ZURWTFN1cUd0YzFpIiwiY25mIjp7Imp3ayI6eyJrdHkiOiJFQyIsImNydiI6IlAtMjU2IiwieCI6IlBrcV82ZDJpeUIwZGVvalYyLXlta0ZWeUpNeElfTDlHZVF4aDBORExoNDQ9IiwieSI6IjBOZnFMdmUtSXEwSFZZUE11eEctWHpRNUlmNktaOFhvQ0hkNmZOaDhsZFU9In19LCJleHAiOjY3OTc3NzcxODcyLCJ2YyI6eyJAY29udGV4dCI6WyJodHRwczovL3d3dy53My5vcmcvMjAxOC9jcmVkZW50aWFscy92MSJdLCJ0eXBlIjpbIlZlcmlmaWFibGVDcmVkZW50aWFsIiwiOTM1ODE5MjVfZGQiXSwiY3JlZGVudGlhbFN0YXR1cyI6eyJ0eXBlIjoiU3RhdHVzTGlzdDIwMjFFbnRyeSIsImlkIjoiaHR0cHM6Ly9pc3N1ZXItdmMtdWF0LndhbGxldC5nb3YudHcvYXBpL3N0YXR1cy1saXN0LzkzNTgxOTI1X2RkL3IwIzYiLCJzdGF0dXNMaXN0SW5kZXgiOiI2Iiwic3RhdHVzTGlzdENyZWRlbnRpYWwiOiJodHRwczovL2lzc3Vlci12Yy11YXQud2FsbGV0Lmdvdi50dy9hcGkvc3RhdHVzLWxpc3QvOTM1ODE5MjVfZGQvcjAiLCJzdGF0dXNQdXJwb3NlIjoicmV2b2NhdGlvbiJ9LCJjcmVkZW50aWFsU2NoZW1hIjp7ImlkIjoiaHR0cHM6Ly9mcm9udGVuZC11YXQud2FsbGV0Lmdvdi50dy9hcGkvc2NoZW1hLzkzNTgxOTI1L2RkL1YxL2Q0ZDFhMGY5LTNmMDktNGMyZS1iODk5LTA4YzM0NDkwYzhlYSIsInR5cGUiOiJKc29uU2NoZW1hIn0sImNyZWRlbnRpYWxTdWJqZWN0Ijp7Il9zZCI6WyJKY2lHYzViS2lkT0dteGp1dkM4TGRVeWthVlhCWEJQaEJYMWtYcERlLUxvIiwicFZPdzJOajU3RzJOa2VWSEJDV3doRUJqdWZTSmhwOWxwM201VzltQWg5QSJdLCJfc2RfYWxnIjoic2hhLTI1NiJ9fSwibm9uY2UiOiJCSElDVTI2TiIsImp0aSI6Imh0dHBzOi8vaXNzdWVyLXZjLXVhdC53YWxsZXQuZ292LnR3L2FwaS9jcmVkZW50aWFsLzRmYzNiYTY1LTY1ZGQtNDEyNC05ZTczLWNhOWY0OWNkNzc2NyJ9.h0wBjwjBDb48wZ_XVWnnrRrWh2Sgd4Lq7sc72N54svJFklnFuHebxvn-Ui6jftnQbPnLTKEyJbE75DatCkfkdQ~WyJ1cWJ5Y0VSZlN4RXF1a0dtWGwyXzl3IiwibmFtZSIsImRlbmtlbmkiXQ~WyJYMXllNDloV0s1bTJneWFBLXROQXRnIiwicm9jX2JpcnRoZGF5IiwiMDc1MDEwMSJd~\\";
const [header, body, signature] = token.split(".");

const hash = new Sha256();
hash.update(header + "." + body);
const result = await hash.digest();

let key =
  "z2dmzD81cgPx8Vki7JbuuMmFYrWPgYoytykUZ3eyqht1j9KbsY9DRqSCgzzRuFbpq9qwJTLkBnmmBXhdSdq6BDJRMx6tCG1jtkdwgKXNfN1qWERDvxac5rY6hcnFP7Hv63iM5y3VxtMN4TsxyZvbnrapW2RpFovE1DJ4m7eDVLSuqGtc1i";
// Remove the 'z' prefix if present (indicating base58btc encoding)
const trimmed = key[0] === "z" ? key.slice(1) : key;
const decodedKey = bs58.decode(trimmed);

function uint8ArrayToHex(uint8Array) {
  return Array.from(uint8Array)
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
}

const spki = "-----BEGIN PUBLIC KEY-----\n" + btoa(decodedKey) + "\n-----END PUBLIC KEY-----";

/*
let pk = await importSPKI(spki, 'ES256')
console.log(pk)
*/

import * as KeyDIDResolver from "key-did-resolver";
import { Resolver } from "did-resolver";

const keyDidResolver = KeyDIDResolver.getResolver();
const didResolver = new Resolver(keyDidResolver);

const p256 = "did:key:zDnaeUKTWUXc1HDpGfKbEK31nKLN19yX5aunFd7VK1CUMeyJu";

//https://atproto.com/specs/cryptography , P256 -> 0x80, 0x24
console.log("======>", uint8ArrayToHex(bs58.decode(p256.slice(9))));

const sub =
  "did:key:zYqNvVCkYXaMsFUXDzboFMC1tRWFc8pTLdN583oqapoK6Mozz9tEVUjXSiC7v6yyNGB8MnCeHuHNaZZss1XKQ9vKsca27EH3CPMqRJsyojjutr4Kk32ZYQ4L4ctzYh5G1hkGR7TYaCD7zG3YMVKEvud1z8YVty7iqg8AU6qCxoKnbnEU6rDA";

console.log("======>", uint8ArrayToHex(bs58.decode(sub.slice(9))));

const iss =
  "did:key:z2dmzD81cgPx8Vki7JbuuMmFYrWPgYoytykUZ3eyqht1j9KbsY9DRqSCgzzRuFbpq9qwJTLkBnmmBXhdSdq6BDJRMx6tCG1jtkdwgKXNfN1qWERDvxac5rY6hcnFP7Hv63iM5y3VxtMN4TsxyZvbnrapW2RpFovE1DJ4m7eDVLSuqGtc1i";

const doc = await didResolver.resolve(p256);
console.log(doc);
