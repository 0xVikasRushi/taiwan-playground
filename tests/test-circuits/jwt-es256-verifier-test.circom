pragma circom 2.1.6;

include "../../circuits/jwt-es256-verifier.circom";

component main = JWES256Verifier(43,6, 1024);
