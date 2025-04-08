pragma circom 2.1.6;

include "../../circuits/JWT.circom";

component main = JWT(43,6, 2048, 256, 2000, 5, 50);
