pragma circom 2.1.6;

include "es-256.circom";
include "header-payload-extractor.circom";

template JWT(
    n,
    k,
    maxMessageLength,
    maxB64HeaderLength,
    maxB64PayloadLength
) {
    signal input message[maxMessageLength]; // JWT message (header + payload)
    signal input messageLength; // Length of the message signed in the JWT
    signal input periodIndex; // Index of the period in the JWT message

    signal input sig_r[k];
    signal input sig_s[k];
    signal input pubkey[2][k];

    component es256 = ES256(n,k,maxMessageLength);
    es256.message <== message;
    es256.messageLength <== messageLength;
    es256.sig_r <== sig_r;
    es256.sig_s <== sig_s;
    es256.pubkey <== pubkey;

    component extractor = HeaderPayloadExtractor(maxMessageLength,maxB64HeaderLength, maxB64PayloadLength);
    extractor.message <== message;
    extractor.messageLength <== messageLength;
    extractor.periodIndex <== periodIndex;
    
    signal header;
    signal payload;
    header <== extractor.header;
    payload <== extractor.payload;    
}