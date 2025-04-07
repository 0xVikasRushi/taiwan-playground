pragma circom 2.1.6;

include "es256.circom";
include "jwt_tx_builder/header-payload-extractor.circom";

template JWT(
    n,
    k,

    maxMessageLength,
    maxB64HeaderLength,
    maxB64PayloadLength,

    maxSubstringLength
) {
    signal input message[maxMessageLength]; // JWT message (header + payload)
    signal input messageLength; // Length of the message signed in the JWT
    signal input periodIndex; // Index of the period in the JWT message

    signal input sig_r[k];
    signal input sig_s[k];
    signal input pubkey[2][k];

    signal input matchSubstring[maxSubstringLength];
    signal input matchLen;
    signal input matchIndex;

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

    component selectors[maxSubstringLength];
    signal    selectorindex[maxSubstringLength];
    var       maxPayloadLength = (maxB64PayloadLength * 3) \ 4;

    component lst[maxSubstringLength];
    component eqs[maxSubstringLength];

    for (var i=0;i<maxSubstringLength;i++) {
        lst[i] = LessThan(8);
        lst[i].in[0] <== i;
        lst[i].in[1] <== matchLen;

        selectorindex[i] <== matchIndex+i;

        selectors[i] = QuinSelector(maxPayloadLength); 
        selectors[i].in <== extractor.payload;
        selectors[i].index <== selectorindex[i];

        eqs[i] = ForceEqualIfEnabled();
        eqs[i].enabled <== lst[i].out; 
        eqs[i].in[0] <== matchSubstring[i];
        eqs[i].in[1] <== selectors[i].out; 
    }

}