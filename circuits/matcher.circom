pragma circom 2.1.6;

include "es256.circom";
include "circomlib/circuits/comparators.circom";

template LocalCalculateTotal(n) {
    signal input in[n];
    signal output out;

    signal sums[n];

    sums[0] <== in[0];

    for (var i = 1; i < n; i++) {
        sums[i] <== sums[i-1] + in[i];
    }

    out <== sums[n-1];
}

template QuinSelector(choices) {
    signal input in[choices];
    signal input index;
    signal output out;
    
    // Ensure that index < choices
    component lessThan = LessThan(8);
    lessThan.in[0] <== index;
    lessThan.in[1] <== choices;
    lessThan.out === 1;

    component calcTotal = LocalCalculateTotal(choices);
    component eqs[choices];

    // For each item, check whether its index equals the input index.
    for (var i = 0; i < choices; i ++) {

        // Is the index we want
        eqs[i] = IsEqual();
        eqs[i].in[0] <== i;
        eqs[i].in[1] <== index;

        calcTotal.in[i] <== eqs[i].out * in[i];
    }

    // Returns 0 + 0 + 0 + item
    out <== calcTotal.out;
}

template Matcher(maxTextLength, maxSubstringLength) {
    signal input text[maxTextLength];
    signal input textLength;
    signal input substring[maxSubstringLength];
    signal input substringIndex;
    signal input substringLength;

    component selectors[maxSubstringLength];
    signal    textIndex[maxSubstringLength];

    component lst[maxSubstringLength];
    component eqs[maxSubstringLength];

    for (var i=0;i<maxSubstringLength;i++) {
        lst[i] = LessThan(8);
        lst[i].in[0] <== i;
        lst[i].in[1] <== substringLength;

        textIndex[i] <== substringIndex+i;

        selectors[i] = QuinSelector(maxTextLength); 
        selectors[i].in <== text;
        selectors[i].index <== textIndex[i];

        eqs[i] = ForceEqualIfEnabled();
        eqs[i].enabled <== lst[i].out; 
        eqs[i].in[0] <== substring[i];
        eqs[i].in[1] <== selectors[i].out; 
    }
}