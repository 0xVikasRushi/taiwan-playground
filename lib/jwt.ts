import { strict as assert } from 'assert';
import { generateES256Inputs, Es256CircuitParams } from './es256';

interface JwtCircuitParams {
    es256: Es256CircuitParams,
    maxB64HeaderLength: number,
    maxB64PayloadLength: number,
    maxMatches: number,
    maxSubstringLength: number
}

export function generateJwtCircuitParams(params: number[]): JwtCircuitParams {
    return {
        es256: {
            n: params[0],
            k: params[1],
            maxMessageLength: params[2],
        },
        maxB64HeaderLength: params[3],
        maxB64PayloadLength: params[4],
        maxMatches: params[5],
        maxSubstringLength: params[6]
    };
}

function string2input(s: string, padLength: number): bigint[] {
    let values = Array.from(s).map(char => BigInt(char.charCodeAt(0)));
    while (values.length < padLength) {
        values.push(0n)
    }
    return values;
}

export function generateJwtInputs(params: JwtCircuitParams, token: string, pk: string, matches: string[]) {
    const [b64header, b64payload, b64signature] = token.split(".");
    assert.ok(b64header.length <= params.maxB64HeaderLength);
    assert.ok(b64payload.length <= params.maxB64PayloadLength);

    const payload = atob(b64payload);

    let es256Inputs = generateES256Inputs(params.es256, Buffer.from(`${b64header}.${b64payload}`), b64signature, pk)

    assert.ok(token.indexOf(".") != -1);
    assert.ok(matches.length <= params.maxMatches);

    let matchSubstring: bigint[][] = [];
    let matchLength: number[] = []
    let matchIndex: number[] = [];
    for (const match of matches) {
        assert.ok(matches.length <= params.maxSubstringLength);
        const index = payload.indexOf(match);
        assert.ok(index != -1);
        matchSubstring.push(string2input(match, params.maxSubstringLength));
        matchLength.push(match.length);
        matchIndex.push(index);
    }

    while (matchIndex.length < params.maxMatches) {
        matchSubstring.push(string2input('', params.maxSubstringLength));
        matchLength.push(0);
        matchIndex.push(0);
    }

    return {
        ...es256Inputs,
        periodIndex : token.indexOf('.'),
        matchesCount : matches.length,
        matchSubstring : matchSubstring,
        matchLength: matchLength,
        matchIndex : matchIndex
    };
}
