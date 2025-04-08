# Taiwan Playground

note: This project uses [circomkit](https://github.com/erhant/circomkit) to compile, setup, prove, and verify Circom circuits

## Installation

```bash
git clone https://github.com/adria0/taiwan-playground
cd taiwan-playground
yarn
```

## Circuits

- `matcher` – Substring matcher circuit
- `es256` – ECDSA signature verification (ES256)
- `jwt` – JWT validation circuit

## Testing

You can test the circuits in two main ways:

### 1. Using circom_tester via typescript

```
yarn test
```

### 2. Using circomkit CLI

The project includes build scripts for each circuit:

```
bash scripts/build matcher # Runs full flow for matcher.circom
bash scripts/build es256 # Runs full flow for es256.circom
bash scripts/build jwt # Runs full flow for jwt.circom
bash scripts/build all # Runs all circuits
```

These commands automatically compile the circuit, download ptau according circuit size,run the proving ceremony, generate proofs using the inputs from default.json, and verify the proofs in a single workflow.
