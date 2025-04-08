CIRCUIT=SumProduct

echo ${CIRCUIT_js}
echo ${CIRCUIT}_js

rm -rf build
mkdir build
circom circuits/$CIRCUIT.circom --r1cs --wasm --sym -o build
snarkjs calculatewitness --wasm "build/${CIRCUIT}_js/$CIRCUIT.wasm" --input input.json --witness build/witness.wtns

echo "entropy\n" > build/entropy

snarkjs groth16 setup build/$CIRCUIT.r1cs ptau/pot12_final.ptau build/$CIRCUIT_0000.zkey
snarkjs zkey contribute build/$CIRCUIT_0000.zkey build/$CIRCUIT.zkey --name="1st Contributor Name" -v < build/entropy
snarkjs zkey export verificationkey build/$CIRCUIT.zkey build/verification_key.json

snarkjs groth16 prove build/SumProduct.zkey build/witness.wtns build/proof.json build/public.json
snarkjs verify build/verification_key.json build/public.json build/proof.json
