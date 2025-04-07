pragma circom 2.0.0;

template SumProduct() {
  signal input a;
  signal input b;
  signal output sum;
  signal output product;
  
  sum <== a+b;
  product <== a*b;
}

component main = SumProduct();
