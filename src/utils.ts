export function string2input(s: string, padLength: number) {
  let values = Array.from(s).map((char) => BigInt(char.charCodeAt(0)));
  while (values.length < padLength) {
    values.push(0n);
  }
  return values;
}
