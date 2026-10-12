/**
 * Cipher test runner — node test_ciphers.js
 * Inlines cipher logic by appending exports at the end of ciphers.js content.
 */
const fs = require('fs');

// Load and patch cipher code to expose vars as module exports
let code = fs.readFileSync('./js/ciphers.js', 'utf-8');

// Append module.exports at the end
code += `
\nif (typeof module !== 'undefined') {
  module.exports = { CaesarCipher, MonoalphabeticCipher, PlayfairCipher,
    HillCipher, VigenereCipher, OneTimePad, RailFenceCipher, ColumnarTranspositionCipher };
}
`;

// Write temp file and require it
const tmpFile = './js/_ciphers_test_tmp.js';
fs.writeFileSync(tmpFile, code);
const {
  CaesarCipher, MonoalphabeticCipher, PlayfairCipher,
  HillCipher, VigenereCipher, OneTimePad,
  RailFenceCipher, ColumnarTranspositionCipher
} = require(tmpFile);
fs.unlinkSync(tmpFile);

// ─── Test helpers ──────────────────────────────────────────────────────────────
let passed = 0, failed = 0;

function test(name, actual, expected) {
  if (actual === expected) {
    console.log(`  ✓ ${name}`);
    passed++;
  } else {
    console.log(`  ✗ ${name}`);
    console.log(`    Expected: "${expected}"`);
    console.log(`    Got:      "${actual}"`);
    failed++;
  }
}

function testError(name, result) {
  if (result && result.error) {
    console.log(`  ✓ ${name} → correctly errored`);
    passed++;
  } else {
    console.log(`  ✗ ${name} — expected error but got: "${result ? result.result : result}"`);
    failed++;
  }
}

// ──── 1. Caesar Cipher ────────────────────────────────────────────────────────
console.log('\n1. CAESAR CIPHER');
let r = CaesarCipher.encrypt('Hello World', '3');
test('Encrypt "Hello World" shift 3', r.result, 'Khoor Zruog');
r = CaesarCipher.decrypt('Khoor Zruog', '3');
test('Decrypt "Khoor Zruog" shift 3', r.result, 'Hello World');
r = CaesarCipher.encrypt('XYZ', '3');
test('Wrap-around XYZ shift 3', r.result, 'ABC');
r = CaesarCipher.decrypt('ABC', '3');
test('Decrypt wrap-around ABC', r.result, 'XYZ');
testError('Empty key', CaesarCipher.encrypt('hello', ''));
testError('Non-numeric key', CaesarCipher.encrypt('hello', 'abc'));

// ──── 2. Monoalphabetic Cipher ────────────────────────────────────────────────
console.log('\n2. MONOALPHABETIC CIPHER');
const monoKey = 'QWERTYUIOPASDFGHJKLZXCVBNM';
r = MonoalphabeticCipher.encrypt('Hello World', monoKey);
test('Encrypt "Hello World"', r.result, 'Itssg Vgksr');
r = MonoalphabeticCipher.decrypt('Itssg Vgksr', monoKey);
test('Decrypt back to "Hello World"', r.result, 'Hello World');
// Round-trip random text
r = MonoalphabeticCipher.encrypt('The Quick Brown Fox', monoKey);
const monoEnc = r.result;
r = MonoalphabeticCipher.decrypt(monoEnc, monoKey);
test('Round-trip "The Quick Brown Fox"', r.result, 'The Quick Brown Fox');
testError('Key < 26 letters', MonoalphabeticCipher.encrypt('test', 'ABCDEF'));
testError('Duplicate in key', MonoalphabeticCipher.encrypt('test', 'AABCDEFGHIJKLMNOPQRSTUVWX'));

// ──── 3. Playfair Cipher ──────────────────────────────────────────────────────
console.log('\n3. PLAYFAIR CIPHER');
// Known Playfair test: MONARCHY key, HELLO → pair: HE LL(X) OX → encrypt each pair
r = PlayfairCipher.encrypt('HELLO', 'MONARCHY');
const pfEnc = r.result;
console.log(`  ℹ Encrypt "HELLO" key MONARCHY → "${pfEnc}"`);
r = PlayfairCipher.decrypt(pfEnc, 'MONARCHY');
console.log(`  ℹ Decrypt back → "${r.result}"`);
// The decrypted form will have filler X from digraph splitting: HELXLO
test('Decrypt back to padded form', r.result, 'HELXLO');

// Round-trip: encrypt "INSTRUMENTS" (well-known example)
r = PlayfairCipher.encrypt('INSTRUMENTS', 'MONARCHY');
const pfEnc2 = r.result;
r = PlayfairCipher.decrypt(pfEnc2, 'MONARCHY');
const pfDec2 = r.result;
console.log(`  ℹ "INSTRUMENTS" → "${pfEnc2}" → "${pfDec2}"`);
// After decrypt, should get INSTRUMENTS back (possibly with X fillers)
test('Decrypt contains INSTRUMENTS letters in order', pfDec2.replace(/X/g, '').includes('INSTRUMENTS'), true);
testError('Empty keyword', PlayfairCipher.encrypt('HELLO', ''));
testError('Empty plaintext', PlayfairCipher.encrypt('', 'MONARCHY'));

// ──── 4. Hill Cipher ──────────────────────────────────────────────────────────
console.log('\n4. HILL CIPHER');
// 3x3 known test: ACT with key [[6,24,1],[13,16,10],[20,17,15]] → POH
r = HillCipher.encrypt('ACT', '6,24,1;13,16,10;20,17,15');
test('Encrypt "ACT" 3×3 matrix', r.result, 'POH');
r = HillCipher.decrypt('POH', '6,24,1;13,16,10;20,17,15');
test('Decrypt "POH" 3×3 matrix', r.result, 'ACT');

// 2x2 test: HI with [[3,3],[2,5]]
r = HillCipher.encrypt('HI', '3,3;2,5');
test('Encrypt "HI" 2×2 matrix', r.result, 'TC');
r = HillCipher.decrypt('TC', '3,3;2,5');
test('Decrypt "TC" 2×2 matrix', r.result, 'HI');

// Padding: HELLO (5 letters) padded to 6 with 2x2 key
r = HillCipher.encrypt('HELLO', '3,3;2,5');
test('Padding to multiple of 2', r.result.length % 2 === 0 && r.result.length === 6, true);
console.log(`  ℹ Padded encrypt "HELLO": "${r.result}" — info: "${r.paddingInfo}"`);

// Full round-trip with 3x3
r = HillCipher.encrypt('PAYMOREMONEY', '6,24,1;13,16,10;20,17,15');
const hillEnc = r.result;
r = HillCipher.decrypt(hillEnc, '6,24,1;13,16,10;20,17,15');
test('Round-trip "PAYMOREMONEY" 3×3', r.result, 'PAYMOREMONEY');

testError('Non-invertible matrix', HillCipher.decrypt('AB', '2,4;6,8'));
testError('Bad matrix format', HillCipher.encrypt('AB', 'abc'));

// ──── 5. Vigenère Cipher ──────────────────────────────────────────────────────
console.log('\n5. VIGENÈRE CIPHER');
r = VigenereCipher.encrypt('HELLO WORLD', 'LEMON');
test('Encrypt "HELLO WORLD" key LEMON', r.result, 'SIXZB HSDZQ');
r = VigenereCipher.decrypt('SIXZB HSDZQ', 'LEMON');
test('Decrypt back', r.result, 'HELLO WORLD');
// Spaces and punctuation preserved
r = VigenereCipher.encrypt('Hello, World!', 'KEY');
const vigEnc = r.result;
r = VigenereCipher.decrypt(vigEnc, 'KEY');
test('Preserve punctuation round-trip', r.result, 'Hello, World!');
testError('Empty keyword', VigenereCipher.encrypt('test', ''));

// ──── 6. One-Time Pad ─────────────────────────────────────────────────────────
console.log('\n6. ONE-TIME PAD');
r = OneTimePad.encrypt('HELLO', 'XMCKL');
test('Encrypt "HELLO" key XMCKL', r.result, 'EQNVZ');
r = OneTimePad.decrypt('EQNVZ', 'XMCKL');
test('Decrypt "EQNVZ"', r.result, 'HELLO');
// Spaces preserved, key counts only letters
r = OneTimePad.encrypt('HI THERE', 'ABCDEFG');  // 7 letters
const otpEnc = r.result;
r = OneTimePad.decrypt(otpEnc, 'ABCDEFG');
test('OTP spaces preserved round-trip', r.result, 'HI THERE');
testError('Key too short', OneTimePad.encrypt('HELLO', 'AB'));
testError('Empty key', OneTimePad.encrypt('HELLO', ''));

// ──── 7. Rail Fence Cipher ────────────────────────────────────────────────────
console.log('\n7. RAIL FENCE CIPHER');
// "WE ARE DISCOVERED FLEE AT ONCE" with 3 rails → classic example
r = RailFenceCipher.encrypt('WEAREDISCOVEREDFLEEATONCE', '3');
const rfClassic = r.result;
test('Encrypt 3-rail classic round-trip encrypt', rfClassic.length, 25);
r = RailFenceCipher.decrypt(rfClassic, '3');
test('Decrypt 3-rail classic', r.result, 'WEAREDISCOVEREDFLEEATONCE');

// Round-trip with spaces
r = RailFenceCipher.encrypt('HELLO WORLD', '3');
const rfEnc = r.result;
r = RailFenceCipher.decrypt(rfEnc, '3');
test('Round-trip "HELLO WORLD" 3 rails', r.result, 'HELLO WORLD');

// 2 rails
r = RailFenceCipher.encrypt('HELLO', '2');
test('Encrypt "HELLO" 2 rails', r.result, 'HLOEL');
r = RailFenceCipher.decrypt('HLOEL', '2');
test('Decrypt "HLOEL" 2 rails', r.result, 'HELLO');

testError('Rails < 2', RailFenceCipher.encrypt('HELLO', '1'));
testError('Rails > length', RailFenceCipher.encrypt('HI', '5'));

// ──── 8. Columnar Transposition ───────────────────────────────────────────────
console.log('\n8. COLUMNAR TRANSPOSITION CIPHER');
// Known example: "HELLO WORLD" with key "ZEBRAS"
r = ColumnarTranspositionCipher.encrypt('HELLO WORLD', 'ZEBRAS');
const ctEnc = r.result;
console.log(`  ℹ Encrypt "HELLO WORLD" key ZEBRAS → "${ctEnc}"`);
r = ColumnarTranspositionCipher.decrypt(ctEnc, 'ZEBRAS');
test('Round-trip "HELLO WORLD" key ZEBRAS', r.result, 'HELLO WORLD');

// Numeric key round-trip
r = ColumnarTranspositionCipher.encrypt('HELLO WORLD', '3,1,4,2');
const ctEnc2 = r.result;
console.log(`  ℹ Encrypt "HELLO WORLD" key 3,1,4,2 → "${ctEnc2}"`);
r = ColumnarTranspositionCipher.decrypt(ctEnc2, '3,1,4,2');
test('Round-trip numeric key "3,1,4,2"', r.result, 'HELLO WORLD');

// Longer text round-trip
r = ColumnarTranspositionCipher.encrypt('ATTACK AT DAWN FROM THE EAST', 'SECRET');
const ctEnc3 = r.result;
r = ColumnarTranspositionCipher.decrypt(ctEnc3, 'SECRET');
test('Round-trip "ATTACK AT DAWN FROM THE EAST" key SECRET', r.result, 'ATTACK AT DAWN FROM THE EAST');

testError('Empty key', ColumnarTranspositionCipher.encrypt('HELLO', ''));

// ──── Summary ─────────────────────────────────────────────────────────────────
console.log(`\n${'═'.repeat(55)}`);
console.log(`Results: ${passed} passed, ${failed} failed out of ${passed + failed} tests`);
if (failed === 0) {
  console.log('🎉 ALL TESTS PASSED!');
} else {
  console.log('⚠  SOME TESTS FAILED — see details above.');
  process.exit(1);
}
