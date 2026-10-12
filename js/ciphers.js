/**
 * Classical Cryptography Toolkit — Cipher Algorithms
 * All 8 classical cipher implementations with encryption, decryption, and validation.
 * Pure logic — no DOM or UI dependencies.
 */

// ─── Utility Helpers ───────────────────────────────────────────────────────────

function isLetter(c) {
  return /^[A-Za-z]$/.test(c);
}

function mod(n, m) {
  return ((n % m) + m) % m;
}

// ─── 1. Caesar Cipher ──────────────────────────────────────────────────────────

const CaesarCipher = {
  name: 'Caesar Cipher',

  validateKey(key) {
    const k = parseInt(key, 10);
    if (isNaN(k)) return { valid: false, error: 'Key must be an integer.' };
    return { valid: true, key: mod(k, 26) };
  },

  encrypt(plaintext, key) {
    const v = this.validateKey(key);
    if (!v.valid) return { error: v.error };
    const shift = v.key;
    let result = '';
    for (const ch of plaintext) {
      if (isLetter(ch)) {
        const base = ch === ch.toUpperCase() ? 65 : 97;
        result += String.fromCharCode(((ch.charCodeAt(0) - base + shift) % 26) + base);
      } else {
        result += ch;
      }
    }
    return { result };
  },

  decrypt(ciphertext, key) {
    const v = this.validateKey(key);
    if (!v.valid) return { error: v.error };
    return this.encrypt(ciphertext, (26 - v.key).toString());
  }
};

// ─── 2. Monoalphabetic Cipher ──────────────────────────────────────────────────

const MonoalphabeticCipher = {
  name: 'Monoalphabetic Cipher',

  validateKey(key) {
    if (!key || typeof key !== 'string') return { valid: false, error: 'Key must be a 26-letter string.' };
    const k = key.toUpperCase();
    if (k.length !== 26) return { valid: false, error: `Key must be exactly 26 letters. You provided ${k.length}.` };
    for (const c of k) {
      if (!/[A-Z]/.test(c)) return { valid: false, error: `Key contains invalid character '${c}'. Only letters A-Z allowed.` };
    }
    const set = new Set(k);
    if (set.size !== 26) {
      const counts = {};
      for (const c of k) counts[c] = (counts[c] || 0) + 1;
      const dups = Object.entries(counts).filter(([, v]) => v > 1).map(([k]) => k);
      return { valid: false, error: `Key must contain each letter exactly once. Duplicates: ${dups.join(', ')}.` };
    }
    return { valid: true, key: k };
  },

  encrypt(plaintext, key) {
    const v = this.validateKey(key);
    if (!v.valid) return { error: v.error };
    const k = v.key;
    let result = '';
    for (const ch of plaintext) {
      if (isLetter(ch)) {
        const idx = ch.toUpperCase().charCodeAt(0) - 65;
        const mapped = k[idx];
        result += ch === ch.toUpperCase() ? mapped : mapped.toLowerCase();
      } else {
        result += ch;
      }
    }
    return { result };
  },

  decrypt(ciphertext, key) {
    const v = this.validateKey(key);
    if (!v.valid) return { error: v.error };
    const k = v.key;
    // Build reverse mapping
    const reverse = new Array(26);
    for (let i = 0; i < 26; i++) {
      reverse[k.charCodeAt(i) - 65] = String.fromCharCode(65 + i);
    }
    let result = '';
    for (const ch of ciphertext) {
      if (isLetter(ch)) {
        const idx = ch.toUpperCase().charCodeAt(0) - 65;
        const mapped = reverse[idx];
        result += ch === ch.toUpperCase() ? mapped : mapped.toLowerCase();
      } else {
        result += ch;
      }
    }
    return { result };
  }
};

// ─── 3. Playfair Cipher ────────────────────────────────────────────────────────

const PlayfairCipher = {
  name: 'Playfair Cipher',

  validateKey(key) {
    if (!key || typeof key !== 'string' || key.trim() === '') return { valid: false, error: 'Keyword cannot be empty.' };
    const filtered = key.toUpperCase().replace(/[^A-Z]/g, '').replace(/J/g, 'I');
    if (filtered.length === 0) return { valid: false, error: 'Keyword must contain at least one letter.' };
    return { valid: true, key: filtered };
  },

  generateMatrix(keyword) {
    const seen = new Set();
    const matrix = [];
    const kw = keyword.toUpperCase().replace(/J/g, 'I');
    for (const c of kw) {
      if (!seen.has(c) && /[A-Z]/.test(c)) { seen.add(c); matrix.push(c); }
    }
    for (let i = 0; i < 26; i++) {
      const c = String.fromCharCode(65 + i);
      if (c === 'J') continue;
      if (!seen.has(c)) { seen.add(c); matrix.push(c); }
    }
    // Build 5x5 grid and position map
    const grid = [];
    const pos = {};
    for (let i = 0; i < 25; i++) {
      const r = Math.floor(i / 5), c = i % 5;
      if (!grid[r]) grid[r] = [];
      grid[r][c] = matrix[i];
      pos[matrix[i]] = { r, c };
    }
    return { grid, pos };
  },

  preparePairs(text) {
    const clean = text.toUpperCase().replace(/J/g, 'I').replace(/[^A-Z]/g, '');
    const pairs = [];
    let i = 0;
    while (i < clean.length) {
      const a = clean[i];
      if (i + 1 >= clean.length) {
        pairs.push([a, 'X']);
        i++;
      } else if (clean[i] === clean[i + 1]) {
        pairs.push([a, 'X']);
        i++;
      } else {
        pairs.push([a, clean[i + 1]]);
        i += 2;
      }
    }
    return pairs;
  },

  encrypt(plaintext, key) {
    const v = this.validateKey(key);
    if (!v.valid) return { error: v.error };
    const clean = plaintext.replace(/[^A-Za-z]/g, '');
    if (clean.length === 0) return { error: 'Plaintext must contain at least one letter.' };
    const { grid, pos } = this.generateMatrix(v.key);
    const pairs = this.preparePairs(plaintext);
    let result = '';
    for (const [a, b] of pairs) {
      const pa = pos[a], pb = pos[b];
      if (pa.r === pb.r) {
        result += grid[pa.r][(pa.c + 1) % 5];
        result += grid[pb.r][(pb.c + 1) % 5];
      } else if (pa.c === pb.c) {
        result += grid[(pa.r + 1) % 5][pa.c];
        result += grid[(pb.r + 1) % 5][pb.c];
      } else {
        result += grid[pa.r][pb.c];
        result += grid[pb.r][pa.c];
      }
    }
    return { result, matrix: grid, pairs };
  },

  decrypt(ciphertext, key) {
    const v = this.validateKey(key);
    if (!v.valid) return { error: v.error };
    const clean = ciphertext.toUpperCase().replace(/[^A-Z]/g, '');
    if (clean.length === 0) return { error: 'Ciphertext must contain at least one letter.' };
    if (clean.length % 2 !== 0) return { error: 'Ciphertext length must be even for Playfair decryption.' };
    const { grid, pos } = this.generateMatrix(v.key);
    let result = '';
    for (let i = 0; i < clean.length; i += 2) {
      const a = clean[i].replace('J', 'I'), b = clean[i + 1].replace('J', 'I');
      const pa = pos[a], pb = pos[b];
      if (!pa || !pb) return { error: `Invalid character in ciphertext: '${!pa ? a : b}'.` };
      if (pa.r === pb.r) {
        result += grid[pa.r][mod(pa.c - 1, 5)];
        result += grid[pb.r][mod(pb.c - 1, 5)];
      } else if (pa.c === pb.c) {
        result += grid[mod(pa.r - 1, 5)][pa.c];
        result += grid[mod(pb.r - 1, 5)][pb.c];
      } else {
        result += grid[pa.r][pb.c];
        result += grid[pb.r][pa.c];
      }
    }
    return { result, matrix: grid };
  }
};

// ─── 4. Hill Cipher ────────────────────────────────────────────────────────────

const HillCipher = {
  name: 'Hill Cipher',

  validateKey(key, forDecrypt = false) {
    // key should be comma-separated rows, e.g. "3,3;2,5" for 2x2
    if (!key || typeof key !== 'string') return { valid: false, error: 'Key matrix is required. Enter rows separated by semicolons, values by commas. E.g. "3,3;2,5" for a 2×2 matrix.' };
    const rows = key.trim().split(';').map(r => r.trim().split(',').map(v => parseInt(v.trim(), 10)));
    const n = rows.length;
    if (n !== 2 && n !== 3) return { valid: false, error: 'Only 2×2 and 3×3 matrices are supported.' };
    for (const row of rows) {
      if (row.length !== n) return { valid: false, error: `Matrix must be square. Expected ${n} values per row.` };
      for (const v of row) {
        if (isNaN(v)) return { valid: false, error: 'All matrix entries must be integers.' };
      }
    }
    // Compute determinant mod 26
    const det = this.determinant(rows, n);
    const detMod = mod(det, 26);
    // Check invertibility
    const gcdVal = this.gcd(detMod, 26);
    if (forDecrypt && gcdVal !== 1) {
      return { valid: false, error: `Matrix determinant mod 26 = ${detMod}, which is not invertible mod 26. The key cannot be used for decryption.` };
    }
    return { valid: true, matrix: rows, size: n, det: detMod };
  },

  gcd(a, b) {
    a = Math.abs(a); b = Math.abs(b);
    while (b) { [a, b] = [b, a % b]; }
    return a;
  },

  modInverse(a, m) {
    a = mod(a, m);
    for (let x = 1; x < m; x++) {
      if ((a * x) % m === 1) return x;
    }
    return -1;
  },

  determinant(matrix, n) {
    if (n === 1) return matrix[0][0];
    if (n === 2) return matrix[0][0] * matrix[1][1] - matrix[0][1] * matrix[1][0];
    let det = 0;
    for (let c = 0; c < n; c++) {
      const sub = [];
      for (let i = 1; i < n; i++) {
        const row = [];
        for (let j = 0; j < n; j++) {
          if (j !== c) row.push(matrix[i][j]);
        }
        sub.push(row);
      }
      det += Math.pow(-1, c) * matrix[0][c] * this.determinant(sub, n - 1);
    }
    return det;
  },

  invertMatrix(matrix, n) {
    const det = this.determinant(matrix, n);
    const detMod = mod(det, 26);
    const detInv = this.modInverse(detMod, 26);
    if (detInv === -1) return null;

    if (n === 2) {
      return [
        [mod(matrix[1][1] * detInv, 26), mod(-matrix[0][1] * detInv, 26)],
        [mod(-matrix[1][0] * detInv, 26), mod(matrix[0][0] * detInv, 26)]
      ];
    }

    // 3x3: compute adjugate
    const cofactors = [];
    for (let i = 0; i < n; i++) {
      cofactors[i] = [];
      for (let j = 0; j < n; j++) {
        const sub = [];
        for (let r = 0; r < n; r++) {
          if (r === i) continue;
          const row = [];
          for (let c = 0; c < n; c++) {
            if (c === j) continue;
            row.push(matrix[r][c]);
          }
          sub.push(row);
        }
        cofactors[i][j] = mod(Math.pow(-1, i + j) * this.determinant(sub, n - 1) * detInv, 26);
      }
    }
    // Transpose to get adjugate * detInv
    const inv = [];
    for (let i = 0; i < n; i++) {
      inv[i] = [];
      for (let j = 0; j < n; j++) {
        inv[i][j] = mod(cofactors[j][i], 26);
      }
    }
    return inv;
  },

  encrypt(plaintext, key) {
    const v = this.validateKey(key);
    if (!v.valid) return { error: v.error };
    const { matrix, size } = v;
    const clean = plaintext.toUpperCase().replace(/[^A-Z]/g, '');
    if (clean.length === 0) return { error: 'Plaintext must contain at least one letter.' };

    let padded = clean;
    let paddingInfo = '';
    if (clean.length % size !== 0) {
      const padCount = size - (clean.length % size);
      padded = clean + 'X'.repeat(padCount);
      paddingInfo = `Padded with ${padCount} 'X' character(s) to make length a multiple of ${size}.`;
    }

    let result = '';
    for (let i = 0; i < padded.length; i += size) {
      const block = [];
      for (let j = 0; j < size; j++) block.push(padded.charCodeAt(i + j) - 65);
      for (let r = 0; r < size; r++) {
        let sum = 0;
        for (let c = 0; c < size; c++) sum += matrix[r][c] * block[c];
        result += String.fromCharCode(mod(sum, 26) + 65);
      }
    }
    return { result, paddingInfo };
  },

  decrypt(ciphertext, key) {
    const v = this.validateKey(key, true);
    if (!v.valid) return { error: v.error };
    const { matrix, size } = v;
    const clean = ciphertext.toUpperCase().replace(/[^A-Z]/g, '');
    if (clean.length === 0) return { error: 'Ciphertext must contain at least one letter.' };
    if (clean.length % size !== 0) return { error: `Ciphertext length must be a multiple of ${size} for a ${size}×${size} key matrix.` };

    const inv = this.invertMatrix(matrix, size);
    if (!inv) return { error: 'Key matrix is not invertible mod 26. Cannot decrypt.' };

    let result = '';
    for (let i = 0; i < clean.length; i += size) {
      const block = [];
      for (let j = 0; j < size; j++) block.push(clean.charCodeAt(i + j) - 65);
      for (let r = 0; r < size; r++) {
        let sum = 0;
        for (let c = 0; c < size; c++) sum += inv[r][c] * block[c];
        result += String.fromCharCode(mod(sum, 26) + 65);
      }
    }
    return { result };
  }
};

// ─── 5. Vigenère Cipher ────────────────────────────────────────────────────────

const VigenereCipher = {
  name: 'Vigenère Cipher',

  validateKey(key) {
    if (!key || typeof key !== 'string' || key.trim() === '') return { valid: false, error: 'Keyword cannot be empty.' };
    const k = key.toUpperCase().replace(/[^A-Z]/g, '');
    if (k.length === 0) return { valid: false, error: 'Keyword must contain at least one letter.' };
    return { valid: true, key: k };
  },

  encrypt(plaintext, key) {
    const v = this.validateKey(key);
    if (!v.valid) return { error: v.error };
    const k = v.key;
    let result = '';
    let ki = 0;
    for (const ch of plaintext) {
      if (isLetter(ch)) {
        const base = ch === ch.toUpperCase() ? 65 : 97;
        const shift = k.charCodeAt(ki % k.length) - 65;
        result += String.fromCharCode(((ch.charCodeAt(0) - base + shift) % 26) + base);
        ki++;
      } else {
        result += ch;
      }
    }
    return { result };
  },

  decrypt(ciphertext, key) {
    const v = this.validateKey(key);
    if (!v.valid) return { error: v.error };
    const k = v.key;
    let result = '';
    let ki = 0;
    for (const ch of ciphertext) {
      if (isLetter(ch)) {
        const base = ch === ch.toUpperCase() ? 65 : 97;
        const shift = k.charCodeAt(ki % k.length) - 65;
        result += String.fromCharCode(mod(ch.charCodeAt(0) - base - shift, 26) + base);
        ki++;
      } else {
        result += ch;
      }
    }
    return { result };
  }
};

// ─── 6. One-Time Pad ───────────────────────────────────────────────────────────

const OneTimePad = {
  name: 'One-Time Pad',

  validateKey(key, textLength) {
    if (!key || typeof key !== 'string') return { valid: false, error: 'Key is required.' };
    const k = key.toUpperCase().replace(/[^A-Z]/g, '');
    if (k.length === 0) return { valid: false, error: 'Key must contain only letters (A-Z).' };
    if (k.length !== textLength) return { valid: false, error: `Key length (${k.length}) must equal the number of letters in the text (${textLength}). Adjust your key.` };
    return { valid: true, key: k };
  },

  encrypt(plaintext, key) {
    const letters = plaintext.replace(/[^A-Za-z]/g, '');
    const v = this.validateKey(key, letters.length);
    if (!v.valid) return { error: v.error };
    const k = v.key;
    let result = '';
    let ki = 0;
    for (const ch of plaintext) {
      if (isLetter(ch)) {
        const base = ch === ch.toUpperCase() ? 65 : 97;
        const shift = k.charCodeAt(ki) - 65;
        result += String.fromCharCode(((ch.charCodeAt(0) - base + shift) % 26) + base);
        ki++;
      } else {
        result += ch;
      }
    }
    return { result };
  },

  decrypt(ciphertext, key) {
    const letters = ciphertext.replace(/[^A-Za-z]/g, '');
    const v = this.validateKey(key, letters.length);
    if (!v.valid) return { error: v.error };
    const k = v.key;
    let result = '';
    let ki = 0;
    for (const ch of ciphertext) {
      if (isLetter(ch)) {
        const base = ch === ch.toUpperCase() ? 65 : 97;
        const shift = k.charCodeAt(ki) - 65;
        result += String.fromCharCode(mod(ch.charCodeAt(0) - base - shift, 26) + base);
        ki++;
      } else {
        result += ch;
      }
    }
    return { result };
  }
};

// ─── 7. Rail Fence Cipher ──────────────────────────────────────────────────────

const RailFenceCipher = {
  name: 'Rail Fence Cipher',

  validateKey(key, textLength) {
    const k = parseInt(key, 10);
    if (isNaN(k) || k < 2) return { valid: false, error: 'Number of rails must be an integer ≥ 2.' };
    if (k > textLength) return { valid: false, error: `Number of rails (${k}) cannot exceed text length (${textLength}).` };
    return { valid: true, key: k };
  },

  encrypt(plaintext, key) {
    if (!plaintext || plaintext.length === 0) return { error: 'Plaintext cannot be empty.' };
    const v = this.validateKey(key, plaintext.length);
    if (!v.valid) return { error: v.error };
    const rails = v.key;
    const fence = Array.from({ length: rails }, () => []);
    let rail = 0, dir = 1;
    for (const ch of plaintext) {
      fence[rail].push(ch);
      if (rail === 0) dir = 1;
      else if (rail === rails - 1) dir = -1;
      rail += dir;
    }
    return { result: fence.flat().join('') };
  },

  decrypt(ciphertext, key) {
    if (!ciphertext || ciphertext.length === 0) return { error: 'Ciphertext cannot be empty.' };
    const v = this.validateKey(key, ciphertext.length);
    if (!v.valid) return { error: v.error };
    const rails = v.key;
    const n = ciphertext.length;

    // Determine length of each rail
    const railLens = new Array(rails).fill(0);
    let rail = 0, dir = 1;
    for (let i = 0; i < n; i++) {
      railLens[rail]++;
      if (rail === 0) dir = 1;
      else if (rail === rails - 1) dir = -1;
      rail += dir;
    }

    // Split ciphertext into rails
    const railTexts = [];
    let idx = 0;
    for (let r = 0; r < rails; r++) {
      railTexts.push(ciphertext.slice(idx, idx + railLens[r]));
      idx += railLens[r];
    }

    // Read off in zigzag order
    const pointers = new Array(rails).fill(0);
    let result = '';
    rail = 0; dir = 1;
    for (let i = 0; i < n; i++) {
      result += railTexts[rail][pointers[rail]++];
      if (rail === 0) dir = 1;
      else if (rail === rails - 1) dir = -1;
      rail += dir;
    }
    return { result };
  }
};

// ─── 8. Columnar Transposition Cipher ──────────────────────────────────────────

const ColumnarTranspositionCipher = {
  name: 'Columnar Transposition Cipher',

  validateKey(key) {
    if (!key || typeof key !== 'string' || key.trim() === '') return { valid: false, error: 'Key cannot be empty.' };
    const k = key.toUpperCase().trim();
    // Accept either a keyword (letters) or comma-separated column order (numbers)
    if (/^[A-Z]+$/.test(k)) {
      // Convert keyword to column order by alphabetical sorting
      const indexed = [...k].map((c, i) => ({ c, i }));
      indexed.sort((a, b) => a.c === b.c ? a.i - b.i : a.c.localeCompare(b.c));
      const order = new Array(k.length);
      indexed.forEach((item, rank) => { order[item.i] = rank; });
      return { valid: true, order, keyLength: k.length };
    }
    if (/^[\d,\s]+$/.test(k)) {
      const nums = k.split(/[,\s]+/).map(Number);
      if (nums.some(isNaN)) return { valid: false, error: 'Numeric key must contain only integers separated by commas.' };
      // Check it's a valid permutation
      const sorted = [...nums].sort((a, b) => a - b);
      const expected = sorted.map((_, i) => sorted[0] + i);
      if (JSON.stringify(sorted) !== JSON.stringify(expected)) {
        return { valid: false, error: 'Numeric key must be a valid permutation (e.g., "3,1,4,2").' };
      }
      const min = Math.min(...nums);
      const order = nums.map(n => n - min);
      return { valid: true, order, keyLength: nums.length };
    }
    return { valid: false, error: 'Key must be a word (letters only) or comma-separated column numbers.' };
  },

  encrypt(plaintext, key) {
    if (!plaintext || plaintext.length === 0) return { error: 'Plaintext cannot be empty.' };
    const v = this.validateKey(key);
    if (!v.valid) return { error: v.error };
    const { order, keyLength } = v;

    const text = plaintext;
    const numRows = Math.ceil(text.length / keyLength);
    const grid = [];
    let idx = 0;
    for (let r = 0; r < numRows; r++) {
      grid[r] = [];
      for (let c = 0; c < keyLength; c++) {
        grid[r][c] = idx < text.length ? text[idx++] : '';
      }
    }

    // Read columns in key order
    let result = '';
    for (let rank = 0; rank < keyLength; rank++) {
      const col = order.indexOf(rank);
      for (let r = 0; r < numRows; r++) {
        if (grid[r][col] !== '') result += grid[r][col];
      }
    }
    return { result };
  },

  decrypt(ciphertext, key) {
    if (!ciphertext || ciphertext.length === 0) return { error: 'Ciphertext cannot be empty.' };
    const v = this.validateKey(key);
    if (!v.valid) return { error: v.error };
    const { order, keyLength } = v;

    const n = ciphertext.length;
    const numRows = Math.ceil(n / keyLength);
    const fullCols = n % keyLength || keyLength;

    // Determine the length of each column
    const colLengths = new Array(keyLength);
    for (let rank = 0; rank < keyLength; rank++) {
      const col = order.indexOf(rank);
      // Columns whose index < (n % keyLength) get an extra row, unless n % keyLength === 0
      if (n % keyLength === 0) {
        colLengths[col] = numRows;
      } else {
        colLengths[col] = col < (n % keyLength) ? numRows : numRows - 1;
      }
    }

    // Fill columns in key order
    const columns = new Array(keyLength);
    let idx = 0;
    for (let rank = 0; rank < keyLength; rank++) {
      const col = order.indexOf(rank);
      columns[col] = ciphertext.slice(idx, idx + colLengths[col]);
      idx += colLengths[col];
    }

    // Read row by row
    let result = '';
    for (let r = 0; r < numRows; r++) {
      for (let c = 0; c < keyLength; c++) {
        if (r < columns[c].length) result += columns[c][r];
      }
    }
    return { result };
  }
};

// ─── Export all ciphers ────────────────────────────────────────────────────────

const CIPHERS = {
  caesar: CaesarCipher,
  monoalphabetic: MonoalphabeticCipher,
  playfair: PlayfairCipher,
  hill: HillCipher,
  vigenere: VigenereCipher,
  otp: OneTimePad,
  railfence: RailFenceCipher,
  columnar: ColumnarTranspositionCipher
};

const CIPHER_LIST = [
  { id: 'caesar', name: 'Caesar Cipher', category: 'substitution', icon: '🔄', description: 'Shifts each letter by a fixed number of positions in the alphabet.' },
  { id: 'monoalphabetic', name: 'Monoalphabetic Cipher', category: 'substitution', icon: '🔤', description: 'Replaces each letter with another letter using a fixed substitution alphabet.' },
  { id: 'playfair', name: 'Playfair Cipher', category: 'substitution', icon: '🔲', description: 'Encrypts pairs of letters using a 5×5 key matrix.' },
  { id: 'hill', name: 'Hill Cipher', category: 'substitution', icon: '📐', description: 'Uses matrix multiplication and modular arithmetic for encryption.' },
  { id: 'vigenere', name: 'Vigenère Cipher', category: 'substitution', icon: '🔑', description: 'A polyalphabetic cipher using a repeating keyword for variable shifts.' },
  { id: 'otp', name: 'One-Time Pad', category: 'substitution', icon: '🎲', description: 'Unbreakable cipher using a random key as long as the message.' },
  { id: 'railfence', name: 'Rail Fence Cipher', category: 'transposition', icon: '🚧', description: 'Arranges plaintext in a zigzag pattern across multiple rails.' },
  { id: 'columnar', name: 'Columnar Transposition', category: 'transposition', icon: '📊', description: 'Rearranges text by writing it into columns and reading in key order.' }
];
