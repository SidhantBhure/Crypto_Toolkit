/**
 * Classical Cryptography Toolkit — Main Application
 * UI logic, routing, cipher page rendering, and Compare Algorithms feature.
 */

// ─── State ─────────────────────────────────────────────────────────────────────

let currentPage = 'dashboard';
let currentMode = {}; // track encrypt/decrypt mode per cipher

// ─── Navigation ────────────────────────────────────────────────────────────────

function navigate(page) {
  // Hide all pages
  document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
  // Show target
  const target = document.getElementById('page-' + page);
  if (target) {
    target.classList.add('active');
    currentPage = page;
  }
  // Update nav items
  document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
  const activeNav = document.querySelector(`.nav-item[data-page="${page}"]`);
  if (activeNav) activeNav.classList.add('active');
  // Close mobile sidebar
  closeSidebar();
  // Scroll to top
  window.scrollTo(0, 0);
}

function closeSidebar() {
  document.querySelector('.sidebar').classList.remove('open');
  document.querySelector('.sidebar-overlay').classList.remove('open');
}

// ─── Key Input Hints ───────────────────────────────────────────────────────────

const KEY_HINTS = {
  caesar: { label: 'Shift Key (integer)', placeholder: 'e.g. 3', type: 'number' },
  monoalphabetic: { label: 'Substitution Alphabet (26 letters)', placeholder: 'e.g. QWERTYUIOPASDFGHJKLZXCVBNM', type: 'text' },
  playfair: { label: 'Keyword', placeholder: 'e.g. MONARCHY', type: 'text' },
  hill: { label: 'Key Matrix (rows separated by ;, values by ,)', placeholder: 'e.g. 3,3;2,5 for 2×2 or 6,24,1;13,16,10;20,17,15 for 3×3', type: 'text' },
  vigenere: { label: 'Keyword', placeholder: 'e.g. LEMON', type: 'text' },
  otp: { label: 'Key (letters, same length as plaintext letters)', placeholder: 'e.g. XMCKL', type: 'text' },
  railfence: { label: 'Number of Rails', placeholder: 'e.g. 3', type: 'number' },
  columnar: { label: 'Keyword or Column Order', placeholder: 'e.g. ZEBRAS or 3,1,4,2', type: 'text' }
};

const KEY_DESCRIPTIONS = {
  caesar: 'Enter an integer shift value (e.g., 3 shifts A→D).',
  monoalphabetic: 'Enter all 26 letters of the alphabet in your desired substitution order. Each letter must appear exactly once.',
  playfair: 'Enter a keyword. It will be used to build a 5×5 matrix (I and J are combined).',
  hill: 'Enter a 2×2 or 3×3 matrix. Separate values with commas and rows with semicolons. For decryption, the matrix must be invertible mod 26.',
  vigenere: 'Enter a keyword made of letters. It repeats cyclically over the plaintext.',
  otp: 'Enter a key consisting of letters only. The key length must exactly match the number of letters in the text (spaces and punctuation are excluded from count).',
  railfence: 'Enter the number of rails (≥ 2 and ≤ text length).',
  columnar: 'Enter a keyword (e.g. ZEBRAS) or comma-separated column numbers (e.g. 3,1,4,2).'
};

// ─── Build Cipher Pages ────────────────────────────────────────────────────────

function buildCipherPages() {
  const container = document.getElementById('cipher-pages-container');
  container.innerHTML = '';

  CIPHER_LIST.forEach(cipher => {
    const isTransposition = cipher.category === 'transposition';
    const hint = KEY_HINTS[cipher.id];
    const desc = KEY_DESCRIPTIONS[cipher.id];

    const page = document.createElement('div');
    page.className = 'page';
    page.id = 'page-' + cipher.id;

    page.innerHTML = `
      <div class="page-title-bar">
        <button class="back-btn" onclick="navigate('dashboard')" title="Back to Dashboard">←</button>
        <h2>${cipher.icon} ${cipher.name}</h2>
        <span class="cipher-type-badge ${isTransposition ? 'trans' : ''}">${isTransposition ? 'Transposition' : 'Substitution'}</span>
      </div>

      <div class="mode-toggle">
        <button class="active" onclick="setMode('${cipher.id}', 'encrypt', this)">🔒 Encrypt</button>
        <button onclick="setMode('${cipher.id}', 'decrypt', this)">🔓 Decrypt</button>
      </div>

      <div class="cipher-workspace">
        <div class="workspace-panel">
          <div class="panel-header">
            <div class="panel-title"><span class="dot"></span> Input</div>
          </div>

          <div class="form-group">
            <label id="${cipher.id}-input-label">Plaintext</label>
            <textarea id="${cipher.id}-input" placeholder="Enter your text here..." rows="4"></textarea>
          </div>

          <div class="form-group">
            <label>${hint.label}</label>
            <input type="${hint.type}" id="${cipher.id}-key" placeholder="${hint.placeholder}">
            <div class="hint">${desc}</div>
          </div>

          <div class="action-bar">
            <button class="btn btn-primary" onclick="runCipher('${cipher.id}')">▶ Run</button>
            <button class="btn btn-secondary" onclick="clearCipher('${cipher.id}')">✕ Clear</button>
            <button class="btn btn-secondary" onclick="swapOutput('${cipher.id}')">⇄ Swap to Input</button>
          </div>
        </div>

        <div class="workspace-panel">
          <div class="panel-header">
            <div class="panel-title"><span class="dot"></span> Output</div>
          </div>

          <div id="${cipher.id}-msg" class="msg"></div>
          <div id="${cipher.id}-info" class="msg msg-info"></div>

          <div class="form-group">
            <div class="output-header">
              <label id="${cipher.id}-enc-label">Encrypted Text</label>
              <button class="btn btn-copy" onclick="copyText('${cipher.id}-enc-output', this)">📋 Copy</button>
            </div>
            <div class="output-area empty" id="${cipher.id}-enc-output">Result will appear here</div>
          </div>

          <div class="form-group">
            <div class="output-header">
              <label>Verification (Decrypt back)</label>
              <button class="btn btn-copy" onclick="copyText('${cipher.id}-dec-output', this)">📋 Copy</button>
            </div>
            <div class="output-area empty" id="${cipher.id}-dec-output">Decrypted verification will appear here</div>
          </div>

          ${cipher.id === 'playfair' ? `
          <div class="form-group" id="${cipher.id}-matrix-container" style="display:none;">
            <label>5×5 Key Matrix</label>
            <div id="${cipher.id}-matrix" class="matrix-display cols-5"></div>
          </div>` : ''}
        </div>
      </div>

      <div class="cipher-note">
        💡 <strong>Note:</strong> ${getCipherNote(cipher.id)}
      </div>
    `;

    container.appendChild(page);
    currentMode[cipher.id] = 'encrypt';
  });
}

function getCipherNote(id) {
  const notes = {
    caesar: 'The Caesar Cipher preserves spaces and punctuation. Shift wraps around (e.g., shift 3: Z→C).',
    monoalphabetic: 'Each letter is mapped to a unique letter. The 26-letter key defines the substitution alphabet.',
    playfair: 'Playfair operates on pairs of letters. I/J are treated as the same letter. Repeated letters in a pair are separated with X. Odd-length plaintext is padded with X.',
    hill: 'Hill Cipher removes non-letter characters and works in uppercase. If the text length is not a multiple of the matrix size, it is padded with X. Decryption requires an invertible matrix mod 26.',
    vigenere: 'The Vigenère Cipher preserves spaces and punctuation. The keyword repeats over the letters of the plaintext.',
    otp: 'The One-Time Pad key must be exactly as long as the number of letters in the text. Spaces and punctuation are preserved but do not consume key characters.',
    railfence: 'The Rail Fence Cipher rearranges all characters (including spaces and punctuation) in a zigzag pattern. The number of rails must be ≥ 2.',
    columnar: 'Columnar Transposition writes all characters into columns and reads them in the order specified by the key. Incomplete rows are left empty at the end.'
  };
  return notes[id] || '';
}

// ─── Mode Toggle ───────────────────────────────────────────────────────────────

function setMode(cipherId, mode, btn) {
  currentMode[cipherId] = mode;
  const toggle = btn.parentElement;
  toggle.querySelectorAll('button').forEach(b => b.classList.remove('active'));
  btn.classList.add('active');

  const inputLabel = document.getElementById(cipherId + '-input-label');
  const encLabel = document.getElementById(cipherId + '-enc-label');

  if (mode === 'encrypt') {
    inputLabel.textContent = 'Plaintext';
    encLabel.textContent = 'Encrypted Text';
  } else {
    inputLabel.textContent = 'Ciphertext';
    encLabel.textContent = 'Decrypted Text';
  }
}

// ─── Run Cipher ────────────────────────────────────────────────────────────────

function runCipher(cipherId) {
  const input = document.getElementById(cipherId + '-input').value;
  const key = document.getElementById(cipherId + '-key').value;
  const mode = currentMode[cipherId];
  const msgEl = document.getElementById(cipherId + '-msg');
  const infoEl = document.getElementById(cipherId + '-info');
  const encOutput = document.getElementById(cipherId + '-enc-output');
  const decOutput = document.getElementById(cipherId + '-dec-output');

  // Reset messages
  msgEl.className = 'msg';
  msgEl.textContent = '';
  infoEl.className = 'msg msg-info';
  infoEl.textContent = '';
  encOutput.className = 'output-area empty';
  encOutput.textContent = 'Result will appear here';
  decOutput.className = 'output-area empty';
  decOutput.textContent = 'Decrypted verification will appear here';

  // Hide playfair matrix
  const matrixContainer = document.getElementById(cipherId + '-matrix-container');
  if (matrixContainer) matrixContainer.style.display = 'none';

  // Validate input
  if (!input.trim()) {
    showMsg(msgEl, 'error', 'Please enter some text.');
    return;
  }

  const cipher = CIPHERS[cipherId];
  if (!cipher) return;

  try {
    let primaryResult, verifyResult;

    if (mode === 'encrypt') {
      primaryResult = cipher.encrypt(input, key);
      if (primaryResult.error) {
        showMsg(msgEl, 'error', primaryResult.error);
        return;
      }
      encOutput.className = 'output-area';
      encOutput.textContent = primaryResult.result;

      // Show padding info if present
      if (primaryResult.paddingInfo) {
        showMsg(infoEl, 'info', primaryResult.paddingInfo);
      }

      // Show Playfair matrix
      if (cipherId === 'playfair' && primaryResult.matrix) {
        showPlayfairMatrix(cipherId, primaryResult.matrix);
      }

      // Verify by decrypting
      verifyResult = cipher.decrypt(primaryResult.result, key);
      if (verifyResult.error) {
        decOutput.className = 'output-area';
        decOutput.textContent = '(Verification unavailable: ' + verifyResult.error + ')';
      } else {
        decOutput.className = 'output-area';
        decOutput.textContent = verifyResult.result;
      }
    } else {
      // Decrypt mode
      primaryResult = cipher.decrypt(input, key);
      if (primaryResult.error) {
        showMsg(msgEl, 'error', primaryResult.error);
        return;
      }
      encOutput.className = 'output-area';
      encOutput.textContent = primaryResult.result;

      // Show Playfair matrix
      if (cipherId === 'playfair' && primaryResult.matrix) {
        showPlayfairMatrix(cipherId, primaryResult.matrix);
      }

      // Verify by encrypting
      verifyResult = cipher.encrypt(primaryResult.result, key);
      if (verifyResult.error) {
        decOutput.className = 'output-area';
        decOutput.textContent = '(Verification unavailable: ' + verifyResult.error + ')';
      } else {
        decOutput.className = 'output-area';
        decOutput.textContent = verifyResult.result;
      }
    }

    showMsg(msgEl, 'success', mode === 'encrypt' ? '✓ Encryption successful!' : '✓ Decryption successful!');
  } catch (e) {
    showMsg(msgEl, 'error', 'An unexpected error occurred: ' + e.message);
  }
}

function showMsg(el, type, text) {
  el.className = `msg msg-${type} show`;
  el.textContent = text;
}

function showPlayfairMatrix(cipherId, matrix) {
  const container = document.getElementById(cipherId + '-matrix-container');
  const matrixEl = document.getElementById(cipherId + '-matrix');
  if (!container || !matrixEl) return;
  container.style.display = 'block';
  matrixEl.innerHTML = '';
  for (const row of matrix) {
    for (const cell of row) {
      const div = document.createElement('div');
      div.className = 'matrix-cell';
      div.textContent = cell;
      matrixEl.appendChild(div);
    }
  }
}

// ─── Cipher Utilities ──────────────────────────────────────────────────────────

function clearCipher(cipherId) {
  document.getElementById(cipherId + '-input').value = '';
  document.getElementById(cipherId + '-key').value = '';
  const msgEl = document.getElementById(cipherId + '-msg');
  const infoEl = document.getElementById(cipherId + '-info');
  msgEl.className = 'msg';
  infoEl.className = 'msg msg-info';
  document.getElementById(cipherId + '-enc-output').className = 'output-area empty';
  document.getElementById(cipherId + '-enc-output').textContent = 'Result will appear here';
  document.getElementById(cipherId + '-dec-output').className = 'output-area empty';
  document.getElementById(cipherId + '-dec-output').textContent = 'Decrypted verification will appear here';
  const mc = document.getElementById(cipherId + '-matrix-container');
  if (mc) mc.style.display = 'none';
}

function swapOutput(cipherId) {
  const encOutput = document.getElementById(cipherId + '-enc-output');
  const inputEl = document.getElementById(cipherId + '-input');
  if (!encOutput.classList.contains('empty')) {
    inputEl.value = encOutput.textContent;

    // Toggle mode: if was encrypt, switch to decrypt and vice versa
    const newMode = currentMode[cipherId] === 'encrypt' ? 'decrypt' : 'encrypt';
    const toggle = document.querySelector(`#page-${cipherId} .mode-toggle`);
    if (toggle) {
      const buttons = toggle.querySelectorAll('button');
      buttons.forEach(b => b.classList.remove('active'));
      if (newMode === 'encrypt') {
        buttons[0].classList.add('active');
      } else {
        buttons[1].classList.add('active');
      }
    }
    currentMode[cipherId] = newMode;

    // Update labels
    const inputLabel = document.getElementById(cipherId + '-input-label');
    const encLabel = document.getElementById(cipherId + '-enc-label');
    if (newMode === 'encrypt') {
      inputLabel.textContent = 'Plaintext';
      encLabel.textContent = 'Encrypted Text';
    } else {
      inputLabel.textContent = 'Ciphertext';
      encLabel.textContent = 'Decrypted Text';
    }

    // Clear outputs
    document.getElementById(cipherId + '-enc-output').className = 'output-area empty';
    document.getElementById(cipherId + '-enc-output').textContent = 'Result will appear here';
    document.getElementById(cipherId + '-dec-output').className = 'output-area empty';
    document.getElementById(cipherId + '-dec-output').textContent = 'Decrypted verification will appear here';
    const msgEl = document.getElementById(cipherId + '-msg');
    if (msgEl) { msgEl.className = 'msg'; msgEl.textContent = ''; }
    const infoEl = document.getElementById(cipherId + '-info');
    if (infoEl) { infoEl.className = 'msg msg-info'; infoEl.textContent = ''; }
  }
}

function copyText(elementId, btn) {
  const el = document.getElementById(elementId);
  if (el.classList.contains('empty')) return;
  navigator.clipboard.writeText(el.textContent).then(() => {
    btn.classList.add('copied');
    const original = btn.innerHTML;
    btn.innerHTML = '✓ Copied';
    setTimeout(() => {
      btn.classList.remove('copied');
      btn.innerHTML = original;
    }, 1500);
  }).catch(() => {
    // Fallback
    const range = document.createRange();
    range.selectNodeContents(el);
    const sel = window.getSelection();
    sel.removeAllRanges();
    sel.addRange(range);
    document.execCommand('copy');
    sel.removeAllRanges();
  });
}

// ─── Compare Algorithms ────────────────────────────────────────────────────────

function initCompare() {
  const checksContainer = document.getElementById('compare-algo-checks');
  const keysContainer = document.getElementById('compare-keys-section');

  checksContainer.innerHTML = '';
  CIPHER_LIST.forEach(c => {
    const label = document.createElement('label');
    label.innerHTML = `<input type="checkbox" value="${c.id}" onchange="onCompareCheckChange()"> ${c.icon} ${c.name}`;
    checksContainer.appendChild(label);
  });
}

function onCompareCheckChange() {
  const checks = document.querySelectorAll('#compare-algo-checks input[type="checkbox"]');
  const keysContainer = document.getElementById('compare-keys-section');
  keysContainer.innerHTML = '';

  // Style checked labels
  checks.forEach(cb => {
    const label = cb.parentElement;
    if (cb.checked) {
      label.classList.add('checked');
    } else {
      label.classList.remove('checked');
    }
  });

  // Show key inputs for selected algorithms
  checks.forEach(cb => {
    if (cb.checked) {
      const id = cb.value;
      const hint = KEY_HINTS[id];
      const info = CIPHER_LIST.find(c => c.id === id);
      const div = document.createElement('div');
      div.className = 'compare-key-input';
      div.innerHTML = `
        <label>${info.icon} ${info.name} — Key</label>
        <input type="${hint.type}" id="compare-key-${id}" placeholder="${hint.placeholder}">
        <div class="key-hint">${KEY_DESCRIPTIONS[id]}</div>
      `;
      keysContainer.appendChild(div);
    }
  });
}

function runCompare() {
  const input = document.getElementById('compare-input').value;
  const msgEl = document.getElementById('compare-msg');
  const resultsContainer = document.getElementById('compare-results');

  msgEl.className = 'msg';
  resultsContainer.innerHTML = '';

  if (!input.trim()) {
    showMsg(msgEl, 'error', 'Please enter some text to compare.');
    return;
  }

  const checks = document.querySelectorAll('#compare-algo-checks input[type="checkbox"]:checked');
  if (checks.length < 2) {
    showMsg(msgEl, 'error', 'Please select at least two algorithms to compare.');
    return;
  }

  const rows = [];
  let hasError = false;

  checks.forEach(cb => {
    const id = cb.value;
    const cipher = CIPHERS[id];
    const info = CIPHER_LIST.find(c => c.id === id);
    const keyInput = document.getElementById('compare-key-' + id);
    const key = keyInput ? keyInput.value : '';

    if (!key.trim()) {
      rows.push({ name: info.name, icon: info.icon, error: 'Key is required.' });
      hasError = true;
      return;
    }

    const encResult = cipher.encrypt(input, key);
    if (encResult.error) {
      rows.push({ name: info.name, icon: info.icon, error: encResult.error });
      hasError = true;
      return;
    }

    const decResult = cipher.decrypt(encResult.result, key);
    rows.push({
      name: info.name,
      icon: info.icon,
      encrypted: encResult.result,
      decrypted: decResult.error ? '(Error: ' + decResult.error + ')' : decResult.result,
      decError: !!decResult.error
    });
  });

  // Build results table
  let html = `
    <div class="compare-table-wrap">
      <table class="compare-table">
        <thead>
          <tr>
            <th>Algorithm</th>
            <th>Encrypted Output</th>
            <th>Decrypted Verification</th>
            <th>Status</th>
          </tr>
        </thead>
        <tbody>`;

  rows.forEach(row => {
    if (row.error) {
      html += `
        <tr>
          <td>${row.icon} ${row.name}</td>
          <td class="cell-error" colspan="2">${row.error}</td>
          <td class="cell-error">✕ Error</td>
        </tr>`;
    } else {
      html += `
        <tr>
          <td>${row.icon} ${row.name}</td>
          <td>${escapeHtml(row.encrypted)}</td>
          <td>${escapeHtml(row.decrypted)}</td>
          <td class="${row.decError ? 'cell-mismatch' : 'cell-match'}">${row.decError ? '⚠ Warning' : '✓ Verified'}</td>
        </tr>`;
    }
  });

  html += `</tbody></table></div>`;
  resultsContainer.innerHTML = html;

  if (hasError) {
    showMsg(msgEl, 'error', 'Some algorithms had errors. Check the results table for details.');
  } else {
    showMsg(msgEl, 'success', '✓ Comparison complete! All selected algorithms produced results.');
  }
}

function escapeHtml(text) {
  const div = document.createElement('div');
  div.textContent = text;
  return div.innerHTML;
}

// ─── Dashboard Cards ───────────────────────────────────────────────────────────

function buildDashboardCards() {
  const subGrid = document.getElementById('sub-cipher-grid');
  const transGrid = document.getElementById('trans-cipher-grid');

  CIPHER_LIST.forEach(c => {
    const card = document.createElement('div');
    card.className = 'cipher-card';
    card.onclick = () => navigate(c.id);
    card.innerHTML = `
      <span class="card-icon">${c.icon}</span>
      <h3>${c.name}</h3>
      <p>${c.description}</p>
      <span class="card-tag ${c.category === 'transposition' ? 'trans' : 'sub'}">${c.category}</span>
    `;
    if (c.category === 'substitution') subGrid.appendChild(card);
    else transGrid.appendChild(card);
  });
}

// ─── Initialization ────────────────────────────────────────────────────────────

document.addEventListener('DOMContentLoaded', () => {
  buildDashboardCards();
  buildCipherPages();
  initCompare();

  // Nav click handlers
  document.querySelectorAll('.nav-item[data-page]').forEach(btn => {
    btn.addEventListener('click', () => navigate(btn.dataset.page));
  });

  // Mobile menu
  document.querySelector('.mobile-menu-btn').addEventListener('click', () => {
    document.querySelector('.sidebar').classList.toggle('open');
    document.querySelector('.sidebar-overlay').classList.toggle('open');
  });

  document.querySelector('.sidebar-overlay').addEventListener('click', closeSidebar);

  // Show dashboard
  navigate('dashboard');
});
