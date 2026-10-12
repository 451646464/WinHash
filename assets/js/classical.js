/*
 * WinHash — classical.js
 * Classical ciphers + encodings, all reversible (encrypt ⇄ decrypt),
 * verified by round-trip tests. Latin letters are ciphered; other
 * characters (Arabic, digits, spaces...) pass through unchanged
 * except XOR/Base64 which work on full UTF-8 bytes.
 */
(function (root) {
  'use strict';
  var WH = root.WinHash = root.WinHash || {};
  var U = WH.utils;

  /* ---------------- helpers ---------------- */
  function isAlpha(ch) {
    var c = ch.charCodeAt(0);
    return (c >= 65 && c <= 90) || (c >= 97 && c <= 122);
  }
  function shiftChar(ch, k) {
    var c = ch.charCodeAt(0);
    if (c >= 65 && c <= 90) return String.fromCharCode(((c - 65 + k) % 26 + 26) % 26 + 65);
    if (c >= 97 && c <= 122) return String.fromCharCode(((c - 97 + k) % 26 + 26) % 26 + 97);
    return ch;
  }
  function lettersOf(s) {
    return String(s).replace(/[^a-zA-Z]/g, '');
  }
  function require(cond, msg) { if (!cond) throw new Error(msg); }

  /* ---------------- Caesar ---------------- */
  function caesar(text, k) {
    var out = '';
    for (var i = 0; i < text.length; i++) out += shiftChar(text[i], k);
    return out;
  }

  /* ---------------- Reverse / Atbash / ROT13 ---------------- */
  function reverse(text) { return text.split('').reverse().join(''); }
  function atbash(text) {
    var out = '';
    for (var i = 0; i < text.length; i++) {
      var c = text.charCodeAt(i);
      if (c >= 65 && c <= 90) out += String.fromCharCode(90 - (c - 65));
      else if (c >= 97 && c <= 122) out += String.fromCharCode(122 - (c - 97));
      else out += text[i];
    }
    return out;
  }

  /* ---------------- Vigenère ---------------- */
  function vigenere(text, key, dir) {
    var ks = lettersOf(key).toUpperCase();
    require(ks.length >= 1, 'Vigenère key must contain at least one Latin letter');
    var out = '', ki = 0;
    for (var i = 0; i < text.length; i++) {
      var ch = text[i];
      if (isAlpha(ch)) {
        var k = ks.charCodeAt(ki % ks.length) - 65;
        out += shiftChar(ch, dir * k);
        ki++;
      } else out += ch;
    }
    return out;
  }

  /* ---------------- Autokey ---------------- */
  function autokey(text, key, dir) {
    var seed = lettersOf(key).toUpperCase();
    require(seed.length >= 1, 'Autokey seed must contain at least one Latin letter');
    var stream = seed.split('');
    var out = '', li = 0;
    for (var i = 0; i < text.length; i++) {
      var ch = text[i];
      if (isAlpha(ch)) {
        var k = stream[li].charCodeAt(0) - 65;
        var res;
        if (dir === 1) { res = shiftChar(ch, k); stream.push(shiftChar(ch, 0).toUpperCase()); }
        else { res = shiftChar(ch, -k); stream.push(res.toUpperCase()); }
        out += res;
        li++;
      } else out += ch;
    }
    return out;
  }

  /* ---------------- One-Time Pad ---------------- */
  function countLetters(text) {
    var n = 0;
    for (var i = 0; i < text.length; i++) if (isAlpha(text[i])) n++;
    return n;
  }
  function otp(text, key, dir) {
    var ks = lettersOf(key).toUpperCase();
    var need = countLetters(text);
    require(ks.length >= need,
      'One-Time Pad key must be at least as long as the message letters (' + need +
      ' letters required, ' + ks.length + ' provided) — use the "Generate key" button');
    var out = '', li = 0;
    for (var i = 0; i < text.length; i++) {
      var ch = text[i];
      if (isAlpha(ch)) {
        var k = ks.charCodeAt(li) - 65;
        out += shiftChar(ch, dir * k);
        li++;
      } else out += ch;
    }
    return out;
  }
  function generateOtpKey(n) {
    var AB = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
    var rnd = U.randomBytes(n);
    var out = '';
    for (var i = 0; i < n; i++) out += AB[rnd[i] % 26];
    return out;
  }

  /* ---------------- Columnar transposition ---------------- */
  function colReadOrder(key) {
    var chars = key.split('');
    var idx = [];
    for (var i = 0; i < chars.length; i++) idx.push(i);
    idx.sort(function (a, b) {
      if (chars[a] < chars[b]) return -1;
      if (chars[a] > chars[b]) return 1;
      return a - b;
    });
    return idx;
  }
  function pad6(n) {
    var s = String(n);
    while (s.length < 6) s = '0' + s;
    return s;
  }
  function columnarEncrypt(text, key) {
    require(key.length >= 2, 'Columnar key must be at least 2 characters');
    require(text.length <= 999999, 'Text is too long for columnar transposition (999,999 char limit)');
    var cols = key.length;
    var data = pad6(text.length) + text;
    var rows = Math.ceil(data.length / cols);
    var total = rows * cols;
    var padded = data;
    while (padded.length < total) padded += 'x';
    var order = colReadOrder(key);
    var out = '';
    for (var o = 0; o < order.length; o++) {
      var c = order[o];
      for (var r = 0; r < rows; r++) out += padded[r * cols + c];
    }
    return out;
  }
  function columnarDecrypt(text, key) {
    require(key.length >= 2, 'Columnar key must be at least 2 characters');
    require(text.length >= 6, 'Encrypted text is too short');
    var cols = key.length;
    require(text.length % cols === 0,
      'Ciphertext length does not match the key — copy the full output without modifications');
    var rows = text.length / cols;
    var order = colReadOrder(key);
    var chars = text.split('');
    var grid = new Array(cols * rows);
    var p = 0;
    for (var o = 0; o < order.length; o++) {
      var c = order[o];
      for (var r = 0; r < rows; r++) grid[r * cols + c] = chars[p++];
    }
    var data = grid.join('');
    var len = parseInt(data.slice(0, 6), 10);
    require(!isNaN(len) && len >= 0 && len <= data.length - 6,
      'Decryption failed: wrong key or corrupted ciphertext');
    return data.slice(6, 6 + len);
  }

  /* Columnar without a key: fixed identity column order (1,2,3...) */
  function fixedKey(cols) {
    var s = '';
    for (var i = 1; i <= cols; i++) s += String(i % 10);
    return s;
  }

  /* ---------------- Rail fence ---------------- */
  function railSeq(len, n) {
    var seq = new Array(len), rail = 0, step = 1;
    for (var i = 0; i < len; i++) {
      seq[i] = rail;
      rail += step;
      if (rail === 0 || rail === n - 1) step = -step;
    }
    return seq;
  }
  function railEncrypt(text, n) {
    if (n === text.length || text.length === 0) return text;
    var rails = [];
    for (var i = 0; i < n; i++) rails.push('');
    var rail = 0, step = 1;
    for (i = 0; i < text.length; i++) {
      rails[rail] += text[i];
      rail += step;
      if (rail === 0 || rail === n - 1) step = -step;
    }
    return rails.join('');
  }
  function railDecrypt(text, n) {
    if (n === text.length || text.length === 0) return text;
    var seq = railSeq(text.length, n);
    var counts = [];
    for (var i = 0; i < n; i++) counts.push(0);
    for (i = 0; i < seq.length; i++) counts[seq[i]]++;
    var parts = [], off = 0;
    for (i = 0; i < n; i++) { parts.push(text.slice(off, off + counts[i])); off += counts[i]; }
    var pos = [];
    for (i = 0; i < n; i++) pos.push(0);
    var out = '';
    for (i = 0; i < seq.length; i++) {
      var r = seq[i];
      out += parts[r][pos[r]++];
    }
    return out;
  }

  /* ---------------- XOR (UTF-8 bytes -> Base64) ---------------- */
  function xorCrypt(text, key, isDecrypt) {
    require(key.length >= 1, 'XOR key cannot be empty');
    var keyBytes = U.utf8Encode(key);
    var bytes = isDecrypt ? U.base64ToBytes(text) : U.utf8Encode(text);
    var out = new Uint8Array(bytes.length);
    for (var i = 0; i < bytes.length; i++) {
      out[i] = bytes[i] ^ keyBytes[i % keyBytes.length];
    }
    return isDecrypt ? U.utf8Decode(out) : U.bytesToBase64(out);
  }

  /* ---------------- Base64 ---------------- */
  function b64enc(text) { return U.bytesToBase64(U.utf8Encode(text)); }
  function b64dec(text) { return U.utf8Decode(U.base64ToBytes(text)); }

  /* ---------------- WinHash Hybrid (Vigenère → Columnar) ---------------- */
  function hybridEncrypt(text, key) {
    require(lettersOf(key).length >= 1, 'WinHash Hybrid key must contain Latin letters');
    return columnarEncrypt(vigenere(text, key, 1), key);
  }
  function hybridDecrypt(text, key) {
    require(lettersOf(key).length >= 1, 'WinHash Hybrid key must contain Latin letters');
    return vigenere(columnarDecrypt(text, key), key, -1);
  }

  /* ================= registry ================= */
  var LIST = [
    { id: 'caesar', name: 'Caesar Cipher', keyType: 'shift', keyDefault: '3',
      desc: 'A fixed alphabet shift (0-25). The oldest classical cipher, great for learning.', level: 'Educational' },
    { id: 'vigenere', name: 'Vigenère', keyType: 'letters',
      desc: 'Polyalphabetic substitution driven by a repeating letter key — far stronger than Caesar.', level: 'Educational' },
    { id: 'autokey', name: 'Autokey', keyType: 'letters',
      desc: 'The key extends itself with the message letters as encryption progresses.', level: 'Educational' },
    { id: 'otp', name: 'One-Time Pad', keyType: 'otp',
      desc: 'A random key as long as the message — provably secure only if used exactly once.', level: 'Conditional' },
    { id: 'columnar', name: 'Columnar Transposition', keyType: 'text',
      desc: 'Writes the text into a grid and reads the columns ordered by the key letters.', level: 'Educational' },
    { id: 'columnar_nk', name: 'Columnar (no key)', keyType: 'cols',
      desc: 'The same grid transposition with a fixed column order (2-9 columns).', level: 'Weak' },
    { id: 'rail', name: 'Rail Fence', keyType: 'rails',
      desc: 'Spreads the text across diagonal rails, then reads it row by row.', level: 'Weak' },
    { id: 'reverse', name: 'Reverse Cipher', keyType: 'none',
      desc: 'Simply reverses the character order — the simplest transformation possible.', level: 'Very weak' },
    { id: 'atbash', name: 'Atbash', keyType: 'none',
      desc: 'Mirrors the alphabet (A↔Z, B↔Y…) — an ancient Hebrew substitution cipher.', level: 'Educational' },
    { id: 'rot13', name: 'ROT13', keyType: 'none',
      desc: 'Caesar with a shift of 13; encrypting twice returns the original text.', level: 'Weak' },
    { id: 'xor', name: 'XOR Cipher', keyType: 'text',
      desc: 'Exclusive-or over the UTF-8 bytes of the text, emitted as Base64.', level: 'Weak' },
    { id: 'base64', name: 'Base64', keyType: 'none',
      desc: 'An encoding for transporting bytes as text — not encryption at all.', level: 'Encoding' },
    { id: 'hybrid', name: 'WinHash Hybrid', keyType: 'letters',
      desc: 'Multi-layer custom cipher: Vigenère followed by columnar transposition.', level: 'Moderate' }
  ];

  var BY_ID = {};
  for (var i = 0; i < LIST.length; i++) BY_ID[LIST[i].id] = LIST[i];

  function run(id, mode, text, key) {
    if (text === null || text === undefined) text = '';
    var enc = mode === 'encrypt';
    switch (id) {
      case 'caesar': {
        var k = parseInt(key, 10);
        if (isNaN(k)) k = 3;
        return caesar(text, enc ? k : -k);
      }
      case 'vigenere': return vigenere(text, key, enc ? 1 : -1);
      case 'autokey': return autokey(text, key, enc ? 1 : -1);
      case 'otp': return otp(text, key, enc ? 1 : -1);
      case 'columnar': return enc ? columnarEncrypt(text, key) : columnarDecrypt(text, key);
      case 'columnar_nk': {
        var cols = parseInt(key, 10);
        if (isNaN(cols) || cols < 2) cols = 3;
        if (cols > 9) cols = 9;
        var fk = fixedKey(cols);
        return enc ? columnarEncrypt(text, fk) : columnarDecrypt(text, fk);
      }
      case 'rail': {
        var n = parseInt(key, 10);
        if (isNaN(n) || n < 2) n = 2;
        if (n > 10) n = 10;
        return enc ? railEncrypt(text, n) : railDecrypt(text, n);
      }
      case 'reverse': return reverse(text);
      case 'atbash': return atbash(text);
      case 'rot13': return caesar(text, 13);
      case 'xor': return xorCrypt(text, key, !enc);
      case 'base64': return enc ? b64enc(text) : b64dec(text);
      case 'hybrid': return enc ? hybridEncrypt(text, key) : hybridDecrypt(text, key);
      default: throw new Error('Unknown algorithm: ' + id);
    }
  }

  WH.classical = {
    list: LIST,
    byId: function (id) { return BY_ID[id]; },
    run: run,
    generateOtpKey: generateOtpKey,
    countLetters: countLetters
  };
})(typeof self !== 'undefined' ? self : this);
