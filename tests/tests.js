/*
 * WinHash — tests.js
 * Runs inside tests.html. Verifies:
 *   1) Hash implementations vs Python hashlib/zlib vectors
 *   2) Incremental chunked hashing consistency
 *   3) HMAC vectors
 *   4) Classical cipher round-trips (encrypt → decrypt == original)
 *   5) Modern AES container round-trips + wrong password/tamper detection
 *   6) RSA-OAEP round-trips
 */
(function () {
  'use strict';

  var R = { total: 0, passed: 0, failed: 0, failures: [] };
  window.__RESULTS__ = R;

  var listEl = document.getElementById('list');

  function line(cls, text) {
    var li = document.createElement('li');
    li.className = cls;
    li.textContent = text;
    listEl.appendChild(li);
  }
  function ok(name) { R.total++; R.passed++; line('pass', '✓ ' + name); }
  function fail(name, detail) {
    R.total++; R.failed++;
    var d = String(detail || '');
    if (d.length > 300) d = d.slice(0, 300) + '…';
    R.failures.push({ name: name, detail: d });
    line('fail', '✗ ' + name + ' — ' + d);
  }
  function assert(cond, msg) { if (!cond) throw new Error(msg || 'assertion failed'); }
  function assertEq(actual, expected, label) {
    if (actual !== expected) {
      var det = (label || '') + ' | got: ' + String(actual).slice(0, 140) + ' | want: ' + String(expected).slice(0, 140);
      if (typeof actual === 'string' && typeof expected === 'string' && actual.length === expected.length) {
        for (var i = 0; i < actual.length; i++) {
          if (actual[i] !== expected[i]) { det += ' | first diff @' + i; break; }
        }
      }
      throw new Error(det);
    }
  }
  async function test(name, fn) {
    try { await fn(); ok(name); }
    catch (e) { fail(name, (e && e.message) ? e.message : String(e)); }
  }

  function hexToBytesLocal(hex) { return WinHash.utils.hexToBytes(hex); }
  function bytesOfInput(hex) { return hexToBytesLocal(hex); }

  /* ============================================================
   * 1. Hash vectors
   * ========================================================== */
  async function runHashVectors() {
    var V = window.VECTORS;
    var ids = WinHash.hashes.list.map(function (h) { return h.id; });
    for (var ii = 0; ii < V.inputs.length; ii++) {
      var inp = V.inputs[ii];
      var bytes = bytesOfInput(inp.hex);
      var expectedEntry = V.hashes[inp.name];
      for (var hh = 0; hh < ids.length; hh++) {
        var id = ids[hh];
        var expected = expectedEntry[id];
        if (!expected) continue;
        /* eslint-disable no-await-in-loop */
        var got = await WinHash.hashes.digestHex(id, bytes);
        if (got !== expected) {
          throw new Error('[' + id + '/' + inp.name + '] got ' + got + ' want ' + expected);
        }
      }
    }
  }

  /* ============================================================
   * 2. Incremental chunking
   * ========================================================== */
  async function runChunking() {
    var V = window.VECTORS;
    var samples = ['a', 'abc', 'block64', 'block65', 'long10k'];
    var ids = ['md5', 'sha256', 'sha1', 'sha3_256', 'ripemd160', 'sha512', 'crc32', 'sha224', 'fnv1a32'];
    var chunks = [1, 7, 64, 1000];
    for (var s = 0; s < samples.length; s++) {
      var inp = null;
      for (var i = 0; i < V.inputs.length; i++) if (V.inputs[i].name === samples[s]) inp = V.inputs[i];
      if (!inp) continue;
      var bytes = bytesOfInput(inp.hex);
      for (var c = 0; c < chunks.length; c++) {
        var size = chunks[c];
        for (var h = 0; h < ids.length; h++) {
          var id = ids[h];
          var hasher = WinHash.hashes.create(id);
          for (var o = 0; o < bytes.length; o += size) {
            hasher.update(bytes.subarray(o, Math.min(o + size, bytes.length)));
          }
          /* eslint-disable no-await-in-loop */
          var got = await hasher.digestHex();
          var want = V.hashes[inp.name][id];
          if (got !== want) {
            throw new Error('[' + id + '/' + inp.name + ' chunk=' + size + '] got ' + got.slice(0, 40) + ' want ' + want.slice(0, 40));
          }
        }
      }
    }
  }

  /* ============================================================
   * 3. HMAC vectors
   * ========================================================== */
  async function runHmac() {
    var V = window.VECTORS;
    for (var i = 0; i < V.hmac.length; i++) {
      var c = V.hmac[i];
      var key = WinHash.utils.utf8Encode(c.key);
      var msg = WinHash.utils.utf8Encode(c.msg);
      /* eslint-disable no-await-in-loop */
      var g256 = await WinHash.hashes.hmacHex('hmac_sha256', key, msg);
      if (g256 !== c.sha256) throw new Error('hmac_sha256 case ' + i + ': ' + g256 + ' != ' + c.sha256);
      var g1 = await WinHash.hashes.hmacHex('hmac_sha1', key, msg);
      if (g1 !== c.sha1) throw new Error('hmac_sha1 case ' + i);
      var g512 = await WinHash.hashes.hmacHex('hmac_sha512', key, msg);
      if (g512 !== c.sha512) throw new Error('hmac_sha512 case ' + i);
    }
  }

  /* ============================================================
   * 4. Classical round-trips
   * ========================================================== */
  function otpKeyFor(text) {
    var n = WinHash.classical.countLetters(text);
    return WinHash.classical.generateOtpKey(n);
  }

  async function runClassical() {
    var texts = [
      '',
      'a',
      'A',
      'Hello, World! 123',
      'The quick brown fox jumps over the lazy dog.',
      'AAA BBB ccc DDD',
      'WinHash — تشفير احترافي 2026!',
      'multiple   spaces\tand\nnewlines',
      ' LEVEL playing field ',
      'ab'.repeat(500),
      '0123456789'.repeat(30),
      'short',
      'xy',
      'Test with trailing x',
      'مرحبا Hello مرحبا'
    ];
    var cases = [
      { id: 'caesar', keys: ['3', '7', '0', '-5', '25', 'abc'] },
      { id: 'vigenere', keys: ['SECRET', 'key', 'ABCXYZ', 'Rakan'] },
      { id: 'autokey', keys: ['KEY', 'RLOmliki', 'a'] },
      { id: 'otp', keys: null },
      { id: 'columnar', keys: ['ZEBRA', 'LEVEL', 'ab', 'CRYPTO'] },
      { id: 'columnar_nk', keys: ['3', '2', '9', ''] },
      { id: 'rail', keys: ['2', '3', '7', 'x'] },
      { id: 'reverse', keys: [''] },
      { id: 'atbash', keys: [''] },
      { id: 'rot13', keys: [''] },
      { id: 'xor', keys: ['p@ssw0rd!#@', 'Rakan', 'مفتاح'] },
      { id: 'base64', keys: [''] },
      { id: 'hybrid', keys: ['Rakan', 'KEY22', 'winhash'] }
    ];
    for (var ci = 0; ci < cases.length; ci++) {
      var c = cases[ci];
      var keys = c.keys;
      if (c.id === 'otp') keys = null;
      var keyCount = keys ? keys.length : texts.length;
      for (var ki = 0; ki < keyCount; ki++) {
        var key = keys ? keys[ki] : null;
        for (var ti = 0; ti < texts.length; ti++) {
          var text = texts[ti];
          if (c.id === 'otp') key = otpKeyFor(text);
          /* enc → dec must reproduce the original exactly */
          var enc = WinHash.classical.run(c.id, 'encrypt', text, key);
          var dec = WinHash.classical.run(c.id, 'decrypt', enc, key);
          if (dec !== text) {
            throw new Error(c.id + ' key=' + JSON.stringify(key) + ' text=' + JSON.stringify(text) +
              ' → dec=' + JSON.stringify(dec));
          }
          /* decrypting garbage must throw (not silently return junk) for key-based ciphers */
          if (c.id === 'columnar' || c.id === 'hybrid' || c.id === 'base64' || c.id === 'xor') {
            var threw = false;
            try { WinHash.classical.run(c.id, 'decrypt', '!!!!not ciphered!!!!', key); }
            catch (e) { threw = true; }
            if (!threw) throw new Error(c.id + ' should throw on invalid ciphertext');
          }
        }
      }
    }
    /* OTP key too short must throw */
    var otpThrew = false;
    try { WinHash.classical.run('otp', 'encrypt', 'HELLO WORLD', 'AB'); }
    catch (e) { otpThrew = true; }
    assert(otpThrew, 'OTP with short key should throw');
    /* OTP with sufficient key must equal a known shift result */
    var otpOut = WinHash.classical.run('otp', 'encrypt', 'ABC', 'BCD');
    assertEq(otpOut, 'BDF', 'otp shift');
    var otpBack = WinHash.classical.run('otp', 'decrypt', otpOut, 'BCD');
    assertEq(otpBack, 'ABC', 'otp roundtrip');
    /* Caesar known vector: shift 3, "abc" → "def" */
    assertEq(WinHash.classical.run('caesar', 'encrypt', 'abc', '3'), 'def', 'caesar abc+3');
    assertEq(WinHash.classical.run('caesar', 'encrypt', 'XYZ', '3'), 'ABC', 'caesar XYZ+3');
    /* ROT13 double application */
    assertEq(WinHash.classical.run('rot13', 'encrypt',
      WinHash.classical.run('rot13', 'encrypt', 'Hello!', ''), ''), 'Hello!', 'rot13 x2');
    /* Vigenère known vector: key=KEY, "ATTACK AT DAWN" (spaces do not consume key) */
    var vig = WinHash.classical.run('vigenere', 'encrypt', 'ATTACK AT DAWN', 'KEY');
    assertEq(vig, 'KXRKGI KX BKAL', 'vigenere known vector');
    assertEq(WinHash.classical.run('vigenere', 'decrypt', vig, 'KEY'), 'ATTACK AT DAWN', 'vigenere roundtrip');
    /* Rail fence known: rails=2, "HELLO WORLD" → "HLOLEWRDLO"? verify roundtrip instead of hardcode */
    var rf = WinHash.classical.run('rail', 'encrypt', 'WE ARE DISCOVERED FLEE AT ONCE', '3');
    assertEq(WinHash.classical.run('rail', 'decrypt', rf, '3'), 'WE ARE DISCOVERED FLEE AT ONCE', 'rail roundtrip');
    assertEq(rf, 'WRIVDETCEAEDSOEE LEA NE  CRF O', 'rail fence known vector');
  }

  /* ============================================================
   * 5. Modern AES container
   * ========================================================== */
  async function runModern() {
    var algos = ['aes-gcm', 'aes-cbc', 'aes-ctr'];
    var supported = await WinHash.modern.supportedAlgorithms();
    supported.forEach(function (a) {
      if (algos.indexOf(a.key) === -1) algos.push(a.key);
    });

    var texts = [
      'Hello WinHash!',
      '',
      'مرحبا بك في WinHash — رسالة عربية طويلة تتكرر مرتين مرتين مرتين.',
      'x'.repeat(5000),
      'Special: `~!@#$%^&*()_+-=[]{};\'":,./<>?\\|'
    ];
    var passwords = ['MyP@ssw0rd!', 'كلمةمرور123'];

    for (var a = 0; a < algos.length; a++) {
      var algo = algos[a];
      for (var t = 0; t < texts.length; t++) {
        for (var p = 0; p < passwords.length; p++) {
          var format = (t % 2 === 0) ? 'base64' : 'hex';
          /* eslint-disable no-await-in-loop */
          var enc = await WinHash.modern.encryptText(texts[t], passwords[p], algo,
            { iterations: 10000, format: format });
          assert(enc && typeof enc === 'string', 'enc should be string');
          var dec = await WinHash.modern.decryptText(enc, passwords[p]);
          if (dec !== texts[t]) {
            throw new Error(algo + ' roundtrip mismatch (len ' + texts[t].length + ')');
          }
        }
      }
      /* wrong password must fail */
      var e1 = await WinHash.modern.encryptText('secret payload', 'right-pass', algo, { iterations: 10000 });
      var rejected = false;
      try { await WinHash.modern.decryptText(e1, 'wrong-pass'); }
      catch (e) { rejected = true; }
      assert(rejected, algo + ': wrong password should throw');
      /* corrupted ciphertext must fail for AEAD modes */
      if (algo === 'aes-gcm' || algo === 'chacha20') {
        var bytes = WinHash.utils.base64ToBytes(e1);
        bytes[bytes.length - 1] ^= 0xff;
        var rej2 = false;
        try { await WinHash.modern.decryptText(WinHash.utils.bytesToBase64(bytes), 'right-pass'); }
        catch (e) { rej2 = true; }
        assert(rej2, algo + ': tampered data should throw');
      }
      /* non-container input must fail */
      var rej3 = false;
      try { await WinHash.modern.decryptText('this is definitely not a container at all', 'x'); }
      catch (e) { rej3 = true; }
      assert(rej3, algo + ': invalid input should throw');
    }

    /* large binary round-trip with metadata (file-style) */
    var big = WinHash.utils.randomBytes(1024 * 1024 + 7);
    var container = await WinHash.modern.encryptBytes(big, 'file-pass-1', 'aes-gcm', {
      iterations: 10000,
      meta: { n: 'photo.jpg', t: 'image/jpeg', s: big.length }
    });
    assert(container.length > big.length, 'container larger than payload');
    assert(container[0] === 0x57 && container[1] === 0x4e, 'magic bytes');
    var res = await WinHash.modern.decryptBytes(container, 'file-pass-1');
    assertEq(res.bytes.length, big.length, 'big file length');
    var same = true;
    for (var i = 0; i < big.length; i++) {
      if (big[i] !== res.bytes[i]) { same = false; break; }
    }
    assert(same, 'big file bytes must match');
    assertEq(res.meta.n, 'photo.jpg', 'meta name');
    assertEq(res.meta.t, 'image/jpeg', 'meta type');
    assertEq(res.meta.s, big.length, 'meta size');

    /* zero-length payload */
    var c0 = await WinHash.modern.encryptBytes(new Uint8Array(0), 'p', 'aes-gcm', { iterations: 10000 });
    var r0 = await WinHash.modern.decryptBytes(c0, 'p');
    assertEq(r0.bytes.length, 0, 'empty payload');

    /* exactly one block / two blocks sizes for CBC padding paths */
    for (var n = 1; n <= 33; n++) {
      var data = WinHash.utils.randomBytes(n);
      /* eslint-disable no-await-in-loop */
      var cc = await WinHash.modern.encryptBytes(data, 'blk', 'aes-cbc', { iterations: 10000 });
      var rr = await WinHash.modern.decryptBytes(cc, 'blk');
      assertEq(WinHash.utils.bytesToHex(rr.bytes), WinHash.utils.bytesToHex(data), 'cbc len=' + n);
    }
  }

  /* ============================================================
   * 6. RSA-OAEP
   * ========================================================== */
  async function runRsa() {
    var pair = await WinHash.modern.rsa.generate(2048);
    assert(pair.publicPem.indexOf('BEGIN PUBLIC KEY') !== -1, 'public PEM label');
    assert(pair.privatePem.indexOf('BEGIN PRIVATE KEY') !== -1, 'private PEM label');

    var texts = ['Hello RSA!', '', 'نص عربي مع RSA — '.repeat(20), 'z'.repeat(1000)];
    for (var i = 0; i < texts.length; i++) {
      /* eslint-disable no-await-in-loop */
      var ct = await WinHash.modern.rsa.encryptText(texts[i], pair.publicPem);
      var pt = await WinHash.modern.rsa.decryptText(ct, pair.privatePem);
      assertEq(pt, texts[i], 'rsa roundtrip #' + i);
    }

    /* importing PEM back works */
    var pub2 = await WinHash.modern.rsa.importPublic(pair.publicPem);
    var ct2 = await WinHash.modern.rsa.encryptText('via imported key', pub2);
    var priv2 = await WinHash.modern.rsa.importPrivate(pair.privatePem);
    var pt2 = await WinHash.modern.rsa.decryptText(ct2, priv2);
    assertEq(pt2, 'via imported key', 'rsa imported roundtrip');

    /* wrong private key must fail */
    var other = await WinHash.modern.rsa.generate(2048);
    var failed = false;
    try { await WinHash.modern.rsa.decryptText(ct2, other.privatePem); }
    catch (e) { failed = true; }
    assert(failed, 'rsa wrong key should throw');

    /* invalid PEM must throw a friendly error */
    var bad = false;
    try { await WinHash.modern.rsa.decryptText(ct2, 'not a pem'); }
    catch (e) { bad = true; }
    assert(bad, 'invalid pem should throw');
  }

  /* ============================================================
   * Runner
   * ========================================================== */
  async function main() {
    var t0 = Date.now();
    await test('hash vectors (18 inputs × 13 algorithms)', runHashVectors);
    await test('incremental chunked hashing (5 inputs × 9 algos × 4 chunk sizes)', runChunking);
    await test('HMAC vectors (sha1/sha256/sha512)', runHmac);
    await test('classical ciphers round-trips + known vectors', runClassical);
    await test('modern AES containers (gcm/cbc/ctr/chacha, text + files)', runModern);
    await test('RSA-OAEP 2048 round-trips', runRsa);

    var summary = document.getElementById('summary');
    var secs = ((Date.now() - t0) / 1000).toFixed(1);
    if (R.failed === 0) {
      summary.className = 'pass';
      summary.textContent = 'ALL ' + R.passed + ' TESTS PASSED (' + secs + 's)';
      document.title = 'PASS';
    } else {
      summary.className = 'fail';
      summary.textContent = R.failed + ' / ' + R.total + ' TESTS FAILED (' + secs + 's)';
      document.title = 'FAIL:' + R.failed;
    }
    document.getElementById('meta').textContent =
      'passed=' + R.passed + ' failed=' + R.failed + ' total=' + R.total;
    window.__DONE__ = true;
  }

  main().catch(function (e) {
    document.title = 'ERROR';
    fail('runner crashed', e && e.message ? e.message : String(e));
    window.__DONE__ = true;
  });
})();
