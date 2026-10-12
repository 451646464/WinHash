/*
 * WinHash — modern.js
 * Modern authenticated encryption via Web Crypto:
 *   - PBKDF2-HMAC-SHA256 key derivation (salt + iterations stored in header)
 *   - AES-256-GCM (authenticated, recommended), AES-256-CBC, AES-256-CTR,
 *     ChaCha20-Poly1305 (shown only if the browser supports it)
 *   - RSA-OAEP 2048/4096 for asymmetric text encryption
 *
 * Container format "WNH1" (binary):
 *   magic[4]="WNH1" | ver[1] | algoId[1] | iterations[4 BE] |
 *   saltLen[1] salt[16] | ivLen[1] iv[N] | metaLen[2 BE] metaCipher |
 *   dataCipher...
 * The JSON metadata (original filename/type/size) is itself encrypted
 * with a separate derived key so nothing leaks except the header.
 */
(function (root) {
  'use strict';
  var WH = root.WinHash = root.WinHash || {};
  var U = WH.utils;

  var subtle = (root.crypto && root.crypto.subtle) ? root.crypto.subtle : null;

  var ITER_DEFAULT = 600000;
  var MAGIC = [0x57, 0x4e, 0x48, 0x31]; /* "WNH1" */
  var VERSION = 1;

  var ALGOS = [
    { id: 1, key: 'aes-gcm', name: 'AES-256-GCM — Recommended',
      auth: true, ivLen: 12, desc: 'Authenticated encryption (AEAD) — detects any tampering with the data.' },
    { id: 2, key: 'aes-cbc', name: 'AES-256-CBC',
      auth: false, ivLen: 16, desc: 'Classic AES mode with PKCS#7 padding — compatible with legacy systems.' },
    { id: 3, key: 'aes-ctr', name: 'AES-256-CTR',
      auth: false, ivLen: 16, desc: 'Counter mode — fast and parallelizable, great for large files.' },
    { id: 4, key: 'chacha20', name: 'ChaCha20-Poly1305',
      auth: true, ivLen: 12, needsProbe: true, desc: 'Modern high-performance authenticated cipher, supported in recent browsers.' }
  ];
  var BY_KEY = {};
  var BY_ID = {};
  ALGOS.forEach(function (a) { BY_KEY[a.key] = a; BY_ID[a.id] = a; });

  function assertSupported() {
    if (!subtle) {
      throw new Error('Web Crypto API is not available — open the site over HTTPS, localhost, or directly from disk');
    }
  }

  /* ---------------- probes ---------------- */
  var chachaOk = null;
  function probeChacha() {
    if (chachaOk !== null) return Promise.resolve(chachaOk);
    if (!subtle) return Promise.resolve(false);
    var k = U.randomBytes(32);
    return subtle.importKey('raw', k, { name: 'ChaCha20-Poly1305' }, false, ['encrypt'])
      .then(function () { chachaOk = true; return true; })
      .catch(function () { chachaOk = false; return false; });
  }

  var cbcPads = null; /* does WebCrypto AES-CBC apply PKCS#7 itself? */
  function probeCbcPadding() {
    if (cbcPads !== null) return Promise.resolve(cbcPads);
    if (!subtle) return Promise.resolve(false);
    var key = U.randomBytes(32);
    var iv = U.randomBytes(16);
    return subtle.importKey('raw', key, { name: 'AES-CBC' }, false, ['encrypt'])
      .then(function (k) { return subtle.encrypt({ name: 'AES-CBC', iv: iv }, k, new Uint8Array(20)); })
      .then(function (ct) { cbcPads = (ct.byteLength === 32); return cbcPads; })
      .catch(function () { cbcPads = false; return false; });
  }

  /* Returns the algorithm list that actually works in this browser. */
  function supportedAlgorithms() {
    return probeChacha().then(function (ok) {
      return ALGOS.filter(function (a) { return !a.needsProbe || ok; });
    });
  }

  /* ---------------- PKCS#7 (used only when WebCrypto does not pad) ---------------- */
  function pkcs7Pad(bytes) {
    var pad = 16 - (bytes.length % 16);
    var out = new Uint8Array(bytes.length + pad);
    out.set(bytes, 0);
    for (var i = bytes.length; i < out.length; i++) out[i] = pad;
    return out;
  }
  function pkcs7Unpad(bytes) {
    if (bytes.length === 0 || bytes.length % 16 !== 0) {
      throw new Error('Invalid CBC data (bad length)');
    }
    var pad = bytes[bytes.length - 1];
    if (pad < 1 || pad > 16) throw new Error('CBAD_PADDING');
    for (var i = bytes.length - pad; i < bytes.length; i++) {
      if (bytes[i] !== pad) throw new Error('CBAD_PADDING');
    }
    return bytes.subarray(0, bytes.length - pad);
  }

  /* ---------------- key derivation ---------------- */
  function deriveKeys(password, salt, iterations) {
    assertSupported();
    return subtle.importKey('raw', U.utf8Encode(String(password)), 'PBKDF2', false, ['deriveBits'])
      .then(function (base) {
        return subtle.deriveBits(
          { name: 'PBKDF2', hash: 'SHA-256', salt: salt, iterations: iterations },
          base, 64 * 8);
      })
      .then(function (bits) {
        var b = new Uint8Array(bits);
        return { data: b.slice(0, 32), meta: b.slice(32, 64) };
      });
  }

  function aesKey(bytes, name) {
    return subtle.importKey('raw', bytes, { name: name }, false, ['encrypt', 'decrypt']);
  }

  /* ---------------- raw data encryption ---------------- */
  function encryptData(dataKey, algoKey, bytes) {
    var algo = BY_KEY[algoKey];
    if (!algo) return Promise.reject(new Error('Unknown algorithm: ' + algoKey));
    var iv = U.randomBytes(algo.ivLen);

    function finish(key, ct, usedIv) {
      return { iv: usedIv, ct: new Uint8Array(ct) };
    }

    if (algo.key === 'chacha20') {
      return subtle.importKey('raw', dataKey, { name: 'ChaCha20-Poly1305' }, false, ['encrypt'])
        .then(function (k) {
          return subtle.encrypt({ name: 'ChaCha20-Poly1305', iv: iv }, k, bytes);
        })
        .then(function (ct) { return finish(null, ct, iv); });
    }

    if (algo.key === 'aes-gcm') {
      return aesKey(dataKey, 'AES-GCM')
        .then(function (k) {
          return subtle.encrypt({ name: 'AES-GCM', iv: iv, tagLength: 128 }, k, bytes);
        })
        .then(function (ct) { return finish(null, ct, iv); });
    }

    if (algo.key === 'aes-cbc') {
      return probeCbcPadding()
        .then(function (pads) {
          var data = pads ? bytes : pkcs7Pad(bytes);
          return aesKey(dataKey, 'AES-CBC').then(function (k) {
            return subtle.encrypt({ name: 'AES-CBC', iv: iv }, k, data);
          });
        })
        .then(function (ct) { return finish(null, ct, iv); });
    }

    /* aes-ctr */
    return aesKey(dataKey, 'AES-CTR')
      .then(function (k) {
        return subtle.encrypt({ name: 'AES-CTR', counter: iv, length: 64 }, k, bytes);
      })
      .then(function (ct) { return finish(null, ct, iv); });
  }

  function decryptData(dataKey, algoKey, iv, ct) {
    var algo = BY_KEY[algoKey];
    if (!algo) return Promise.reject(new Error('Unknown algorithm found in file: ' + algoKey));

    if (algo.key === 'chacha20') {
      return subtle.importKey('raw', dataKey, { name: 'ChaCha20-Poly1305' }, false, ['decrypt'])
        .then(function (k) { return subtle.decrypt({ name: 'ChaCha20-Poly1305', iv: iv }, k, ct); })
        .then(function (buf) { return new Uint8Array(buf); });
    }
    if (algo.key === 'aes-gcm') {
      return aesKey(dataKey, 'AES-GCM')
        .then(function (k) { return subtle.decrypt({ name: 'AES-GCM', iv: iv, tagLength: 128 }, k, ct); })
        .then(function (buf) { return new Uint8Array(buf); });
    }
    if (algo.key === 'aes-cbc') {
      return aesKey(dataKey, 'AES-CBC')
        .then(function (k) { return subtle.decrypt({ name: 'AES-CBC', iv: iv }, k, ct); })
        .then(function (buf) {
          var bytes = new Uint8Array(buf);
          return probeCbcPadding().then(function (pads) {
            if (pads) return bytes;
            return pkcs7Unpad(bytes);
          });
        });
    }
    /* aes-ctr */
    return aesKey(dataKey, 'AES-CTR')
      .then(function (k) {
        return subtle.decrypt({ name: 'AES-CTR', counter: iv, length: 64 }, k, ct);
      })
      .then(function (buf) { return new Uint8Array(buf); });
  }

  /* ---------------- container ---------------- */
  function concatArrays(arrays) {
    var total = 0, i;
    for (i = 0; i < arrays.length; i++) total += arrays[i].length;
    var out = new Uint8Array(total);
    var off = 0;
    for (i = 0; i < arrays.length; i++) { out.set(arrays[i], off); off += arrays[i].length; }
    return out;
  }

  function buildContainer(algoId, iterations, salt, iv, metaCipher, dataCipher) {
    var head = new Uint8Array(4 + 1 + 1 + 4 + 1 + salt.length + 1 + iv.length + 2);
    var o = 0;
    head[o++] = MAGIC[0]; head[o++] = MAGIC[1]; head[o++] = MAGIC[2]; head[o++] = MAGIC[3];
    head[o++] = VERSION;
    head[o++] = algoId;
    head[o++] = (iterations >>> 24) & 255;
    head[o++] = (iterations >>> 16) & 255;
    head[o++] = (iterations >>> 8) & 255;
    head[o++] = iterations & 255;
    head[o++] = salt.length;
    head.set(salt, o); o += salt.length;
    head[o++] = iv.length;
    head.set(iv, o); o += iv.length;
    head[o++] = (metaCipher.length >>> 8) & 255;
    head[o++] = metaCipher.length & 255;
    return concatArrays([head, metaCipher, dataCipher]);
  }

  function parseContainer(bytes) {
    if (bytes.length < 20) throw new Error('File is too short — not a valid WinHash file');
    if (bytes[0] !== MAGIC[0] || bytes[1] !== MAGIC[1] || bytes[2] !== MAGIC[2] || bytes[3] !== MAGIC[3]) {
      throw new Error('This is not an encrypted WinHash file (signature mismatch)');
    }
    var o = 4;
    var ver = bytes[o++];
    if (ver !== VERSION) throw new Error('Unsupported container version: ' + ver);
    var algoId = bytes[o++];
    var iterations = ((bytes[o] << 24) | (bytes[o + 1] << 16) | (bytes[o + 2] << 8) | bytes[o + 3]) >>> 0;
    o += 4;
    var saltLen = bytes[o++];
    if (saltLen < 8 || o + saltLen > bytes.length) throw new Error('Corrupted file header (salt)');
    var salt = bytes.subarray(o, o + saltLen); o += saltLen;
    var ivLen = bytes[o++];
    if (ivLen < 8 || o + ivLen > bytes.length) throw new Error('Corrupted file header (iv)');
    var iv = bytes.subarray(o, o + ivLen); o += ivLen;
    var metaLen = (bytes[o] << 8) | bytes[o + 1];
    o += 2;
    if (o + metaLen > bytes.length) throw new Error('Corrupted file header (metadata)');
    var metaCipher = bytes.subarray(o, o + metaLen); o += metaLen;
    var dataCipher = bytes.subarray(o);
    if (iterations < 1000 || iterations > 5000000) throw new Error('Unreasonable iteration count in file');
    return {
      algoId: algoId, iterations: iterations, salt: salt, iv: iv,
      metaCipher: metaCipher, dataCipher: dataCipher
    };
  }

  var META_IV = new Uint8Array(12); /* safe: meta key is unique per file (random salt) and used once */

  function encryptBytes(bytes, password, algoKey, opts) {
    opts = opts || {};
    assertSupported();
    var algo = BY_KEY[algoKey];
    if (!algo) return Promise.reject(new Error('Unknown algorithm: ' + algoKey));
    if (algo.needsProbe && chachaOk === false) {
      return Promise.reject(new Error('Your browser does not support ChaCha20-Poly1305 — use AES-GCM instead'));
    }
    var iterations = opts.iterations || ITER_DEFAULT;
    var salt = U.randomBytes(16);
    var metaObj = opts.meta || {};
    var metaPlain = U.utf8Encode(JSON.stringify(metaObj));

    return deriveKeys(password, salt, iterations)
      .then(function (keys) {
        return subtle.importKey('raw', keys.meta, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt'])
          .then(function (mk) {
            return subtle.encrypt({ name: 'AES-GCM', iv: META_IV, tagLength: 128 }, mk, metaPlain);
          })
          .then(function (metaCipher) {
            return encryptData(keys.data, algo.key, bytes).then(function (res) {
              return buildContainer(algo.id, iterations, salt, res.iv,
                new Uint8Array(metaCipher), res.ct);
            });
          });
      });
  }

  function decryptBytes(container, password) {
    assertSupported();
    var parsed;
    try { parsed = parseContainer(container); }
    catch (e) { return Promise.reject(e); }
    var algo = BY_ID[parsed.algoId];
    if (!algo) return Promise.reject(new Error('The encryption algorithm in this file is not supported'));

    return deriveKeys(password, parsed.salt, parsed.iterations)
      .then(function (keys) {
        return subtle.importKey('raw', keys.meta, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt'])
          .then(function (mk) {
            return subtle.decrypt({ name: 'AES-GCM', iv: META_IV, tagLength: 128 }, mk, parsed.metaCipher);
          })
          .then(function (metaBuf) {
            var meta = {};
            try { meta = JSON.parse(U.utf8Decode(new Uint8Array(metaBuf))); }
            catch (e) { meta = {}; }
            return decryptData(keys.data, algo.key, parsed.iv, parsed.dataCipher)
              .then(function (bytes) {
                return { bytes: bytes, meta: meta, algo: algo, iterations: parsed.iterations };
              });
          });
      })
      .catch(function (e) {
        if (e && (e.name === 'OperationError' || /CBAD_PADDING/.test(e.message || ''))) {
          throw new Error('Wrong password, or the file is corrupted/tampered');
        }
        throw e;
      });
  }

  /* ---------------- text helpers ---------------- */
  function detectAndParse(input) {
    var clean = String(input).replace(/\s+/g, '');
    if (!clean) throw new Error('No ciphertext provided');
    if (/^574e4831/i.test(clean)) return U.hexToBytes(clean);
    if (/^v05imq/i.test(clean)) return U.base64ToBytes(clean);
    if (/^[0-9a-f]+$/i.test(clean) && clean.length % 2 === 0) return U.hexToBytes(clean);
    return U.base64ToBytes(clean);
  }

  function encryptText(text, password, algoKey, opts) {
    opts = opts || {};
    var meta = { n: opts.filename || 'winhash-text', t: 'text/plain', s: text.length, kind: 'text' };
    return encryptBytes(U.utf8Encode(text), password, algoKey, {
      iterations: opts.iterations,
      meta: meta
    }).then(function (bytes) {
      return (opts.format === 'hex') ? U.bytesToHex(bytes) : U.bytesToBase64(bytes);
    });
  }

  function decryptText(input, password) {
    var bytes;
    try { bytes = detectAndParse(input); }
    catch (e) { return Promise.reject(e); }
    return decryptBytes(bytes, password).then(function (res) {
      return U.utf8Decode(res.bytes);
    });
  }

  /* ---------------- RSA-OAEP ---------------- */
  var PEM_PUB = 'PUBLIC KEY';     /* SPKI */
  var PEM_PRIV = 'PRIVATE KEY';   /* PKCS8 */

  function derToPem(der, label) {
    var b64 = U.bytesToBase64(der);
    var lines = [];
    for (var i = 0; i < b64.length; i += 64) lines.push(b64.slice(i, i + 64));
    return '-----BEGIN ' + label + '-----\n' + lines.join('\n') + '\n-----END ' + label + '-----\n';
  }
  function pemToDer(pem, label) {
    var m = String(pem).match(new RegExp('-----BEGIN ' + label + '-----([\\s\\S]*?)-----END ' + label + '-----'));
    if (!m) throw new Error('Invalid key format — paste the full key including BEGIN/END lines');
    return U.base64ToBytes(m[1].replace(/\s+/g, ''));
  }

  function rsaImportPublic(pem) {
    assertSupported();
    var der = pemToDer(pem, PEM_PUB);
    return subtle.importKey('spki', der, { name: 'RSA-OAEP', hash: 'SHA-256' }, false, ['encrypt']);
  }
  function rsaImportPrivate(pem) {
    assertSupported();
    var der = pemToDer(pem, PEM_PRIV);
    return subtle.importKey('pkcs8', der, { name: 'RSA-OAEP', hash: 'SHA-256' }, false, ['decrypt']);
  }

  function rsaGenerate(bits) {
    assertSupported();
    bits = bits === 4096 ? 4096 : 2048;
    return subtle.generateKey({
      name: 'RSA-OAEP',
      modulusLength: bits,
      publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
      hash: 'SHA-256'
    }, true, ['encrypt', 'decrypt'])
      .then(function (pair) {
        return Promise.all([
          subtle.exportKey('spki', pair.publicKey),
          subtle.exportKey('pkcs8', pair.privateKey)
        ]).then(function (keys) {
          return {
            bits: bits,
            publicPem: derToPem(new Uint8Array(keys[0]), PEM_PUB),
            privatePem: derToPem(new Uint8Array(keys[1]), PEM_PRIV),
            publicKey: pair.publicKey,
            privateKey: pair.privateKey
          };
        });
      });
  }

  function rsaEncryptText(text, publicPemOrKey) {
    assertSupported();
    var keyP = (typeof publicPemOrKey === 'string') ? rsaImportPublic(publicPemOrKey) : Promise.resolve(publicPemOrKey);
    var data = U.utf8Encode(text);
    var chunk = 190; /* OAEP max = k - 2*hLen - 2 = 256 - 64 - 2 for 2048-bit RSA SHA-256 */
    return keyP.then(function (key) {
      var mod = (key.algorithm && key.algorithm.modulusLength) ? key.algorithm.modulusLength : 2048;
      chunk = mod / 8 - 66;
      var promises = [];
      for (var i = 0; i < data.length; i += chunk) {
        promises.push(subtle.encrypt({ name: 'RSA-OAEP' }, key, data.subarray(i, i + chunk)));
      }
      if (promises.length === 0) {
        return '';
      }
      return Promise.all(promises).then(function (cts) {
        var arrs = cts.map(function (c) { return new Uint8Array(c); });
        return U.bytesToBase64(concatArrays(arrs));
      });
    });
  }

  function rsaDecryptText(b64, privatePemOrKey) {
    assertSupported();
    var bytes = U.base64ToBytes(b64);
    var keyP = (typeof privatePemOrKey === 'string') ? rsaImportPrivate(privatePemOrKey) : Promise.resolve(privatePemOrKey);
    return keyP.then(function (key) {
      var mod = (key.algorithm && key.algorithm.modulusLength) ? key.algorithm.modulusLength : 2048;
      var cs = mod / 8;
      if (bytes.length === 0) return '';
      if (bytes.length % cs !== 0) {
        throw new Error('Ciphertext length does not match the key size — copy it in full');
      }
      var jobs = [];
      for (var i = 0; i < bytes.length; i += cs) {
        jobs.push(subtle.decrypt({ name: 'RSA-OAEP' }, key, bytes.subarray(i, i + cs)));
      }
      return Promise.all(jobs).then(function (pts) {
        var arrs = pts.map(function (p) { return new Uint8Array(p); });
        return U.utf8Decode(concatArrays(arrs));
      });
    }).catch(function (e) {
      if (e && e.name === 'OperationError') {
        throw new Error('RSA decryption failed: the private key does not match or the ciphertext is corrupted');
      }
      throw e;
    });
  }

  WH.modern = {
    algos: ALGOS,
    supportedAlgorithms: supportedAlgorithms,
    iterationsDefault: ITER_DEFAULT,
    encryptBytes: encryptBytes,
    decryptBytes: decryptBytes,
    encryptText: encryptText,
    decryptText: decryptText,
    parseContainer: parseContainer,
    rsa: {
      generate: rsaGenerate,
      encryptText: rsaEncryptText,
      decryptText: rsaDecryptText,
      importPublic: rsaImportPublic,
      importPrivate: rsaImportPrivate
    },
    isSupported: function () { return !!subtle; }
  };
})(typeof self !== 'undefined' ? self : this);
