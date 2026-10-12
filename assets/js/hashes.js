/*
 * WinHash — hashes.js
 * Hash implementations:
 *   - Pure JS (incremental): MD5, SHA-224, SHA3-224/256/384/512, RIPEMD-160,
 *     CRC32, FNV-1a 32, (SHA-256 fallback when WebCrypto is unavailable)
 *   - WebCrypto (native, fast): SHA-1, SHA-256, SHA-384, SHA-512
 * Verified against Python hashlib / zlib vectors in tests/vectors.js
 */
(function (root) {
  'use strict';
  var WH = root.WinHash = root.WinHash || {};

  /* =====================================================================
   * Generic block-hash driver: buffering + MD/SHA style padding
   * =================================================================== */
  function createBlockHash(spec) {
    var bs = spec.blockSize;
    var state = spec.initState.slice();
    var buf = new Uint8Array(bs);
    var bufLen = 0;
    var total = 0;

    function processBlock(blk) { spec.compress(state, blk); }

    return {
      update: function (bytes) {
        if (!(bytes instanceof Uint8Array)) bytes = new Uint8Array(bytes);
        total += bytes.length;
        var i = 0;
        if (bufLen > 0) {
          var take = Math.min(bs - bufLen, bytes.length);
          buf.set(bytes.subarray(0, take), bufLen);
          bufLen += take;
          i = take;
          if (bufLen === bs) { processBlock(buf); bufLen = 0; }
        }
        while (i + bs <= bytes.length) {
          processBlock(bytes.subarray(i, i + bs));
          i += bs;
        }
        if (i < bytes.length) {
          buf.set(bytes.subarray(i), 0);
          bufLen = bytes.length - i;
        }
      },
      digestBytes: function () {
        var rem = bufLen;
        var tailLen = (rem < bs - 8) ? (bs - rem) : (2 * bs - rem);
        var tail = new Uint8Array(tailLen);
        tail[0] = 0x80;
        var bitsLo = (total * 8) % 4294967296;
        var bitsHi = Math.floor(total / 536870912);
        var off = tailLen - 8;
        if (spec.lengthLittleEndian) {
          tail[off] = bitsLo & 255; tail[off + 1] = (bitsLo >>> 8) & 255;
          tail[off + 2] = (bitsLo >>> 16) & 255; tail[off + 3] = (bitsLo >>> 24) & 255;
          tail[off + 4] = bitsHi & 255; tail[off + 5] = (bitsHi >>> 8) & 255;
          tail[off + 6] = (bitsHi >>> 16) & 255; tail[off + 7] = (bitsHi >>> 24) & 255;
        } else {
          tail[off] = (bitsHi >>> 24) & 255; tail[off + 1] = (bitsHi >>> 16) & 255;
          tail[off + 2] = (bitsHi >>> 8) & 255; tail[off + 3] = bitsHi & 255;
          tail[off + 4] = (bitsLo >>> 24) & 255; tail[off + 5] = (bitsLo >>> 16) & 255;
          tail[off + 6] = (bitsLo >>> 8) & 255; tail[off + 7] = bitsLo & 255;
        }
        var j = 0;
        while (j < tailLen) {
          var t = Math.min(bs - bufLen, tailLen - j);
          buf.set(tail.subarray(j, j + t), bufLen);
          bufLen += t;
          j += t;
          if (bufLen === bs) { processBlock(buf); bufLen = 0; }
        }
        return spec.output(state);
      }
    };
  }

  /* =====================================================================
   * MD5
   * =================================================================== */
  var MD5_S = [
    7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
    5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
    4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
    6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21
  ];
  var MD5_K = (function () {
    var k = new Int32Array(64);
    for (var i = 0; i < 64; i++) k[i] = Math.floor(Math.abs(Math.sin(i + 1)) * 4294967296);
    return k;
  })();

  function md5Compress(state, block) {
    var m = new Int32Array(16);
    for (var i = 0; i < 16; i++) {
      var j = i * 4;
      m[i] = (block[j] | (block[j + 1] << 8) | (block[j + 2] << 16) | (block[j + 3] << 24)) | 0;
    }
    var A = state[0], B = state[1], C = state[2], D = state[3];
    for (i = 0; i < 64; i++) {
      var f, g;
      if (i < 16) { f = (B & C) | (~B & D); g = i; }
      else if (i < 32) { f = (D & B) | (~D & C); g = (5 * i + 1) % 16; }
      else if (i < 48) { f = B ^ C ^ D; g = (3 * i + 5) % 16; }
      else { f = C ^ (B | ~D); g = (7 * i) % 16; }
      var t = (A + f + MD5_K[i] + m[g]) | 0;
      A = D; D = C; C = B;
      B = (B + (((t << MD5_S[i]) | (t >>> (32 - MD5_S[i]))))) | 0;
    }
    state[0] = (state[0] + A) | 0;
    state[1] = (state[1] + B) | 0;
    state[2] = (state[2] + C) | 0;
    state[3] = (state[3] + D) | 0;
  }

  function createMD5() {
    return createBlockHash({
      blockSize: 64,
      lengthLittleEndian: true,
      initState: new Int32Array([0x67452301, 0xefcdab89 | 0, 0x98badcfe | 0, 0x10325476]),
      compress: md5Compress,
      output: function (state) {
        var out = new Uint8Array(16);
        for (var i = 0; i < 4; i++) {
          out[i * 4] = state[i] & 255;
          out[i * 4 + 1] = (state[i] >>> 8) & 255;
          out[i * 4 + 2] = (state[i] >>> 16) & 255;
          out[i * 4 + 3] = (state[i] >>> 24) & 255;
        }
        return out;
      }
    });
  }

  /* =====================================================================
   * SHA-256 core (shared by SHA-224 and JS SHA-256 fallback)
   * =================================================================== */
  var K256 = new Uint32Array([
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
  ]);

  function sha256Compress(state, block) {
    var w = new Uint32Array(64);
    var i;
    for (i = 0; i < 16; i++) {
      var j = i * 4;
      w[i] = ((block[j] << 24) | (block[j + 1] << 16) | (block[j + 2] << 8) | block[j + 3]) >>> 0;
    }
    for (i = 16; i < 64; i++) {
      var x = w[i - 15];
      var s0 = ((x >>> 7) | (x << 25)) ^ ((x >>> 18) | (x << 14)) ^ (x >>> 3);
      var y = w[i - 2];
      var s1 = ((y >>> 17) | (y << 15)) ^ ((y >>> 19) | (y << 13)) ^ (y >>> 10);
      w[i] = (w[i - 16] + s0 + w[i - 7] + s1) >>> 0;
    }
    var a = state[0], b = state[1], c = state[2], d = state[3];
    var e = state[4], f = state[5], g = state[6], h = state[7];
    for (i = 0; i < 64; i++) {
      var S1 = ((e >>> 6) | (e << 26)) ^ ((e >>> 11) | (e << 21)) ^ ((e >>> 25) | (e << 7));
      var ch = (e & f) ^ (~e & g);
      var t1 = (h + S1 + ch + K256[i] + w[i]) >>> 0;
      var S0 = ((a >>> 2) | (a << 30)) ^ ((a >>> 13) | (a << 19)) ^ ((a >>> 22) | (a << 10));
      var maj = (a & b) ^ (a & c) ^ (b & c);
      var t2 = (S0 + maj) >>> 0;
      h = g; g = f; f = e;
      e = (d + t1) >>> 0;
      d = c; c = b; b = a;
      a = (t1 + t2) >>> 0;
    }
    state[0] = (state[0] + a) >>> 0;
    state[1] = (state[1] + b) >>> 0;
    state[2] = (state[2] + c) >>> 0;
    state[3] = (state[3] + d) >>> 0;
    state[4] = (state[4] + e) >>> 0;
    state[5] = (state[5] + f) >>> 0;
    state[6] = (state[6] + g) >>> 0;
    state[7] = (state[7] + h) >>> 0;
  }

  function shaOut(state, bytes) {
    var out = new Uint8Array(bytes);
    var words = Math.ceil(bytes / 4);
    for (var i = 0; i < words; i++) {
      var v = state[i];
      out[i * 4] = (v >>> 24) & 255;
      out[i * 4 + 1] = (v >>> 16) & 255;
      out[i * 4 + 2] = (v >>> 8) & 255;
      if (i * 4 + 3 < bytes) out[i * 4 + 3] = v & 255;
    }
    return out;
  }

  function createSHA224() {
    return createBlockHash({
      blockSize: 64,
      lengthLittleEndian: false,
      initState: new Uint32Array([
        0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939,
        0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4
      ]),
      compress: sha256Compress,
      output: function (state) { return shaOut(state, 28); }
    });
  }

  function createSHA256JS() {
    return createBlockHash({
      blockSize: 64,
      lengthLittleEndian: false,
      initState: new Uint32Array([
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
      ]),
      compress: sha256Compress,
      output: function (state) { return shaOut(state, 32); }
    });
  }

  /* =====================================================================
   * SHA-3 (Keccak-f[1600], BigInt lanes)
   * =================================================================== */
  var KECCAK_RC_STR = [
    '0x0000000000000001', '0x0000000000008082', '0x800000000000808a', '0x8000000080008000',
    '0x000000000000808b', '0x0000000080000001', '0x8000000080008081', '0x8000000000008009',
    '0x000000000000008a', '0x0000000000000088', '0x0000000080008009', '0x000000008000000a',
    '0x000000008000808b', '0x800000000000008b', '0x8000000000008089', '0x8000000000008003',
    '0x8000000000008002', '0x8000000000000080', '0x000000000000800a', '0x800000008000000a',
    '0x8000000080008081', '0x8000000000008080', '0x0000000080000001', '0x8000000080008008'
  ];
  /* NOTE: parsed from strings — Number literals would lose precision above 2^53 */
  var KECCAK_RC = KECCAK_RC_STR.map(function (v) { return BigInt(v); });

  /* rotation offsets r[x][y] */
  var KECCAK_ROT = [
    [0, 36, 3, 41, 18],
    [1, 44, 10, 45, 2],
    [62, 6, 43, 15, 61],
    [28, 55, 25, 21, 56],
    [27, 20, 39, 8, 14]
  ];

  var MASK64 = (1n << 64n) - 1n;

  function keccakF(A) {
    var C = new Array(5), D = new Array(5), B = new Array(25);
    var x, y, i;
    for (i = 0; i < 25; i++) B[i] = 0n;
    for (var round = 0; round < 24; round++) {
      /* theta */
      for (x = 0; x < 5; x++) {
        C[x] = A[x] ^ A[x + 5] ^ A[x + 10] ^ A[x + 15] ^ A[x + 20];
      }
      for (x = 0; x < 5; x++) {
        D[x] = C[(x + 4) % 5] ^ (((C[(x + 1) % 5] << 1n) | (C[(x + 1) % 5] >> 63n)) & MASK64);
      }
      for (x = 0; x < 5; x++) {
        for (y = 0; y < 5; y++) A[x + 5 * y] = (A[x + 5 * y] ^ D[x]) & MASK64;
      }
      /* rho + pi */
      for (x = 0; x < 5; x++) {
        for (y = 0; y < 5; y++) {
          var s = BigInt(KECCAK_ROT[x][y]);
          var v = A[x + 5 * y];
          var r = s === 0n ? v : (((v << s) | (v >> (64n - s))) & MASK64);
          B[y + 5 * ((2 * x + 3 * y) % 5)] = r;
        }
      }
      /* chi */
      for (x = 0; x < 5; x++) {
        for (y = 0; y < 5; y++) {
          A[x + 5 * y] = (B[x + 5 * y] ^ ((~B[(x + 1) % 5 + 5 * y] & MASK64) & B[(x + 2) % 5 + 5 * y])) & MASK64;
        }
      }
      /* iota */
      A[0] = (A[0] ^ KECCAK_RC[round]) & MASK64;
    }
  }

  function createKeccak(bits) {
    var outLen = bits / 8;
    var rate = 200 - 2 * outLen;
    var A = new Array(25);
    for (var i = 0; i < 25; i++) A[i] = 0n;
    var buf = new Uint8Array(rate);
    var bufLen = 0;
    var finished = false;

    function absorbBlock(blk) {
      for (var k = 0; k < rate; k += 8) {
        var lane = 0n;
        for (var b = 7; b >= 0; b--) lane = (lane << 8n) | BigInt(blk[k + b]);
        var idx = k / 8;
        A[idx] = (A[idx] ^ lane) & MASK64;
      }
      keccakF(A);
    }

    return {
      update: function (bytes) {
        if (!(bytes instanceof Uint8Array)) bytes = new Uint8Array(bytes);
        var i = 0;
        if (bufLen > 0) {
          var take = Math.min(rate - bufLen, bytes.length);
          buf.set(bytes.subarray(0, take), bufLen);
          bufLen += take;
          i = take;
          if (bufLen === rate) { absorbBlock(buf); bufLen = 0; }
        }
        while (i + rate <= bytes.length) {
          absorbBlock(bytes.subarray(i, i + rate));
          i += rate;
        }
        if (i < bytes.length) {
          buf.set(bytes.subarray(i), 0);
          bufLen = bytes.length - i;
        }
      },
      digestBytes: function () {
        if (finished) throw new Error('This hash state has already been finalized');
        finished = true;
        /* pad10* with SHA-3 domain separator 0x06 */
        var rem = bufLen;
        var padded;
        if (rem === rate - 1) {
          padded = new Uint8Array(rate);
          padded.set(buf.subarray(0, rem), 0);
          padded[rem] = 0x86;
        } else {
          padded = new Uint8Array(rate);
          padded.set(buf.subarray(0, rem), 0);
          padded[rem] = 0x06;
          padded[rate - 1] |= 0x80;
        }
        absorbBlock(padded);
        /* squeeze */
        var out = new Uint8Array(outLen);
        var produced = 0;
        while (produced < outLen) {
          for (var k = 0; k < rate && produced < outLen; k += 8) {
            var lane = A[k / 8];
            for (var b = 0; b < 8 && produced < outLen; b++) {
              out[produced++] = Number((lane >> BigInt(8 * b)) & 0xffn);
            }
          }
          if (produced < outLen) keccakF(A);
        }
        return out;
      }
    };
  }

  /* =====================================================================
   * RIPEMD-160
   * =================================================================== */
  var RI = {
    r1: [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
         7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8,
         3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12,
         1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15, 14, 5, 6, 2,
         4, 0, 5, 9, 7, 12, 2, 10, 14, 1, 3, 8, 11, 6, 15, 13],
    r2: [5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12,
         6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12, 4, 9, 1, 2,
         15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13,
         8, 6, 4, 1, 3, 11, 15, 0, 5, 12, 2, 13, 9, 7, 10, 14,
         12, 15, 10, 4, 1, 5, 8, 7, 6, 2, 13, 14, 0, 3, 9, 11],
    s1: [11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8,
         7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15, 9, 11, 7, 13, 12,
         11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5,
         11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12,
         9, 15, 5, 11, 6, 8, 13, 12, 5, 12, 13, 14, 11, 8, 5, 6],
    s2: [8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6,
         9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12, 7, 6, 15, 13, 11,
         9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5,
         15, 5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15, 8,
         8, 5, 12, 9, 12, 5, 14, 6, 8, 13, 6, 5, 15, 13, 11, 11],
    kl: [0x00000000, 0x5a827999, 0x6ed9eba1, 0x8f1bbcdc, 0xa953fd4e],
    kr: [0x50a28be6, 0x5c4dd124, 0x6d703ef3, 0x7a6d76e9, 0x00000000]
  };

  function ripemdF(j, x, y, z) {
    switch (j) {
      case 0: return x ^ y ^ z;
      case 1: return (x & y) | (~x & z);
      case 2: return (x | ~y) ^ z;
      case 3: return (x & z) | (y & ~z);
      case 4: return x ^ (y | ~z);
    }
    return 0;
  }

  function ripemdCompress(state, block) {
    var X = new Int32Array(16);
    for (var i = 0; i < 16; i++) {
      var j = i * 4;
      X[i] = (block[j] | (block[j + 1] << 8) | (block[j + 2] << 16) | (block[j + 3] << 24)) | 0;
    }
    var al = state[0] | 0, bl = state[1] | 0, cl = state[2] | 0, dl = state[3] | 0, el = state[4] | 0;
    var ar = state[0] | 0, br = state[1] | 0, cr = state[2] | 0, dr = state[3] | 0, er = state[4] | 0;
    function rol(v, n) { return ((v << n) | (v >>> (32 - n))) | 0; }

    for (var rnd = 0; rnd < 5; rnd++) {
      for (i = 0; i < 16; i++) {
        var t;
        /* left line: function index = round */
        t = (rol((al + ripemdF(rnd, bl, cl, dl) + X[RI.r1[rnd * 16 + i]] + RI.kl[rnd]) | 0, RI.s1[rnd * 16 + i]) + el) | 0;
        al = el; el = dl; dl = rol(cl, 10); cl = bl; bl = t;
        /* right line: function index = 4 - round */
        t = (rol((ar + ripemdF(4 - rnd, br, cr, dr) + X[RI.r2[rnd * 16 + i]] + RI.kr[rnd]) | 0, RI.s2[rnd * 16 + i]) + er) | 0;
        ar = er; er = dr; dr = rol(cr, 10); cr = br; br = t;
      }
    }

    var t = (state[1] + cl + dr) | 0;
    state[1] = (state[2] + dl + er) | 0;
    state[2] = (state[3] + el + ar) | 0;
    state[3] = (state[4] + al + br) | 0;
    state[4] = (state[0] + bl + cr) | 0;
    state[0] = t;
  }

  function createRIPEMD160() {
    return createBlockHash({
      blockSize: 64,
      lengthLittleEndian: true,
      initState: new Int32Array([
        0x67452301, 0xefcdab89 | 0, 0x98badcfe | 0, 0x10325476, 0xc3d2e1f0 | 0
      ]),
      compress: ripemdCompress,
      output: function (state) {
        var out = new Uint8Array(20);
        for (var i = 0; i < 5; i++) {
          out[i * 4] = state[i] & 255;
          out[i * 4 + 1] = (state[i] >>> 8) & 255;
          out[i * 4 + 2] = (state[i] >>> 16) & 255;
          out[i * 4 + 3] = (state[i] >>> 24) & 255;
        }
        return out;
      }
    });
  }

  /* =====================================================================
   * CRC32 / FNV-1a (checksums)
   * =================================================================== */
  var CRC_TABLE = (function () {
    var t = new Uint32Array(256);
    for (var n = 0; n < 256; n++) {
      var c = n;
      for (var k = 0; k < 8; k++) c = (c & 1) ? (0xEDB88320 ^ (c >>> 1)) : (c >>> 1);
      t[n] = c >>> 0;
    }
    return t;
  })();

  function createCRC32() {
    var crc = 0xFFFFFFFF;
    return {
      update: function (bytes) {
        if (!(bytes instanceof Uint8Array)) bytes = new Uint8Array(bytes);
        for (var i = 0; i < bytes.length; i++) {
          crc = CRC_TABLE[(crc ^ bytes[i]) & 0xFF] ^ (crc >>> 8);
        }
      },
      digestBytes: function () {
        var v = (crc ^ 0xFFFFFFFF) >>> 0;
        return new Uint8Array([(v >>> 24) & 255, (v >>> 16) & 255, (v >>> 8) & 255, v & 255]);
      }
    };
  }

  function createFNV1a32() {
    var h = 0x811c9dc5;
    return {
      update: function (bytes) {
        if (!(bytes instanceof Uint8Array)) bytes = new Uint8Array(bytes);
        for (var i = 0; i < bytes.length; i++) {
          h ^= bytes[i];
          h = Math.imul(h, 0x01000193) >>> 0;
        }
      },
      digestBytes: function () {
        return new Uint8Array([(h >>> 24) & 255, (h >>> 16) & 255, (h >>> 8) & 255, h & 255]);
      }
    };
  }

  /* =====================================================================
   * WebCrypto wrapper (buffers chunks, digests at the end)
   * =================================================================== */
  var SUBtle = (root.crypto && root.crypto.subtle) ? root.crypto.subtle : null;
  var MAX_BUFFER = 1.5 * 1024 * 1024 * 1024; /* 1.5 GiB safety cap */

  function createWebCrypto(name) {
    var chunks = [];
    var size = 0;
    return {
      update: function (bytes) {
        if (!(bytes instanceof Uint8Array)) bytes = new Uint8Array(bytes);
        size += bytes.length;
        if (size > MAX_BUFFER) {
          throw new Error('File exceeds the safe processing limit (' + WH.utils.formatBytes(MAX_BUFFER) + ')');
        }
        chunks.push(bytes.slice());
      },
      digestBytes: function () {
        if (!SUBtle) {
          return Promise.reject(new Error('Web Crypto is not available here — open the site over HTTPS or localhost'));
        }
        var all;
        if (chunks.length === 1) { all = chunks[0]; }
        else {
          all = new Uint8Array(size);
          var off = 0;
          for (var i = 0; i < chunks.length; i++) { all.set(chunks[i], off); off += chunks[i].length; }
        }
        return SUBtle.digest(name, all.buffer.slice(all.byteOffset, all.byteOffset + all.byteLength))
          .then(function (buf) { return new Uint8Array(buf); });
      }
    };
  }

  function createSHA256() {
    if (SUBtle) return createWebCrypto('SHA-256');
    return createSHA256JS();
  }

  /* =====================================================================
   * Registry
   * =================================================================== */
  var LIST = [
    { id: 'sha512', name: 'SHA-512', bits: 512, cat: 'modern', note: 'Strong member of the SHA-2 family', secure: 'strong' },
    { id: 'sha384', name: 'SHA-384', bits: 384, cat: 'modern', note: 'Common for authentication and signatures', secure: 'strong' },
    { id: 'sha256', name: 'SHA-256', bits: 256, cat: 'modern', note: 'The most widely used hash worldwide', secure: 'strong' },
    { id: 'sha224', name: 'SHA-224', bits: 224, cat: 'modern', note: 'Truncated variant of SHA-256', secure: 'strong' },
    { id: 'sha1', name: 'SHA-1', bits: 160, cat: 'legacy', note: 'Deprecated — do not use for security', secure: 'weak' },
    { id: 'sha3_512', name: 'SHA3-512', bits: 512, cat: 'modern', note: 'Modern Keccak architecture (NIST)', secure: 'strong' },
    { id: 'sha3_384', name: 'SHA3-384', bits: 384, cat: 'modern', note: 'Modern Keccak architecture (NIST)', secure: 'strong' },
    { id: 'sha3_256', name: 'SHA3-256', bits: 256, cat: 'modern', note: 'Modern Keccak architecture (NIST)', secure: 'strong' },
    { id: 'sha3_224', name: 'SHA3-224', bits: 224, cat: 'modern', note: 'Modern Keccak architecture (NIST)', secure: 'strong' },
    { id: 'ripemd160', name: 'RIPEMD-160', bits: 160, cat: 'legacy', note: 'Used in Bitcoin for wallet addresses', secure: 'medium' },
    { id: 'md5', name: 'MD5', bits: 128, cat: 'broken', note: 'Broken — non-security use only', secure: 'broken' },
    { id: 'crc32', name: 'CRC32', bits: 32, cat: 'checksum', note: 'Error-detection checksum, not encryption', secure: 'none' },
    { id: 'fnv1a32', name: 'FNV-1a 32', bits: 32, cat: 'checksum', note: 'Fast non-cryptographic checksum', secure: 'none' }
  ];

  var FACTORIES = {
    md5: createMD5,
    sha1: function () { return createWebCrypto('SHA-1'); },
    sha224: createSHA224,
    sha256: createSHA256,
    sha384: function () { return createWebCrypto('SHA-384'); },
    sha512: function () { return createWebCrypto('SHA-512'); },
    sha3_224: function () { return createKeccak(224); },
    sha3_256: function () { return createKeccak(256); },
    sha3_384: function () { return createKeccak(384); },
    sha3_512: function () { return createKeccak(512); },
    ripemd160: createRIPEMD160,
    crc32: createCRC32,
    fnv1a32: createFNV1a32
  };

  function create(id) {
    var f = FACTORIES[id];
    if (!f) throw new Error('Unknown hash algorithm: ' + id);
    var impl = f();
    var api = {
      update: function (bytes) { impl.update(bytes); },
      digestBytes: function () {
        var r = impl.digestBytes();
        return (r && typeof r.then === 'function') ? r : Promise.resolve(r);
      },
      digestHex: function () {
        return api.digestBytes().then(function (b) { return WH.utils.bytesToHex(b); });
      }
    };
    return api;
  }

  function digestHex(id, bytes) {
    var h = create(id);
    h.update(bytes);
    return h.digestHex();
  }

  /* HMAC (SHA-1 / SHA-256 / SHA-512) via WebCrypto.
   * WebCrypto rejects empty keys, so an empty key is expanded to a
   * zero-filled block first — exactly what HMAC specifies. */
  function hmacHex(algo, keyBytes, msgBytes) {
    if (!SUBtle) return Promise.reject(new Error('Web Crypto is not available in this context'));
    var hashName = { hmac_sha1: 'SHA-1', hmac_sha256: 'SHA-256', hmac_sha512: 'SHA-512' }[algo];
    if (!hashName) return Promise.reject(new Error('Unsupported HMAC algorithm: ' + algo));
    var key = keyBytes;
    if (!key || key.length === 0) {
      var blockSize = (hashName === 'SHA-512') ? 128 : 64;
      key = new Uint8Array(blockSize); /* zero block == empty key */
    }
    return SUBtle.importKey('raw', key, { name: 'HMAC', hash: hashName }, false, ['sign'])
      .then(function (k) { return SUBtle.sign('HMAC', k, msgBytes); })
      .then(function (sig) { return WH.utils.bytesToHex(new Uint8Array(sig)); });
  }

  WH.hashes = {
    list: LIST,
    create: create,
    digestHex: digestHex,
    hmacHex: hmacHex
  };
})(typeof self !== 'undefined' ? self : this);
