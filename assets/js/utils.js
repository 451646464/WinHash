/*
 * WinHash — utils.js
 * Encoding helpers, byte utilities, download/copy helpers.
 * Works on file:// and http(s)://, no modules, no fetch.
 */
(function (root) {
  'use strict';
  var WH = root.WinHash = root.WinHash || {};

  var utf8Encoder = new TextEncoder();
  var utf8Decoder = new TextDecoder('utf-8', { fatal: false });

  /* ---------- bytes / text ---------- */
  function utf8Encode(str) { return utf8Encoder.encode(String(str)); }
  function utf8Decode(bytes) { return utf8Decoder.decode(bytes); }

  /* ---------- hex ---------- */
  function bytesToHex(bytes) {
    var out = new Array(bytes.length);
    for (var i = 0; i < bytes.length; i++) {
      out[i] = (bytes[i] < 16 ? '0' : '') + bytes[i].toString(16);
    }
    return out.join('');
  }
  function hexToBytes(hex) {
    var clean = String(hex).replace(/[^0-9a-fA-F]/g, '');
    if (clean.length % 2 !== 0) throw new Error('Hex input must contain an even number of characters');
    var out = new Uint8Array(clean.length / 2);
    for (var i = 0; i < out.length; i++) {
      out[i] = parseInt(clean.substr(i * 2, 2), 16);
    }
    return out;
  }

  /* ---------- base64 (safe for large buffers) ---------- */
  function bytesToBase64(bytes) {
    var CHUNK = 0x8000;
    var parts = [];
    for (var i = 0; i < bytes.length; i += CHUNK) {
      var sub = bytes.subarray(i, i + CHUNK);
      var s = '';
      for (var j = 0; j < sub.length; j++) s += String.fromCharCode(sub[j]);
      parts.push(s);
    }
    return btoa(parts.join(''));
  }
  function base64ToBytes(b64) {
    var clean = String(b64).replace(/\s+/g, '');
    var bin;
    try { bin = atob(clean); }
    catch (e) { throw new Error('Input is not valid Base64'); }
    var out = new Uint8Array(bin.length);
    for (var i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  }

  /* ---------- random ---------- */
  function randomBytes(n) {
    var b = new Uint8Array(n);
    var api = root.crypto || root.msCrypto;
    /* getRandomValues is limited to 65536 bytes per call */
    var MAX = 65536;
    for (var off = 0; off < n; off += MAX) {
      api.getRandomValues(b.subarray(off, Math.min(off + MAX, n)));
    }
    return b;
  }

  /* ---------- formatting ---------- */
  function formatBytes(n, decimals) {
    if (n === 0) return '0 B';
    if (n < 1024) return n + ' B';
    var units = ['KB', 'MB', 'GB', 'TB'];
    var i = Math.floor(Math.log(n) / Math.log(1024));
    var v = n / Math.pow(1024, i);
    return v.toFixed(decimals === undefined ? 2 : decimals) + ' ' + units[i - 1];
  }

  /* ---------- download ---------- */
  function downloadBytes(bytes, filename, mime) {
    var blob = new Blob([bytes], { type: mime || 'application/octet-stream' });
    downloadBlob(blob, filename);
  }
  function downloadBlob(blob, filename) {
    var url = URL.createObjectURL(blob);
    var a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    setTimeout(function () {
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
    }, 1500);
  }

  /* ---------- clipboard ---------- */
  function copyText(text) {
    if (navigator.clipboard && navigator.clipboard.writeText) {
      return navigator.clipboard.writeText(text);
    }
    return new Promise(function (resolve, reject) {
      var ta = document.createElement('textarea');
      ta.value = text;
      ta.style.position = 'fixed';
      ta.style.opacity = '0';
      document.body.appendChild(ta);
      ta.select();
      try {
        document.execCommand('copy');
        resolve();
      } catch (e) { reject(e); }
      document.body.removeChild(ta);
    });
  }

  /* ---------- misc ---------- */
  function errMsg(e) {
    if (!e) return 'Unknown error';
    if (typeof e === 'string') return e;
    var m = e.message || String(e);
    var map = [
      ['OperationError', 'Decryption failed: wrong password or corrupted data'],
      ['InvalidAccessError', 'Invalid value — please check your inputs'],
      ['SyntaxError', 'Malformed input format'],
      ['DataError', 'Invalid data']
    ];
    for (var i = 0; i < map.length; i++) {
      if (m.indexOf(map[i][0]) !== -1) return map[i][1];
    }
    return m;
  }

  WH.utils = {
    utf8Encode: utf8Encode,
    utf8Decode: utf8Decode,
    bytesToHex: bytesToHex,
    hexToBytes: hexToBytes,
    bytesToBase64: bytesToBase64,
    base64ToBytes: base64ToBytes,
    randomBytes: randomBytes,
    formatBytes: formatBytes,
    downloadBytes: downloadBytes,
    downloadBlob: downloadBlob,
    copyText: copyText,
    errMsg: errMsg
  };
})(typeof self !== 'undefined' ? self : this);
