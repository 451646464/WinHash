/*
 * WinHash# — pages/tools.js
 * Password generator + Base64 / HEX / URL encoders.
 */
(function (root) {
  'use strict';
  var WH = root.WinHash;
  var U = WH.utils, UI = WH.ui;

  function $(id) { return document.getElementById(id); }
  function on(el, ev, fn) { if (el) el.addEventListener(ev, fn); }

  /* ============================================================
   * Password generator
   * ============================================================ */
  function entropyBits(length, pool) {
    if (pool < 2) pool = 2;
    return Math.round(length * (Math.log(pool) / Math.LN2));
  }

  function generatePassword() {
    var len = parseInt($('pgLen').value, 10) || 20;
    var sets = [];
    if ($('pgUpper').checked) sets.push('ABCDEFGHJKLMNPQRSTUVWXYZ');
    if ($('pgLower').checked) sets.push('abcdefghijkmnopqrstuvwxyz');
    if ($('pgDigits').checked) sets.push('23456789');
    if ($('pgSymbols').checked) sets.push('!@#$%^&*-_=+?');
    if (!sets.length) { UI.toast('Select at least one character set', 'error'); return null; }

    var pool = sets.join('');
    /* Ensure at least one char from each selected set */
    var chars = [];
    sets.forEach(function (s) {
      var buf = U.randomBytes(1);
      chars.push(s[buf[0] % s.length]);
    });
    while (chars.length < len) {
      var b = U.randomBytes(1);
      chars.push(pool[b[0] % pool.length]);
    }
    /* Fisher–Yates shuffle with random bytes */
    for (var i = chars.length - 1; i > 0; i--) {
      var rb = U.randomBytes(2);
      var r = ((rb[0] << 8) | rb[1]) % (i + 1);
      var t = chars[i]; chars[i] = chars[r]; chars[r] = t;
    }
    var pw = chars.slice(0, len).join('');
    $('pgOut').value = pw;
    paintPassword(pw, pool.length);
    return pw;
  }

  function paintPassword(pw, poolSize) {
    var bits = entropyBits(pw.length, poolSize);
    var bar = $('pgBar'), info = $('pgInfo');
    var label, color;
    if (bits < 40) { label = 'Weak'; color = 'var(--red)'; }
    else if (bits < 60) { label = 'Fair'; color = 'var(--warn)'; }
    else if (bits < 90) { label = 'Strong'; color = '#2ee6a6'; }
    else { label = 'Excellent'; color = '#2ee6a6'; }
    bar.style.width = Math.min(100, bits) + '%';
    bar.style.background = color;
    info.innerHTML = '<strong style="color:' + color + '">' + label + '</strong> · ' +
      pw.length + ' characters · ~' + bits + ' bits of entropy · ' +
      'roughly 10<sup>' + Math.max(0, Math.floor(bits / 3.3)) + '</sup> combinations';
  }

  function initPassword() {
    if (!$('pgGen')) return;

    on($('pgLen'), 'input', function () { $('pgLenVal').textContent = $('pgLen').value; });
    on($('pgGen'), 'click', function () {
      var pw = generatePassword();
      if (pw) UI.toast('Password generated', 'success');
    });
    on($('pgCopy'), 'click', function () {
      if ($('pgOut').value) UI.copy($('pgOut').value, 'Password copied');
      else UI.toast('Generate a password first', 'error');
    });

    /* live preview on load */
    generatePassword();
  }

  /* ============================================================
   * Encoders
   * ============================================================ */
  function encode(algo, text) {
    switch (algo) {
      case 'base64': return U.bytesToBase64(U.utf8Encode(text));
      case 'hex': return U.bytesToHex(U.utf8Encode(text));
      case 'url': return encodeURIComponent(text);
      default: return text;
    }
  }
  function decode(algo, text) {
    switch (algo) {
      case 'base64': return U.utf8Decode(U.base64ToBytes(text));
      case 'hex': return U.utf8Decode(U.hexToBytes(text));
      case 'url': return decodeURIComponent(text);
      default: return text;
    }
  }

  function initEncoders() {
    var algoSel = $('encAlgo'), inEl = $('encIn'), outEl = $('encOut');
    if (!algoSel) return;

    function refreshOut() {
      if (!inEl.value) { outEl.value = ''; return; }
      try { outEl.value = encode(algoSel.value, inEl.value); }
      catch (e) { outEl.value = ''; }
    }

    on(algoSel, 'change', refreshOut);
    on(inEl, 'input', refreshOut);

    on($('encSwap'), 'click', function () {
      if (!outEl.value) { UI.toast('Nothing to decode yet', 'error'); return; }
      try {
        var decoded = decode(algoSel.value, outEl.value);
        inEl.value = decoded;
        outEl.value = '';
        UI.toast('Decoded back to input', 'success');
      } catch (e) {
        UI.toast('Could not decode — is the input valid ' + algoSel.options[algoSel.selectedIndex].text + '?', 'error');
      }
    });

    on($('encClear'), 'click', function () { inEl.value = ''; outEl.value = ''; });
    on($('encCopy'), 'click', function () {
      if (outEl.value) UI.copy(outEl.value, 'Output copied');
      else UI.toast('Nothing to copy', 'error');
    });
  }

  /* ---------------- boot ---------------- */
  function boot() { initPassword(); initEncoders(); }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', boot);
  } else {
    boot();
  }
})(typeof self !== 'undefined' ? self : this);
