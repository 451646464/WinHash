/*
 * WinHash# — pages/text.js
 * Text encryption workbench: Classical ciphers · AES-256 · RSA.
 */
(function (root) {
  'use strict';
  var WH = root.WinHash;
  var U = WH.utils, C = WH.classical, M = WH.modern, UI = WH.ui;

  function $(id) { return document.getElementById(id); }
  function on(el, ev, fn) { if (el) el.addEventListener(ev, fn); }

  /* ============================================================
   * Shared helpers
   * ============================================================ */

  /* Rough password strength from entropy (length + charset variety). */
  function scorePassword(pw) {
    if (!pw) return { bits: 0, label: 'No password yet', color: 'var(--muted)', w: 0 };
    var pool = 0;
    if (/[a-z]/.test(pw)) pool += 26;
    if (/[A-Z]/.test(pw)) pool += 26;
    if (/[0-9]/.test(pw)) pool += 10;
    if (/[^a-zA-Z0-9]/.test(pw)) pool += 33;
    if (!pool) pool = 26;
    var bits = Math.round(pw.length * (Math.log(pool) / Math.LN2));
    var label, color;
    if (bits < 40) { label = 'Weak — add length or variety'; color = 'var(--red)'; }
    else if (bits < 60) { label = 'Fair — a decent password'; color = 'var(--warn)'; }
    else if (bits < 90) { label = 'Strong — good for real use'; color = '#2ee6a6'; }
    else { label = 'Excellent — very hard to crack'; color = '#2ee6a6'; }
    return { bits: bits, label: label + '  ·  ~' + bits + ' bits', color: color, w: Math.min(100, bits) };
  }
  function paintStrength(barEl, labelEl, pw) {
    var s = scorePassword(pw);
    if (barEl) { barEl.style.width = s.w + '%'; barEl.style.background = s.color; }
    if (labelEl) { labelEl.textContent = s.label; labelEl.style.color = s.color; }
  }

  /* Wire an eye button to toggle a password/text field. */
  function wireEye(eyeId, inputId) {
    var eye = $(eyeId), input = $(inputId);
    on(eye, 'click', function () {
      if (!input) return;
      var show = input.type === 'password';
      input.type = show ? 'text' : 'password';
      eye.setAttribute('aria-pressed', show ? 'true' : 'false');
    });
  }

  /* Run a busy-aware async action with error toasting. */
  function guard(btn, label, fn) {
    UI.setBusy(btn, true, label);
    return Promise.resolve().then(fn).catch(function (e) {
      UI.toast(U.errMsg(e), 'error');
    }).then(function () { UI.setBusy(btn, false); });
  }

  /* ============================================================
   * 1) Classical ciphers
   * ============================================================ */
  function initClassical() {
    var algoSel = $('clAlgo'), desc = $('clDesc');
    var keyField = $('clKeyField'), keyInput = $('clKey'), keyHint = $('clKeyHint');
    var genBtn = $('clGenKey');
    var inEl = $('clIn'), outEl = $('clOut');

    if (!algoSel) return;

    C.list.forEach(function (a) {
      var o = document.createElement('option');
      o.value = a.id; o.textContent = a.name;
      algoSel.appendChild(o);
    });
    algoSel.value = 'vigenere';

    var HINTS = {
      shift: 'Alphabet shift, 0–25',
      letters: 'Latin letters only (A–Z)',
      text: 'Any key text',
      otp: 'Must be as long as your message',
      cols: 'Number of columns, 2–9',
      rails: 'Number of rails, 2–10'
    };

    function current() { return C.byId(algoSel.value); }

    function syncKeyUi() {
      var a = current();
      if (!a) return;
      desc.textContent = a.desc + '  ·  Security level: ' + a.level;

      var needsKey = a.keyType !== 'none';
      keyField.classList.toggle('hidden', !needsKey);

      /* numeric keys become number inputs */
      var numeric = (a.keyType === 'shift' || a.keyType === 'cols' || a.keyType === 'rails');
      keyInput.type = numeric ? 'number' : 'text';
      keyInput.min = a.keyType === 'shift' ? '0' : (a.keyType === 'rails' ? '2' : '2');
      keyInput.max = a.keyType === 'shift' ? '25' : (a.keyType === 'cols' ? '9' : '10');

      keyHint.textContent = HINTS[a.keyType] || '';
      keyInput.placeholder = 'Enter key';
      keyInput.value = a.keyDefault || '';

      /* OTP gets its generator button; others hide it */
      genBtn.classList.toggle('hidden', a.keyType !== 'otp');
      /* OTP key box is the important one */
      keyInput.setAttribute('data-otp', a.keyType === 'otp' ? '1' : '0');
    }

    on(algoSel, 'change', syncKeyUi);
    syncKeyUi();

    /* OTP: generate a key sized to the current message */
    on(genBtn, 'click', function () {
      var a = current();
      var n = Math.max(1, C.countLetters(inEl.value) || 24);
      if (n > 4000) n = 4000;
      keyInput.value = C.generateOtpKey(n);
      UI.toast('Generated a ' + keyInput.value.length + '-letter key', 'success');
    });

    wireEye('clKeyEye', 'clKey');

    function runMode(mode, btn) {
      var a = current();
      var text = inEl.value;
      if (!text) { UI.toast('Enter some text first', 'error'); return; }
      guard(btn, 'Working…', function () {
        var out = C.run(a.id, mode, text, keyInput.value);
        outEl.value = out;
        UI.toast((mode === 'encrypt' ? 'Encrypted' : 'Decrypted') + ' with ' + a.name, 'success');
      });
    }

    on($('clEncrypt'), 'click', function () { runMode('encrypt', $('clEncrypt')); });
    on($('clDecrypt'), 'click', function () { runMode('decrypt', $('clDecrypt')); });

    on($('clSwap'), 'click', function () {
      if (!outEl.value) { UI.toast('Nothing to move yet', 'error'); return; }
      inEl.value = outEl.value;
      outEl.value = '';
      UI.toast('Result moved to input', 'success');
    });
    on($('clClear'), 'click', function () { inEl.value = ''; outEl.value = ''; });
    on($('clCopy'), 'click', function () { if (outEl.value) UI.copy(outEl.value, 'Result copied'); else UI.toast('Nothing to copy', 'error'); });
    on($('clDownload'), 'click', function () {
      if (!outEl.value) { UI.toast('Nothing to download', 'error'); return; }
      U.downloadBlob(new Blob([outEl.value], { type: 'text/plain;charset=utf-8' }), 'winhash-text.txt');
      UI.toast('Download started', 'success');
    });

    /* exposed for deep-linking */
    return { select: function (id) { if (C.byId(id)) { algoSel.value = id; syncKeyUi(); } } };
  }

  /* ============================================================
   * 2) AES-256 (modern)
   * ============================================================ */
  function initAes() {
    var algoSel = $('aesAlgo'), desc = $('aesDesc');
    var pass = $('aesPass'), bar = $('aesBar'), sLabel = $('aesStrength');
    var fmtSel = $('aesFormat'), iterSel = $('aesIter');
    var inEl = $('aesIn'), outEl = $('aesOut');

    if (!algoSel) return;

    wireEye('aesEye', 'aesPass');
    on(pass, 'input', function () { paintStrength(bar, sLabel, pass.value); });

    var algoMap = {};
    return M.supportedAlgorithms().then(function (list) {
      list.forEach(function (a) {
        var o = document.createElement('option');
        o.value = a.key; o.textContent = a.name;
        algoSel.appendChild(o);
        algoMap[a.key] = a;
      });
      algoSel.value = list.length ? list[0].key : 'aes-gcm';
      syncDesc();

      function syncDesc() {
        var a = algoMap[algoSel.value];
        desc.textContent = a ? a.desc : '';
      }
      on(algoSel, 'change', syncDesc);

      function opts() {
        return {
          iterations: parseInt(iterSel.value, 10) || M.iterationsDefault,
          format: fmtSel.value,
          filename: 'winhash-text'
        };
      }

      on($('aesEncrypt'), 'click', function () {
        if (!inEl.value) { UI.toast('Enter some text first', 'error'); return; }
        if (!pass.value) { UI.toast('Enter a password first', 'error'); return; }
        guard($('aesEncrypt'), 'Encrypting…', function () {
          return M.encryptText(inEl.value, pass.value, algoSel.value, opts()).then(function (ct) {
            outEl.value = ct;
            UI.toast('Encrypted with ' + (algoMap[algoSel.value] || {}).name, 'success');
          });
        });
      });

      on($('aesDecrypt'), 'click', function () {
        if (!outEl.value && !inEl.value) { UI.toast('Paste some ciphertext first', 'error'); return; }
        var src = outEl.value || inEl.value;
        if (!pass.value) { UI.toast('Enter the password first', 'error'); return; }
        guard($('aesDecrypt'), 'Decrypting…', function () {
          return M.decryptText(src, pass.value).then(function (pt) {
            outEl.value = pt;
            UI.toast('Decrypted successfully', 'success');
          });
        });
      });

      on($('aesClear'), 'click', function () { inEl.value = ''; outEl.value = ''; });
      on($('aesCopy'), 'click', function () { if (outEl.value) UI.copy(outEl.value, 'Result copied'); else UI.toast('Nothing to copy', 'error'); });
      on($('aesDownload'), 'click', function () {
        if (!outEl.value) { UI.toast('Nothing to download', 'error'); return; }
        U.downloadBlob(new Blob([outEl.value], { type: 'text/plain;charset=utf-8' }), 'winhash-aes.txt');
        UI.toast('Download started', 'success');
      });

      return { select: function (key) { if (algoMap[key]) { algoSel.value = key; syncDesc(); } } };
    });
  }

  /* ============================================================
   * 3) RSA (asymmetric)
   * ============================================================ */
  function initRsa() {
    var bitsSel = $('rsaBits'), genBtn = $('rsaGen');
    var pub = $('rsaPub'), priv = $('rsaPriv');
    var inEl = $('rsaIn'), outEl = $('rsaOut');

    if (!genBtn) return;

    wireEye('rsaEye', 'rsaPriv');

    on(genBtn, 'click', function () {
      var bits = parseInt(bitsSel.value, 10);
      guard(genBtn, 'Generating…', function () {
        return M.rsa.generate(bits).then(function (pair) {
          pub.value = pair.publicPem;
          priv.value = pair.privatePem;
          UI.toast(bits + '-bit key pair generated', 'success');
        });
      });
    });

    on($('rsaPubCopy'), 'click', function () { if (pub.value) UI.copy(pub.value, 'Public key copied'); else UI.toast('Nothing to copy', 'error'); });
    on($('rsaPrivCopy'), 'click', function () { if (priv.value) UI.copy(priv.value, 'Private key copied'); else UI.toast('Nothing to copy', 'error'); });
    on($('rsaOutCopy'), 'click', function () { if (outEl.value) UI.copy(outEl.value, 'Output copied'); else UI.toast('Nothing to copy', 'error'); });

    on($('rsaPubDl'), 'click', function () {
      if (!pub.value) { UI.toast('Generate a key pair first', 'error'); return; }
      U.downloadBlob(new Blob([pub.value], { type: 'application/x-pem-file' }), 'winhash-public.pem');
    });
    on($('rsaPrivDl'), 'click', function () {
      if (!priv.value) { UI.toast('Generate a key pair first', 'error'); return; }
      U.downloadBlob(new Blob([priv.value], { type: 'application/x-pem-file' }), 'winhash-private.pem');
    });

    on($('rsaEncrypt'), 'click', function () {
      if (!inEl.value) { UI.toast('Enter a message first', 'error'); return; }
      if (!pub.value.trim()) { UI.toast('Paste a public key or generate a pair first', 'error'); return; }
      guard($('rsaEncrypt'), 'Encrypting…', function () {
        return M.rsa.encryptText(inEl.value, pub.value).then(function (ct) {
          outEl.value = ct;
          UI.toast('Encrypted with the public key', 'success');
        });
      });
    });

    on($('rsaDecrypt'), 'click', function () {
      var src = outEl.value || inEl.value;
      if (!src.trim()) { UI.toast('Paste some ciphertext first', 'error'); return; }
      if (!priv.value.trim()) { UI.toast('Paste your private key first', 'error'); return; }
      guard($('rsaDecrypt'), 'Decrypting…', function () {
        return M.rsa.decryptText(src, priv.value).then(function (pt) {
          outEl.value = pt;
          UI.toast('Decrypted with the private key', 'success');
        });
      });
    });

    return {};
  }

  /* ============================================================
   * Boot + deep-link support (?algo=)
   * ============================================================ */
  function boot() {
    var classicalApi = initClassical();
    var aesPromise = initAes();
    initRsa();

    /* Deep links: ?algo=vigenere / ?algo=aes-gcm / ?algo=chacha20 / ?algo=rsa */
    var params = new URLSearchParams(location.search);
    var algo = (params.get('algo') || '').toLowerCase();
    if (algo) {
      if (algo === 'rsa') {
        UI.activateTab('enc', 'rsa');
      } else if (algo.indexOf('aes') === 0 || algo === 'chacha20' || algo === 'chacha20-poly1305') {
        UI.activateTab('enc', 'aes');
        var key = (algo === 'chacha20-poly1305') ? 'chacha20' : algo;
        aesPromise.then(function (api) { if (api && api.select) api.select(key); });
      } else if (classicalApi && classicalApi.select) {
        UI.activateTab('enc', 'classical');
        classicalApi.select(algo);
      }
    }
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', boot);
  } else {
    boot();
  }
})(typeof self !== 'undefined' ? self : this);
