/*
 * WinHash# — pages/files.js
 * Drag-and-drop file encryption / decryption using the .wnh container.
 * All processing is in-memory; nothing is uploaded.
 */
(function (root) {
  'use strict';
  var WH = root.WinHash;
  var U = WH.utils, M = WH.modern, UI = WH.ui;

  function $(id) { return document.getElementById(id); }
  function on(el, ev, fn) { if (el) el.addEventListener(ev, fn); }

  /* ---------------- state ---------------- */
  var state = { file: null, bytes: null, mode: 'encrypt', result: null, resultUrl: null, resultName: null };

  /* ---------------- password strength (shared logic) ---------------- */
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
  function paintStrength() {
    var pw = $('filePass').value;
    var s = scorePassword(pw);
    $('fileBar').style.width = s.w + '%';
    $('fileBar').style.background = s.color;
    $('fileStrength').textContent = s.label;
    $('fileStrength').style.color = s.color;
  }

  /* ---------------- strong random password ---------------- */
  function genPassword(len) {
    var chars = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#$%^&*-_=+?';
    var buf = U.randomBytes(len || 20);
    var out = '';
    for (var i = 0; i < buf.length; i++) out += chars[buf[i] % chars.length];
    return out;
  }

  /* ---------------- progress helper ---------------- */
  function showProgress(pct) {
    $('progressLine').classList.remove('hidden');
    $('progBar').style.width = pct + '%';
    $('progPct').textContent = Math.round(pct) + '%';
  }
  function hideProgress() { $('progressLine').classList.add('hidden'); }

  /* ---------------- file selection ---------------- */
  function setFile(file) {
    if (!file) return;
    state.file = file;
    var reader = new FileReader();
    reader.onload = function () {
      state.bytes = new Uint8Array(reader.result);
      $('fileMeta').classList.remove('hidden');
      $('fmName').textContent = file.name;
      $('fmSub').textContent = U.formatBytes(file.size) + '  ·  ' + (file.type || 'unknown type');
      $('dzTitle').textContent = 'File loaded — ready to go';
      $('dzSub').textContent = 'Drop another file to replace it';
      UI.toast(file.name + ' loaded', 'success');
    };
    reader.readAsArrayBuffer(file);
  }

  function clearFile() {
    state.file = null; state.bytes = null; state.result = null; state.resultUrl = null;
    if (state.resultUrl) { URL.revokeObjectURL(state.resultUrl); state.resultUrl = null; }
    $('fileMeta').classList.add('hidden');
    $('preview').classList.add('hidden'); $('preview').innerHTML = '';
    $('resultNote').hidden = true;
    $('downloadBtn').classList.add('hidden');
    $('fileInput').value = '';
    $('dzTitle').textContent = 'Drop your file here';
    $('dzSub').textContent = 'or click to browse — images, video, audio, PDF and any document';
    hideProgress();
  }

  /* ---------------- mode switch ---------------- */
  function setMode(mode) {
    state.mode = mode;
    var enc = mode === 'encrypt';
    $('modeEncrypt').classList.toggle('active', enc);
    $('modeDecrypt').classList.toggle('active', !enc);
    $('modeEncrypt').setAttribute('aria-selected', enc ? 'true' : 'false');
    $('modeDecrypt').setAttribute('aria-selected', enc ? 'false' : 'true');
    $('runBtn').innerHTML = UI.icon(enc ? 'lock' : 'unlock') + ' ' + (enc ? 'Encrypt file' : 'Decrypt file');
    $('algoSelect').closest('.field').classList.toggle('hidden', !enc);
    $('iterSelect').closest('.field').classList.toggle('hidden', !enc);
    $('algoDesc').classList.toggle('hidden', !enc);
    $('dzTitle').textContent = enc ? 'Drop your file here' : 'Drop a .wnh file here';
    $('dzSub').textContent = enc
      ? 'or click to browse — images, video, audio, PDF and any document'
      : 'or click to browse — choose an encrypted .wnh file';
    $('resultNote').hidden = true;
    $('downloadBtn').classList.add('hidden');
    $('preview').classList.add('hidden'); $('preview').innerHTML = '';
  }

  /* ---------------- preview support ---------------- */
  function previewType(t) {
    if (!t) return null;
    if (t.indexOf('image/') === 0) return 'img';
    if (t.indexOf('video/') === 0) return 'video';
    if (t.indexOf('audio/') === 0) return 'audio';
    return null;
  }

  /* ---------------- run ---------------- */
  function run() {
    if (!state.bytes) { UI.toast('Choose a file first', 'error'); return; }
    var pass = $('filePass').value;
    if (!pass) { UI.toast('Enter a password first', 'error'); return; }

    var btn = $('runBtn');
    UI.setBusy(btn, true, state.mode === 'encrypt' ? 'Encrypting…' : 'Decrypting…');
    showProgress(8);

    var p;
    if (state.mode === 'encrypt') {
      var meta = { n: state.file.name, t: state.file.type || 'application/octet-stream', s: state.file.size, kind: 'file' };
      showProgress(30);
      p = M.encryptBytes(state.bytes, pass, $('algoSelect').value, {
        iterations: parseInt($('iterSelect').value, 10) || M.iterationsDefault,
        meta: meta
      }).then(function (container) {
        showProgress(90);
        state.result = container;
        state.resultName = state.file.name + '.wnh';
        /* clear any old object URL */
        if (state.resultUrl) { URL.revokeObjectURL(state.resultUrl); }
        state.resultUrl = URL.createObjectURL(new Blob([container], { type: 'application/octet-stream' }));
        $('downloadBtn').classList.remove('hidden');
        var note = $('resultNote');
        note.hidden = false;
        note.innerHTML = '<strong>Encrypted.</strong> ' + U.formatBytes(container.length) +
          ' — saved as <span class="mono">' + state.resultName + '</span>. Keep the password safe; it is required to decrypt.';
        $('preview').classList.add('hidden');
        showProgress(100);
        UI.toast('File encrypted', 'success');
      });
    } else {
      showProgress(30);
      p = M.decryptBytes(state.bytes, pass).then(function (res) {
        showProgress(90);
        state.result = res.bytes;
        var meta = res.meta || {};
        var origName = meta.n || 'decrypted-file';
        var origType = meta.t || 'application/octet-stream';
        state.resultName = origName;
        if (state.resultUrl) { URL.revokeObjectURL(state.resultUrl); }
        state.resultUrl = URL.createObjectURL(new Blob([res.bytes], { type: origType }));
        $('downloadBtn').classList.remove('hidden');

        var note = $('resultNote');
        note.hidden = false;
        note.innerHTML = '<strong>Decrypted.</strong> Original: <span class="mono">' + origName + '</span> · ' +
          U.formatBytes(meta.s || res.bytes.length) + ' · ' + origType +
          ' — algorithm ' + res.algo.name + ' · ' + res.iterations.toLocaleString() + ' iterations.';

        /* preview images / video / audio inline */
        var kind = previewType(origType);
        var pv = $('preview');
        if (kind) {
          var el;
          if (kind === 'img') { el = document.createElement('img'); el.alt = origName; }
          else if (kind === 'video') { el = document.createElement('video'); el.controls = true; }
          else { el = document.createElement('audio'); el.controls = true; }
          el.src = state.resultUrl;
          pv.innerHTML = ''; pv.appendChild(el);
          pv.classList.remove('hidden');
        } else {
          pv.classList.add('hidden'); pv.innerHTML = '';
        }
        showProgress(100);
        UI.toast('File decrypted', 'success');
      });
    }

    p.catch(function (e) {
      UI.toast(U.errMsg(e), 'error');
      hideProgress();
    }).then(function () {
      UI.setBusy(btn, false);
      setTimeout(hideProgress, 800);
    });
  }

  /* ---------------- download ---------------- */
  function download() {
    if (!state.resultUrl) { UI.toast('Nothing to download yet', 'error'); return; }
    var a = document.createElement('a');
    a.href = state.resultUrl;
    a.download = state.resultName || 'winhash-output';
    document.body.appendChild(a); a.click(); a.remove();
    UI.toast('Download started', 'success');
  }

  /* ---------------- boot ---------------- */
  function boot() {
    var dz = $('dropzone'), input = $('fileInput');

    /* populate algorithm select */
    M.supportedAlgorithms().then(function (list) {
      var sel = $('algoSelect');
      list.forEach(function (a) {
        var o = document.createElement('option');
        o.value = a.key; o.textContent = a.name;
        sel.appendChild(o);
      });
      sel.value = list.length ? list[0].key : 'aes-gcm';
      var sync = function () {
        var a = null;
        list.forEach(function (x) { if (x.key === sel.value) a = x; });
        $('algoDesc').textContent = a ? a.desc : '';
      };
      on(sel, 'change', sync); sync();
    });

    /* dropzone interactions */
    on(dz, 'click', function () { input.click(); });
    on(dz, 'keydown', function (e) { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); input.click(); } });
    on(input, 'change', function () { if (input.files && input.files[0]) setFile(input.files[0]); });
    ['dragenter', 'dragover'].forEach(function (ev) {
      on(dz, ev, function (e) { e.preventDefault(); dz.style.borderColor = 'var(--red)'; });
    });
    ['dragleave', 'drop'].forEach(function (ev) {
      on(dz, ev, function (e) { e.preventDefault(); dz.style.borderColor = ''; });
    });
    on(dz, 'drop', function (e) {
      if (e.dataTransfer && e.dataTransfer.files && e.dataTransfer.files[0]) setFile(e.dataTransfer.files[0]);
    });

    on($('fmClear'), 'click', clearFile);
    on($('modeEncrypt'), 'click', function () { setMode('encrypt'); });
    on($('modeDecrypt'), 'click', function () { setMode('decrypt'); });
    on($('runBtn'), 'click', run);
    on($('downloadBtn'), 'click', download);

    /* password helpers */
    on($('filePass'), 'input', paintStrength);
    on($('fileEye'), 'click', function () {
      var p = $('filePass');
      p.type = p.type === 'password' ? 'text' : 'password';
    });
    on($('genPass'), 'click', function () {
      $('filePass').value = genPassword(20);
      $('filePass').type = 'text';
      paintStrength();
      UI.toast('Strong password generated', 'success');
    });
    on($('copyPass'), 'click', function () {
      if ($('filePass').value) UI.copy($('filePass').value, 'Password copied');
      else UI.toast('Nothing to copy', 'error');
    });

    setMode('encrypt');
    paintStrength();
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', boot);
  } else {
    boot();
  }
})(typeof self !== 'undefined' ? self : this);
