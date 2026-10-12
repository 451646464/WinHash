/*
 * WinHash# — pages/hash.js
 * Hash generator: from text, from files, and HMAC signatures.
 */
(function (root) {
  'use strict';
  var WH = root.WinHash;
  var U = WH.utils, H = WH.hashes, UI = WH.ui;

  function $(id) { return document.getElementById(id); }
  function on(el, ev, fn) { if (el) el.addEventListener(ev, fn); }

  var CHUNK = 1024 * 1024; /* 1 MiB read chunks for smooth progress */

  /* Map a hash's security level to a badge class + label. */
  function badgeFor(secure) {
    switch (secure) {
      case 'strong': return { cls: 'badge-strong', label: 'Strong' };
      case 'medium': return { cls: 'badge-medium', label: 'Moderate' };
      case 'weak': return { cls: 'badge-weak', label: 'Weak' };
      case 'broken': return { cls: 'badge-weak', label: 'Broken' };
      default: return { cls: 'badge-none', label: 'Checksum' };
    }
  }

  /* Build one result row. */
  function rowHtml(algo, hex, highlight) {
    var b = badgeFor(algo.secure);
    var matches = highlight && hex.toLowerCase() === highlight.toLowerCase();
    return '<tr class="' + (matches ? 'match' : '') + '">' +
      '<td><strong>' + algo.name + '</strong> <span class="badge ' + b.cls + '" style="margin-inline-start:6px">' + b.label + '</span></td>' +
      '<td>' + algo.bits + '</td>' +
      '<td class="hash-cell">' + hex + '</td>' +
      '<td><button class="icon-btn" data-copy="' + hex + '" aria-label="Copy hash" title="Copy" data-icon="copy"></button></td>' +
      '</tr>';
  }

  /* Delegate copy buttons inside a table body. */
  function wireCopyButtons(tbody) {
    on(tbody, 'click', function (e) {
      var btn = e.target.closest('[data-copy]');
      if (btn) UI.copy(btn.getAttribute('data-copy'), 'Hash copied');
    });
  }

  /* ============================================================
   * From text
   * ============================================================ */
  function initText() {
    var inEl = $('htIn'), verify = $('htVerify'), tbody = $('htTable').querySelector('tbody');
    if (!inEl) return;

    wireCopyButtons(tbody);

    function run() {
      var text = inEl.value;
      if (!text) { UI.toast('Enter some text first', 'error'); return; }
      var bytes = U.utf8Encode(text);
      var want = verify.value.trim().toLowerCase();
      var btn = $('htRun');
      UI.setBusy(btn, true, 'Hashing…');
      Promise.all(H.list.map(function (algo) {
        return H.digestHex(algo.id, bytes).then(function (hex) {
          return { algo: algo, hex: hex };
        });
      })).then(function (results) {
        var rows = '';
        results.forEach(function (r) { rows += rowHtml(r.algo, r.hex, want); });
        tbody.innerHTML = rows;
        UI.hydrateIcons(tbody);
        if (want) {
          var any = results.some(function (r) { return r.hex.toLowerCase() === want; });
          UI.toast(any ? 'Match found — highlighted in green' : 'No algorithm matched that hash', any ? 'success' : 'error');
        } else {
          UI.toast('Hashes generated', 'success');
        }
      }).catch(function (e) {
        UI.toast(U.errMsg(e), 'error');
      }).then(function () { UI.setBusy(btn, false); });
    }

    on($('htRun'), 'click', run);
    on(verify, 'keydown', function (e) { if (e.key === 'Enter') { e.preventDefault(); run(); } });
    on($('htClear'), 'click', function () { inEl.value = ''; verify.value = ''; tbody.innerHTML = '<tr><td colspan="4" class="muted center">Enter text and press “Generate hashes”.</td></tr>'; });
  }

  /* ============================================================
   * From a file (incremental, chunked with progress)
   * ============================================================ */
  function initFile() {
    var dz = $('hzDrop'), input = $('hzInput'), tbody = $('hzTable').querySelector('tbody');
    if (!dz) return;

    wireCopyButtons(tbody);

    var currentFile = null;

    function clearFile() {
      currentFile = null;
      $('hzMeta').classList.add('hidden');
      $('hzProgLine').classList.add('hidden');
      input.value = '';
      tbody.innerHTML = '<tr><td colspan="4" class="muted center">Load a file to compute all hashes.</td></tr>';
      $('hzTitle').textContent = 'Drop a file here';
      $('hzSub').textContent = 'or click to browse — hashed locally, never uploaded';
    }

    function hashFile(file) {
      currentFile = file;
      $('hzMeta').classList.remove('hidden');
      $('hzName').textContent = file.name;
      $('hzSubInfo').textContent = U.formatBytes(file.size) + '  ·  ' + (file.type || 'unknown type');
      $('hzTitle').textContent = 'File loaded';
      $('hzSub').textContent = 'Drop another file to replace it';

      /* create one incremental hasher per algorithm */
      var hashers = H.list.map(function (a) { return { algo: a, h: H.create(a.id) }; });

      var offset = 0;
      var bar = $('hzBar'), pct = $('hzPct'), progLine = $('hzProgLine');
      progLine.classList.remove('hidden');

      function step() {
        var slice = file.slice(offset, Math.min(offset + CHUNK, file.size));
        var reader = new FileReader();
        reader.onload = function () {
          var bytes = new Uint8Array(reader.result);
          hashers.forEach(function (x) { x.h.update(bytes); });
          offset += bytes.length;
          var p = file.size ? (offset / file.size) * 100 : 100;
          bar.style.width = p + '%';
          pct.textContent = Math.round(p) + '%';
          if (offset < file.size) {
            setTimeout(step, 0);
          } else {
            /* finalize all digests */
            Promise.all(hashers.map(function (x) {
              return x.h.digestHex().then(function (hex) { return { algo: x.algo, hex: hex }; });
            })).then(function (results) {
              var rows = '';
              results.forEach(function (r) { rows += rowHtml(r.algo, r.hex, null); });
              tbody.innerHTML = rows;
              UI.hydrateIcons(tbody);
              progLine.classList.add('hidden');
              UI.toast('All hashes computed', 'success');
            });
          }
        };
        reader.readAsArrayBuffer(slice);
      }
      step();
    }

    on(dz, 'click', function () { input.click(); });
    on(dz, 'keydown', function (e) { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); input.click(); } });
    on(input, 'change', function () { if (input.files && input.files[0]) hashFile(input.files[0]); });
    ['dragenter', 'dragover'].forEach(function (ev) {
      on(dz, ev, function (e) { e.preventDefault(); dz.style.borderColor = 'var(--red)'; });
    });
    ['dragleave', 'drop'].forEach(function (ev) {
      on(dz, ev, function (e) { e.preventDefault(); dz.style.borderColor = ''; });
    });
    on(dz, 'drop', function (e) {
      if (e.dataTransfer && e.dataTransfer.files && e.dataTransfer.files[0]) hashFile(e.dataTransfer.files[0]);
    });
    on($('hzClear'), 'click', clearFile);
  }

  /* ============================================================
   * HMAC
   * ============================================================ */
  function initHmac() {
    var key = $('hmKey'), msg = $('hmMsg'), out = $('hmOut'), outField = $('hmOutField'), algoSel = $('hmAlgo');
    if (!key) return;

    on($('hmEye'), 'click', function () { key.type = key.type === 'password' ? 'text' : 'password'; });
    on($('hmCopy'), 'click', function () { if (out.value) UI.copy(out.value, 'HMAC copied'); else UI.toast('Nothing to copy', 'error'); });

    on($('hmRun'), 'click', function () {
      if (!msg.value) { UI.toast('Enter a message first', 'error'); return; }
      if (!key.value) { UI.toast('Enter a secret key first', 'error'); return; }
      var btn = $('hmRun');
      UI.setBusy(btn, true, 'Computing…');
      H.hmacHex(algoSel.value, U.utf8Encode(key.value), U.utf8Encode(msg.value)).then(function (hex) {
        out.value = hex;
        outField.hidden = false;
        UI.toast('HMAC computed', 'success');
      }).catch(function (e) {
        UI.toast(U.errMsg(e), 'error');
      }).then(function () { UI.setBusy(btn, false); });
    });
  }

  /* ---------------- boot ---------------- */
  function boot() { initText(); initFile(); initHmac(); }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', boot);
  } else {
    boot();
  }
})(typeof self !== 'undefined' ? self : this);
