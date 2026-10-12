/*
 * WinHash# — pages/algorithms.js
 * Builds the filterable algorithm reference from the three registries
 * (modern, classical, hashes) with security-level badges.
 */
(function (root) {
  'use strict';
  var WH = root.WinHash;
  var H = WH.hashes, C = WH.classical, M = WH.modern, UI = WH.ui;

  function $(id) { return document.getElementById(id); }
  function on(el, ev, fn) { if (el) el.addEventListener(ev, fn); }

  /* Map a security level string to a badge class + label. */
  function badge(level) {
    var map = {
      strong: ['badge-strong', 'Strong'],
      moderate: ['badge-medium', 'Moderate'],
      medium: ['badge-medium', 'Moderate'],
      weak: ['badge-weak', 'Weak'],
      broken: ['badge-weak', 'Broken'],
      'very weak': ['badge-weak', 'Very weak'],
      educational: ['badge-none', 'Educational'],
      conditional: ['badge-medium', 'Conditional'],
      encoding: ['badge-none', 'Encoding'],
      checksum: ['badge-none', 'Checksum'],
      none: ['badge-none', 'Checksum']
    };
    var v = map[String(level || '').toLowerCase()] || ['badge-none', level || '—'];
    return '<span class="badge ' + v[0] + '">' + v[1] + '</span>';
  }

  /* Collect every algorithm into one flat list with a category tag. */
  function collect() {
    var items = [];

    /* modern encryption */
    M.algos.forEach(function (a) {
      items.push({
        cat: 'modern',
        name: a.name,
        desc: a.desc,
        level: a.auth ? 'strong' : 'moderate',
        href: 'text.html?algo=' + a.key,
        tryLabel: 'Try in Text tool'
      });
    });

    /* classical ciphers */
    C.list.forEach(function (a) {
      items.push({
        cat: 'classical',
        name: a.name,
        desc: a.desc,
        level: a.level,
        href: 'text.html?algo=' + a.id,
        tryLabel: 'Try in Text tool'
      });
    });

    /* hashes (skip the HMAC pseudo-entries; the registry already holds only real ones) */
    H.list.forEach(function (a) {
      var isChecksum = (a.cat === 'checksum');
      items.push({
        cat: isChecksum ? 'checksum' : 'hash',
        name: a.name + ' · ' + a.bits + '-bit',
        desc: a.note,
        level: a.secure === 'none' ? 'checksum' : a.secure,
        href: 'hash.html',
        tryLabel: 'Open Hash tool'
      });
    });

    return items;
  }

  function render(filter) {
    var grid = $('algoGrid');
    var items = collect();
    var html = '';
    items.forEach(function (it) {
      if (filter !== 'all' && it.cat !== filter) return;
      html +=
        '<div class="card algo-card">' +
        '  <div class="algo-top">' +
        '    <span class="algo-name">' + it.name + '</span>' +
        badge(it.level) +
        '  </div>' +
        '  <p class="algo-desc">' + it.desc + '</p>' +
        '  <a class="try-link" href="' + it.href + '">' + it.tryLabel + ' →</a>' +
        '</div>';
    });
    if (!html) html = '<div class="card"><p class="algo-desc">No algorithms in this category.</p></div>';
    grid.innerHTML = html;
  }

  function boot() {
    var bar = $('filterBar');
    if (!bar) return;
    render('all');

    on(bar, 'click', function (e) {
      var btn = e.target.closest('button[data-filter]');
      if (!btn) return;
      bar.querySelectorAll('button').forEach(function (b) { b.classList.toggle('active', b === btn); });
      render(btn.getAttribute('data-filter'));
    });
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', boot);
  } else {
    boot();
  }
})(typeof self !== 'undefined' ? self : this);
