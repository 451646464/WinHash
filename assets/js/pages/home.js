/*
 * WinHash# — home.js
 * Page bootstrap for index.html. Icons are hydrated by chrome.js, but this
 * script also injects the FAQ toggle glyph and re-runs hydration so any
 * late-rendered markup is covered.
 */
(function (root) {
  'use strict';
  var WH = root.WinHash;

  function boot() {
    /* FAQ plus/minus glyph */
    document.querySelectorAll('.faq-q .fq-icon').forEach(function (el) {
      if (el.getAttribute('data-icon-done')) return;
      el.innerHTML = WH.ui.icon('plus');
      el.setAttribute('data-icon-done', '1');
    });
    WH.ui.hydrateIcons();
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', boot);
  } else {
    boot();
  }
})(typeof self !== 'undefined' ? self : this);
