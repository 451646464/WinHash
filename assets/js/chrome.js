/*
 * WinHash# — chrome.js
 * Shared layout: header, footer, mobile nav, scroll progress, reveal
 * animations, counters, FAQ, toasts, copy helpers.
 */
(function (root) {
  'use strict';
  var WH = root.WinHash = root.WinHash || {};

  var NAV = [
    { page: 'index', href: 'index.html', label: 'Home' },
    { page: 'text', href: 'text.html', label: 'Encrypt Text' },
    { page: 'files', href: 'files.html', label: 'Encrypt Files' },
    { page: 'hash', href: 'hash.html', label: 'Hash' },
    { page: 'tools', href: 'tools.html', label: 'Tools' },
    { page: 'algorithms', href: 'algorithms.html', label: 'Algorithms' },
    { page: 'about', href: 'about.html', label: 'About' }
  ];

  var ICONS = {
    home: '<path d="M3 10.5 12 3l9 7.5V21a1 1 0 0 1-1 1h-5v-6H9v6H4a1 1 0 0 1-1-1z"/>',
    lock: '<rect x="4" y="10" width="16" height="11" rx="2"/><path d="M8 10V7a4 4 0 0 1 8 0v3"/>',
    unlock: '<rect x="4" y="10" width="16" height="11" rx="2"/><path d="M8 10V7a4 4 0 0 1 7.8-1"/>',
    file: '<path d="M14 3v5h5"/><path d="M19 8v11a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h7z"/>',
    hash: '<path d="M9 3 7 21M17 3l-2 18M4 8.5h16M3 15.5h16"/>',
    tools: '<path d="M14.7 6.3a4 4 0 0 0-5.4 5.4L3 18v3h3l6.3-6.3a4 4 0 0 0 5.4-5.4l-2.6 2.6-2.4-2.4z"/>',
    shield: '<path d="M12 3 4 6v6c0 5 3.4 8.4 8 9 4.6-.6 8-4 8-9V6z"/><path d="m9 12 2 2 4-4"/>',
    eye: '<path d="M2 12s3.6-7 10-7 10 7 10 7-3.6 7-10 7-10-7-10-7z"/><circle cx="12" cy="12" r="3"/>',
    copy: '<rect x="9" y="9" width="12" height="12" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/>',
    bolt: '<path d="M13 2 4 14h6l-1 8 9-12h-6z"/>',
    globe: '<circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3a15 15 0 0 1 0 18 15 15 0 0 1 0-18z"/>',
    key: '<circle cx="8" cy="14" r="4"/><path d="m11 11 9-9 2 2-2 2 2 2-3 3-2-2-2 2"/>',
    layers: '<path d="m12 3 9 5-9 5-9-5z"/><path d="m3 13 9 5 9-5"/>',
    users: '<circle cx="9" cy="8" r="3.5"/><path d="M2.5 20a6.5 6.5 0 0 1 13 0"/><path d="M16 5.2a3.5 3.5 0 0 1 0 6.6M17.5 14.4A6.5 6.5 0 0 1 21.5 20"/>',
    book: '<path d="M4 5a2 2 0 0 1 2-2h13v16H6a2 2 0 0 0-2 2z"/><path d="M6 17h13"/>',
    github: '<path d="M12 2a10 10 0 0 0-3.16 19.49c.5.09.68-.22.68-.48v-1.7c-2.78.6-3.37-1.34-3.37-1.34-.45-1.16-1.11-1.47-1.11-1.47-.91-.62.07-.61.07-.61 1 .07 1.53 1.03 1.53 1.03.9 1.53 2.36 1.09 2.94.83.09-.65.35-1.09.63-1.34-2.22-.25-4.56-1.11-4.56-4.94 0-1.09.39-1.98 1.03-2.68-.1-.25-.45-1.27.1-2.64 0 0 .84-.27 2.75 1.02a9.5 9.5 0 0 1 5 0c1.91-1.29 2.75-1.02 2.75-1.02.55 1.37.2 2.39.1 2.64.64.7 1.03 1.59 1.03 2.68 0 3.84-2.34 4.68-4.57 4.93.36.31.68.92.68 1.85V21c0 .27.18.58.69.48A10 10 0 0 0 12 2z"/>',
    plus: '<path d="M12 5v14M5 12h14"/>',
    swap: '<path d="M7 16H3m0 0 3-3m-3 3 3 3M17 8h4m0 0-3-3m3 3-3 3"/>',
    trash: '<path d="M3 6h18M8 6V4h8v2M6 6l1 14h10l1-14"/>',
    download: '<path d="M12 3v12m0 0 4-4m-4 4-4-4M4 17v2a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2v-2"/>',
    check: '<path d="m5 13 4 4L19 7"/>',
    refresh: '<path d="M3 12a9 9 0 0 1 15-6.7L21 8m0 0V3m0 5h-5M21 12a9 9 0 0 1-15 6.7L3 16m0 0v5m0-5h5"/>',
    mail: '<rect x="3" y="5" width="18" height="14" rx="2"/><path d="m3 7 9 6 9-6"/>',
    info: '<circle cx="12" cy="12" r="9"/><path d="M12 11v5M12 8h.01"/>'
  };

  function icon(name) {
    return '<svg class="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9" ' +
      'stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">' + (ICONS[name] || ICONS.hash) + '</svg>';
  }

  function brandMarkup() {
    return '<img class="brand-img" src="assets/img/icon.png" alt="" width="42" height="42" decoding="async">' +
      '<span class="brand-text"><span class="wm-mark">#Win</span><span class="wm-tail">Hash</span></span>';
  }

  /* ------------ header ------------ */
  function currentPage() {
    var f = (location.pathname.split('/').pop() || 'index.html').toLowerCase();
    if (!f) f = 'index.html';
    return f.replace('.html', '');
  }

  function renderHeader() {
    var host = document.getElementById('site-header');
    if (!host) return;
    var cur = currentPage();
    var links = NAV.map(function (n) {
      var active = n.page === cur ? ' class="active" aria-current="page"' : '';
      return '<a href="' + n.href + '"' + active + '>' + n.label + '</a>';
    }).join('');

    host.innerHTML =
      '<div class="scroll-progress" id="scrollProgress"></div>' +
      '<header class="site-header">' +
      '  <div class="container nav-wrap">' +
      '    <a class="brand" href="index.html" aria-label="WinHash home">' + brandMarkup() + '</a>' +
      '    <nav class="site-nav" id="siteNav" aria-label="Main navigation">' + links + '</nav>' +
      '    <div class="nav-actions">' +
      '      <a class="btn btn-primary btn-sm" href="text.html">Start Encrypting</a>' +
      '      <button class="nav-burger" id="navBurger" aria-label="Open menu" aria-expanded="false">' +
      '<span></span><span></span><span></span></button>' +
      '    </div>' +
      '  </div>' +
      '</header>';
  }

  /* ------------ footer ------------ */
  function renderFooter() {
    var host = document.getElementById('site-footer');
    if (!host) return;
    var year = new Date().getFullYear();
    host.innerHTML =
      '<footer class="site-footer">' +
      '  <div class="container">' +
      '    <div class="footer-grid">' +
      '      <div class="footer-brand">' +
      '        <a class="brand" href="index.html">' + brandMarkup() + '</a>' +
      '        <p>A complete encryption and hashing platform that runs entirely inside your browser — ' +
      'text, images, video, audio and documents. Nothing you process ever leaves your device.</p>' +
      '        <div class="footer-social">' +
      '          <a class="icon-btn" href="https://github.com/451646464/encrption_interface" target="_blank" rel="noopener" aria-label="GitHub repository" title="Original repository">' +
      icon('github') + '</a>' +
      '          <a class="icon-btn" href="mailto:rakanalmoliki33@gmail.com" aria-label="Email" title="Contact the developer">' +
      '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9"><rect x="3" y="5" width="18" height="14" rx="2"/><path d="m3 7 9 6 9-6"/></svg></a>' +
      '        </div>' +
      '      </div>' +
      '      <div class="footer-col"><h4>Encryption Tools</h4><ul>' +
      '        <li><a href="text.html">Text encryption</a></li>' +
      '        <li><a href="files.html">Files, images & video</a></li>' +
      '        <li><a href="hash.html">Hash generator</a></li>' +
      '        <li><a href="tools.html">Password generator</a></li>' +
      '      </ul></div>' +
      '      <div class="footer-col"><h4>Explore</h4><ul>' +
      '        <li><a href="algorithms.html">Algorithm library</a></li>' +
      '        <li><a href="index.html#how">How it works</a></li>' +
      '        <li><a href="index.html#faq">FAQ</a></li>' +
      '        <li><a href="about.html">About the project</a></li>' +
      '      </ul></div>' +
      '      <div class="footer-col"><h4>Project</h4><ul>' +
      '        <li><a href="https://github.com/451646464/encrption_interface" target="_blank" rel="noopener">Original source</a></li>' +
      '        <li><a href="about.html#security">Security notice</a></li>' +
      '        <li><a href="about.html#dev">Developer</a></li>' +
      '        <li><a href="algorithms.html">Security levels</a></li>' +
      '      </ul></div>' +
      '    </div>' +
      '    <div class="footer-bottom">' +
      '      <div>© <span id="footYear">' + year + '</span> WinHash<span style="color:var(--red)">#</span> — All rights reserved.</div>' +
      '      <div>Designed &amp; developed by <strong style="color:var(--red-3)">Rakan Almoliki</strong> <span class="heart">♥</span> — every operation runs locally in your browser</div>' +
      '    </div>' +
      '  </div>' +
      '</footer>' +
      '<button id="backTop" aria-label="Back to top" title="Back to top">↑</button>' +
      '<div id="toast-root" role="status" aria-live="polite"></div>';
  }

  /* ------------ icon hydration ------------
   * Scans for any element carrying a data-icon attribute and injects the
   * matching SVG. Page scripts can call hydrateIcons() again after they
   * render dynamic markup. */
  function hydrateIcons(scope) {
    var rootEl = scope || document;
    rootEl.querySelectorAll('[data-icon]').forEach(function (el) {
      if (el.getAttribute('data-icon-done')) return;
      var name = el.getAttribute('data-icon');
      /* Prepend (not replace) so button labels / existing content survive. */
      el.insertAdjacentHTML('afterbegin', icon(name));
      el.setAttribute('data-icon-done', '1');
    });
  }

  /* ------------ toast ------------ */
  function toast(message, type) {
    var rootEl = document.getElementById('toast-root');
    if (!rootEl) {
      rootEl = document.createElement('div');
      rootEl.id = 'toast-root';
      document.body.appendChild(rootEl);
    }
    var el = document.createElement('div');
    el.className = 'toast toast-' + (type || 'info');
    el.textContent = message;
    rootEl.appendChild(el);
    setTimeout(function () {
      el.classList.add('out');
      setTimeout(function () { el.remove(); }, 320);
    }, 3400);
    while (rootEl.children.length > 4) rootEl.firstChild.remove();
  }

  /* ------------ copy ------------ */
  function copy(text, label) {
    return (WH.utils ? WH.utils.copyText(text) : Promise.reject()).then(function () {
      toast((label || 'Copied to clipboard') + ' ✓', 'success');
    }).catch(function () {
      toast('Could not copy to the clipboard', 'error');
    });
  }

  /* ------------ busy button ------------ */
  var busyMap = new WeakMap();
  function setBusy(btn, busy, loadingLabel) {
    if (!btn) return;
    if (busy) {
      busyMap.set(btn, { html: btn.innerHTML, disabled: btn.disabled });
      btn.disabled = true;
      btn.innerHTML = '<span class="spinner"></span> ' + (loadingLabel || 'Working…');
    } else {
      var prev = busyMap.get(btn);
      if (prev) {
        btn.innerHTML = prev.html;
        btn.disabled = prev.disabled;
      }
    }
  }

  /* ------------ reveal ------------ */
  function initReveal() {
    var els = document.querySelectorAll('[data-reveal]');
    if (!els.length) return;
    if (!('IntersectionObserver' in root)) {
      els.forEach(function (el) { el.classList.add('revealed'); });
      return;
    }
    var io = new IntersectionObserver(function (entries) {
      entries.forEach(function (e) {
        if (e.isIntersecting) {
          e.target.classList.add('revealed');
          io.unobserve(e.target);
        }
      });
    }, { threshold: 0.12, rootMargin: '0px 0px -40px 0px' });
    els.forEach(function (el, i) {
      el.style.transitionDelay = ((i % 6) * 60) + 'ms';
      io.observe(el);
    });
  }

  /* ------------ counters ------------ */
  function initCounters() {
    var els = document.querySelectorAll('[data-count]');
    if (!els.length) return;
    var io = new IntersectionObserver(function (entries) {
      entries.forEach(function (e) {
        if (!e.isIntersecting) return;
        io.unobserve(e.target);
        var el = e.target;
        var target = parseFloat(el.getAttribute('data-count'));
        var suffix = el.getAttribute('data-suffix') || '';
        var dur = 1400;
        var t0 = performance.now();
        function tick(now) {
          var p = Math.min(1, (now - t0) / dur);
          var eased = 1 - Math.pow(1 - p, 3);
          el.textContent = String(Math.round(target * eased)) + suffix;
          if (p < 1) requestAnimationFrame(tick);
        }
        requestAnimationFrame(tick);
      });
    }, { threshold: 0.4 });
    els.forEach(function (el) { io.observe(el); });
  }

  /* ------------ FAQ ------------ */
  function initFaq() {
    document.querySelectorAll('.faq-item').forEach(function (item) {
      var q = item.querySelector('.faq-q');
      var a = item.querySelector('.faq-a');
      if (!q || !a) return;
      q.addEventListener('click', function () {
        var open = item.classList.contains('open');
        document.querySelectorAll('.faq-item.open').forEach(function (o) {
          o.classList.remove('open');
          var oa = o.querySelector('.faq-a');
          if (oa) oa.style.maxHeight = '0px';
        });
        if (!open) {
          item.classList.add('open');
          a.style.maxHeight = a.scrollHeight + 'px';
        }
      });
    });
  }

  /* ------------ nav / scroll ------------ */
  function initNav() {
    var burger = document.getElementById('navBurger');
    var nav = document.getElementById('siteNav');
    if (burger && nav) {
      burger.addEventListener('click', function () {
        var open = nav.classList.toggle('open');
        burger.classList.toggle('open', open);
        burger.setAttribute('aria-expanded', open ? 'true' : 'false');
      });
      nav.addEventListener('click', function (e) {
        if (e.target.tagName === 'A') {
          nav.classList.remove('open');
          burger.classList.remove('open');
        }
      });
    }

    var progress = document.getElementById('scrollProgress');
    var backTop = document.getElementById('backTop');
    function onScroll() {
      var h = document.documentElement;
      var max = h.scrollHeight - h.clientHeight;
      if (progress) progress.style.width = (max > 0 ? (h.scrollTop / max) * 100 : 0) + '%';
      if (backTop) backTop.classList.toggle('show', h.scrollTop > 500);
    }
    document.addEventListener('scroll', onScroll, { passive: true });
    onScroll();
    if (backTop) {
      backTop.addEventListener('click', function () {
        root.scrollTo({ top: 0, behavior: 'smooth' });
      });
    }
  }

  /* ------------ tabs helper ------------ */
  function initTabs() {
    document.querySelectorAll('[data-tabs]').forEach(function (group) {
      var btns = group.querySelectorAll('.tab-btn');
      btns.forEach(function (btn) {
        btn.addEventListener('click', function () {
          var name = btn.getAttribute('data-tab');
          btns.forEach(function (b) { b.classList.toggle('active', b === btn); });
          var scope = group.getAttribute('data-tabs');
          document.querySelectorAll('[data-tabgroup="' + scope + '"]').forEach(function (p) {
            p.classList.toggle('active', p.getAttribute('data-tabpanel') === name);
          });
          document.dispatchEvent(new CustomEvent('tabchange', { detail: { group: scope, tab: name } }));
        });
      });
    });
  }

  function activateTab(groupName, tabName) {
    var btn = document.querySelector('[data-tabs="' + groupName + '"] .tab-btn[data-tab="' + tabName + '"]');
    if (btn) btn.click();
  }

  /* ------------ init ------------ */
  function initChrome() {
    renderHeader();
    renderFooter();
    initNav();
    initReveal();
    initCounters();
    initFaq();
    initTabs();
    hydrateIcons();
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initChrome);
  } else {
    initChrome();
  }

  WH.ui = {
    icon: icon,
    hydrateIcons: hydrateIcons,
    toast: toast,
    copy: copy,
    setBusy: setBusy,
    brandMarkup: brandMarkup,
    activateTab: activateTab
  };
})(typeof self !== 'undefined' ? self : this);
