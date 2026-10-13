'use strict';

const express = require('express');
const Unblocker = require('unblocker');
const crypto = require('crypto');
const dns = require('dns').promises;
const net = require('net');
const https = require('https');
const fs = require('fs');
const path = require('path');

const app = express();
const VERSION = '6.5';
const PORT = process.env.PORT || 8080;
const TAB_TITLE = process.env.TAB_TITLE || 'Google';
const KEEP_AWAKE = process.env.KEEP_AWAKE === '1';
const DEBUG = process.env.DEBUG === '1';

// Address-bar path cleanup: "all" (default), "spa" (Next.js/Nuxt only), or "0" (off)
const CLEAN_MODE = String(process.env.CLEAN_PATHS || 'all').toLowerCase();
// Sites to skip, comma separated, for example: CLEAN_PATHS_EXCLUDE=example.com,foo.org
const CLEAN_EXCLUDE = String(process.env.CLEAN_PATHS_EXCLUDE || '')
  .split(',').map((s) => s.trim().toLowerCase()).filter(Boolean);

// Optional: send requests for certain hosts through an outbound proxy (ideally residential).
//   UPSTREAM_PROXY=http://user:pass@host:port      (needs: npm i https-proxy-agent)
//   UPSTREAM_PROXY_HOSTS_RE=regex of hostnames to route (default: TikTok domains)
const UPSTREAM_PROXY = process.env.UPSTREAM_PROXY || '';
const UPSTREAM_HOSTS_RE = new RegExp(
  process.env.UPSTREAM_PROXY_HOSTS_RE ||
    '(^|\\.)(tiktok\\.com|tiktokcdn\\.com|tiktokcdn-us\\.com|tiktokw\\.us|ttwstatic\\.com|byteoversea\\.com)$',
  'i'
);

/* ------------------------------------------------------------------ */
/* Optional upstream proxy (per-host)                                  */
/*                                                                     */
/* Wraps https.request so matching hosts use an HttpsProxyAgent. This   */
/* depends on node-unblocker calling https.request without its own      */
/* agent, which I could not verify. Look for "[upstream-proxy] routed"  */
/* lines in the logs when DEBUG=1.                                      */
/* ------------------------------------------------------------------ */

if (UPSTREAM_PROXY) {
  try {
    const { HttpsProxyAgent } = require('https-proxy-agent');
    const proxyAgent = new HttpsProxyAgent(UPSTREAM_PROXY);
    const origRequest = https.request;
    https.request = function (opts, ...rest) {
      try {
        if (opts && typeof opts === 'object' && !(opts instanceof URL) && !opts.agent) {
          const h = String(opts.hostname || opts.host || '').toLowerCase().replace(/:\d+$/, '');
          if (UPSTREAM_HOSTS_RE.test(h)) {
            if (DEBUG) console.log('[upstream-proxy] routed ' + h);
            opts = Object.assign({}, opts, { agent: proxyAgent });
          }
        }
      } catch (e) { /* fall back to a direct request */ }
      return origRequest.call(this, opts, ...rest);
    };
    console.log('Upstream proxy enabled for hosts matching ' + UPSTREAM_HOSTS_RE);
  } catch (e) {
    console.error('UPSTREAM_PROXY is set but https-proxy-agent is not installed (npm i https-proxy-agent).');
  }
}

/* ------------------------------------------------------------------ */
/* Helpers                                                             */
/* ------------------------------------------------------------------ */

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, (c) => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
  }[c]));
}
const TITLE_HTML = escapeHtml(TAB_TITLE);

function ipOf(req) {
  const xff = String(req.headers['x-forwarded-for'] || '').split(',')[0].trim();
  return xff || req.socket.remoteAddress || 'unknown';
}

// Styled error page (only static text is ever passed in)
function errorPage(code, title, msg) {
  return '<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">' +
    '<meta name="viewport" content="width=device-width, initial-scale=1">' +
    '<title>' + TITLE_HTML + '</title><style>' +
    '*{box-sizing:border-box}body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;' +
    'background:#040907;color:#ecfdf3;font-family:Inter,system-ui,-apple-system,"Segoe UI",sans-serif;padding:20px}' +
    '.box{max-width:460px;text-align:center;padding:40px 32px;border-radius:24px;background:rgba(255,255,255,.04);' +
    'border:1px solid rgba(255,255,255,.09);box-shadow:0 20px 80px rgba(34,197,94,.25)}' +
    '.code{font-size:64px;font-weight:800;background:linear-gradient(90deg,#22c55e,#10b981);' +
    '-webkit-background-clip:text;background-clip:text;color:transparent}' +
    'h1{font-size:22px;margin:6px 0 10px}p{color:#8fa89a;line-height:1.6;margin:0 0 24px}' +
    'a{display:inline-block;padding:12px 26px;border-radius:999px;color:#fff;text-decoration:none;font-weight:700;' +
    'background:linear-gradient(135deg,#22c55e,#10b981)}' +
    '</style></head><body><div class="box"><div class="code">' + code + '</div><h1>' + title +
    '</h1><p>' + msg + '</p><a href="/">Back home</a></div></body></html>';
}

// The origin of the site you were last browsing (from the bb_last cookie), or null
function lastOrigin(req) {
  const m = /(?:^|;\s*)bb_last=([^;]+)/.exec(req.headers.cookie || '');
  if (!m) return null;
  try {
    const origin = decodeURIComponent(m[1]);
    const u = new URL(origin);
    return u.protocol === 'http:' || u.protocol === 'https:' ? u.origin : null;
  } catch (e) {
    return null;
  }
}

// True for a browser refresh (F5 / Ctrl+R / Ctrl+Shift+R)
function isReload(req) {
  return /max-age=0|no-cache/i.test(String(req.headers['cache-control'] || '')) ||
    /no-cache/i.test(String(req.headers.pragma || ''));
}

/* ------------------------------------------------------------------ */
/* Target safety: stop the proxy from reaching private/internal hosts   */
/* ------------------------------------------------------------------ */

const blocked = new net.BlockList();
[
  ['0.0.0.0', 8], ['10.0.0.0', 8], ['100.64.0.0', 10], ['127.0.0.0', 8],
  ['169.254.0.0', 16], ['172.16.0.0', 12], ['192.0.0.0', 24], ['192.168.0.0', 16],
  ['198.18.0.0', 15], ['224.0.0.0', 4], ['240.0.0.0', 4],
].forEach(([addr, prefix]) => blocked.addSubnet(addr, prefix, 'ipv4'));
blocked.addAddress('::1', 'ipv6');
blocked.addAddress('::', 'ipv6');
blocked.addSubnet('fc00::', 7, 'ipv6');
blocked.addSubnet('fe80::', 10, 'ipv6');
blocked.addSubnet('ff00::', 8, 'ipv6');

function isPrivateIp(ip) {
  ip = String(ip).replace(/%.*$/, '').toLowerCase();
  const mapped = /^::ffff:(\d+\.\d+\.\d+\.\d+)$/.exec(ip);
  if (mapped) ip = mapped[1];
  const fam = net.isIP(ip);
  if (!fam) return true; // unparseable: block
  return blocked.check(ip, fam === 4 ? 'ipv4' : 'ipv6');
}

const dnsCache = new Map();
async function hostIsPrivate(host) {
  const hit = dnsCache.get(host);
  if (hit && hit.exp > Date.now()) return hit.priv;
  let priv = false;
  try {
    const addrs = await dns.lookup(host, { all: true });
    priv = addrs.some((a) => isPrivateIp(a.address));
  } catch (e) {
    priv = false; // let the proxy report the DNS failure itself
  }
  if (dnsCache.size > 500) dnsCache.clear();
  dnsCache.set(host, { priv, exp: Date.now() + 60 * 1000 });
  return priv;
}

function parseTarget(reqUrl) {
  const m = /^\/proxy\/(https?):\/*([^\/?#]*)/i.exec(reqUrl);
  if (!m || !m[2]) return null;
  if (/[@\\%]/.test(m[2])) return null; // avoid parser-differential tricks
  try {
    return new URL(m[1].toLowerCase() + '://' + m[2]);
  } catch (e) {
    return null;
  }
}

// Returns a reason string if the target must be refused, otherwise null
async function checkTarget(target, req) {
  const host = target.hostname.replace(/^\[|\]$/g, '').toLowerCase();
  const self = String(req.headers.host || '').toLowerCase().split(':')[0];
  if (host === self) return 'That would loop back into this proxy.';
  if (net.isIP(host)) return isPrivateIp(host) ? 'Private and internal addresses are blocked.' : null;
  if (host === 'localhost' || /\.(localhost|local|internal)$/.test(host)) {
    return 'Private and internal addresses are blocked.';
  }
  return (await hostIsPrivate(host)) ? 'Private and internal addresses are blocked.' : null;
}

const isClientAsset = (url) => url.startsWith('/proxy/client/');

/* ------------------------------------------------------------------ */
/* Service worker (v3.2)                                               */
/*                                                                     */
/* Big sites build absolute URLs in JavaScript (fetch, XHR, <video>,    */
/* CSS fonts, dynamic import). Those skip the browser-side rewriting    */
/* and go straight to the real site, where the browser blocks them      */
/* (CORS), so videos, fonts and API calls fail. This worker catches     */
/* every cross-origin request from a proxied page and sends it through  */
/* /proxy/ instead. It does nothing for same-origin requests.           */
/* ------------------------------------------------------------------ */

const SW_JS = String.raw`
'use strict';
self.addEventListener('install', function () { self.skipWaiting(); });
self.addEventListener('activate', function (e) { e.waitUntil(self.clients.claim()); });

self.addEventListener('fetch', function (e) {
  var req = e.request;
  var u;
  try { u = new URL(req.url); } catch (err) { return; }
  if (u.origin === self.location.origin) return;
  if (u.protocol !== 'http:' && u.protocol !== 'https:') return;
  e.respondWith(proxied(req, u));
});

async function proxied(req, u) {
  var init = { method: req.method, headers: req.headers, credentials: 'include' };
  if (req.method !== 'GET' && req.method !== 'HEAD') {
    init.body = await req.clone().arrayBuffer();
  }
  if (req.referrer && req.referrer !== 'about:client') {
    init.referrer = req.referrer;
    init.referrerPolicy = 'unsafe-url';
  }
  try {
    return await fetch(self.location.origin + '/proxy/' + u.href, init);
  } catch (err) {
    return Response.error();
  }
}
`;

/* ------------------------------------------------------------------ */
/* Patched copy of node-unblocker's browser script                      */
/*                                                                     */
/* Fixes in the original script:                                       */
/*  1. crashes on non-string URLs ("urlStr.substr is not a function")   */
/*  2. fetch(Request) assigns to a read-only property and throws        */
/*  3. WebSockets pick ws:// on https pages (blocked as mixed content)  */
/* Additions:                                                          */
/*  - proxies img/script/iframe/media src and link href set from JS,    */
/*    plus setAttribute("src" | "srcset" | "poster" | link href)        */
/*  - every rewritten URL is made ABSOLUTE (https://proxy/...)          */
/*  - window.open goes through the proxy                                */
/*  - Navigation API guard that reroutes JS redirects                   */
/*  - address-bar path cleanup                                          */
/*  - registers the proxy's service worker and blocks the site's own    */
/*  - strips domain=... from document.cookie writes                     */
/* ------------------------------------------------------------------ */

const CLIENT_SHIM = String.raw`
;(function (g) {
  'use strict';
  var origInit = g.unblockerInit;
  var fixUrl = g.__unblockerFixUrl;
  if (typeof origInit !== 'function' || typeof fixUrl !== 'function') return;

  g.unblockerInit = function (config, win) {
    origInit(config, win);
    if (win !== g) return;
    try { patchServiceWorker(win); } catch (e) { console.error('[proxy] service worker patch failed', e); }
    try { patchCookies(win); } catch (e) { console.error('[proxy] cookie patch failed', e); }
    try { patchCodecs(win); } catch (e) { console.error('[proxy] codec patch failed', e); }
    try { patchUrl(config, win); } catch (e) { console.error('[proxy] url patch failed', e); }
    try { patchMessaging(config, win); } catch (e) { console.error('[proxy] messaging patch failed', e); }
    try { patchDom(config, win); } catch (e) { console.error('[proxy] dom patch failed', e); }
    try { cleanPaths(config, win); } catch (e) { console.error('[proxy] clean paths failed', e); }
    try { guardNavigation(config, win); } catch (e) { console.error('[proxy] nav guard failed', e); }
  };

  // Every proxied site lives on the proxy's own origin, so sites that call
  // postMessage(data, "https://real-site") are refused by the browser, and sites that check
  // event.origin see the proxy's address instead of the real one. Make both sides see the
  // real site origin (the Google sign-in button, captchas and embeds depend on this).
  function patchMessaging(config, win) {
    function realOrigin() {
      try { return new URL(config.url).origin; } catch (e) { return win.location.origin; }
    }
    win.__bbOrigin = realOrigin;
    var nativePost = win.postMessage;
    if (typeof nativePost === 'function') {
      win.postMessage = function (msg, target) {
        var args = Array.prototype.slice.call(arguments);
        if (typeof target === 'string') {
          if (target !== '/') args[1] = '*';
        } else if (target && typeof target === 'object' && typeof target.targetOrigin === 'string') {
          args[1] = Object.assign({}, target, { targetOrigin: '*' });
        }
        return nativePost.apply(this, args);
      };
    }
    var proto = win.MessageEvent && win.MessageEvent.prototype;
    var d = proto && Object.getOwnPropertyDescriptor(proto, 'origin');
    if (d && d.get) {
      Object.defineProperty(proto, 'origin', {
        configurable: true,
        enumerable: d.enumerable,
        get: function () {
          var o = d.get.call(this);
          if (o !== win.location.origin) return o;
          try {
            var s = this.source;
            if (s && typeof s.__bbOrigin === 'function') return s.__bbOrigin();
          } catch (e) {}
          return realOrigin();
        }
      });
    }
  }

  function patchServiceWorker(win) {
    var sw = win.navigator && win.navigator.serviceWorker;
    if (!sw || typeof sw.register !== 'function') return;
    var nativeRegister = sw.register.bind(sw);
    // Our own worker: catches cross-origin requests and routes them through the proxy
    try { nativeRegister('/sw.js', { scope: '/' }).catch(function () {}); } catch (e) {}
    // The site's own worker would register under /proxy/ and fail, so ignore it quietly
    sw.register = function () { return new Promise(function () {}); };
  }

  // Sites like TikTok pick H.265 (HEVC) video when the browser claims support, and many
  // browsers can't really play it. Report it as unsupported so the site serves H.264.
  function patchCodecs(win) {
    var HEVC_RE = /hvc1|hev1|hevc|h\.?265/i;
    var proto = win.HTMLMediaElement && win.HTMLMediaElement.prototype;
    if (proto && proto.canPlayType) {
      var nativeCan = proto.canPlayType;
      proto.canPlayType = function (type) {
        return HEVC_RE.test(String(type)) ? '' : nativeCan.call(this, type);
      };
    }
    if (win.MediaSource && win.MediaSource.isTypeSupported) {
      var nativeSupported = win.MediaSource.isTypeSupported.bind(win.MediaSource);
      win.MediaSource.isTypeSupported = function (type) {
        return HEVC_RE.test(String(type)) ? false : nativeSupported(type);
      };
    }
    var mc = win.navigator && win.navigator.mediaCapabilities;
    if (mc && mc.decodingInfo) {
      var nativeDecode = mc.decodingInfo.bind(mc);
      mc.decodingInfo = function (cfg) {
        var ct = cfg && cfg.video && cfg.video.contentType;
        if (ct && HEVC_RE.test(String(ct))) {
          return Promise.resolve({ supported: false, smooth: false, powerEfficient: false });
        }
        return nativeDecode(cfg);
      };
    }
  }

  function patchCookies(win) {
    var proto = win.Document && win.Document.prototype;
    var d = proto && Object.getOwnPropertyDescriptor(proto, 'cookie');
    if (!d || !d.set) return;
    Object.defineProperty(proto, 'cookie', {
      configurable: true,
      enumerable: d.enumerable,
      get: d.get,
      set: function (v) { d.set.call(this, String(v).replace(/;\s*domain\s*=[^;]*/ig, '')); }
    });
  }

  // Sites call new URL("/proxy/https://...") on proxied paths, which throws because it is
  // relative. Resolve any such path against the proxy's own origin so it always parses.
  function patchUrl(config, win) {
    var NativeURL = win.URL;
    if (!NativeURL || NativeURL.__bbPatched) return;
    // unblocker itself builds new URL(location.pathname minus "/proxy/") for new frames.
    // After the address bar is cleaned (/game/x) that yields junk like "nockout-ctv",
    // so when a string equals that leftover, hand back the real page URL instead.
    function isCleanedTail(str) {
      var l = win.location;
      if (l.pathname.indexOf(config.prefix) === 0) return false;
      var n = config.prefix.length;
      var a = l.pathname, b = a + l.search, c = b + l.hash;
      return a.slice(n) === str || b.slice(n) === str || c.slice(n) === str;
    }
    function PatchedURL(u, base) {
      var s = u;
      if (typeof s === 'string' && base === undefined && s.indexOf(config.prefix) === 0) {
        s = win.location.origin + s;
      }
      try {
        return base === undefined ? new NativeURL(s) : new NativeURL(s, base);
      } catch (err) {
        if (typeof s === 'string' && base === undefined && config.url && isCleanedTail(s)) {
          return new NativeURL(config.url);
        }
        throw err;
      }
    }
    PatchedURL.prototype = NativeURL.prototype;
    Object.setPrototypeOf(PatchedURL, NativeURL);
    PatchedURL.__bbPatched = true;
    win.URL = PatchedURL;
  }

  function patchDom(config, win) {
    var loc = win.location;
    var SKIP_RE = /^(?:blob:|data:|about:|javascript:|mailto:|tel:|#)/i;

    // Sites pass these values to new URL(), which throws on a relative
    // "/proxy/https://..." path. Always hand back a full https://proxy/... URL.
    function abs(s) {
      return (s.charAt(0) === '/' && s.charAt(1) !== '/') ? loc.origin + s : s;
    }

    function fix(v) {
      if (v == null || v === '') return v;
      var s = String(v);
      if (SKIP_RE.test(s)) return v;
      if (s.indexOf(config.prefix) === 0) return abs(s);
      if (s.indexOf(loc.origin + config.prefix) === 0) return v;
      try { return abs(fixUrl(s, config, loc)); } catch (e) { return v; }
    }
    function fixSet(v) {
      if (v == null || v === '') return v;
      return String(v).split(',').map(function (part) {
        var bits = part.trim().split(/\s+/);
        bits[0] = fix(bits[0]);
        return bits.join(' ');
      }).join(', ');
    }
    // Webpack works out where to load its chunks from document.currentScript.src.
    // CrazyGames scripts are requested as /path?__proxy_cookies_to=<real script URL>, which
    // makes chunks load from the wrong host (404). Report the real script URL instead,
    // so chunks are requested next to the real file (through the proxy).
    function realScriptSrc(v) {
      if (typeof v !== 'string' || v.indexOf('__proxy_cookies_to=') < 0) return v;
      try {
        var real = new win.URL(v).searchParams.get('__proxy_cookies_to');
        if (real && /^https?:\/\//i.test(real)) return loc.origin + config.prefix + real;
      } catch (e) {}
      return v;
    }
    function patchProp(ctor, prop) {
      var proto = win[ctor] && win[ctor].prototype;
      var d = proto && Object.getOwnPropertyDescriptor(proto, prop);
      if (!d || !d.set) return;
      var isScriptSrc = ctor === 'HTMLScriptElement' && prop === 'src';
      Object.defineProperty(proto, prop, {
        configurable: true,
        enumerable: d.enumerable,
        get: isScriptSrc ? function () { return realScriptSrc(d.get.call(this)); } : d.get,
        set: function (v) { d.set.call(this, fix(v)); }
      });
    }

    [
      ['HTMLImageElement', 'src'],
      ['HTMLScriptElement', 'src'],
      ['HTMLIFrameElement', 'src'],
      ['HTMLMediaElement', 'src'],
      ['HTMLSourceElement', 'src'],
      ['HTMLLinkElement', 'href']
    ].forEach(function (p) { patchProp(p[0], p[1]); });

    var origSetAttribute = win.Element.prototype.setAttribute;
    win.Element.prototype.setAttribute = function (name, value) {
      var n = String(name).toLowerCase();
      var tag = this.tagName ? this.tagName.toLowerCase() : '';
      if (n === 'src' || n === 'poster') value = fix(value);
      else if (n === 'srcset') value = fixSet(value);
      else if (n === 'href' && tag === 'link') value = fix(value);
      return origSetAttribute.call(this, name, value);
    };

    // window.open(...) to the real site should stay inside the proxy
    var nativeOpen = win.open;
    win.open = function (u) {
      var args = Array.prototype.slice.call(arguments);
      if (u) args[0] = fix(u);
      return nativeOpen.apply(win, args);
    };
  }

  function cleanPaths(config, win) {
    if (!win.document.querySelector('meta[name="bb-clean-paths"]')) return;
    var prefix = config.prefix;
    var loc = win.location;
    if (loc.pathname.indexOf(prefix) !== 0) return;
    var proto = win.History && win.History.prototype;
    if (!proto) return;
    var nativePush = proto.pushState;
    var nativeReplace = proto.replaceState;

    var remote;
    try { remote = new URL(loc.pathname.slice(prefix.length) + loc.search + loc.hash); } catch (e) { return; }

    function pathOf(u) { return u.pathname + u.search + u.hash; }
    function toRemote(url) {
      var s = String(url);
      if (s.indexOf(prefix) === 0) return new URL(s.slice(prefix.length));
      if (s.indexOf(loc.origin + prefix) === 0) return new URL(s.slice(loc.origin.length + prefix.length));
      return new URL(s, remote.href);
    }

    // Remember which site this tab is on, so a refresh or a stray root-relative
    // request is routed back to it. Re-stamped whenever the tab is shown again.
    function stamp() {
      try {
        win.document.cookie = 'bb_last=' + encodeURIComponent(remote.origin) +
          '; Path=/; Max-Age=3600; Secure; SameSite=Lax';
      } catch (e) {}
    }

    function wrap(nativeFn) {
      return function (state, title, url) {
        if (url == null) return nativeFn.call(win.history, state, title);
        var target = toRemote(url);
        var shown = target.origin === remote.origin ? pathOf(target) : prefix + target.href;
        remote = target;
        config.url = target.href;
        stamp();
        return nativeFn.call(win.history, state, title, shown);
      };
    }

    // Show the site's own path instead of /proxy/https://site/path
    nativeReplace.call(win.history, win.history.state, '', pathOf(remote));
    config.url = remote.href;
    stamp();
    win.history.pushState = wrap(nativePush);
    win.history.replaceState = wrap(nativeReplace);
    win.addEventListener('popstate', function () {
      try {
        remote = new URL(loc.pathname + loc.search + loc.hash, remote.href);
        config.url = remote.href;
      } catch (e) {}
    });
    win.addEventListener('focus', stamp);
    win.document.addEventListener('visibilitychange', function () {
      if (!win.document.hidden) stamp();
    });
  }

  // Scripts that do location.href = "https://real-site/..." can't be patched directly
  // (location is unforgeable). The Navigation API lets us catch those and reroute them.
  function guardNavigation(config, win) {
    var nav = win.navigation;
    if (!nav || !nav.addEventListener) return; // older browsers: nothing to do
    nav.addEventListener('navigate', function (e) {
      if (!e.cancelable) return;
      if (e.navigationType === 'reload' || e.navigationType === 'traverse') return;
      var u;
      try { u = new URL(e.destination.url); } catch (err) { return; }
      if (u.protocol !== 'http:' && u.protocol !== 'https:') return;
      if (u.origin === win.location.origin) return;
      e.preventDefault();
      win.location.href = win.location.origin + config.prefix + u.href;
    });
  }
})(this);
`;

function loadPatchedClient() {
  const candidates = [];
  try {
    candidates.push(path.join(path.dirname(require.resolve('unblocker/package.json')), 'lib', 'client', 'unblocker-client.js'));
  } catch (e) { /* ignore */ }
  try {
    candidates.push(path.join(path.dirname(require.resolve('unblocker')), 'client', 'unblocker-client.js'));
  } catch (e) { /* ignore */ }
  const file = candidates.find((f) => fs.existsSync(f));
  if (!file) {
    console.warn('Could not find the unblocker client script; serving it unpatched.');
    return null;
  }

  let out = fs.readFileSync(file, 'utf8');
  const notes = [];
  const patch = (re, replacement, label) => {
    const next = out.replace(re, replacement);
    if (next !== out) { out = next; notes.push(label); }
  };

  patch(
    /function\s+fixUrl\s*\(\s*urlStr\s*,\s*config\s*,\s*location\s*\)\s*\{/,
    (m) => m + ' urlStr = String(urlStr);',
    'string-coercion'
  );
  patch(
    /resource\.url\s*=\s*fixUrl\(\s*resource\.url\s*,\s*config\s*,\s*location\s*\)\s*;/,
    () => 'try { resource = new Request(fixUrl(resource.url, config, location), resource); } catch (e) {}',
    'fetch-request'
  );
  patch(/location\.protocol\s*===\s*"https"/, () => 'location.protocol === "https:"', 'websocket-https-check');
  patch(
    /isSecure\s*\?\s*"ws"\s*\+\s*wsSecure\s*\+\s*":\/\/"\s*:\s*"ws:\/\/"/,
    () => 'isSecure ? "wss://" : "ws://"',
    'websocket-scheme'
  );
  patch(
    /global\.unblockerInit\s*=\s*initForWindow\s*;/,
    () => 'global.unblockerInit = initForWindow; global.__unblockerFixUrl = fixUrl;',
    'expose-fixUrl'
  );

  out += '\n' + CLIENT_SHIM;
  console.log('Patched unblocker client script (' + (notes.join(', ') || 'no patterns matched') + ')');
  return out;
}
const PATCHED_CLIENT = loadPatchedClient();


/* ------------------------------------------------------------------ */
/* Homepage (rendered once at startup)                                 */
/* ------------------------------------------------------------------ */

const HOME = String.raw`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="robots" content="noindex, nofollow">
  <meta name="theme-color" content="#050807">
  <title>__TITLE__</title>
  <link rel="manifest" href="/manifest.webmanifest">
  <link rel="icon" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 32 32'%3E%3Cdefs%3E%3ClinearGradient id='g' x1='0' y1='0' x2='1' y2='1'%3E%3Cstop offset='0' stop-color='%2322c55e'/%3E%3Cstop offset='1' stop-color='%2310b981'/%3E%3C/linearGradient%3E%3C/defs%3E%3Crect width='32' height='32' rx='9' fill='url(%23g)'/%3E%3C/svg%3E">
  <style>
    * { box-sizing: border-box; }
    [hidden] { display: none !important; }
    :root {
      --a: #22c55e; --b: #10b981; --c: #14b8a6;
      --bg: #050807; --card: rgba(255,255,255,.04); --border: rgba(255,255,255,.09);
      --text: #ecfdf3; --muted: #8fa89a;
    }
    html { scroll-behavior: smooth; }
    body { margin: 0; min-height: 100vh; color: var(--text); background: var(--bg); font-family: Inter, system-ui, -apple-system, 'Segoe UI', sans-serif; overflow-x: hidden; position: relative; }
    :focus-visible { outline: 2px solid var(--a); outline-offset: 3px; }
    button { font-family: inherit; }

    .bg { position: fixed; inset: 0; z-index: 0; pointer-events: none; overflow: hidden; }
    .blob { position: absolute; border-radius: 50%; filter: blur(110px); opacity: .5; }
    .b1 { width: 520px; height: 520px; background: var(--a); top: -180px; left: -120px; animation: float 14s ease-in-out infinite; }
    .b2 { width: 460px; height: 460px; background: var(--b); bottom: -200px; right: -100px; opacity: .33; animation: float 18s ease-in-out infinite reverse; }
    .b3 { width: 360px; height: 360px; background: var(--c); top: 40%; left: 55%; opacity: .22; animation: float 22s ease-in-out infinite; }
    .grid { position: absolute; inset: 0; background-image: linear-gradient(rgba(255,255,255,.04) 1px, transparent 1px), linear-gradient(90deg, rgba(255,255,255,.04) 1px, transparent 1px); background-size: 56px 56px; -webkit-mask-image: radial-gradient(circle at 50% 35%, #000 0%, transparent 70%); mask-image: radial-gradient(circle at 50% 35%, #000 0%, transparent 70%); }
    @keyframes float { 0%, 100% { transform: translate(0,0) scale(1); } 50% { transform: translate(40px,30px) scale(1.08); } }
    body.calm * { animation: none !important; transition: none !important; }
    body.calm .blob { opacity: .22; }

    nav { position: relative; z-index: 3; max-width: 1000px; margin: 22px auto 0; padding: 6px 8px; display: flex; align-items: center; justify-content: space-between; gap: 12px; width: calc(100% - 32px); }
    .tagline { flex: 1; text-align: center; font-size: 14px; font-weight: 600; letter-spacing: .4px; color: var(--muted); }
    .logo { display: flex; align-items: center; gap: 10px; font-weight: 700; letter-spacing: .2px; }
    .right { display: flex; align-items: center; gap: 10px; }
    .clock { font-size: 13px; color: var(--muted); font-variant-numeric: tabular-nums; }
    .status { font-size: 13px; color: var(--muted); display: flex; align-items: center; gap: 8px; padding: 6px 12px; border: 1px solid var(--border); border-radius: 999px; font-variant-numeric: tabular-nums; }
    .dot { width: 8px; height: 8px; border-radius: 50%; background: #22c55e; box-shadow: 0 0 10px #22c55e; animation: pulse 2s infinite; }
    .status.off .dot { background: #ef4444; box-shadow: 0 0 10px #ef4444; animation: none; }
    @keyframes pulse { 50% { opacity: .35; } }
    .iconbtn { width: 36px; height: 36px; border-radius: 50%; border: 1px solid var(--border); background: var(--card); color: var(--text); font-size: 17px; cursor: pointer; transition: border-color .15s, background .15s, transform .15s; }
    .iconbtn:hover { border-color: var(--a); background: color-mix(in srgb, var(--a) 14%, transparent); transform: rotate(30deg); }

    main { position: relative; z-index: 2; max-width: 780px; margin: 0 auto; padding: 7vh 20px 50px; text-align: center; }
    .badge { display: inline-block; font-size: 13px; padding: 7px 16px; border-radius: 999px; color: #fff; background: color-mix(in srgb, var(--a) 16%, transparent); border: 1px solid color-mix(in srgb, var(--a) 45%, transparent); margin-bottom: 24px; }
    h1 { font-size: clamp(38px, 10vw, 76px); line-height: 1.05; margin: 0 0 8px; font-weight: 800; letter-spacing: 1px; word-spacing: 8px; text-transform: none; background: linear-gradient(90deg, #fff, var(--a), var(--c), var(--a), #fff); background-size: 300% 100%; -webkit-background-clip: text; background-clip: text; color: transparent; animation: shimmer 8s linear infinite; }
    @keyframes shimmer { to { background-position: 300% 50%; } }
    .greet { color: var(--muted); font-size: 17px; margin: 0 0 30px; min-height: 1.4em; }

    .search-wrap { position: relative; padding: 2px; border-radius: 999px; background: linear-gradient(120deg, color-mix(in srgb, var(--a) 70%, transparent), color-mix(in srgb, var(--b) 70%, transparent), color-mix(in srgb, var(--c) 70%, transparent)); box-shadow: 0 10px 50px color-mix(in srgb, var(--a) 35%, transparent); transition: box-shadow .25s, transform .25s; }
    .search-wrap:focus-within { box-shadow: 0 10px 70px color-mix(in srgb, var(--a) 60%, transparent); transform: translateY(-2px); }
    form#f { display: flex; align-items: center; gap: 8px; padding: 6px 6px 6px 22px; border-radius: 999px; background: #08100c; }
    form#f svg { flex: none; opacity: .7; }
    input#q { flex: 1; min-width: 0; padding: 14px 4px; border: 0; outline: 0; background: transparent; color: var(--text); font-size: 17px; font-family: inherit; }
    input#q::placeholder { color: #5f7a6b; }
    .kbd { flex: none; font-size: 11px; color: var(--muted); border: 1px solid var(--border); border-radius: 6px; padding: 2px 7px; }
    .go { padding: 14px 30px; border: 0; border-radius: 999px; cursor: pointer; color: #fff; font-size: 16px; font-weight: 700; background: linear-gradient(135deg, var(--a), var(--b)); box-shadow: 0 6px 22px color-mix(in srgb, var(--a) 50%, transparent); transition: transform .15s, filter .15s; }
    .go:hover { transform: translateY(-1px); filter: brightness(1.1); }

    .sugg { position: absolute; left: 14px; right: 14px; top: calc(100% + 8px); z-index: 20; margin: 0; padding: 6px; list-style: none; text-align: left; border-radius: 18px; background: #0a120d; border: 1px solid var(--border); box-shadow: 0 20px 60px rgba(0,0,0,.6); }
    .sugg button { width: 100%; display: flex; align-items: center; gap: 10px; padding: 10px 12px; border: 0; border-radius: 12px; background: none; color: var(--text); font-size: 14px; text-align: left; cursor: pointer; }
    .sugg button.on, .sugg button:hover { background: color-mix(in srgb, var(--a) 16%, transparent); }
    .sugg small { margin-left: auto; color: var(--muted); font-size: 12px; max-width: 45%; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }

    .engines { margin-top: 18px; display: flex; flex-wrap: wrap; gap: 8px; justify-content: center; align-items: center; font-size: 13px; color: var(--muted); }
    .chip { font: inherit; font-size: 13px; color: var(--muted); text-decoration: none; cursor: pointer; padding: 7px 14px; border-radius: 999px; border: 1px solid var(--border); background: rgba(255,255,255,.025); transition: color .15s, border-color .15s, background .15s; }
    .chip:hover { color: var(--text); border-color: var(--a); }
    .chip.active { color: #fff; border-color: var(--a); background: color-mix(in srgb, var(--a) 24%, transparent); }

    section { margin-top: 40px; }
    .label { font-size: 12px; text-transform: uppercase; letter-spacing: 1.5px; color: #6b8577; margin-bottom: 14px; display: flex; align-items: center; justify-content: center; gap: 12px; }
    .link { background: none; border: 0; color: var(--a); cursor: pointer; font-size: 12px; text-transform: uppercase; letter-spacing: 1.5px; padding: 0; }
    .link:hover { color: #fff; }

    .quick { display: grid; gap: 14px; grid-template-columns: repeat(auto-fit, minmax(130px, 1fr)); }
    .quick.single { grid-template-columns: minmax(150px, 210px); justify-content: center; }
    .tile { position: relative; }
    .tile a, .tile .addtile { text-decoration: none; color: var(--text); padding: 20px 14px; border-radius: 18px; width: 100%; background: var(--card); border: 1px solid var(--border); -webkit-backdrop-filter: blur(10px); backdrop-filter: blur(10px); display: flex; flex-direction: column; align-items: center; gap: 10px; font-size: 14px; font-weight: 600; transition: transform .2s, border-color .2s, background .2s, box-shadow .2s; }
    .tile .addtile { cursor: pointer; border-style: dashed; color: var(--muted); justify-content: center; height: 100%; min-height: 108px; }
    .tile a:hover, .tile .addtile:hover { transform: translateY(-5px); border-color: var(--a); background: color-mix(in srgb, var(--a) 10%, transparent); box-shadow: 0 14px 34px color-mix(in srgb, var(--a) 25%, transparent); }
    .ico { width: 44px; height: 44px; border-radius: 14px; display: flex; align-items: center; justify-content: center; font-size: 24px; font-weight: 800; background: linear-gradient(135deg, color-mix(in srgb, var(--a) 35%, transparent), color-mix(in srgb, var(--b) 25%, transparent)); border: 1px solid var(--border); }
    .tile b { max-width: 100%; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; font-weight: 600; }
    .x { position: absolute; top: 6px; right: 6px; width: 24px; height: 24px; border-radius: 50%; border: 0; cursor: pointer; background: rgba(255,255,255,.08); color: #bbb; font-size: 15px; line-height: 1; opacity: 0; transition: opacity .15s, background .15s; }
    .tile:hover .x, .x:focus-visible { opacity: 1; }
    .x:hover { background: rgba(239,68,68,.6); color: #fff; }
    @media (hover: none) { .x { opacity: .7; } }

    .chips { display: flex; flex-wrap: wrap; gap: 10px; justify-content: center; }
    .chips .chip { max-width: 100%; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
    .actions { display: flex; flex-wrap: wrap; gap: 10px; justify-content: center; }

    .earth { position: fixed; z-index: 0; left: 50%; bottom: -44vmin; width: 115vmin; height: 115vmin; transform: translateX(-50%); border-radius: 50%; overflow: hidden; opacity: .8; pointer-events: none; background: radial-gradient(circle at 35% 28%, color-mix(in srgb, var(--a) 70%, #000) 0%, color-mix(in srgb, var(--b) 45%, #000) 34%, color-mix(in srgb, var(--b) 20%, #000) 64%, #020806 100%); box-shadow: 0 0 90px color-mix(in srgb, var(--a) 45%, transparent), 0 0 220px color-mix(in srgb, var(--b) 28%, transparent), inset -50px -50px 110px rgba(0,0,0,.7); }
    .earth svg { position: absolute; top: 0; left: 0; width: 200%; height: 100%; animation: spin 140s linear infinite; }
    .earth svg g { fill: rgba(255,255,255,.2); }
    .earth::after { content: ''; position: absolute; inset: 0; border-radius: 50%; background: radial-gradient(circle at 50% 50%, transparent 55%, rgba(2,10,6,.75) 100%); }
    @keyframes spin { to { transform: translateX(-50%); } }

    .note { margin: 0 auto; max-width: 540px; font-size: 13px; line-height: 1.6; color: #5f7a6b; }
    .features { margin-top: 22px; display: flex; flex-wrap: wrap; gap: 10px; justify-content: center; }
    .features div { font-size: 13px; color: var(--muted); padding: 8px 16px; border-radius: 999px; border: 1px solid var(--border); background: rgba(255,255,255,.025); }
    footer { position: relative; z-index: 2; text-align: center; padding: 6px 20px 34px; }

    .sidenav { position: absolute; left: 0; top: 50vh; transform: translateY(-50%); z-index: 30; display: flex; flex-direction: column; gap: 10px; padding: 12px 10px; border: 1px solid var(--border); border-left: 0; border-radius: 0 16px 16px 0; background: var(--card); -webkit-backdrop-filter: blur(10px); backdrop-filter: blur(10px); }
    .sidenav > span { font-size: 11px; text-transform: uppercase; letter-spacing: 1.2px; color: var(--muted); }
    .sidenav #engines { display: flex; flex-direction: column; align-items: stretch; gap: 8px; margin: 0; }
    .sidenav .chip { text-align: left; }
    @media (max-width: 520px) { .sidenav { padding: 8px 6px; } .sidenav .chip { font-size: 11px; padding: 5px 8px; } }

    dialog { padding: 0; border: 1px solid var(--border); border-radius: 22px; background: #09100c; color: var(--text); width: min(560px, calc(100% - 28px)); max-height: calc(100vh - 40px); box-shadow: 0 30px 100px rgba(0,0,0,.7); }
    dialog::backdrop { background: rgba(0,0,0,.62); -webkit-backdrop-filter: blur(4px); backdrop-filter: blur(4px); }
    .dh { display: flex; align-items: center; justify-content: space-between; padding: 18px 22px; border-bottom: 1px solid var(--border); font-weight: 700; font-size: 17px; }
    .dh button { background: none; border: 0; color: var(--muted); font-size: 24px; cursor: pointer; }
    .db { padding: 6px 22px 22px; overflow-y: auto; max-height: calc(100vh - 130px); text-align: left; }
    .db h3 { font-size: 11px; text-transform: uppercase; letter-spacing: 1.5px; color: var(--a); margin: 22px 0 10px; }
    .row { display: flex; align-items: center; justify-content: space-between; gap: 14px; padding: 9px 0; font-size: 14px; }
    .row small { display: block; color: var(--muted); font-size: 12px; margin-top: 2px; }
    .db input[type=text], .db input[type=url], .db select { background: #0d1812; color: var(--text); border: 1px solid var(--border); border-radius: 12px; padding: 10px 12px; font: inherit; font-size: 14px; min-width: 0; max-width: 100%; }
    .db input.full { width: 100%; margin-bottom: 10px; }
    .swatches { display: flex; gap: 10px; flex-wrap: wrap; }
    .sw { width: 30px; height: 30px; border-radius: 50%; border: 2px solid transparent; cursor: pointer; padding: 0; }
    .sw.on { border-color: #fff; box-shadow: 0 0 0 3px rgba(255,255,255,.2); }
    .tog { position: relative; width: 44px; height: 24px; flex: none; border-radius: 999px; border: 0; background: rgba(255,255,255,.14); cursor: pointer; transition: background .2s; }
    .tog::after { content: ''; position: absolute; top: 3px; left: 3px; width: 18px; height: 18px; border-radius: 50%; background: #fff; transition: transform .2s; }
    .tog[aria-pressed=true] { background: var(--a); }
    .tog[aria-pressed=true]::after { transform: translateX(20px); }
    .btn { padding: 9px 16px; border-radius: 999px; border: 1px solid var(--border); background: rgba(255,255,255,.04); color: var(--text); font-size: 13px; cursor: pointer; text-decoration: none; display: inline-block; }
    .btn:hover { border-color: var(--a); }
    .btn.danger:hover { border-color: #ef4444; color: #fca5a5; }
    .btn.primary { background: linear-gradient(135deg, var(--a), var(--b)); border-color: transparent; color: #fff; font-weight: 700; }
    .btns { display: flex; flex-wrap: wrap; gap: 8px; }
    .about { font-size: 13px; color: var(--muted); line-height: 1.8; font-variant-numeric: tabular-nums; }

    .sidebtn { position: absolute; right: 0; top: 50vh; transform: translateY(-50%); z-index: 30; width: 42px; height: 54px; border: 1px solid var(--border); border-right: 0; border-radius: 16px 0 0 16px; background: var(--card); -webkit-backdrop-filter: blur(10px); backdrop-filter: blur(10px); color: var(--text); font-size: 20px; cursor: pointer; transition: background .15s, border-color .15s; }
    .sidebtn:hover { border-color: var(--a); background: color-mix(in srgb, var(--a) 16%, transparent); }
    .drawer { position: fixed; top: 0; right: 0; bottom: 0; z-index: 40; width: min(300px, 85vw); padding: 18px; display: flex; flex-direction: column; gap: 14px; background: #09100c; border-left: 1px solid var(--border); box-shadow: -20px 0 60px rgba(0,0,0,.55); transform: translateX(100%); visibility: hidden; transition: transform .25s ease, visibility .25s; text-align: left; overflow-y: auto; }
    .drawer.open { transform: none; visibility: visible; }
    .drawer-head { display: flex; align-items: center; justify-content: space-between; font-size: 16px; }
    .drawer-head span { display: flex; align-items: center; gap: 12px; }
    .drawer-x { background: none; border: 0; color: var(--muted); font-size: 24px; cursor: pointer; line-height: 1; }
    .drawer .chips { flex-direction: column; flex-wrap: nowrap; align-items: stretch; }
    .drawer .chip { text-align: left; }
    .drawer .empty { color: var(--muted); font-size: 14px; }

    @media (max-width: 520px) { .go { padding: 12px 20px; } .greet { font-size: 15px; } .clock, .kbd { display: none; } }
    @media (prefers-reduced-motion: reduce) { * { animation: none !important; transition: none !important; } }
  </style>
</head>
<body>
  <div class="bg">
    <div class="blob b1"></div><div class="blob b2"></div><div class="blob b3"></div><div class="grid"></div>
  </div>
  <div class="earth"><svg viewBox="0 0 800 400" preserveAspectRatio="none" aria-hidden="true">
    <defs><g id="land">
      <path d="M40 120 C60 80 120 70 150 100 C175 125 160 160 130 175 C110 195 70 190 50 165 C35 150 30 135 40 120 Z"/>
      <path d="M200 90 C230 60 290 65 310 100 C325 130 300 150 285 175 C270 205 235 215 220 190 C205 165 175 130 200 90 Z"/>
      <path d="M110 250 C140 235 180 245 190 275 C200 305 170 345 140 350 C110 355 85 320 90 290 C92 270 95 258 110 250 Z"/>
      <path d="M300 250 C330 240 370 255 375 285 C380 315 350 335 325 330 C300 325 280 295 285 272 C288 260 292 254 300 250 Z"/>
    </g></defs>
    <use href="#land"/><use href="#land" x="400"/>
  </svg></div>

  <aside class="sidenav"><span>Search with</span><div id="engines"></div></aside>

  <nav>
    <div class="logo"></div>
    <div class="tagline">PLAY WHATEVER GAMES YOU WANT</div>
    <div class="right">
      <span class="clock" id="clock"></span>
      <div class="status" id="status"><span class="dot"></span><span id="stext">Undetected</span></div>
      <button class="iconbtn" id="openSettings" type="button" title="Settings" aria-label="Settings">&#9881;</button>
    </div>
  </nav>

  <main>
    <div class="badge">Fast &bull; Private &bull; Simple</div>
    <h1>Blah Blah Blah</h1>
    <p class="greet" id="greet"></p>

    <div class="search-wrap">
      <form id="f" autocomplete="off">
        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" style="color:var(--a)"><circle cx="11" cy="11" r="7"/><path d="M20 20l-3.5-3.5"/></svg>
        <input id="q" placeholder="Put in your blocked website" autocomplete="off" autocapitalize="off" spellcheck="false" autofocus>
        <span class="kbd">/</span>
        <button class="go" type="submit">Go</button>
      </form>
      <ul class="sugg" id="sugg" hidden></ul>
    </div>

    <section>
      <div class="label">Shortcuts</div>
      <div class="quick" id="quick"></div>
    </section>

    <section>
      <div class="actions">
        <button class="btn" id="blankBtn" type="button">Open in new tab</button>
        <button class="btn" id="fsBtn" type="button">Fullscreen</button>
        <button class="btn" id="panicBtn" type="button">Panic now</button>
      </div>
    </section>

    <section class="fun">
      <div class="label">Quick fun</div>
      <div class="quick single">
        <div class="tile">
          <a href="/proxy/https://www.crazygames.com" id="funCg"><span class="ico">&#127918;</span><b>CrazyGames</b></a>
        </div>
      </div>
    </section>
  </main>

  <footer>
    <p class="note">Heavy sites like TikTok, Instagram, or anything behind a Cloudflare check usually won't load through a web proxy. Shortcuts, recent sites and settings are saved in this browser only.</p>
    <div class="features"><div>HTTPS</div><div>No tracking</div><div>Browser bar on every site</div></div>
  </footer>

  <button class="sidebtn" id="recentBtn" type="button" aria-label="Recent sites">&#128339;</button>

  <aside class="drawer" id="drawer" aria-label="Recent sites">
    <div class="drawer-head">
      <b>Recent</b>
      <span>
        <button class="link" id="clearRecent" type="button">Clear</button>
        <button class="drawer-x" id="drawerClose" type="button" aria-label="Close">&times;</button>
      </span>
    </div>
    <div class="chips" id="recents"></div>
  </aside>


  <dialog id="addDlg">
    <div class="dh">Add shortcut <button type="button" data-close aria-label="Close">&times;</button></div>
    <form class="db" id="addForm" autocomplete="off">
      <input class="full" type="text" id="aName" placeholder="Name (for example Wikipedia)" required maxlength="24">
      <input class="full" type="text" id="aUrl" placeholder="Address (for example wikipedia.org)" required>
      <input class="full" type="text" id="aEmoji" placeholder="Emoji (optional)" maxlength="4">
      <div class="btns"><button class="btn primary" type="submit">Add</button><button class="btn" type="button" data-close>Cancel</button></div>
    </form>
  </dialog>

  <dialog id="setDlg">
    <div class="dh">Settings <button type="button" data-close aria-label="Close">&times;</button></div>
    <div class="db">
      <h3>Appearance</h3>
      <div class="row"><div>Accent colour</div><div class="swatches" id="swatches"></div></div>
      <div class="row"><div>Calm mode<small>Turns off the moving background</small></div><button class="tog" id="tCalm" type="button" aria-pressed="false"></button></div>

      <h3>Privacy</h3>
      <div class="row"><div>Tab cloak<small>Changes the tab title and icon on every page</small></div><select id="cloakSel"></select></div>
      <div class="row"><div>Panic key<small>Jumps to the page below. Click, then press a key</small></div><button class="btn" id="pk" type="button"></button></div>
      <div class="row"><div>Calculator key<small>Turns the whole screen into a plain white calculator. Press it again to go back</small></div><button class="btn" id="ck" type="button"></button></div>
      <input class="full" type="text" id="panicUrl" placeholder="Panic page address">

      <h3>Browsing</h3>
      <div class="row"><div>Browser bar on sites<small>Small button with home, back, forward, reload and address box</small></div><button class="tog" id="tBar" type="button" aria-pressed="true"></button></div>
      <div class="row"><div>Default search</div><select id="engSel"></select></div>

      <h3>Data</h3>
      <div class="btns">
        <button class="btn" id="exp" type="button">Export settings</button>
        <button class="btn" id="imp" type="button">Import settings</button>
        <button class="btn danger" id="resetAll" type="button">Reset everything</button>
      </div>
      <input type="file" id="impFile" accept="application/json" hidden>

      <h3>About</h3>
      <div class="about" id="about">Loading...</div>
    </div>
  </dialog>

  <script>window.__bbHome = true;</script>
  <script src="/bb-tools.js"></script>
  <script>
  (function () {
    'use strict';
    var T = window.__bbTools || { PRESETS: { none: { n: 'Off' } }, applyCloak: function () {} };
    function $(s) { return document.querySelector(s); }
    function el(tag, cls, text) { var n = document.createElement(tag); if (cls) n.className = cls; if (text != null) n.textContent = text; return n; }
    function load(k, d) { try { var v = JSON.parse(localStorage.getItem(k)); return v == null ? d : v; } catch (e) { return d; } }
    function save(k, v) { try { localStorage.setItem(k, JSON.stringify(v)); } catch (e) {} }

    // Being on the homepage means no site is "current" in this tab
    try { document.cookie = 'bb_last=; Max-Age=0; Path=/; Secure; SameSite=Lax'; } catch (e) {}
    try { if (navigator.serviceWorker) navigator.serviceWorker.register('/sw.js', { scope: '/' }).catch(function () {}); } catch (e) {}

    /* ---- theme + calm mode ---- */
    var THEMES = {
      green: ['#22c55e', '#10b981', '#14b8a6'], purple: ['#8b5cf6', '#ec4899', '#6366f1'],
      blue: ['#3b82f6', '#06b6d4', '#6366f1'], pink: ['#ec4899', '#f43f5e', '#f97316'],
      orange: ['#f97316', '#eab308', '#ef4444'], mono: ['#d4d4d8', '#a1a1aa', '#71717a']
    };
    function applyTheme(name) {
      var t = THEMES[name] || THEMES.green, s = document.documentElement.style;
      s.setProperty('--a', t[0]); s.setProperty('--b', t[1]); s.setProperty('--c', t[2]);
    }
    function applyCalm() { document.body.classList.toggle('calm', load('bb_calm', false) === true); }
    applyTheme(load('bb_theme', 'green')); applyCalm();

    /* ---- greeting + clock ---- */
    function greeting() {
      var h = new Date().getHours();
      return h < 5 ? 'Up late?' : h < 12 ? 'Good morning.' : h < 18 ? 'Good afternoon.' : 'Good evening.';
    }
    function tick() {
      $('#clock').textContent = new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
      $('#greet').textContent = greeting();
    }

    /* ---- data ---- */
    var ENGINES = {
      bing:  { name: 'Bing',       url: 'https://www.bing.com/search?q=' },
      brave: { name: 'Brave',      url: 'https://search.brave.com/search?q=' },
      wiki:  { name: 'Wikipedia',  url: 'https://en.wikipedia.org/w/index.php?search=' },
      ddg:   { name: 'DuckDuckGo', url: 'https://lite.duckduckgo.com/lite/?q=' }
    };
    var DEFAULT_SHORTCUTS = [
      { n: 'CrazyGames', u: 'https://www.crazygames.com', e: '\uD83C\uDFAE' },
      { n: 'Wikipedia',  u: 'https://en.wikipedia.org',   e: '\uD83D\uDCD6' },
      { n: 'Reddit',     u: 'https://www.reddit.com',     e: '\uD83D\uDCAC' },
      { n: 'YouTube',    u: 'https://www.youtube.com',    e: '\u25B6\uFE0F' }
    ];
    var engine = load('bb_engine', 'ddg'); if (!ENGINES[engine]) engine = 'ddg';
    var recents = load('bb_recents', []);
    var shortcuts = load('bb_shortcuts', null);
    if (!Array.isArray(shortcuts)) shortcuts = DEFAULT_SHORTCUTS.slice();

    function hostOf(u) { try { return new URL(u).hostname.replace(/^www\./, ''); } catch (e) { return u; } }
    function normalize(v) {
      if (/^https?:\/\//i.test(v)) return v;
      if (/^[^\s\/]+\.[a-z]{2,}(:\d+)?([\/?#]\S*)?$/i.test(v)) return 'https://' + v;
      return null;
    }
    function addRecent(label, url) {
      recents = recents.filter(function (r) { return r.u !== url; });
      recents.unshift({ l: label, u: url });
      recents = recents.slice(0, 8);
      save('bb_recents', recents);
    }
    function go(url, label) { addRecent(label, url); location.href = '/proxy/' + url; }

    /* ---- renderers ---- */
    function renderEngines() {
      var box = $('#engines'); box.textContent = '';
      Object.keys(ENGINES).forEach(function (k) {
        var b = el('button', 'chip' + (k === engine ? ' active' : ''), ENGINES[k].name);
        b.type = 'button';
        b.onclick = function () { engine = k; save('bb_engine', k); renderEngines(); $('#engSel').value = k; $('#q').focus(); };
        box.appendChild(b);
      });
    }
    function renderRecents() {
      var box = $('#recents'); box.textContent = '';
      if (!recents.length) { box.appendChild(el('span', 'empty', 'Nothing here yet')); return; }
      recents.forEach(function (r) {
        var a = el('a', 'chip', r.l); a.href = '/proxy/' + r.u; box.appendChild(a);
      });
    }
    function renderShortcuts() {
      var box = $('#quick'); box.textContent = '';
      shortcuts.forEach(function (s, i) {
        var tile = el('div', 'tile');
        var a = el('a'); a.href = '/proxy/' + s.u;
        a.appendChild(el('span', 'ico', s.e || (s.n || '?').charAt(0).toUpperCase()));
        a.appendChild(el('b', null, s.n));
        a.addEventListener('click', function () { addRecent(hostOf(s.u), s.u); });
        var x = el('button', 'x', '\u00D7'); x.type = 'button'; x.title = 'Remove'; x.setAttribute('aria-label', 'Remove ' + s.n);
        x.onclick = function () { shortcuts.splice(i, 1); save('bb_shortcuts', shortcuts); renderShortcuts(); };
        tile.appendChild(a); tile.appendChild(x); box.appendChild(tile);
      });
      var add = el('div', 'tile');
      var ab = el('button', 'addtile'); ab.type = 'button';
      ab.appendChild(el('span', 'ico', '+')); ab.appendChild(el('b', null, 'Add'));
      ab.onclick = function () { $('#addForm').reset(); $('#addDlg').showModal(); $('#aName').focus(); };
      add.appendChild(ab); box.appendChild(add);
    }
    $('#clearRecent').onclick = function () { recents = []; save('bb_recents', recents); renderRecents(); };

    /* ---- recent sites side tab ---- */
    var drawer = $('#drawer');
    function toggleDrawer(on) { drawer.classList.toggle('open', on); }
    $('#recentBtn').onclick = function (e) { e.stopPropagation(); toggleDrawer(!drawer.classList.contains('open')); };
    $('#drawerClose').onclick = function () { toggleDrawer(false); };
    document.addEventListener('click', function (e) { if (!drawer.contains(e.target)) toggleDrawer(false); });
    document.addEventListener('keydown', function (e) { if (e.key === 'Escape') toggleDrawer(false); });

    /* ---- add shortcut ---- */
    $('#addForm').addEventListener('submit', function (e) {
      e.preventDefault();
      var u = normalize($('#aUrl').value.trim());
      if (!u) { $('#aUrl').setCustomValidity('Enter a site address'); $('#aUrl').reportValidity(); $('#aUrl').setCustomValidity(''); return; }
      shortcuts.push({ n: $('#aName').value.trim(), u: u, e: $('#aEmoji').value.trim() });
      save('bb_shortcuts', shortcuts); renderShortcuts(); $('#addDlg').close();
    });

    /* ---- search + suggestions ---- */
    var items = [], active = -1, sugg = $('#sugg'), qin = $('#q');
    function closeSugg() { sugg.hidden = true; active = -1; }
    function paintActive() {
      var btns = sugg.querySelectorAll('button');
      for (var i = 0; i < btns.length; i++) btns[i].classList.toggle('on', i === active);
    }
    function showSugg() {
      var q = qin.value.trim().toLowerCase();
      if (!q) return closeSugg();
      items = [];
      shortcuts.concat(recents.map(function (r) { return { n: r.l, u: r.u }; })).forEach(function (s) {
        var hay = (s.n + ' ' + s.u).toLowerCase();
        if (hay.indexOf(q) >= 0 && !items.some(function (x) { return x.u === s.u; })) items.push({ l: s.n, u: s.u, hint: hostOf(s.u) });
      });
      items = items.slice(0, 5);
      var direct = normalize(qin.value.trim());
      if (direct) items.unshift({ l: 'Open ' + hostOf(direct), u: direct, hint: 'open' });
      items.push({ l: 'Search ' + ENGINES[engine].name + ' for "' + qin.value.trim() + '"', search: true, hint: 'search' });
      sugg.textContent = '';
      items.forEach(function (it, i) {
        var li = el('li'), b = el('button', null, it.l); b.type = 'button';
        b.appendChild(el('small', null, it.hint));
        b.onmousedown = function (e) { e.preventDefault(); choose(it); };
        li.appendChild(b); sugg.appendChild(li);
      });
      sugg.hidden = false; active = -1;
    }
    function choose(it) {
      closeSugg();
      if (it.search) go(ENGINES[engine].url + encodeURIComponent(qin.value.trim()), '\uD83D\uDD0D ' + qin.value.trim());
      else go(it.u, hostOf(it.u));
    }
    qin.addEventListener('input', showSugg);
    qin.addEventListener('blur', function () { setTimeout(closeSugg, 120); });
    qin.addEventListener('keydown', function (e) {
      if (sugg.hidden) return;
      if (e.key === 'ArrowDown') { e.preventDefault(); active = (active + 1) % items.length; paintActive(); }
      else if (e.key === 'ArrowUp') { e.preventDefault(); active = (active - 1 + items.length) % items.length; paintActive(); }
      else if (e.key === 'Escape') closeSugg();
    });
    $('#f').addEventListener('submit', function (e) {
      e.preventDefault();
      if (active >= 0 && items[active]) return choose(items[active]);
      var v = qin.value.trim(); if (!v) return;
      var u = normalize(v);
      if (u) go(u, hostOf(u)); else go(ENGINES[engine].url + encodeURIComponent(v), '\uD83D\uDD0D ' + v);
    });

    /* ---- quick actions ---- */
    $('#blankBtn').onclick = function () {
      var w = window.open('about:blank', '_blank');
      if (!w) { alert('Allow pop-ups for this site first, then try again.'); return; }
      var d = w.document, p = T.PRESETS[load('bb_cloak', 'none')];
      d.title = (p && p.t) || document.title;
      if (p && p.i) { var l = d.createElement('link'); l.rel = 'icon'; l.href = p.i; d.head.appendChild(l); }
      d.body.style.cssText = 'margin:0;background:#050807';
      var f = d.createElement('iframe');
      f.src = location.origin + '/';
      f.style.cssText = 'position:fixed;inset:0;width:100%;height:100%;border:0';
      d.body.appendChild(f);
    };
    $('#fsBtn').onclick = function () {
      if (document.fullscreenElement) document.exitFullscreen();
      else if (document.documentElement.requestFullscreen) document.documentElement.requestFullscreen();
    };
    $('#panicBtn').onclick = function () { location.replace(load('bb_panic_url', 'https://classroom.google.com')); };

    /* ---- settings ---- */
    var setDlg = $('#setDlg');
    function setTog(btn, on) { btn.setAttribute('aria-pressed', on ? 'true' : 'false'); }
    function keyLabel(k) { return k === ' ' ? 'Space' : (k || 'None'); }
    function openSettings() {
      setTog($('#tCalm'), load('bb_calm', false) === true);
      setTog($('#tBar'), load('bb_toolbar', '1') !== '0');
      $('#cloakSel').value = load('bb_cloak', 'none');
      $('#engSel').value = engine;
      $('#panicUrl').value = load('bb_panic_url', 'https://classroom.google.com');
      $('#pk').textContent = keyLabel(load('bb_panic_key', '\u0060'));
      $('#ck').textContent = keyLabel(load('bb_calc_key', 'F2'));
      document.querySelectorAll('.sw').forEach(function (s) { s.classList.toggle('on', s.dataset.t === load('bb_theme', 'green')); });
      setDlg.showModal();
      fetch('/api/info', { cache: 'no-store' }).then(function (r) { return r.json(); }).then(function (i) {
        var up = Math.floor(i.uptime), h = Math.floor(up / 3600), m = Math.floor((up % 3600) / 60);
        $('#about').innerHTML = '';
        [['Version', i.version], ['Server uptime', h + 'h ' + m + 'm'], ['Upstream proxy', i.upstreamProxy],
         ['Address cleanup', i.cleanMode], ['Active sessions', String(i.sessions)], ['Node', i.node]
        ].forEach(function (r) { var d = el('div'); d.textContent = r[0] + ': ' + r[1]; $('#about').appendChild(d); });
      }).catch(function () { $('#about').textContent = 'Could not load server info.'; });
    }
    $('#openSettings').onclick = openSettings;
    document.querySelectorAll('dialog').forEach(function (dlg) {
      dlg.addEventListener('click', function (e) { if (e.target === dlg || (e.target.hasAttribute && e.target.hasAttribute('data-close'))) dlg.close(); });
    });

    var sw = $('#swatches');
    Object.keys(THEMES).forEach(function (k) {
      var b = el('button', 'sw'); b.type = 'button'; b.dataset.t = k; b.title = k; b.setAttribute('aria-label', k + ' theme');
      b.style.background = 'linear-gradient(135deg,' + THEMES[k][0] + ',' + THEMES[k][1] + ')';
      b.onclick = function () {
        save('bb_theme', k); applyTheme(k);
        document.querySelectorAll('.sw').forEach(function (s) { s.classList.toggle('on', s === b); });
      };
      sw.appendChild(b);
    });
    $('#tCalm').onclick = function () { var on = !(load('bb_calm', false) === true); save('bb_calm', on); setTog(this, on); applyCalm(); };
    $('#tBar').onclick = function () { var on = load('bb_toolbar', '1') === '0'; save('bb_toolbar', on ? '1' : '0'); setTog(this, on); };

    var cs = $('#cloakSel');
    Object.keys(T.PRESETS).forEach(function (k) { var o = el('option', null, T.PRESETS[k].n); o.value = k; cs.appendChild(o); });
    cs.onchange = function () { save('bb_cloak', cs.value); T.applyCloak(document.title); if (cs.value === 'none') location.reload(); };
    var es = $('#engSel');
    Object.keys(ENGINES).forEach(function (k) { var o = el('option', null, ENGINES[k].name); o.value = k; es.appendChild(o); });
    es.onchange = function () { engine = es.value; save('bb_engine', engine); renderEngines(); };

    $('#panicUrl').addEventListener('change', function () {
      var v = this.value.trim(), u = normalize(v);
      if (u) save('bb_panic_url', u); else this.value = load('bb_panic_url', 'https://classroom.google.com');
    });
    function bindKeyBtn(btn, store, def, otherStore, otherDef, otherName) {
      btn.onclick = function () {
        btn.textContent = 'Press a key...';
        window.__bbCapturing = true;
        function h(e) {
          if (['Shift', 'Control', 'Alt', 'Meta'].indexOf(e.key) >= 0) return;
          e.preventDefault(); e.stopPropagation();
          document.removeEventListener('keydown', h, true);
          if (e.key !== 'Escape') {
            if (e.key === load(otherStore, otherDef)) alert('That key is already used for the ' + otherName + '.');
            else save(store, e.key);
          }
          btn.textContent = keyLabel(load(store, def));
          setTimeout(function () { window.__bbCapturing = false; }, 50);
        }
        document.addEventListener('keydown', h, true);
      };
    }
    bindKeyBtn($('#pk'), 'bb_panic_key', '\u0060', 'bb_calc_key', 'F2', 'calculator key');
    bindKeyBtn($('#ck'), 'bb_calc_key', 'F2', 'bb_panic_key', '\u0060', 'panic key');

    function bbKeys() {
      var out = {};
      for (var i = 0; i < localStorage.length; i++) {
        var k = localStorage.key(i);
        if (k && k.indexOf('bb_') === 0) out[k] = localStorage.getItem(k);
      }
      return out;
    }
    $('#exp').onclick = function () {
      var a = document.createElement('a');
      a.href = URL.createObjectURL(new Blob([JSON.stringify(bbKeys(), null, 2)], { type: 'application/json' }));
      a.download = 'proxy-settings.json'; document.body.appendChild(a); a.click(); a.remove();
    };
    $('#imp').onclick = function () { $('#impFile').click(); };
    $('#impFile').onchange = function () {
      var f = this.files && this.files[0]; if (!f) return;
      var r = new FileReader();
      r.onload = function () {
        try {
          var o = JSON.parse(r.result);
          Object.keys(o).forEach(function (k) { if (k.indexOf('bb_') === 0 && typeof o[k] === 'string') localStorage.setItem(k, o[k]); });
          location.reload();
        } catch (e) { alert('That file is not a valid settings export.'); }
      };
      r.readAsText(f);
    };
    $('#resetAll').onclick = function () {
      if (!confirm('Reset all shortcuts, recents and settings in this browser?')) return;
      Object.keys(bbKeys()).forEach(function (k) { localStorage.removeItem(k); });
      location.reload();
    };

    /* ---- keyboard + status ---- */
    document.addEventListener('keydown', function (e) {
      var t = e.target && e.target.tagName;
      if (window.__bbCapturing) return;
      if ((e.key === '/' && t !== 'INPUT' && t !== 'TEXTAREA' && t !== 'SELECT') || ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'k')) { e.preventDefault(); qin.focus(); qin.select(); }
      if (e.key === 'Escape' && !document.querySelector('dialog[open]')) qin.blur();
    });
    function setStatus(ok, ms) {
      $('#status').className = 'status' + (ok ? '' : ' off');
      $('#status').title = ok ? ms + ' ms' : '';
      $('#stext').textContent = ok ? 'Undetected' : 'Offline';
    }
    function ping() {
      var t0 = performance.now();
      fetch('/healthz', { cache: 'no-store' })
        .then(function (r) { setStatus(r.ok, Math.round(performance.now() - t0)); })
        .catch(function () { setStatus(false, 0); });
    }

    renderEngines(); renderRecents(); renderShortcuts();
    $('#funCg').addEventListener('click', function () { addRecent('crazygames.com', 'https://www.crazygames.com'); });
    T.applyCloak(null);
    tick(); setInterval(tick, 20000);
    ping(); setInterval(ping, 30000);
  })();
  </script>
</body>
</html>`;
const HOME_HTML = HOME.replace(/__TITLE__/g, TITLE_HTML).replace(/__VERSION__/g, VERSION);


/* ------------------------------------------------------------------ */
/* App setup                                                           */
/* ------------------------------------------------------------------ */

app.disable('x-powered-by');
app.set('trust proxy', true); // Render terminates HTTPS in front of the app

app.use((req, res, next) => {
  res.set('X-Robots-Tag', 'noindex, nofollow');
  if (!req.url.startsWith('/proxy/')) {
    res.set('X-Content-Type-Options', 'nosniff');
    res.set('Referrer-Policy', 'no-referrer');
  }
  next();
});

app.get('/robots.txt', (req, res) => res.type('text/plain').send('User-agent: *\nDisallow: /\n'));
app.get('/healthz', (req, res) => res.type('text/plain').set('Cache-Control', 'no-store').send('ok'));

// The service worker script holds no secrets. It is served before the login so the
// browser can always fetch and update it, even when it doesn't send the password.
app.get('/sw.js', (req, res) => {
  res.type('application/javascript')
    .set('Cache-Control', 'no-cache')
    .set('Service-Worker-Allowed', '/')
    .send(SW_JS);
});

/* ------------------------------------------------------------------ */
/* Password protection                                                 */
/*                                                                     */
/* Set the PROXY_PASS environment variable to require a password.       */
/* Visitors sign in once (30-day cookie). /healthz, /robots.txt and the */
/* service worker stay public. Without PROXY_PASS there is no login.    */
/* ------------------------------------------------------------------ */

const PROXY_PASS = process.env.PROXY_PASS || '';
const AUTH_ON = PROXY_PASS.length > 0;
const sha = (v) => crypto.createHash('sha256').update(String(v)).digest();
const AUTH_TOKEN = crypto.createHmac('sha256', sha('bb-key:' + PROXY_PASS)).update('signed-in').digest('hex');
const safeEq = (a, b) => crypto.timingSafeEqual(sha(a), sha(b));

function isAuthed(req) {
  if (!AUTH_ON) return true;
  const m = /(?:^|;\s*)bb_auth=([a-f0-9]{64})/.exec((req.headers && req.headers.cookie) || '');
  return !!m && safeEq(m[1], AUTH_TOKEN);
}

// Only allow sending people back to a path on this site
function safeNext(n) {
  n = String(n || '/');
  return n.charAt(0) === '/' && n.charAt(1) !== '/' && n.charAt(1) !== '\\' && n.length < 2000 ? n : '/';
}

// Slow down password guessing: 8 wrong tries per IP, then a 10 minute wait
const loginFails = new Map();
function lockedOut(ip) {
  const r = loginFails.get(ip);
  if (!r) return false;
  if (Date.now() - r.t > 10 * 60 * 1000) { loginFails.delete(ip); return false; }
  return r.n >= 8;
}
function noteFail(ip) {
  const r = loginFails.get(ip);
  if (loginFails.size > 2000) loginFails.clear();
  loginFails.set(ip, { n: (r && Date.now() - r.t <= 10 * 60 * 1000 ? r.n : 0) + 1, t: Date.now() });
}

function loginPage(msg, next) {
  return '<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">' +
    '<meta name="viewport" content="width=device-width, initial-scale=1">' +
    '<meta name="robots" content="noindex, nofollow"><title>' + TITLE_HTML + '</title><style>' +
    '*{box-sizing:border-box}body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;' +
    'background:#040907;color:#ecfdf3;font-family:Inter,system-ui,-apple-system,"Segoe UI",sans-serif;padding:20px}' +
    'form{width:100%;max-width:380px;text-align:center;padding:40px 30px;border-radius:24px;background:rgba(255,255,255,.04);' +
    'border:1px solid rgba(255,255,255,.09);box-shadow:0 20px 80px rgba(34,197,94,.25)}' +
    'h1{font-size:22px;margin:0 0 6px}p{color:#8fa89a;margin:0 0 22px;font-size:14px}' +
    '.err{color:#fca5a5;font-size:13px;margin:0 0 14px;min-height:1em}' +
    'input{width:100%;padding:14px 18px;border-radius:999px;border:1px solid rgba(255,255,255,.14);background:#08100c;' +
    'color:#ecfdf3;font:inherit;font-size:16px;outline:0;margin-bottom:14px}input:focus{border-color:#22c55e}' +
    'button{width:100%;padding:14px;border:0;border-radius:999px;cursor:pointer;color:#fff;font:inherit;font-size:16px;' +
    'font-weight:700;background:linear-gradient(135deg,#22c55e,#10b981)}' +
    '</style></head><body><form method="post" action="/login" autocomplete="off">' +
    '<h1>Password required</h1><p>Enter the password to continue.</p>' +
    '<div class="err">' + escapeHtml(msg || '') + '</div>' +
    '<input type="hidden" name="next" value="' + escapeHtml(next || '/') + '">' +
    '<input type="password" name="password" placeholder="Password" autofocus required>' +
    '<button type="submit">Enter</button></form></body></html>';
}

if (AUTH_ON) {
  console.log('Password protection is ON (PROXY_PASS is set)');
  app.get('/login', (req, res) => {
    if (isAuthed(req)) return res.redirect(302, safeNext(req.query.next));
    res.type('html').set('Cache-Control', 'no-store').send(loginPage('', safeNext(req.query.next)));
  });
  app.post('/login', express.urlencoded({ extended: false, limit: '4kb' }), (req, res) => {
    const ip = ipOf(req);
    const next = safeNext(req.body && req.body.next);
    if (lockedOut(ip)) {
      return res.status(429).type('html').set('Cache-Control', 'no-store')
        .send(loginPage('Too many wrong tries. Wait a few minutes and try again.', next));
    }
    if (safeEq((req.body && req.body.password) || '', PROXY_PASS)) {
      loginFails.delete(ip);
      res.append('Set-Cookie', 'bb_auth=' + AUTH_TOKEN + '; Path=/; HttpOnly; SameSite=Lax; Max-Age=2592000' + (req.secure ? '; Secure' : ''));
      return res.redirect(303, next);
    }
    noteFail(ip);
    res.status(401).type('html').set('Cache-Control', 'no-store').send(loginPage('Wrong password.', next));
  });
  app.get('/logout', (req, res) => {
    res.append('Set-Cookie', 'bb_auth=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0' + (req.secure ? '; Secure' : ''));
    res.redirect(303, '/login');
  });
  // Everything below this point needs the password
  app.use((req, res, next) => {
    if (isAuthed(req)) return next();
    if (req.method === 'GET' && /text\/html/i.test(String(req.headers.accept || ''))) {
      return res.redirect(302, '/login?next=' + encodeURIComponent(req.originalUrl));
    }
    res.status(401).type('text/plain').set('Cache-Control', 'no-store').send('Sign in required');
  });
} else {
  console.log('No PROXY_PASS set: the proxy is open to everyone. Set PROXY_PASS to add a password.');
}


const BB_TOOLS_JS = String.raw`
;(function () {
  'use strict';

  // Game and video frames inside a page only pass their key presses up to the main page
  if (window.__bbFrame) {
    window.addEventListener('keydown', function (e) {
      var w = window;
      for (var i = 0; i < 8; i++) {
        try {
          if (w === w.parent) return;
          w = w.parent;
          if (w.__bbTools && w.__bbTools.handleKey) { w.__bbTools.handleKey(e); return; }
        } catch (x) { return; }
      }
    }, true);
    return;
  }

  try {
    if (window.top !== window.self && window.top.location.href !== 'about:blank') return;
  } catch (e) { return; }
  if (window.__bbToolsLoaded) return;
  window.__bbToolsLoaded = true;

  function load(k, d) { try { var v = JSON.parse(localStorage.getItem(k)); return v == null ? d : v; } catch (e) { return d; } }
  function save(k, v) { try { localStorage.setItem(k, JSON.stringify(v)); } catch (e) {} }

  function ic(letter, color) {
    return 'data:image/svg+xml,' + encodeURIComponent(
      '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32"><rect width="32" height="32" rx="7" fill="' + color +
      '"/><text x="16" y="23" font-size="20" font-family="Arial,sans-serif" font-weight="700" text-anchor="middle" fill="#fff">' +
      letter + '</text></svg>');
  }
  var PRESETS = {
    none:      { n: 'Off (show the real page title)' },
    google:    { n: 'Google',               t: 'Google',                          i: ic('G', '#4285f4') },
    classroom: { n: 'Google Classroom',     t: 'Classes',                         i: ic('C', '#0f9d58') },
    docs:      { n: 'Google Docs',          t: 'Untitled document - Google Docs', i: ic('D', '#4285f4') },
    drive:     { n: 'Google Drive',         t: 'My Drive - Google Drive',         i: ic('D', '#34a853') },
    canvas:    { n: 'Canvas',               t: 'Dashboard',                       i: ic('C', '#e72429') },
    wiki:      { n: 'Wikipedia',            t: 'Wikipedia, the free encyclopedia', i: ic('W', '#555555') }
  };

  var obs = null, applying = false;
  function setIcon(href) {
    var old = document.querySelectorAll('link[rel~="icon"]');
    for (var i = 0; i < old.length; i++) old[i].parentNode.removeChild(old[i]);
    var l = document.createElement('link');
    l.rel = 'icon'; l.href = href;
    document.head.appendChild(l);
  }
  function applyCloak(homeTitle) {
    if (obs) { obs.disconnect(); obs = null; }
    var p = PRESETS[load('bb_cloak', 'none')];
    if (!p || !p.t) { if (homeTitle) document.title = homeTitle; return; }
    function run() {
      applying = true;
      if (document.title !== p.t) document.title = p.t;
      var cur = document.querySelector('link[rel~="icon"]');
      if (!cur || cur.getAttribute('href') !== p.i) setIcon(p.i);
      applying = false;
    }
    run();
    if (document.head) {
      obs = new MutationObserver(function () { if (!applying) run(); });
      obs.observe(document.head, { childList: true, subtree: true, characterData: true, attributes: true, attributeFilter: ['href'] });
    }
  }

  var ENGINES = {
    ddg: 'https://lite.duckduckgo.com/lite/?q=', bing: 'https://www.bing.com/search?q=',
    brave: 'https://search.brave.com/search?q=', wiki: 'https://en.wikipedia.org/w/index.php?search='
  };
  function normalize(v) {
    v = String(v || '').trim();
    if (!v) return null;
    if (/^https?:\/\//i.test(v)) return v;
    if (/^[^\s\/]+\.[a-z]{2,}(:\d+)?([\/?#]\S*)?$/i.test(v)) return 'https://' + v;
    return (ENGINES[load('bb_engine', 'ddg')] || ENGINES.ddg) + encodeURIComponent(v);
  }
  function realUrl() {
    var l = location, p = '/proxy/';
    if (l.pathname.indexOf(p) === 0) return l.pathname.slice(p.length) + l.search + l.hash;
    var m = /(?:^|;\s*)bb_last=([^;]+)/.exec(document.cookie);
    if (m) { try { return decodeURIComponent(m[1]) + l.pathname + l.search + l.hash; } catch (e) {} }
    return '';
  }

  /* ---------------------------------------------------------------- */
  /* Calculator mode: a plain white full-screen calculator             */
  /* ---------------------------------------------------------------- */

  var calc = { host: null, root: null, open: false, expr: '', prev: '', done: false, err: false };

  // Small expression parser (no eval): + - * / % and brackets
  function evaluate(s) {
    var i = 0;
    function peek() { return s.charAt(i); }
    function post(v) { while (peek() === '%') { i++; v = v / 100; } return v; }
    function primary() {
      var c = peek();
      if (c === '(') {
        i++;
        var v = expr();
        if (peek() !== ')') throw 0;
        i++;
        return post(v);
      }
      if (c === '-') { i++; return -primary(); }
      if (c === '+') { i++; return primary(); }
      var m = /^(\d+\.?\d*|\.\d+)/.exec(s.slice(i));
      if (!m) throw 0;
      i += m[0].length;
      return post(parseFloat(m[0]));
    }
    function term() {
      var v = primary();
      for (;;) {
        var c = peek();
        if (c === '*') { i++; v = v * primary(); }
        else if (c === '/') { i++; var r = primary(); if (r === 0) throw 0; v = v / r; }
        else return v;
      }
    }
    function expr() {
      var v = term();
      for (;;) {
        var c = peek();
        if (c === '+') { i++; v = v + term(); }
        else if (c === '-') { i++; v = v - term(); }
        else return v;
      }
    }
    var out = expr();
    if (i !== s.length) throw 0;
    return out;
  }
  function fmt(r) {
    if (!isFinite(r)) throw 0;
    var a = Math.abs(r);
    if (a >= 1e21) throw 0;
    var out = Number.isInteger(r) ? String(r) : (a < 1e-6 ? r.toFixed(12).replace(/\.?0+$/, '') : String(parseFloat(r.toPrecision(12))));
    if (/e/i.test(out)) throw 0;
    return out === '-0' ? '0' : out;
  }
  function autoClose(s) {
    var o = (s.match(/\(/g) || []).length - (s.match(/\)/g) || []).length;
    while (o-- > 0) s += ')';
    return s;
  }
  function tryEval(s) {
    try { return fmt(evaluate(autoClose(s))); } catch (e) { return null; }
  }
  function pretty(s) {
    return s.replace(/\*/g, '\u00D7').replace(/\//g, '\u00F7').replace(/-/g, '\u2212');
  }

  function render() {
    if (!calc.root) return;
    var main = calc.root.querySelector('#r'), sub = calc.root.querySelector('#s');
    var shown = calc.err ? 'Error' : (calc.expr ? pretty(calc.expr) : '0');
    var small = '';
    if (!calc.err) {
      if (calc.done) small = pretty(calc.prev) + ' =';
      else if (/[-+*\/%]/.test(calc.expr.replace(/^-/, ''))) {
        var p = tryEval(calc.expr);
        if (p !== null && p !== calc.expr) small = '= ' + p;
      }
    }
    var n = shown.length;
    main.style.fontSize = (n <= 9 ? 48 : n <= 13 ? 36 : n <= 19 ? 28 : 22) + 'px';
    main.textContent = shown;
    sub.textContent = small || '\u00A0';
  }

  function press(k) {
    var wasErr = calc.err;
    calc.err = false;
    var s = calc.expr, last = s.charAt(s.length - 1);

    if (k === 'C') { calc.expr = ''; calc.done = false; return render(); }
    if (k === 'B') {
      if (calc.done || wasErr) { calc.expr = ''; calc.done = false; }
      else calc.expr = s.slice(0, -1);
      return render();
    }
    if (k === '=') {
      if (!s || calc.done) return render();
      var r = tryEval(s);
      if (r === null) calc.err = true;
      else { calc.prev = s; calc.expr = r; calc.done = true; }
      return render();
    }

    if (calc.done) {
      if (/[0-9.(]/.test(k)) { s = ''; last = ''; }
      calc.done = false;
    }

    if (/[0-9]/.test(k)) {
      if (last === ')' || last === '%') s += '*';
      if (/(^|[^0-9.])0$/.test(s)) s = s.slice(0, -1);
      s += k;
    } else if (k === '.') {
      var seg = /[0-9.]*$/.exec(s)[0];
      if (seg.indexOf('.') >= 0) return render();
      if (last === ')' || last === '%') s += '*';
      s += seg ? '.' : '0.';
    } else if (/[-+*\/]/.test(k)) {
      if (!s) { if (k !== '-') return render(); s = '-'; }
      else if (last === '(') { if (k !== '-') return render(); s += '-'; }
      else if (/[-+*\/]/.test(last)) { if (s.length === 1) return render(); s = s.slice(0, -1) + k; }
      else s += k;
    } else if (k === '%') {
      if (!/[0-9)%]/.test(last)) return render();
      s += '%';
    } else if (k === '(') {
      if (/[0-9)%.]/.test(last)) s += '*';
      s += '(';
    } else if (k === ')') {
      var open = (s.match(/\(/g) || []).length - (s.match(/\)/g) || []).length;
      if (open < 1 || !/[0-9)%]/.test(last)) return render();
      s += ')';
    } else {
      return render();
    }
    if (s.length > 40) return render();
    calc.expr = s;
    render();
  }

  function buildCalc() {
    var host = document.createElement('div');
    host.style.cssText = 'all:initial;position:fixed;left:0;top:0;right:0;bottom:0;z-index:2147483647;display:none';
    host.setAttribute('tabindex', '-1');
    var root = host.attachShadow({ mode: 'open' });
    var keys = [
      ['C', 'C'], ['(', '('], [')', ')'], ['B', '\u232B'],
      ['7', '7'], ['8', '8'], ['9', '9'], ['/', '\u00F7'],
      ['4', '4'], ['5', '5'], ['6', '6'], ['*', '\u00D7'],
      ['1', '1'], ['2', '2'], ['3', '3'], ['-', '\u2212'],
      ['0', '0'], ['.', '.'], ['%', '%'], ['+', '+']
    ];
    var html = [
      '<style>',
      '*{box-sizing:border-box}',
      '.w{position:fixed;left:0;top:0;right:0;bottom:0;background:#fff;color:#000;display:flex;align-items:center;justify-content:center;font-family:system-ui,-apple-system,"Segoe UI",Arial,sans-serif;-webkit-font-smoothing:antialiased}',
      '.c{width:min(340px,92vw);display:flex;flex-direction:column;gap:12px}',
      '.d{height:112px;border:2px solid #000;border-radius:10px;padding:10px 14px;text-align:right;display:flex;flex-direction:column;justify-content:flex-end;overflow:hidden;background:#fff}',
      '.s{font-size:15px;min-height:20px;white-space:nowrap;overflow:hidden}',
      '.r{font-weight:600;line-height:1.15;white-space:nowrap;overflow:hidden}',
      '.g{display:grid;grid-template-columns:repeat(4,1fr);gap:8px}',
      'button{height:62px;font:inherit;font-size:24px;color:#000;background:#fff;border:1.5px solid #000;border-radius:10px;cursor:pointer;padding:0}',
      'button:hover{background:#eee}button:active{background:#ddd}',
      '.eq{grid-column:1/-1;height:58px}',
      '</style>',
      '<div class="w"><div class="c"><div class="d"><div class="s" id="s">&nbsp;</div><div class="r" id="r">0</div></div><div class="g">'
    ];
    keys.forEach(function (k) { html.push('<button data-k="' + k[0] + '">' + k[1] + '</button>'); });
    html.push('<button class="eq" data-k="=">=</button></div></div></div>');
    root.innerHTML = html.join('');
    root.addEventListener('click', function (e) {
      var b = e.target && e.target.closest ? e.target.closest('button') : null;
      if (b) press(b.getAttribute('data-k'));
    });
    (document.documentElement || document.body).appendChild(host);
    calc.host = host; calc.root = root;
  }

  function pauseMedia(doc) {
    try {
      var m = doc.querySelectorAll('video,audio');
      for (var i = 0; i < m.length; i++) { try { m[i].pause(); } catch (e) {} }
      var f = doc.querySelectorAll('iframe');
      for (var j = 0; j < f.length; j++) { try { pauseMedia(f[j].contentDocument); } catch (e) {} }
    } catch (e) {}
  }
  function openCalc() {
    if (!calc.host) buildCalc();
    calc.expr = ''; calc.prev = ''; calc.done = false; calc.err = false;
    calc.host.style.display = 'block';
    calc.open = true;
    pauseMedia(document);
    try {
      if (document.activeElement && document.activeElement.blur) document.activeElement.blur();
      window.focus();
      calc.host.focus();
    } catch (e) {}
    render();
  }
  function closeCalc() {
    calc.open = false;
    if (calc.host) calc.host.style.display = 'none';
  }

  function calcKey(e) {
    if (e.ctrlKey || e.metaKey || e.altKey) return;
    var k = e.key, p = null;
    if (/^[0-9]$/.test(k)) p = k;
    else if (k === '.' || k === ',') p = '.';
    else if (k === '+' || k === '-' || k === '*' || k === '/' || k === '%' || k === '(' || k === ')') p = k;
    else if (k === 'x' || k === 'X') p = '*';
    else if (k === 'Enter' || k === '=') p = '=';
    else if (k === 'Backspace') p = 'B';
    else if (k === 'Delete' || k === 'Escape' || k === 'c' || k === 'C') p = 'C';
    e.preventDefault(); e.stopPropagation();
    if (e.stopImmediatePropagation) e.stopImmediatePropagation();
    if (p) press(p);
  }

  /* ---------------------------------------------------------------- */
  /* Key handling: panic key and calculator key                        */
  /* ---------------------------------------------------------------- */

  function handleKey(e) {
    if (window.__bbCapturing) return false;
    var key = e.key;
    var t = e.target, tag = t && t.tagName;
    var typing = tag === 'INPUT' || tag === 'TEXTAREA' || (t && t.isContentEditable);

    var panicKey = load('bb_panic_key', '\u0060');
    if (panicKey && key === panicKey && !(typing && panicKey.length === 1)) {
      e.preventDefault();
      location.replace(load('bb_panic_url', 'https://classroom.google.com'));
      return true;
    }

    var calcKeyName = load('bb_calc_key', 'F2');
    if (calcKeyName && key === calcKeyName && (calc.open || !(typing && calcKeyName.length === 1))) {
      e.preventDefault(); e.stopPropagation();
      if (e.stopImmediatePropagation) e.stopImmediatePropagation();
      if (calc.open) closeCalc(); else openCalc();
      return true;
    }

    if (calc.open) { calcKey(e); return true; }
    return false;
  }
  window.addEventListener('keydown', function (e) { handleKey(e); }, true);

  // Floating browser bar (proxied pages only)
  function buildBar() {
    if (window.__bbHome || load('bb_toolbar', '1') === '0') return;
    var host = document.createElement('div');
    host.id = 'bb-tools-host';
    host.style.cssText = 'all:initial;position:fixed;left:12px;bottom:12px;z-index:2147483646';
    var root = host.attachShadow({ mode: 'open' });
    root.innerHTML = [
      '<style>',
      '*{box-sizing:border-box;font-family:system-ui,-apple-system,"Segoe UI",sans-serif}',
      '.pill{width:38px;height:38px;border-radius:50%;border:1px solid rgba(255,255,255,.18);background:rgba(10,16,13,.88);color:#ecfdf3;font-size:17px;cursor:pointer;box-shadow:0 6px 24px rgba(0,0,0,.45);opacity:.55;transition:opacity .15s}',
      '.pill:hover{opacity:1}',
      '.bar{display:none;align-items:center;gap:6px;padding:6px;border-radius:999px;background:rgba(10,16,13,.94);border:1px solid rgba(255,255,255,.16);box-shadow:0 10px 40px rgba(0,0,0,.55);max-width:calc(100vw - 24px)}',
      '.bar.open{display:flex}',
      '.bar button{width:32px;height:32px;flex:none;border-radius:50%;border:0;background:rgba(255,255,255,.07);color:#ecfdf3;font-size:15px;cursor:pointer}',
      '.bar button:hover{background:rgba(255,255,255,.18)}',
      '.bar input{width:min(380px,48vw);height:32px;border-radius:999px;border:1px solid rgba(255,255,255,.12);background:rgba(0,0,0,.35);color:#ecfdf3;padding:0 14px;font-size:13px;outline:0}',
      '.bar input:focus{border-color:#4ade80}',
      '</style>',
      '<button class="pill" id="p" title="Browser bar">&#9776;</button>',
      '<div class="bar" id="b">',
      '<button id="h" title="Home">&#8962;</button><button id="bk" title="Back">&larr;</button>',
      '<button id="fw" title="Forward">&rarr;</button><button id="rl" title="Reload">&#10227;</button>',
      '<input id="u" spellcheck="false" autocomplete="off" placeholder="Search or enter address">',
      '<button id="go" title="Go">&#10140;</button><button id="x" title="Hide">&times;</button>',
      '</div>'
    ].join('');
    var $ = function (s) { return root.querySelector(s); };
    var bar = $('#b'), pill = $('#p'), input = $('#u'), timer = null;

    function sync() { if (root.activeElement !== input) input.value = realUrl(); }
    function open(on) {
      bar.classList.toggle('open', on);
      pill.style.display = on ? 'none' : 'block';
      save('bb_toolbar_open', on);
      clearInterval(timer);
      if (on) { sync(); timer = setInterval(sync, 1000); }
    }
    function go() {
      var u = normalize(input.value);
      if (u) location.href = '/proxy/' + u;
    }
    pill.onclick = function () { open(true); };
    $('#x').onclick = function () { open(false); };
    $('#h').onclick = function () { location.href = '/'; };
    $('#bk').onclick = function () { history.back(); };
    $('#fw').onclick = function () { history.forward(); };
    $('#rl').onclick = function () { location.reload(); };
    $('#go').onclick = go;
    input.addEventListener('keydown', function (e) { e.stopPropagation(); if (e.key === 'Enter') go(); });
    input.addEventListener('focus', function () { input.select(); });
    ['keyup', 'keypress'].forEach(function (n) { input.addEventListener(n, function (e) { e.stopPropagation(); }); });

    (document.documentElement || document.body).appendChild(host);
    open(load('bb_toolbar_open', false) === true);
  }

  window.__bbTools = { PRESETS: PRESETS, applyCloak: applyCloak, normalize: normalize, realUrl: realUrl, handleKey: handleKey, isCalcOpen: function () { return calc.open; } };

  function start() {
    try { applyCloak(null); } catch (e) {}
    try { buildBar(); } catch (e) { console.error('[bb-tools]', e); }
  }
  if (window.__bbHome) { /* the homepage calls applyCloak itself */ }
  else if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', start);
  else start();
})();
`;

/* ------------------------------------------------------------------ */
/* v5.0: styled login page, 30-day sign-in cookie, web app manifest,   */
/* and the client toolkit (browser bar, tab cloak, panic key)           */
/* ------------------------------------------------------------------ */

app.get('/manifest.webmanifest', (req, res) => {
  res.type('application/manifest+json').set('Cache-Control', 'no-cache').send(JSON.stringify({
    name: TAB_TITLE, short_name: TAB_TITLE, start_url: '/', scope: '/', display: 'standalone',
    background_color: '#050807', theme_color: '#050807',
    icons: [{
      src: 'data:image/svg+xml,' + encodeURIComponent('<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32"><rect width="32" height="32" rx="9" fill="#22c55e"/></svg>'),
      sizes: 'any', type: 'image/svg+xml', purpose: 'any',
    }],
  }));
});

app.get('/bb-tools.js', (req, res) => {
  res.type('application/javascript').set('Cache-Control', 'no-cache').send(BB_TOOLS_JS);
});

app.get('/api/info', (req, res) => {
  res.set('Cache-Control', 'no-store').json({
    version: VERSION,
    uptime: process.uptime(),
    upstreamProxy: UPSTREAM_PROXY ? 'on' : 'off',
    cleanMode: CLEAN_MODE,
    sessions: jars.size,
    node: process.version,
  });
});


// Give each browser its own private id (used for its cookie jar, never shared)
app.use((req, res, next) => {
  if (!sidOf(req)) {
    res.append('Set-Cookie', 'bb_sid=' + crypto.randomBytes(16).toString('hex') +
      '; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=2592000');
  }
  next();
});

app.get('/favicon.ico', (req, res) => res.status(204).end());

// Open /__blocks in a new tab after a video fails: shows what this browser's cookie jar
// holds (names only) and the last requests a site refused. Handy for debugging.
app.get('/__blocks', (req, res) => {
  const j = jarFor(req, false);
  const jarLines = j && j.size
    ? [...j].map(([site, m]) => '  ' + site + ': ' + ([...m.keys()].join(', ') || '(none)'))
    : ['  (empty)'];
  // /__blocks?status=403 shows only that status
  const want = String(req.query.status || '').replace(/\D/g, '');
  const shown = want ? recentBlocks.filter((l) => l.indexOf('[' + want + ']') >= 0) : recentBlocks;
  res.type('text/plain').set('Cache-Control', 'no-store').send(
    'v' + VERSION + '\nupstream proxy: ' + (UPSTREAM_PROXY ? 'on' : 'off') +
    '\n\nCookie jar for this browser (names only):\n' + jarLines.join('\n') +
    '\n\nRecent failed requests, status 400+ (newest last, up to 100):\n' +
    (shown.length ? shown.join('\n') : '  (none yet)') + '\n');
});

// /__html?from=80&to=95 shows those lines of the last page sent to the browser, so a script
// error such as "line 87, column 49" in the console can be matched to the real text.
app.get('/__html', (req, res) => {
  if (!lastHtml) return res.type('text/plain').send('No page captured yet. Load a site first.\n');
  const from = Math.max(1, parseInt(req.query.from, 10) || 1);
  const to = Math.min(from + 200, parseInt(req.query.to, 10) || from + 20);
  const lines = Buffer.from(lastHtml.html, 'latin1').toString('utf8').split('\n');
  const out = [];
  for (let i = from; i <= Math.min(to, lines.length); i++) out.push(i + ': ' + lines[i - 1].slice(0, 600));
  res.type('text/plain').set('Cache-Control', 'no-store')
    .send(lastHtml.url + '\n(' + lines.length + ' lines)\n\n' + out.join('\n') + '\n');
});

// Serve the patched browser script instead of unblocker's original
app.get('/proxy/client/unblocker-client.js', (req, res, next) => {
  if (!PATCHED_CLIENT) return next();
  res.type('application/javascript').set('Cache-Control', 'no-cache').send(PATCHED_CLIENT);
});

// Make the app treat requests as https so generated URLs aren't http://
app.use((req, res, next) => {
  if (req.headers['x-forwarded-proto'] === 'https') req.socket.encrypted = true;
  next();
});

// Google One Tap / sign-in widgets check the page address against an allow-list, so they can
// never work from a proxy and only fill the console with errors. Answer them with an empty
// script instead (set BLOCK_NOISE=0 to turn this off).
const NOISE_RE = /^\/proxy\/https?:\/\/accounts\.google\.com\/gsi\//i;
app.use((req, res, next) => {
  if (process.env.BLOCK_NOISE === '0' || !NOISE_RE.test(req.url)) return next();
  if (req.headers['sec-fetch-dest'] === 'iframe') return res.type('html').send('<!doctype html><title></title>');
  res.type('application/javascript').set('Cache-Control', 'no-store')
    .send('/* Google sign-in cannot work through a proxy */');
});

// CrazyGames loads games as /proxy/https://www.site/path?__proxy_cookies_to=<real game URL>.
// Follow that parameter so the game page is fetched from the host it names.
app.use((req, res, next) => {
  try {
    if (req.method !== 'GET' || !req.url.startsWith('/proxy/') || isClientAsset(req.url)) return next();
    if (req.url.indexOf('__proxy_cookies_to=') < 0) return next();
    const to = new URL(req.url, 'http://x').searchParams.get('__proxy_cookies_to');
    if (to && /^https?:\/\//i.test(to)) return res.redirect(307, '/proxy/' + to);
  } catch (e) { /* fall through to normal handling */ }
  next();
});

// Refuse invalid targets, private/internal hosts, and loops
app.use(async (req, res, next) => {
  try {
    if (!req.url.startsWith('/proxy/') || isClientAsset(req.url)) return next();
    const target = parseTarget(req.url);
    if (!target) {
      return res.status(400).send(errorPage(400, 'Invalid address', 'That address could not be understood. Use a full link like https://example.com.'));
    }
    const reason = await checkTarget(target, req);
    if (reason) return res.status(403).send(errorPage(403, 'Blocked', reason));
    next();
  } catch (err) {
    next(err);
  }
});

/* ------------------------------------------------------------------ */
/* HTML post-processing on the final bytes sent to the browser          */
/*  - removes integrity="..." (rewritten files never match the hash)    */
/*  - removes CSP and referrer <meta> tags                              */
/*  - marks pages for the address-bar path cleanup                      */
/*  - injects the browser bar / tab cloak / panic key (v5.0)            */
/*  - remembers the last site (cookie) so refreshes and root-relative   */
/*    requests that lost their context can still be routed              */
/*  - adds a notice when a Cloudflare bot check blocks the page         */
/* ------------------------------------------------------------------ */

const INTEGRITY_RE = /\s+integrity\s*=\s*("[^"]*"|'[^']*')/gi;
const META_CSP_RE = /<meta[^>]+http-equiv\s*=\s*["']?content-security-policy["']?[^>]*>/gi;
const META_REFERRER_RE = /<meta[^>]+name\s*=\s*["']?referrer["']?[^>]*>/gi;
const SPA_RE = /__NEXT_DATA__|id=["']__next["']|window\.__NUXT__|id=["']__nuxt["']/i;
const HEAD_OPEN_RE = /<head(\s[^>]*)?>/i;
const CLEAN_META = '<meta name="bb-clean-paths" content="1">';

// node-unblocker rewrites an unquoted attribute value (href=https://x.com>) up to the next
// space, so the value swallows characters after the address (">", "<", a closing backtick in
// a script) and percent-encodes them. That breaks the page: a template literal never ends, or
// an <a> tag swallows the next tag. Put the swallowed characters back.
// (The page is held as latin1 text, so text that was decoded as Unicode is converted back.)
const MANGLED_RE = /(=\s*)\/proxy\/(https?:\/\/[^\s"'<>%?]*)((?:%3E|%3C|%60)[^\s"'<>?]*)(\?__proxy_cookies_to=([^\s"'<>]*))?/gi;
const toBin = (str) => Buffer.from(str, 'utf8').toString('latin1');
function repairMangledUrls(html) {
  return html.replace(MANGLED_RE, (m, eq, head, tail, ck, enc) => {
    let url = head;
    let rest;
    try { rest = decodeURIComponent(tail); } catch (e) { return m; }
    if (enc) {
      try {
        const orig = decodeURIComponent(enc);
        const i = orig.search(/[<>`]/);
        if (/^https?:\/\//i.test(orig) && i > 0) { url = orig.slice(0, i); rest = orig.slice(i); }
      } catch (e) { /* keep the guess from the path */ }
    }
    return eq + '/proxy/' + toBin(url) + toBin(rest);
  });
}

// The last page that was sent to the browser, for /__html (debugging)
let lastHtml = null;
const TOOLS_TAG = '<script src="/bb-tools.js" defer></script>';
// Frames (games, videos) only pass key presses up to the main page, so the calculator and panic keys work inside them
const FRAME_TAG = '<script>window.__bbFrame=1</script>' + TOOLS_TAG;
const CF_BANNER =
  '<div style="position:fixed;z-index:2147483647;left:12px;right:12px;bottom:12px;padding:14px 44px 14px 16px;' +
  'border-radius:14px;background:#0b1d12;color:#ecfdf3;border:1px solid #22c55e;font:14px/1.5 system-ui,sans-serif;' +
  'box-shadow:0 10px 40px rgba(0,0,0,.5)">This site is showing a Cloudflare bot check, which can\'t finish through a ' +
  'web proxy. Try opening the site directly in your browser instead.' +
  '<button onclick="this.parentNode.remove()" style="position:absolute;top:8px;right:10px;background:none;border:0;' +
  'color:#bbb;font-size:20px;cursor:pointer">&times;</button></div>';

// Should this page get the address-bar path cleanup?
function shouldCleanPaths(html, target, isDoc) {
  if (!isDoc || !target) return false;                       // top-level pages only, not iframes or fetches
  if (CLEAN_MODE === '0' || CLEAN_MODE === 'off') return false;
  const host = target.hostname.toLowerCase();
  if (CLEAN_EXCLUDE.some((d) => host === d || host.endsWith('.' + d))) return false;
  return CLEAN_MODE === 'spa' ? SPA_RE.test(html) : true;
}

app.use((req, res, next) => {
  if (!req.url.startsWith('/proxy/') || isClientAsset(req.url)) return next();

  const docTarget = parseTarget(req.url);
  const dest = req.headers['sec-fetch-dest'];
  const isDoc = dest === 'document' || (!dest && /text\/html/i.test(String(req.headers.accept || '')));

  const origWriteHead = res.writeHead;
  const origWrite = res.write;
  const origEnd = res.end;
  const chunks = [];
  let decided = false;
  let buffering = false;
  let challenged = false;

  function addLastSiteCookie(hdrs) {
    // Not HttpOnly on purpose: the page's own script re-stamps it when the tab is shown again
    const cookie = 'bb_last=' + encodeURIComponent(docTarget.origin) +
      '; Path=/; Max-Age=3600; Secure; SameSite=Lax';
    if (hdrs && typeof hdrs === 'object' && !Array.isArray(hdrs)) {
      hdrs['set-cookie'] = [].concat(hdrs['set-cookie'] || [], cookie);
    } else {
      res.setHeader('Set-Cookie', [].concat(res.getHeader('set-cookie') || [], cookie));
    }
  }

  function decide(code, hdrs) {
    decided = true;
    const find = (name) => {
      if (hdrs && typeof hdrs === 'object' && !Array.isArray(hdrs)) {
        for (const k of Object.keys(hdrs)) if (k.toLowerCase() === name) return hdrs[k];
      }
      return res.getHeader(name);
    };
    const ct = String(find('content-type') || '');
    if (/text\/html/i.test(ct) && !find('content-encoding')) {
      buffering = true;
      challenged =
        !!find('cf-mitigated') ||
        ([403, 429, 503].includes(code) && /cloudflare/i.test(String(find('server') || '')));
      if (isDoc && docTarget && code < 400) addLastSiteCookie(hdrs);
      if (hdrs && typeof hdrs === 'object' && !Array.isArray(hdrs)) {
        for (const k of Object.keys(hdrs)) if (k.toLowerCase() === 'content-length') delete hdrs[k];
      }
      res.removeHeader('content-length');
    }
  }

  res.writeHead = function (code, reason, headers) {
    decide(code, typeof reason === 'string' ? headers : reason);
    return origWriteHead.apply(res, arguments);
  };

  res.write = function (chunk, encoding, cb) {
    if (!decided) decide(res.statusCode, null);
    if (!buffering) return origWrite.apply(res, arguments);
    if (chunk) {
      chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk, typeof encoding === 'string' ? encoding : 'utf8'));
    }
    const done = typeof encoding === 'function' ? encoding : cb;
    if (typeof done === 'function') done();
    return true;
  };

  res.end = function (chunk, encoding, cb) {
    if (!decided) decide(res.statusCode, null);
    if (!buffering) return origEnd.apply(res, arguments);
    buffering = false;
    if (chunk && typeof chunk !== 'function') {
      chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk, typeof encoding === 'string' ? encoding : 'utf8'));
    }
    // latin1 round-trips every byte unchanged, so non-UTF-8 pages are not corrupted
    const raw = Buffer.concat(chunks).toString('latin1');
    if (DEBUG) {
      console.log('[html] ' + req.url.slice(0, 90) + ' integrity attrs: ' + (raw.match(INTEGRITY_RE) || []).length);
    }
    let html = raw.replace(INTEGRITY_RE, '').replace(META_CSP_RE, '').replace(META_REFERRER_RE, '');
    html = repairMangledUrls(html);
    if (!challenged && shouldCleanPaths(html, docTarget, isDoc)) {
      html = html.replace(HEAD_OPEN_RE, (m) => m + CLEAN_META);
    }
    // Browser bar, tab cloak and panic key on top-level pages
    if (isDoc && docTarget && html.indexOf(TOOLS_TAG) < 0) {
      html = html.replace(HEAD_OPEN_RE, (m) => m + TOOLS_TAG);
    } else if (dest === 'iframe' && docTarget && html.indexOf(TOOLS_TAG) < 0) {
      html = html.replace(HEAD_OPEN_RE, (m) => m + FRAME_TAG);
    }
    if (challenged) {
      html = /<\/body>/i.test(html)
        ? html.replace(/<\/body>/i, () => CF_BANNER + '</body>')
        : html + CF_BANNER;
    }
    if (isDoc && docTarget && html.length < 3000000) lastHtml = { url: req.url.slice(0, 200), html };
    const done = [chunk, encoding, cb].find((a) => typeof a === 'function');
    return origEnd.call(res, Buffer.from(html, 'latin1'), done);
  };

  next();
});

/* ------------------------------------------------------------------ */
/* The proxy                                                           */
/* ------------------------------------------------------------------ */

// Never forward these to the sites you visit. "authorization" matters most:
// the browser attaches your proxy login to every request, so without this the
// proxy password would be sent to every site.
const STRIP_REQUEST_HEADERS = [
  'authorization', 'x-forwarded-for', 'x-forwarded-proto', 'x-forwarded-host', 'x-forwarded-port',
  'forwarded', 'x-real-ip', 'via', 'true-client-ip', 'cf-connecting-ip', 'cf-ipcountry', 'cf-ray',
  'cf-visitor', 'x-request-id', 'rndr-id', 'render-proxy-ttl', 'x-render-routing',
];

// "referrer-policy" is removed because unblocker needs the full Referer to
// route root-relative requests (like /images/bg.jpg) back to the right site.
const STRIP_RESPONSE_HEADERS = [
  'content-security-policy', 'content-security-policy-report-only', 'x-frame-options',
  'cross-origin-opener-policy', 'cross-origin-embedder-policy', 'cross-origin-resource-policy',
  'permissions-policy', 'report-to', 'nel', 'origin-agent-cluster', 'referrer-policy',
];

// Make sure the site you are visiting sees a Referer/Origin that looks like its own,
// not the proxy's address. Pages with a cleaned address bar (/en/games) send a Referer
// that points at the proxy itself, so it is mapped back to the last site you browsed.
function fixReferer(data) {
  try {
    const cr = data.clientRequest;
    if (!cr || !cr.headers) return;
    const proxyHost = String(cr.headers.host || '').toLowerCase();
    const ref = data.headers.referer;
    let site = null;

    if (ref) {
      const r = new URL(ref);
      if (r.host.toLowerCase() === proxyHost) {
        if (r.pathname.indexOf('/proxy/') === 0) {
          site = new URL(r.pathname.slice('/proxy/'.length) + r.search);
        } else {
          const o = lastOrigin(cr);
          site = o ? new URL(r.pathname + r.search, o) : null;
        }
        if (site) data.headers.referer = site.href;
        else delete data.headers.referer;
      } else {
        site = r;
      }
    } else if (cr.headers['sec-fetch-dest'] !== 'document') {
      const o = lastOrigin(cr);
      if (o) {
        site = new URL(o + '/');
        data.headers.referer = site.href;
      }
    }

    if (site && data.headers.origin) data.headers.origin = site.origin;
  } catch (e) { /* leave headers as they are */ }
}

/* ------------------------------------------------------------------ */
/* Cookie jar (v3.3)                                                   */
/*                                                                     */
/* node-unblocker keeps cookies per host, so cookies that www.site.com  */
/* sets never reach cdn.site.com. Sites like TikTok need them there     */
/* (the video link says tk=tt_chain_token) and answer 403 without.      */
/* This jar remembers cookies per site (all subdomains together) and    */
/* adds them to requests, like a real browser would. Each browser gets  */
/* its own private jar (random bb_sid cookie); nothing is shared.       */
/*                                                                     */
/* v4.1: cookies from unrelated trackers/sites are no longer sent to    */
/* TikTok (all proxied sites share one browser origin, so the browser   */
/* would otherwise send everything everywhere).                         */
/* ------------------------------------------------------------------ */

// "v16-webapp-prime.us.tiktok.com" -> "tiktok.com", "a.b.example.co.uk" -> "example.co.uk"
function siteKey(host) {
  if (net.isIP(host)) return host;
  const parts = host.split('.');
  if (parts.length <= 2) return host;
  const second = parts[parts.length - 2];
  const shortSecond = second.length <= 3 && parts[parts.length - 1].length === 2;
  return parts.slice(shortSecond ? -3 : -2).join('.');
}

// Cookies a real TikTok session would never carry (ad-tech, analytics, other sites)
const FOREIGN_COOKIE_RE =
  /^(_ga|_gcl|_gid|_fbp|_iiq|_li_|_lc2|_lr_|33across|cto_|pbjs|panorama|_cc_id|_czyId|enwiki|perf_feed_cache)/i;
const TIKTOK_SITES = new Set(['tiktok.com', 'tiktokcdn.com', 'tiktokcdn-us.com', 'tiktokw.us', 'ttwstatic.com', 'byteoversea.com']);

const jars = new Map(); // session id -> Map(siteKey -> Map(cookie name -> value))
const MAX_SESSIONS = 50;

function sidOf(req) {
  const m = /(?:^|;\s*)bb_sid=([a-f0-9]{32})/.exec((req && req.headers && req.headers.cookie) || '');
  return m ? m[1] : null;
}

// Least-recently-used eviction: a session that is still in use is never the one dropped
function jarFor(req, create) {
  const sid = sidOf(req);
  if (!sid) return null;
  let j = jars.get(sid);
  if (j) {
    jars.delete(sid);
    jars.set(sid, j);
    return j;
  }
  if (!create) return null;
  if (jars.size >= MAX_SESSIONS) jars.delete(jars.keys().next().value);
  j = new Map();
  jars.set(sid, j);
  return j;
}

function targetHost(data) {
  try { return new URL(String(data.url)).hostname.toLowerCase(); } catch (e) { return null; }
}

function storeCookies(data) {
  const host = targetHost(data);
  const list = [].concat((data.headers && data.headers['set-cookie']) || []);
  if (!host || !list.length) return;
  const j = jarFor(data.clientRequest, true);
  if (!j) return;
  const key = siteKey(host);
  let m = j.get(key);
  if (!m) {
    if (j.size >= 100) j.clear();
    m = new Map();
    j.set(key, m);
  }
  for (const c of list) {
    const parts = String(c).split(';');
    const eq = parts[0].indexOf('=');
    if (eq < 1) continue;
    const name = parts[0].slice(0, eq).trim();
    if (name.indexOf('bb_') === 0) continue; // the proxy's own cookies stay out of the jar
    const value = parts[0].slice(eq + 1).trim();
    const attrs = parts.slice(1).join(';');
    const maxAge = /max-age\s*=\s*(-?\d+)/i.exec(attrs);
    const exp = /expires\s*=\s*([^;]+)/i.exec(attrs);
    const expired = (maxAge && Number(maxAge[1]) <= 0) || (!maxAge && exp && Date.parse(exp[1]) < Date.now());
    if (expired) m.delete(name);
    else if (m.size < 150 || m.has(name)) m.set(name, value);
  }
}

function attachJarCookies(data) {
  const host = targetHost(data);
  const j = host && jarFor(data.clientRequest, false);
  const m = j && j.get(siteKey(host));
  if (!m || !m.size) return;
  const existing = String(data.headers.cookie || '');
  const have = new Set(existing.split(/;\s*/).map((c) => c.split('=')[0]));
  const add = [];
  for (const [name, value] of m) if (!have.has(name)) add.push(name + '=' + value);
  if (add.length) data.headers.cookie = [existing].concat(add).filter(Boolean).join('; ');
}

// Last step before a request leaves: drop the proxy's own cookies, repeated names,
// and (for TikTok hosts) cookies that belong to other sites or ad trackers
function cleanCookieHeader(data) {
  if (!data.headers.cookie) return;
  const host = targetHost(data) || '';
  const isTikTok = TIKTOK_SITES.has(siteKey(host));
  const seen = new Set();
  const kept = [];
  for (const c of String(data.headers.cookie).split(/;\s*/)) {
    const name = c.split('=')[0];
    if (!c || name.indexOf('bb_') === 0 || seen.has(name)) continue;
    if (isTikTok && FOREIGN_COOKIE_RE.test(name)) continue;
    seen.add(name);
    kept.push(c);
  }
  if (kept.length) data.headers.cookie = kept.join('; ');
  else delete data.headers.cookie;
}

// What we sent, remembered so a blocked response can be explained (names only, never values)
function noteRequest(data) {
  if (!data.clientRequest) return;
  data.clientRequest._bbReq = {
    dest: data.headers['sec-fetch-dest'] || '-',
    referer: data.headers.referer || '-',
    origin: data.headers.origin || '-',
    cookies: String(data.headers.cookie || '').split(/;\s*/).filter(Boolean).map((c) => c.split('=')[0]),
  };
}

// Logs why a site refused a request. The last 100 are also shown at /__blocks.
const recentBlocks = [];
let blockLogs = 0;
let blockLogReset = Date.now();
function logUpstreamBlock(data, status) {
  const r = (data.clientRequest && data.clientRequest._bbReq) || {};
  const rh = (data.remoteResponse && data.remoteResponse.headers) || {};
  const line = new Date().toISOString().slice(11, 19) + ' [' + status + '] ' + String(data.url).slice(0, 130) +
    '\n    sent: dest=' + r.dest + ' referer=' + r.referer + ' origin=' + r.origin +
    ' cookies=[' + (r.cookies || []).join(',') + ']' +
    '\n    got:  server=' + (rh.server || '-') + ' via=' + (rh.via || '-') + ' x-tt-logid=' + (rh['x-tt-logid'] || '-');
  recentBlocks.push(line);
  if (recentBlocks.length > 100) recentBlocks.shift();
  const now = Date.now();
  if (now - blockLogReset > 60000) { blockLogs = 0; blockLogReset = now; }
  if (blockLogs++ < 20) console.log('[upstream] ' + line);
}

const unblocker = new Unblocker({
  prefix: '/proxy/',
  requestMiddleware: [
    (data) => {
      STRIP_REQUEST_HEADERS.forEach((h) => delete data.headers[h]);
      // Ask for uncompressed content so pages can be rewritten safely.
      // Media (video/audio, or anything using Range) is never rewritten, so leave that
      // request exactly as the browser made it.
      const dest = data.headers['sec-fetch-dest'];
      const isMedia = dest === 'video' || dest === 'audio' || !!data.headers.range;
      if (!isMedia) data.headers['accept-encoding'] = 'identity';
      fixReferer(data);
      // From the site's point of view the page and its media are on the same site, not "same-origin" with a proxy
      // Sec-Fetch-Site would say "same-origin" (the proxy). Recompute it from the real
      // page and target so CDNs that cross-check it against Origin/Referer see the truth.
      if (data.headers['sec-fetch-site'] && data.headers.referer) {
        try {
          const ref = new URL(data.headers.referer);
          const tgt = new URL(String(data.url));
          data.headers['sec-fetch-site'] = ref.origin === tgt.origin ? 'same-origin'
            : siteKey(ref.hostname) === siteKey(tgt.hostname) ? 'same-site' : 'cross-site';
        } catch (e) {
          if (data.headers['sec-fetch-site'] === 'same-origin') data.headers['sec-fetch-site'] = 'same-site';
        }
      }
      // Our own cookies (last site, session id, sign-in) are not for the sites you visit
      if (data.headers.cookie) {
        const kept = String(data.headers.cookie).split(/;\s*/).filter((c) =>
          c && !c.startsWith('bb_last=') && !c.startsWith('bb_sid=') && !c.startsWith('bb_auth='));
        if (kept.length) data.headers.cookie = kept.join('; ');
        else delete data.headers.cookie;
      }
      attachJarCookies(data);
      cleanCookieHeader(data);
      noteRequest(data);
    },
  ],
  responseMiddleware: [
    (data) => {
      const h = data.headers;
      storeCookies(data);
      const sc = data.remoteResponse && data.remoteResponse.statusCode;
      if (sc >= 400) logUpstreamBlock(data, sc);
      STRIP_RESPONSE_HEADERS.forEach((name) => delete h[name]);

      // Cookies must be Secure because the proxy is served over https, and a cookie
      // that names the real site's domain is rejected by the browser, so drop Domain.
      if (h['set-cookie']) {
        h['set-cookie'] = [].concat(h['set-cookie']).map((c) => {
          let out = String(c).replace(/;\s*domain\s*=[^;]*/ig, '');
          if (!/;\s*Secure/i.test(out)) out += '; Secure';
          return out;
        });
      }
    },
  ],
});

// Add this browser's saved cookies for the target site before unblocker sees the request
app.use((req, res, next) => {
  try {
    if (req.url.startsWith('/proxy/') && !isClientAsset(req.url)) {
      const target = parseTarget(req.url);
      const j = target && jarFor(req, false);
      const m = j && j.get(siteKey(target.hostname.toLowerCase()));
      if (m && m.size) {
        const existing = String(req.headers.cookie || '');
        const have = new Set(existing.split(/;\s*/).map((c) => c.split('=')[0]));
        const add = [];
        for (const [name, value] of m) if (!have.has(name)) add.push(name + '=' + value);
        if (add.length) req.headers.cookie = [existing].concat(add).filter(Boolean).join('; ');
      }
    }
  } catch (e) { /* carry on without the extra cookies */ }
  next();
});

app.use(unblocker);

/* ------------------------------------------------------------------ */
/* Routes, errors, server                                              */
/* ------------------------------------------------------------------ */


// Homepage. A refresh of "/" while a site is current means the site's own front
// page (its cleaned path is "/"), so send that back to the site.
app.get('/', (req, res) => {
  if (isReload(req)) {
    const origin = lastOrigin(req);
    if (origin) return res.redirect(307, '/proxy/' + origin + req.originalUrl);
  }
  res.type('html').set('Cache-Control', 'no-store').send(HOME_HTML);
});

// A request for something like /images/bg.jpg that lost its proxy context
// (for example from a page whose address was cleaned): send it to the site
// you were last browsing.
app.use((req, res, next) => {
  if (req.method !== 'GET' && req.method !== 'HEAD') return next();
  if (req.url.startsWith('/proxy/')) return next();
  const origin = lastOrigin(req);
  if (!origin) return next();
  res.redirect(307, '/proxy/' + origin + req.originalUrl);
});

app.use((req, res) => {
  res.status(404).send(errorPage(404, 'Page not found', "That page doesn't exist."));
});

app.use((err, req, res, next) => { // eslint-disable-line no-unused-vars
  console.error('Request error:', err && err.message);
  if (res.headersSent) return res.end();
  res.status(500).send(errorPage(500, 'Something went wrong', 'The proxy hit an error. Try again, or try a different site.'));
});

const server = app.listen(PORT, () => {
  console.log('Server running on port ' + PORT + ' (v' + VERSION + ', path cleanup: ' + CLEAN_MODE + ')');
});

// Render's load balancer holds connections ~60s; keep ours longer to avoid random 502s
server.keepAliveTimeout = 65 * 1000;
server.headersTimeout = 66 * 1000;

// WebSocket upgrades skip Express middleware, so check login and target here
server.on('upgrade', async (req, socket, head) => {
  socket.on('error', () => {});
  try {
    if (!isAuthed(req)) {
      socket.end('HTTP/1.1 401 Unauthorized\r\nConnection: close\r\n\r\n');
      return;
    }
    if (req.url.startsWith('/proxy/') && !isClientAsset(req.url)) {
      const target = parseTarget(req.url);
      if (!target || (await checkTarget(target, req))) {
        socket.end('HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n');
        return;
      }
    }
    unblocker.onUpgrade(req, socket, head);
  } catch (e) {
    socket.destroy();
  }
});

// Optional: keep the free Render instance from sleeping (set KEEP_AWAKE=1)
if (KEEP_AWAKE && process.env.RENDER_EXTERNAL_URL) {
  setInterval(() => {
    fetch(process.env.RENDER_EXTERNAL_URL + '/healthz').catch(() => {});
  }, 10 * 60 * 1000);
}

// Render sends SIGTERM on deploys; finish up cleanly
function shutdown() {
  console.log('Shutting down');
  server.close(() => process.exit(0));
  setTimeout(() => process.exit(0), 10000).unref();
}
process.on('SIGTERM', shutdown);
process.on('SIGINT', shutdown);

// A bad upstream response shouldn't take the whole proxy down
process.on('unhandledRejection', (e) => console.error('Unhandled rejection:', e));
process.on('uncaughtException', (e) => console.error('Uncaught exception:', e));
