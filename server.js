/**
 * GazeMap Proxy Server
 * Strips X-Frame-Options + CSP frame-ancestors so any site can be iframed.
 * Rewrites relative URLs so sub-resources load through the proxy.
 * Run: node server.js
 * PORT defaults to 3000, set PORT env var to override.
 */

const http     = require('http');
const https    = require('https');
const url      = require('url');
const path     = require('path');
const fs       = require('fs');
const zlib     = require('zlib');

const PORT = process.env.PORT || 3000;

// Blocked headers we strip from upstream responses
const STRIP_RESPONSE_HEADERS = [
  'x-frame-options',
  'content-security-policy',
  'content-security-policy-report-only',
  'x-content-type-options',
  'strict-transport-security', // don't forward HSTS to our proxy
];

// Blocked headers we strip from forwarded requests (don't leak proxy host)
const STRIP_REQUEST_HEADERS = [
  'host',
  'origin',
  'referer',
];

// ── Static file map (serve the frontend) ────────────────────────────────────
const STATIC_DIR = path.join(__dirname, 'public');
const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.js':   'application/javascript',
  '.css':  'text/css',
  '.png':  'image/png',
  '.ico':  'image/x-icon',
};

function serveStatic(res, filePath) {
  const ext  = path.extname(filePath);
  const mime = MIME[ext] || 'application/octet-stream';
  try {
    const data = fs.readFileSync(filePath);
    res.writeHead(200, {
      'Content-Type': mime,
      'Cache-Control': 'no-cache',
      'Cross-Origin-Opener-Policy':   'same-origin',
      'Cross-Origin-Embedder-Policy': 'require-corp',
    });
    res.end(data);
  } catch {
    res.writeHead(404);
    res.end('Not found');
  }
}

// ── URL rewriting ─────────────────────────────────────────────────────────
/**
 * Rewrite all relative and absolute resource URLs in HTML/CSS/JS
 * so they load through our proxy.
 * proxyBase = 'http://yourserver.com'  (no trailing slash)
 * targetBase = 'https://example.com'  (scheme+host of the target page)
 */
function rewriteUrls(text, proxyBase, targetBase) {
  const targetUrl = new URL(targetBase);

  function makeProxied(rawUrl) {
    let abs;
    try {
      abs = new URL(rawUrl, targetBase).href;
    } catch {
      return rawUrl; // can't parse, leave alone
    }
    return `${proxyBase}/proxy?url=${encodeURIComponent(abs)}`;
  }

  // href="..." src="..." action="..." srcset (basic)
  text = text.replace(
    /(href|src|action|srcset|data-src)\s*=\s*["']([^"']+)["']/gi,
    (match, attr, val) => {
      // skip data URIs, anchors, mailto, javascript
      if (/^(data:|#|javascript:|mailto:)/i.test(val)) return match;
      // skip already proxied
      if (val.includes('/proxy?url=')) return match;
      return `${attr}="${makeProxied(val)}"`;
    }
  );

  // CSS url(...)
  text = text.replace(
    /url\(\s*['"]?([^)'"]+)['"]?\s*\)/gi,
    (match, val) => {
      if (/^(data:|#)/i.test(val)) return match;
      if (val.includes('/proxy?url=')) return match;
      return `url("${makeProxied(val)}")`;
    }
  );

  return text;
}

// Inject a small script into proxied HTML that:
// 1. Fixes form actions to use proxy
// 2. Intercepts navigation (window.location changes) to stay in proxy
// 3. Sends scroll height up to parent via postMessage
const INJECT_SCRIPT = `
<script>
(function(){
  // ── FRAME-BUSTER NEUTRALIZER ──────────────────────────────────────────
  // Many sites detect they're inside an iframe with: if(window !== window.top)
  // and then do window.top.location = window.location to "break out".
  // We freeze window.top so that assignment silently does nothing.
  // Source: community solution from niutech/x-frame-bypass & Win7Simu research
  try {
    Object.defineProperty(window, 'top',    { get: function(){ return window; } });
    Object.defineProperty(window, 'parent', { get: function(){ return window; } });
    Object.defineProperty(window, 'frameElement', { get: function(){ return null; } });
  } catch(e){}

  // Also intercept location reassignment attempts
  var _loc = window.location;
  try {
    Object.defineProperty(window, 'location', {
      get: function(){ return _loc; },
      set: function(v){
        // Redirect through proxy instead of breaking out
        try {
          var abs = new URL(String(v), _loc.href).href;
          _loc.replace('/proxy?url=' + encodeURIComponent(abs));
        } catch(e){ _loc.replace(v); }
      }
    });
  } catch(e){}

  // ── KEEP NAVIGATION IN PROXY ──────────────────────────────────────────
  var _open = window.open;
  window.open = function(u){ return _open('/proxy?url='+encodeURIComponent(new URL(String(u),location.href).href)); };

  // Intercept link clicks so navigation stays proxied
  document.addEventListener('click', function(e){
    var a = e.target.closest('a[href]');
    if(!a) return;
    var href = a.getAttribute('href');
    if(!href || /^(#|javascript:|mailto:|tel:)/i.test(href)) return;
    if(href.includes('/proxy?url=')) return;
    e.preventDefault();
    try {
      var abs = new URL(href, location.href).href;
      location.href = '/proxy?url=' + encodeURIComponent(abs);
    } catch(err){}
  }, true);

  // ── REPORT SIZE TO PARENT ─────────────────────────────────────────────
  function reportSize(){
    var h = Math.max(document.body.scrollHeight||0, document.documentElement.scrollHeight||0);
    var w = Math.max(document.body.scrollWidth||0,  document.documentElement.scrollWidth||0);
    try{ window.__gazeParent.postMessage({type:'gazeSize',h:h,w:w},'*'); }catch(e){}
  }
  // Store real parent reference before we override window.parent above
  try { window.__gazeParent = window.__proto__.__proto__.constructor.prototype; } catch(e){}
  window.__gazeParent = (function(){ return this; }).call(null) || self;
  // Use postMessage directly — works even with overridden window.parent
  function postUp(msg){
    try{ top.postMessage(msg,'*'); }catch(e){
      try{ parent.postMessage(msg,'*'); }catch(e2){
        // fallback: use opener
        try{ window.opener && window.opener.postMessage(msg,'*'); }catch(e3){}
      }
    }
  }

  function reportSizeReal(){
    var h = Math.max(document.body.scrollHeight||0, document.documentElement.scrollHeight||0);
    var w = Math.max(document.body.scrollWidth||0,  document.documentElement.scrollWidth||0);
    postUp({type:'gazeSize',h:h,w:w});
  }
  window.addEventListener('load',   reportSizeReal);
  window.addEventListener('resize', reportSizeReal);
  setInterval(reportSizeReal, 1500);

  // ── REPORT SCROLL TO PARENT ───────────────────────────────────────────
  window.addEventListener('scroll', function(){
    postUp({ type:'gazeScroll', x: window.scrollX||0, y: window.scrollY||0 });
  }, {passive:true});

})();
</script>
`;

// ── Proxy handler ─────────────────────────────────────────────────────────
function handleProxy(req, res) {
  const parsed   = url.parse(req.url, true);
  const targetRaw = parsed.query.url;

  if (!targetRaw) {
    res.writeHead(400); res.end('Missing ?url= param'); return;
  }

  let targetUrl;
  try { targetUrl = new URL(targetRaw); } catch {
    res.writeHead(400); res.end('Invalid URL'); return;
  }

  const isHttps = targetUrl.protocol === 'https:';
  const lib     = isHttps ? https : http;

  const forwardHeaders = Object.assign({}, req.headers);
  STRIP_REQUEST_HEADERS.forEach(h => delete forwardHeaders[h]);
  forwardHeaders['host']   = targetUrl.host;
  forwardHeaders['origin'] = targetUrl.origin;

  const options = {
    hostname: targetUrl.hostname,
    port:     targetUrl.port || (isHttps ? 443 : 80),
    path:     targetUrl.pathname + (targetUrl.search || ''),
    method:   req.method,
    headers:  forwardHeaders,
    timeout:  15000,
  };

  const proxyReq = lib.request(options, (proxyRes) => {
    const resHeaders = Object.assign({}, proxyRes.headers);

    // Strip blocking headers
    STRIP_RESPONSE_HEADERS.forEach(h => delete resHeaders[h]);

    // Allow embedding from any origin
    resHeaders['access-control-allow-origin'] = '*';
    resHeaders['x-frame-options']             = 'ALLOWALL'; // force allow
    // Don't let upstream HSTS cause loops
    delete resHeaders['strict-transport-security'];

    const contentType = (resHeaders['content-type'] || '').toLowerCase();
    const isHtml = contentType.includes('text/html');
    const isCss  = contentType.includes('text/css');
    const isJs   = contentType.includes('javascript');
    const needsRewrite = isHtml || isCss || isJs;

    const encoding = resHeaders['content-encoding'];
    const compressed = encoding === 'gzip' || encoding === 'br' || encoding === 'deflate';

    if(!needsRewrite){
      // Pass through binary/other content unchanged
      res.writeHead(proxyRes.statusCode, resHeaders);
      proxyRes.pipe(res);
      return;
    }

    // For text content: decompress → rewrite URLs → recompress (skip recompress for simplicity)
    delete resHeaders['content-encoding']; // we'll send uncompressed
    delete resHeaders['content-length'];   // length will change

    let chunks = [];
    let stream = proxyRes;

    if(compressed){
      if(encoding === 'gzip')    stream = proxyRes.pipe(zlib.createGunzip());
      else if(encoding === 'br') stream = proxyRes.pipe(zlib.createBrotliDecompress());
      else                       stream = proxyRes.pipe(zlib.createInflate());
    }

    stream.on('data', c => chunks.push(c));
    stream.on('end', () => {
      let text = Buffer.concat(chunks).toString('utf8');
      const proxyBase = `${req.headers['x-forwarded-proto'] || (req.socket.encrypted ? 'https' : 'http')}://${req.headers.host}`;
      const targetBase = targetUrl.origin;

      text = rewriteUrls(text, proxyBase, targetBase);

      if(isHtml){
        // Inject our helper script before </head> or at start of body
        if(text.includes('</head>')){
          text = text.replace('</head>', INJECT_SCRIPT + '</head>');
        } else if(text.includes('<body')){
          text = text.replace(/<body([^>]*)>/, `<body$1>${INJECT_SCRIPT}`);
        } else {
          text = INJECT_SCRIPT + text;
        }
      }

      res.writeHead(proxyRes.statusCode, resHeaders);
      res.end(text);
    });
    stream.on('error', () => { res.writeHead(502); res.end('Proxy decompress error'); });
  });

  proxyReq.on('timeout', () => { proxyReq.destroy(); res.writeHead(504); res.end('Timeout'); });
  proxyReq.on('error', (e) => {
    console.error('Proxy error:', e.message);
    res.writeHead(502); res.end('Proxy error: ' + e.message);
  });

  req.pipe(proxyReq);
}

// ── Main HTTP handler ─────────────────────────────────────────────────────
const server = http.createServer((req, res) => {
  // CORS preflight
  if(req.method === 'OPTIONS'){
    res.writeHead(204, {
      'Access-Control-Allow-Origin':  '*',
      'Access-Control-Allow-Methods': 'GET,POST,OPTIONS',
      'Access-Control-Allow-Headers': '*',
    });
    res.end(); return;
  }

  const parsedUrl = url.parse(req.url);
  const pathname  = parsedUrl.pathname;

  if(pathname === '/proxy' || pathname.startsWith('/proxy?')){
    handleProxy(req, res);
    return;
  }

  // Serve static frontend files
  if(pathname === '/' || pathname === '/index.html'){
    serveStatic(res, path.join(STATIC_DIR, 'index.html'));
    return;
  }

  // Other static assets
  const filePath = path.join(STATIC_DIR, pathname.replace(/\.\./g, ''));
  if(fs.existsSync(filePath) && fs.statSync(filePath).isFile()){
    serveStatic(res, filePath);
    return;
  }

  res.writeHead(404); res.end('Not found');
});

server.listen(PORT, () => {
  console.log(`GazeMap server running on http://localhost:${PORT}`);
  console.log(`Proxy endpoint: http://localhost:${PORT}/proxy?url=https://example.com`);
});
