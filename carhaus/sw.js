// Descifra la maqueta en el navegador cuando el cliente ha introducido su código.
'use strict';
var BASE = new URL(self.registration.scope).pathname;
var DB = "doyouwin-maqueta-carhaus";
var VALIDEZ = 24 * 3600 * 1000;
var TIPOS = {html:'text/html; charset=utf-8',css:'text/css; charset=utf-8',js:'text/javascript; charset=utf-8',mjs:'text/javascript; charset=utf-8',json:'application/json',svg:'image/svg+xml',webp:'image/webp',png:'image/png',jpg:'image/jpeg',jpeg:'image/jpeg',avif:'image/avif',gif:'image/gif',ico:'image/x-icon',mp4:'video/mp4',webm:'video/webm',woff2:'font/woff2',woff:'font/woff',ttf:'font/ttf',txt:'text/plain; charset=utf-8',xml:'application/xml',webmanifest:'application/manifest+json'};
var estado = null;

self.addEventListener('install', function () { self.skipWaiting(); });
self.addEventListener('activate', function (e) { e.waitUntil(self.clients.claim()); });
self.addEventListener('message', function () { estado = null; });

function leerRegistro() {
  return new Promise(function (res) {
    var r = indexedDB.open(DB, 1);
    r.onupgradeneeded = function () { r.result.createObjectStore('k'); };
    r.onerror = function () { res(null); };
    r.onsuccess = function () {
      var q = r.result.transaction('k', 'readonly').objectStore('k').get('acceso');
      q.onsuccess = function () { res(q.result || null); };
      q.onerror = function () { res(null); };
    };
  });
}
function borrarRegistro() {
  return new Promise(function (res) {
    var r = indexedDB.open(DB, 1);
    r.onerror = function () { res(); };
    r.onsuccess = function () {
      var t = r.result.transaction('k', 'readwrite'); t.objectStore('k').delete('acceso'); t.oncomplete = function () { res(); };
    };
  });
}
async function descifrar(key, buf) {
  var b = new Uint8Array(buf);
  return crypto.subtle.decrypt({ name: 'AES-GCM', iv: b.slice(0, 12) }, key, b.slice(12));
}
async function cargarEstado() {
  if (estado && Date.now() - estado.ts < VALIDEZ) return estado;
  estado = null;
  var rec = await leerRegistro();
  if (!rec || !rec.key || Date.now() - rec.ts > VALIDEZ) { if (rec) await borrarRegistro(); return null; }
  try {
    var r = await fetch(BASE + '_c/manifest.bin', { cache: 'no-cache' });
    var man = JSON.parse(new TextDecoder().decode(await descifrar(rec.key, await r.arrayBuffer())));
    estado = { key: rec.key, ts: rec.ts, man: man };
  } catch (e) { return null; }
  return estado;
}
function resolver(man, rel) {
  var cand = rel === '' || rel.slice(-1) === '/'
    ? [rel + 'index.html']
    : [rel, rel + '.html', rel + '/index.html'];
  for (var i = 0; i < cand.length; i++) if (Object.prototype.hasOwnProperty.call(man, cand[i])) return cand[i];
  return null;
}
function tipo(p) { return TIPOS[p.split('.').pop().toLowerCase()] || 'application/octet-stream'; }

async function servir(req, rel) {
  var est = await cargarEstado();
  if (!est) {
    if (rel === '' || rel === 'index.html') return fetch(req);
    if (req.mode === 'navigate') {
      var u = new URL(req.url);
      return Response.redirect(BASE + 'acceso.html?volver=' + encodeURIComponent(u.pathname + u.search + u.hash), 302);
    }
    return new Response('Acceso no autorizado', { status: 401 });
  }
  var ruta = resolver(est.man, rel), estadoHttp = 200;
  if (!ruta) { ruta = est.man['404.html'] ? '404.html' : null; estadoHttp = 404; }
  if (!ruta) return new Response('No encontrado', { status: 404 });
  var r = await fetch(BASE + '_c/' + est.man[ruta] + '.bin');
  if (!r.ok) return new Response('No encontrado', { status: 404 });
  var datos = new Uint8Array(await descifrar(est.key, await r.arrayBuffer()));
  var cab = { 'Content-Type': tipo(ruta), 'Cache-Control': 'private, max-age=0', 'Accept-Ranges': 'bytes' };
  var rango = req.headers.get('range'), m = rango && /^bytes=(\d*)-(\d*)$/.exec(rango);
  if (m && estadoHttp === 200) {
    var ini = m[1] === '' ? Math.max(datos.length - Number(m[2]), 0) : Number(m[1]);
    var fin = m[1] === '' || m[2] === '' ? datos.length - 1 : Math.min(Number(m[2]), datos.length - 1);
    if (ini > fin || ini >= datos.length) return new Response(null, { status: 416, headers: { 'Content-Range': 'bytes */' + datos.length } });
    cab['Content-Range'] = 'bytes ' + ini + '-' + fin + '/' + datos.length;
    cab['Content-Length'] = String(fin - ini + 1);
    return new Response(datos.slice(ini, fin + 1), { status: 206, headers: cab });
  }
  cab['Content-Length'] = String(datos.length);
  return new Response(datos, { status: estadoHttp, headers: cab });
}

self.addEventListener('fetch', function (e) {
  var u = new URL(e.request.url);
  if (u.origin !== location.origin || u.pathname.indexOf(BASE) !== 0) return;
  var rel;
  try { rel = decodeURIComponent(u.pathname.slice(BASE.length)); } catch (x) { return; }
  if (rel === 'sw.js' || rel === 'acceso.html' || rel === 'aviso-legal.html' || rel.indexOf('_c/') === 0 || rel.indexOf('acceso/') === 0) return;
  e.respondWith(servir(e.request, rel));
});
