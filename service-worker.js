// Henson Hauling Driver Tools -- offline app-shell caching.
//
// Strategy: stale-while-revalidate for everything except API calls.
//   - A cached copy (if any) is served immediately, so the app still opens
//     with no signal instead of a blank white screen.
//   - A fresh copy is fetched in the background and saved for next time, so
//     the app naturally catches up to the latest deployed version on the
//     next launch.
//   - Requests to /api/ are never intercepted or cached here -- inspection
//     data, materials, and everything else the app already has its own
//     "check your connection" handling for should always reflect what's
//     actually on the server, never a stale cached copy.
//
// Bump CACHE_NAME whenever this file changes so old caches get cleared out.
const CACHE_NAME = 'henson-driver-v1';

const APP_SHELL = [
  './',
  './index.html',
  './manifest.json',
  './icon-192.png',
  './icon-512.png',
  './apple-touch-icon.png'
];

self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(CACHE_NAME)
      .then((cache) => cache.addAll(APP_SHELL))
      .catch((err) => console.error('Service worker install/cache failed:', err))
  );
  self.skipWaiting();
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys().then((keys) =>
      Promise.all(keys.filter((k) => k !== CACHE_NAME).map((k) => caches.delete(k)))
    )
  );
  self.clients.claim();
});

self.addEventListener('fetch', (event) => {
  const req = event.request;

  if (req.method !== 'GET') return;
  if (req.url.includes('/api/')) return; // never cache live data

  event.respondWith(
    caches.match(req).then((cached) => {
      const networkFetch = fetch(req).then((res) => {
        // Cross-origin CDN scripts (Chart.js, Leaflet, Google Fonts, etc.)
        // come back as opaque responses -- status is always 0 by design,
        // so status===200 alone would silently skip caching all of them.
        const cacheable = res && (res.status === 200 || res.type === 'opaque');
        if (cacheable) {
          const resClone = res.clone();
          caches.open(CACHE_NAME).then((cache) => cache.put(req, resClone));
        }
        return res;
      }).catch(() => cached);
      return cached || networkFetch;
    })
  );
});
