// Henson Hauling Driver Tools -- offline app-shell caching.
//
// Strategy:
//   - The app page itself (index.html) is NETWORK-FIRST: opening the app
//     always loads the latest deployed version, so updates show up right
//     away instead of one launch late. If there's no signal, or the network
//     takes more than 4 seconds, the saved copy is shown instead, so the app
//     still opens with no signal instead of a blank white screen.
//   - Everything else (icons, manifest, CDN scripts) is stale-while-
//     revalidate: served instantly from the saved copy and refreshed in the
//     background.
//   - Requests to /api/ are never intercepted or cached here -- inspection
//     data, materials, and everything else the app already has its own
//     "check your connection" handling for should always reflect what's
//     actually on the server, never a stale cached copy.
//
// Bump CACHE_NAME whenever this file changes so old caches get cleared out.
const CACHE_NAME = 'henson-driver-v2';

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

  // The app page: network first, saved copy only as a fallback.
  const isPage = req.mode === 'navigate' || /\/(index\.html)?$/.test(new URL(req.url).pathname);
  if (isPage) {
    event.respondWith((async () => {
      const cache = await caches.open(CACHE_NAME);
      try {
        const res = await Promise.race([
          fetch(req, { cache: 'no-store' }),
          new Promise((_, reject) => setTimeout(() => reject(new Error('slow network')), 4000))
        ]);
        if (res && res.status === 200) cache.put(req, res.clone());
        return res;
      } catch (err) {
        const cached = await cache.match(req) || await cache.match('./index.html') || await cache.match('./');
        return cached || fetch(req);
      }
    })());
    return;
  }

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
