const CACHE = 'worktrack-v5';

self.addEventListener('install', e => {
  self.skipWaiting();
  // Only cache static assets, NOT the HTML pages themselves
  e.waitUntil(caches.open(CACHE).then(c => c.addAll([])).catch(() => {}));
});

self.addEventListener('activate', e => {
  e.waitUntil(
    caches.keys().then(keys =>
      Promise.all(keys.map(k => caches.delete(k))) // delete ALL old caches
    )
  );
  self.clients.claim();
  // Tell all open pages to reload to get fresh content
  self.clients.matchAll({type:'window'}).then(clients => {
    clients.forEach(c => c.postMessage({type:'SW_UPDATED'}));
  });
});

self.addEventListener('fetch', e => {
  const url = new URL(e.request.url);
  // Never cache HTML pages or API calls — always go to network
  if (url.pathname.startsWith('/api/') ||
      url.pathname === '/manager' ||
      url.pathname === '/worker') return;
  // Other assets: network first, cache fallback
  e.respondWith(
    fetch(e.request).catch(() => caches.match(e.request))
  );
});
