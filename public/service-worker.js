const CACHE_NAME = 'diemdanh-shell-v1';

self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(CACHE_NAME).then((cache) => cache.add('/'))
  );
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys().then((keys) => Promise.all(
      keys.filter((key) => key.startsWith('diemdanh-shell-') && key !== CACHE_NAME)
        .map((key) => caches.delete(key))
    ))
  );
});

self.addEventListener('fetch', (event) => {
  const request = event.request;
  if (request.method !== 'GET' || new URL(request.url).origin !== self.location.origin) return;
  if (request.mode !== 'navigate') return;

  event.respondWith(
    fetch(request).then((response) => {
      const copy = response.clone();
      caches.open(CACHE_NAME).then((cache) => cache.put('/', copy));
      return response;
    }).catch(async () => {
      const cached = await caches.match('/');
      if (cached) return cached;
      return new Response('Ứng dụng chưa được tải để dùng offline. Hãy mở ứng dụng khi có mạng trước.', {
        status: 503,
        headers: { 'Content-Type': 'text/plain; charset=utf-8' },
      });
    })
  );
});
