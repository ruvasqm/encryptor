// sw.js
const CACHE_NAME = "crypto-pwa-js-cache-v1.1"; // Increment version on change
// Add essential files. Vite handles hashing for production builds.
// For a simple PWA, caching the main entry points is often enough.
// More complex PWAs might use Workbox via vite-plugin-pwa for precaching.
const urlsToCache = [
	"/", // Alias for index.html
	"/index.html",
	// Vite will include main.js and openpgp.js in its build output,
	// usually with hashed names in the 'assets' directory.
	// For robust caching of these, vite-plugin-pwa is recommended.
	// For a simple approach, we cache the entry points.
	// The browser will fetch other JS chunks as needed.
	"/manifest.json",
	"/vite.svg", // Your app icon
];

self.addEventListener("install", (event) => {
	event.waitUntil(
		caches.open(CACHE_NAME).then((cache) => {
			console.log("Opened cache:", CACHE_NAME);
			return cache
				.addAll(urlsToCache.map((url) => new Request(url, { cache: "reload" }))) // Force reload from network for install
				.catch((err) => {
					console.error("Failed to cache initial resources:", err);
				});
		}),
	);
	self.skipWaiting(); // Activate new SW immediately
});

self.addEventListener("activate", (event) => {
	const cacheWhitelist = [CACHE_NAME];
	event.waitUntil(
		caches
			.keys()
			.then((cacheNames) => {
				return Promise.all(
					cacheNames.map((cacheName) => {
						if (cacheWhitelist.indexOf(cacheName) === -1) {
							console.log("Deleting old cache:", cacheName);
							return caches.delete(cacheName);
						}
					}),
				);
			})
			.then(() => self.clients.claim()), // Take control of open clients
	);
});

self.addEventListener("fetch", (event) => {
	// Only handle GET requests
	if (event.request.method !== "GET") {
		return;
	}

	event.respondWith(
		caches.match(event.request).then((response) => {
			if (response) {
				// Cache hit - return response
				return response;
			}
			// Not in cache - fetch from network
			return fetch(event.request)
				.then((networkResponse) => {
					// Check if we received a valid response
					if (
						!networkResponse ||
						networkResponse.status !== 200 ||
						networkResponse.type !== "basic"
					) {
						return networkResponse;
					}

					// IMPORTANT: Clone the response. A response is a stream
					// and because we want the browser to consume the response
					// as well as the cache consuming the response, we need
					// to clone it so we have two streams.
					const responseToCache = networkResponse.clone();

					caches.open(CACHE_NAME).then((cache) => {
						// Don't cache non-essential or large dynamic assets aggressively here
						// This simple strategy caches any successful GET request.
						// You might want to be more selective.
						// cache.put(event.request, responseToCache);
					});
					return networkResponse;
				})
				.catch((error) => {
					console.log("Fetch failed; returning offline page instead.", error);
					// Optionally, return a fallback offline page if appropriate
					// return caches.match('/offline.html');
				});
		}),
	);
});
