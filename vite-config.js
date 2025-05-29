// vite.config.js
import { defineConfig } from "vite";

export default defineConfig({
	// If deploying to GitHub Pages like: https://username.github.io/my-crypto-pwa-js/
	base: "/encryptor/", // Uncomment and set your repo name
	build: {
		target: "esnext", // Good for modern browser features like SubtleCrypto
	},
});
