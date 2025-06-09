// vite.config.js
import { defineConfig } from "vite";
import { VitePWA } from "vite-plugin-pwa";

export default defineConfig({
	base: "/encryptor/",
	build: {
		target: "esnext", // Good for modern browser features like SubtleCrypto
	},
	plugins: [
		VitePWA({
			injectRegister: "auto",
			includeAssets: ["favicon.ico", "apple-touch-icon.png", "mask-icon.svg"],
			manifest: {
				version: "0.0.3",
				manifest_version: 3,
				name: "Encryptor | Web-based encryption tools",
				short_name: "Encryptor",
				description:
					"Client-side encryption and hashing tool using OpenPGP.js and SubtleCrypto.",
				start_url: "/encryptor/",
				display: "standalone",
				background_color: "#ffffff",
				theme_color: "#007bff",
				icons: [
					{
						src: "vite.svg",
						sizes: "192x192",
						type: "image/svg+xml",
						purpose: "any maskable",
					},
					{
						src: "vite.svg",
						sizes: "512x512",
						type: "image/svg+xml",
						purpose: "any maskable",
					},
				],
			},
		}),
	],
});
