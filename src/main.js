// main.js
import * as openpgp from "openpgp/lightweight";

// --- DOM Elements ---
const appStatus = document.getElementById("app-status");

// AES Elements
const aesInputText = document.getElementById("aesInputText");
const aesPassword = document.getElementById("aesPassword");
const aesEncryptBtn = document.getElementById("aesEncryptBtn");
const aesDecryptBtn = document.getElementById("aesDecryptBtn");
const aesOutput = document.getElementById("aesOutput");

// PGP Elements
const pgpInputText = document.getElementById("pgpInputText");
const pgpPassword = document.getElementById("pgpPassword");
const pgpPublicKey = document.getElementById("pgpPublicKey");
const pgpPrivateKey = document.getElementById("pgpPrivateKey");
const pgpPrivateKeyPassphrase = document.getElementById(
	"pgpPrivateKeyPassphrase",
);
const pgpEncryptBtn = document.getElementById("pgpEncryptBtn");
const pgpDecryptBtn = document.getElementById("pgpDecryptBtn");
const pgpOutput = document.getElementById("pgpOutput");

// Hash Elements
const hashInput = document.getElementById("hashInput");
const sha256Btn = document.getElementById("sha256Btn");
const sha1Btn = document.getElementById("sha1Btn");
const hashOutput = document.getElementById("hashOutput");
const sha1Warning = document.getElementById("sha1Warning");

// --- PWA Service Worker Registration ---
if ("serviceWorker" in navigator) {
	window.addEventListener("load", () => {
		navigator.serviceWorker
			.register("/sw.js")
			.then((registration) => {
				console.log(
					"ServiceWorker registration successful with scope: ",
					registration.scope,
				);
				appStatus.textContent = "App Ready (Offline Capable)";
			})
			.catch((error) => {
				console.log("ServiceWorker registration failed: ", error);
				appStatus.textContent =
					"ServiceWorker registration failed. Offline mode may not work.";
				appStatus.classList.add("error");
			});
	});
} else {
	appStatus.textContent =
		"ServiceWorker not supported. Offline mode unavailable.";
}

// --- Helper Functions ---
function arrayBufferToHex(buffer) {
	return Array.from(new Uint8Array(buffer))
		.map((b) => b.toString(16).padStart(2, "0"))
		.join("");
}

function base64ToArrayBuffer(base64) {
	const binaryString = window.atob(base64);
	const len = binaryString.length;
	const bytes = new Uint8Array(len);
	for (let i = 0; i < len; i++) {
		bytes[i] = binaryString.charCodeAt(i);
	}
	return bytes.buffer;
}

function arrayBufferToBase64(buffer) {
	let binary = "";
	const bytes = new Uint8Array(buffer);
	const len = bytes.byteLength;
	for (let i = 0; i < len; i++) {
		binary += String.fromCharCode(bytes[i]);
	}
	return window.btoa(binary);
}

// --- SubtleCrypto AES-GCM Functions ---
const AES_KEY_USAGE = ["encrypt", "decrypt"];
const AES_ALGORITHM = "AES-GCM";
const PBKDF2_ITERATIONS = 100000; // Iterations for PBKDF2
const PBKDF2_HASH = "SHA-256";

async function deriveKeyFromPasswordAES(password, salt) {
	const enc = new TextEncoder();
	const keyMaterial = await window.crypto.subtle.importKey(
		"raw",
		enc.encode(password),
		{ name: "PBKDF2" },
		false,
		["deriveKey"],
	);
	return window.crypto.subtle.deriveKey(
		{
			name: "PBKDF2",
			salt: salt,
			iterations: PBKDF2_ITERATIONS,
			hash: PBKDF2_HASH,
		},
		keyMaterial,
		{ name: AES_ALGORITHM, length: 256 },
		true,
		AES_KEY_USAGE,
	);
}

aesEncryptBtn.addEventListener("click", async () => {
	try {
		aesOutput.textContent = "Encrypting...";
		aesOutput.classList.remove("error");
		const plaintext = aesInputText.value;
		const password = aesPassword.value;
		if (!plaintext || !password) {
			aesOutput.textContent = "Error: Plaintext and password are required.";
			aesOutput.classList.add("error");
			return;
		}

		const salt = window.crypto.getRandomValues(new Uint8Array(16)); // 16-byte salt
		const iv = window.crypto.getRandomValues(new Uint8Array(12)); // 12-byte IV for AES-GCM

		const key = await deriveKeyFromPasswordAES(password, salt);
		const encodedPlaintext = new TextEncoder().encode(plaintext);

		const ciphertextBuffer = await window.crypto.subtle.encrypt(
			{ name: AES_ALGORITHM, iv: iv },
			key,
			encodedPlaintext,
		);

		// Combine salt, iv, and ciphertext for storage/transmission
		// salt (16) + iv (12) + ciphertext
		const combined = new Uint8Array(
			salt.length + iv.length + ciphertextBuffer.byteLength,
		);
		combined.set(salt, 0);
		combined.set(iv, salt.length);
		combined.set(new Uint8Array(ciphertextBuffer), salt.length + iv.length);

		aesOutput.textContent = `Encrypted (Base64): ${arrayBufferToBase64(combined.buffer)}`;
	} catch (e) {
		aesOutput.textContent = `Error: ${e.message}`;
		aesOutput.classList.add("error");
		console.error(e);
	}
});

aesDecryptBtn.addEventListener("click", async () => {
	try {
		aesOutput.textContent = "Decrypting...";
		aesOutput.classList.remove("error");
		const base64CiphertextCombined = aesInputText.value;
		const password = aesPassword.value;

		if (!base64CiphertextCombined || !password) {
			aesOutput.textContent =
				"Error: Encrypted text (Base64) and password are required.";
			aesOutput.classList.add("error");
			return;
		}

		const combinedBuffer = base64ToArrayBuffer(base64CiphertextCombined);
		const combined = new Uint8Array(combinedBuffer);

		const salt = combined.slice(0, 16);
		const iv = combined.slice(16, 16 + 12);
		const ciphertext = combined.slice(16 + 12);

		const key = await deriveKeyFromPasswordAES(password, salt);

		const decryptedBuffer = await window.crypto.subtle.decrypt(
			{ name: AES_ALGORITHM, iv: iv },
			key,
			ciphertext,
		);

		aesOutput.textContent = `Decrypted: ${new TextDecoder().decode(decryptedBuffer)}`;
	} catch (e) {
		aesOutput.textContent = `Error: Decryption failed. Wrong password or corrupted data. ${e.message}`;
		aesOutput.classList.add("error");
		console.error(e);
	}
});

// --- OpenPGP.js Functions ---
pgpEncryptBtn.addEventListener("click", async () => {
	try {
		pgpOutput.textContent = "Encrypting with PGP...";
		pgpOutput.classList.remove("error");
		const plaintext = pgpInputText.value;
		const password = pgpPassword.value;
		const publicKeyArmored = pgpPublicKey.value;

		if (!plaintext) {
			pgpOutput.textContent =
				"Error: Plaintext is required for PGP encryption.";
			pgpOutput.classList.add("error");
			return;
		}

		let encryptionKeys = [];
		if (publicKeyArmored) {
			try {
				encryptionKeys = await openpgp.readKeys({
					armoredKeys: publicKeyArmored,
				});
			} catch (keyError) {
				pgpOutput.textContent = `Error reading public key: ${keyError.message}`;
				pgpOutput.classList.add("error");
				return;
			}
		}

		const message = await openpgp.createMessage({ text: plaintext });
		let encrypted;

		if (encryptionKeys.length > 0) {
			// Asymmetric encryption
			encrypted = await openpgp.encrypt({
				message,
				encryptionKeys,
			});
		} else if (password) {
			// Symmetric encryption
			encrypted = await openpgp.encrypt({
				message,
				passwords: [password],
			});
		} else {
			pgpOutput.textContent =
				"Error: Provide either a PGP public key or a password for encryption.";
			pgpOutput.classList.add("error");
			return;
		}
		pgpOutput.textContent = `${encrypted}`; // PGP message is already armored (text)
	} catch (e) {
		pgpOutput.textContent = `Error: ${e.message}`;
		pgpOutput.classList.add("error");
		console.error(e);
	}
});

pgpDecryptBtn.addEventListener("click", async () => {
	try {
		pgpOutput.textContent = "Decrypting PGP message...";
		pgpOutput.classList.remove("error");
		const armoredMessage = pgpInputText.value;
		const privateKeyArmored = pgpPrivateKey.value;
		const passphrase = pgpPrivateKeyPassphrase.value;

		if (!armoredMessage) {
			pgpOutput.textContent = "Error: PGP encrypted message is required.";
			pgpOutput.classList.add("error");
			return;
		}

		const message = await openpgp.readMessage({ armoredMessage });
		let decryptionKeys = [];
		let options = { message };

		if (privateKeyArmored) {
			try {
				const privateKey = await openpgp.decryptKey({
					privateKey: await openpgp.readPrivateKey({
						armoredKey: privateKeyArmored,
					}),
					passphrase,
				});
				decryptionKeys.push(privateKey);
				options.decryptionKeys = decryptionKeys;
			} catch (keyError) {
				pgpOutput.textContent = `Error with private key or passphrase: ${keyError.message}`;
				pgpOutput.classList.add("error");
				return;
			}
		} else {
			// If no private key, try password-based decryption
			if (pgpPassword.value) {
				options.passwords = [pgpPassword.value];
			} else if (!privateKeyArmored) {
				pgpOutput.textContent =
					"Error: PGP private key (and passphrase if needed) or a password is required for decryption.";
				pgpOutput.classList.add("error");
				return;
			}
		}

		const { data: decrypted, signatures } = await openpgp.decrypt(options);

		pgpOutput.textContent = `Decrypted: ${decrypted}`;
		// You could also verify signatures if present:
		// if (signatures && signatures.length > 0 && signatures[0].verified) {
		//    const keyid = signatures[0].keyID.toHex();
		//    console.log(`Signed by key id ${keyid}`);
		// }
	} catch (e) {
		pgpOutput.textContent = `Error: PGP Decryption failed. ${e.message}`;
		pgpOutput.classList.add("error");
		console.error(e);
	}
});

// --- SubtleCrypto Hashing Functions ---
async function hashData(algorithm, data) {
	const encoder = new TextEncoder();
	const dataBuffer = encoder.encode(data);
	const hashBuffer = await window.crypto.subtle.digest(algorithm, dataBuffer);
	return arrayBufferToHex(hashBuffer);
}

sha256Btn.addEventListener("click", async () => {
	try {
		sha1Warning.style.display = "none";
		const data = hashInput.value;
		if (!data) {
			hashOutput.textContent = "Enter data to hash.";
			return;
		}
		hashOutput.textContent = "Hashing SHA-256...";
		const digest = await hashData("SHA-256", data);
		hashOutput.textContent = `SHA-256: ${digest}`;
	} catch (e) {
		hashOutput.textContent = `Error: ${e.message}`;
		console.error(e);
	}
});

sha1Btn.addEventListener("click", async () => {
	try {
		sha1Warning.style.display = "block";
		const data = hashInput.value;
		if (!data) {
			hashOutput.textContent = "Enter data to hash.";
			return;
		}
		hashOutput.textContent = "Hashing SHA-1...";
		const digest = await hashData("SHA-1", data);
		hashOutput.textContent = `SHA-1: ${digest}`;
	} catch (e) {
		hashOutput.textContent = `Error: ${e.message}`;
		console.error(e);
	}
});

// Initial status
if (window.crypto && window.crypto.subtle) {
	console.log("SubtleCrypto API available.");
} else {
	appStatus.textContent =
		"Error: SubtleCrypto API not available. This app requires a modern browser with HTTPS.";
	appStatus.classList.add("error");
	// Disable buttons or show a more prominent error
}
