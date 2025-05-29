# Encryptor

A simple, client-side Progressive Web App (PWA) for performing common cryptographic operations like AES encryption/decryption, OpenPGP encryption/decryption, and SHA hashing directly in your browser. All operations are performed locally, and your data never leaves your machine.

**[Live Demo](https://ruvasqm.github.io/encryptor/)**

## Features

*   **AES-256-GCM Encryption/Decryption:** Symmetrically encrypt and decrypt text snippets using a password.
*   **OpenPGP Encryption/Decryption:**
    *   Encrypt messages using a password (symmetric PGP).
    *   Encrypt messages using a recipient's PGP public key (asymmetric PGP).
    *   Decrypt PGP messages using your private key and passphrase (if applicable) or a password.
*   **SHA Hashing:** Generate SHA-256 and SHA-1 (for demonstration only) hashes of text.
*   **Client-Side Operations:** All cryptographic functions run entirely within your browser. No data is sent to any server.
*   **Offline Capable (PWA):** Once loaded, the app can function without an internet connection.
*   **Simple & Clean UI:** Easy to use interface for quick crypto tasks.

## Technologies Used

*   **HTML5, CSS3, JavaScript (ES Modules)**
*   **[Vite](https://vitejs.dev/):** Fast frontend build tool.
*   **[OpenPGP.js](https://openpgpjs.org/):** A JavaScript implementation of the OpenPGP standard for PGP operations.
*   **[Web Crypto API (SubtleCrypto)](https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API/SubtleCrypto):** Browser-native API for cryptographic primitives like AES and SHA hashing.
*   **Progressive Web App (PWA):** Service Workers for offline capabilities and manifest for app-like experience.

## ⚠️ Important Security Considerations & Risks ⚠️

This tool is provided for educational, demonstrative, and convenience purposes. While it utilizes established cryptographic libraries and browser APIs, **users must understand the inherent risks and best practices when dealing with cryptography and sensitive data:**

1.  **Client-Side Security is Not Absolute:**
    *   **Browser Extensions:** Malicious browser extensions can potentially access data within your browser tabs, including plaintext or keys entered into this tool.
    *   **Compromised Browser/OS:** If your browser or operating system is compromised with malware, the security of any client-side application can be undermined.
    *   **XSS Vulnerabilities (Developer Responsibility):** While this application aims to be secure, any web application *could* have XSS vulnerabilities if not carefully developed. This tool relies on the security of its own code and the browser's sandbox.

2.  **Key Management is Your Responsibility:**
    *   **Password Strength:** For password-based encryption (AES or symmetric PGP), the security heavily relies on the strength and secrecy of your password. Use strong, unique passwords.
    *   **PGP Private Key Security:** Your PGP private key is extremely sensitive. Protect it diligently. If using it in this tool, ensure you trust the environment. Avoid pasting private keys on public or untrusted computers.
    *   **Nonce/IV Reuse (AES-GCM):** This application correctly generates random nonces (IVs) for AES-GCM. Reusing a nonce with the same key in AES-GCM can catastrophically break security.

3.  **SHA-1 is Insecure:**
    *   The SHA-1 hashing option is included for demonstration or compatibility with legacy systems *only*. **SHA-1 is cryptographically broken and should NOT be used for any security-sensitive applications.** Use SHA-256 or stronger.

4.  **No Guarantees or Warranties:**
    *   This software is provided "as is," without warranty of any kind, express or implied. The developers and contributors are not liable for any loss or damage arising from the use of this tool.
    *   **Always verify critical operations with trusted, audited, and dedicated cryptographic software for highly sensitive information.**

5.  **Trusting the Code:**
    *   As an open-source tool, you can inspect the code. However, when using the live deployed version, you are trusting that the deployed code matches the public repository and has not been tampered with (this is a general concern for all web apps).

**In summary: Use this tool responsibly and with an understanding of its limitations. For critical security needs, rely on dedicated, well-audited cryptographic software and hardware.**

## Development

1.  Clone the repository.
2.  Install dependencies: `npm install`
3.  Run the development server: `npm run dev`
4.  Build for production: `npm run build` (Output will be in the `dist` folder)

## Contributing

Contributions, issues, and feature requests are welcome! Please feel free to check [issues page](https://github.com/ruvasqm/encryptor/issues).

## License

This project is licensed under the [MIT License](LICENSE.md).
