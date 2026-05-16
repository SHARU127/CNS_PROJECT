# Ghost Vault: Key Concept Review & Chat Summary

This document summarizes the key technical explanations and demonstration steps discussed during the development of the Ghost Vault project.

## 1. The Core Doubt: How to send the "Secure Key"?
In many cryptographic systems, the "Bootstrap" problem is how to get a secret key to someone else without an attacker seeing it.
*   **The Wrong Way:** Sending a password in a text message.
*   **The Right Way (Hybrid Cryptography):** 
    1.  Encrypt the message with a fast, random **Symmetric Key** (AES-256).
    2.  Encrypt that AES key with the recipient's **Asymmetric Public Key** (RSA-2048).
    3.  This is called **Key Wrapping**.

## 2. Realistic Example: Alice & Bob
1.  **Bob** creates a Keypair. He shares his **Public Key** with Alice.
2.  **Alice** "Forges" a Ghost image. The app generates a random AES key, locks it with Bob's Public Key, and hides it in an image.
3.  **Bob** receives the image and uses his **Private Key** (which he never shared) to unlock the AES key and read the message.
4.  **Result:** The key travels securely inside the image, and only Bob can open it.

## 3. How to Explain "Key Wrapping" to a Teacher
Use these technical points:
*   **Efficiency:** RSA is slow for big files; AES is fast. We use AES for the message and RSA for the key.
*   **Zero-Knowledge:** The sender doesn't need to know a password; they only need the recipient's public key.
*   **Payload Packaging:** We bundle the `[RSA Ciphertext]` and the `[AES Ciphertext]` together into a single hidden payload.

## 4. Live Demonstration Steps
1.  **Generate Keys:** Download `public.pem` and `private.pem`.
2.  **Forge:** Upload a photo, type a secret, and upload the `public.pem`. Download the resulting `ghost_vault.png`.
3.  **Oracle:** Upload the `ghost_vault.png` and the `private.pem`.
4.  **Reveal:** Show the secret message.
5.  **Failure Test:** Show that a different (wrong) private key cannot unlock the same image.

## 5. Security Pillars of Ghost Vault
*   **Confidentiality:** AES-256 encryption.
*   **Identity:** RSA-2048 public/private keys.
*   **Integrity:** SHA-256 hashing (used in the client/server code).
*   **Stealth:** LSB Steganography (Hiding in plain sight).
