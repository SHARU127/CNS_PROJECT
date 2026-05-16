# Ghost Vault: PPT Presentation Content

## Slide 1: Title Slide
*   **Title:** Ghost Vault: Steganographic Secure Communication
*   **Subtitle:** A Hybrid Cryptographic System for Secret Messaging
*   **Presented by:** Sharath & Team
*   **Keywords:** RSA-2048, AES-256, LSB Steganography, FastAPI

---

## Slide 2: The Problem & Our Solution
*   **The Problem:** 
    *   Standard encrypted messages look suspicious to eavesdroppers.
    *   Manual password sharing (Symmetric-only) is a major security bottleneck.
*   **Our Solution:** 
    *   **Steganography:** Hides the existence of the message inside a carrier image.
    *   **Hybrid Encryption:** Combines RSA and AES to eliminate manual key sharing.

---

## Slide 3: System Architecture (The Hybrid Approach)
*   **Symmetric Encryption (AES-256):** Used for bulk data encryption (High performance).
*   **Asymmetric Encryption (RSA-2048):** Used for secure "Key Exchange" (Key Wrapping).
*   **Double-Layer Security:** The message is first encrypted (Cryptography) and then hidden (Steganography).

---

## Slide 4: Key Management (RSA-2048)
*   **Public Key:** Shared openly; used by the sender to "wrap" the session key.
*   **Private Key:** Kept secret by the recipient; used to "unwrap" and unlock the message.
*   **No Shared Passwords:** Each recipient has their own unique keypair. If a private key isn't present, the "Ghost" image remains a mystery.

---

## Slide 5: Data Hiding (LSB Steganography)
*   **Method:** Least Significant Bit (LSB) substitution in the RGB color space.
*   **The "Secret":** We modify the bits that have the least impact on the color.
*   **Invisibility:** The modification is so subtle (1/255th of a color level) that the image appears identical to the original.
*   **Capacity:** Efficiently packs data across millions of pixels.

---

## Slide 6: "The Forge" (The Encoding Process)
1.  **Generate:** Algorithm creates a random AES-256 "Session Key".
2.  **Encrypt:** The secret message is encrypted using AES-256-CBC.
3.  **Wrap:** The AES key itself is encrypted using the recipient's RSA Public Key.
4.  **Embed:** The [Locked Key + Encrypted Message] is hidden into the image pixels.
5.  **Output:** A secure "Ghost Image" ready for transmission.

---

## Slide 7: "The Oracle" (The Decoding Process)
1.  **Extract:** The hidden bitstream is pulled from the stego-image pixels.
2.  **Separate:** The system identifies the RSA ciphertext and the AES ciphertext.
3.  **Unwrap:** The recipient's RSA Private Key recovers the original AES Session Key.
4.  **Reveal:** The recovered AES key decrypts the secret message.
5.  **Output:** The original plaintext is displayed to the recipient.

---

## Slide 8: Security Benefits & Conclusion
*   **Confidentiality:** AES-256 provides world-class encryption strength.
*   **Authentication:** Only the owner of the math-matched Private Key can read the message.
*   **Stealth:** Uses the "Hiding in plain sight" principle to avoid detection.
*   **Zero-Knowledge:** The server/sender never needs to know the recipient's password.
