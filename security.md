# SECURITY.md - Secure Multi-Layer Cipher (CyberX 2.0)

This document provides an auditable overview of the cryptographic design and security posture of the CyberX 2.0 system.

## 1. Randomization and Key Management Philosophy

The primary security goal is **Unpredictability** and **Defense in Depth**.

* **Master Seed and KDF:** Every encryption operation begins with the generation of a high-entropy 32-byte `MASTER_SEED` using `Cryptodome.Random.get_random_bytes`. Keys for all classical ciphers (Caesar, Vigenere, RailFence) are **derived** from this Master Seed using **PBKDF2** with a unique salt (the cipher name). This ensures all session keys are cryptographically linked to a single, high-security seed, eliminating simple key brute-forcing.
* **CSPRNG for Sessions:** Session IDs are generated using Python's `secrets` module (a Cryptographically Secure Pseudo-Random Number Generator) for unpredictable and high-entropy identifiers.

## 2. Layering and Obscurity Rules

The system enforces a randomized, multi-layered structure for every message:

1.  **Classical Ciphers (1-3 layers):** A random sequence of 1 to 3 classical ciphers (Caesar, Vigenere, RailFence, Hill, Monoalphabetic) is selected.
2.  **Obscurity Transformations (0-2 layers):** 0 to 2 non-cipher transformations (`REVERSE`, `BASE64`) are randomly interspersed within the classical sequence.
3.  **Modern Ciphers (1-2 layers, Final Layer):** A final, randomized sequence of 1 to 2 modern ciphers (AES, DES, RSA) is applied.

**Enforced Constraint:** The final encryption layer must always be a **Modern Cipher (AES/DES/RSA)**. This ensures the resulting ciphertext has high entropy and appears as an encoded block (often Base64), masking the preceding classical layers.

## 3. Cryptographic Primitives

| Primitive | Mode/Key Size | Justification |
| :--- | :--- | :--- |
| **AES** | 128-bit Key, **CBC Mode** | Industry standard, strong confidentiality. CBC mode is used to mitigate pattern detection inherent in ECB mode. |
| **DES** | 64-bit Key, **CBC Mode** | Included for demonstration of legacy standards, but also implemented in CBC mode. |
| **RSA** | 2048-bit Keys, **PKCS1_OAEP** Padding | Provides secure asymmetric key exchange and encryption. OAEP padding is essential for semantic security. |

## 4. Audibility and Attack Simulation

The `/simulate` endpoint is designed as an internal audit tool to verify the system's resilience:

* It checks the ciphertext's **Entropy** and **Base64-like signature**.
* It performs a **Multi-Layered Attack Simulation** (Caesar, Vigenere, RailFence brute-force/analysis) not only on the raw ciphertext but also on intermediate states (`Base64 Decoded`, `Reversed`, and `Base64 Decoded + Reversed`).
* A **Strength Score** is calculated, which penalizes the system if any attack successfully yields English plaintext in *any* layer. This score is used for continuous improvement.