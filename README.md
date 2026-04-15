# Cipher Vault

A locally-hosted, highly secure password manager built with Python and Tkinter. Designed with advanced threat modeling in mind, Cipher Vault protects your credentials against both digital and physical intrusion using military-grade encryption and OS-level red-team defenses.

## 🛡️ Core Security Features

* **AES-128 Encryption:** Credentials are encrypted at rest using the `cryptography` library's Fernet protocol. 
* **Zero-Knowledge Architecture:** Cryptographic keys are derived dynamically via SHA-256 hashing. Passwords are never stored in plaintext on the disk.
* **Red-Team Defenses:**
  * **Anti-Keylogging:** A randomized, scrambled virtual keyboard actively blocks hardware keystrokes during Master and Vault authentication.
  * **Anti-Screen Sniffing:** Utilizes 64-bit Windows OS-level API calls (`SetWindowDisplayAffinity`) to render the application invisible to screenshots, screenshares, and malware scrapers.
  * **Inactivity Auto-Lock:** A background chronometer monitors system events and automatically purges decrypted memory and clipboard data if left unattended.
  * **Visual Masking:** Passwords in the vault are masked by default to prevent shoulder-surfing.

## 💻 UI / UX Features

* **Single Page Application (SPA) Routing:** Fluid, dynamic interface rendering without intrusive popup windows.
* **Native Dark Mode:** Deep, customizable `ttk.Style` themes with a real-time Dark/Light mode toggle.
* **Dynamic Strength Meter:** Real-time entropy calculation providing visual feedback as you type new passwords.
* **CSPRNG Generation:** One-click generation of cryptographically secure 24-character passwords.
* **Composite Key Structure:** Allows seamless storage of multiple distinct accounts (e.g., multiple emails) for the same website.

## Prerequisites
* Python 3.x
* Windows 10/11 (Required for OS-level screen defense APIs)

## Installation
1. Clone the repository:
   ```bash
   git clone <https://github.com/I-AM-SATVIK/CipherVault>
   cd CipherVault