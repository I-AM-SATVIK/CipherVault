# Cipher Vault

A locally-hosted password manager built with Python and Tkinter.

## Overview
Cipher Vault stores credentials locally. It encrypts the database using 128-bit AES encryption before writing it to the disk. A master password protects the main application, and a secondary hashed password protects the vault interface.

## Features
* **AES-128 Encryption:** Secures data using the `cryptography` library (Fernet protocol).
* **Dual Authentication:** A Master Password unlocks the application. A separate, secondary password protects the saved credentials dashboard. Password verification relies on SHA-256 hashing.
* **Secure Password Generation:** Uses Python's `secrets` module (a cryptographically secure pseudorandom number generator) to generate 24-character passwords.
* **Clipboard Integration:** One-click copying and automatic clipboard appending for generated passwords.
* **Modern GUI:** Built with themed Tkinter (`ttk`) widgets, a scalable Treeview data table, and DPI-awareness for high-resolution displays.
* **Local Storage:** Data remains entirely on the local drive.

## Prerequisites
* Python 3.x

## Installation
1. Clone the repository:
   ```bash
   git clone <https://github.com/I-AM-SATVIK/CipherVault>
   cd CipherVault