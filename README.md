# Cipher Vault

A secure, locally-hosted password manager built with Python and Tkinter. 

## Overview
Cipher Vault stores credentials locally using a master-password system. It avoids plain-text storage by encrypting the database using 128-bit AES encryption before writing it to the disk.

## Features
* **AES Encryption:** Secures password data using the `cryptography` library (Fernet protocol).
* **Master Password Protection:** A single key derived from a SHA-256 hash protects the entire vault.
* **Complex Password Generation:** Built-in tool to generate high-entropy passwords using a mix of upper/lower case letters, digits, and punctuation.
* **Local Storage:** Data remains entirely on your local hardware.

## Prerequisites
* Python 3.x

## Installation
1. Clone this repository:
   ```bash
   git clone <https://github.com/I-AM-SATVIK/CipherVault>
   cd CipherVault