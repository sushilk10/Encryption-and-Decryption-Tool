# HOW TO RUN THE CODE

--python -m venv .env
--.env\Scripts\activate
--pip install pybase64
--pip install cryptography
--python main.py

# HOW ITS WORK'S

🔐 Advanced Text & File Encryptor

The Advanced Text & File Encryptor is a Python-based desktop application built with Tkinter that allows users to securely encrypt and decrypt both text and files. 
It combines multiple encryption algorithms, including Base64 for simple encoding, Fernet (AES) from the cryptography library for strong encryption, and a Caesar 
Cipher for educational purposes. The application requires a password to be set before any encryption or decryption can take place, ensuring that only authorized 
users can access the content.

The app offers an integrated text editor where users can directly write, encrypt, or decrypt messages. For file handling, it provides an option to open and save 
files, as well as support for drag-and-drop functionality, making it easy to encrypt or decrypt files with just one action. When encrypting files, the program 
generates a new file with an .enc extension, while decrypting produces a new file with a _decrypted suffix, so the original files remain untouched.

The user interface is designed to be modern and user-friendly, with a status bar at the bottom to display feedback messages about ongoing operations. It also 
includes a toggle option to switch between dark and light themes, giving users flexibility in how they interact with the application. Buttons for encryption, 
decryption, clearing, saving, opening files, and toggling the theme are easily accessible, and a drop-down menu lets users choose the encryption method before proceeding.

Installation is straightforward: clone the repository, install the required dependencies (cryptography and pybase64), and optionally install tkdnd if drag-and-drop 
support is needed. Once launched, the app provides a secure, flexible, and interactive way to handle both text and file encryption.

Future improvements could include adding RSA public/private key encryption, automatic strong password generation, compression before encryption, exporting encrypted 
text directly to PDF, and packaging the project as a standalone executable for Windows. Licensed under MIT, the project is free to use, modify, and share, making it 
a practical tool for learning as well as real-world secure text and file management.
