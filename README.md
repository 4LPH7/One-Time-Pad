# OTP-Cipher


### Description:
A modern, user-friendly One-Time Pad encryption/decryption tool with a sleek GUI built using CustomTkinter.

---

A modern, user-friendly One-Time Pad encryption/decryption tool with a sleek GUI built using CustomTkinter.

## Features
- **Secure Encryption**: Implements the unbreakable One-Time Pad cipher with cryptographically secure key generation.
- **Sleek GUI**: Built with CustomTkinter for a modern and responsive design.
- **Copy-to-Clipboard**: Easily copy ciphertext and keys for secure sharing.
- **Error Handling**: Provides clear error messages for invalid inputs or mismatched keys.
- **Cross-Platform**: Works on Windows, macOS, and Linux.

## How to Use
1. **Encryption**:
   - Enter your plaintext in the "Encryption" tab.
   - Click "Encrypt" to generate ciphertext and a secret key.
   - Copy the ciphertext and key securely for transmission.

2. **Decryption**:
   - Enter the ciphertext and secret key in the "Decryption" tab.
   - Click "Decrypt" to retrieve the original plaintext.

3. **Security Reminder**:
   - Always keep the secret key secure and share it through a separate secure channel.

## Requirements
- Python 3.7 or higher
- Install dependencies:
  ```bash
  pip install customtkinter
  ```

## Installation
1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/OTP-Cipher.git
   ```
2. Navigate to the project directory:
   ```bash
   cd OTP-Cipher
   ```
3. Run the application:
   ```bash
   python otp_cipher.py
   ```

## Notes
- **Key Management**: The security of the One-Time Pad relies entirely on the secrecy of the key. Never reuse keys and ensure they are transmitted securely.
- **Key Length**: The key must be as long as the plaintext message.

## License
This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.

## Contributing
Contributions are welcome! Please open an issue or submit a pull request for any improvements or bug fixes.

## Acknowledgments
- Built using [CustomTkinter](https://github.com/TomSchimansky/CustomTkinter) for the modern GUI.
- Inspired by cryptographic best practices for secure communication.

