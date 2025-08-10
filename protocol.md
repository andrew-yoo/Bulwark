# Protocol Details

## Cryptography

- Key Derivation
    - Argon2
- Encryption
    - XChaCha20 for light and normal modes.
    - XChaCha20, Camellia, and AES cascaded for overkill mode.
- Authentication
    - Keyed Blake3

## File

| Field               | Byte Size | Byte Offset |
| :------------------ | :-------- | :---------- |
| Magic Number        | 4         | 0           |
| Version             | 2         | 4           |
| MAC                 | 32        | 6           |
| Settings 1          | 1         | 38          |
| Settings 2          | 1         | 39          |
| Miscellaneous       | 8         | 40          |
| Argon2 Salt         | 32        | 48          |
| XChaCha20 Nonce     | 24        | 80          |
| Camellia Nonce      | 16        | 104         |
| AES Nonce           | 16        | 120         |
| Ciphertext          |           | 136         |