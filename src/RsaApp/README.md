# RSA Cryptosystem Implementation

![RSA Algorithm](https://img.shields.io/badge/Algorithm-RSA-blue)
![C#](https://img.shields.io/badge/Language-C%23-green)
[![License](https://img.shields.io/badge/License-MIT-orange)](LICENSE)

Complete implementation of RSA asymmetric encryption algorithm in C# with:
- Key generation (manual/auto)
- File encryption/decryption
- Prime number validation
- Optimal block processing

## Features

### Core Functionality
- ✔ Full RSA algorithm implementation
- ✔ Support for arbitrarily large numbers (using `BigInteger`)
- ✔ Probabilistic prime generation (Miller-Rabin test)
- ✔ Modular inverse calculation
- ✔ PKCS#1 v1.5 compatible block processing

### Security Components
- 🔒 Prime number validation
- 🔑 Key pair generation
- 🛡️ Safe modular exponentiation
- 📦 Block-wise encryption/decryption

### User Interface
- 🖥️ Console menu system
- 📁 File operations support
- 🔢 Interactive parameter input
- 📊 Progress feedback

## Getting Started

### Prerequisites
- .NET 6.0+ SDK
- Basic understanding of RSA cryptosystem

### Installation
```bash
git clone https://github.com/yourusername/RSA-Implementation.git
cd RSA-Implementation
```

## Usage Examples

### 1. Key Generation
```bash
dotnet run
```
Select option `1` from menu:
```text
1. Generate RSA keys
2. Encrypt file
3. Decrypt file
4. Exit
```

### 2. File Encryption
```bash
dotnet run
```
Select option `2` and provide:
- Input file path
- Public exponent (e)
- Modulus (N)

### 3. File Decryption
```bash
dotnet run
```
Select option `3` and provide:
- Encrypted file path
- Private exponent (d)
- Modulus (N)

## Code Structure

### Main Components
| File | Description |
|------|-------------|
| `Program.cs` | Console interface and menu system |
| `RSACipher.cs` | Core cryptographic operations |
| `CryptographicException.cs` | Custom exception class |

### Key Methods
```csharp
// Generate key pair
(BigInteger N, BigInteger e, BigInteger d) = RSACipher.GenerateKeyPair(2048);

// Encrypt data
byte[] encrypted = RSACipher.EncryptData(data, e, N);

// Decrypt data
byte[] decrypted = RSACipher.DecryptData(encrypted, d, N);
```

## Testing

### Test Vectors
Sample files included:
- `test.txt` - Original plaintext
- `test.enc.txt` - Encrypted output
- `test.dec.txt` - Decrypted output

### Verification
```bash
# Compare original and decrypted files
fc test.txt test.dec.txt
```

## Performance Notes
- Key generation time increases exponentially with bit size
- 2048-bit keys recommended for production use
- Prime generation uses optimized Miller-Rabin test

## Security Considerations
⚠️ **Important**: This is an educational implementation. For production use:
- Use established libraries like `System.Security.Cryptography`
- Never store private keys in plaintext
- Implement proper padding schemes (OAEP)
- Protect against side-channel attacks

## License
MIT License - See [LICENSE](LICENSE) file for details

---

<div align="center">
  <sub>Developed with ❤️ for cryptographic education</sub>
</div>