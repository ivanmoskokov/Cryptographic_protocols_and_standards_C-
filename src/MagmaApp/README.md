# GOST 28147-89 (Magma) Implementation

C# implementation of Russian block cipher standard (GOST 28147-89).

## Features
- 256-bit key support
- ECB mode operation
- PKCS#7 padding
- Console interface

## Usage
### Encryption
```csharp
var cipher = new MagmaCipher();
byte[] encrypted = cipher.Encrypt(
    File.ReadAllBytes("test.txt"),
    Encoding.ASCII.GetBytes("my-256-bit-key-here-1234567890ABCDEF")
);
```

### Test Vectors
Directory `test_vectors/` contains:
- `test.txt` - Original text
- `test_enc.txt` - Encrypted result
- `test_enc_dec.txt` - Decrypted result

Example test key (hex):  
`FFEEDDCCBBAA99887766554433221100F0F1F2F3F4F5F6F7F8F9FAFBFCFDFEFF`

## Technical Details
### S-Boxes
Uses standard GOST R 34.11-94 S-boxes:
```csharp
static readonly byte[,] SBox = {
    {1, 7, 14, 13, 0, 5, 8, 3, 4, 15, 10, 6, 9, 12, 11, 2},
    // ... 7 more S-boxes
};
```

## Build & Run
```bash
dotnet build
dotnet run --project src/Magma/
```