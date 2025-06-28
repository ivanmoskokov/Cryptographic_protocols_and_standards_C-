using System;
using System.IO;
using System.Numerics;
using System.Linq;

/// <summary>
/// RSA asymmetric encryption algorithm implementation with enhanced error handling and optimizations
/// </summary>
public static class RSACipher
{
    // Small primes for preliminary primality testing
    private static readonly int[] SmallPrimes = { 2, 3, 5, 7, 11, 13, 17, 19, 23, 29 };

    /// <summary>
    /// Encrypts a single block of data using RSA
    /// </summary>
    /// <param name="block">Data block to encrypt (cannot be null or empty)</param>
    /// <param name="exponent">Public/private exponent</param>
    /// <param name="modulus">Modulus N (must be > 1)</param>
    /// <returns>Encrypted block</returns>
    /// <exception cref="ArgumentException">Invalid input parameters</exception>
    public static byte[] EncryptBlock(byte[] block, BigInteger exponent, BigInteger modulus)
    {
        // Input validation
        if (block == null || block.Length == 0)
            throw new ArgumentException("Block cannot be null or empty", nameof(block));
        if (modulus <= 1)
            throw new ArgumentException("Modulus must be greater than 1", nameof(modulus));

        try
        {
            // Convert block to BigInteger (unsigned, big-endian)
            BigInteger message = new BigInteger(block, isUnsigned: true, isBigEndian: true);
            
            // Verify message is smaller than modulus
            if (message >= modulus)
                throw new ArgumentException($"Message is too large for modulus N (message: {message}, N: {modulus})");

            // Perform modular exponentiation: ciphertext = message^exponent mod N
            BigInteger encrypted = BigInteger.ModPow(message, exponent, modulus);
            
            return encrypted.ToByteArray(isUnsigned: true, isBigEndian: true);
        }
        catch (Exception ex)
        {
            throw new CryptographicException("Block encryption failed", ex);
        }
    }

    /// <summary>
    /// Decrypts a single block of data using RSA
    /// </summary>
    /// <param name="block">Encrypted data block (cannot be null or empty)</param>
    /// <param name="exponent">Private/public exponent</param>
    /// <param name="modulus">Modulus N (must be > 1)</param>
    /// <returns>Decrypted block</returns>
    /// <exception cref="ArgumentException">Invalid input parameters</exception>
    public static byte[] DecryptBlock(byte[] block, BigInteger exponent, BigInteger modulus)
    {
        // Input validation
        if (block == null || block.Length == 0)
            throw new ArgumentException("Block cannot be null or empty", nameof(block));
        if (modulus <= 1)
            throw new ArgumentException("Modulus must be greater than 1", nameof(modulus));

        try
        {
            BigInteger encrypted = new BigInteger(block, isUnsigned: true, isBigEndian: true);
            
            if (encrypted >= modulus)
                throw new ArgumentException($"Encrypted message is too large for modulus N (encrypted: {encrypted}, N: {modulus})");

            BigInteger decrypted = BigInteger.ModPow(encrypted, exponent, modulus);
            return decrypted.ToByteArray(isUnsigned: true, isBigEndian: true);
        }
        catch (Exception ex)
        {
            throw new CryptographicException("Block decryption failed", ex);
        }
    }

    /// <summary>
    /// Encrypts data using RSA with block processing
    /// </summary>
    /// <param name="data">Data to encrypt (cannot be null)</param>
    /// <param name="exponent">Public exponent</param>
    /// <param name="modulus">Modulus N</param>
    /// <returns>Encrypted data</returns>
    /// <exception cref="ArgumentNullException">Data is null</exception>
    public static byte[] EncryptData(byte[] data, BigInteger exponent, BigInteger modulus)
    {
        if (data == null)
            throw new ArgumentNullException(nameof(data));
        if (data.Length == 0)
            return Array.Empty<byte>();

        int blockSize = GetBlockSize(modulus) - 1; // Leave space for padding
        if (blockSize <= 0)
            throw new InvalidOperationException("Invalid block size calculated");

        using (MemoryStream ms = new MemoryStream())
        {
            for (int offset = 0; offset < data.Length; offset += blockSize)
            {
                int chunkSize = Math.Min(blockSize, data.Length - offset);
                byte[] block = new byte[chunkSize];
                Buffer.BlockCopy(data, offset, block, 0, chunkSize);
                
                byte[] encryptedBlock = EncryptBlock(block, exponent, modulus);
                ms.Write(encryptedBlock, 0, encryptedBlock.Length);
            }
            return ms.ToArray();
        }
    }

    /// <summary>
    /// Decrypts data using RSA with block processing
    /// </summary>
    /// <param name="data">Encrypted data (cannot be null)</param>
    /// <param name="exponent">Private exponent</param>
    /// <param name="modulus">Modulus N</param>
    /// <returns>Decrypted data</returns>
    /// <exception cref="ArgumentNullException">Data is null</exception>
    public static byte[] DecryptData(byte[] data, BigInteger exponent, BigInteger modulus)
    {
        if (data == null)
            throw new ArgumentNullException(nameof(data));
        if (data.Length == 0)
            return Array.Empty<byte>();

        int blockSize = GetBlockSize(modulus);
        if (blockSize <= 0)
            throw new InvalidOperationException("Invalid block size calculated");

        using (MemoryStream ms = new MemoryStream())
        {
            for (int offset = 0; offset < data.Length; offset += blockSize)
            {
                int chunkSize = Math.Min(blockSize, data.Length - offset);
                byte[] block = new byte[chunkSize];
                Buffer.BlockCopy(data, offset, block, 0, chunkSize);
                
                byte[] decryptedBlock = DecryptBlock(block, exponent, modulus);
                ms.Write(decryptedBlock, 0, decryptedBlock.Length);
            }
            return ms.ToArray();
        }
    }

    /// <summary>
    /// Calculates the appropriate block size for a given modulus
    /// </summary>
    /// <param name="modulus">Modulus N (must be > 1)</param>
    /// <returns>Block size in bytes</returns>
    /// <exception cref="ArgumentException">Invalid modulus</exception>
    public static int GetBlockSize(BigInteger modulus)
    {
        if (modulus <= 1)
            throw new ArgumentException("Modulus must be greater than 1", nameof(modulus));

        return modulus.ToByteArray(isUnsigned: true, isBigEndian: true).Length;
    }

    /// <summary>
    /// Generates a probable prime number using optimized Miller-Rabin test
    /// </summary>
    /// <param name="bitSize">Size in bits (must be ≥ 32)</param>
    /// <returns>Probable prime number</returns>
    /// <exception cref="ArgumentException">Invalid bit size</exception>
    public static BigInteger GeneratePrime(int bitSize)
    {
        if (bitSize < 32)
            throw new ArgumentException("Bit size must be at least 32", nameof(bitSize));

        Random random = new Random();
        byte[] bytes = new byte[bitSize / 8 + 1];
        
        for (int attempt = 0; attempt < 1000; attempt++) // Limit attempts
        {
            random.NextBytes(bytes);
            bytes[bytes.Length - 1] &= 0x7F; // Ensure positive
            BigInteger candidate = new BigInteger(bytes);

            // Ensure minimum size and odd number
            if (candidate.GetBitLength() < bitSize || candidate.IsEven)
                candidate = BigInteger.Abs(candidate) | 1;

            // Quick check against small primes
            if (SmallPrimes.Any(p => candidate != p && candidate % p == 0))
                continue;

            // Faster probabilistic test
            if (IsProbablePrime(candidate, certainty: 5))
                return candidate;
        }

        throw new CryptographicException("Failed to generate prime number after 1000 attempts");
    }

    /// <summary>
    /// Miller-Rabin primality test with optimized checks
    /// </summary>
    /// <param name="n">Number to test</param>
    /// <param name="certainty">Number of test rounds (higher = more certain)</param>
    /// <returns>True if probable prime</returns>
    public static bool IsProbablePrime(BigInteger n, int certainty)
    {
        // Handle small primes and even numbers quickly
        if (n == 2 || n == 3) return true;
        if (n < 2 || n.IsEven) return false;

        // Write n-1 as d*2^s
        BigInteger d = n - 1;
        int s = 0;
        while (d.IsEven)
        {
            d >>= 1;
            s++;
        }

        Random random = new Random();
        byte[] bytes = new byte[n.ToByteArray().Length];

        for (int i = 0; i < certainty; i++)
        {
            BigInteger a;
            do
            {
                random.NextBytes(bytes);
                a = new BigInteger(bytes);
            }
            while (a < 2 || a >= n - 1);

            BigInteger x = BigInteger.ModPow(a, d, n);
            if (x == 1 || x == n - 1)
                continue;

            for (int j = 0; j < s - 1; j++)
            {
                x = BigInteger.ModPow(x, 2, n);
                if (x == 1) return false;
                if (x == n - 1) break;
            }

            if (x != n - 1) return false;
        }

        return true;
    }

    /// <summary>
    /// Calculates modular inverse using extended Euclidean algorithm
    /// </summary>
    /// <param name="a">Number</param>
    /// <param name="m">Modulus</param>
    /// <returns>Inverse of a modulo m</returns>
    /// <exception cref="ArithmeticException">No inverse exists</exception>
    public static BigInteger ModInverse(BigInteger a, BigInteger m)
    {
        if (a == 0)
            throw new ArithmeticException("Zero has no modular inverse");

        BigInteger m0 = m;
        BigInteger y = 0, x = 1;

        if (m == 1)
            return 0;

        while (a > 1)
        {
            if (m == 0)
                throw new ArithmeticException("No modular inverse exists");

            BigInteger q = a / m;
            BigInteger t = m;

            m = a % m;
            a = t;
            t = y;

            y = x - q * y;
            x = t;
        }

        if (x < 0)
            x += m0;

        return x;
    }

    /// <summary>
    /// Generates RSA key pair with validation
    /// </summary>
    /// <param name="bitSize">Prime size in bits (must be ≥ 128 and ≤ 4096)</param>
    /// <param name="e">Public exponent (default 65537)</param>
    /// <returns>Tuple of (N, e, d)</returns>
    /// <exception cref="ArgumentException">Invalid parameters</exception>
    public static (BigInteger N, BigInteger e, BigInteger d) GenerateKeyPair(int bitSize, BigInteger e = default)
    {
        if (bitSize < 128 || bitSize > 4096)
            throw new ArgumentException("Bit size must be between 128 and 4096", nameof(bitSize));

        if (e == default) 
            e = 65537;
        else if (e < 3)
            throw new ArgumentException("Public exponent must be at least 3", nameof(e));

        // Generate distinct primes
        BigInteger p = GeneratePrime(bitSize);
        BigInteger q;
        do {
            q = GeneratePrime(bitSize);
        } while (q == p);

        BigInteger N = p * q;
        BigInteger phi = (p - 1) * (q - 1);

        // Validate public exponent
        if (e >= phi)
            throw new ArgumentException($"Public exponent e must be less than φ(N) ({phi})");
        if (BigInteger.GreatestCommonDivisor(e, phi) != 1)
            throw new ArgumentException($"Public exponent e must be coprime with φ(N) ({phi})");

        BigInteger d = ModInverse(e, phi);
        return (N, e, d);
    }
}

/// <summary>
/// Custom exception for cryptographic operations
/// </summary>
public class CryptographicException : Exception
{
    public CryptographicException() { }
    public CryptographicException(string message) : base(message) { }
    public CryptographicException(string message, Exception inner) : base(message, inner) { }
}