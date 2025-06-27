using System;

namespace CryptographicProtocols
{
    /// <summary>
    /// GOST 28147-89 (Magma) cipher implementation
    /// </summary>
    public class MagmaCipher
    {
        // S-boxes (GOST R 34.11-94 standard)
        private static readonly byte[,] SBox = {
            {1,7,14,13,0,5,8,3,4,15,10,6,9,12,11,2},
            {8,14,2,5,6,9,1,12,15,4,11,0,13,10,3,7},
            {5,13,15,6,9,2,12,10,11,7,8,1,4,3,14,0},
            {7,15,5,10,8,1,6,13,0,9,3,14,11,4,2,12},
            {12,8,2,1,13,4,15,6,7,0,10,5,3,14,9,11},
            {11,3,5,8,2,15,10,13,14,1,7,4,12,9,6,0},
            {6,8,2,3,9,10,5,12,1,14,4,7,11,13,0,15},
            {12,4,6,2,10,5,11,9,14,8,13,7,0,3,15,1}
        };

        /// <summary>
        /// Encrypts data using Magma algorithm
        /// </summary>
        /// <param name="data">Input data to encrypt</param>
        /// <param name="key">256-bit key as hex string</param>
        /// <param name="decrypt">Decryption mode flag</param>
        /// <returns>Processed byte array</returns>
        public static byte[] ProcessData(byte[] data, string key, bool decrypt = false)
        {
            // Add PKCS7 padding before processing
            byte[] paddedData = AddPadding(data);
            uint[] keyParts = KeyToUInts(key);
            uint[] roundKeys = GenerateRoundKeys(keyParts, decrypt);
            byte[] result = new byte[paddedData.Length];

            for (int i = 0; i < paddedData.Length; i += 8)
            {
                ulong block = BitConverter.ToUInt64(paddedData, i);
                ulong processed = ProcessBlock(block, roundKeys);
                Buffer.BlockCopy(BitConverter.GetBytes(processed), 0, result, i, 8);
            }

            return decrypt ? RemovePadding(result) : result;
        }

        private static byte[] AddPadding(byte[] data)
        {
            int padLength = (8 - (data.Length % 8)) % 8;
            if (padLength == 0) return (byte[])data.Clone();
            
            byte[] padded = new byte[data.Length + padLength];
            Array.Copy(data, padded, data.Length);
            for (int i = data.Length; i < padded.Length; i++)
            {
                padded[i] = (byte)padLength;
            }
            return padded;
        }

        private static byte[] RemovePadding(byte[] data)
        {
            int padLength = data[^1];
            if (padLength > 0 && padLength <= 8)
                return data[..^padLength];
            return data;
        }

        private static uint[] KeyToUInts(string key)
        {
            if (key.Length != 64)
                throw new ArgumentException("Key must be 64 hex characters (256 bits)");

            uint[] result = new uint[8];
            for (int i = 0; i < 8; i++)
                result[i] = Convert.ToUInt32(key.Substring(i * 8, 8), 16);
            return result;
        }

        private static uint[] GenerateRoundKeys(uint[] key, bool forDecryption)
        {
            uint[] roundKeys = new uint[32];
            
            // First 24 rounds: K1..K8 repeated 3 times
            for (int i = 0; i < 24; i++)
                roundKeys[i] = key[i % 8];
            
            // Last 8 rounds: K8..K1 in reverse
            for (int i = 24; i < 32; i++)
                roundKeys[i] = key[7 - (i - 24)];
            
            return forDecryption ? roundKeys.Reverse().ToArray() : roundKeys;
        }

        private static ulong ProcessBlock(ulong block, uint[] roundKeys)
        {
            uint left = (uint)(block >> 32);
            uint right = (uint)(block & 0xFFFFFFFF);
            
            for (int round = 0; round < 32; round++)
            {
                uint fResult = F(right, roundKeys[round]);
                (left, right) = (right, left ^ fResult);
            }
            
            return ((ulong)right << 32) | left;
        }

        private static uint F(uint block, uint roundKey)
        {
            uint value = block + roundKey; // mod 2^32
            value = Substitute(value);
            return (value << 11) | (value >> 21); // Rotate left 11
        }

        private static uint Substitute(uint value)
        {
            uint result = 0;
            for (int i = 0; i < 8; i++)
            {
                byte nibble = (byte)((value >> (4 * i)) & 0xF);
                result |= (uint)(SBox[7 - i, nibble] << (4 * i));
            }
            return result;
        }
    }
}