using System;
using System.IO;
using System.Numerics;

class Program
{
    /// <summary>
    /// Reads file contents as byte array
    /// </summary>
    static byte[] ReadFile(string filePath)
    {
        try
        {
            return File.ReadAllBytes(filePath);
        }
        catch (Exception ex)
        {
            Console.WriteLine($"File read error: {ex.Message}");
            return null;
        }
    }

    /// <summary>
    /// Writes data to file
    /// </summary>
    static bool WriteFile(string filePath, byte[] data)
    {
        try
        {
            File.WriteAllBytes(filePath, data);
            return true;
        }
        catch (Exception ex)
        {
            Console.WriteLine($"File write error: {ex.Message}");
            return false;
        }
    }

    /// <summary>
    /// Reads a prime number from user input with validation
    /// </summary>
    static BigInteger ReadPrime(string prompt)
    {
        while (true)
        {
            Console.Write(prompt);
            if (BigInteger.TryParse(Console.ReadLine(), out BigInteger number))
            {
                if (number < 2)
                {
                    Console.WriteLine("Number must be greater than 1.");
                    continue;
                }

                if (RSACipher.IsProbablePrime(number, 10))
                {
                    return number;
                }
                else
                {
                    Console.WriteLine("Number is not prime. Try again.");
                }
            }
            else
            {
                Console.WriteLine("Invalid input. Enter an integer.");
            }
        }
    }

    /// <summary>
    /// Reads public exponent with validation
    /// </summary>
    static BigInteger ReadExponent(BigInteger phi)
    {
        while (true)
        {
            Console.Write($"Enter public exponent e (1 < e < {phi}, coprime with φ(N)): ");
            if (BigInteger.TryParse(Console.ReadLine(), out BigInteger e))
            {
                if (e <= 1 || e >= phi)
                {
                    Console.WriteLine($"Exponent must be in range: 1 < e < {phi}");
                    continue;
                }

                if (BigInteger.GreatestCommonDivisor(e, phi) != 1)
                {
                    Console.WriteLine($"Exponent e must be coprime with φ(N) = {phi}");
                    continue;
                }

                return e;
            }
            else
            {
                Console.WriteLine("Invalid input. Enter an integer.");
            }
        }
    }

    static void Main()
    {
        while (true)
        {
            Console.Clear();
            Console.WriteLine("RSA Encryption System");
            Console.WriteLine("1. Generate RSA keys");
            Console.WriteLine("2. Encrypt file");
            Console.WriteLine("3. Decrypt file");
            Console.WriteLine("4. Exit");
            Console.Write("Select option: ");

            if (!int.TryParse(Console.ReadLine(), out int choice) || choice < 1 || choice > 4)
            {
                Console.WriteLine("Invalid choice!");
                Console.ReadLine();
                continue;
            }

            if (choice == 4) break;

            Console.Clear();

            try
            {
                if (choice == 1)
                {
                    Console.WriteLine("RSA Key Generation:");
                    Console.WriteLine("1. Enter primes manually");
                    Console.WriteLine("2. Generate primes automatically");
                    Console.Write("Select method: ");
                    
                    int genChoice;
                    while (!int.TryParse(Console.ReadLine(), out genChoice) || genChoice < 1 || genChoice > 2)
                    {
                        Console.Write("Invalid choice. Enter 1 or 2: ");
                    }

                    BigInteger p, q;

                    if (genChoice == 1)
                    {
                        p = ReadPrime("Enter prime p: ");
                        q = ReadPrime("Enter prime q: ");
                        
                        while (p == q)
                        {
                            Console.WriteLine("Primes p and q must be different!");
                            q = ReadPrime("Enter prime q (different from p): ");
                        }
                    }
                    else
                    {
                        Console.Write("Enter prime size in bits (recommended 32-4096): ");
                        int bitSize;
                        while (!int.TryParse(Console.ReadLine(), out bitSize) || bitSize < 8 || bitSize > 4096)
                        {
                            Console.Write("Invalid size. Enter 8-4096: ");
                        }

                        Console.WriteLine("Generating primes...");
                        p = RSACipher.GeneratePrime(bitSize);
                        q = RSACipher.GeneratePrime(bitSize);
                        
                        while (p == q)
                        {
                            q = RSACipher.GeneratePrime(bitSize);
                        }

                        Console.WriteLine($"Generated p = {p}");
                        Console.WriteLine($"Generated q = {q}");
                    }

                    BigInteger N = p * q;
                    BigInteger phi = (p - 1) * (q - 1);

                    Console.WriteLine($"\nCalculated N = {N}");
                    Console.WriteLine($"Calculated φ(N) = {phi}");

                    Console.WriteLine("\nSelect public exponent e:");
                    Console.WriteLine("1. Use standard value 65537");
                    Console.WriteLine("2. Enter manually");
                    Console.Write("Select option: ");
                    
                    int eChoice;
                    while (!int.TryParse(Console.ReadLine(), out eChoice) || eChoice < 1 || eChoice > 2)
                    {
                        Console.Write("Invalid choice. Enter 1 or 2: ");
                    }

                    BigInteger e;
                    if (eChoice == 1)
                    {
                        e = 65537;
                        if (e >= phi || BigInteger.GreatestCommonDivisor(e, phi) != 1)
                        {
                            Console.WriteLine("Standard e=65537 is invalid for these primes.");
                            Console.WriteLine("Try different primes or enter e manually.");
                            return;
                        }
                    }
                    else
                    {
                        e = ReadExponent(phi);
                    }

                    BigInteger d = RSACipher.ModInverse(e, phi);

                    Console.WriteLine("\nPublic key (e, N):");
                    Console.WriteLine($"e = {e}");
                    Console.WriteLine($"N = {N}");

                    Console.WriteLine("\nPrivate key (d, N):");
                    Console.WriteLine($"d = {d}");
                    Console.WriteLine($"N = {N}");

                    Console.WriteLine("\nSave these keys securely!");
                }
                else if (choice == 2 || choice == 3)
                {
                    Console.Write("Enter file path: ");
                    string filePath = Console.ReadLine();

                    if (!File.Exists(filePath))
                    {
                        Console.WriteLine("File not found!");
                        Console.ReadLine();
                        continue;
                    }

                    byte[] fileData = ReadFile(filePath);
                    if (fileData == null)
                    {
                        Console.ReadLine();
                        continue;
                    }

                    Console.Write("Enter modulus N: ");
                    BigInteger N = BigInteger.Parse(Console.ReadLine());

                    byte[] result;
                    string outputFile;

                    if (choice == 2)
                    {
                        Console.Write("Enter public exponent e: ");
                        BigInteger e = BigInteger.Parse(Console.ReadLine());

                        result = RSACipher.EncryptData(fileData, e, N);
                        outputFile = Path.ChangeExtension(filePath, "enc.txt");
                        Console.WriteLine("Encryption complete.");
                    }
                    else
                    {
                        Console.Write("Enter private exponent d: ");
                        BigInteger d = BigInteger.Parse(Console.ReadLine());

                        result = RSACipher.DecryptData(fileData, d, N);
                        outputFile = Path.ChangeExtension(filePath[..^6], "dec.txt");
                        Console.WriteLine("Decryption complete.");
                    }

                    if (WriteFile(outputFile, result))
                    {
                        Console.WriteLine($"Result saved to: {outputFile}");
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error: {ex.Message}");
            }

            Console.ReadLine();
        }
    }
}