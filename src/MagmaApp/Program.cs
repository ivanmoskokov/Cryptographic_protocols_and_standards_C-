using System;
using System.IO;
using System.Text;

namespace CryptographicProtocols
{
    class Program
    {
        static void Main()
        {
            while (true)
            {
                Console.Clear();
                Console.WriteLine("GOST 28147-89 (Magma) Cipher");
                Console.WriteLine("1. Encrypt file");
                Console.WriteLine("2. Decrypt file");
                Console.WriteLine("3. Exit");
                Console.Write("Select operation: ");

                if (!int.TryParse(Console.ReadLine(), out int choice) || choice < 1 || choice > 3)
                {
                    ShowError("Invalid choice");
                    continue;
                }

                if (choice == 3) break;

                try
                {
                    string filePath = GetFilePath();
                    string key = GetEncryptionKey();
                    ProcessFile(filePath, key, choice == 2);
                }
                catch (Exception ex)
                {
                    ShowError(ex.Message);
                }
            }
        }

        private static string GetFilePath()
        {
            Console.Write("Enter file path: ");
            string path = Console.ReadLine()!;
            if (!File.Exists(path)) throw new FileNotFoundException("File not found");
            return path;
        }

        private static string GetEncryptionKey()
        {
            Console.Write("Enter 64-character hex key: ");
            string key = Console.ReadLine()!;
            if (key.Length != 64 || !System.Text.RegularExpressions.Regex.IsMatch(key, @"\A\b[0-9a-fA-F]+\b\Z"))
                throw new ArgumentException("Invalid key format");
            return key;
        }

        private static void ProcessFile(string inputPath, string key, bool decrypt)
        {
            byte[] data = File.ReadAllBytes(inputPath);
            byte[] processed = MagmaCipher.ProcessData(data, key, decrypt);

            string outputPath = decrypt 
                ? inputPath.Replace("_enc.txt", "_dec.txt") 
                : Path.Combine(
                    Path.GetDirectoryName(inputPath)!,
                    Path.GetFileNameWithoutExtension(inputPath) + "_enc.txt");

            File.WriteAllBytes(outputPath, processed);
            Console.WriteLine($"Operation completed. Output: {outputPath}");
            Console.ReadKey();
        }

        private static void ShowError(string message)
        {
            Console.WriteLine($"Error: {message}");
            Console.ReadKey();
        }
    }
}