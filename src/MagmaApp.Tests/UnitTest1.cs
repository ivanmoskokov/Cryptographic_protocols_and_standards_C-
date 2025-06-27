using MagmaApp;
using NUnit.Framework;

namespace MagmaApp.Tests;

[TestFixture]
public class MagmaTests
{
    private const string TestKey = "FFEEDDCCBBAA99887766554433221100F0F1F2F3F4F5F6F7F8F9FAFBFCFDFEFF";
    
    [Test]
    public void ProcessData_EncryptThenDecrypt_ReturnsOriginal()
    {
        // Arrange
        byte[] original = { 0x01, 0x02, 0x03, 0x04 };
        
        // Act
        byte[] encrypted = MagmaCipher.ProcessData(original, TestKey);
        byte[] decrypted = MagmaCipher.ProcessData(encrypted, TestKey, decrypt: true);
        
        // Assert
        Assert.That(decrypted, Is.EqualTo(original));
    }

    [Test]
    public void ProcessData_WithEmptyData_ThrowsException()
    {
        // Arrange
        byte[] emptyData = Array.Empty<byte>();
        
        // Act & Assert
        Assert.Throws<ArgumentException>(() => 
            MagmaCipher.ProcessData(emptyData, TestKey));
    }
}