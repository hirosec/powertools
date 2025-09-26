// # Copyright (c) HIROSEC. All rights reserved.
// # Licensed under the MIT License.

// 2025/09/26
// C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe -out:XORCrypter.exe XORCrypter.cs

using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

class XORCrypter
{
	private byte key; 
	
	public XORCrypter(byte key)
	{
		this.key = key;
	}
	
	public void EncryptFile(string filePath)
	{
		byte[] data = File.ReadAllBytes(filePath);
			
		for (int i = 0; i < data.Length; i++)
		{
			data[i] ^= key;
		}
			
		File.WriteAllBytes(filePath, data);
	}
	
	static void Main(string[] args)
	{
		byte encryptionKey = 0x12;

		string XORkey = encryptionKey.ToString("x2");
		
		string filePath = args[0];
		
		if (!File.Exists(filePath))
        {
			Console.WriteLine("ERROR - Filename not found : " + filePath);
			return;
		}
		
		string md5Hash = CalculateMD5(filePath);
				
		Console.WriteLine("Filename : " + filePath);
		Console.WriteLine("MD5 hash : " + md5Hash);
		Console.WriteLine("XOR Key  : 0x" + XORkey);
		
		XORCrypter crypter = new XORCrypter(encryptionKey);

		crypter.EncryptFile(filePath);
	}
	
    static string CalculateMD5(string filePath)
    {
        using (var md5 = MD5.Create())
        using (var stream = File.OpenRead(filePath))
        {
            byte[] hashBytes = md5.ComputeHash(stream);
            StringBuilder sb = new StringBuilder();
            foreach (byte b in hashBytes)
                sb.Append(b.ToString("x2"));
            return sb.ToString();
        }
    }

}