using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using MLSecurityScanner.Models;

namespace MLSecurityScanner.Services
{
    public class FileAnalyzer
    {
        private static readonly HashSet<string> SuspiciousKeywords = new HashSet<string>
        {
            "cmd.exe", "powershell", "wscript", "cscript", "rundll32", "regsvr32",
            "CreateProcess", "WinExec", "ShellExecute", "VirtualAlloc", "WriteProcessMemory",
            "CreateRemoteThread", "RegCreateKey", "RegSetValue", "InternetOpen",
            "URLDownloadToFile", "HttpSendRequest", "socket", "connect", "recv", "send",
            "WSASocket", "CreateService", "StartService", "CreateMutex", "OpenProcess",
            "GetProcAddress", "LoadLibrary", "SetWindowsHookEx", "CreateToolhelp32Snapshot"
        };

        public FileMetrics AnalyzeFile(string filePath)
        {
            if (!File.Exists(filePath))
                throw new FileNotFoundException($"File not found: {filePath}");

            var fileInfo = new FileInfo(filePath);

            var metrics = new FileMetrics
            {
                FileName = fileInfo.Name,
                FilePath = filePath,
                FileSize = fileInfo.Length,
                CreatedAt = DateTime.Now
            };

            // Byte dizisini oku
            byte[] fileBytes = File.ReadAllBytes(filePath);

            // 1. Entropi hesaplama
            metrics.EntropyScore = CalculateEntropy(fileBytes);

            // 2. PE Header kontrolü (executable dosyalar için)
            metrics.HasValidPEHeader = CheckPEHeader(fileBytes);

            // 3. String çıkarma ve analiz etme
            var extractedStrings = ExtractStrings(fileBytes);
            metrics.StringEntropyValue = CalculateStringsEntropy(extractedStrings);
            metrics.SuspiciousStringCount = CountSuspiciousStrings(extractedStrings);
            
            // 4. API çağrı analizi (basitleştirilmiş)
            metrics.SuspiciousAPICount = metrics.SuspiciousStringCount;
            
            // 5. Obfuscation analizi (basitleştirilmiş)
            metrics.ObfuscatedCodeRatio = CalculateObfuscationRatio(extractedStrings, fileBytes.Length);
            
            // 6. İmza doğrulama (basitleştirilmiş)
            metrics.HasValidSignature = metrics.EntropyScore < 7.0;
            
            // 7. Çalıştırılabilir kod segmentleri (basitleştirilmiş)
            metrics.ExecutableCodeRatio = metrics.HasValidPEHeader ? 0.7 : 0.2;
            
            // 8. Sıkıştırma oranı (basitleştirilmiş)
            metrics.CompressionRatio = CalculateCompressionRatio(fileBytes);
            
            // 9. Şifrelenmiş segment oranı tahmini (basitleştirilmiş)
            metrics.EncryptedSectionRatio = metrics.EntropyScore > 7.0 ? 0.8 : 0.1;

            return metrics;
        }

        private double CalculateEntropy(byte[] data)
        {
            if (data == null || data.Length == 0)
                return 0;

            var byteCounts = new int[256];
            foreach (byte b in data)
            {
                byteCounts[b]++;
            }

            double entropy = 0;
            int fileSize = data.Length;

            foreach (int count in byteCounts)
            {
                if (count == 0)
                    continue;

                double probability = (double)count / fileSize;
                entropy -= probability * Math.Log(probability, 2);
            }

            return entropy;
        }

        private bool CheckPEHeader(byte[] data)
        {
            if (data.Length < 64)
                return false;

            // MZ header kontrolü (0x4D, 0x5A)
            if (data[0] != 0x4D || data[1] != 0x5A)
                return false;

            // PE header offset'i (e_lfanew) al
            int peOffset = BitConverter.ToInt32(data, 60);
            if (peOffset < 0 || peOffset > data.Length - 4)
                return false;

            // PE imzası kontrolü (PE\0\0)
            return data[peOffset] == 0x50 && data[peOffset + 1] == 0x45 && data[peOffset + 2] == 0x00 && data[peOffset + 3] == 0x00;
        }

        private List<string> ExtractStrings(byte[] data, int minLength = 4)
        {
            var strings = new List<string>();
            var ascii = new Regex(@"[ -~]{" + minLength + ",}");

            string asciiText = Encoding.ASCII.GetString(data);
            var matches = ascii.Matches(asciiText);
            
            foreach (Match match in matches)
            {
                strings.Add(match.Value);
            }

            // Unicode için
            string unicodeText = Encoding.Unicode.GetString(data);
            matches = ascii.Matches(unicodeText);
            
            foreach (Match match in matches)
            {
                // Tekrarları önlemek için kontrol
                if (!strings.Contains(match.Value))
                    strings.Add(match.Value);
            }

            return strings;
        }

        private double CalculateStringsEntropy(List<string> strings)
        {
            if (strings == null || strings.Count == 0)
                return 0;

            var allChars = string.Join("", strings).ToCharArray();
            var charCounts = new Dictionary<char, int>();

            foreach (char c in allChars)
            {
                if (charCounts.ContainsKey(c))
                    charCounts[c]++;
                else
                    charCounts[c] = 1;
            }

            double entropy = 0;
            int totalChars = allChars.Length;

            foreach (var kvp in charCounts)
            {
                double probability = (double)kvp.Value / totalChars;
                entropy -= probability * Math.Log(probability, 2);
            }

            return entropy;
        }

        private int CountSuspiciousStrings(List<string> strings)
        {
            int count = 0;
            
            foreach (string str in strings)
            {
                foreach (string keyword in SuspiciousKeywords)
                {
                    if (str.Contains(keyword, StringComparison.OrdinalIgnoreCase))
                    {
                        count++;
                        break;
                    }
                }
            }
            
            return count;
        }

        private double CalculateObfuscationRatio(List<string> strings, int fileSize)
        {
            // Basit bir yaklaşım: Ortalama string uzunluğu kısa ise ve
            // toplam string sayısı az ise obfuscation oranı yüksektir
            if (strings.Count == 0)
                return 0.5;

            double avgLength = strings.Average(s => s.Length);
            double stringRatio = (double)string.Join("", strings).Length / fileSize;

            // 8 karakterden kısa ortalama string uzunluğu ve düşük string oranı genellikle obfuscation göstergesi
            if (avgLength < 8 && stringRatio < 0.2)
                return 0.8;
            else if (avgLength < 12 && stringRatio < 0.3)
                return 0.5;
            else
                return 0.2;
        }

        private double CalculateCompressionRatio(byte[] data)
        {
            try
            {
                using var memoryStream = new MemoryStream();
                using (var gzipStream = new System.IO.Compression.GZipStream(memoryStream, System.IO.Compression.CompressionMode.Compress))
                {
                    gzipStream.Write(data, 0, data.Length);
                }

                var compressedData = memoryStream.ToArray();
                return 1.0 - ((double)compressedData.Length / data.Length);
            }
            catch
            {
                // Hata durumunda varsayılan bir değer döndür
                return 0.3;
            }
        }
    }
} 