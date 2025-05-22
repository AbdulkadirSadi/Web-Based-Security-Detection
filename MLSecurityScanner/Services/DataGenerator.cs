using System;
using System.Collections.Generic;
using System.IO;
using MLSecurityScanner.Models;

namespace MLSecurityScanner.Services
{
    public class DataGenerator
    {
        private readonly Random _random = new Random();
        
        /// <summary>
        /// Yapay zeka modelini eğitmek için sentetik veri üretir
        /// </summary>
        /// <param name="count">Üretilecek örnek sayısı</param>
        /// <returns>ScanResultModel listesi</returns>
        public List<ScanResultModel> GenerateSyntheticData(int count)
        {
            var result = new List<ScanResultModel>();
            
            // Zararlı ve zararsız dağılımı: %30 zararlı, %70 zararsız
            int malwareCount = (int)(count * 0.3);
            int benignCount = count - malwareCount;
            
            // Zararlı örnekler oluştur
            for (int i = 0; i < malwareCount; i++)
            {
                // %15 ihtimalle zararlıyı zararsız olarak etiketle (gürültü ekle)
                bool wronglyLabeled = _random.NextDouble() <= 0.15;
                var data = GenerateSyntheticMalwareData();
                
                if (wronglyLabeled)
                {
                    // Zararlı dosyayı zararsız olarak etiketleme - gerçek dünyada olabilecek yanlış tespitler
                    data.IsMalicious = false;
                    data.DetectedBy = "";
                    data.DetectedPatterns = "";
                }
                
                result.Add(data);
            }
            
            // Zararsız örnekler oluştur
            for (int i = 0; i < benignCount; i++)
            {
                // %10 ihtimalle zararsızı zararlı olarak etiketle (gürültü ekle)
                bool wronglyLabeled = _random.NextDouble() <= 0.10;
                var data = GenerateSyntheticBenignData();
                
                if (wronglyLabeled)
                {
                    // Zararsız dosyayı zararlı olarak etiketleme - gerçek dünyada olabilecek false positive'ler
                    data.IsMalicious = true;
                    var detectionEngine = new[] { "Avast", "Kaspersky", "Microsoft", "Symantec" }[_random.Next(4)];
                    data.DetectedBy = detectionEngine;
                    data.DetectedPatterns = "PUA:Win32/FalsePositive";
                }
                
                result.Add(data);
            }
            
            return result;
        }
        
        private ScanResultModel GenerateSyntheticMalwareData()
        {
            // Bazı zararlılarda (%20) düşük entropi değerleri kullan
            bool useLowEntropy = _random.NextDouble() <= 0.20;
            // Bazı zararlılarda (%15) düşük şüpheli API sayısı kullan
            bool useLowAPICount = _random.NextDouble() <= 0.15;
            
            var model = new ScanResultModel
            {
                FileName = GenerateRandomFileName(true),
                FilePath = $"C:\\SyntheticData\\Malware\\{Guid.NewGuid()}",
                ScanDate = DateTime.Now.AddDays(-_random.Next(1, 60)),
                IsMalicious = true,
                IsGeneratedData = true,
                
                // Zararlı yazılımlar için metrikler - daha çeşitli ve gerçekçi değerler
                FileSize = _random.Next(10_000, 50_000_000), // Daha geniş dosya boyutu aralığı
                // Bazı zararlılar düşük entropi gösterebilir
                EntropyScore = useLowEntropy 
                    ? 4.5 + (_random.NextDouble() * 2.0)   // 4.5 - 6.5 (zararsıza benzer)
                    : 5.8 + (_random.NextDouble() * 2.2),  // 5.8 - 8.0 (tipik zararlı)
                HasValidPEHeader = _random.NextDouble() > 0.25, // %75 ihtimalle geçerli
                // Zararlı yazılımlarda değişken sayıda şüpheli API
                SuspiciousAPICount = useLowAPICount 
                    ? _random.Next(0, 3)      // Zararsıza benzer düşük sayıda API
                    : _random.Next(2, 25),    // Tipik zararlı API sayısı
                StringEntropyValue = 4.5 + (_random.NextDouble() * 3.0), // 4.5 - 7.5 (daha geniş aralık)
                SuspiciousStringCount = _random.Next(1, 20), // Daha geniş aralık
                ObfuscatedCodeRatio = 0.3 + (_random.NextDouble() * 0.6), // 0.3 - 0.9 (daha geniş)
                HasValidSignature = _random.NextDouble() > 0.85, // %15 ihtimalle geçerli (biraz daha gerçekçi)
                ExecutableCodeRatio = 0.3 + (_random.NextDouble() * 0.5), // 0.3 - 0.8 
                CompressionRatio = 0.1 + (_random.NextDouble() * 0.5), // 0.1 - 0.6 (daha değişken)
                EncryptedSectionRatio = 0.1 + (_random.NextDouble() * 0.7), // 0.1 - 0.8 (daha değişken)
                
                // VirusTotal benzeri sonuçlar - daha değişken
                // Bazı zararlılar az sayıda motor tarafından tespit edilebilir
                VirusTotalDetectionCount = _random.Next(1, 45), // 1-45 arası tespit (daha gerçekçi)
                VirusTotalTotalScans = _random.Next(45, 70) // 45-70 arası toplam tarama
            };
            
            // Tespit bilgileri
            var detectionEngines = new[] { "Avast", "Kaspersky", "Microsoft", "Symantec", "McAfee", "ClamAV", "BitDefender" };
            var detectionTypes = new[] { "Trojan", "Backdoor", "Worm", "Ransomware", "Spyware", "Adware", "Rootkit" };
            
            // Tespit eden motor sayısı değişken
            int engineCount = Math.Max(1, (int)Math.Round(model.VirusTotalDetectionCount / 10.0));
            var selectedEngines = new List<string>();
            
            for (int i = 0; i < engineCount && i < detectionEngines.Length; i++)
            {
                selectedEngines.Add(detectionEngines[_random.Next(detectionEngines.Length)]);
            }
            
            model.DetectedBy = string.Join(", ", selectedEngines);
            model.DetectedPatterns = $"{detectionTypes[_random.Next(detectionTypes.Length)]}.{GenerateRandomString(5, 8)}";
            
            return model;
        }
        
        private ScanResultModel GenerateSyntheticBenignData()
        {
            // Bazı zararsızlarda (%20) yüksek entropi değerleri kullan (zararlıya benzer)
            bool useHighEntropy = _random.NextDouble() <= 0.20;
            // Bazı zararsızlarda (%10) yüksek şüpheli API sayısı kullan
            bool useHighAPICount = _random.NextDouble() <= 0.10;
            
            var model = new ScanResultModel
            {
                FileName = GenerateRandomFileName(false),
                FilePath = $"C:\\SyntheticData\\Benign\\{Guid.NewGuid()}",
                ScanDate = DateTime.Now.AddDays(-_random.Next(1, 60)),
                IsMalicious = false,
                IsGeneratedData = true,
                
                // Zararsız yazılımlar için metrikler - gerçek dünyaya daha yakın
                FileSize = _random.Next(5_000, 200_000_000), // Daha geniş dosya boyutu aralığı
                // Bazı zararsız dosyalar yüksek entropi gösterebilir (sıkıştırılmış/şifreli içerik)
                EntropyScore = useHighEntropy 
                    ? 5.5 + (_random.NextDouble() * 2.5)  // 5.5 - 8.0 (zararlıya benzer yüksek entropi)
                    : 3.0 + (_random.NextDouble() * 3.5), // 3.0 - 6.5 (tipik zararsız)
                HasValidPEHeader = _random.NextDouble() > 0.15, // %85 ihtimalle geçerli
                // Zararsız dosyalarda değişken sayıda API (bazen meşru nedenlerle şüpheli API'ler içerebilir)
                SuspiciousAPICount = useHighAPICount 
                    ? _random.Next(2, 8)     // Zararlıya benzer API sayısı (meşru sebeplerle)
                    : _random.Next(0, 3),    // Tipik zararsız API sayısı
                StringEntropyValue = 2.5 + (_random.NextDouble() * 4.0), // 2.5 - 6.5 
                SuspiciousStringCount = useHighAPICount 
                    ? _random.Next(1, 5)     // Zararlıya benzer şüpheli string sayısı
                    : _random.Next(0, 2),    // Tipik zararsız şüpheli string sayısı
                ObfuscatedCodeRatio = _random.NextDouble() * 0.5, // 0.0 - 0.5
                HasValidSignature = _random.NextDouble() > 0.25, // %75 ihtimalle geçerli
                ExecutableCodeRatio = 0.1 + (_random.NextDouble() * 0.6), // 0.1 - 0.7
                CompressionRatio = useHighEntropy 
                    ? 0.2 + (_random.NextDouble() * 0.3)   // 0.2 - 0.5 (daha yüksek sıkıştırma)
                    : 0.05 + (_random.NextDouble() * 0.15), // 0.05 - 0.2 (tipik)
                EncryptedSectionRatio = useHighEntropy 
                    ? 0.1 + (_random.NextDouble() * 0.2)   // 0.1 - 0.3 (yüksek şifreleme)
                    : _random.NextDouble() * 0.1,           // 0.0 - 0.1 (tipik)
                
                // VirusTotal benzeri sonuçlar
                // False positive oranı artırıldı
                VirusTotalDetectionCount = _random.NextDouble() <= 0.20 
                    ? _random.Next(1, 3)   // False positive: 1-3 motor tespit etti
                    : 0,                   // Çoğunluk: Hiçbir motor tespit etmedi
                VirusTotalTotalScans = _random.Next(45, 70),
                
                // Tespit bilgileri
                DetectedBy = "",
                DetectedPatterns = ""
            };
            
            // False positive durumları için
            if (model.VirusTotalDetectionCount > 0)
            {
                var detectionEngines = new[] { "Avast", "Kaspersky", "Microsoft", "Symantec", "McAfee", "ClamAV", "BitDefender" };
                model.DetectedBy = detectionEngines[_random.Next(detectionEngines.Length)];
                var falsePositivePatterns = new[] { "PUA:Win32/ToolSpy", "Riskware.Tool", "PUP.Optional", "Unwanted.Program", "Suspicious.ML" };
                model.DetectedPatterns = falsePositivePatterns[_random.Next(falsePositivePatterns.Length)];
            }
            
            return model;
        }
        
        private string GenerateRandomFileName(bool isMalware)
        {
            var extensions = isMalware
                ? new[] { ".exe", ".dll", ".bat", ".com", ".scr", ".pif", ".js", ".vbs" }
                : new[] { ".exe", ".dll", ".txt", ".docx", ".pdf", ".jpg", ".png", ".msi", ".zip" };
                
            var baseNames = isMalware
                ? new[] { "setup", "install", "update", "patch", "crack", "keygen", "activator", "driver", "tool", "fixer" }
                : new[] { "document", "report", "presentation", "invoice", "image", "screenshot", "backup", "data", "project", "notes" };
                
            string baseName = baseNames[_random.Next(baseNames.Length)];
            string extension = extensions[_random.Next(extensions.Length)];
            
            if (_random.NextDouble() > 0.5)
            {
                baseName += "_" + GenerateRandomString(3, 5);
            }
            
            return baseName + extension;
        }
        
        private string GenerateRandomString(int minLength, int maxLength)
        {
            const string chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
            int length = _random.Next(minLength, maxLength + 1);
            
            var stringBuilder = new System.Text.StringBuilder(length);
            for (int i = 0; i < length; i++)
            {
                stringBuilder.Append(chars[_random.Next(chars.Length)]);
            }
            
            return stringBuilder.ToString();
        }
    }
} 