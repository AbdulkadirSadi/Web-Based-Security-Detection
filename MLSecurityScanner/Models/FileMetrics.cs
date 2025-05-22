using System;
using System.ComponentModel.DataAnnotations;

namespace MLSecurityScanner.Models
{
    public class FileMetrics
    {
        [Key]
        public int Id { get; set; }
        
        public required string FileName { get; set; }
        
        public required string FilePath { get; set; }
        
        public long FileSize { get; set; } // Dosya boyutu (byte)
        
        public double EntropyScore { get; set; } // Dosya içeriğinin entropi değeri
        
        public bool HasValidPEHeader { get; set; } // Executable dosyalar için PE header kontrolü
        
        public int SuspiciousAPICount { get; set; } // Şüpheli API çağrı sayısı
        
        public double StringEntropyValue { get; set; } // String değerlerinin entropi değeri
        
        public int SuspiciousStringCount { get; set; } // Şüpheli keyword sayısı
        
        public double ObfuscatedCodeRatio { get; set; } // Obfuscated kod oranı
        
        public bool HasValidSignature { get; set; } // İmza doğrulama sonucu
        
        public double ExecutableCodeRatio { get; set; } // Çalıştırılabilir kod segmentleri yüzdesi
        
        public double CompressionRatio { get; set; } // Sıkıştırma oranı
        
        public double EncryptedSectionRatio { get; set; } // Şifrelenmiş bölüm oranı
        
        public bool IsMalware { get; set; } // Etiket: Zararlı mı?
        
        public DateTime CreatedAt { get; set; } = DateTime.Now;
        
        public bool IsGeneratedData { get; set; } // Sentetik veri mi?
        
        public string? DetectedBy { get; set; } // VirusTotal veya başka bir motor tarafından tespit edildi mi?
        
        public string? DetectionPatterns { get; set; } // Tespit edilen desenler
        
        public int VirusTotalDetectionCount { get; set; } // VirusTotal'da kaç motor tarafından tespit edildi
        
        public int VirusTotalTotalScans { get; set; } // VirusTotal'da toplam tarama sayısı
        
        public float VirusTotalDetectionRatio => 
            VirusTotalTotalScans > 0 ? (float)VirusTotalDetectionCount / VirusTotalTotalScans : 0;
    }
} 