using System;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace SecurityAgent.Models
{
    public class ScanResultModel
    {
        [Key]
        public int Id { get; set; }
        
        public string FilePath { get; set; }
        
        public string FileName { get; set; }
        
        public DateTime ScanDate { get; set; }
        
        public bool IsMalicious { get; set; }
        
        public string DetectedBy { get; set; }
        
        public string DetectedPatterns { get; set; }
        
        // Add ML-specific metrics
        public long FileSize { get; set; }
        
        public double EntropyScore { get; set; }
        
        public bool HasValidPEHeader { get; set; }
        
        public int SuspiciousAPICount { get; set; }
        
        public double StringEntropyValue { get; set; }
        
        public int SuspiciousStringCount { get; set; }
        
        public double ObfuscatedCodeRatio { get; set; }
        
        public bool HasValidSignature { get; set; }
        
        public double ExecutableCodeRatio { get; set; }
        
        public double CompressionRatio { get; set; }
        
        public double EncryptedSectionRatio { get; set; }
        
        public int VirusTotalDetectionCount { get; set; }
        
        public int VirusTotalTotalScans { get; set; }
        
        public bool IsGeneratedData { get; set; }
        
        // VirusTotalDetectionRatio veritabanında olmadığından NotMapped olarak işaretlendi
        [NotMapped]
        public float VirusTotalDetectionRatio { 
            get => VirusTotalTotalScans > 0 ? (float)VirusTotalDetectionCount / VirusTotalTotalScans : 0;
            set { /* Bu özellik sadece okunabilir */ } 
        }
        
        // Calculate the ratio when the entity is used
        [NotMapped]
        public float CalculatedVirusTotalDetectionRatio => 
            VirusTotalTotalScans > 0 ? (float)VirusTotalDetectionCount / VirusTotalTotalScans : 0;
    }
} 