using Microsoft.ML.Data;

namespace MLSecurityScanner.Models
{
    public class FileData
    {
        [LoadColumn(0)]
        public float FileSize { get; set; }

        [LoadColumn(1)]
        public float EntropyScore { get; set; }

        [LoadColumn(2)]
        public float HasValidPEHeader { get; set; }  // bool değerini 0/1 olarak temsil edeceğiz

        [LoadColumn(3)]
        public float SuspiciousAPICount { get; set; }

        [LoadColumn(4)]
        public float StringEntropyValue { get; set; }

        [LoadColumn(5)]
        public float SuspiciousStringCount { get; set; }

        [LoadColumn(6)]
        public float ObfuscatedCodeRatio { get; set; }

        [LoadColumn(7)]
        public float HasValidSignature { get; set; }  // bool değerini 0/1 olarak temsil edeceğiz

        [LoadColumn(8)]
        public float ExecutableCodeRatio { get; set; }

        [LoadColumn(9)]
        public float CompressionRatio { get; set; }

        [LoadColumn(10)]
        public float EncryptedSectionRatio { get; set; }
        
        [LoadColumn(11)]
        public float VirusTotalDetectionRatio { get; set; }

        [LoadColumn(12), ColumnName("Label")]
        public bool IsMalware { get; set; }  // IsMalicious olarak değiştirilecek
    }
} 