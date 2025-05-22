using System.Collections.Generic;
using System.Linq;

namespace MLSecurityScanner.Models
{
    public static class ScanResultModelExtensions
    {
        /// <summary>
        /// ScanResultModel'i ML.NET için FileData'ya dönüştürür
        /// </summary>
        public static FileData ToFileData(this ScanResultModel model)
        {
            return new FileData
            {
                FileSize = (float)model.FileSize,
                EntropyScore = (float)model.EntropyScore,
                HasValidPEHeader = model.HasValidPEHeader ? 1.0f : 0.0f,
                SuspiciousAPICount = model.SuspiciousAPICount,
                StringEntropyValue = (float)model.StringEntropyValue,
                SuspiciousStringCount = model.SuspiciousStringCount,
                ObfuscatedCodeRatio = (float)model.ObfuscatedCodeRatio,
                HasValidSignature = model.HasValidSignature ? 1.0f : 0.0f,
                ExecutableCodeRatio = (float)model.ExecutableCodeRatio,
                CompressionRatio = (float)model.CompressionRatio,
                EncryptedSectionRatio = (float)model.EncryptedSectionRatio,
                VirusTotalDetectionRatio = model.VirusTotalDetectionRatio,
                IsMalware = model.IsMalicious // IsMalicious verisi IsMalware'e dönüştürülüyor
            };
        }
        
        /// <summary>
        /// ScanResultModel listesini FileData listesine dönüştürür
        /// </summary>
        public static IEnumerable<FileData> ToFileDataList(this IEnumerable<ScanResultModel> models)
        {
            return models.Select(m => m.ToFileData());
        }
    }
} 