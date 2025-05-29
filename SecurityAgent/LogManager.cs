using System;
using System.IO;
using System.Text;
using System.Text.Json;
using System.Collections.Generic;
using System.Linq;

namespace SecurityAgent
{
    public class LogManager
    {
        private static readonly string LogDirectory = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "Logs");
        private static readonly string ScanLogFile = Path.Combine(LogDirectory, "scan_results.log");
        private static readonly string QuarantineLogFile = Path.Combine(LogDirectory, "quarantine.log");
        private static readonly string DetailedScanLogFile = Path.Combine(LogDirectory, "detailed_scan_results.json");
        private static readonly string StatisticsFile = Path.Combine(LogDirectory, "statistics.json");
        private static Dictionary<string, int> ScanStatistics = new();

        public class DetailedScanResult
        {
            public string FilePath { get; set; }
            public DateTime ScanTime { get; set; }
            public bool IsMalicious { get; set; }
            public int DetectionCount { get; set; }
            public int TotalScans { get; set; }
            public string FileHash { get; set; }
            public long FileSize { get; set; }
            public string FileType { get; set; }
            public List<string> DetectedThreats { get; set; }
            public Dictionary<string, string> ScannerResults { get; set; }
            public string Action { get; set; }
            public string DetectedBy { get; set; }
            public string DetectedPatterns { get; set; }
            public double EntropyScore { get; set; }
            public double StringEntropyValue { get; set; }
            public double ObfuscatedCodeRatio { get; set; }
            public double ExecutableCodeRatio { get; set; }
            public double CompressionRatio { get; set; }
            public double EncryptedSectionRatio { get; set; }
        }

        public static void Initialize()
        {
            if (!Directory.Exists(LogDirectory))
            {
                Directory.CreateDirectory(LogDirectory);
            }
            LoadStatistics();
        }

        private static void LoadStatistics()
        {
            try
            {
                if (File.Exists(StatisticsFile))
                {
                    string json = File.ReadAllText(StatisticsFile);
                    ScanStatistics = JsonSerializer.Deserialize<Dictionary<string, int>>(json);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error loading statistics: {ex.Message}");
                ScanStatistics = new Dictionary<string, int>();
            }
        }

        private static void SaveStatistics()
        {
            try
            {
                string json = JsonSerializer.Serialize(ScanStatistics, new JsonSerializerOptions { WriteIndented = true });
                File.WriteAllText(StatisticsFile, json);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error saving statistics: {ex.Message}");
            }
        }

        public static void LogScanResult(string filePath, bool isMalicious, int detectionCount, int totalScans, string detectionDetails)
        {
            try
            {
                string status = isMalicious ? "MALICIOUS" : "CLEAN";
                
                // ScanResultModel oluştur
                var scanResult = new Models.ScanResultModel
                {
                    FilePath = filePath,
                    FileName = Path.GetFileName(filePath),
                    ScanDate = DateTime.Now,
                    IsMalicious = isMalicious,
                    VirusTotalDetectionCount = detectionCount,
                    VirusTotalTotalScans = totalScans,
                    DetectedBy = string.Join(", ", ParseDetectionDetails(detectionDetails)),
                    DetectedPatterns = string.Join(", ", ParseScannerResults(detectionDetails).Select(x => $"{x.Key}: {x.Value}"))
                };

                // Dosya hala mevcutsa ML metriklerini hesapla
                if (File.Exists(filePath))
                {
                    try
                    {
                        var fileAnalyzer = new Services.FileAnalyzer();
                        var fileMetrics = fileAnalyzer.AnalyzeFile(filePath);
                        
                        // ML metriklerini kopyala
                        scanResult.FileSize = fileMetrics.FileSize;
                        scanResult.EntropyScore = fileMetrics.EntropyScore;
                        scanResult.HasValidPEHeader = fileMetrics.HasValidPEHeader;
                        scanResult.SuspiciousAPICount = fileMetrics.SuspiciousAPICount;
                        scanResult.StringEntropyValue = fileMetrics.StringEntropyValue;
                        scanResult.SuspiciousStringCount = fileMetrics.SuspiciousStringCount;
                        scanResult.ObfuscatedCodeRatio = fileMetrics.ObfuscatedCodeRatio;
                        scanResult.HasValidSignature = fileMetrics.HasValidSignature;
                        scanResult.ExecutableCodeRatio = fileMetrics.ExecutableCodeRatio;
                        scanResult.CompressionRatio = fileMetrics.CompressionRatio;
                        scanResult.EncryptedSectionRatio = fileMetrics.EncryptedSectionRatio;

                        // --- FLOAT/DOUBLE ALANLAR İÇİN KONTROL ---
                        scanResult.EntropyScore = (double.IsNaN(scanResult.EntropyScore) || double.IsInfinity(scanResult.EntropyScore)) ? 0.0 : scanResult.EntropyScore;
                        scanResult.StringEntropyValue = (double.IsNaN(scanResult.StringEntropyValue) || double.IsInfinity(scanResult.StringEntropyValue)) ? 0.0 : scanResult.StringEntropyValue;
                        scanResult.ObfuscatedCodeRatio = (double.IsNaN(scanResult.ObfuscatedCodeRatio) || double.IsInfinity(scanResult.ObfuscatedCodeRatio)) ? 0.0 : scanResult.ObfuscatedCodeRatio;
                        scanResult.ExecutableCodeRatio = (double.IsNaN(scanResult.ExecutableCodeRatio) || double.IsInfinity(scanResult.ExecutableCodeRatio)) ? 0.0 : scanResult.ExecutableCodeRatio;
                        scanResult.CompressionRatio = (double.IsNaN(scanResult.CompressionRatio) || double.IsInfinity(scanResult.CompressionRatio)) ? 0.0 : scanResult.CompressionRatio;
                        scanResult.EncryptedSectionRatio = (double.IsNaN(scanResult.EncryptedSectionRatio) || double.IsInfinity(scanResult.EncryptedSectionRatio)) ? 0.0 : scanResult.EncryptedSectionRatio;
                        // --- FLOAT/DOUBLE ALANLAR İÇİN KONTROL SONU ---
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"Warning: Could not analyze file for ML metrics: {ex.Message}");
                        // ML metrikleri olmadan devam et
                    }
                }
                
                // Veritabanına kaydet
                try
                {
                    using (var dbContext = new ScanResultsContext())
                    {
                        Console.WriteLine($"Veritabanına kaydediliyor: {scanResult.FileName}");
                        dbContext.ScanResults.Add(scanResult);
                        var entriesWritten = dbContext.SaveChanges();
                        Console.WriteLine($"Veritabanına başarıyla kaydedildi: {entriesWritten} kayıt");
                    }
                }
                catch (Exception dbEx)
                {
                    Console.WriteLine($"Error saving to database: {dbEx.Message}");
                    // İç içe exception'ları kontrol et
                    var innerEx = dbEx.InnerException;
                    while (innerEx != null)
                    {
                        Console.WriteLine($"İç hata: {innerEx.Message}");
                        innerEx = innerEx.InnerException;
                    }
                    throw; // Hatayı yukarı fırlat
                }

                // Detaylı log kaydı
                var detailedResult = new DetailedScanResult
                {
                    FilePath = filePath,
                    ScanTime = DateTime.Now,
                    IsMalicious = isMalicious,
                    DetectionCount = detectionCount,
                    TotalScans = totalScans,
                    FileHash = File.Exists(filePath) ? CalculateFileHash(filePath) : "N/A (file deleted)",
                    FileSize = scanResult.FileSize,
                    FileType = Path.GetExtension(filePath),
                    DetectedThreats = ParseDetectionDetails(detectionDetails),
                    ScannerResults = ParseScannerResults(detectionDetails),
                    Action = isMalicious ? "DELETED" : "SCANNED",
                    DetectedBy = scanResult.DetectedBy,
                    DetectedPatterns = scanResult.DetectedPatterns,
                    EntropyScore = scanResult.EntropyScore,
                    StringEntropyValue = scanResult.StringEntropyValue,
                    ObfuscatedCodeRatio = scanResult.ObfuscatedCodeRatio,
                    ExecutableCodeRatio = scanResult.ExecutableCodeRatio,
                    CompressionRatio = scanResult.CompressionRatio,
                    EncryptedSectionRatio = scanResult.EncryptedSectionRatio
                };

                SaveDetailedLog(detailedResult);

                // İstatistikleri güncelle
                string key = isMalicious ? "Malicious" : "Clean";
                if (!ScanStatistics.ContainsKey(key))
                    ScanStatistics[key] = 0;
                ScanStatistics[key]++;
                SaveStatistics();
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error in LogScanResult: {ex.Message}");
                throw; // Hatayı yukarı fırlat
            }
        }

        private static string CalculateFileHash(string filePath)
        {
            try
            {
                using var md5 = System.Security.Cryptography.MD5.Create();
                using var stream = File.OpenRead(filePath);
                var hash = md5.ComputeHash(stream);
                return BitConverter.ToString(hash).Replace("-", "").ToLowerInvariant();
            }
            catch
            {
                return "hash_calculation_failed";
            }
        }

        private static string FormatFileSize(long bytes)
        {
            string[] sizes = { "B", "KB", "MB", "GB", "TB" };
            int order = 0;
            double size = bytes;
            while (size >= 1024 && order < sizes.Length - 1)
            {
                order++;
                size = size / 1024;
            }
            return $"{size:0.##} {sizes[order]}";
        }

        private static List<string> ParseDetectionDetails(string details)
        {
            var threats = new List<string>();
            if (string.IsNullOrEmpty(details)) return threats;

            foreach (var line in details.Split('\n'))
            {
                if (line.TrimStart().StartsWith("-"))
                {
                    threats.Add(line.TrimStart('-').Trim());
                }
            }
            return threats;
        }

        private static Dictionary<string, string> ParseScannerResults(string details)
        {
            var results = new Dictionary<string, string>();
            if (string.IsNullOrEmpty(details)) return results;

            foreach (var line in details.Split('\n'))
            {
                if (line.Contains(":"))
                {
                    var parts = line.Split(new[] { ':' }, 2);
                    if (parts.Length == 2)
                    {
                        results[parts[0].Trim()] = parts[1].Trim();
                    }
                }
            }
            return results;
        }

        public static void SaveDetailedLog(DetailedScanResult result)
        {
            try
            {
                List<DetailedScanResult> logs = new();
                if (File.Exists(DetailedScanLogFile))
                {
                    string existingJson = File.ReadAllText(DetailedScanLogFile);
                    logs = JsonSerializer.Deserialize<List<DetailedScanResult>>(existingJson) ?? new List<DetailedScanResult>();
                }

                logs.Add(result);

                // Keep only last 1000 entries
                if (logs.Count > 1000)
                    logs = logs.OrderByDescending(x => x.ScanTime).Take(1000).ToList();

                string json = JsonSerializer.Serialize(logs, new JsonSerializerOptions { WriteIndented = true });
                File.WriteAllText(DetailedScanLogFile, json);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error saving detailed log: {ex.Message}");
            }
        }

        public static void LogQuarantineAction(string filePath, string action, string reason)
        {
            var logEntry = new StringBuilder();
            logEntry.AppendLine($"=== Quarantine Action: {DateTime.Now:yyyy-MM-dd HH:mm:ss} ===");
            logEntry.AppendLine($"File: {filePath}");
            logEntry.AppendLine($"Action: {action}");
            logEntry.AppendLine($"Reason: {reason}");
            logEntry.AppendLine($"File Hash: {CalculateFileHash(filePath)}");
            logEntry.AppendLine("=====================================");
            
            File.AppendAllText(QuarantineLogFile, logEntry.ToString());
        }

        public static string[] GetRecentScanLogs(int count = 10)
        {
            if (!File.Exists(ScanLogFile))
                return Array.Empty<string>();

            var lines = File.ReadAllLines(ScanLogFile);
            return lines.Reverse().Take(count * 7).ToArray(); // Her log 7 satır (file size ve hash eklendi)
        }

        public static List<DetailedScanResult> GetDetailedScanLogs(int count = 50)
        {
            try
            {
                if (!File.Exists(DetailedScanLogFile))
                    return new List<DetailedScanResult>();

                string json = File.ReadAllText(DetailedScanLogFile);
                var logs = JsonSerializer.Deserialize<List<DetailedScanResult>>(json);
                return logs?.OrderByDescending(x => x.ScanTime).Take(count).ToList() ?? new List<DetailedScanResult>();
            }
            catch
            {
                return new List<DetailedScanResult>();
            }
        }

        public static Dictionary<string, int> GetStatistics()
        {
            return new Dictionary<string, int>(ScanStatistics);
        }

        public static string[] GetQuarantineLogs()
        {
            if (!File.Exists(QuarantineLogFile))
                return Array.Empty<string>();

            return File.ReadAllLines(QuarantineLogFile);
        }
    }
} 