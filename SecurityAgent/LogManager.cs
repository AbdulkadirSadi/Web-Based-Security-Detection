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
            // Update statistics
            string status = isMalicious ? "MALICIOUS" : "CLEAN";
            if (!ScanStatistics.ContainsKey(status))
                ScanStatistics[status] = 0;
            ScanStatistics[status]++;
            SaveStatistics();

            // Create detailed log entry
            var detailedResult = new DetailedScanResult
            {
                FilePath = filePath,
                ScanTime = DateTime.Now,
                IsMalicious = isMalicious,
                DetectionCount = detectionCount,
                TotalScans = totalScans,
                FileHash = CalculateFileHash(filePath),
                FileSize = new FileInfo(filePath).Length,
                FileType = Path.GetExtension(filePath),
                DetectedThreats = ParseDetectionDetails(detectionDetails),
                ScannerResults = ParseScannerResults(detectionDetails),
                Action = "Scan Completed"
            };

            // Save detailed JSON log
            SaveDetailedLog(detailedResult);

            // Save traditional log
            var logEntry = new StringBuilder();
            logEntry.AppendLine($"=== Scan Result: {DateTime.Now:yyyy-MM-dd HH:mm:ss} ===");
            logEntry.AppendLine($"File: {filePath}");
            logEntry.AppendLine($"Status: {status}");
            logEntry.AppendLine($"Detections: {detectionCount}/{totalScans}");
            logEntry.AppendLine($"File Size: {FormatFileSize(detailedResult.FileSize)}");
            logEntry.AppendLine($"File Hash: {detailedResult.FileHash}");
            
            if (!string.IsNullOrEmpty(detectionDetails))
            {
                logEntry.AppendLine("Detection Details:");
                logEntry.AppendLine(detectionDetails);
            }
            
            logEntry.AppendLine("=====================================");
            
            File.AppendAllText(ScanLogFile, logEntry.ToString());
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

        private static void SaveDetailedLog(DetailedScanResult result)
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