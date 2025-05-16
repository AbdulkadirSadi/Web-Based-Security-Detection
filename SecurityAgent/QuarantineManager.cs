using System;
using System.IO;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Linq;
using System.Text.Json;

namespace SecurityAgent
{
    public class QuarantineManager
    {
        private static readonly string QuarantineDirectory = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "Quarantine");
        private static readonly string QuarantineIndexFile = Path.Combine(QuarantineDirectory, "index.json");
        private static readonly string QuarantineStatsFile = Path.Combine(QuarantineDirectory, "stats.json");
        private static readonly Dictionary<string, QuarantineInfo> QuarantineIndex = new();
        private static QuarantineStats Statistics = new();

        public class QuarantineInfo
        {
            public string OriginalPath { get; set; }
            public string QuarantinePath { get; set; }
            public DateTime QuarantineDate { get; set; }
            public string Reason { get; set; }
            public string FileHash { get; set; }
            public long FileSize { get; set; }
            public string FileType { get; set; }
            public string DetectionDetails { get; set; }
            public int DetectionCount { get; set; }
            public bool IsEncrypted { get; set; }
        }

        public class QuarantineStats
        {
            public int TotalQuarantinedFiles { get; set; }
            public int ActiveQuarantinedFiles { get; set; }
            public int RestoredFiles { get; set; }
            public int DeletedFiles { get; set; }
            public Dictionary<string, int> FileTypeStats { get; set; } = new();
            public Dictionary<string, int> DetectionStats { get; set; } = new();
            public long TotalQuarantineSize { get; set; }
            public DateTime LastUpdated { get; set; }
        }

        public static void Initialize()
        {
            if (!Directory.Exists(QuarantineDirectory))
            {
                Directory.CreateDirectory(QuarantineDirectory);
            }

            LoadQuarantineIndex();
            LoadStatistics();
            UpdateStatistics();
        }

        private static void LoadQuarantineIndex()
        {
            if (File.Exists(QuarantineIndexFile))
            {
                try
                {
                    var json = File.ReadAllText(QuarantineIndexFile);
                    var index = JsonSerializer.Deserialize<Dictionary<string, QuarantineInfo>>(json);
                    if (index != null)
                    {
                        QuarantineIndex.Clear();
                        foreach (var item in index)
                        {
                            QuarantineIndex[item.Key] = item.Value;
                        }
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Error loading quarantine index: {ex.Message}");
                }
            }
        }

        private static void LoadStatistics()
        {
            if (File.Exists(QuarantineStatsFile))
            {
                try
                {
                    var json = File.ReadAllText(QuarantineStatsFile);
                    Statistics = JsonSerializer.Deserialize<QuarantineStats>(json) ?? new QuarantineStats();
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Error loading quarantine statistics: {ex.Message}");
                    Statistics = new QuarantineStats();
                }
            }
        }

        private static void SaveQuarantineIndex()
        {
            try
            {
                var json = JsonSerializer.Serialize(QuarantineIndex, new JsonSerializerOptions { WriteIndented = true });
                File.WriteAllText(QuarantineIndexFile, json);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error saving quarantine index: {ex.Message}");
            }
        }

        private static void SaveStatistics()
        {
            try
            {
                Statistics.LastUpdated = DateTime.Now;
                var json = JsonSerializer.Serialize(Statistics, new JsonSerializerOptions { WriteIndented = true });
                File.WriteAllText(QuarantineStatsFile, json);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error saving quarantine statistics: {ex.Message}");
            }
        }

        private static void UpdateStatistics()
        {
            Statistics.ActiveQuarantinedFiles = QuarantineIndex.Count;
            Statistics.TotalQuarantineSize = QuarantineIndex.Values.Sum(x => x.FileSize);
            
            // Update file type stats
            Statistics.FileTypeStats.Clear();
            foreach (var file in QuarantineIndex.Values)
            {
                var fileType = file.FileType ?? "unknown";
                if (!Statistics.FileTypeStats.ContainsKey(fileType))
                    Statistics.FileTypeStats[fileType] = 0;
                Statistics.FileTypeStats[fileType]++;
            }

            SaveStatistics();
        }

        public static string QuarantineFile(string filePath, string reason, bool encrypt = true)
        {
            try
            {
                if (!File.Exists(filePath))
                    throw new FileNotFoundException("File not found", filePath);

                // Calculate file hash
                string fileHash;
                using (var md5 = MD5.Create())
                using (var stream = File.OpenRead(filePath))
                {
                    fileHash = BitConverter.ToString(md5.ComputeHash(stream)).Replace("-", "");
                }

                // Get file info
                var fileInfo = new FileInfo(filePath);
                string fileType = Path.GetExtension(filePath).ToLower();

                // Create quarantine file name
                string fileName = Path.GetFileName(filePath);
                string quarantinePath = Path.Combine(QuarantineDirectory, 
                    $"{DateTime.Now:yyyyMMdd_HHmmss}_{fileHash}_{fileName}.quarantine");

                // Copy file to quarantine (instead of moving, for safety)
                File.Copy(filePath, quarantinePath, true);

                // Encrypt the quarantined file if requested
                if (encrypt)
                {
                    EncryptFile(quarantinePath);
                }

                // Create quarantine info
                var info = new QuarantineInfo
                {
                    OriginalPath = filePath,
                    QuarantinePath = quarantinePath,
                    QuarantineDate = DateTime.Now,
                    Reason = reason,
                    FileHash = fileHash,
                    FileSize = fileInfo.Length,
                    FileType = fileType,
                    IsEncrypted = encrypt
                };

                // Update index and statistics
                QuarantineIndex[quarantinePath] = info;
                Statistics.TotalQuarantinedFiles++;
                
                if (!Statistics.FileTypeStats.ContainsKey(fileType))
                    Statistics.FileTypeStats[fileType] = 0;
                Statistics.FileTypeStats[fileType]++;

                SaveQuarantineIndex();
                UpdateStatistics();

                // Delete original file
                try
                {
                    File.Delete(filePath);
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Warning: Could not delete original file: {ex.Message}");
                }

                // Log action
                LogManager.LogQuarantineAction(filePath, "Quarantined", reason);

                return quarantinePath;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error quarantining file: {ex.Message}");
                return null;
            }
        }

        private static void EncryptFile(string filePath)
        {
            // Bu metod dosyayı şifreleyecek şekilde geliştirilebilir
            // Şimdilik sadece bir placeholder
            return;
        }

        private static void DecryptFile(string filePath)
        {
            // Bu metod dosyayı şifre çözecek şekilde geliştirilebilir
            // Şimdilik sadece bir placeholder
            return;
        }

        public static bool RestoreFile(string quarantinePath)
        {
            try
            {
                if (!QuarantineIndex.ContainsKey(quarantinePath))
                    return false;

                var info = QuarantineIndex[quarantinePath];
                string restorePath = info.OriginalPath;

                // If original path exists or is not writable, create alternative path
                if (File.Exists(restorePath))
                {
                    restorePath = Path.Combine(
                        Path.GetDirectoryName(restorePath),
                        $"Restored_{Path.GetFileName(restorePath)}");
                }

                // Decrypt if necessary
                if (info.IsEncrypted)
                {
                    DecryptFile(quarantinePath);
                }

                // Copy file back (instead of moving, for safety)
                File.Copy(quarantinePath, restorePath, true);

                // Delete quarantined file
                File.Delete(quarantinePath);
                
                QuarantineIndex.Remove(quarantinePath);
                Statistics.RestoredFiles++;

                SaveQuarantineIndex();
                UpdateStatistics();

                LogManager.LogQuarantineAction(restorePath, "Restored", 
                    $"Restored from quarantine: {quarantinePath}");

                return true;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error restoring file: {ex.Message}");
                return false;
            }
        }

        public static bool DeleteQuarantinedFile(string quarantinePath)
        {
            try
            {
                if (!QuarantineIndex.ContainsKey(quarantinePath))
                    return false;

                File.Delete(quarantinePath);
                QuarantineIndex.Remove(quarantinePath);
                Statistics.DeletedFiles++;

                SaveQuarantineIndex();
                UpdateStatistics();

                LogManager.LogQuarantineAction(quarantinePath, "Deleted", 
                    "Permanently deleted from quarantine");

                return true;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error deleting quarantined file: {ex.Message}");
                return false;
            }
        }

        public static List<QuarantineInfo> GetQuarantinedFiles()
        {
            return QuarantineIndex.Values.OrderByDescending(x => x.QuarantineDate).ToList();
        }

        public static QuarantineStats GetStatistics()
        {
            return Statistics;
        }

        public static void CleanupOldFiles(int daysToKeep = 30)
        {
            var cutoffDate = DateTime.Now.AddDays(-daysToKeep);
            var oldFiles = QuarantineIndex.Values
                .Where(x => x.QuarantineDate < cutoffDate)
                .ToList();

            foreach (var file in oldFiles)
            {
                DeleteQuarantinedFile(file.QuarantinePath);
            }
        }

        public static long GetQuarantineFolderSize()
        {
            return Statistics.TotalQuarantineSize;
        }

        public static Dictionary<string, int> GetFileTypeStatistics()
        {
            return new Dictionary<string, int>(Statistics.FileTypeStats);
        }
    }
} 