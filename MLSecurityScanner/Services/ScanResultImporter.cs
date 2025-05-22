using System;
using System.Collections.Generic;
using System.Linq;
using Microsoft.Data.SqlClient;
using Microsoft.Extensions.Configuration;
using MLSecurityScanner.Models;

namespace MLSecurityScanner.Services
{
    public class ScanResultImporter
    {
        private readonly string? _connectionString;
        
        public ScanResultImporter(IConfiguration configuration)
        {
            _connectionString = configuration.GetConnectionString("DefaultConnection");
        }
        
        /// <summary>
        /// Ajanın veritabanından ScanResult verilerini alır
        /// </summary>
        /// <param name="maxResults">Maksimum sonuç sayısı (0 = tümü)</param>
        /// <returns>ScanResultModel listesi</returns>
        public List<ScanResultModel> ImportScanResults(int maxResults = 0)
        {
            var results = new List<ScanResultModel>();
            
            string query = @"
                SELECT TOP (@maxResults) *
                FROM ScanResultsML
                WHERE FilePath IS NOT NULL
                ORDER BY ScanDate DESC";
            
            if (maxResults <= 0)
            {
                query = query.Replace("TOP (@maxResults) ", "");
            }
            
            try
            {
                using (var connection = new SqlConnection(_connectionString ?? ""))
                {
                    connection.Open();
                    
                    using (var command = new SqlCommand(query, connection))
                    {
                        if (maxResults > 0)
                        {
                            command.Parameters.AddWithValue("@maxResults", maxResults);
                        }
                        
                        using (var reader = command.ExecuteReader())
                        {
                            while (reader.Read())
                            {
                                var model = new ScanResultModel
                                {
                                    Id = reader.GetInt32(reader.GetOrdinal("Id")),
                                    FilePath = reader["FilePath"].ToString(),
                                    FileName = reader["FileName"].ToString(),
                                    ScanDate = reader.GetDateTime(reader.GetOrdinal("ScanDate")),
                                    IsMalicious = reader.GetBoolean(reader.GetOrdinal("IsMalicious")),
                                    DetectedBy = reader["DetectedBy"].ToString(),
                                    DetectedPatterns = reader["DetectedPatterns"].ToString()
                                };
                                
                                // ML metrikleri de var mı kontrol et
                                try 
                                {
                                    model.FileSize = reader.GetInt64(reader.GetOrdinal("FileSize"));
                                    model.EntropyScore = reader.GetDouble(reader.GetOrdinal("EntropyScore"));
                                    model.HasValidPEHeader = reader.GetBoolean(reader.GetOrdinal("HasValidPEHeader"));
                                    model.SuspiciousAPICount = reader.GetInt32(reader.GetOrdinal("SuspiciousAPICount"));
                                    model.StringEntropyValue = reader.GetDouble(reader.GetOrdinal("StringEntropyValue"));
                                    model.SuspiciousStringCount = reader.GetInt32(reader.GetOrdinal("SuspiciousStringCount"));
                                    model.ObfuscatedCodeRatio = reader.GetDouble(reader.GetOrdinal("ObfuscatedCodeRatio"));
                                    model.HasValidSignature = reader.GetBoolean(reader.GetOrdinal("HasValidSignature"));
                                    model.ExecutableCodeRatio = reader.GetDouble(reader.GetOrdinal("ExecutableCodeRatio"));
                                    model.CompressionRatio = reader.GetDouble(reader.GetOrdinal("CompressionRatio"));
                                    model.EncryptedSectionRatio = reader.GetDouble(reader.GetOrdinal("EncryptedSectionRatio"));
                                    model.VirusTotalDetectionCount = reader.GetInt32(reader.GetOrdinal("VirusTotalDetectionCount"));
                                    model.VirusTotalTotalScans = reader.GetInt32(reader.GetOrdinal("VirusTotalTotalScans"));
                                    model.IsGeneratedData = reader.GetBoolean(reader.GetOrdinal("IsGeneratedData"));
                                    
                                    // Try to read VirusTotalDetectionRatio if it exists
                                    try
                                    {
                                        model.VirusTotalDetectionRatio = reader.GetFloat(reader.GetOrdinal("VirusTotalDetectionRatio"));
                                    }
                                    catch
                                    {
                                        // If it doesn't exist in the database, calculate it
                                        model.VirusTotalDetectionRatio = model.VirusTotalTotalScans > 0 
                                            ? (float)model.VirusTotalDetectionCount / model.VirusTotalTotalScans 
                                            : 0;
                                    }
                                }
                                catch
                                {
                                    // Eksik alanlar varsa, ScanResultAdapter ile analiz yapalım
                                    if (!string.IsNullOrEmpty(model.FilePath))
                                    {
                                        var analyzedModel = ScanResultAdapter.ConvertToScanResultModel(
                                            model.FilePath, 
                                            model.IsMalicious, 
                                            model.DetectedBy ?? "", 
                                            model.DetectedPatterns ?? "");
                                        
                                        // Sadece ML metriklerini al
                                        model.FileSize = analyzedModel.FileSize;
                                        model.EntropyScore = analyzedModel.EntropyScore;
                                        model.HasValidPEHeader = analyzedModel.HasValidPEHeader;
                                        model.SuspiciousAPICount = analyzedModel.SuspiciousAPICount;
                                        model.StringEntropyValue = analyzedModel.StringEntropyValue;
                                        model.SuspiciousStringCount = analyzedModel.SuspiciousStringCount;
                                        model.ObfuscatedCodeRatio = analyzedModel.ObfuscatedCodeRatio;
                                        model.HasValidSignature = analyzedModel.HasValidSignature;
                                        model.ExecutableCodeRatio = analyzedModel.ExecutableCodeRatio;
                                        model.CompressionRatio = analyzedModel.CompressionRatio;
                                        model.EncryptedSectionRatio = analyzedModel.EncryptedSectionRatio;
                                    }
                                }
                                
                                results.Add(model);
                            }
                        }
                    }
                }
                
                Console.WriteLine($"{results.Count} ScanResult verisi alındı.");
                Console.WriteLine($"Zararlı: {results.Count(r => r.IsMalicious)}, Zararsız: {results.Count(r => !r.IsMalicious)}");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"ScanResult verileri alınırken hata oluştu: {ex.Message}");
                Console.WriteLine(ex.StackTrace);
            }
            
            return results;
        }
        
        /// <summary>
        /// Son N gün içindeki tarama sonuçlarını getirir
        /// </summary>
        public List<ScanResultModel> ImportRecentScanResults(int days = 30)
        {
            var results = new List<ScanResultModel>();
            
            string query = @"
                SELECT *
                FROM ScanResultsML
                WHERE FilePath IS NOT NULL
                AND ScanDate >= @fromDate
                ORDER BY ScanDate DESC";
            
            try
            {
                using (var connection = new SqlConnection(_connectionString ?? ""))
                {
                    connection.Open();
                    
                    using (var command = new SqlCommand(query, connection))
                    {
                        command.Parameters.AddWithValue("@fromDate", DateTime.Now.AddDays(-days));
                        
                        using (var reader = command.ExecuteReader())
                        {
                            while (reader.Read())
                            {
                                var model = new ScanResultModel
                                {
                                    Id = reader.GetInt32(reader.GetOrdinal("Id")),
                                    FilePath = reader["FilePath"].ToString(),
                                    FileName = reader["FileName"].ToString(),
                                    ScanDate = reader.GetDateTime(reader.GetOrdinal("ScanDate")),
                                    IsMalicious = reader.GetBoolean(reader.GetOrdinal("IsMalicious")),
                                    DetectedBy = reader["DetectedBy"].ToString(),
                                    DetectedPatterns = reader["DetectedPatterns"].ToString()
                                };
                                
                                // ML metrikleri de var mı kontrol et
                                try 
                                {
                                    model.FileSize = reader.GetInt64(reader.GetOrdinal("FileSize"));
                                    model.EntropyScore = reader.GetDouble(reader.GetOrdinal("EntropyScore"));
                                    model.HasValidPEHeader = reader.GetBoolean(reader.GetOrdinal("HasValidPEHeader"));
                                    model.SuspiciousAPICount = reader.GetInt32(reader.GetOrdinal("SuspiciousAPICount"));
                                    model.StringEntropyValue = reader.GetDouble(reader.GetOrdinal("StringEntropyValue"));
                                    model.SuspiciousStringCount = reader.GetInt32(reader.GetOrdinal("SuspiciousStringCount"));
                                    model.ObfuscatedCodeRatio = reader.GetDouble(reader.GetOrdinal("ObfuscatedCodeRatio"));
                                    model.HasValidSignature = reader.GetBoolean(reader.GetOrdinal("HasValidSignature"));
                                    model.ExecutableCodeRatio = reader.GetDouble(reader.GetOrdinal("ExecutableCodeRatio"));
                                    model.CompressionRatio = reader.GetDouble(reader.GetOrdinal("CompressionRatio"));
                                    model.EncryptedSectionRatio = reader.GetDouble(reader.GetOrdinal("EncryptedSectionRatio"));
                                    model.VirusTotalDetectionCount = reader.GetInt32(reader.GetOrdinal("VirusTotalDetectionCount"));
                                    model.VirusTotalTotalScans = reader.GetInt32(reader.GetOrdinal("VirusTotalTotalScans"));
                                    model.IsGeneratedData = reader.GetBoolean(reader.GetOrdinal("IsGeneratedData"));
                                    
                                    // Try to read VirusTotalDetectionRatio if it exists
                                    try
                                    {
                                        model.VirusTotalDetectionRatio = reader.GetFloat(reader.GetOrdinal("VirusTotalDetectionRatio"));
                                    }
                                    catch
                                    {
                                        // If it doesn't exist in the database, calculate it
                                        model.VirusTotalDetectionRatio = model.VirusTotalTotalScans > 0 
                                            ? (float)model.VirusTotalDetectionCount / model.VirusTotalTotalScans 
                                            : 0;
                                    }
                                }
                                catch
                                {
                                    // Eksik alanlar varsa, ScanResultAdapter ile analiz yapalım
                                    if (!string.IsNullOrEmpty(model.FilePath))
                                    {
                                        var analyzedModel = ScanResultAdapter.ConvertToScanResultModel(
                                            model.FilePath, 
                                            model.IsMalicious, 
                                            model.DetectedBy ?? "", 
                                            model.DetectedPatterns ?? "");
                                        
                                        // Sadece ML metriklerini al
                                        model.FileSize = analyzedModel.FileSize;
                                        model.EntropyScore = analyzedModel.EntropyScore;
                                        model.HasValidPEHeader = analyzedModel.HasValidPEHeader;
                                        model.SuspiciousAPICount = analyzedModel.SuspiciousAPICount;
                                        model.StringEntropyValue = analyzedModel.StringEntropyValue;
                                        model.SuspiciousStringCount = analyzedModel.SuspiciousStringCount;
                                        model.ObfuscatedCodeRatio = analyzedModel.ObfuscatedCodeRatio;
                                        model.HasValidSignature = analyzedModel.HasValidSignature;
                                        model.ExecutableCodeRatio = analyzedModel.ExecutableCodeRatio;
                                        model.CompressionRatio = analyzedModel.CompressionRatio;
                                        model.EncryptedSectionRatio = analyzedModel.EncryptedSectionRatio;
                                    }
                                }
                                
                                results.Add(model);
                            }
                        }
                    }
                }
                
                Console.WriteLine($"Son {days} gün içindeki {results.Count} ScanResult verisi alındı.");
                Console.WriteLine($"Zararlı: {results.Count(r => r.IsMalicious)}, Zararsız: {results.Count(r => !r.IsMalicious)}");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"ScanResult verileri alınırken hata oluştu: {ex.Message}");
                Console.WriteLine(ex.StackTrace);
            }
            
            return results;
        }
    }
} 