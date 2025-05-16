using System;
using System.IO;
using System.Net.Http;
using System.Threading.Tasks;
using System.Collections.Generic;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System.Security.Cryptography;
using System.Text;

namespace SecurityAgent
{
    public class VirusTotalClient
    {
        private readonly HttpClient _httpClient;
        private readonly string _apiKey;
        private const string BaseUrl = "https://www.virustotal.com/api/v3";
        private readonly bool _hasValidApiKey;

        // Threshold for considering a file malicious (percentage of positives)
        private const int MaliciousThreshold = 1;

        public VirusTotalClient(string apiKey)
        {
            _apiKey = apiKey;
            _httpClient = new HttpClient();
            _httpClient.DefaultRequestHeaders.Add("x-apikey", _apiKey);
            
            // Check if API key looks legitimate (basic validation)
            _hasValidApiKey = !string.IsNullOrEmpty(_apiKey) && 
                             _apiKey.Length >= 32 && 
                             !_apiKey.Contains("YOUR_VIRUSTOTAL_API_KEY");
            
            if (!_hasValidApiKey)
            {
                Console.WriteLine("Warning: VirusTotal API key is not properly configured.");
                Console.WriteLine("VirusTotal scanning will not work correctly.");
                Console.WriteLine("To configure VirusTotal, update VirusTotalApiKey in your config.json file.");
            }
        }

        public async Task<ScanResult> AnalyzeFile(string filePath)
        {
            if (!_hasValidApiKey)
            {
                return new ScanResult 
                { 
                    IsMalicious = false, 
                    Error = "VirusTotal scanning is disabled (API key not configured)" 
                };
            }
            
            if (!File.Exists(filePath))
            {
                return new ScanResult
                {
                    IsMalicious = false,
                    Error = "File does not exist"
                };
            }
            
            try
            {
                // First, check if the file has already been analyzed using its hash
                Console.WriteLine("Computing file hash for VirusTotal lookup...");
                var fileHash = ComputeFileHash(filePath);
                Console.WriteLine($"File hash: {fileHash}");
                
                Console.WriteLine("Checking if file has been previously analyzed by VirusTotal...");
                var existingAnalysis = await GetFileReport(fileHash);

                if (existingAnalysis != null)
                {
                    Console.WriteLine($"Found existing VirusTotal analysis for file: {Path.GetFileName(filePath)}");
                    
                    if (existingAnalysis.IsMalicious)
                    {
                        Console.WriteLine($"Detected by {existingAnalysis.DetectionCount} out of {existingAnalysis.TotalScans} engines");
                    }
                    else
                    {
                        Console.WriteLine($"File is clean according to {existingAnalysis.TotalScans} engines");
                    }
                    
                    return existingAnalysis;
                }

                // If no existing analysis, upload the file
                var fileInfo = new FileInfo(filePath);
                Console.WriteLine($"Uploading file to VirusTotal (size: {FormatFileSize(fileInfo.Length)})...");
                
                var uploadResponse = await UploadFile(filePath);
                if (!uploadResponse.Success)
                {
                    var errorMsg = $"Failed to upload file to VirusTotal: {uploadResponse.Error}";
                    Console.WriteLine(errorMsg);
                    return new ScanResult { IsMalicious = false, Error = errorMsg };
                }

                // Then, get the analysis results
                Console.WriteLine($"File uploaded successfully. Analysis ID: {uploadResponse.AnalysisId}");
                Console.WriteLine("Waiting for VirusTotal analysis to complete...");
                
                // VirusTotal needs time to analyze the file, so we'll wait a bit
                int maxAttempts = 10;
                for (int i = 0; i < maxAttempts; i++)
                {
                    int waitTime = 5000; // 5 seconds
                    if (i > 3) waitTime = 10000; // Increase wait time after a few attempts
                    
                    Console.WriteLine($"Checking analysis status (attempt {i+1}/{maxAttempts})...");
                    await Task.Delay(waitTime); // Wait between checks
                    
                    var analysisResponse = await GetAnalysis(uploadResponse.AnalysisId);
                    
                    if (analysisResponse.Status == "completed")
                    {
                        Console.WriteLine("VirusTotal analysis completed successfully.");
                        return new ScanResult
                        {
                            IsMalicious = analysisResponse.IsMalicious,
                            DetectionCount = analysisResponse.DetectionCount,
                            TotalScans = analysisResponse.TotalScans,
                            DetectedBy = analysisResponse.DetectedBy,
                            Error = null
                        };
                    }
                    else if (analysisResponse.Status == "error")
                    {
                        return new ScanResult { 
                            IsMalicious = false, 
                            Error = $"VirusTotal error: {analysisResponse.Error}" 
                        };
                    }
                    else
                    {
                        Console.WriteLine($"Analysis status: {analysisResponse.Status}");
                    }
                }
                
                return new ScanResult { 
                    IsMalicious = false, 
                    Error = "VirusTotal analysis is still in progress. Check results later by manually scanning the file again." 
                };
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error in VirusTotal analysis: {ex.Message}");
                return new ScanResult { IsMalicious = false, Error = ex.Message };
            }
        }

        private string ComputeFileHash(string filePath)
        {
            using var sha256 = SHA256.Create();
            using var stream = File.OpenRead(filePath);
            var hash = sha256.ComputeHash(stream);
            return BitConverter.ToString(hash).Replace("-", "").ToLowerInvariant();
        }

        private string FormatFileSize(long bytes)
        {
            string[] suffixes = { "B", "KB", "MB", "GB", "TB" };
            int suffixIndex = 0;
            double size = bytes;
            
            while (size >= 1024 && suffixIndex < suffixes.Length - 1)
            {
                size /= 1024;
                suffixIndex++;
            }
            
            return $"{size:0.##} {suffixes[suffixIndex]}";
        }

        private async Task<ScanResult> GetFileReport(string fileHash)
        {
            try
            {
                var response = await _httpClient.GetAsync($"{BaseUrl}/files/{fileHash}");
                
                if (!response.IsSuccessStatusCode)
                {
                    // 404 typically means the file hasn't been analyzed yet
                    if (response.StatusCode == System.Net.HttpStatusCode.NotFound)
                    {
                        return null;
                    }
                    
                    // Rate limiting or API key issues
                    if (response.StatusCode == System.Net.HttpStatusCode.Forbidden || 
                        response.StatusCode == System.Net.HttpStatusCode.Unauthorized ||
                        response.StatusCode == System.Net.HttpStatusCode.TooManyRequests)
                    {
                        string errorMsg = await response.Content.ReadAsStringAsync();
                        Console.WriteLine($"VirusTotal API access error: {response.StatusCode}");
                        Console.WriteLine(errorMsg);
                        return new ScanResult
                        {
                            IsMalicious = false,
                            Error = $"VirusTotal API access error: {response.StatusCode}"
                        };
                    }
                    
                    return null;
                }

                var jsonContent = await response.Content.ReadAsStringAsync();
                var json = JObject.Parse(jsonContent);
                
                var attributes = json["data"]?["attributes"];
                if (attributes == null)
                {
                    return null;
                }
                
                var stats = attributes["last_analysis_stats"];
                int malicious = stats?["malicious"]?.Value<int>() ?? 0;
                int suspicious = stats?["suspicious"]?.Value<int>() ?? 0;
                int total = 0;
                
                foreach (var prop in stats.Children<JProperty>())
                {
                    total += prop.Value.Value<int>();
                }
                
                var detectedBy = new Dictionary<string, string>();
                var results = attributes["last_analysis_results"];
                
                if (results != null)
                {
                    foreach (var prop in results.Children<JProperty>())
                    {
                        var engine = prop.Name;
                        var result = prop.Value["category"].Value<string>();
                        
                        if (result == "malicious" || result == "suspicious")
                        {
                            detectedBy[engine] = result;
                        }
                    }
                }
                
                bool isMalicious = (malicious + suspicious) > 0 && 
                                   ((malicious + suspicious) * 100 / total) >= MaliciousThreshold;
                
                return new ScanResult
                {
                    IsMalicious = isMalicious,
                    DetectionCount = malicious + suspicious,
                    TotalScans = total,
                    DetectedBy = detectedBy,
                    Error = null
                };
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error getting file report: {ex.Message}");
                return null;
            }
        }

        private async Task<UploadResponse> UploadFile(string filePath)
        {
            try
            {
                // First check file size - VirusTotal has a limit (typically 32MB for public API)
                var fileInfo = new FileInfo(filePath);
                if (fileInfo.Length > 32 * 1024 * 1024) // 32MB
                {
                    return new UploadResponse 
                    { 
                        Success = false, 
                        Error = $"File is too large for VirusTotal API: {FormatFileSize(fileInfo.Length)}" 
                    };
                }
                
                using var form = new MultipartFormDataContent();
                using var fileStream = File.OpenRead(filePath);
                form.Add(new StreamContent(fileStream), "file", Path.GetFileName(filePath));

                // Use a timeout for large files
                var uploadTimeout = TimeSpan.FromMinutes(2);
                var cts = new System.Threading.CancellationTokenSource(uploadTimeout);
                
                var response = await _httpClient.PostAsync($"{BaseUrl}/files", form, cts.Token);
                var content = await response.Content.ReadAsStringAsync();
                
                if (!response.IsSuccessStatusCode)
                {
                    // Check for common API issues
                    if (response.StatusCode == System.Net.HttpStatusCode.Forbidden || 
                        response.StatusCode == System.Net.HttpStatusCode.Unauthorized)
                    {
                        return new UploadResponse 
                        { 
                            Success = false, 
                            Error = "Invalid VirusTotal API key or insufficient permissions" 
                        };
                    }
                    else if (response.StatusCode == System.Net.HttpStatusCode.TooManyRequests)
                    {
                        return new UploadResponse 
                        { 
                            Success = false, 
                            Error = "VirusTotal API rate limit exceeded. Try again later." 
                        };
                    }
                    
                    return new UploadResponse 
                    { 
                        Success = false, 
                        Error = $"VirusTotal API error: {response.StatusCode} - {content}" 
                    };
                }

                try
                {
                    var json = JObject.Parse(content);
                    var analysisId = json["data"]?["id"]?.Value<string>();
                    
                    if (string.IsNullOrEmpty(analysisId))
                    {
                        return new UploadResponse 
                        { 
                            Success = false, 
                            Error = "Missing analysis ID in VirusTotal response" 
                        };
                    }
                    
                    return new UploadResponse 
                    { 
                        Success = true,
                        AnalysisId = analysisId,
                        Error = null
                    };
                }
                catch (Exception ex)
                {
                    return new UploadResponse 
                    { 
                        Success = false, 
                        Error = $"Error parsing upload response: {ex.Message}" 
                    };
                }
            }
            catch (TaskCanceledException)
            {
                return new UploadResponse 
                { 
                    Success = false, 
                    Error = "VirusTotal upload timed out. The file may be too large." 
                };
            }
            catch (Exception ex)
            {
                return new UploadResponse 
                { 
                    Success = false, 
                    Error = $"Error uploading to VirusTotal: {ex.Message}" 
                };
            }
        }

        private async Task<AnalysisResponse> GetAnalysis(string analysisId)
        {
            try
            {
                var response = await _httpClient.GetAsync($"{BaseUrl}/analyses/{analysisId}");
                var content = await response.Content.ReadAsStringAsync();
                
                if (!response.IsSuccessStatusCode)
                {
                    // Handle specific error codes
                    if (response.StatusCode == System.Net.HttpStatusCode.TooManyRequests)
                    {
                        return new AnalysisResponse 
                        { 
                            Status = "error", 
                            Error = "VirusTotal API rate limit exceeded. Try again later." 
                        };
                    }
                    
                    return new AnalysisResponse { Status = "error", Error = content };
                }

                try
                {
                    var json = JObject.Parse(content);
                    var attributes = json["data"]?["attributes"];
                    
                    if (attributes == null)
                    {
                        return new AnalysisResponse { Status = "error", Error = "Invalid response format" };
                    }
                    
                    var status = attributes["status"]?.Value<string>();
                    
                    if (status != "completed")
                    {
                        return new AnalysisResponse { Status = status };
                    }
                    
                    var stats = attributes["stats"];
                    int malicious = stats?["malicious"]?.Value<int>() ?? 0;
                    int suspicious = stats?["suspicious"]?.Value<int>() ?? 0;
                    int total = 0;
                    
                    foreach (var prop in stats.Children<JProperty>())
                    {
                        total += prop.Value.Value<int>();
                    }
                    
                    var detectedBy = new Dictionary<string, string>();
                    var results = attributes["results"];
                    
                    if (results != null)
                    {
                        foreach (var prop in results.Children<JProperty>())
                        {
                            var engine = prop.Name;
                            var result = prop.Value["category"]?.Value<string>();
                            
                            if (result == "malicious" || result == "suspicious")
                            {
                                detectedBy[engine] = result;
                            }
                        }
                    }
                    
                    bool isMalicious = (malicious + suspicious) > 0 && 
                                      ((malicious + suspicious) * 100 / total) >= MaliciousThreshold;
                    
                    return new AnalysisResponse
                    {
                        Status = "completed",
                        IsMalicious = isMalicious,
                        DetectionCount = malicious + suspicious,
                        TotalScans = total,
                        DetectedBy = detectedBy,
                        Error = null
                    };
                }
                catch (Exception ex)
                {
                    return new AnalysisResponse 
                    { 
                        Status = "error", 
                        Error = $"Error parsing analysis response: {ex.Message}" 
                    };
                }
            }
            catch (Exception ex)
            {
                return new AnalysisResponse
                {
                    Status = "error",
                    Error = $"Error getting analysis: {ex.Message}"
                };
            }
        }
    }

    public class UploadResponse
    {
        public bool Success { get; set; }
        public string AnalysisId { get; set; }
        public string Error { get; set; }
    }

    public class AnalysisResponse
    {
        public string Status { get; set; }
        public bool IsMalicious { get; set; }
        public int DetectionCount { get; set; }
        public int TotalScans { get; set; }
        public Dictionary<string, string> DetectedBy { get; set; }
        public string Error { get; set; }
    }

    public class ScanResult
    {
        public bool IsMalicious { get; set; }
        public int DetectionCount { get; set; }
        public int TotalScans { get; set; }
        public Dictionary<string, string> DetectedBy { get; set; }
        public string Error { get; set; }
    }
} 