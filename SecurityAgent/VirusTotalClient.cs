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
        // Yerel önbellek için sözlük (dosya hash -> tarama sonucu)
        private static Dictionary<string, ScanResult> _localCache = new Dictionary<string, ScanResult>();
        // Son API çağrı zamanını izlemek için
        private static DateTime _lastApiCall = DateTime.MinValue;
        // API çağrıları arasında minimum gecikme süresi (milisaniye)
        private const int ApiRateLimit = 15000; // 15 saniye

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
                
                // Yerel önbellekte kontrol et
                if (_localCache.ContainsKey(fileHash))
                {
                    Console.WriteLine("Found result in local cache.");
                    return _localCache[fileHash];
                }
                
                // API çağrısı öncesi gecikme süresi kontrolü
                var timeSinceLastCall = DateTime.Now - _lastApiCall;
                if (timeSinceLastCall.TotalMilliseconds < ApiRateLimit)
                {
                    var waitTime = ApiRateLimit - (int)timeSinceLastCall.TotalMilliseconds;
                    Console.WriteLine($"Waiting {waitTime}ms to respect VirusTotal API rate limits...");
                    await Task.Delay(waitTime);
                }
                
                Console.WriteLine("Checking if file has been previously analyzed by VirusTotal...");
                _lastApiCall = DateTime.Now;
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
                    
                    // Sonucu önbelleğe kaydet
                    _localCache[fileHash] = existingAnalysis;
                    return existingAnalysis;
                }

                // If no existing analysis, upload the file
                var fileInfo = new FileInfo(filePath);
                Console.WriteLine($"Uploading file to VirusTotal (size: {FormatFileSize(fileInfo.Length)})...");
                
                // API çağrısı öncesi gecikme süresi kontrolü
                timeSinceLastCall = DateTime.Now - _lastApiCall;
                if (timeSinceLastCall.TotalMilliseconds < ApiRateLimit)
                {
                    var waitTime = ApiRateLimit - (int)timeSinceLastCall.TotalMilliseconds;
                    Console.WriteLine($"Waiting {waitTime}ms to respect VirusTotal API rate limits...");
                    await Task.Delay(waitTime);
                }
                
                _lastApiCall = DateTime.Now;
                var uploadResponse = await UploadFile(filePath);
                if (!uploadResponse.Success)
                {
                    var errorMsg = $"VirusTotal API access error: {uploadResponse.Error}";
                    Console.WriteLine(errorMsg);
                    
                    if (uploadResponse.Error.Contains("TooManyRequests") || 
                        uploadResponse.Error.Contains("Quota exceeded") ||
                        uploadResponse.Error.Contains("QuotaExceededError"))
                    {
                        Console.WriteLine("VirusTotal API için kota aşıldı. Bu ücretsiz API'nın bir sınırlamasıdır.");
                        Console.WriteLine("Devam etmek için dosya yerel tarama yöntemleri kullanılacak.");
                        
                        // API kota hatası durumunda yerel IOC taraması yap
                        var localScan = new ScanResult 
                        { 
                            IsMalicious = false, 
                            DetectionCount = 0,
                            TotalScans = 0,
                            DetectedBy = new Dictionary<string, string>(),
                            Error = "VirusTotal API quota exceeded. Using local scanning only."
                        };
                        
                        _localCache[fileHash] = localScan;
                        return localScan;
                    }
                    
                    return new ScanResult { IsMalicious = false, Error = errorMsg };
                }

                // Then, get the analysis results
                Console.WriteLine($"File uploaded successfully. Analysis ID: {uploadResponse.AnalysisId}");
                Console.WriteLine("Waiting for VirusTotal analysis to complete...");
                
                // VirusTotal needs time to analyze the file, so we'll wait a bit
                int maxAttempts = 10;
                for (int i = 0; i < maxAttempts; i++)
                {
                    // Increase wait times significantly - VirusTotal community API is rate-limited
                    int waitTime = 15000; // Start with 15 seconds
                    if (i > 2) waitTime = 20000; // 20 seconds after first few attempts
                    if (i > 5) waitTime = 30000; // 30 seconds for later attempts
                    
                    Console.WriteLine($"Checking analysis status (attempt {i+1}/{maxAttempts})...");
                    await Task.Delay(waitTime); // Wait between checks
                    
                    // API çağrısı öncesi gecikme süresi kontrolü
                    timeSinceLastCall = DateTime.Now - _lastApiCall;
                    if (timeSinceLastCall.TotalMilliseconds < ApiRateLimit)
                    {
                        var additionalWaitTime = ApiRateLimit - (int)timeSinceLastCall.TotalMilliseconds;
                        Console.WriteLine($"Waiting additional {additionalWaitTime}ms for API rate limit...");
                        await Task.Delay(additionalWaitTime);
                    }
                    
                    _lastApiCall = DateTime.Now;
                    var analysisResponse = await GetAnalysis(uploadResponse.AnalysisId);
                    
                    if (analysisResponse.Status == "completed")
                    {
                        Console.WriteLine("VirusTotal analysis completed successfully.");
                        var result = new ScanResult
                        {
                            IsMalicious = analysisResponse.IsMalicious,
                            DetectionCount = analysisResponse.DetectionCount,
                            TotalScans = analysisResponse.TotalScans,
                            DetectedBy = analysisResponse.DetectedBy,
                            Error = null
                        };
                        
                        // Sonucu önbelleğe kaydet
                        _localCache[fileHash] = result;
                        return result;
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
                        Console.WriteLine($"Analysis status: {analysisResponse.Status} - Waiting longer for analysis to complete...");
                    }
                }
                
                return new ScanResult { 
                    IsMalicious = false, 
                    Error = "VirusTotal analysis is still in progress. VirusTotal free API has strict rate limits. Check results later by manually scanning the file again." 
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