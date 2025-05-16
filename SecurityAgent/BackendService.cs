using System;
using System.Net.Http;
using System.Net.Http.Json;
using System.Threading.Tasks;
using System.Collections.Generic;
using System.IO;
using System.Text;
using Newtonsoft.Json;

namespace SecurityAgent
{
    public class BackendService
    {
        private readonly HttpClient _httpClient;
        private readonly string _apiUrl;
        private bool _hasValidConfiguration = false;
        private bool _isConnected;

        public bool IsConnected => _isConnected;

        public BackendService(string apiUrl)
        {
            _apiUrl = apiUrl;
            _httpClient = new HttpClient
            {
                Timeout = TimeSpan.FromSeconds(30)
            };

            // Detaylı URL kontrolü
            Console.WriteLine($"Initializing BackendService with URL: {_apiUrl}");
            _hasValidConfiguration = false;
            
            if (string.IsNullOrWhiteSpace(_apiUrl)) 
            {
                Console.WriteLine("Warning: Backend API URL is empty or null.");
            }
            else if (_apiUrl.Contains("your-backend-api.com") || _apiUrl.StartsWith("https://example.com"))
            {
                Console.WriteLine("Warning: Backend API URL contains default placeholder values.");
            }
            else
            {
                _hasValidConfiguration = true;
                Console.WriteLine($"Backend API URL configured: {_apiUrl}");
            }
            
            if (!_hasValidConfiguration)
            {
                Console.WriteLine("Warning: Backend API URL is not properly configured.");
                Console.WriteLine("Results will only be displayed locally, not sent to a backend.");
                Console.WriteLine("To configure a backend, update BackendApiUrl in your config.json file.");
                _isConnected = false;
                return;
            }

            // Check connection on startup
            Task.Run(async () => {
                _isConnected = await CheckConnection();
                if (_isConnected)
                {
                    Console.WriteLine("Connected to backend API");
                }
                else
                {
                    Console.WriteLine("Warning: Could not connect to backend API");
                    Console.WriteLine($"Attempted connection to: {_apiUrl}");
                }
            });
        }

        private async Task<bool> CheckConnection()
        {
            try
            {
                // If URL is not properly configured, don't even try to connect
                if (!_hasValidConfiguration)
                {
                    return false;
                }
                
                // Just check if we can reach the host
                var request = new HttpRequestMessage(HttpMethod.Head, _apiUrl);
                var response = await _httpClient.SendAsync(request);
                return response.IsSuccessStatusCode;
            }
            catch
            {
                return false;
            }
        }

        public async Task<bool> SendScanResult(ScanResultData scanResult)
        {
            try
            {
                if (!_hasValidConfiguration)
                {
                    // No valid backend URL configured, log locally
                    LogResultLocally(scanResult);
                    return false;
                }

                var json = JsonConvert.SerializeObject(scanResult);
                var content = new StringContent(json, Encoding.UTF8, "application/json");
                var response = await _httpClient.PostAsync(_apiUrl + "/scanresults", content);
                
                _isConnected = response.IsSuccessStatusCode;
                if (response.IsSuccessStatusCode)
                {
                    return true;
                }
                else
                {
                    // Log locally as fallback
                    LogResultLocally(scanResult);
                    return false;
                }
            }
            catch (Exception ex)
            {
                _isConnected = false;
                Console.WriteLine($"Error sending results to backend: {ex.Message}");
                LogResultLocally(scanResult);
                return false;
            }
        }
        
        private void LogResultLocally(ScanResultData scanResult)
        {
            Console.WriteLine("Saving scan result locally (not sent to backend):");
            Console.WriteLine($"- File: {scanResult.FilePath}");
            Console.WriteLine($"- Scan Date: {scanResult.ScanDate}");
            Console.WriteLine($"- Malicious: {scanResult.IsMalicious}");
            Console.WriteLine($"- Detection Count: {scanResult.DetectionCount}/{scanResult.TotalScans}");
            
            // Create a log file in the app's folder
            try
            {
                string logDir = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "Logs");
                Directory.CreateDirectory(logDir);
                
                string logFile = Path.Combine(logDir, "scan_results.log");
                string logEntry = $"[{scanResult.ScanDate}] {scanResult.FilePath} - " +
                                  $"Malicious: {scanResult.IsMalicious}, " +
                                  $"Detections: {scanResult.DetectionCount}/{scanResult.TotalScans}\n";
                
                File.AppendAllText(logFile, logEntry);
                Console.WriteLine($"Log saved to: {logFile}");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Failed to save local log: {ex.Message}");
            }
        }
    }

    public class ScanResultData
    {
        public string FilePath { get; set; } = string.Empty;
        public DateTime ScanDate { get; set; }
        public bool IsMalicious { get; set; }
        public int DetectionCount { get; set; }
        public int TotalScans { get; set; }
        public List<string> DetectedBy { get; set; } = new List<string>();
        public List<string> DetectedPatterns { get; set; } = new List<string>();
    }
} 