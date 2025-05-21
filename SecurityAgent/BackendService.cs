using System;
using System.Net.Http;
using System.Net.Http.Json;
using System.Threading.Tasks;
using System.Collections.Generic;
using System.IO;
using System.Text;
using Newtonsoft.Json;
using System.Net.NetworkInformation;

namespace SecurityAgent
{
    public class BackendService
    {
        private readonly HttpClient _httpClient;
        private readonly string _apiUrl;
        private bool _hasValidConfiguration = false;
        private bool _isConnected;
        private readonly int _maxRetries = 3;
        private readonly int _retryDelayMs = 2000;

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
                    
                    // Additional diagnostic information
                    await DiagnoseConnectionIssue();
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

                try 
                {
                    // Check if host is reachable first
                    Uri uri = new Uri(_apiUrl);
                    string host = uri.Host;
                    
                    // If localhost, check if port is open
                    if (host == "localhost" || host == "127.0.0.1")
                    {
                        Console.WriteLine($"Checking if localhost port {uri.Port} is open...");
                    }
                    
                    // Use a GET request instead of HEAD since we have a proper endpoint now
                    var response = await _httpClient.GetAsync(_apiUrl);
                    
                    Console.WriteLine($"Backend connection check status: {response.StatusCode}");
                    if (response.IsSuccessStatusCode)
                    {
                        // Additional verification: try to access configuration endpoint
                        var configEndpoint = _apiUrl + "/configuration";
                        var configResponse = await _httpClient.GetAsync(configEndpoint);
                        if (configResponse.IsSuccessStatusCode)
                        {
                            Console.WriteLine("Successfully connected to API and verified configuration endpoint");
                            // Both endpoints succeeded, we're good to go
                            return true;
                        }
                        Console.WriteLine($"Warning: Main API endpoint OK but configuration endpoint returned {configResponse.StatusCode}");
                        // Even if configuration endpoint fails, we consider the API connected if the main endpoint works
                        return true;
                    }
                    return false;
                }
                catch (HttpRequestException httpEx)
                {
                    Console.WriteLine($"HTTP request error during connection check: {httpEx.Message}");
                    return false;
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Unexpected error during connection check: {ex.Message}");
                return false;
            }
        }

        private async Task DiagnoseConnectionIssue()
        {
            try
            {
                Uri uri = new Uri(_apiUrl);
                string host = uri.Host;
                int port = uri.Port;

                // Check if we can ping the host
                if (host == "localhost" || host == "127.0.0.1")
                {
                    Console.WriteLine("Checking local network services...");
                    Console.WriteLine("Is Web API project running? Make sure it's started in Visual Studio.");
                    
                    // Try to connect to the specific endpoint with more details
                    try
                    {
                        var configEndpoint = _apiUrl.TrimEnd('/') + "/configuration";
                        Console.WriteLine($"Trying to access configuration endpoint: {configEndpoint}");
                        var response = await _httpClient.GetAsync(configEndpoint);
                        Console.WriteLine($"Response from configuration endpoint: {response.StatusCode}");
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"Failed to access configuration endpoint: {ex.Message}");
                    }
                }
                else
                {
                    // For remote hosts, try ping
                    try
                    {
                        Console.WriteLine($"Attempting to ping {host}...");
                        Ping ping = new Ping();
                        PingReply reply = await ping.SendPingAsync(host);
                        Console.WriteLine($"Ping result: {reply.Status}");
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"Ping failed: {ex.Message}");
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error while diagnosing connection: {ex.Message}");
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

                // Check connection if not already known to be connected
                if (!_isConnected)
                {
                    _isConnected = await CheckConnection();
                    if (!_isConnected)
                    {
                        Console.WriteLine("Cannot send scan result: Not connected to backend API");
                        LogResultLocally(scanResult);
                        return false;
                    }
                }

                // Retry logic for network issues
                for (int retry = 0; retry < _maxRetries; retry++)
                {
                    try
                    {
                        var json = JsonConvert.SerializeObject(scanResult);
                        var content = new StringContent(json, Encoding.UTF8, "application/json");
                        
                        // Build the full URL with proper path combining
                        string scanResultsEndpoint = _apiUrl.TrimEnd('/') + "/scanresults";
                        
                        // Reduced logging - only show endpoint without request content
                        Console.WriteLine($"Sending scan result to backend API...");
                        
                        var response = await _httpClient.PostAsync(scanResultsEndpoint, content);
                        
                        _isConnected = response.IsSuccessStatusCode;
                        if (response.IsSuccessStatusCode)
                        {
                            // Minimize response logging
                            Console.WriteLine("Scan result sent to backend API successfully.");
                            return true;
                        }
                        else
                        {
                            string errorContent = await response.Content.ReadAsStringAsync();
                            Console.WriteLine($"API Error: {response.StatusCode} - {errorContent.Substring(0, Math.Min(errorContent.Length, 100))}");
                            
                            // If it's a server error, retry
                            if ((int)response.StatusCode >= 500)
                            {
                                Console.WriteLine($"Server error, retrying... Attempt {retry+1} of {_maxRetries}");
                                await Task.Delay(_retryDelayMs);
                                continue;
                            }
                            
                            // Bad request or other client error, don't retry
                            LogResultLocally(scanResult);
                            return false;
                        }
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"Attempt {retry+1} failed: {ex.Message}");
                        
                        if (retry < _maxRetries - 1)
                        {
                            await Task.Delay(_retryDelayMs);
                            continue;
                        }
                        
                        _isConnected = false;
                        Console.WriteLine($"Error sending results to backend after {_maxRetries} attempts: {ex.Message}");
                        LogResultLocally(scanResult);
                        return false;
                    }
                }
                
                // All retries failed
                _isConnected = false;
                LogResultLocally(scanResult);
                return false;
            }
            catch (Exception ex)
            {
                _isConnected = false;
                Console.WriteLine($"Unexpected error sending results to backend: {ex.Message}");
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