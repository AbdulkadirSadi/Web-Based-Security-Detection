using System;
using System.IO;
using System.Collections.Generic;
using Newtonsoft.Json;


namespace SecurityAgent
{
    public class Configuration
    {
        // File monitoring settings
        public string[] MonitoringPaths { get; set; }
        public string[] MonitoredExtensions { get; set; }
        public bool IncludeSubdirectories { get; set; }
        
        // API keys and service URLs
        public string VirusTotalApiKey { get; set; }
        public string BackendApiUrl { get; set; }
        
        // IOC scanning settings
        public List<string> AdditionalSuspiciousPatterns { get; set; }
        
        // Alert and automatic response settings
        public bool EnableAlerts { get; set; }
        public bool EnableProcessMonitoring { get; set; }
        public bool AutoTerminateMaliciousProcesses { get; set; }
        public bool AutoDeleteMaliciousFiles { get; set; }
        public int VirusTotalDetectionThreshold { get; set; }
        
        // Default values
        public static Configuration Default => new Configuration
        {
            MonitoringPaths = new[] { Environment.GetFolderPath(Environment.SpecialFolder.UserProfile) },
            MonitoredExtensions = new[] { ".exe", ".dll", ".bat", ".ps1", ".vbs", ".js", ".jse", ".wsf", ".wsh", ".msi", ".txt", ".pdf" },
            IncludeSubdirectories = true,
            VirusTotalApiKey = "YOUR_VIRUSTOTAL_API_KEY",
            BackendApiUrl = "http://localhost:7260/api",
            AdditionalSuspiciousPatterns = new List<string>(),
            EnableAlerts = true,
            EnableProcessMonitoring = true,
            AutoTerminateMaliciousProcesses = true,
            AutoDeleteMaliciousFiles = true,
            VirusTotalDetectionThreshold = 1  // Even a single detection is considered malicious
        };
        
        // Load configuration from JSON file
        public static Configuration LoadFromFile(string filePath)
        {
            try
            {
                if (File.Exists(filePath))
                {
                    string json = File.ReadAllText(filePath);
                    return JsonConvert.DeserializeObject<Configuration>(json) ?? Default;
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error loading configuration: {ex.Message}");
            }
            
            return Default;
        }
        
        // Save configuration to JSON file
        public void SaveToFile(string filePath)
        {
            try
            {
                string json = JsonConvert.SerializeObject(this, Formatting.Indented);
                File.WriteAllText(filePath, json);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error saving configuration: {ex.Message}");
            }
        }
    }
} 
