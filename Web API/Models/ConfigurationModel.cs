using System.Collections.Generic;

namespace Web_API.Models
{
    public class ConfigurationModel
    {
        public string[] MonitoringPaths { get; set; }
        public string[] MonitoredExtensions { get; set; }
        public bool IncludeSubdirectories { get; set; }
        public string VirusTotalApiKey { get; set; }
        public string BackendApiUrl { get; set; }
        public string[] AdditionalSuspiciousPatterns { get; set; }
        public bool EnableAlerts { get; set; }
        public bool EnableProcessMonitoring { get; set; }
        public bool AutoTerminateMaliciousProcesses { get; set; }
        public bool AutoDeleteMaliciousFiles { get; set; }
        public int VirusTotalDetectionThreshold { get; set; }
    }
} 